"""Orchestrate the code-graph security analysis.

1. Build the graphify code graph (knowledge base + structural summary) and,
   when an artifact dir is given, write ``graph.json`` / ``graph.html``.
2. Run the precise Python AST taint engine and the multi-language tree-sitter
   sink scan.
3. Compute call-graph **reachability** (is the enclosing function reachable from
   an entry point, and by what path) and use it to enrich every finding and to
   adjust the severity/confidence of the structural "risk zone" findings.

Nothing here executes target code (AST / tree-sitter parsing only).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..log import get_logger
from ..models import Family, Finding, Severity
from . import chokepoints, sinks, taint, treesitter_scan
from .reachability import CallGraph, ReachInfo

_log = get_logger("analysis")

_SEV_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
_CONF_ORDER = ["low", "medium", "high"]


def _downgrade(sev: Severity, steps: int) -> Severity:
    idx = min(len(_SEV_ORDER) - 1, _SEV_ORDER.index(sev) + steps)
    return _SEV_ORDER[idx]


def _bump_conf(conf: str, steps: int = 1) -> str:
    try:
        idx = _CONF_ORDER.index(conf)
    except ValueError:
        return conf
    return _CONF_ORDER[min(len(_CONF_ORDER) - 1, idx + steps)]


@dataclass
class AnalysisResult:
    findings: list[Finding] = field(default_factory=list)
    graph_summary: dict[str, Any] = field(default_factory=dict)
    artifacts: dict[str, str] = field(default_factory=dict)  # name -> path


# graphify ``file_type`` values that are documentation/prose, not code. The
# security graph keeps only ``code`` (and ``concept`` — external/stdlib call
# targets, which are code structure).
_NON_CODE_FILE_TYPES = frozenset({"document", "rationale", "paper", "image"})


def _keep_code_only(G) -> None:
    """Drop documentation/comment nodes (and their edges) from the graph."""
    drop = [n for n, d in G.nodes(data=True) if d.get("file_type") in _NON_CODE_FILE_TYPES]
    G.remove_nodes_from(drop)


def _build_graph(files: list[Path], work_dir: Path, artifacts_dir: Path | None):
    """Build the graphify graph. Returns (summary, artifacts, call_graph).
    Best-effort: any failure yields an empty summary and ``None`` call graph so
    the security analysis still runs (without reachability)."""
    summary: dict[str, Any] = {}
    artifacts: dict[str, str] = {}
    try:
        from graphify.analyze import god_nodes
        from graphify.build import build_from_json
        from graphify.cluster import cluster
        from graphify.extract import extract
    except Exception as exc:  # graphify or a dep missing
        summary["error"] = f"graph unavailable: {exc}"
        return summary, artifacts, None, None, {}

    try:
        extraction = extract(files, cache_root=work_dir, parallel=False)
        G = build_from_json(extraction, directed=True)
    except Exception as exc:  # noqa: BLE001
        summary["error"] = f"graph build failed: {exc}"
        return summary, artifacts, None, None, {}

    # graphify is a general knowledge-graph tool: it also models prose — markdown
    # files become ``document`` nodes and Python docstrings / rationale comments
    # (``# NOTE:`` …) become ``rationale`` nodes, plus ``paper``/``image`` nodes
    # for ingested docs. A *security* code graph wants code structure only, so
    # drop those node types (and their edges) before clustering/export/view.
    _keep_code_only(G)

    try:
        communities = cluster(G) or {}
    except Exception:  # noqa: BLE001
        communities = {}
    try:
        hubs = god_nodes(G, top_n=10)
    except Exception:  # noqa: BLE001
        hubs = []

    try:
        call_graph = CallGraph(extraction)
    except Exception:  # noqa: BLE001
        call_graph = None

    summary = {
        "nodes": G.number_of_nodes(),
        "edges": G.number_of_edges(),
        "communities": len(communities),
        "functions": call_graph.function_count if call_graph else 0,
        "entry_points": call_graph.entry_point_count if call_graph else 0,
        "god_nodes": [
            {"label": h.get("label"), "degree": h.get("degree")} for h in hubs
        ],
    }

    if artifacts_dir is not None:
        artifacts_dir.mkdir(parents=True, exist_ok=True)
        try:
            from graphify.export import to_json

            out = artifacts_dir / "graph.json"
            to_json(G, communities, str(out), force=True)
            if out.exists():
                artifacts["graph.json"] = str(out)
        except Exception:  # noqa: BLE001
            pass
    return summary, artifacts, call_graph, G, communities


def _reach_fields(info: ReachInfo | None) -> dict[str, Any]:
    """Reachability fields attached to a finding's ``extra`` (always present so
    the shape is stable, even when reachability could not be computed)."""
    if info is None:
        return {"reachable_from_entrypoint": None, "entry_point": None,
                "entry_kind": "unknown", "call_distance": None, "call_path": []}
    return {
        "reachable_from_entrypoint": info.reachable,
        "entry_point": info.entry_point,
        "entry_kind": info.entry_kind,
        "call_distance": info.distance if info.distance >= 0 else None,
        "call_path": info.call_path,
    }


def _taint_findings(files: list[Path], root: Path, cg: CallGraph | None) -> list[Finding]:
    findings: list[Finding] = []
    for p in taint.analyze_python(files, root):
        sev = sinks.spec(p.kind).severity
        info = cg.lookup(p.file, p.line) if cg else None
        extra = {
            "engine": "analysis/taint-python",
            "kind": p.kind,
            "confidence": "high",
            "reachable": True,  # taint proved a data-flow to the sink
            "sanitized": False,
            "taint_chain": p.chain,
            "remediation": sinks.remediation(p.kind),
        }
        extra.update(_reach_fields(info))
        findings.append(Finding(
            tool="analysis",
            family=Family.ANALYSIS,
            rule=p.cwe or p.kind,
            severity=sev,
            message=_taint_message(p, info),
            location=f"{p.file}:{p.line}",
            cwes=[p.cwe] if p.cwe.upper().startswith("CWE-") else [],
            extra=extra,
        ))
    return findings


def _taint_message(p, info: ReachInfo | None) -> str:
    base = (
        f"{p.kind}: untrusted input reaches {p.sink}() without sanitization "
        f"(cross-function taint path)"
    )
    if info and info.reachable and info.entry_kind in ("web", "cli"):
        return base + f" — reachable from {info.entry_kind} entry point {info.entry_point}"
    return base


def _treesitter_findings(files: list[Path], root: Path, cg: CallGraph | None) -> list[Finding]:
    findings: list[Finding] = []
    for h in treesitter_scan.scan_files(files, root):
        base = sinks.spec(h.kind).severity
        info = cg.lookup(h.file, h.line) if cg else None
        external = bool(info and info.reachable and info.entry_kind in ("web", "cli"))

        if h.unsanitized and (h.input_nearby or external):
            sev, conf = base, "medium"
            note = "reachable from external input, no sanitizer in scope"
        elif h.unsanitized:
            sev, conf = _downgrade(base, 1), "low"
            note = "no sanitizer in scope (reachability from input not confirmed)"
        else:
            sev, conf = _downgrade(base, 2), "low"
            note = "a sanitizer appears in scope — likely mitigated, verify"

        # A confirmed path from a web/CLI entry point is evidence of exposure:
        # raise confidence (it's not just a lexical match in dead code).
        if external:
            conf = _bump_conf(conf)
            note += f"; reachable from {info.entry_kind} entry point {info.entry_point}"

        extra = {
            "engine": "analysis/treesitter",
            "kind": h.kind,
            "confidence": conf,
            "unsanitized": h.unsanitized,
            "input_nearby": h.input_nearby,
            "remediation": sinks.remediation(h.kind),
        }
        extra.update(_reach_fields(info))
        findings.append(Finding(
            tool="analysis",
            family=Family.ANALYSIS,
            rule=h.cwe or h.kind,
            severity=sev,
            message=f"{h.kind}: dangerous call {h.callee}() — {note}",
            location=f"{h.file}:{h.line}",
            cwes=[h.cwe] if h.cwe.upper().startswith("CWE-") else [],
            extra=extra,
        ))
    return findings


def analyze_target(
    target: Path,
    work_dir: Path,
    artifacts_dir: Path | None = None,
) -> AnalysisResult:
    """Analyze a directory (or single file): build the graph and find risk zones."""
    findings, summary, artifacts, cg, G, communities = _analyze(target, work_dir, artifacts_dir)

    # Security-annotated interactive graph view + queryable payload.
    if artifacts_dir is not None and G is not None:
        try:
            from . import graph_view
            from .graph_html import render_graph_html

            payload = graph_view.build(G, findings, cg, communities)
            (artifacts_dir / "graph.html").write_text(render_graph_html(payload), encoding="utf-8")
            artifacts["graph.html"] = str(artifacts_dir / "graph.html")
            # Machine-readable payload so the graph can be queried after the scan.
            import json as _json

            (artifacts_dir / "graph.view.json").write_text(_json.dumps(payload), encoding="utf-8")
            artifacts["graph.view.json"] = str(artifacts_dir / "graph.view.json")
            summary["security_graph"] = payload["counts"]
            _log.debug("graph.html: %s", payload["counts"])
        except Exception as exc:  # noqa: BLE001
            _log.debug("graph.html render skipped: %s", exc)

    return AnalysisResult(findings=findings, graph_summary=summary, artifacts=artifacts)


def _analyze(target: Path, work_dir: Path, artifacts_dir: Path | None):
    """Shared core: collect files, build the graph + findings + choke points.
    Returns (findings, summary, artifacts, cg, G, communities)."""
    try:
        from graphify.extract import collect_files

        files = collect_files(target)
    except Exception:  # noqa: BLE001 — fall back to a plain code-file walk
        files = _walk_code_files(target)

    root = target if target.is_dir() else target.parent
    _log.debug("collected %d code file(s) under %s", len(files), target)
    summary, artifacts, cg, G, communities = _build_graph(files, work_dir, artifacts_dir)
    _log.debug(
        "graph: %s nodes, %s edges, %s functions, %s entry points",
        summary.get("nodes"), summary.get("edges"),
        summary.get("functions"), summary.get("entry_points"),
    )
    taint_f = _taint_findings(files, root, cg)
    ts_f = _treesitter_findings(files, root, cg)
    # taint (precise) wins over a tree-sitter risk-zone at the same location, so a
    # Python sink covered by both engines is reported once (taint kept).
    taint_locs = {f.location for f in taint_f}
    ts_f = [f for f in ts_f if f.location not in taint_locs]
    _log.debug("findings: %d python-taint, %d tree-sitter", len(taint_f), len(ts_f))
    findings = taint_f + ts_f
    if cg is not None and findings:
        try:
            choke = chokepoints.analyze(cg, findings)  # also writes extra["choke_points"]
            summary["choke_points"] = choke["choke_points"]
            _log.debug("choke points: %d", len(choke["choke_points"]))
        except Exception as exc:  # noqa: BLE001 — never fail the scan on analysis extras
            _log.debug("choke-point analysis skipped: %s", exc)
    summary["findings_reachable_from_entry"] = sum(
        1 for f in findings if f.extra.get("reachable_from_entrypoint")
    )
    summary["findings_via_web_or_cli"] = sum(
        1 for f in findings if f.extra.get("entry_kind") in ("web", "cli")
    )
    return findings, summary, artifacts, cg, G, communities


def security_payload(target: Path, work_dir: Path) -> dict | None:
    """Build the security-annotated graph payload for querying (no files written).
    Returns None when the code graph could not be built."""
    from . import graph_view

    findings, _summary, _artifacts, cg, G, communities = _analyze(target, work_dir, None)
    if G is None:
        return None
    return graph_view.build(G, findings, cg, communities)


_CODE_EXTS = set(sinks.EXT_TO_FAMILY) | {".py", ".pyw"}


def _walk_code_files(target: Path) -> list[Path]:
    if target.is_file():
        return [target]
    skip = {".git", ".venv", "node_modules", "__pycache__", ".tox", "dist", "build"}
    out: list[Path] = []
    for p in target.rglob("*"):
        if p.is_file() and p.suffix.lower() in _CODE_EXTS and not (skip & set(p.parts)):
            out.append(p)
    return out
