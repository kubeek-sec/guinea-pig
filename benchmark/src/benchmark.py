#!/usr/bin/env python3
"""guinea-pig scanner benchmark.

Runs the vendored deep-scan scanners (``benchmark/src/dsbench/``) against the
fixtures, maps every finding to the per-theme ground truth
(``benchmark/ground-truth/<theme>.json``) and reports, per scanner:

  * what was **found** (true positives, CWE-accurate or not),
  * what was **missed** (false negatives in the scanner's expected scope),
  * **false positives** (reports on a ``patched.*`` / look-alike / benign fixture, or on
    a fixed line / decoy line of a ``projects/<lang>/app-patched`` application),
  * **noise** (reports on repo files that are not a known fixture).

It then ranks the **top-3 scanners per family** (across all themes), and writes the
report as Markdown, HTML and PDF.

Usage
-----
    # install the scanner tools (download+verify / docker / uv / system)
    python3 benchmark/src/benchmark.py install --all
    python3 benchmark/src/benchmark.py install gitleaks opengrep
    python3 benchmark/src/benchmark.py list                 # scanners + install status

    # run the benchmark
    python3 benchmark/src/benchmark.py run                  # every static theme (default)
    python3 benchmark/src/benchmark.py run --all            # incl. projects-dast (builds + runs each app in docker)
    python3 benchmark/src/benchmark.py run --theme projects # one theme
    python3 benchmark/src/benchmark.py run --theme skills --scanner cisco-ai-skill-scanner

Disabling scanners
------------------
Any scanner is toggled by an env var (its name upper-cased, ``-``/space -> ``_``)
in the environment or a ``.env`` in the working directory, e.g.::

    CODEQL=false
    ZAPROXY=false
    KINGFISHER=false

See ``.env.example``.
"""
from __future__ import annotations

import argparse
import asyncio
import html
import json
import os
import re
import socket
import subprocess
import sys
import time
from collections import defaultdict
from contextlib import closing
from urllib.parse import urlsplit
from datetime import datetime
from pathlib import Path

SRC = Path(__file__).resolve().parent
REPO = SRC.parents[1]                       # benchmark/src -> benchmark -> repo root
sys.path.insert(0, str(SRC))                # make the vendored ``dsbench`` importable

from dsbench import config, install, registry, runner   # noqa: E402
from dsbench.install.catalog import TOOLS, ToolKind      # noqa: E402
from dsbench.models import Family, Mode, ToolStatus      # noqa: E402

GROUND_TRUTH_DIR = REPO / "benchmark" / "ground-truth"

# Theme -> (fixture dir, scan mode).
THEMES: dict[str, tuple[str, Mode]] = {
    "secrets": ("secrets", Mode.STATIC),
    "projects": ("projects", Mode.STATIC),
    "pipeline": ("pipeline", Mode.STATIC),
    "skills": ("skills", Mode.STATIC),
    "projects-dast": ("projects", Mode.DYNAMIC),
}
# Theme -> ground-truth file (when it differs from the theme name).
GT_FILE = {"projects-dast": "projects"}
PROJECT_THEMES = {"projects", "projects-dast"}


def is_dynamic(theme: str) -> bool:
    return THEMES[theme][1] == Mode.DYNAMIC

# Each scanner's *expected scope*: which ground-truth ``scanner_types`` it is
# meant to cover. Used as the fair recall denominator and to decide whether a
# miss counts against it. A detection on any fixture is still credited.
SCOPE: dict[str, set[str]] = {
    "gitleaks": {"SECRET"}, "trufflehog": {"SECRET"}, "nosey_parker": {"SECRET"},
    "titus": {"SECRET"}, "betterleaks": {"SECRET"}, "kingfisher": {"SECRET"},
    "opengrep": {"SAST", "IAC", "PIPELINE"}, "codeql": {"SAST"},
    "trivy": {"SCA"}, "trivy-misconfig": {"IAC"}, "trivy-license": {"LICENSE"},
    "osv-scanner": {"SCA"}, "checkov": {"IAC"}, "plumber": {"PIPELINE"},
    "nuclei": {"DAST"}, "zaproxy": {"DAST"},
    "cisco-ai-skill-scanner": {"SKILL"}, "yara": {"SKILL"}, "mcp-threats": {"SKILL"},
    "clamav": {"MALWARE"},
    "analysis": {"SAST"}, "reachable-deps": {"SCA"},
}

# Display order for the per-family ranking (families not listed are appended).
FAMILY_ORDER = ["SECRET", "SAST", "IAC", "SCA", "PIPELINE", "DAST", "SKILL", "LICENSE", "MALWARE"]


# --------------------------------------------------------------------------- #
# Ground truth
# --------------------------------------------------------------------------- #
def load_theme_gt(theme: str) -> dict:
    """positives/negatives/catalogue/dast for one theme, keyed by repo path
    (by weakness id for the project themes)."""
    doc = json.loads((GROUND_TRUTH_DIR / f"{GT_FILE.get(theme, theme)}.json").read_text(encoding="utf-8"))
    if theme in PROJECT_THEMES:
        return load_projects_gt(doc)
    positives: dict[str, dict] = {}
    dast: list[dict] = []
    for f in doc.get("positives", []):
        types = {str(t).upper() for t in f.get("scanner_types", [])}
        cwes = {c["id"] for c in f.get("cwe", []) if c.get("id")}
        if f.get("expected_cwe"):
            cwes.add(f["expected_cwe"])
        loc = f.get("location") or {}
        if types == {"DAST"} or f.get("analysis") == "dynamic":
            dast.append({"endpoint": loc.get("endpoint"), "cwes": cwes})
            continue
        rel = loc.get("file")
        if not rel:
            continue
        if rel in positives:
            positives[rel]["cwes"] |= cwes
            positives[rel]["types"] |= types
        else:
            positives[rel] = {"cwes": cwes, "types": types}

    negatives: dict[str, dict] = {}
    for n in doc.get("negatives", []):
        rel = n.get("file")
        if rel:
            negatives[rel] = {"kind": n.get("kind", ""),
                              "types": {str(t).upper() for t in n.get("scanner_types", [])}}

    catalogue: dict[str, dict] = {}
    cat = doc.get("secret_catalogue") or {}
    if cat:
        cat_dir = REPO / cat.get("dir", "secrets/catalogue")
        if cat_dir.is_dir():
            for p in sorted(cat_dir.rglob("*.txt")):
                catalogue[str(p.relative_to(REPO))] = {
                    "cwes": {cat.get("expected_cwe", "CWE-798")}, "types": {"SECRET"}}
    return {"positives": positives, "negatives": negatives,
            "catalogue": catalogue, "dast": dast}


def _norm_pkg(name: str) -> str:
    return name.lower().replace("_", "-").replace(".", "-")


def _endpoint_key(app: str, endpoint: str) -> str:
    return f"{app} {endpoint}"


def load_projects_gt(doc: dict) -> dict:
    """Line-level ground truth of the projects/ applications, keyed by weakness id."""
    positives: dict[str, dict] = {}
    dast: list[dict] = []
    for f in doc.get("positives", []):
        types = {str(t).upper() for t in f.get("scanner_types", [])}
        cwes = {c["id"] for c in f.get("cwe", []) if c.get("id")} | {f.get("expected_cwe")} - {None}
        loc = f.get("location") or {}
        app = next((a["app"] for a in doc.get("apps", []) if loc.get("file", "").startswith(a["app"] + "/")), "")
        if f.get("analysis") == "dynamic":
            method, _, path = (f.get("endpoint") or "").partition(" ")
            dast.append({"id": f["id"], "app": app, "method": method.upper(),
                         "path": path.split("?", 1)[0], "cwes": cwes,
                         "endpoint": _endpoint_key(app, f.get("endpoint") or "")})
            continue
        locs = [(loc["file"], loc.get("start_line"))] + [
            (a["file"], a.get("start_line")) for a in f.get("alt_locations", [])]
        positives[f["id"]] = {"cwes": cwes, "types": types, "locs": locs,
                              "package": _norm_pkg(f["package"]) if f.get("package") else None,
                              "version": f.get("version"), "app": app}
    negatives: dict[str, dict] = {}
    for n in doc.get("negatives", []):
        negatives[n["id"]] = {"kind": n.get("kind", ""), "file": n["file"], "line": n.get("start_line"),
                              "types": {str(t).upper() for t in n.get("scanner_types", [])},
                              "cwes": {n.get("expected_cwe")} - {None}}
    return {"positives": positives, "negatives": negatives, "catalogue": {}, "dast": dast,
            "apps": doc.get("apps", []), "tol": int(doc.get("line_tolerance", 3))}


# --------------------------------------------------------------------------- #
# Location resolution (finding location -> known repo fixture path)
# --------------------------------------------------------------------------- #
def _strip_line(loc: str) -> str:
    loc = loc[7:] if loc.startswith("file://") else loc
    head = loc.rsplit(":", 1)
    if len(head) == 2 and head[1].isdigit():
        return head[0]
    return loc


def make_resolver(theme_dir: str, known: set[str]):
    """Map a finding location (relative to the scanned theme dir) to a known
    fixture path. Tries the reconstructed repo path first, then a basename+suffix
    match (handles tools that echo absolute or differently-rooted paths)."""
    by_base: dict[str, list[str]] = defaultdict(list)
    for rel in known:
        by_base[os.path.basename(rel)].append(rel)

    def resolve(location: str) -> str | None:
        loc = _strip_line(location)
        if not loc:
            return None
        repo_rel = f"{theme_dir}/{loc}".replace("//", "/")
        if repo_rel in known:
            return repo_rel
        base = os.path.basename(loc)
        best = None
        for cand in by_base.get(base, []):
            if cand == repo_rel or cand.endswith("/" + loc) or cand.endswith(loc) or repo_rel.endswith(cand):
                if best is None or len(cand) > len(best):
                    best = cand
        return best
    return resolve


# --------------------------------------------------------------------------- #
# Running a theme
# --------------------------------------------------------------------------- #
def _free_port() -> int:
    with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _wait_http(port: int, timeout: float = 20.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as s:
            s.settimeout(1.0)
            if s.connect_ex(("127.0.0.1", port)) == 0:
                return True
        time.sleep(0.3)
    return False


def run_theme(theme: str, scanner_names: list[str] | None, raw_dir: Path | None):
    """Run the applicable scanners for a theme and return their Report."""
    theme_dir, mode = THEMES[theme]
    if mode == Mode.DYNAMIC:
        raise ValueError("dynamic themes are run per application (see run_projects_dast)")
    target = REPO / theme_dir
    return asyncio.run(runner.run_scan(
        str(target), mode=Mode.STATIC, scanners=scanner_names, raw_dir=raw_dir))


def _docker(*args: str, timeout: int = 900) -> subprocess.CompletedProcess:
    return subprocess.run(["docker", *args], capture_output=True, text=True, timeout=timeout, check=False)


def _wait_health(url: str, timeout: float = 120.0) -> bool:
    import urllib.request
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=3) as r:  # noqa: S310 — local container
                if r.status < 500:
                    return True
        except Exception:  # noqa: BLE001 — not up yet
            pass
        time.sleep(1)
    return False


def run_app_container(app_dir: Path, runtime: dict, scanner_names: list[str] | None,
                      raw_dir: Path | None):
    """Build ``app_dir`` with its Dockerfile, run it on a free local port, run the
    DAST scanners against it and return their Report (None if it did not start)."""
    tag = "guinea-pig/" + "-".join(app_dir.relative_to(REPO / "projects").parts).lower()
    print(f"  building {tag} …")
    b = _docker("build", "-q", "-t", tag, str(app_dir), timeout=1800)
    if b.returncode != 0:
        print(f"  build failed: {b.stderr.strip()[-400:]}")
        return None
    port = _free_port()
    env_args = [a for k, v in (runtime.get("env") or {}).items() for a in ("-e", f"{k}={v}")]
    r = _docker("run", "-d", "--rm", "-p", f"127.0.0.1:{port}:{runtime.get('port', 8080)}",
                *env_args, tag)
    if r.returncode != 0:
        print(f"  run failed: {r.stderr.strip()[-400:]}")
        return None
    cid = r.stdout.strip()
    try:
        url = f"http://127.0.0.1:{port}"
        if not _wait_health(url + runtime.get("health", "/")):
            print("  application did not become healthy in time")
            return None
        return asyncio.run(runner.run_scan(
            url, mode=Mode.DYNAMIC, scanners=scanner_names, raw_dir=raw_dir,
            allow_private_urls=True))
    finally:
        _docker("rm", "-f", cid, timeout=60)


def run_projects_dast(gt: dict, scanner_names: list[str] | None, raw_dir: Path | None) -> dict:
    """{app: {"app": Report|None, "patched": Report|None}} for every application."""
    out: dict[str, dict] = {}
    for a in gt.get("apps", []):
        print(f"  --- {a['app']}")
        sub = (raw_dir / a["language"]) if raw_dir else None
        out[a["app"]] = {
            "app": run_app_container(REPO / a["app"], a.get("runtime", {}), scanner_names,
                                     sub / "app" if sub else None),
            "patched": run_app_container(REPO / a["patched"], a.get("runtime", {}), scanner_names,
                                         sub / "patched" if sub else None),
        }
    return out


# --------------------------------------------------------------------------- #
# Scoring
# --------------------------------------------------------------------------- #
def score_theme(theme: str, gt: dict, report) -> dict:
    """Per-scanner detection stats for one theme's Report."""
    theme_dir = THEMES[theme][0]
    positives, negatives, catalogue = gt["positives"], gt["negatives"], gt["catalogue"]
    known = set(positives) | set(negatives) | set(catalogue)
    resolve = make_resolver(theme_dir, known)
    all_pos = {**positives, **catalogue}

    out: dict[str, dict] = {}
    for tr in report.tools:
        scope = SCOPE.get(tr.scanner, set())
        # finding location -> {repo_path: cwes}
        by_file: dict[str, set[str]] = defaultdict(set)
        noise: set[str] = set()
        for f in tr.findings:
            rel = resolve(f.location)
            if rel:
                by_file[rel] |= set(f.cwes)
            else:
                loc = _strip_line(f.location)
                if "/" in loc:  # a path we could not map under this theme = noise
                    noise.add(f"{theme_dir}/{loc}".replace("//", "/"))

        applicable = {p for p, m in all_pos.items() if scope & m["types"]}
        found_cwe = found_hit = 0
        found_files: list[str] = []
        for p in applicable:
            if p in by_file:
                found_files.append(p)
                if by_file[p] & all_pos[p]["cwes"]:
                    found_cwe += 1
                else:
                    found_hit += 1
        missed = sorted(applicable - set(found_files))
        # cross-family detections (credited but outside the scanner's scope)
        extra = sorted(set(by_file) & set(all_pos) - applicable)
        fps = sorted(p for p in negatives if p in by_file)
        out[tr.scanner] = {
            "status": tr.status.value, "duration": tr.duration,
            "family": tr.family.value, "raw": len(tr.findings),
            "applicable": len(applicable), "found": len(found_files),
            "found_cwe": found_cwe, "found_hit": found_hit,
            "missed": missed, "extra": extra,
            "fp": fps, "noise": sorted(noise),
            "detected": set(found_files),
        }
    return out


# --------------------------------------------------------------------------- #
# Scoring — projects (line-level static, endpoint-level dynamic)
# --------------------------------------------------------------------------- #
_LOC_RE = re.compile(r"^(.*?):(\d+)(?::\d+)?$")


def _project_path(location: str, theme_dir: str) -> tuple[str, int | None]:
    """Finding location -> (repo-relative path, line or None)."""
    loc = location[7:] if location.startswith("file://") else location
    m = _LOC_RE.match(loc)
    path, line = (m.group(1), int(m.group(2))) if m else (loc, None)
    pp = Path(path)
    if pp.is_absolute():
        try:
            path = str(pp.resolve().relative_to(REPO))
        except ValueError:
            pass
    elif not path.startswith(theme_dir + "/"):
        path = f"{theme_dir}/{path}".replace("//", "/")
    return path, line


def score_projects(theme: str, gt: dict, report) -> dict:
    """Line-level scoring: a finding hits a weakness when it is in the sink's (or an
    alternate location's) file within ±tol lines; an SCA finding hits a dependency
    when it is on its manifest and names the package. Findings on a fixed line or a
    decoy line (±tol) are false positives; anything else under projects/ is noise."""
    theme_dir = THEMES[theme][0]
    positives, negatives, tol = gt["positives"], gt["negatives"], gt["tol"]
    out: dict[str, dict] = {}

    def near(a: int | None, b: int | None) -> bool:
        return a is None or b is None or abs(a - b) <= tol

    for tr in report.tools:
        scope = SCOPE.get(tr.scanner, set())
        hit_cwes: dict[str, set[str]] = defaultdict(set)
        fps: set[str] = set()
        noise: set[str] = set()
        for f in tr.findings:
            path, line = _project_path(f.location, theme_dir)
            blob = _norm_pkg(f"{f.location} {f.rule} {f.message}")
            matched = False
            for pid, pos in positives.items():
                if pos["package"]:
                    manifest = pos["locs"][0][0]
                    if pos["package"] in blob and (path == manifest or path.startswith(pos["app"] + "/")):
                        hit_cwes[pid] |= set(f.cwes)
                        matched = True
                elif any(path == lf and near(line, ll) for lf, ll in pos["locs"]):
                    hit_cwes[pid] |= set(f.cwes)
                    matched = True
            if matched:
                continue
            neg = [nid for nid, n in negatives.items() if path == n["file"] and near(line, n["line"])]
            if neg:
                fps.update(neg)
            elif path.startswith(theme_dir + "/"):
                noise.add(f"{path}:{line}" if line else path)

        applicable = {pid for pid, m in positives.items() if scope & m["types"]}
        found = set(hit_cwes) & applicable
        found_cwe = sum(1 for pid in found if hit_cwes[pid] & positives[pid]["cwes"])
        out[tr.scanner] = {
            "status": tr.status.value, "duration": tr.duration,
            "family": tr.family.value, "raw": len(tr.findings),
            "applicable": len(applicable), "found": len(found),
            "found_cwe": found_cwe, "found_hit": len(found) - found_cwe,
            "missed": sorted(applicable - found), "extra": sorted(set(hit_cwes) - applicable),
            "fp": sorted(fps), "noise": sorted(noise),
            "detected": set(hit_cwes),
        }
    return out


def _endpoint_hit(e: dict, path: str, cwes: set[str]) -> tuple[bool, bool]:
    """(path matches the endpoint template, CWE matches)."""
    tmpl = re.sub(r"\{[^/}]+\}|:[A-Za-z_]\w*", r"[^/]+", e["path"].rstrip("/") or "/")
    p = (path or "/").split("?", 1)[0].rstrip("/") or "/"
    return bool(re.fullmatch(tmpl + r"(/.*)?", p)), bool(e["cwes"] & cwes)


def score_projects_dast(gt: dict, runs: dict) -> dict:
    """Endpoint-graded scoring over every application. A weakness endpoint is found
    when a finding on the vulnerable app hits its path (or its CWE, for site-wide
    findings); the same hit (path AND CWE) on the patched app is a false positive."""
    out: dict[str, dict] = {}
    for app, reps in runs.items():
        eps = [e for e in gt.get("dast", []) if e["app"] == app]
        for kind in ("app", "patched"):
            report = reps.get(kind)
            if report is None:
                continue
            for tr in report.tools:
                s = out.setdefault(tr.scanner, {
                    "status": tr.status.value, "duration": 0.0, "family": tr.family.value,
                    "raw": 0, "applicable": 0, "found": 0, "found_cwe": 0, "found_hit": 0,
                    "missed": [], "extra": [], "fp": [], "noise": [], "detected": set()})
                s["duration"] += tr.duration
                s["raw"] += len(tr.findings)
                hits = []
                for f in tr.findings:
                    loc = f.location or ""
                    hits.append((urlsplit(loc).path if "://" in loc else loc, set(f.cwes)))
                for e in eps:
                    res = [_endpoint_hit(e, pth, cw) for pth, cw in hits]
                    path_hit = any(ph for ph, _ in res)
                    cwe_hit = any(ch for _, ch in res)
                    both = any(ph and ch for ph, ch in res)
                    if kind == "app":
                        s["applicable"] += 1
                        if path_hit or cwe_hit:
                            s["found"] += 1
                            s["detected"].add(e["endpoint"])
                            s["found_cwe" if cwe_hit else "found_hit"] += 1
                        else:
                            s["missed"].append(e["endpoint"])
                    elif both:
                        s["fp"].append(f"{app}-patched {e['endpoint'].split(' ', 1)[1]}")
                if kind == "app":
                    for pth, cw in hits:
                        if not any(any(_endpoint_hit(e, pth, cw)) for e in eps):
                            s["noise"].append(f"{app} {pth}")
    for s in out.values():
        s["noise"] = sorted(set(s["noise"]))
    return out


# --------------------------------------------------------------------------- #
# Rendering
# --------------------------------------------------------------------------- #
def _pct(n: int, d: int) -> str:
    return f"{n / d:.0%}" if d else "n/a"


def top_by_family(results: dict, gts: dict) -> dict:
    """Aggregate each scanner across **all themes**, grouped by the vulnerability
    family it targets (its detection scope). Returns
    ``{family: [(scanner, found, applicable, fp_total, noise_total), …]}`` sorted by
    recall desc. A scanner with a multi-family scope (e.g. opengrep → SAST/IAC/
    PIPELINE) appears under each of its families."""
    detected: dict[str, set] = defaultdict(set)
    errs: dict[str, list] = defaultdict(lambda: [0, 0])
    for per in results.values():
        for sc, s in per.items():
            detected[sc] |= set(s.get("detected") or ())
            errs[sc][0] += len(s.get("fp") or ())
            errs[sc][1] += len(s.get("noise") or ())
    fam_pos: dict[str, set] = defaultdict(set)
    for theme, gt in gts.items():
        if is_dynamic(theme):
            for e in gt.get("dast", []):
                if e.get("endpoint"):
                    fam_pos["DAST"].add(e["endpoint"])
        else:
            for path, meta in {**gt.get("positives", {}), **gt.get("catalogue", {})}.items():
                for fam in meta["types"]:
                    fam_pos[fam].add(path)
    out: dict[str, list] = {}
    for fam, paths in fam_pos.items():
        rows = []
        for sc, det in detected.items():
            if fam not in SCOPE.get(sc, set()):
                continue
            rows.append((sc, len(det & paths), len(paths), errs[sc][0], errs[sc][1]))
        rows.sort(key=lambda r: (-(r[1] / r[2] if r[2] else 0), r[3] + r[4], r[0]))
        if rows:
            out[fam] = rows
    return out


_HTML_CSS = """
body{font-family:-apple-system,Segoe UI,Roboto,Helvetica,sans-serif;margin:2rem;color:#1b1b1b;font-size:12px;line-height:1.45}
h1{font-size:22px;margin:0 0 .3rem}h2{font-size:16px;border-bottom:2px solid #e0e0e0;padding-bottom:4px;margin:1.6rem 0 .6rem}
h3{font-size:13px;margin:1rem 0 .25rem;color:#333}
table{border-collapse:collapse;margin:.4rem 0 1rem;font-size:11px}
th,td{border:1px solid #d0d0d0;padding:3px 8px;text-align:left}
th{background:#f3f4f6;font-weight:600}td:nth-child(n+4),th:nth-child(n+4){text-align:right}
code{background:#f4f4f5;padding:0 4px;border-radius:3px;font-size:11px}
ul{margin:.2rem 0 .6rem;padding-left:1.2rem}li{font-size:11px}
"""


def _html_doc(body: str) -> str:
    return ("<!doctype html><html><head><meta charset='utf-8'>"
            f"<style>{_HTML_CSS}</style></head><body>{body}</body></html>")


def _write_html_pdf(out_dir, md_text: str) -> None:
    """Render the markdown report to ``benchmark.html`` and ``benchmark.pdf``. The
    PDF is best-effort — skipped with a note if weasyprint (or its libs) is absent."""
    try:
        import markdown as _md
        body = _md.markdown(md_text, extensions=["tables", "fenced_code", "sane_lists"])
    except Exception as exc:  # noqa: BLE001 — degrade to a <pre> dump
        body = "<pre>" + html.escape(md_text) + "</pre>"
        print(f"  (html: markdown lib unavailable, using <pre> — {exc})")
    doc = _html_doc(body)
    (out_dir / "benchmark.html").write_text(doc, encoding="utf-8")
    try:
        from weasyprint import HTML
        HTML(string=doc).write_pdf(str(out_dir / "benchmark.pdf"))
    except Exception as exc:  # noqa: BLE001 — PDF is optional
        print(f"  (pdf skipped — {type(exc).__name__}: {exc})")


def render(results: dict[str, dict], gts: dict[str, dict]) -> str:
    """results[theme][scanner] = stats. Build the markdown report."""
    L: list[str] = ["# guinea-pig scanner benchmark\n"]
    L.append(f"- Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    L.append(f"- Themes: {', '.join(results)}\n")

    # ---- 1. recap: per (scanner, theme) found / missed / FP ----
    L.append("## Recap — per scanner & theme\n")
    L.append("`found` = applicable positives detected (✓=CWE-accurate); "
             "`missed` = applicable positives not reported; `FP` = reports on a "
             "negative; `noise` = reports on non-fixture files; `extra` = "
             "cross-family detections credited outside the scanner's scope.\n")
    L.append("| Theme | Scanner | Family | Status | Applicable | Found (✓cwe) | Missed | Extra | FP | Noise | Recall |")
    L.append("|---|---|---|---|--:|--:|--:|--:|--:|--:|--:|")
    for theme, per in results.items():
        for scanner, s in sorted(per.items(), key=lambda kv: (-kv[1]["found"], kv[0])):
            if s["applicable"] == 0 and s["found"] == 0 and not s["fp"] and not s["noise"]:
                continue  # nothing to say for this scanner on this theme
            L.append(
                f"| {theme} | {scanner} | {s['family']} | {s['status']} | "
                f"{s['applicable']} | {s['found']} ({s['found_cwe']}) | {len(s['missed'])} | "
                f"{len(s['extra'])} | {len(s['fp'])} | {len(s['noise'])} | "
                f"{_pct(s['found'], s['applicable'])} |")
    L.append("")

    # ---- 2. top-3 scanners per family ----
    L.append("## Top 3 scanners per family\n")
    L.append("Scanners grouped by the vulnerability family they target (their detection "
             "scope), ranked by **recall over that family's positives aggregated across all "
             "themes**, then fewer errors. FP/Noise are the scanner's totals across themes.\n")
    fam_rank = top_by_family(results, gts)
    ordered = [f for f in FAMILY_ORDER if f in fam_rank] + [f for f in fam_rank if f not in FAMILY_ORDER]
    for fam in ordered:
        rows = fam_rank[fam]
        L.append(f"### {fam} — {rows[0][2]} positives")
        L.append("| # | Scanner | Recall | Found | FP | Noise |")
        L.append("|--:|---|--:|--:|--:|--:|")
        for i, (sc, found, appl, fp, noise) in enumerate(rows[:3], 1):
            L.append(f"| {i} | {sc} | {_pct(found, appl)} | {found}/{appl} | {fp} | {noise} |")
        L.append("")

    # ---- 3. visibility: what NOTHING found, per theme ----
    L.append("## Not found by any scanner (per theme)\n")
    for theme, per in results.items():
        gt = gts[theme]
        if is_dynamic(theme):
            all_pos = {e["endpoint"]: {"cwes": e["cwes"]} for e in gt.get("dast", [])}
        else:
            all_pos = {**gt["positives"], **gt["catalogue"]}
        detected: set[str] = set()
        for s in per.values():
            detected |= s["detected"]
        undetected = sorted(set(all_pos) - detected)
        L.append(f"### {theme} — {len(undetected)}/{len(all_pos)} positives undetected")
        if not undetected:
            L.append("All positives detected by at least one scanner. ✓\n")
            continue
        shown = undetected[:40]
        for p in shown:
            L.append(f"- `{p}` (expected {','.join(sorted(all_pos[p]['cwes'])) or '—'})")
        if len(undetected) > len(shown):
            L.append(f"- … and {len(undetected) - len(shown)} more")
        L.append("")

    # ---- 4. false positives detail, per scanner ----
    L.append("## False positives & noise (per scanner)\n")
    any_err = False
    for theme, per in results.items():
        for scanner, s in per.items():
            if not s["fp"] and not s["noise"]:
                continue
            any_err = True
            L.append(f"**{scanner}** / {theme} — {len(s['fp'])} FP, {len(s['noise'])} noise")
            for p in s["fp"][:15]:
                L.append(f"  - FP `{p}`")
            for p in s["noise"][:15]:
                L.append(f"  - noise `{p}`")
            L.append("")
    if not any_err:
        L.append("None — no scanner reported on a negative or a non-fixture file. ✓\n")
    return "\n".join(L)


# --------------------------------------------------------------------------- #
# Scanner selection
# --------------------------------------------------------------------------- #
def select_scanner_names(theme: str, requested: list[str] | None) -> list[str] | None:
    """Names to run for a theme: explicit ``requested`` (filtered to the theme's
    mode), else None (let the runner pick all enabled scanners for the mode)."""
    mode = THEMES[theme][1]
    if requested:
        names = []
        for n in requested:
            s = registry.REGISTRY.get(n)
            if s is None:
                raise SystemExit(f"unknown scanner: {n}. Known: {', '.join(sorted(registry.REGISTRY))}")
            if s.mode == mode:
                names.append(n)
        return names or None
    return None  # runner selects all enabled scanners for the mode


# --------------------------------------------------------------------------- #
# Commands
# --------------------------------------------------------------------------- #
def cmd_list(_args) -> int:
    print(f"{'scanner':24} {'family':9} {'mode':8} {'tool':24} installed")
    for s in sorted(registry.REGISTRY.values(), key=lambda s: (s.family.value, s.name)):
        inst = "-"
        if s.tool:
            inst = "yes" if install.is_installed(s.tool) else "NO"
        env_off = "" if config.scanner_enabled(s.name) else "  (disabled via env)"
        print(f"{s.name:24} {s.family.value:9} {s.mode.value:8} {s.tool or '-':24} {inst}{env_off}")
    return 0


def _warm_uv_tool(name: str) -> None:
    """Pre-resolve a UV scanner's pinned overlay in this project's uv cache, so the
    first scan isn't slowed by the download. Idempotent; failures are non-fatal."""
    spec = TOOLS[name]
    pkg = spec.uv_package or spec.name
    exe = spec.executable or spec.name
    print(f"  {name}: preparing project-uv overlay ({pkg}=={spec.version})…")
    try:
        subprocess.run(["uv", "run", "--with", f"{pkg}=={spec.version}", exe, "--version"],
                       cwd=str(REPO), capture_output=True, text=True, timeout=900)
    except (OSError, subprocess.SubprocessError) as exc:
        print(f"  {name}: warm-up note: {exc}")


def cmd_install(args) -> int:
    names = list(TOOLS) if args.all else args.tools
    if not names:
        print("Specify tool names or --all (`list` shows them).")
        return 2
    explicit = bool(args.tools) and not args.all
    results = []
    for name in names:
        spec = TOOLS.get(name)
        if spec is None:
            print(f"  {name}: unknown tool")
            continue
        if spec.kind == ToolKind.UV:
            # UV scanners run through this project's uv (`uv run --with`), not a
            # global `uv tool install` — just warm the pinned overlay.
            _warm_uv_tool(name)
        elif spec.kind == ToolKind.SYSTEM and not explicit:
            print(f"  {name}: SYSTEM package — install explicitly (`install {name}`, uses apt/sudo)")
        else:
            try:
                install.install(name, force=args.force)
            except install.InstallError as exc:
                print(f"  {name}: FAILED — {exc}")
        results.append(install.status(name))
    print(f"\n{'tool':26} {'version':10} {'kind':9} installed")
    for st in results:
        print(f"{st.name:26} {st.version:10} {st.kind:9} {'yes' if st.installed else 'NO'}")
    return 0


def cmd_run(args) -> int:
    if args.theme:
        themes = [args.theme]
    elif args.all:
        themes = list(THEMES)
    else:  # default + --all-except-dast
        themes = [t for t in THEMES if not is_dynamic(t)]
    requested = args.scanner.split(",") if args.scanner else None

    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_dir = REPO / "benchmark" / "results" / f"bench_{stamp}"
    out_dir.mkdir(parents=True, exist_ok=True)

    results: dict[str, dict] = {}
    gts: dict[str, dict] = {}
    for theme in themes:
        print(f"\n=== theme: {theme} ===")
        gt = load_theme_gt(theme)
        gts[theme] = gt
        names = select_scanner_names(theme, requested)
        raw = out_dir / "raw" / theme
        if theme == "projects-dast":
            try:
                runs = run_projects_dast(gt, names, raw)
            except Exception as exc:  # noqa: BLE001 — one theme failing must not sink the rest
                print(f"  theme {theme} failed: {exc}")
                continue
            results[theme] = score_projects_dast(gt, runs)
            continue
        try:
            report = run_theme(theme, names, raw)
        except Exception as exc:  # noqa: BLE001 — one theme failing must not sink the rest
            print(f"  theme {theme} failed: {exc}")
            continue
        for tr in report.tools:
            print(f"  {tr.scanner:24} {tr.status.value:8} "
                  f"{len(tr.findings):5} findings  {tr.duration:5.1f}s"
                  f"  {tr.error or tr.skip_reason or ''}")
        results[theme] = (score_projects(theme, gt, report) if theme in PROJECT_THEMES
                          else score_theme(theme, gt, report))

    md = render(results, gts)
    (out_dir / "benchmark.md").write_text(md, encoding="utf-8")
    _write_html_pdf(out_dir, md)
    (out_dir / "benchmark.json").write_text(json.dumps(
        {theme: {sc: {k: (sorted(v) if isinstance(v, set) else v)
                      for k, v in st.items()} for sc, st in per.items()}
         for theme, per in results.items()}, indent=2, default=list), encoding="utf-8")
    print(f"\nWrote {out_dir}/benchmark.{{md,html,pdf,json}}")
    # brief console top-3 per family
    fam_rank = top_by_family(results, gts)
    for fam in [f for f in FAMILY_ORDER if f in fam_rank]:
        rows = fam_rank[fam]
        top = ", ".join(f"{sc} ({_pct(found, appl)})" for sc, found, appl, _, _ in rows[:3])
        print(f"  top {fam:9}: {top}")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="guinea-pig scanner benchmark")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p_list = sub.add_parser("list", help="list scanners + install status")
    p_list.set_defaults(func=cmd_list)

    p_inst = sub.add_parser("install", help="install scanner tools")
    p_inst.add_argument("tools", nargs="*", help="tool names (catalog keys); empty + --all installs all")
    p_inst.add_argument("--all", action="store_true", help="install every catalog tool")
    p_inst.add_argument("--force", action="store_true", help="reinstall even if present")
    p_inst.set_defaults(func=cmd_install)

    p_run = sub.add_parser("run", help="run the benchmark")
    g = p_run.add_mutually_exclusive_group()
    g.add_argument("--theme", choices=list(THEMES), help="run a single theme")
    g.add_argument("--all", action="store_true", help="run every theme (incl. projects-dast)")
    g.add_argument("--all-except-dast", action="store_true", help="every static theme (default)")
    p_run.add_argument("--scanner", help="comma-separated scanner names to run (default: all enabled)")
    p_run.set_defaults(func=cmd_run)

    args = ap.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
