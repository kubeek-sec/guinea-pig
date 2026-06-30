"""Nuclei: template-based dynamic scanning of a running target URL.

Nuclei needs its **templates** (the separate ``nuclei-templates`` repo), which
are not part of the binary. They're expected to be present (baked into the image
or in the user's nuclei home). Knobs:

* ``DEEPSCAN_NUCLEI_UPDATE_TEMPLATES`` — refresh templates before each scan.
  **On by default** (best-effort: a blocked update falls back to baked/existing
  templates); set it falsey (``false``/``0``) to rely solely on baked templates.
* ``DEEPSCAN_NUCLEI_TEMPLATES`` — explicit templates directory (``-templates``).
* ``DEEPSCAN_NUCLEI_SEVERITY`` — severities to run (default ``medium,high,critical``).

If no templates are available, the scanner **skips cleanly** (with a hint)
rather than failing the scan.
"""

from __future__ import annotations

import json
import re
import urllib.request

from .. import config
from ..models import Family, Finding, Mode, Severity
from .base import ScanContext, Scanner, ScannerSkipped

_EMPTY_SARIF = json.dumps(
    {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "nuclei"}}, "results": []}],
    }
)

_FALSEY = {"false", "0", "no", "off", "disable", "disabled"}
_NO_TEMPLATES_HINTS = (
    "no templates provided",
    "no templates were found",
    "could not find any templates",
    "no such file or directory",  # nuclei-templates dir missing
)


class Nuclei(Scanner):
    name = "nuclei"
    family = Family.DAST
    mode = Mode.DYNAMIC
    tool = "nuclei"
    description = "Template-based dynamic vulnerability scanning"

    def _openapi_spec(self, url: str, work) -> "object | None":
        """If the target exposes an OpenAPI/Swagger spec, fetch it, rewrite its
        server to the live target and stage it for an import-mode DAST run. Returns
        the staged spec path, or None to scan the bare URL with templates only."""
        base = url.rstrip("/")
        for path in ("/openapi.yml", "/openapi.yaml", "/openapi.json", "/swagger.json"):
            try:
                with urllib.request.urlopen(base + path, timeout=10) as resp:
                    if getattr(resp, "status", 200) != 200:
                        continue
                    spec = resp.read().decode("utf-8", "replace")
            except Exception:  # noqa: BLE001 — no spec, fall back to URL+templates
                continue
            spec = re.sub(r"(url:\s*)https?://[^\s\"']+", lambda m: m.group(1) + base, spec, count=1)
            ext = ".json" if path.endswith(".json") else ".yaml"
            dest = work / f"nuclei-openapi{ext}"
            dest.write_text(spec, encoding="utf-8")
            return dest
        return None

    async def _execute(self, ctx: ScanContext) -> list[Finding]:
        if not ctx.target_url:
            raise ScannerSkipped("Dynamic scanner needs a target URL.")
        binary = self.binary()

        # Refresh templates before each scan by default (newest rules / CVEs).
        # Best-effort: a blocked/slow update never fails the scan — it falls back
        # to whatever templates are present (e.g. those baked into the image).
        # Disable with DEEPSCAN_NUCLEI_UPDATE_TEMPLATES=false to rely on baked ones.
        if (config.get("DEEPSCAN_NUCLEI_UPDATE_TEMPLATES") or "").strip().lower() not in _FALSEY:
            try:
                await self._run([str(binary), "-update-templates", "-no-color"])
            except Exception:  # noqa: BLE001 — template refresh is best-effort
                pass

        out = ctx.work_dir / f"{self.name}.jsonl"
        severities = config.get("DEEPSCAN_NUCLEI_SEVERITY", "medium,high,critical")
        cmd = [
            str(binary),
            "-severity",
            str(severities),
            "-jsonl-export",
            str(out),
            "-no-color",
            "-duc",
        ]
        # If the target exposes an OpenAPI spec, import every endpoint and run the
        # DAST (fuzzing) templates against them — otherwise the param routes are
        # never exercised. Else fall back to template scanning of the bare URL.
        spec = self._openapi_spec(ctx.target_url, ctx.work_dir)
        if spec is not None:
            cmd += ["-list", str(spec), "-input-mode", "openapi", "-dast"]
        else:
            cmd += ["-target", ctx.target_url]
        # Operator config/nuclei/ custom templates win, else DEEPSCAN_NUCLEI_TEMPLATES.
        cfg = self.config_dir()
        templates = str(cfg) if cfg else config.get("DEEPSCAN_NUCLEI_TEMPLATES")
        if templates and str(templates).strip():
            cmd += ["-templates", str(templates).strip()]

        code, stdout, stderr = await self._run(cmd)
        text = out.read_text(encoding="utf-8") if out.is_file() else ""
        if not text.strip():
            blob = f"{stderr}\n{stdout}".lower()
            if any(hint in blob for hint in _NO_TEMPLATES_HINTS):
                raise ScannerSkipped(
                    "nuclei has no templates installed — run 'nuclei -update-templates', "
                    "set DEEPSCAN_NUCLEI_UPDATE_TEMPLATES=1, point DEEPSCAN_NUCLEI_TEMPLATES "
                    "at a templates dir, or bake them into the image."
                )
            if code != 0:
                raise RuntimeError(f"nuclei exited {code}: {stderr[-500:]}")
            return []  # ran cleanly, nothing found
        self.save_raw(ctx, f"{self.name}.jsonl", text)
        return self._parse_jsonl(text)

    def _parse_jsonl(self, text: str) -> list[Finding]:
        """Parse nuclei JSONL: each line carries the matched URL (`matched-at`) and
        CWE ids (`info.classification.cwe-id`) that the SARIF export drops."""
        findings: list[Finding] = []
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                o = json.loads(line)
            except json.JSONDecodeError:
                continue
            info = o.get("info") or {}
            raw = (info.get("classification") or {}).get("cwe-id") or []
            if isinstance(raw, str):
                raw = [raw]
            cwes = [c if (c := str(x).upper()).startswith("CWE-") else f"CWE-{c}" for x in raw]
            findings.append(Finding(
                tool=self.name,
                family=self.family,
                rule=o.get("template-id") or info.get("name") or "nuclei",
                severity=Severity.from_string(info.get("severity")),
                message=info.get("name") or o.get("template-id") or "nuclei finding",
                location=o.get("matched-at") or o.get("url") or o.get("host") or "",
                cwes=cwes,
                extra={"matcher": o.get("matcher-name", "")},
            ))
        return findings
