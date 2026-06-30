"""OWASP ZAP baseline scan, run in Docker.

Hardening: container runs as the host UID/GID, work dir is a private (0700)
scratch directory, host networking only so the container can reach targets on
localhost during local testing.
"""

from __future__ import annotations

import json
import os
import re
import sys
import urllib.request

from ..models import Family, Finding, Mode, Severity
from .base import ScanContext, Scanner, ScannerSkipped

_RISK_MAP = {
    "3": Severity.HIGH,
    "2": Severity.MEDIUM,
    "1": Severity.LOW,
    "0": Severity.INFO,
}


class Zap(Scanner):
    name = "zaproxy"
    family = Family.DAST
    mode = Mode.DYNAMIC
    tool = "zaproxy"
    description = "OWASP ZAP baseline scan (passive + spider) via Docker"

    async def _execute(self, ctx: ScanContext) -> list[Finding]:
        if not ctx.target_url:
            raise ScannerSkipped("Dynamic scanner needs a target URL.")
        image = self.require_docker_image()
        work = ctx.work_dir / "zap"
        work.mkdir(mode=0o700, exist_ok=True)
        report_name = "zap-report.json"
        # If the target exposes an OpenAPI spec, drive an *active* per-endpoint
        # API scan (zap-api-scan) instead of the passive baseline — a passive
        # spider never discovers parameterized routes (/search?q=, /ping?host=…).
        target, fmt = self._api_target(ctx.target_url, work)
        script = "zap-api-scan.py" if fmt else "zap-baseline.py"
        cmd = [
            "docker",
            "run",
            "--rm",
            "-u",
            f"{os.getuid()}:{os.getgid()}" if sys.platform != "win32" else "1000:1000",
            "-v",
            f"{work}:/zap/wrk:rw",
            "--network",
            "host",
            image,
            script,
            "-t",
            target,
            "-J",
            report_name,
            "-I",
        ]
        if fmt:
            cmd += ["-f", fmt]
        code, _stdout, stderr = await self._run(cmd)
        report_path = work / report_name
        if not report_path.is_file():
            raise RuntimeError(f"zap exited {code} without report: {stderr[-500:]}")
        text = report_path.read_text(encoding="utf-8")
        self.save_raw(ctx, f"{self.name}.json", text)
        return self._parse(text)

    def _api_target(self, url: str, work) -> "tuple[str, str | None]":
        """Discover an OpenAPI/Swagger spec on the target. If found, rewrite its
        server URL to the live target, stage it under the mounted work dir, and
        return ``(/zap/wrk/openapi.<ext>, "openapi")`` for an active api-scan.
        Otherwise return ``(url, None)`` for the passive baseline."""
        base = url.rstrip("/")
        for path in ("/openapi.yml", "/openapi.yaml", "/openapi.json", "/swagger.json"):
            try:
                with urllib.request.urlopen(base + path, timeout=10) as resp:
                    if getattr(resp, "status", 200) != 200:
                        continue
                    spec = resp.read().decode("utf-8", "replace")
            except Exception:  # noqa: BLE001 — no spec here, fall through to baseline
                continue
            # Point the spec's server at the live target (the fixture pins
            # localhost:3000; the app may run on any port).
            spec = re.sub(r"(url:\s*)https?://[^\s\"']+", lambda m: m.group(1) + base, spec, count=1)
            ext = ".json" if path.endswith(".json") else ".yaml"
            (work / f"openapi{ext}").write_text(spec, encoding="utf-8")
            return f"/zap/wrk/openapi{ext}", "openapi"
        return url, None

    def _parse(self, text: str) -> list[Finding]:
        doc = json.loads(text)
        findings: list[Finding] = []
        for site in doc.get("site") or []:
            site_name = site.get("@name") or "unknown"
            for alert in site.get("alerts") or []:
                severity = _RISK_MAP.get(str(alert.get("riskcode", "1")), Severity.LOW)
                instances = alert.get("instances") or []
                location = (instances[0].get("uri") if instances else None) or site_name
                cwe = alert.get("cweid")
                findings.append(
                    Finding(
                        tool=self.name,
                        family=self.family,
                        rule=f"zap-{alert.get('pluginid', 'unknown')}",
                        severity=severity,
                        message=alert.get("alert") or alert.get("name") or "ZAP alert",
                        location=location,
                        cwes=[f"CWE-{cwe}"] if cwe and str(cwe) not in ("-1", "0") else [],
                        extra={"instances": len(instances)},
                    )
                )
        return findings
