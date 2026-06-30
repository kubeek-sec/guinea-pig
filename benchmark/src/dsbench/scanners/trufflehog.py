"""TruffleHog: secrets via regex + entropy. Native JSON-lines output is
normalized directly; raw secret values are never copied into findings."""

from __future__ import annotations

import json

from ..models import Family, Finding, Mode, Severity
from .base import ScanContext, Scanner, ScannerSkipped


class Trufflehog(Scanner):
    name = "trufflehog"
    family = Family.SECRET
    mode = Mode.STATIC
    tool = "trufflehog"
    description = "Secrets via regex + entropy analysis (no remote verification)"

    async def _execute(self, ctx: ScanContext) -> list[Finding]:
        if ctx.target_path is None:
            raise ScannerSkipped("Static scanner needs a directory target.")
        cmd = [
            str(self.binary()),
            "filesystem",
            str(ctx.target_path),
            "--json",
            "--no-update",
            "--no-verification",
        ]
        cfg = self.config_file("*.yaml", "*.yml")  # operator config/trufflehog/ custom detectors
        if cfg is not None:
            cmd += ["--config", str(cfg)]
        _code, stdout, _stderr = await self._run(cmd)
        self.save_raw(ctx, f"{self.name}.jsonl", stdout)
        findings: list[Finding] = []
        for line in stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
            except ValueError:
                continue
            detector = event.get("DetectorName")
            if not detector:
                continue
            meta = (
                ((event.get("SourceMetadata") or {}).get("Data") or {}).get("Filesystem") or {}
            )
            file = meta.get("file") or "unknown"
            line_no = meta.get("line")
            redacted = event.get("Redacted") or ""
            message = f"Potential {detector} secret"
            if redacted:
                message += f" (redacted: {redacted})"
            findings.append(
                Finding(
                    tool=self.name,
                    family=self.family,
                    rule=f"trufflehog-{detector.lower()}",
                    severity=Severity.CRITICAL if event.get("Verified") else Severity.HIGH,
                    message=message,
                    location=f"{file}:{line_no}" if line_no else file,
                    cwes=["CWE-798"],
                )
            )
        return findings
