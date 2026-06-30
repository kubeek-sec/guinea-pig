"""Gitleaks: hardcoded secrets in the working tree."""

from __future__ import annotations

from ..models import Family, Finding, Mode
from ..sarif import parse_sarif
from .base import ScanContext, Scanner, ScannerSkipped


class Gitleaks(Scanner):
    name = "gitleaks"
    family = Family.SECRET
    mode = Mode.STATIC
    tool = "gitleaks"
    description = "Hardcoded secrets, API keys and tokens"

    @staticmethod
    def _build_cmd(binary: str, target, out, config_file=None) -> list[str]:
        cmd = [
            binary, "dir", str(target),
            "--report-format", "sarif", "--report-path", str(out),
            "--exit-code", "0", "--no-banner",
        ]
        if config_file is not None:  # operator config/gitleaks/*.toml
            cmd += ["--config", str(config_file)]
        return cmd

    async def _execute(self, ctx: ScanContext) -> list[Finding]:
        if ctx.target_path is None:
            raise ScannerSkipped("Static scanner needs a directory target.")
        out = ctx.work_dir / f"{self.name}.sarif"
        cmd = self._build_cmd(
            str(self.binary()), ctx.target_path, out, self.config_file("*.toml")
        )
        code, _stdout, stderr = await self._run(cmd)
        if not out.is_file():
            raise RuntimeError(f"gitleaks exited {code} without report: {stderr[-500:]}")
        text = out.read_text(encoding="utf-8")
        self.save_raw(ctx, f"{self.name}.sarif", text)
        findings = parse_sarif(text, tool=self.name, family=self.family)
        for finding in findings:
            finding.cwes = finding.cwes or ["CWE-798"]
        return findings
