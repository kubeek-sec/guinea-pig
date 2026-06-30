"""``plumber`` scanner — CI/CD pipeline compliance (getplumber/plumber).

Plumber audits pipeline/CI configuration for risky patterns: unpinned container
images and GitHub Actions, action CVEs, branch-protection gaps, unsafe script
execution and secrets leaked in pipeline YAML. We run ``plumber analyze`` over
the target and read its **SARIF** output, parsed into normalized ``Finding``
objects like every other scanner.

It auto-detects the git provider from the repo's remote; provider-specific checks
(action CVEs, branch protection) use ``GH_TOKEN`` / ``GITHUB_TOKEN`` /
``GITLAB_TOKEN`` from the environment when present, and are simply skipped
otherwise. Plumber requires a ``.plumber.yaml`` policy file; we honour the
target's own if present, otherwise we generate the default one into the scratch
dir (never writing into the scanned repo). Disable with ``PLUMBER=false``.
"""

from __future__ import annotations

import os
from pathlib import Path

from ..models import Family, Finding, Mode
from ..sarif import parse_sarif
from .base import ScanContext, Scanner, ScannerSkipped


class Plumber(Scanner):
    name = "plumber"
    family = Family.PIPELINE
    mode = Mode.STATIC
    tool = "plumber"
    description = "CI/CD pipeline compliance (action/image pinning, branch protection, pipeline secrets)"

    async def _execute(self, ctx: ScanContext) -> list[Finding]:
        if ctx.target_path is None:
            raise ScannerSkipped("plumber needs a directory target.")
        binary = self.binary()  # skips cleanly if not installed

        # plumber's local scan audits a git checkout — it derives the provider
        # (and branch-protection / action-CVE context) from the repo's remote.
        # A target with no .git (e.g. a zip upload) can't be scanned locally, so
        # skip cleanly rather than erroring.
        if not (ctx.target_path / ".git").is_dir():
            raise ScannerSkipped(
                "plumber audits a git repository's CI/CD config; this target is "
                "not a git checkout (scan a git URL / cloned repo for pipeline checks)."
            )
        # Disable plumber's "newer version available" update check: it makes a
        # network call that, in a restricted-egress container, fails and makes
        # plumber exit non-zero without writing SARIF.
        env = {**os.environ, "PLUMBER_NO_UPDATE_CHECK": "1"}
        config = await self._config(ctx, binary, env)
        sarif = ctx.work_dir / "plumber.sarif"
        cmd = [str(binary), "analyze", "--config", str(config), "--sarif", str(sarif)]
        code, stdout, stderr = await self._run(cmd, cwd=ctx.target_path, env=env)
        if not sarif.is_file():
            raise ScannerSkipped(
                f"plumber produced no SARIF (exit {code}): "
                f"{(stderr or stdout).strip()[-200:] or 'no pipeline config found'}"
            )
        text = sarif.read_text(encoding="utf-8", errors="replace")
        self.save_raw(ctx, "plumber.sarif", text)
        return parse_sarif(text, tool=self.name, family=self.family)

    async def _config(self, ctx: ScanContext, binary: str, env: dict[str, str]) -> Path:
        """The policy file to use: the target's own ``.plumber.yaml`` if present,
        else an operator default in ``config/plumber/`` if provided, else a default
        generated into the scratch dir (the scanned repo is never modified)."""
        own = (ctx.target_path / ".plumber.yaml") if ctx.target_path else None
        if own and own.is_file():
            return own
        operator = self.config_file(".plumber.yaml", "*.yaml", "*.yml")
        if operator is not None:
            return operator
        generated = ctx.work_dir / ".plumber.yaml"
        _code, _out, err = await self._run(
            [str(binary), "config", "generate", "--output", str(generated), "--force"],
            cwd=ctx.work_dir,
            env=env,
        )
        if not generated.is_file():
            raise ScannerSkipped(
                f"plumber needs a .plumber.yaml and the default could not be generated: "
                f"{err.strip()[-200:]}"
            )
        return generated
