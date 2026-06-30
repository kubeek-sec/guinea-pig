"""``analysis`` scanner — code-graph security analysis (no AI).

Builds the graphify code graph (a knowledge base + structural summary, written
as ``graph.json``/``graph.html`` when raw output is kept) and layers a
deterministic security analysis over it:

* precise Python AST taint (source → sink across functions, sanitizer-aware);
* multi-language tree-sitter detection of dangerous call-sites ("risk zones").

It emits the same normalized ``Finding`` objects as every other scanner, so the
results flow through dedup, the four report formats, the API/kruncher and the
ASPM dashboard unchanged — and feed the ``ai-analysis`` triage scanner.
"""

from __future__ import annotations

import asyncio

from ..analysis import analyze_target
from ..models import Family, Finding, Mode
from .base import ScanContext, Scanner, ScannerSkipped


class Analysis(Scanner):
    name = "analysis"
    family = Family.ANALYSIS
    mode = Mode.STATIC
    tool = None  # pure-Python engine + vendored graphify, no managed binary
    description = "Code-graph (graphify) + taint/sanitization security analysis"

    async def _execute(self, ctx: ScanContext) -> list[Finding]:
        if ctx.target_path is None:
            raise ScannerSkipped("analysis scanner needs a directory target.")
        # The engine parses with ast/tree-sitter (CPU-bound, synchronous); run
        # it off the event loop so concurrent scanners are not blocked.
        result = await asyncio.to_thread(
            analyze_target, ctx.target_path, ctx.work_dir, ctx.raw_dir
        )
        if ctx.raw_dir is not None and result.graph_summary:
            import json

            self.save_raw(ctx, "analysis.json", json.dumps(
                {"graph_summary": result.graph_summary,
                 "artifacts": result.artifacts,
                 "findings": [f.to_dict() for f in result.findings]},
                indent=2,
            ))
        return result.findings
