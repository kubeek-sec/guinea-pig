# dsbench — vendored deep-scan scanner engine

This package is **vendored** (copied) from
`deep-scan/packages/core/src/deepscan_core` and trimmed to what the guinea-pig
benchmark needs. It is consumed only by `benchmark/src/benchmark.py`.

## What's here
- `scanners/` — the scanner contract (`base.py`) + every **detection** scanner
  (trivy ×3, osv-scanner, gitleaks, trufflehog, nosey_parker, titus, betterleaks,
  kingfisher, opengrep, plumber, nuclei, zaproxy, clamav, checkov, codeql, yara,
  mcp-threats, cisco-ai-skill-scanner) **plus** the `analysis` (AST/code-graph,
  taint) and `reachable-deps` scanners.
- `install/` — the secure tool installer (download + SHA-256 verify / docker pull /
  `uv tool install` / system package) and the pinned `catalog.py`.
- `models.py`, `config.py` (`.env`-driven), `sarif.py`, `dedup.py`, `runner.py`,
  `registry.py`, `validation.py`, `metrics.py`, `log.py`, `data/scanner_rules/`.

## Diverged from upstream
- Removed the `ai/` package and the `ai-analysis` LLM scanner (out of scope here).
- Removed the HTML graph viz (`analysis/graph_html.py`, `graph_view.py`).
- `scanners/base.py`: `files("deepscan_core")` → `files("dsbench")`.
- `install/__init__.py`: UV scanners (cisco-ai-skill-scanner, checkov) run through
  **this project's uv** — `uv_run_command` returns `uv run --with <pkg>==<ver> <exe>`
  (isolated, version-pinned overlay) instead of a global console script / `uvx`, and
  `is_installed` for UV reflects uv availability. This keeps tools with conflicting
  deps (cisco needs importlib-metadata≥8, checkov <8) out of one shared env, with no
  global `uv tool install` and no pip `--user`.
- `scanners/titus.py`: pass `--accessibility public` to `titus scan`. By default
  titus treats a local (non-git) target as "private" (−25 score penalty) and
  auto-rejects every finding, so `report` returns 0. `public` surfaces titus's raw
  detection recall (0% → 63% on the secret fixtures), which is what the benchmark
  measures. (Worth porting upstream.)
- `scanners/zap.py`: when the target exposes an OpenAPI/Swagger spec, drive an
  **active** `zap-api-scan.py -f openapi` against every imported endpoint instead
  of the passive `zap-baseline.py` (which never discovers parameterized routes).
  The spec's server URL is rewritten to the live target. DAST recall 0% → 88%.
- `scanners/nuclei.py`: import the OpenAPI spec (`-input-mode openapi -dast`) to
  fuzz the endpoints, and parse **JSONL** (`-jsonl-export`) instead of SARIF — the
  SARIF export drops the matched URL and CWE that endpoint-grading needs.
- `analysis/treesitter_scan.py`: fixed multi-language coverage — `_callee_text`
  now derives the callee from the call node's argument-list child (chained calls
  like `Runtime.getRuntime().exec(x)` keep their `.exec` tail; **java + c#** were
  silently missed before), and the sink matcher tries every dotted **suffix** (so a
  key like `Process.Start` matches `System.Diagnostics.Process.Start`). Python is
  also routed through the tree-sitter pass (coarse risk-zones complementing the
  precise taint engine, deduped by location in `engine.py`). Static SAST recall for
  `analysis` 31% → 50%. Needs the `tree-sitter-<lang>` grammars — all in the project
  uv (`pyproject.toml`).

## Refreshing from deep-scan
Re-copy the upstream tree, then re-apply the two divergences above (drop `ai/` +
`ai_analysis` from `scanners/__init__.py`, fix the `files(...)` package name).
The tools are resolved from `DEEPSCAN_TOOLS_DIR` (default
`~/.local/share/deepscan/tools`), so binaries installed by deep-scan are reused.

> Heavy deps (`tree_sitter`, `sentry_sdk`) are imported lazily — the package
> imports cleanly without them; `analysis`'s multi-language layer simply degrades
> (its Python taint layer is pure `ast` and always works).