# Scanner detection benchmark

A **self-contained** benchmark: it runs a fleet of real security scanners against
the guinea-pig fixtures and grades each one against the **uniform per-theme ground
truth** (the five `benchmark/ground-truth/<theme>.json` files, documented in
[`GROUND-TRUTH.md`](./GROUND-TRUTH.md)).

Two pieces:

- **`src/dsbench/`** — the scanner engine, **vendored** from deep-scan (see
  [`src/dsbench/VENDORED.md`](./src/dsbench/VENDORED.md)): the scanner contract,
  every detection scanner + the `analysis` (AST/code-graph) scanner, a secure
  pinned-tool installer, and the normalized model.
- **`src/benchmark.py`** — the CLI: install the tools, run scanners per theme,
  map findings to the ground truth, and emit the recap + top-3 tables.

The old SARIF/`security_mcp` scorer is gone — the scanners now run **in-process**.

## Quick start

The benchmark runs through **uv** — the project env (`pyproject.toml`) provides
the tree-sitter grammars the `analysis` scanner needs for multi-language coverage.
`uv sync` once, then `uv run`. Plain `python3 benchmark/src/benchmark.py` also
works, but `analysis` then only covers Python (its pure-`ast` taint layer).

```bash
# 0) set up the Python env (tree-sitter grammars for the `analysis` scanner)
uv sync

# 1) install the scanner tools (download + SHA-256 verify / docker / uv / system)
uv run python benchmark/src/benchmark.py install --all
uv run python benchmark/src/benchmark.py install gitleaks opengrep   # or a subset
uv run python benchmark/src/benchmark.py list                        # scanners + install status

# 2) run the benchmark
uv run python benchmark/src/benchmark.py run                    # every static theme (default)
uv run python benchmark/src/benchmark.py run --all              # incl. projects-dast (docker build + run of every app)
uv run python benchmark/src/benchmark.py run --theme projects   # a single theme
uv run python benchmark/src/benchmark.py run --theme skills --scanner cisco-ai-skill-scanner
```

Output goes to `benchmark/results/bench_<timestamp>/` (git-ignored):
`benchmark.md` (the tables below) and `benchmark.json` (machine-readable), plus
each scanner's raw output under `raw/<theme>/`.

## Themes & modes

| Theme | Target | Mode | Scanners that apply |
|---|---|---|---|
| `secrets` | `secrets/` | static | SECRET (+ SAST/IaC for in-code credentials) |
| `projects` | `projects/<lang>/app{,-patched}` | static | SAST, SCA, SECRET, IaC — graded by **file + line** (±3) |
| `pipeline` | `pipeline/` | static | SCA, PIPELINE, SAST |
| `skills` | `skills/` | static | the skill scanner + malicious-intent (yara, mcp-threats) |
| `projects-dast` | every app, running in docker | **dynamic** | DAST (nuclei, zaproxy) — graded by endpoint |

- **Default** (`run` with no flag) = every static theme (nothing to launch).
  `--all-except-dast` is the explicit form.
- `--all` adds `projects-dast`: for each `dataset/<lang>.json`, the runner builds
  `app/` and `app-patched/` with their `Dockerfile`, runs each on a free local port,
  waits for `runtime.health`, scans the URL (the scanners import `runtime.openapi`)
  and removes the container. A hit on the patched app (same endpoint, same CWE) is a
  false positive.
- `--theme <name>` runs exactly one.
- `--scanner a,b,c` restricts to named scanners (filtered to the theme's mode).

### How `projects` is graded

- a finding **hits** a weakness when it is in the sink's file — or one of its
  `source` / `related` files — within ±3 lines; ✓ when its CWE matches;
- an SCA finding hits a dependency when it is on its manifest and names the package;
- a finding on the fixed line of `app-patched/` or on a decoy line is a **false
  positive**; any other finding under `projects/` is **noise**.

## What it reports

`benchmark.md` contains four sections:

1. **Recap — per scanner & theme**: `applicable` positives, `found` (with
   ✓ = CWE-accurate), `missed`, `extra` (cross-family detections credited outside
   the scanner's expected scope), `FP` (reports on a `patched.*`/look-alike/benign
   negative, a fixed line or a decoy), `noise` (reports on non-fixture files /
   unlisted lines) and `recall`.
2. **Top 3 scanners per theme**: ranked by recall over applicable positives, then
   CWE-accuracy, then fewer false positives.
3. **Not found by any scanner** (per theme): the positives no scanner caught —
   visibility on coverage gaps.
4. **False positives & noise** (per scanner): the exact negatives/non-fixtures
   each scanner wrongly flagged.

A scanner's **expected scope** (the recall denominator) is the `SCOPE` map in
`benchmark.py` (e.g. gitleaks→SECRET, opengrep→SAST/IAC/PIPELINE, trivy→SCA). A
detection on **any** fixture is still credited regardless of family — scope only
decides what counts as a *miss*.

## Disabling scanners (`.env`)

Every scanner is toggled by an env var — its name UPPER-CASED with `-`/space →
`_` — read from the environment or a `.env` in the working directory:

```bash
CODEQL=false        # slow (per-language DB build)
ZAPROXY=false       # needs docker
KINGFISHER=false
```

See [`.env.example`](../.env.example) at the repo root. Tuning knobs
(`DEEPSCAN_TIMEOUT`, `DEEPSCAN_PARALLEL`, `DEEPSCAN_TOOLS_DIR`, …) live there too.

## Ground truth

The four `benchmark/ground-truth/<theme>.json` catalogs (`secrets`, `projects`, `pipeline`, `skills`) are generated by
`benchmark/src/build_report.py` from the fixtures (see
[`GROUND-TRUTH.md`](./GROUND-TRUTH.md)). Re-run it after adding or changing
fixtures; the benchmark reads them directly.