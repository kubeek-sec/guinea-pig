# Ground-truth catalogs — schema & update procedure

The benchmark grades scanners against a **uniform ground-truth file per theme**,
all centralized under `benchmark/ground-truth/`. Each file is **generated**, not
hand-written — `benchmark/src/build_report.py` walks the fixture tree (plus two
small sidecars) and derives every entry.

```bash
python3 benchmark/src/build_report.py   # regenerate all five catalogs
```

## One file per theme (in `benchmark/ground-truth/`)

| File | Fixture family | Positives | Negatives |
|---|---|---|---|
| `benchmark/ground-truth/static.json` | SAST / IAC / PIPELINE / SECRET source fixtures | `vulnerable.*` (+ secret catalogue) | `patched.*` + look-alikes |
| `benchmark/ground-truth/pipeline.json` | SCA manifests + CI/CD configs + the `bumpy` pyyaml project | one per CWE per file | — |
| `benchmark/ground-truth/dynamic.json` | DAST endpoints (`dynamic/app.js`) | one per endpoint (endpoint-graded) | — |
| `benchmark/ground-truth/llm.json` | context-stripped UUID twins | one per weakness (`source` backref) | — |
| `benchmark/ground-truth/skills.json` | Agent skill fixtures | malicious skills | benign / benign-look-alike skills |

All five share the **same envelope**:

```jsonc
{
  "schema_version": "5.0",
  "theme":            "static",
  "report":           { ... },          // metadata, scanner_families, field glossary
  "summary":          { ... },          // counts: positives, negatives, by_*
  "positives":        [ { ... }, ... ], // a scanner SHOULD detect these
  "negatives":        [ { ... }, ... ], // a scanner should NOT flag these
  "secret_catalogue": { ... }           // static/ only — expanded by the benchmark
}
```

`benchmark/src/benchmark.py` loads each theme's catalog and scores the scanners against it.

## `positives[]`

| Field | Description |
|---|---|
| `id` | `GP-<FAMILY>-<NNN>` (e.g. `GP-SAST-007`, `GP-DAST-002`, `GP-SKILL-001`) |
| `analysis` | `static` (source), `dynamic` (DAST), or `skill` |
| `scanner_types` | families able to detect it: `SAST`, `IAC`, `PIPELINE`, `SECRET`, `DAST`, `SCA`, `SKILL` (a list — e.g. hard-coded creds are `["SAST","SECRET"]`) |
| `language` | fixture language/ecosystem (`python`, `terraform`, `github`, `env`, `http`, `skill`, …) |
| `cwe` | `[{ "id": "CWE-89", "name": "…" }]` (empty for skills) |
| `expected_cwe` | **ground truth** CWE for `benchmark.py` (`null` for skills — use `category`) |
| `category` | skills only: `secret-exfiltration`, `remote-code-execution`, `sabotage`, `unexpected-side-effect`, `prompt-injection` |
| `severity` | from the CWE severity map (or the authored skill severity) |
| `location` | `{ file, start_line, snippet }` (dynamic entries also carry `endpoint`) |
| `patched` | path to the remediated sibling (static only; `null` otherwise) |
| `source` | **llm only** — the original annotated fixture, held back from the model under test |
| `indicators` | skills only — the concrete signals planted in the fixture |
| `description` | one-line description |

## `negatives[]`

| Field | Description |
|---|---|
| `id` | `FP-<NNN>` / `GP-FP-SKILL-<NNN>` |
| `kind` | `remediation` (a `patched.*`), `lookalike` (benign code resembling a rule), `benign`, or `benign-lookalike` (a skill that touches secrets but handles them safely) |
| `expect` | always `no-finding` — a report here is a benchmark **false positive** |
| `scanner_types` | the family that would scan this file (informational) |
| `file` | path that must stay clean |
| `resembles` / `reason` | which rule it mimics and why it's benign |

## `secret_catalogue` (static only)

`{ dir, expected_cwe, scanner_types, files, providers, note, entries[] }`. Every
per-rule secret example is enumerated in `entries[]`
(`{ id: SEC-NNNN, provider, rule, name, file, detected_by:[…], examples }`) — all
CWE-798 positives. The benchmark also expands `dir` directly, file by file.

## Generator inputs (single source of truth)

`benchmark/src/build_report.py` holds:
- `CWE_INFO` — canonical CWE name + default severity (add new CWEs here);
- `LANG_SCANNER` / `SECRET_ALSO` — language → scanner type, and CWEs a secret scanner also catches;
- `SCA_MANIFESTS` / `PIPELINE_SAST` — the whole-file SCA manifests (incl. `bumpy`) and source-level sinks inside pipeline projects.

Two **irreducible authored sidecars** live next to it:
- `benchmark/src/llm_sources.json` — the opaque `llm/<uuid>` → `source` map (cannot be derived from the tree). The generator joins it with the freshly-built positives to (re)emit `benchmark/ground-truth/llm.json`, so the llm catalog stays in sync with the originals.
- `benchmark/src/skills_labels.json` — the authored verdicts/categories for `skills/` (the `SKILL.md` files carry no in-file marker by design).

## Update procedure

1. **Static**: add `static/CWE-<n>/<language>/vulnerable.<ext>` (+ `patched.<ext>`), with header:
   ```
   <comment> CWE-<n>: <CWE official name>
   <comment> <one-sentence description>
   <comment> Vulnerable sink: <the exact function/pattern>
   ```
2. **DAST**: add a path to `dynamic/app.js` and `dynamic/openapi.yml` (with `x-cwe:` and `x-vuln:`).
3. **SCA / pipeline project**: add the manifest to `SCA_MANIFESTS` (and any source sink to `PIPELINE_SAST`).
4. **Skill**: drop a `skills/{malicious,benign}/<name>/SKILL.md` and add its label/category/indicators to `benchmark/src/skills_labels.json`.
5. If the CWE is new, add it to `CWE_INFO`.
6. Run `python3 benchmark/src/build_report.py`; the benchmark picks it up automatically (it reads every `benchmark/ground-truth/*.json`).

## Related files

- `benchmark/ground-truth/<theme>.json` — the five generated catalogs (ground truth).
- `benchmark/src/build_report.py` — the generator (single source of truth).
- `benchmark/src/benchmark.py` — runs the scanners and scores them (engine vendored under `src/dsbench/`).
- `benchmark/INVENTORY.md` — human recap (CWE × language matrix, totals).

```bash
python3 -c "import json; \
print(sum(json.load(open(f'benchmark/ground-truth/{t}.json'))['summary']['positives'] \
for t in ['static','pipeline','dynamic','llm','skills']), 'positives total')"
```