# Ground-truth catalogs — schema & update procedure

The benchmark grades scanners against **one generated file per theme** under
`benchmark/ground-truth/`. They are produced by `benchmark/src/build_report.py`
— never edit them by hand.

```bash
python3 benchmark/src/build_report.py              # checks projects/, regenerates the 4 catalogs + INVENTORY.md
python3 benchmark/src/build_report.py --skip-lint  # same, without the "no hint in app/" check
```

## One file per theme

| File | Built from | Positives | Negatives |
|---|---|---|---|
| `secrets.json` | `secrets/` | `fixtures/**/vulnerable.*` (+ `secret_catalogue`: one entry per rule) | `fixtures/**/patched.*` + `false-positives/*` |
| `projects.json` | `dataset/<lang>.json` + `projects/<lang>/app{,-patched}` | one per weakness (static) + one per DAST endpoint + one per vulnerable dependency | the fixed line of every weakness + every decoy line |
| `pipeline.json` | `pipeline/` | SCA manifests, bumpy `yaml.load` sinks, one per CWE per CI file | — |
| `skills.json` | `skills/` + `src/skills_labels.json` | malicious skills | benign / benign-look-alike skills |

Common envelope:

```jsonc
{
  "schema_version": "6.0",
  "theme": "projects",
  "report":    { ... },          // metadata, scanner_families, field glossary
  "summary":   { ... },          // counts by analysis / scanner type / severity / language
  "positives": [ ... ],          // a scanner SHOULD detect these
  "negatives": [ ... ],          // a scanner should NOT flag these
  "secret_catalogue": { ... },   // secrets only
  "apps": [ ... ],               // projects only: app / patched / runtime per language
  "line_tolerance": 3            // projects only
}
```

## `positives[]`

| Field | Description |
|---|---|
| `id` | `GP-<FAMILY>-<NNN>` for path-derived fixtures; the authored id (e.g. `py-007`, `py-007-dast`, `py-dep-01`) for projects |
| `analysis` | `static`, `dynamic` (DAST, endpoint-graded) or `skill` |
| `scanner_types` | families able to detect it: `SAST`, `SCA`, `SECRET`, `IAC`, `PIPELINE`, `DAST`, `SKILL` |
| `language` | language / format |
| `cwe` / `expected_cwe` | CWE list (incl. `also_cwe`) and the ground-truth CWE (`null` for skills) |
| `severity` | authored, else the `CWE_INFO` default |
| `location` | `{ file, start_line, snippet }` — for projects, `start_line` is resolved from the anchor; DAST entries add `endpoint` |
| `alt_locations` | projects: `source` / `related` lines a scanner may report instead of the sink |
| `pattern` | projects: `direct`, `inter-file`, `second-order`, `sanitizer-mismatch`, `config`, … (see `dataset/README.md`) |
| `endpoint` | projects: `METHOD /path` when reachable over HTTP |
| `patched` | the remediated location (`{file, start_line, snippet}` for projects, a path for secret fixtures) |
| `package` / `version` / `advisories` / `reachable` | projects SCA entries |
| `category` / `indicators` | skills only |
| `description` | what is wrong |

## `negatives[]`

| Field | Description |
|---|---|
| `id` | `FP-…` |
| `kind` | `remediation` (fixed code), `lookalike` (decoy / benign look-alike), `benign`, `benign-lookalike` |
| `expect` | always `no-finding` |
| `file` / `start_line` | must-stay-clean location (`start_line`: projects only) |
| `expected_cwe` | the CWE it resembles (projects) |
| `resembles` / `reason` | what it mimics and why it is safe |

## Generator inputs

- `dataset/<lang>.json` — authored ground truth of each application ([schema](../dataset/README.md));
- `dataset/lint.json` — hint words forbidden in `projects/<lang>/app` and README requirements;
- `benchmark/src/build_report.py` — `CWE_INFO` (names + default severity), `SCA_MANIFESTS` /
  `PIPELINE_SAST` (pipeline theme);
- `benchmark/src/skills_labels.json` — skill verdicts.

## Update procedure

1. **Application**: edit `projects/<lang>/app` and `app-patched`, then `dataset/<lang>.json`.
2. **Secret fixture**: `secrets/fixtures/CWE-<n>/<format>/vulnerable.<ext>` + `patched.<ext>` with the 3-line header.
3. **Secret rule example**: `secrets/tools/coverage.py` then `secrets/tools/gen.py`.
4. **SCA / pipeline project**: `SCA_MANIFESTS` / `PIPELINE_SAST`; CI files mention each CWE in a comment.
5. **Skill**: `skills/{malicious,benign}/<name>/SKILL.md` + `benchmark/src/skills_labels.json`.
6. New CWE → `CWE_INFO`.
7. `python3 benchmark/src/build_report.py`.
