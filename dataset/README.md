# dataset/ — ground truth of the `projects/` applications

One file per language: `dataset/<lang>.json`. It is the **only** place that says
where the weaknesses of `projects/<lang>/app` are — the applications themselves carry
no marker (no CWE ids, no hints in names or comments), so a scanner (or an LLM) has to
find them from the code and the running service alone.

`benchmark/src/build_report.py` reads these files, resolves every *anchor* to a line
number and emits `benchmark/ground-truth/projects.json`. An anchor that does not match
**exactly one line** of its file aborts the build, so the ground truth cannot silently
drift when the code is edited.

```bash
python3 benchmark/src/build_report.py      # validates anchors + regenerates the ground truth
```

## Layout

```
projects/<lang>/app/            the application, with its weaknesses
projects/<lang>/app-patched/    the same application, every weakness fixed (decoys kept)
dataset/<lang>.json             this ground truth
```

Both applications build and run with their own `Dockerfile`, listen on the port given
in `runtime.port` and serve their OpenAPI document at `runtime.openapi`, so DAST tools
can import every endpoint.

## Schema

```jsonc
{
  "language": "python",
  "app": "projects/python/app",
  "patched": "projects/python/app-patched",
  "runtime": {
    "port": 8000,                       // container port
    "openapi": "/openapi.yml",          // served by the app
    "health": "/healthz",               // GET → 200 once ready
    "env": { "KEY": "value" }           // optional extra container env
  },
  "weaknesses": [
    {
      "id": "py-007",                   // <lang-prefix>-NNN, stable
      "cwe": "CWE-89",                  // ground-truth CWE (the benchmark's expected_cwe)
      "also_cwe": ["CWE-943"],          // optional: other CWEs a scanner may legitimately report
      "title": "SQL injection in catalogue sort",
      "file": "toolshed/catalog.py",    // relative to `app`
      "anchor": "ORDER BY {order}",     // unique substring of the SINK line
      "source": { "file": "...", "anchor": "..." },   // optional: where the tainted data enters
      "related": [ { "file": "...", "anchor": "..." } ],   // optional: other lines a scanner may report
      "scanner_types": ["SAST", "DAST"],               // families expected to find it
      "endpoint": "GET /api/tools?sort=",              // when reachable over HTTP (DAST)
      "pattern": "inter-file",          // see below
      "severity": "High",               // optional, defaults to the CWE severity
      "description": "…",               // what is wrong and how it is reached
      "patched": { "file": "...", "anchor": "..." },   // the fixed line in `patched` (→ a negative)
      "fix": "…"                        // what the fix does
    }
  ],
  "dependencies": [
    {
      "id": "py-dep-01", "manifest": "requirements.txt", "anchor": "PyYAML==5.3.1",
      "package": "PyYAML", "version": "5.3.1", "advisories": ["CVE-2020-14343"],
      "reachable": true,                // is the vulnerable API actually called?
      "description": "…"
    }
  ],
  "decoys": [
    {
      "id": "py-decoy-01", "file": "...", "anchor": "...",   // present in BOTH app and app-patched
      "resembles": "CWE-78", "scanner_types": ["SAST"],
      "reason": "Fixed argv list, no shell, no user input."
    }
  ]
}
```

### `pattern` values

| value | meaning |
|---|---|
| `direct` | source and sink in the same function |
| `inter-procedural` | tainted value crosses one or more function calls in the same file |
| `inter-file` | source and sink live in different modules |
| `second-order` | input is stored first (DB, file, cache) and reaches the sink on a later request |
| `sanitizer-mismatch` | input *is* sanitised, but for another context (e.g. HTML-escaped then used in SQL / shell) |
| `incomplete-validation` | a check exists but can be bypassed (prefix check, deny-list, case, encoding, TOCTOU) |
| `config` | the code is fine, the configuration (framework flag, env default, Dockerfile, manifest) makes it vulnerable |
| `framework-specific` | needs framework knowledge to see (template auto-escape off, ORM raw fragment, …) |
| `business-logic` | no dangerous API involved: missing ownership / authorization / state check (mostly DAST) |
| `reachable-dependency` / `unreachable-dependency` | vulnerable library whose affected API is / is not used |
| `secret` | hard-coded credential or key |
| `memory` | memory-safety defect (C, C++, unsafe Rust) |

## How the benchmark grades `projects`

- **Static positives** — a scanner finding is a hit when it is in the same file as the
  sink (or one of `source` / `related`) within ±`line_tolerance` lines (3). The CWE is
  checked separately (`found_cwe` vs `found_hit`).
- **SCA positives** — a hit when the finding names the package (any location).
- **DAST positives** — graded per endpoint (path match, CWE match).
- **Negatives** — the `patched` line of every weakness and every decoy line (in both
  applications): a finding there (±tolerance) is a **false positive**. Other findings in
  `app-patched/` are reported as noise.

## Adding a weakness

1. Write it in `projects/<lang>/app/…` as ordinary product code.
2. Write the fix at the same place in `projects/<lang>/app-patched/…`.
3. Add the entry to `dataset/<lang>.json` (anchor = a substring unique in the file).
4. Run `python3 benchmark/src/build_report.py`.
