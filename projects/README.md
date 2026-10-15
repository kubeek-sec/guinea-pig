# projects/ — one complete application per language

```
projects/<lang>/app/            the application
projects/<lang>/app-patched/    the same application, fixed
```

Ground truth lives **only** in [`../dataset/<lang>.json`](../dataset/README.md).

## Rules for every application

1. **Complete and runnable** — a real product (its own domain, data model, several
   features), built and started with its `Dockerfile`, listening on the port given in
   `dataset/<lang>.json` (`runtime.port`), with a health URL (`runtime.health`).
2. **OpenAPI** — an `openapi.yml` (or `.yaml` / `.json`) describing every endpoint,
   served by the running app at `runtime.openapi` so DAST tools can import it.
3. **README.md** — use [`README.template.md`](README.template.md): overview, features,
   build, run, URLs, OpenAPI / Swagger URLs, configuration.
4. **`app/` gives no hint** — ordinary names, ordinary comments, ordinary README. No
   CWE ids, no "vuln/unsafe/insecure/bad_…" identifiers, no comments pointing at a
   flaw. Enforced by `build_report.py` with the patterns of
   [`../dataset/lint.json`](../dataset/lint.json).
5. **`app-patched/` explains** — same tree, every weakness fixed in place; comments
   explaining each fix are welcome *here only*. Decoys (safe code that looks risky)
   stay identical in both.

## Checks

```bash
python3 benchmark/src/build_report.py              # structure + hint lint + anchors → ground truth
python3 benchmark/src/build_report.py --skip-lint  # while drafting
```

`build_report.py` fails when an application has no `Dockerfile`, no OpenAPI document,
a README missing one of the required sections / a `http://localhost…` URL / the
OpenAPI URL, when `app/` contains a hint word, or when a `dataset/<lang>.json` anchor
does not match exactly one line.

## Benchmark

```bash
uv run python benchmark/src/benchmark.py run --theme projects        # SAST / SCA / SECRET / IAC, line-level
uv run python benchmark/src/benchmark.py run --theme projects-dast   # docker build + run each app and app-patched, DAST
```
