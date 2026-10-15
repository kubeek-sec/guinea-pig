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

## Running them

Everything runs in docker — no language toolchain is needed on the host.

```bash
docker compose -f projects/compose.yml up -d --build   # all twenty
docker compose -f projects/compose.yml up -d python go # a subset
docker compose -f projects/compose.yml ps              # which port is which
docker compose -f projects/compose.yml down -v         # stop, drop the volumes
```

`app` is published on `127.0.0.1:81NN`, `app-patched` on `127.0.0.1:82NN`, in the
order of the table below. Each service keeps its SQLite file and its uploads in a
named volume, so `down -v` gives every application a clean workshop again.

| # | Language | app | app-patched |
|--:|---|---|---|
| 1 | python | 8101 | 8201 |
| 2 | go | 8102 | 8202 |
| 3 | typescript | 8103 | 8203 |
| 4 | java | 8104 | 8204 |
| 5 | csharp | 8105 | 8205 |
| 6 | php | 8106 | 8206 |
| 7 | ruby | 8107 | 8207 |
| 8 | rust | 8108 | 8208 |
| 9 | c | 8109 | 8209 |
| 10 | cpp | 8110 | 8210 |

A single application, without compose:

```bash
docker build -t toolshed-python projects/python/app
docker run --rm -p 8000:8000 -e TOOLSHED_TOKEN_KEY=change-me toolshed-python
```

## Checks

```bash
python3 benchmark/src/build_report.py              # structure + hint lint + anchors → ground truth
python3 benchmark/src/build_report.py --skip-lint  # while drafting
projects/verify.sh                                 # build + run + exercise all twenty containers
projects/verify.sh go rust                         # only these languages
VARIANTS="app" projects/verify.sh                  # skip the patched variants
```

`verify.sh` builds each image, runs it, waits for `runtime.health`, then exercises
the whole API over HTTP — catalogue, sorting, search, sign-in, role checks, token
rejection, the rental cycle and the photo upload — and exits non-zero on the first
application that misbehaves. It is the quickest way to tell that a change to an
application has not broken it.

`build_report.py` fails when an application has no `Dockerfile`, no OpenAPI document,
a README missing one of the required sections / a `http://localhost…` URL / the
OpenAPI URL, when `app/` contains a hint word, or when a `dataset/<lang>.json` anchor
does not match exactly one line.

## Benchmark

```bash
uv run python benchmark/src/benchmark.py run --theme projects        # SAST / SCA / SECRET / IAC, line-level
uv run python benchmark/src/benchmark.py run --theme projects-dast   # docker build + run each app and app-patched, DAST
```
