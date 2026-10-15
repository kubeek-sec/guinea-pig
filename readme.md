
# Guinea Pig

![Guinea Pig](guinea-pig.png)

## Description
This repo is a **security-scanner test bed**: complete applications per language
with their weaknesses, the same applications fixed, a secret catalogue covering every
rule of [`secret-rules`](https://github.com/kubeek-sec/secret-rules), supply-chain /
CI fixtures and Agent-skill fixtures — each graded against a generated ground truth.

### Layout
```
projects/<lang>/app/                     # a complete application (README, Dockerfile, OpenAPI) — no hint in the code
projects/<lang>/app-patched/             # the same application, every weakness fixed (fixes explained here only)
dataset/<lang>.json                      # ground truth of projects/<lang>: weaknesses (anchors), deps, decoys
dataset/lint.json                        # words app/ must not contain (CWE ids, "vuln", "unsafe" comments…)
secrets/catalogue/<provider>/*.txt       # one example per secret rule (1157 files, all 1667 rules covered)
secrets/fixtures/CWE-<n>/<format>/       # vulnerable/patched secret fixtures (env, ini, conf, pem, code, IaC)
secrets/false-positives/*                # benign look-alikes (precision)
secrets/tools/                           # coverage check + generator against secret-rules/referential/rules.yaml
pipeline/sca/<eco>/<manifest>            # vulnerable dependency manifests (SCA)
pipeline/ci/<platform>/...               # realistic CI files (plumber / poutine)
skills/{malicious,benign}/<name>/SKILL.md  # Agent-skill fixtures for skill scanners
benchmark/ground-truth/<theme>.json      # generated ground truth: secrets, projects, pipeline, skills
```

- **projects** — SAST, SCA, SECRET, IaC (static, graded by file + line) and DAST
  (each app built and run in docker, graded by endpoint). See
  [`projects/README.md`](projects/README.md) and [`dataset/README.md`](dataset/README.md).
- **secrets** — SECRET scanners: catalogue (recall), fixtures (vulnerable/patched),
  look-alikes (precision). See [`secrets/catalogue/README.md`](secrets/catalogue/README.md).
- **pipeline** — SCA + CI/CD, see [`pipeline/README.md`](pipeline/README.md).
- **skills** — skill scanners, see [`skills/README.md`](skills/README.md).

### Ground truth & benchmark
```bash
python3 benchmark/src/build_report.py                    # checks projects + regenerates the ground truth
uv run python benchmark/src/benchmark.py install --all   # install scanner tools
uv run python benchmark/src/benchmark.py run             # static themes
uv run python benchmark/src/benchmark.py run --all       # + projects-dast (docker)
```
The ground-truth files are **generated** — never edit them by hand. Details:
[`benchmark/README.md`](benchmark/README.md), [`benchmark/GROUND-TRUTH.md`](benchmark/GROUND-TRUTH.md).

## Adding fixtures

- **An application** — `projects/<lang>/app` + `app-patched` following
  [`projects/README.md`](projects/README.md), and its `dataset/<lang>.json`
  ([schema](dataset/README.md)).
- **A weakness in an application** — code in `app/`, fix in `app-patched/`, entry in
  `dataset/<lang>.json` (anchors = unique substrings of the lines).
- **A secret fixture** — `secrets/fixtures/CWE-<n>/<format>/vulnerable.<ext>` + `patched.<ext>`
  with a 3-line header (`CWE-<n>: <name>`, description, `Vulnerable sink: …`).
- **A secret rule example** — run `secrets/tools/coverage.py` then `secrets/tools/gen.py`.
- **A benign look-alike** — `secrets/false-positives/` with `Resembles:` / `Why benign:` header.
- **SCA manifest / CI file** — see the `SCA_MANIFESTS` / `PIPELINE_SAST` tables in
  `benchmark/src/build_report.py`; CI files mention each CWE in a comment.
- **Skill fixture** — `skills/{malicious,benign}/<name>/SKILL.md` + its verdict in
  `benchmark/src/skills_labels.json`.
- **New CWE** — add it to `CWE_INFO` in `benchmark/src/build_report.py`.

Then run `python3 benchmark/src/build_report.py`.


## VSCode configuration
The MCP server is declared in `.vscode/mcp.json` (`security-mcp-server` →
`http://127.0.0.1:8000/mcp/`). Open VSCode's MCP **Servers** view and **Start** it.
You may need to be signed in to GitHub Copilot for it to work.

## Claude code configuration 
```
claude mcp add --transport http --scope project my-serveur http://127.0.0.1:8000/mcp/
```


## Some prompts
### For all features secrets, sca and sast
```
Please scan my project for security vulnerabilities about secrets, sca and sast. Provide me a prioritization of identified vulnerabilities. And propose a modification of the code.

```

### For only secrets
```
Could you provide me with a list of all the secrets in this repo?
```

## Sources
- **SCA base fixtures** — adapted from
  https://github.com/dehvCurtis/vulnerable-code-examples
- **Hard-coded-secret config fixtures** (`env`, `ini`, `conf`, `pem`) — drawn from
  https://github.com/Yelp/detect-secrets/tree/master/test_data
- **Secret catalogue** (`secrets/catalogue/`, 1157 per-rule examples)
  — generated from the regex rule packs of kingfisher, titus, noseyparker,
  gitleaks and betterleaks in the sibling `../secret-rules` repo. The benign
  look-alikes in `secrets/false-positives/` are hand-written; the 129 entries added
  for full `rules.yaml` coverage are generated by `secrets/tools/gen.py`.

