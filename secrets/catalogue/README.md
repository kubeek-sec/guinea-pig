# CWE-798 — Secret Catalogue

Detectable-secret examples, one file per rule, built from the regex configs of every
scanner in `/media/workspace/projects/security/secret-rules`:

| Scanner | Version | Config | Rules |
|---|---|---|---|
| kingfisher | v1.102.0 | one `.yml` per provider | 954 |
| titus | v1.2.2 | one `.yml` per provider | 499 |
| noseyparker | v0.24.0 | one `.yml` per provider | 189 |
| betterleaks | v1.4.1 | single `betterleaks.toml` | 305 |
| gitleaks | v8.30.1 | single `gitleaks.toml` | 222 |

## Layout

```
catalogue/
  <provider>/<rule>.txt        one file per distinct rule (e.g. anthropic/anthropic.1.txt)
  _regex-scanner-only/<id>.txt  rules that exist only in the gitleaks/betterleaks configs
```

**1157 files across 591 providers.**

## How rules were grouped

The same secret type is detected by several scanners under near-identical rule ids
(`kingfisher.anthropic.1`, `np.anthropic.1`, …). Rules are merged into one catalogue
entry per `(provider, normalized-id)`, where the normalized id drops the scanner
prefix (`kingfisher.` / `np.`). Each file's header lists every scanner + rule id that
fires on it. The single-file regex scanners (gitleaks, betterleaks) are matched to the
provider and listed under *Related provider rules*.

## Content of each file

- A header comment: rule name, provider, the scanners/ids that detect it, and the regex.
- One or more example secrets.

Examples come straight from the scanners' own test corpora (`examples:` in the YAML
rules); the 14 entries under `_regex-scanner-only/` are synthesized to match the regex
and verified with Python `re`. **All values are fake — placeholders that match the
detection regex but are not live credentials — and are safe to commit.**

## Coverage of the secret-rules referential

Every rule of `kubeek-sec/secret-rules` `referential/rules.yaml` (1667 rules) fires
on at least one catalogue example (regex match on the rule's `secret_group`):

```bash
python3 secrets/tools/coverage.py ../secret-rules/referential/rules.yaml secrets/catalogue /tmp/cov.json
python3 secrets/tools/gen.py      ../secret-rules/referential/rules.yaml /tmp/cov.json secrets/catalogue
```

`coverage.py` reports `covered` / `low_entropy` (regex hit but the secret is below the
rule's `entropy`) / `uncovered`; `gen.py` writes `<topic>/<uid>.txt` for the missing
ones, from the rule's own `examples:` when they pass, else synthesized from the regex
(`re2py.py` translates the RE2-only constructs: mid-pattern `(?i)`, `\z`). 129 entries
were added this way.

Five rules have an entropy threshold that no string matching their secret group can
reach (their entries are best-effort and say so in the header):
`asana-client-id-3`, `discord-bot-id` (digits only: max 3.32 < 3.5),
`kubernetes-bootstrap-token-pair` (6 chars: max 2.58 < 2.8),
`sendbird-api-token` (40 hex: max < 4.0), `contains-encrypted-rsa-private-key`
(secret group 1 is the `-----BEGIN…` header line, < 4.5).

See `../false-positives/` for the companion set: benign source code that *looks* like
these rules but must not be flagged.
