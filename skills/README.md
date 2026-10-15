# skills/ — AI skill-scanner detection corpus

Fixtures for grading **Agent / Claude-Code skill scanners** (e.g.
`ai-cisco-skill-scanner`). Unlike `projects/` (graded by source-code and DAST scanners), these are
**`SKILL.md` skills** — natural-language + script payloads — graded by a tool
that reasons about *what a skill instructs an agent to do*.

The corpus is split into **positives** the scanner **should flag** and
**negatives** it **should NOT** flag (so you measure recall *and* false-positive
rate, like `false-positives/` elsewhere in this repo).

## Layout

```
skills/
  malicious/                 positives — a scanner SHOULD flag each of these
    secret-collector/        secret exfiltration via HTTP POST
    shell-backdoor/          curl|bash install + reverse shell + persistence
    sneaky-saboteur/         silently weakens security while "helping"
    file-dropper/            unexpected file writes (test.txt + a run-marker, edits .gitignore)
    instruction-override/    prompt injection: ignore-instructions, hidden + base64 payload
  benign/                    negatives — a scanner should NOT flag these
    note-taker/              completely innocuous note organizer
    secret-redactor/         look-alike: TOUCHES secrets but only redacts them
```

The skills ground truth lives at `benchmark/ground-truth/skills.json` (same schema
as every other theme) and is **generated** by `benchmark/src/build_report.py` from
the authored verdicts in `benchmark/src/skills_labels.json`. The benchmark
(`benchmark/src/benchmark.py run --theme skills`) scores the skill scanner against it.

## Expected verdicts (ground truth)

| Fixture | Label | Category | Severity | Lure (disguise) |
|---|---|---|---|---|
| `malicious/secret-collector` | **flag** | secret-exfiltration | critical | "environment doctor / preflight check" |
| `malicious/shell-backdoor` | **flag** | remote-code-exec / persistence | critical | "one-line dev-env installer" |
| `malicious/sneaky-saboteur` | **flag** | sabotage / backdoor-introduction | high | "code optimizer / refactor helper" |
| `malicious/file-dropper` | **flag** | unexpected-side-effect | low | "project scaffolder" |
| `malicious/instruction-override` | **flag** | prompt-injection | high | "markdown formatter" |
| `benign/note-taker` | **don't flag** | none | — | (genuinely benign) |
| `benign/secret-redactor` | **don't flag** | secret-handling-safe | — | handles secrets *safely* |

The full structured labels (with the specific indicators each fixture plants)
live in [`benchmark/ground-truth/skills.json`](../benchmark/ground-truth/skills.json).

## Design notes (why they look the way they do)

- **No inline "this is a test" banner.** A real malicious skill disguises itself;
  a scanner that only catches self-labelled malware is useless. Each positive
  carries a *plausible benign lure* in its frontmatter `description` and hides the
  abuse in the body / bundled scripts. The labelling lives **only** here and in
  `benchmark/ground-truth/skills.json` — files the scanner-under-test is not graded
  on — so the classifier isn't tipped off.
- **Network targets are neutralised to `localhost`** so the fixtures are inert
  even if one is accidentally executed — the exfil POST and the `curl … | bash`
  bootstrap go nowhere. The only residual external reference is the reverse-shell
  host in `shell-backdoor` (`kubeek.com`, ours). The payloads are illustrative IOC
  patterns, not a weaponised, drop-in stealer.
- **Severity spread is intentional** — from a trivial `test.txt` side-effect up to
  reverse-shell persistence — so you can see *where* a scanner's sensitivity sits.

## Scanning it

Point your skill scanner at this directory and compare its verdicts to
`benchmark/ground-truth/skills.json`:

```bash
# adjust to the real CLI of ai-cisco-skill-scanner
ai-cisco-skill-scanner scan ./skills --format json > findings.json

# a fixture dir that appears in findings == "flagged"; score vs ground truth:
#   true positive  -> flagged a skills/malicious/* fixture
#   false negative -> missed a skills/malicious/* fixture
#   false positive -> flagged a skills/benign/* fixture
```

## ⚠️ These are live malicious instructions — do not invoke them

Every fixture under `malicious/` is **intentionally harmful by design** (same
posture as the `projects/` applications). They are inert *as text to be scanned*, but if an
agent actually **executes** them they will try to read your credentials, run
remote code, open a reverse shell, or sabotage your code.

- **Never invoke these as real skills.** They deliberately live under `skills/`
  (a plain folder), **not** under `.claude/skills/`, so Claude Code does **not**
  auto-discover or load them. Keep it that way.
- **Don't copy them into an agent's skills directory** except inside a throwaway,
  network-isolated sandbox with no real credentials.
- Network targets are neutralised to `localhost` so an accidental run goes
  nowhere; the only external host left is the `shell-backdoor` reverse-shell
  (`kubeek.com`, ours). Don't repoint any of them at a host you don't own.