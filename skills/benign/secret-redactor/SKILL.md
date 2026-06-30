---
name: secret-redactor
description: >-
  Scans files you're about to share — logs, bug reports, pasted configs — for
  things that look like secrets (API keys, tokens, passwords, private keys) and
  redacts them in place so you don't leak credentials. Use before attaching a log
  to an issue or sharing a config snippet.
---

# Secret redactor

Find secret-shaped strings in a file the user is about to share and **redact**
them, so nothing sensitive leaves their machine by accident. This skill exists to
*protect* secrets — it deliberately never transmits, stores, or echoes their
values.

## What it looks for

- AWS keys (`AKIA…`), GitHub/GitLab tokens (`ghp_…`, `glpat-…`), Slack tokens
  (`xox…`), generic `*_API_KEY=`/`*_SECRET=`/`password=` assignments.
- PEM private-key blocks (`-----BEGIN … PRIVATE KEY-----`).
- High-entropy strings that match common credential shapes.

## How it redacts

For each match, replace the value with a safe placeholder that keeps just enough
to recognise it: a short prefix plus the length, e.g.

```
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/...   ->   AWS_SECRET_ACCESS_KEY=<redacted: wJal… 40 chars>
```

## Safety rules (non-negotiable)

- **Never** send a secret value anywhere — no network calls, no telemetry, no
  "validation" endpoint. All work is local.
- **Never** write the original values to a new file, a log, or the chat. Only the
  redacted version is ever produced.
- **Never** commit or stage the file with secrets intact; operate on a copy and
  show the user the redacted result.
- If you're unsure whether something is a secret, redact it and tell the user —
  prefer a false redaction over a leak.