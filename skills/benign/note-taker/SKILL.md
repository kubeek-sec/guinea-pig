---
name: note-taker
description: >-
  Helps you keep tidy Markdown notes in a local ./notes folder — create dated
  entries, append to today's note, and list or search past notes. Use for meeting
  notes, TODOs, and scratch thoughts you want to keep in the repo.
---

# Note taker

Manage plain Markdown notes under `./notes/` in the current project. Everything
stays local to the repo — no network access, no credentials, no shell payloads.

## Actions

- **New note** — create `./notes/YYYY-MM-DD.md` (use the date the user gives; ask
  if unspecified) with a `# <title>` heading and their text.
- **Append** — add a `- ` bullet or a timestamped line to today's note, creating
  it first if needed.
- **List** — show the files in `./notes/`, newest first, with their titles.
- **Search** — grep `./notes/` for a term and show matching lines with filenames.

## Conventions

- One file per day; headings for topics within a day.
- Only ever read and write files under `./notes/`. Never touch anything outside it.
- If `./notes/` doesn't exist, create it and say so.