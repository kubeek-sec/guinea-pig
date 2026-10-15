#!/usr/bin/env python3
"""Check that every rule of secret-rules/referential/rules.yaml fires on at least
one example of guinea-pig/secrets/catalogue (regex match + entropy threshold)."""
import json
import math
import re
import sys
from collections import Counter
from pathlib import Path

import yaml
from re2py import to_py

RULES = Path(sys.argv[1])
CAT = Path(sys.argv[2])
OUT = Path(sys.argv[3])


def entropy(s: str) -> float:
    if not s:
        return 0.0
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in Counter(s).values())


def body(p: Path) -> str:
    """Everything after the catalogue header (the header ends at the first blank line)."""
    text = p.read_text(encoding="utf-8", errors="replace")
    if text.startswith("#") and "\n\n" in text:
        return text.split("\n\n", 1)[1]
    return text


rules = yaml.safe_load(RULES.read_text())["rules"]
files = {str(p.relative_to(CAT)): body(p) for p in sorted(CAT.rglob("*.txt"))}

covered, regex_only, uncovered, bad = [], [], [], []
for r in rules:
    try:
        rx = re.compile(to_py(r["pattern"]))
    except re.error as e:
        bad.append({"uid": r["uid"], "error": str(e)})
        continue
    grp = r.get("secret_group", 0) or 0
    thr = r.get("entropy") or 0
    hit_ent = hit_rx = None
    for name, text in files.items():
        for m in rx.finditer(text):
            try:
                sec = m.group(grp) or m.group(0)
            except IndexError:
                sec = m.group(0)
            hit_rx = hit_rx or name
            if entropy(sec) >= thr:
                hit_ent = name
                break
        if hit_ent:
            break
    row = {"uid": r["uid"], "topic": r.get("topic"), "file": hit_ent or hit_rx,
           "sources": [f"{s['scanner']}:{s['id']}" for s in r.get("sources", [])],
           "has_examples": bool(r.get("examples"))}
    if hit_ent:
        covered.append(row)
    elif hit_rx:
        regex_only.append(row)
    else:
        uncovered.append(row)

OUT.write_text(json.dumps({"covered": covered, "low_entropy": regex_only,
                           "uncovered": uncovered, "bad_regex": bad}, indent=1))
print(f"rules={len(rules)} covered={len(covered)} low_entropy={len(regex_only)} "
      f"uncovered={len(uncovered)} bad_regex={len(bad)}")
print("uncovered with examples in rules.yaml:", sum(u["has_examples"] for u in uncovered))
print("uncovered by scanner:", Counter(s.split(":")[0] for u in uncovered for s in u["sources"]))
