#!/usr/bin/env python3
"""Synthesize one catalogue entry per rule that the catalogue does not cover yet.

For each rule: try the rule's own `examples:` first, else generate random strings
from the regex (sre parse tree), keep the first one that (a) matches the rule,
(b) whose secret group reaches the rule's entropy threshold and (c) contains one
of the rule's keywords (gitleaks/betterleaks prefilter). Writes
<catalogue>/<topic>/<uid>.txt with the same header layout as the existing files.
"""
import json
import signal
import time
import math
import random
import re
import string
import sys
from collections import Counter
from pathlib import Path

try:
    from re import _parser as sre_parse, _constants as C
except ImportError:  # python < 3.11
    import sre_parse
    import sre_constants as C

import yaml
from re2py import to_py

RULES, COV, CAT = Path(sys.argv[1]), Path(sys.argv[2]), Path(sys.argv[3])
rnd = random.Random(798)

ALNUM = string.ascii_letters + string.digits
GAP = " =:_.-\"'"        # what a `.` turns into in context gaps
PRINT = [chr(c) for c in range(0x20, 0x7f)]


def entropy(s: str) -> float:
    if not s:
        return 0.0
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in Counter(s).values())


def _class_chars(items, icase: bool) -> list[str]:
    neg, chars = False, set()
    for op, av in items:
        if op is C.NEGATE:
            neg = True
        elif op is C.LITERAL:
            chars.add(chr(av))
        elif op is C.RANGE:
            chars.update(chr(c) for c in range(av[0], min(av[1], 0x7e) + 1))
        elif op is C.CATEGORY:
            name = str(av)
            if "DIGIT" in name and "NOT" not in name:
                chars.update(string.digits)
            elif "WORD" in name and "NOT" not in name:
                chars.update(ALNUM + "_")
            elif "SPACE" in name and "NOT" not in name:
                chars.add(" ")
            elif "NOT" in name:
                chars.update("-./:")
    if neg:
        chars = set(PRINT) - chars - {"\n"}
    pool = sorted(c for c in chars if c >= " ") or sorted(chars)
    if not pool:
        return ["x"]
    alnum = [c for c in pool if c in ALNUM]
    # bias toward alphanumerics so tokens look like tokens and carry entropy
    return alnum * 4 + pool if alnum else pool


def gen(tree, icase: bool = False) -> str:
    out = []
    for op, av in tree:
        if op is C.LITERAL:
            out.append(chr(av))
        elif op is C.NOT_LITERAL:
            out.append(rnd.choice([c for c in ALNUM if ord(c) != av]))
        elif op is C.ANY:
            out.append(rnd.choice(GAP if rnd.random() < 0.4 else ALNUM))
        elif op is C.IN:
            out.append(rnd.choice(_class_chars(av, icase)))
        elif op is C.BRANCH:
            out.append(gen(rnd.choice(av[1]), icase))
        elif op is C.SUBPATTERN:
            out.append(gen(av[-1], icase))
        elif op in (C.MAX_REPEAT, C.MIN_REPEAT, getattr(C, "POSSESSIVE_REPEAT", None)):
            lo, hi, sub = av
            hi = lo + 40 if hi is C.MAXREPEAT else hi
            if op is C.MIN_REPEAT and lo == 0 and rnd.random() < 0.6:
                n = rnd.choice([0, 1, 1, 2])            # lazy context gap: keep it short
            elif lo == hi:
                n = lo
            else:
                n = rnd.randint(lo, min(hi, lo + 24))
            out.append("".join(gen(sub, icase) for _ in range(n)))
        elif op is C.GROUPREF:
            out.append("")
        # AT (\b ^ $), ASSERT, ASSERT_NOT: emit nothing, the final match check decides
    return "".join(out)


def keyword_ok(text: str, kws: list[str]) -> bool:
    return not kws or any(k.lower() in text.lower() for k in kws)


def secret_of(m: re.Match, grp: int) -> str:
    try:
        return m.group(grp) or m.group(0)
    except IndexError:
        return m.group(0)


def candidate_ok(rx, text, grp, thr, kws) -> bool:
    if not keyword_ok(text, kws):
        return False
    return any(entropy(secret_of(m, grp)) >= thr for m in rx.finditer(text))


def wrap(sample: str, kws: list[str]) -> str:
    """Put a keyword-free sample in a plausible assignment so prefilters see a keyword."""
    if keyword_ok(sample, kws):
        return sample
    return f"{kws[0].upper().strip('_-')}_TOKEN = \"{sample}\""


UNREACHABLE: list[tuple[str, float, float]] = []


def synthesize(rule) -> tuple[list[str], str] | None:
    pat = to_py(rule["pattern"])
    rx = re.compile(pat)
    grp, thr = rule.get("secret_group", 0) or 0, rule.get("entropy") or 0
    kws = rule.get("keywords") or []
    good = [ex for ex in rule.get("examples") or [] if candidate_ok(rx, ex, grp, thr, kws)]
    if good:
        return good[:3], "rule examples (rules.yaml)"
    tree = sre_parse.parse(pat)
    best, best_ent = None, -1.0          # fallback when the threshold is out of reach
    for ex in rule.get("examples") or []:
        for m in rx.finditer(ex):
            if keyword_ok(ex, kws) and entropy(secret_of(m, grp)) > best_ent:
                best, best_ent = ex, entropy(secret_of(m, grp))
    deadline = time.monotonic() + 20
    for _ in range(4000):
        if time.monotonic() > deadline:
            break
        s = gen(tree)
        for cand in (s, wrap(s, kws), f"{s} ", f"\"{s}\""):
            if candidate_ok(rx, cand, grp, thr, kws):
                return [cand], "synthesized from the regex"
            if keyword_ok(cand, kws):
                for m in rx.finditer(cand):
                    e = entropy(secret_of(m, grp))
                    if e > best_ent:
                        best, best_ent = cand, e
    if best is None:
        return None
    UNREACHABLE.append((rule["uid"], thr, round(best_ent, 2)))
    return [best], (f"best effort: entropy threshold {thr} unreachable for the secret group, "
                    f"best {best_ent:.2f}")


def header(rule, how: str) -> str:
    srcs = "\n".join(f"#   - {s['scanner']:<12}{s['id']}" for s in rule.get("sources", []))
    return (
        "# CWE-798 — Use of Hard-coded Credentials\n"
        f"# Catalogue entry: {rule['name']}\n"
        f"# Provider: {rule.get('topic', 'misc')}    Rule id (normalized): {rule['uid']}\n"
        "#\n# Detected by this rule:\n"
        f"{srcs}\n#\n"
        f"# Pattern: {rule['pattern']}\n#\n"
        f"# Fake credentials ({how}) — safe to commit, not live secrets.\n\n"
    )


def _timeout(*_):
    raise TimeoutError


def main() -> None:
    signal.signal(signal.SIGALRM, _timeout)
    rules = {r["uid"]: r for r in yaml.safe_load(RULES.read_text())["rules"]}
    cov = json.loads(COV.read_text())
    todo = [x["uid"] for x in cov["uncovered"] + cov["low_entropy"]]
    written, failed = [], []
    for uid in todo:
        rule = rules[uid]
        dest = CAT / (rule.get("topic") or "misc") / f"{uid}.txt"
        if dest.exists():
            written.append(str(dest.relative_to(CAT)))
            continue
        signal.alarm(40)
        try:
            res = synthesize(rule)
        except TimeoutError:
            res = None
        finally:
            signal.alarm(0)
        if not res:
            failed.append(uid)
            continue
        samples, how = res
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(header(rule, how) + "\n".join(samples) + "\n", encoding="utf-8")
        written.append(str(dest.relative_to(CAT)))
    print(f"todo={len(todo)} written={len(written)} failed={len(failed)}")
    if failed:
        print("FAILED:", failed)
    for uid, thr, got in UNREACHABLE:
        print(f"  entropy unreachable: {uid:40} threshold={thr} best={got}")


if __name__ == "__main__":
    main()
