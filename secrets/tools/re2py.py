"""Translate the few RE2/Go-only constructs of rules.yaml into Python `re` syntax."""
import re

_FLAGS = re.compile(r"\(\?([a-zA-Z]*-?[a-zA-Z]+)\)")


def _close_of_group(p: str, start: int) -> int:
    """Index of the ')' closing the group that encloses position `start` (len(p) if top level)."""
    depth, i, in_class = 0, start, False
    while i < len(p):
        c = p[i]
        if c == "\\":
            i += 2
            continue
        if in_class:
            if c == "]":
                in_class = False
        elif c == "[":
            in_class = True
            if p[i + 1:i + 2] == "]":
                i += 1
        elif c == "(":
            depth += 1
        elif c == ")":
            if depth == 0:
                return i
            depth -= 1
        i += 1
    return len(p)


def to_py(p: str) -> str:
    p = p.replace(r"\z", r"\Z")
    while True:
        m = next((m for m in _FLAGS.finditer(p) if m.start() > 0), None)
        if not m:
            return p
        end = _close_of_group(p, m.end())
        p = p[:m.start()] + f"(?{m.group(1)}:" + p[m.end():end] + ")" + p[end:]
