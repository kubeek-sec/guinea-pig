"""Precise Python AST taint analysis (sanitizer-aware, cross-function).

Builds a call graph + per-function data-flow view from Python source using the
standard ``ast`` module, then traces source → sink paths that cross function
boundaries without passing a sanitizer. This is the high-confidence engine of
the ``analysis`` scanner; it is the cross-function reach that single-line SAST
misses.

SAFETY: source is parsed with ``ast`` only — never imported, deserialized or
executed. Sink names (``pickle.loads``, ``yaml.load``, …) are matched as
strings, never invoked.

Derived from the project's ``codegraph.py`` triage tool; the sink/source/
sanitizer tables now live in ``sinks.py`` so there is a single knowledge base.
"""

from __future__ import annotations

import ast
import warnings
from dataclasses import dataclass, field
from pathlib import Path

from . import sinks

_PY = "python"
_SOURCE_CALLS = sinks.SOURCES[_PY]
_SOURCE_ATTRS = sinks.SOURCE_ATTRS[_PY]
_SINKS = sinks.SINKS[_PY]
_SANITIZERS = sinks.SANITIZERS[_PY]


@dataclass
class FuncNode:
    qualname: str
    file: str
    lineno: int
    params: list[str] = field(default_factory=list)
    # each call: (callee, lineno, arg source-names, is_safe_sink_form)
    calls: list[tuple[str, int, list[str], bool]] = field(default_factory=list)
    # each assignment: (target names, RHS source names, rhs_passes_sanitizer)
    assigns: list[tuple[list[str], list[str], bool]] = field(default_factory=list)


@dataclass
class TaintPath:
    sink: str
    kind: str
    cwe: str
    file: str
    line: int
    chain: list[str]  # human-readable hops from source to sink

    def to_dict(self) -> dict:
        return {
            "sink": self.sink, "kind": self.kind, "cwe": self.cwe,
            "file": self.file, "line": self.line, "chain": self.chain,
            "remediation": sinks.remediation(self.kind),
        }


def _dotted(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return f"{_dotted(node.value)}.{node.attr}"
    if isinstance(node, ast.Call):
        return _dotted(node.func)
    return ""


def _names_in(node: ast.AST) -> list[str]:
    found: list[str] = []
    for child in ast.walk(node):
        if isinstance(child, ast.Name):
            found.append(child.id)
        elif isinstance(child, ast.Attribute):
            dotted = _dotted(child)
            if dotted:
                found.append(dotted)
    return found


def _arg_names(call: ast.Call) -> list[str]:
    names: list[str] = []
    for arg in list(call.args) + [kw.value for kw in call.keywords]:
        names.extend(_names_in(arg))
    return names


def _is_safe_sink_call(call: ast.Call, callee: str) -> bool:
    """Recognise the safe form of a dangerous API so patched code is not
    flagged. Conservative: only well-known safe shapes return True."""
    short = callee.rsplit(".", 1)[-1]
    keywords = {kw.arg: kw.value for kw in call.keywords}
    shell_true = (
        isinstance(keywords.get("shell"), ast.Constant)
        and keywords["shell"].value is True
    )
    if short in {"execute", "executemany"} and len(call.args) >= 2:
        return True  # parameterized query: value passed out-of-band
    if short in {"run", "call", "Popen", "check_output", "check_call"}:
        if call.args and isinstance(call.args[0], (ast.List, ast.Tuple)) and not shell_true:
            return True
    if short == "load" and "yaml" in callee:
        loader = keywords.get("Loader")
        if loader is not None and "Safe" in _dotted(loader):
            return True
    return False


def _rhs_is_sanitized(value: ast.AST | None) -> bool:
    if value is None:
        return False
    for child in ast.walk(value):
        if isinstance(child, ast.Call):
            callee = _dotted(child.func)
            if callee in _SANITIZERS or callee.rsplit(".", 1)[-1] in _SANITIZERS:
                return True
    return False


class _Collector(ast.NodeVisitor):
    def __init__(self, file: str):
        self.file = file
        self.funcs: dict[str, FuncNode] = {}
        self._stack: list[str] = []

    def _visit_func(self, node):
        qual = ".".join(self._stack + [node.name])
        fn = FuncNode(
            qualname=qual, file=self.file, lineno=node.lineno,
            params=[a.arg for a in node.args.args if a.arg != "self"],
        )
        self.funcs[qual] = fn
        for child in ast.walk(node):
            if isinstance(child, ast.Call):
                callee = _dotted(child.func)
                if callee:
                    fn.calls.append((
                        callee, getattr(child, "lineno", node.lineno),
                        _arg_names(child), _is_safe_sink_call(child, callee),
                    ))
            elif isinstance(child, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
                targets = child.targets if isinstance(child, ast.Assign) else [child.target]
                names: list[str] = []
                for t in targets:
                    names.extend(_names_in(t))
                rhs = _names_in(child.value) if child.value is not None else []
                if isinstance(child, ast.AugAssign):
                    rhs = rhs + names  # x += y keeps x's prior taint
                if names:
                    fn.assigns.append((names, rhs, _rhs_is_sanitized(child.value)))
        self._stack.append(node.name)
        self.generic_visit(node)
        self._stack.pop()

    visit_FunctionDef = _visit_func
    visit_AsyncFunctionDef = _visit_func


def build_graph(files: list[Path], root: Path) -> dict[str, FuncNode]:
    funcs: dict[str, FuncNode] = {}
    for path in files:
        try:
            with warnings.catch_warnings():
                # Parsing untrusted target code: a SyntaxWarning (e.g. an invalid
                # escape sequence like "\d") is about the *scanned* project's code,
                # not ours — suppress it so it doesn't flood the worker log.
                warnings.simplefilter("ignore", SyntaxWarning)
                tree = ast.parse(
                    path.read_text(encoding="utf-8", errors="replace"), filename=str(path)
                )
        except (SyntaxError, OSError, ValueError):
            continue
        try:
            rel = str(path.relative_to(root))
        except ValueError:
            rel = path.name
        collector = _Collector(rel)
        collector.visit(tree)
        # Key by file + qualname so same-named functions in different files
        # (e.g. a vulnerable file and its *_patched sibling) do not collide.
        for qual, fn in collector.funcs.items():
            funcs[f"{rel}::{qual}"] = fn
    return funcs


def _short(name: str) -> str:
    return name.rsplit(".", 1)[-1]


def _resolve(callee: str, caller: FuncNode, funcs: dict[str, FuncNode]) -> FuncNode | None:
    short = _short(callee)
    matches = [f for f in funcs.values() if _short(f.qualname) == short]
    if not matches:
        return None
    same_file = [f for f in matches if f.file == caller.file]
    if len(same_file) == 1:
        return same_file[0]
    return matches[0] if len(matches) == 1 else None


def find_taint_paths(funcs: dict[str, FuncNode]) -> list[TaintPath]:
    """Trace source → sink paths, following calls into local functions and
    propagating taint through their parameters."""
    paths: list[TaintPath] = []

    def walk(fn: FuncNode, tainted: set[str], chain: list[str], seen: set[str]):
        node_key = f"{fn.file}::{fn.qualname}"
        if node_key in seen:
            return
        seen = seen | {node_key}
        local = set(tainted)
        changed = True
        while changed:
            changed = False
            for targets, rhs, sanitized in fn.assigns:
                if sanitized:
                    continue
                if any(r in local or r.split(".")[0] in local for r in rhs):
                    for t in targets:
                        if t not in local:
                            local.add(t)
                            changed = True
        for callee, line, args, safe_form in fn.calls:
            short = _short(callee)
            tainted_args = [a for a in args if a in local or a.split(".")[0] in local]
            if callee in _SOURCE_CALLS or short in {_short(s) for s in _SOURCE_CALLS} \
                    or any(s in callee for s in _SOURCE_ATTRS):
                local.add(f"__ret_{line}")
            if (callee in _SANITIZERS or short in _SANITIZERS) and tainted_args:
                local.difference_update(tainted_args)
                continue
            kind = _SINKS.get(callee) or _SINKS.get(short)
            if kind and not safe_form and tainted_args:
                hop = chain + [
                    f"{fn.file}:{fn.qualname} → {callee}() at line {line} "
                    f"[tainted: {', '.join(sorted(set(tainted_args)))}]"
                ]
                paths.append(TaintPath(
                    sink=callee, kind=kind, cwe=sinks.spec(kind).cwe,
                    file=fn.file, line=line, chain=hop,
                ))
            callee_fn = _resolve(callee, fn, funcs)
            if callee_fn and tainted_args:
                walk(callee_fn, set(callee_fn.params),
                     chain + [f"{fn.file}:{fn.qualname} → {callee}() at line {line}"],
                     seen)

    for fn in funcs.values():
        # Entry assumption: every parameter of a function is a potential
        # untrusted source (HTTP handlers, CLI entry points, etc.).
        walk(fn, set(fn.params), [], set())
    unique: dict[tuple, TaintPath] = {}
    for p in paths:
        unique[(p.file, p.line, p.sink)] = p
    return list(unique.values())


def analyze_python(files: list[Path], root: Path) -> list[TaintPath]:
    """Convenience: build the graph for the Python files and return taint paths."""
    py = [f for f in files if f.suffix.lower() in (".py", ".pyw")]
    if not py:
        return []
    return find_taint_paths(build_graph(py, root))
