"""
Switch between loader versions by updating pyproject.toml and deleting uv.lock.

Usage:
    uv run python scripts/switch_phase.py 1   # pyyaml==3.13  (legacy API)
    uv run python scripts/switch_phase.py 2   # pyyaml==5.3   (transitional)
    uv run python scripts/switch_phase.py 3   # pyyaml>=6.0   (strict API)
"""
import re
import sys
from pathlib import Path

ROOT      = Path(__file__).parent.parent
PYPROJECT = ROOT / "pyproject.toml"
LOCKFILE  = ROOT / "uv.lock"

PHASES = {
    "1": {
        "label": "Phase 1 — legacy loader (pyyaml==3.13)",
        "dep": "pyyaml==3.13",
        "next": [
            "uv run python demo/load_normal.py",
            "uv run python demo/run_fixtures.py",
        ],
    },
    "2": {
        "label": "Phase 2 — transitional (pyyaml==5.3, API warnings)",
        "dep": "pyyaml==5.3",
        "next": [
            "uv run python demo/run_fixtures.py",
        ],
    },
    "3": {
        "label": "Phase 3 — strict loader (pyyaml>=6.0)",
        "dep": "pyyaml>=6.0",
        "next": [
            "uv run python demo/run_fixtures.py",
        ],
    },
}


def switch(phase: str) -> None:
    if phase not in PHASES:
        print(f"Unknown phase: {phase!r}. Choose from: {', '.join(PHASES)}")
        sys.exit(1)

    info = PHASES[phase]
    content = PYPROJECT.read_text(encoding="utf-8")

    new_content = re.sub(
        r'("pyyaml[^"]*")',
        f'"{info["dep"]}"',
        content,
    )

    if new_content == content:
        print("WARN: no pyyaml dependency found in pyproject.toml")
    else:
        PYPROJECT.write_text(new_content, encoding="utf-8")
        print(f"pyproject.toml updated: {info['dep']}")

    if LOCKFILE.exists():
        LOCKFILE.unlink()
        print("uv.lock deleted")
    else:
        print("uv.lock not found — nothing to delete")

    print()
    print(f"==> {info['label']}")
    print()
    print("Next steps:")
    print("  uv sync")
    for cmd in info["next"]:
        print(f"  {cmd}")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(__doc__)
        sys.exit(1)
    switch(sys.argv[1])
