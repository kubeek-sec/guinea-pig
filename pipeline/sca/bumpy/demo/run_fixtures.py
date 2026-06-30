"""
Load fixtures with the legacy yaml.load() API and display results.
Requires pyyaml==3.13. Switch with: python scripts/switch_phase.py 1

Run with: uv run python demo/run_fixtures.py
"""
from pathlib import Path
import yaml

ROOT     = Path(__file__).parent.parent
DYNAMIC  = ROOT / "fixtures" / "config_dynamic.yaml"
WRITER   = ROOT / "fixtures" / "config_writer.yaml"
OUTPUT   = ROOT / "output.txt"


def section(title: str) -> None:
    print(f"\n{'='*50}")
    print(f"  {title}")
    print(f"{'='*50}")


def run_dynamic() -> None:
    section("config_dynamic.yaml — legacy loader")
    print(f"file: {DYNAMIC}\n")

    raw = DYNAMIC.read_text(encoding="utf-8")
    result = yaml.load(raw)

    host = result.get("database", {}).get("host")
    if isinstance(host, bytes):
        print(f"resolved host : {host.decode().strip()!r}")
    else:
        print(f"resolved host : {host!r}")


def run_writer() -> None:
    section("config_writer.yaml — legacy loader")
    print(f"file: {WRITER}\n")

    if OUTPUT.exists():
        OUTPUT.unlink()

    raw = WRITER.read_text(encoding="utf-8")
    yaml.load(raw)

    if OUTPUT.exists():
        print(f"output.txt written : {OUTPUT.read_text()!r}")
    else:
        print("output.txt not written")
        print(f"  current pyyaml: {yaml.__version__} (requires 3.13)")


if __name__ == "__main__":
    print(f"pyyaml: {yaml.__version__}")

    run_dynamic()
    run_writer()

    print(f"\n{'='*50}")
    print("  Switch to strict mode: python scripts/switch_phase.py 3")
    print(f"{'='*50}\n")
