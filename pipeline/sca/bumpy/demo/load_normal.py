"""
Load config/normal.yaml and display its values.
Run with: uv run python demo/load_normal.py
"""
from pathlib import Path
import yaml

CONFIG = Path(__file__).parent.parent / "config" / "normal.yaml"


def main():
    raw = CONFIG.read_text(encoding="utf-8")
    config = yaml.safe_load(raw)

    print(f"pyyaml : {yaml.__version__}")
    print(f"file   : {CONFIG}\n")

    print("--- database ---")
    db = config["database"]
    print(f"  host : {db['host']}")
    print(f"  port : {db['port']}")
    print(f"  name : {db['name']}")

    print("\n--- app ---")
    app = config["app"]
    print(f"  debug      : {app['debug']}")
    print(f"  secret_key : {app['secret_key']}")


if __name__ == "__main__":
    main()
