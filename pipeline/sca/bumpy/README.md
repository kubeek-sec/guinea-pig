# bumpy-pig — pyyaml loader compatibility study

Explores how the `yaml.load()` API behaves across pyyaml versions and what
changes when migrating from the legacy loader to the strict one.

## Requirements

```bash
uv --version   # >= 0.4
```

## Quick start

```bash
# Phase 1: legacy loader behaviour
python scripts/switch_phase.py 1
uv sync
uv run python demo/load_normal.py
uv run python demo/run_fixtures.py

# Phase 2: transitional version (API warnings)
python scripts/switch_phase.py 2
uv sync
uv run python demo/run_fixtures.py

# Phase 3: strict loader
python scripts/switch_phase.py 3
uv sync
uv run python demo/run_fixtures.py
```

## Project layout

```
bumpy-pig/
├── pyproject.toml           # versioned pyyaml dependency
├── scripts/
│   └── switch_phase.py      # version switcher + lock deletion
├── app/
│   └── config_loader.py     # config loader using legacy API
├── config/
│   └── normal.yaml          # standard config file
├── fixtures/
│   ├── config_dynamic.yaml  # config with dynamic resolution
│   └── config_writer.yaml   # config that writes an output file
└── demo/
    ├── load_normal.py        # display values from normal.yaml
    └── run_fixtures.py       # run fixture configs and show results
```
