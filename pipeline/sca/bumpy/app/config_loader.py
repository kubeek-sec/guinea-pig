import yaml


def load_config(path: str) -> dict:
    with open(path, "r") as f:
        return yaml.load(f)


def load_config_from_string(content: str) -> dict:
    return yaml.load(content)


def display_config(config: dict) -> None:
    print("--- config ---")
    for key, value in config.items():
        print(f"  {key}: {value}")
