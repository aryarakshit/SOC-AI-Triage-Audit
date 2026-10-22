"""Configuration package for SOC AI Triage Copilot."""
from pathlib import Path
import yaml

CONFIG_PATH = Path(__file__).resolve().parent / "copilot_config.yaml"

def load_config(config_path: Path = CONFIG_PATH) -> dict:
    """Load and return YAML configuration dictionary."""
    with open(config_path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)
