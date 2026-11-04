"""
Config loader. Reads config.yaml and env vars.

API keys and tool paths live here instead of hardcoded in modules, so
swapping a wordlist or adding a Censys key doesn't mean touching code.
"""

import os
from pathlib import Path
from typing import Any, Dict

import yaml


DEFAULT_CONFIG_PATH = Path(__file__).resolve().parent.parent / "config.yaml"


def load_config(path: str = None) -> Dict[str, Any]:
    config_path = Path(path) if path else DEFAULT_CONFIG_PATH
    if not config_path.exists():
        raise FileNotFoundError(
            f"Config file not found at {config_path}. Copy config.example.yaml to config.yaml and fill it in."
        )

    with open(config_path, "r") as f:
        config = yaml.safe_load(f) or {}

    # allow env vars to override anything under api_keys, e.g. CENSYS_API_KEY
    api_keys = config.setdefault("api_keys", {})
    for key_name in list(api_keys.keys()):
        env_name = key_name.upper()
        if env_name in os.environ:
            api_keys[key_name] = os.environ[env_name]

    return config


def tool_path(config: Dict[str, Any], tool_name: str) -> str:
    """
    Returns the configured path/binary name for an external tool.
    Falls back to just the tool name (assumes it's on PATH) if not configured.
    """
    return config.get("tools", {}).get(tool_name, tool_name)
