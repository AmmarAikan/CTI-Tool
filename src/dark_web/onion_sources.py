"""
Dark Web source and Tor proxy configuration loader.

Deliberately self-contained rather than added to
`src/utils/config_loader.py`: `config/dark_web_sources.json` is a
separate file with its own shape (source list + Tor proxy settings),
not part of `config/sources.json`, so there's no shared state to
justify touching a module every other collector already depends on.
This mirrors the same load/return pattern `config_loader.py` uses
elsewhere, just scoped to this one file.

Source configuration lives here, separated from collection logic in
`dark_web_collector.py`, per the architecture requirement — no onion
addresses are hard-coded in Python anywhere in this module.
"""

import json
import os
from typing import Any, Dict, List

from src.utils.logger import get_logger

logger = get_logger(__name__)

_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DEFAULT_DARK_WEB_CONFIG_PATH = os.path.join(_PROJECT_ROOT, "config", "dark_web_sources.json")

DEFAULT_TOR_HOST = "127.0.0.1"
DEFAULT_TOR_PORT = 9050


def load_dark_web_config(config_path: str = DEFAULT_DARK_WEB_CONFIG_PATH) -> Dict[str, Any]:
    """
    Load the Dark Web configuration file.

    Returns:
        Parsed configuration as a dict. Returns an empty dict if the
        file is missing or invalid, so callers can fail gracefully
        (no sources, defaults for everything else) rather than crash.
    """
    if not os.path.exists(config_path):
        logger.error("Dark Web configuration file not found: %s", config_path)
        return {}

    try:
        with open(config_path, "r", encoding="utf-8") as f:
            config = json.load(f)
        logger.info("Loaded Dark Web configuration from %s", config_path)
        return config
    except json.JSONDecodeError as e:
        logger.error("Invalid JSON in Dark Web configuration file %s: %s", config_path, e)
        return {}
    except OSError as e:
        logger.error("Could not read Dark Web configuration file %s: %s", config_path, e)
        return {}


def get_dark_web_sources(config_path: str = DEFAULT_DARK_WEB_CONFIG_PATH) -> List[Dict[str, Any]]:
    """
    Return the configured Dark Web sources (both enabled and disabled —
    the collector itself decides what to skip). Never invents or
    hard-codes onion addresses; whatever isn't in the config file simply
    isn't collected.
    """
    config = load_dark_web_config(config_path)
    return config.get("dark_web_sources", [])


def get_tor_proxy_config(config_path: str = DEFAULT_DARK_WEB_CONFIG_PATH) -> Dict[str, Any]:
    """
    Return the Tor SOCKS5 proxy host/port to use.

    Resolution order: `TOR_PROXY_HOST`/`TOR_PROXY_PORT` environment
    variables, then the `tor_proxy` section of the config file, then
    hard-coded defaults (127.0.0.1:9050, Tor's own standard default).
    No credentials are ever read or stored here — a SOCKS5 proxy for
    Tor doesn't need any.
    """
    config = load_dark_web_config(config_path)
    proxy_config = config.get("tor_proxy", {})

    host = os.environ.get("TOR_PROXY_HOST", proxy_config.get("host", DEFAULT_TOR_HOST))
    port_raw = os.environ.get("TOR_PROXY_PORT", proxy_config.get("port", DEFAULT_TOR_PORT))

    try:
        port = int(port_raw)
    except (TypeError, ValueError):
        logger.error("Invalid Tor proxy port '%s'; falling back to default %d", port_raw, DEFAULT_TOR_PORT)
        port = DEFAULT_TOR_PORT

    return {"host": host, "port": port}


def get_default_timeout(config_path: str = DEFAULT_DARK_WEB_CONFIG_PATH) -> int:
    """Return the project-wide default request timeout for Dark Web sources."""
    config = load_dark_web_config(config_path)
    return config.get("default_timeout", 30)


def get_default_request_delay(config_path: str = DEFAULT_DARK_WEB_CONFIG_PATH) -> int:
    """Return the project-wide default delay (seconds) between Dark Web requests."""
    config = load_dark_web_config(config_path)
    return config.get("default_request_delay", 5)
