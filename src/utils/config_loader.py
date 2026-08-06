"""
Configuration loading utilities.

All source definitions (RSS feeds, CERT feeds, API endpoints, social
media targets, etc.) live in `config/sources.json` instead of being
hardcoded in the collector modules. This module is the single place
responsible for reading and validating that file (and the separate
`config/preprocessing_rules.json`).
"""

import json
import os
from typing import Any, Dict

from src.utils.logger import get_logger

logger = get_logger(__name__)

_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DEFAULT_CONFIG_PATH = os.path.join(_PROJECT_ROOT, "config", "sources.json")
DEFAULT_PREPROCESSING_CONFIG_PATH = os.path.join(_PROJECT_ROOT, "config", "preprocessing_rules.json")


def load_config(config_path: str = DEFAULT_CONFIG_PATH) -> Dict[str, Any]:
    """
    Load a JSON configuration file.

    Args:
        config_path: Path to the JSON configuration file.

    Returns:
        Parsed configuration as a dictionary. Returns an empty dict
        (with empty default sections) if the file is missing or invalid,
        so that callers can fail gracefully rather than crashing.
    """
    if not os.path.exists(config_path):
        logger.error("Configuration file not found: %s", config_path)
        return {}

    try:
        with open(config_path, "r", encoding="utf-8") as f:
            config = json.load(f)
        logger.info("Loaded configuration from %s", config_path)
        return config
    except json.JSONDecodeError as e:
        logger.error("Invalid JSON in configuration file %s: %s", config_path, e)
        return {}
    except OSError as e:
        logger.error("Could not read configuration file %s: %s", config_path, e)
        return {}


def get_rss_sources(config_path: str = DEFAULT_CONFIG_PATH) -> list:
    """
    Convenience accessor returning only the RSS feed sources.

    Returns:
        A list of RSS source dictionaries, e.g.:
        [{"name": "The Hacker News", "url": "...", "category": "news"}, ...]
    """
    config = load_config(config_path)
    return config.get("rss_sources", [])


def get_boilerplate_patterns(config_path: str = DEFAULT_PREPROCESSING_CONFIG_PATH) -> list:
    """
    Convenience accessor returning the configured boilerplate regex patterns
    used by the Phase 3 text preprocessor to strip leftover noise lines
    (share bars, cookie notices, newsletter prompts, etc.).

    Returns:
        A list of regex pattern strings. Empty list if the config is
        missing or invalid.
    """
    config = load_config(config_path)
    return config.get("boilerplate_patterns", [])


def get_cert_sources(config_path: str = DEFAULT_CONFIG_PATH) -> list:
    """
    Convenience accessor returning only the CERT advisory sources.

    Returns:
        A list of CERT source dictionaries, e.g.:
        [{"name": "CISA", "url": "...", "category": "advisory", "method": "scrape"}, ...]
        `method` is either "rss" or "scrape".
    """
    config = load_config(config_path)
    return config.get("cert_sources", [])


def get_vulnerability_sources(config_path: str = DEFAULT_CONFIG_PATH) -> list:
    """
    Convenience accessor returning only the vulnerability database sources.

    Returns:
        A list of vulnerability source dictionaries, e.g.:
        [{"name": "NVD", "type": "nvd", "base_url": "...", "days_back": 3}, ...]
        `type` is either "nvd" or "mitre".
    """
    config = load_config(config_path)
    return config.get("vulnerability_sources", [])


def get_social_media_sources(config_path: str = DEFAULT_CONFIG_PATH) -> list:
    """
    Convenience accessor returning only the social media sources.

    Returns:
        A list of social media source dictionaries, e.g.:
        [{"name": "Reddit - r/netsec", "platform": "reddit", "url": "...", "category": "social"}, ...]
        `platform` determines which collector handler is used
        (currently "reddit") and is designed to be extended with new
        platforms without changing existing handlers.
    """
    config = load_config(config_path)
    return config.get("social_media_sources", [])


def get_hackernews_sources(config_path: str = DEFAULT_CONFIG_PATH) -> list:
    """
    Convenience accessor returning only the Hacker News sources.

    Returns:
        A list of Hacker News source dictionaries, e.g.:
        [{"name": "Hacker News - CVE", "query": "CVE", "category": "social", "limit": 30}]
    """
    config = load_config(config_path)
    return config.get("hackernews_sources", [])


def get_github_sources(config_path: str = DEFAULT_CONFIG_PATH) -> list:
    """
    Convenience accessor returning only the GitHub sources.

    Returns:
        A list of GitHub source dictionaries, e.g.:
        [{"name": "GitHub Security Advisories", "category": "vulnerability", "per_page": 20}]
    """
    config = load_config(config_path)
    return config.get("github_sources", [])


def get_telegram_sources(config_path: str = DEFAULT_CONFIG_PATH) -> list:
    """
    Convenience accessor returning only the Telegram channel sources.

    Returns:
        A list of Telegram source dictionaries, e.g.:
        [{"name": "Telegram - The Hacker News", "channel": "thehackernews", "category": "social"}, ...]
        `channel` is the public channel username (no "@" or "t.me/"
        prefix), used to build the public web preview URL
        `https://t.me/s/{channel}`.
    """
    config = load_config(config_path)
    return config.get("telegram_sources", [])