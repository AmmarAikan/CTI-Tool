"""
Simple JSON-based storage helpers.

Phase 1 only requires writing collected article metadata to JSON files.
This module centralizes that logic so later phases (and eventually a
real database layer) can reuse or replace it without touching collector
code.
"""

import glob
import json
import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from src.utils.logger import get_logger

logger = get_logger(__name__)

_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DATA_DIR = os.path.join(_PROJECT_ROOT, "src", "data")


def save_json(items: List[Dict[str, Any]], filename: str, data_dir: str = DATA_DIR) -> str:
    """
    Save a list of dict items to a JSON file inside the data directory.

    Args:
        items: List of serializable dictionaries to save.
        filename: Target filename (a timestamp is NOT auto-appended;
            pass an already-unique name if needed).
        data_dir: Directory in which to save the file.

    Returns:
        The full path to the written file, or an empty string on failure.
    """
    os.makedirs(data_dir, exist_ok=True)
    filepath = os.path.join(data_dir, filename)

    try:
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(items, f, ensure_ascii=False, indent=2)
        logger.info("Saved %d items to %s", len(items), filepath)
        return filepath
    except OSError as e:
        logger.error("Failed to save JSON file %s: %s", filepath, e)
        return ""


def timestamped_filename(prefix: str, extension: str = "json") -> str:
    """Build a filename like `prefix_20260717_153000.json` using UTC time."""
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    return f"{prefix}_{ts}.{extension}"


def load_json(filepath: str) -> List[Dict[str, Any]]:
    """
    Load a list of items from a JSON file.

    Args:
        filepath: Full path to the JSON file to read.

    Returns:
        The parsed list of dictionaries, or an empty list if the file
        is missing or invalid. Errors are logged, never raised, so a
        single unreadable file doesn't crash a pipeline stage.
    """
    if not os.path.exists(filepath):
        logger.error("JSON file not found: %s", filepath)
        return []

    try:
        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, list):
            logger.error("Expected a JSON list in %s, got %s", filepath, type(data).__name__)
            return []
        logger.info("Loaded %d items from %s", len(data), filepath)
        return data
    except (json.JSONDecodeError, OSError) as e:
        logger.error("Failed to load JSON file %s: %s", filepath, e)
        return []


def latest_file(prefix: str, data_dir: str = DATA_DIR) -> Optional[str]:
    """
    Find the most recently created file matching `prefix_*.json` in
    `data_dir`. Used to chain pipeline stages (e.g. the crawler picking
    up the newest RSS output) without hardcoding filenames.

    Args:
        prefix: Filename prefix to match, e.g. "rss_articles".
        data_dir: Directory to search in.

    Returns:
        Full path to the newest matching file, or None if none exist.
    """
    pattern = os.path.join(data_dir, f"{prefix}_*.json")
    matches = glob.glob(pattern)
    if not matches:
        logger.warning("No files found matching pattern: %s", pattern)
        return None
    return max(matches, key=os.path.getmtime)
