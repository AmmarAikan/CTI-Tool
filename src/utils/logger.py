"""
Centralized logging configuration for the CTI Tool.

Every module should obtain its logger via `get_logger(__name__)` instead of
configuring logging individually. This keeps log formatting, log levels,
and log file destinations consistent across the whole project.
"""

import logging
import os
from logging.handlers import RotatingFileHandler

LOG_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "logs")
LOG_FILE = os.path.join(LOG_DIR, "cti_tool.log")

_LOG_FORMAT = "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s"
_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"

_configured = False


def _configure_root_logger(level: int = logging.INFO) -> None:
    """Configure the root logger exactly once (idempotent)."""
    global _configured
    if _configured:
        return

    os.makedirs(LOG_DIR, exist_ok=True)

    formatter = logging.Formatter(_LOG_FORMAT, datefmt=_DATE_FORMAT)

    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)

    file_handler = RotatingFileHandler(
        LOG_FILE, maxBytes=5 * 1024 * 1024, backupCount=3, encoding="utf-8"
    )
    file_handler.setFormatter(formatter)

    root_logger = logging.getLogger()
    root_logger.setLevel(level)
    root_logger.addHandler(console_handler)
    root_logger.addHandler(file_handler)

    _configured = True


def get_logger(name: str, level: int = logging.INFO) -> logging.Logger:
    """
    Return a configured logger for the given module name.

    Args:
        name: Typically `__name__` of the calling module.
        level: Logging level for the root logger (only applied on first call).

    Returns:
        A `logging.Logger` instance ready to use.
    """
    _configure_root_logger(level)
    return logging.getLogger(name)
