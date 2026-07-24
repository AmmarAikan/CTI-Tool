from __future__ import annotations

import os
from pathlib import Path
from typing import Any


class ClassificationModelLoader:
    """Optional loader for a future trained document classifier."""

    def __init__(self, model_path: str | Path | None = None) -> None:
        configured_path = model_path or os.getenv("CTI_CLASSIFIER_MODEL_PATH")
        self.model_path = Path(configured_path) if configured_path else None

    def load(self) -> Any | None:
        if self.model_path is None or not self.model_path.exists():
            return None
        try:
            from joblib import load
        except ImportError:
            return None
        try:
            return load(self.model_path)
        except Exception:
            return None
