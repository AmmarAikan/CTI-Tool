"""
Content Classification module.

Wraps the already-trained TF-IDF + LinearSVC pipeline (built and
trained by another team — see the uploaded `main.py`/README for how)
to distinguish CTI-relevant content from general content. This module
contains NO training logic and does not modify the model in any way —
it only loads the existing trained pipeline once and exposes a single
reusable `classify(text) -> bool` function.

IMPORTANT — preprocessing must match training exactly:
The training script (`main.py`) did NOT rely solely on the sklearn
Pipeline's own TfidfVectorizer for preprocessing. Before ever calling
`.fit()`, it manually: lowercased the text, replaced every CVE ID with
the literal token `specifiedcve`, and replaced every IPv4 address with
the literal token `specifiedip`. Those substitutions are NOT part of
the pickled Pipeline (TfidfVectorizer only lowercases and tokenizes —
it has no idea what a CVE ID or an IP address is), so skipping them
here would feed the model a systematically different input
distribution than it was trained on. Testing this confirmed it's not
a hypothetical concern: skipping this preprocessing measurably degrades
predictions. `_preprocess()` below replicates those exact steps.

IMPORTANT — this model expects article-length text:
Empirically verified while integrating this: the same non-CTI topic,
written as a full multi-paragraph article, was correctly classified as
0 — but written as a single short sentence, it was misclassified as 1.
TF-IDF + a linear SVM decision boundary trained on full article text
doesn't carry enough signal on very short input to be reliable. Always
pass the fullest text available for an item (its `content` field, not
just a `title` or short `summary`) into `classify()`.
"""

import re
from pathlib import Path
from typing import Any, Dict, List, Optional

from src.utils.logger import get_logger

logger = get_logger(__name__)

MODEL_PATH = Path(__file__).resolve().parent / "model" / "cti_svm_model.pkl"

# Same two regexes as the training script (main.py), applied in the same
# order, before lowercasing — kept as module-level constants so they're
# defined in exactly one place.
_CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
_IPV4_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

# Loaded lazily, once, on first use — and reused for every subsequent
# call for the lifetime of the process. Never reloaded per article.
_model: Optional[object] = None
_load_attempted = False


def _preprocess(text: str) -> str:
    """
    Replicate the training script's exact text normalization:
    CVE IDs -> 'specifiedcve', IPv4 addresses -> 'specifiedip', then
    lowercase. Order matters (CVE/IP substitution happens before
    lowercasing the whole string, same as `main.py`).
    """
    text = _CVE_PATTERN.sub("specifiedcve", text)
    text = _IPV4_PATTERN.sub("specifiedip", text)
    return text.lower()


def _load_model():
    """
    Load the trained pipeline from disk exactly once per process.
    Subsequent calls return the already-loaded object immediately —
    the model is never reloaded per article, per the requirement.
    """
    global _model, _load_attempted

    if _model is not None:
        return _model
    if _load_attempted:
        # A previous load already failed this process; don't retry on
        # every single call (that would negate the "load once" goal
        # and spam the log for every article).
        return None
    _load_attempted = True

    if not MODEL_PATH.exists():
        logger.error(
            "Classification model not found at %s. classify() will fail open "
            "(return True) for every call until the trained model file is placed there.",
            MODEL_PATH,
        )
        return None

    try:
        import joblib

        _model = joblib.load(MODEL_PATH)
        logger.info("Content classification model loaded from %s", MODEL_PATH)
        return _model
    except Exception as e:  # noqa: BLE001 - a bad model file must not crash the pipeline
        logger.error("Failed to load classification model from %s: %s", MODEL_PATH, e)
        return None


def classify(text: str) -> bool:
    """
    Classify a piece of text as CTI-relevant or not.

    Args:
        text: Plain, already-cleaned text (e.g. an item's `content`
            field) — never raw HTML. Should be the fullest text
            available for the item; very short input (a title or a
            one-line summary) is unreliable for this model (see module
            docstring).

    Returns:
        True if the model predicts the CTI-relevant class, False
        otherwise. Empty/whitespace-only text always returns False
        (nothing to classify). Fails open — returns True — if the
        model can't be loaded or prediction raises, so a classifier
        problem never silently discards otherwise-good collected data;
        both cases are logged clearly either way.
    """
    if not text or not text.strip():
        return False

    model = _load_model()
    if model is None:
        return True  # fail open: don't silently discard data over a missing/broken model

    try:
        processed = _preprocess(text)
        prediction = model.predict([processed])[0]
        return bool(prediction == 1)
    except Exception as e:  # noqa: BLE001 - one bad text must not crash the caller
        logger.error("Classification failed for a text sample: %s", e)
        return True  # fail open


def filter_cti_relevant(items: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Filter a list of unified CTIItem dicts, keeping only those the
    classifier judges CTI-relevant.

    This is the single, shared integration point every general-purpose
    collector (Reddit, Telegram, Mastodon, GitHub, general web
    crawling, and any future community/general-purpose source) should
    call right before saving — rather than each collector re-implementing
    the same "get an item's text, call classify(), keep or discard" loop.

    Trusted CTI sources (curated RSS feeds, CERT, NVD/MITRE) should
    NEVER call this: their content is already guaranteed relevant by
    virtue of where it came from, and running it through the classifier
    would just add cost without adding value.

    Args:
        items: List of unified CTI item dicts, each expected to carry a
            `content` field (falling back to `summary` if empty) —
            already-cleaned text, never raw HTML.

    Returns:
        The subset of `items` classified as CTI-relevant, in the same
        order. Discarded items are logged (count only, not per-item, to
        avoid flooding the log) at INFO level.
    """
    kept = []
    discarded = 0

    for item in items:
        text = item.get("content") or item.get("summary") or ""
        if classify(text):
            kept.append(item)
        else:
            discarded += 1

    if discarded:
        logger.info(
            "Classification filter: kept %d item(s), discarded %d as not CTI-relevant.",
            len(kept), discarded,
        )

    return kept


if __name__ == "__main__":
    # Quick manual smoke test — not an automated test suite, just a
    # convenience check that the model loads and predicts sensibly.
    samples = [
        ("A critical remote code execution vulnerability CVE-2024-1234 was disclosed "
         "today affecting a widely deployed VPN appliance, allowing unauthenticated "
         "attackers to execute arbitrary code on affected systems without user interaction.", True),
        ("Ransomware group LockBit claims responsibility for a breach of a hospital network, "
         "encrypting patient records across multiple facilities and demanding a large payment "
         "in cryptocurrency before a disclosed deadline passes.", True),
        ("The stock market rallied today as major technology companies reported strong "
         "quarterly earnings that beat analyst expectations across the board, sending the "
         "Nasdaq composite index to its best single-day performance in months.", False),
    ]
    for text, expected in samples:
        result = classify(text)
        status = "OK" if result == expected else "UNEXPECTED"
        print(f"[{status}] classify() -> {result} (expected {expected}) | {text[:60]}...")
