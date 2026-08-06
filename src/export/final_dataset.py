"""
Final dataset consolidation — Phase 8.

Runs as the last step in the pipeline, after every collector has
finished. Merges the most recent output from every external source
into a single file for handoff to the next team (NER / IOC extraction).

This module does NOT re-implement anything from the collectors — every
one of them already produces the exact same unified schema
(`src.utils.schema.CTIItem`: title, link, source, category, content,
summary, published, author, tags, collected_at, metadata), so merging
is just "load the newest file per source prefix, concatenate the
lists." No per-source parsing or transformation logic lives here.

What this module DOES add on top of the raw merge:
- Drops any item with empty `content` — nothing for NER/IOC extraction
  to work on, and no point handing the next team empty records.
- Adds a stable `record_id` per item (short hash of `link`, falling
  back to `title`) — a predictable unique key the next team can use
  for their own storage/deduplication, without requiring any schema
  change to `CTIItem` itself (this is added only in the final export,
  not in any collector's own output).

Trusted vs. general-purpose sources are handled identically here —
that distinction only matters for the classification step further
upstream (already applied inside each general-purpose collector's own
`run()`); by the time output reaches this module, everything is
already a normalized, already-cleaned CTIItem dict regardless of
origin.
"""

import hashlib
from datetime import datetime, timezone
from typing import Any, Dict, List

from src.utils.logger import get_logger
from src.utils.storage import latest_file, load_json, save_json, timestamped_filename

logger = get_logger(__name__)

# Every source's output-file prefix, exactly as each collector's own
# `run()` already names it via `timestamped_filename(prefix)`. Adding a
# future source later just means adding one more prefix here.
SOURCE_PREFIXES = [
    "clean_articles",        # Phase 1-3: RSS + Web Crawler + Text Cleaning
    "cert_advisories",       # Phase 4: CERT
    "vulnerabilities",       # Phase 5: NVD / MITRE CVE
    "social_media_posts",    # Phase 6: Reddit
    "hackernews_posts",      # Phase 6: Hacker News
    "github_advisories",     # Phase 6: GitHub Security Advisories
    "telegram_posts",        # Phase 6: Telegram
    "dark_web_posts",        # Phase 7: Dark Web
]


def _make_record_id(item: Dict[str, Any]) -> str:
    """
    Build a short, stable identifier for a record so the next team has
    a predictable unique key without needing any schema change. Derived
    from `link` (falling back to `title`) via SHA-256 — the same
    pattern used elsewhere in this project (deterministic across runs,
    useful for de-duplication/upserts downstream).
    """
    basis = item.get("link") or item.get("title") or ""
    return hashlib.sha256(basis.encode("utf-8")).hexdigest()[:16]


def build_final_dataset() -> List[Dict[str, Any]]:
    """
    Load the newest output file for every known source prefix, merge
    them into one list, drop empty-content records, and tag each with
    a stable `record_id`.

    A source with no output file yet (collector never ran, or produced
    nothing this run) is logged and skipped — never treated as an
    error, since that's an expected, normal state for e.g. Dark Web
    when no source is configured/enabled.

    Returns:
        The merged, deduplicated-by-nothing-yet (that's for the next
        team), record_id-tagged list of items.
    """
    merged: List[Dict[str, Any]] = []

    for prefix in SOURCE_PREFIXES:
        filepath = latest_file(prefix)
        if not filepath:
            logger.info("No output found for source '%s'; skipping (not an error).", prefix)
            continue

        items = load_json(filepath)
        if not items:
            logger.info("Source '%s' output file was empty; skipping.", prefix)
            continue

        kept_for_source = 0
        for item in items:
            content = item.get("content") or ""
            if not content.strip():
                continue  # nothing for NER/IOC extraction to work on

            item["record_id"] = _make_record_id(item)
            merged.append(item)
            kept_for_source += 1

        logger.info(
            "Merged %d record(s) from '%s' (source file: %s).",
            kept_for_source, prefix, filepath,
        )

    return merged


def run() -> str:
    """
    Convenience entry point matching every other phase's `run()`
    pattern: build the merged dataset and save it via the existing
    storage layer.

    Returns:
        Path to the written file, or an empty string if nothing was
        available to merge or saving failed.
    """
    dataset = build_final_dataset()

    if not dataset:
        logger.warning("Final dataset consolidation produced no records.")
        return ""

    filename = timestamped_filename("final_dataset")
    output_path = save_json(dataset, filename)

    if output_path:
        logger.info(
            "Final dataset ready for NER/IOC extraction: %d records across %d source(s). Output: %s",
            len(dataset),
            len({item.get("source") for item in dataset}),
            output_path,
        )

    return output_path


if __name__ == "__main__":
    output_path = run()
    if output_path:
        print(f"Final dataset build complete. Output saved to: {output_path}")
    else:
        print("Final dataset build finished with no output.")