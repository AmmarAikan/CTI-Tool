from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import resource
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
GATEWAY_PATH = ROOT / "infra" / "vps" / "gateway" / "app.py"
SNAPSHOT_BYTES = 101_261_642
INCOMING_BYTES = 921_732
EXISTING_ITEMS = 19_800
INCOMING_ITEMS = 122


def _load_gateway() -> Any:
    for key in (
        "FEED_PUBLISH_TOKEN",
        "FEED_READ_TOKEN",
        "FEED_RESPONSE_HMAC_SECRET",
        "SENSOR_READ_TOKEN",
        "SENSOR_RESPONSE_HMAC_SECRET",
        "CURSOR_HMAC_SECRET",
    ):
        os.environ.setdefault(key, f"test-{key.lower()}-0123456789abcdef")
    spec = importlib.util.spec_from_file_location("cti_vps_gateway_memory_module", GATEWAY_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _item(index: int, content: str = "") -> dict[str, object]:
    return {
        "external_id": f"memory-{index:05d}",
        "source": "synthetic-memory-regression",
        "source_type": "fixture",
        "title": f"Synthetic advisory {index:05d}",
        "content": content,
        "summary": None,
        "url": None,
        "published_at": "2026-09-01T00:00:00Z",
        "collected_at": "2026-09-01T00:01:00Z",
        "category": "regression",
        "tags": ["synthetic", "memory", f"bucket-{index % 32}"],
        "metadata": {
            "fixture": True,
            "sequence": index,
            "attributes": [f"a{part % 100:02d}" for part in range(384)],
        },
    }


def _compact(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _write_snapshot(path: Path) -> None:
    prefix = (
        b'{"feed_id":"external-team-feed","generated_at":"2026-09-01T00:00:00Z",'
        b'"items":['
    )
    suffix = b'],"schema_version":"1.0"}\n'
    item_bytes = sum(len(_compact(_item(index))) for index in range(EXISTING_ITEMS))
    fixed_size = len(prefix) + len(suffix) + item_bytes + EXISTING_ITEMS - 1
    padding = SNAPSHOT_BYTES - fixed_size
    if padding < 0:
        raise AssertionError("synthetic snapshot metadata exceeds requested fixture size")
    per_item, remainder = divmod(padding, EXISTING_ITEMS)

    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("wb") as handle:
        handle.write(prefix)
        for index in range(EXISTING_ITEMS):
            if index:
                handle.write(b",")
            content = "x" * (per_item + (1 if index < remainder else 0))
            handle.write(_compact(_item(index, content)))
        handle.write(suffix)
    if path.stat().st_size != SNAPSHOT_BYTES:
        raise AssertionError(f"unexpected fixture size: {path.stat().st_size}")


def _incoming_payload() -> dict[str, object]:
    payload: dict[str, object] = {
        "completed_at": "2026-09-02T00:00:00Z",
        "dataset": [_item(EXISTING_ITEMS + index) for index in range(INCOMING_ITEMS)],
    }
    base_size = len(_compact(payload))
    padding = INCOMING_BYTES - base_size
    if padding < 0:
        raise AssertionError("synthetic incoming metadata exceeds requested fixture size")
    per_item, remainder = divmod(padding, INCOMING_ITEMS)
    payload["dataset"] = [
        _item(
            EXISTING_ITEMS + index,
            "y" * (per_item + (1 if index < remainder else 0)),
        )
        for index in range(INCOMING_ITEMS)
    ]
    if len(_compact(payload)) != INCOMING_BYTES:
        raise AssertionError("unexpected incoming fixture size")
    return payload


def _legacy_merge(
    gateway: Any,
    path: Path,
    incoming: dict[str, Any],
    settings: Any,
) -> tuple[dict[str, Any], dict[str, int]]:
    existing = json.loads(path.read_bytes().decode("utf-8"))
    merged = {str(item["external_id"]): item for item in existing["items"]}
    inserted = updated = unchanged = 0
    for item in incoming["items"]:
        external_id = str(item["external_id"])
        previous = merged.get(external_id)
        if previous is None:
            inserted += 1
        elif previous == item:
            unchanged += 1
        else:
            updated += 1
        merged[external_id] = item
    envelope = {
        "schema_version": "1.0",
        "feed_id": settings.feed_id,
        "generated_at": incoming["generated_at"],
        "items": [merged[key] for key in sorted(merged)],
    }
    if len(gateway._json_bytes(envelope)) > settings.max_feed_snapshot_bytes:
        raise AssertionError("legacy fixture unexpectedly exceeded the configured limit")
    return envelope, {
        "inserted_items": inserted,
        "updated_items": updated,
        "unchanged_items": unchanged,
    }


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _run_probe(*, legacy: bool = False) -> dict[str, int | str]:
    gateway = _load_gateway()
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        snapshot = root / "external_feed.json"
        _write_snapshot(snapshot)
        payload = _incoming_payload()
        settings = gateway.GatewaySettings(
            feed_publish_token="publish-token-0123456789abcdef",
            feed_read_token="read-token-0123456789abcdefghi",
            feed_hmac_secret="feed-hmac-0123456789abcdefghij",
            sensor_read_token="sensor-token-0123456789abcdef",
            sensor_hmac_secret="sensor-hmac-0123456789abcdefg",
            cursor_secret="cursor-secret-0123456789abcdefg",
            data_dir=root,
            max_feed_snapshot_bytes=110 * 1024 * 1024,
        )
        incoming = gateway._normalize_publish(payload, settings)
        if legacy:
            envelope, counts = _legacy_merge(gateway, snapshot, incoming, settings)
            encoded = gateway._json_bytes(envelope)
            written = len(encoded)
            digest = hashlib.sha256(encoded).hexdigest()
            gateway._atomic_write(snapshot, encoded)
        else:
            envelope, counts, _ = gateway._merge_feed_snapshot(snapshot, incoming, settings)
            digest, written = gateway._atomic_write_json(
                snapshot,
                envelope,
                settings.max_feed_snapshot_bytes,
            )
        if _file_sha256(snapshot) != digest:
            raise AssertionError("persisted digest mismatch")
        return {
            "snapshot_bytes": SNAPSHOT_BYTES,
            "incoming_bytes": INCOMING_BYTES,
            "written_bytes": written,
            "item_count": len(envelope["items"]),
            "inserted_items": counts["inserted_items"],
            "peak_rss_kib": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
        }


class VPSGatewayMemoryRegressionTests(unittest.TestCase):
    @unittest.skipUnless(
        sys.platform.startswith("linux"),
        "RSS units and Gateway runtime are Linux-specific",
    )
    def test_production_sized_snapshot_stays_below_768_mib(self) -> None:
        completed = subprocess.run(
            [sys.executable, __file__, "--probe"],
            check=True,
            capture_output=True,
            text=True,
        )
        result = json.loads(completed.stdout)
        self.assertEqual(result["snapshot_bytes"], SNAPSHOT_BYTES)
        self.assertEqual(result["incoming_bytes"], INCOMING_BYTES)
        self.assertEqual(result["item_count"], EXISTING_ITEMS + INCOMING_ITEMS)
        self.assertEqual(result["inserted_items"], INCOMING_ITEMS)
        self.assertLess(result["peak_rss_kib"], 700 * 1024)


if __name__ == "__main__":
    if sys.argv[1:] in (["--probe"], ["--probe-legacy"]):
        print(json.dumps(_run_probe(legacy=sys.argv[1] == "--probe-legacy"), sort_keys=True))
    else:
        unittest.main()
