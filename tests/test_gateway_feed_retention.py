from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import sys
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
GATEWAY_PATH = ROOT / "infra" / "vps" / "gateway" / "app.py"


def load_gateway() -> Any:
    for key in (
        "FEED_PUBLISH_TOKEN",
        "FEED_READ_TOKEN",
        "FEED_RESPONSE_HMAC_SECRET",
        "SENSOR_READ_TOKEN",
        "SENSOR_RESPONSE_HMAC_SECRET",
        "CURSOR_HMAC_SECRET",
    ):
        os.environ.setdefault(key, f"test-{key.lower()}-0123456789abcdef")
    spec = importlib.util.spec_from_file_location("cti_gateway_retention_test", GATEWAY_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


gateway = load_gateway()


def item(index: int, *, revision: str = "v1") -> dict[str, Any]:
    return {
        "external_id": f"record-{index:05d}",
        "source": "retention-fixture",
        "source_type": "fixture",
        "title": f"Record {index}",
        "content": revision,
        "summary": None,
        "url": None,
        "published_at": "2026-01-01T00:00:00Z",
        "collected_at": f"2026-01-{1 + (index % 28):02d}T00:00:00Z",
        "category": "test",
        "tags": [],
        "metadata": {},
    }


class GatewayFeedRetentionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.settings = gateway.GatewaySettings(
            feed_publish_token="publish-token-0123456789abcdef",
            feed_read_token="read-token-0123456789abcdefghi",
            feed_hmac_secret="feed-hmac-0123456789abcdefghij",
            sensor_read_token="sensor-token-0123456789abcdef",
            sensor_hmac_secret="sensor-hmac-0123456789abcdefg",
            cursor_secret="cursor-secret-0123456789abcdefg",
            data_dir=self.root,
            max_feed_items=20_000,
            max_feed_snapshot_bytes=100 * 1024 * 1024,
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _seed(self, values: list[dict[str, Any]], unacknowledged: set[str]) -> str:
        envelope = {
            "schema_version": "1.0",
            "feed_id": self.settings.feed_id,
            "generated_at": "2026-09-24T00:00:00Z",
            "items": sorted(values, key=lambda value: value["external_id"]),
        }
        digest, _ = gateway._atomic_write_json(
            gateway._feed_path(self.settings),
            envelope,
            self.settings.max_feed_snapshot_bytes,
        )
        gateway._write_feed_delivery_state(self.settings, digest, unacknowledged)
        return digest

    def _publish(self, values: list[dict[str, Any]], generated_at: str) -> tuple[Any, Any, Any, str]:
        incoming = {
            "schema_version": "1.0",
            "feed_id": self.settings.feed_id,
            "generated_at": generated_at,
            "items": values,
        }
        envelope, counts, unacknowledged = gateway._merge_feed_snapshot(
            gateway._feed_path(self.settings), incoming, self.settings
        )
        digest, _ = gateway._atomic_write_json(
            gateway._feed_path(self.settings), envelope, self.settings.max_feed_snapshot_bytes
        )
        gateway._write_feed_delivery_state(
            self.settings, digest, unacknowledged, last_publish=counts
        )
        return envelope, counts, unacknowledged, digest

    def test_production_boundary_replay_and_followup_are_bounded_and_deterministic(self) -> None:
        existing = [item(index) for index in range(19_737)]
        safe_ids = {value["external_id"] for value in existing[:10_874]}
        all_ids = {value["external_id"] for value in existing}
        self._seed(existing, all_ids - safe_ids)
        incoming = [item(index, revision="v2") for index in range(19_604, 19_737)]
        incoming.extend(item(index) for index in range(19_737, 20_236))

        envelope, counts, unacknowledged, digest = self._publish(
            incoming, "2026-09-25T00:39:20Z"
        )

        self.assertEqual(counts["previous_count"], 19_737)
        self.assertEqual(counts["incoming_count"], 632)
        self.assertEqual(counts["overlap_count"], 133)
        self.assertEqual(counts["new_count"], 499)
        self.assertEqual(counts["pruned_count"], 236)
        self.assertEqual(counts["final_count"], 20_000)
        self.assertEqual(len(envelope["items"]), 20_000)
        self.assertTrue({value["external_id"] for value in incoming}.issubset(
            {value["external_id"] for value in envelope["items"]}
        ))
        self.assertTrue({value["external_id"] for value in incoming}.issubset(unacknowledged))
        self.assertEqual(
            [value["external_id"] for value in envelope["items"]],
            sorted(value["external_id"] for value in envelope["items"]),
        )
        first_bytes = gateway._feed_path(self.settings).read_bytes()
        self.assertEqual(hashlib.sha256(first_bytes).hexdigest(), digest)

        replay_envelope, replay_counts, replay_unacknowledged, replay_digest = self._publish(
            incoming, "2026-09-25T00:39:20Z"
        )
        self.assertEqual(replay_counts["new_count"], 0)
        self.assertEqual(replay_counts["pruned_count"], 0)
        self.assertEqual(replay_counts["final_count"], 20_000)
        self.assertEqual(gateway._feed_path(self.settings).read_bytes(), first_bytes)
        self.assertEqual(replay_digest, digest)
        self.assertEqual(replay_envelope, envelope)
        self.assertEqual(replay_unacknowledged, unacknowledged)

        followup = [item(index) for index in range(20_236, 20_261)]
        final, followup_counts, final_unacknowledged, _ = self._publish(
            followup, "2026-09-25T02:00:00Z"
        )
        self.assertEqual(followup_counts["new_count"], 25)
        self.assertEqual(followup_counts["pruned_count"], 25)
        self.assertEqual(followup_counts["final_count"], 20_000)
        self.assertTrue({value["external_id"] for value in followup}.issubset(final_unacknowledged))
        self.assertEqual(len(final["items"]), self.settings.max_feed_items)

    def test_update_becomes_protected_and_unacknowledged_capacity_never_evicts(self) -> None:
        existing = [item(1), item(2)]
        self.settings = replace(self.settings, max_feed_items=2)
        self._seed(existing, set())
        updated, counts, unacknowledged, _ = self._publish(
            [item(1, revision="updated")], "2026-09-25T01:00:00Z"
        )
        self.assertEqual(counts["updated_items"], 1)
        self.assertIn("record-00001", unacknowledged)
        self.assertEqual(updated["items"][0]["content"], "updated")

        current_ids = {value["external_id"] for value in updated["items"]}
        digest = gateway._sha256_file(gateway._feed_path(self.settings))
        gateway._write_feed_delivery_state(self.settings, digest, current_ids)
        before_snapshot = gateway._feed_path(self.settings).read_bytes()
        before_state = gateway._feed_delivery_state_path(self.settings).read_bytes()
        incoming = {
            "schema_version": "1.0",
            "feed_id": self.settings.feed_id,
            "generated_at": "2026-09-25T02:00:00Z",
            "items": [item(3)],
        }
        with self.assertRaisesRegex(gateway.HTTPException, "unacknowledged"):
            gateway._merge_feed_snapshot(gateway._feed_path(self.settings), incoming, self.settings)
        self.assertEqual(gateway._feed_path(self.settings).read_bytes(), before_snapshot)
        self.assertEqual(gateway._feed_delivery_state_path(self.settings).read_bytes(), before_state)

    def test_partial_and_complete_ack_are_idempotent_and_checkpoint_bound(self) -> None:
        values = [item(1), item(2), item(3)]
        digest = self._seed(values, {value["external_id"] for value in values})
        first = gateway._acknowledge_feed_delivery(
            self.settings, digest, ["record-00001", "record-00002"]
        )
        self.assertEqual(first["scope"], "verified_subset")
        self.assertEqual(first["newly_acknowledged_items"], 2)
        self.assertEqual(first["unacknowledged_items"], 1)
        repeated = gateway._acknowledge_feed_delivery(
            self.settings, digest, ["record-00001", "record-00002"]
        )
        self.assertEqual(repeated["newly_acknowledged_items"], 0)
        complete = gateway._acknowledge_feed_delivery(self.settings, digest, None)
        self.assertEqual(complete["unacknowledged_items"], 0)
        with self.assertRaisesRegex(gateway.HTTPException, "stale"):
            gateway._acknowledge_feed_delivery(self.settings, "0" * 64, None)


if __name__ == "__main__":
    unittest.main()
