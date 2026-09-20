from __future__ import annotations

import json
import unittest

from backend.app.pipeline.ingestion.external.manual_source.json_ingestion import (
    JSONFieldMapping, JSONIngestionError, adapt_records, decode_json, parse_document,
)


HEADERS = {"Content-Type": "application/json"}


class JSONIngestionTests(unittest.TestCase):
    def test_root_and_named_collections_are_independent_records(self):
        for value, path in [
            ([{"id": 1, "title": "One", "content": "body one"}, {"id": 2, "title": "Two", "content": "body two"}], ()),
            ({"posts": [{"id": 1, "name": "One", "message": "body"}]}, ("posts",)),
            ({"items": [{"guid": "a", "headline": "One", "description": "body"}]}, ("items",)),
            ({"results": [{"id": "a", "title": "One", "body": "body"}]}, ("results",)),
            ({"entries": [{"id": "a", "title": "One", "text": "body"}]}, ("entries",)),
            ({"data": [{"id": "a", "title": "One", "content": "body"}]}, ("data",)),
        ]:
            with self.subTest(path=path):
                body = json.dumps(value).encode()
                document = parse_document(body, HEADERS, max_bytes=10_000)
                records = [record for record, error in adapt_records(document, document_url="https://example.test/data.json") if not error]
                self.assertEqual(document.mapping.collection_path, path)
                self.assertEqual(len(records), len(value) if isinstance(value, list) else 1)

    def test_explicit_mapping_supports_one_root_object_and_stable_identity(self):
        mapping = JSONFieldMapping(id_field="id", title_field="title", content_field="body")
        body = b'{"id":"stable","title":"Title","body":"Content"}'
        first = parse_document(body, {"content-type": "application/problem+json"}, max_bytes=1000, mapping=mapping)
        second = parse_document(body, {"content-type": "application/problem+json"}, max_bytes=1000, mapping=mapping)
        self.assertEqual(list(adapt_records(first, document_url="https://example.test/a"))[0][0].identity, "stable")
        self.assertEqual(first.content_hash, second.content_hash)

    def test_malformed_entry_is_isolated(self):
        value = {"items": [{"id": "ok", "title": "Good", "content": "Body"}, {"id": "bad", "title": "Missing"}]}
        document = parse_document(json.dumps(value).encode(), HEADERS, max_bytes=10_000,
                                  mapping=JSONFieldMapping(("items",), "id", "title", "content"))
        outcomes = list(adapt_records(document, document_url="https://example.test/data"))
        self.assertIsNotNone(outcomes[0][0]); self.assertEqual(outcomes[1][1], "missing_required_record_fields")

    def test_empty_collection_is_valid_but_explicitly_warned(self):
        document = parse_document(b'{"items":[]}', HEADERS, max_bytes=1000)
        self.assertEqual((document.approximate_count, document.warnings), (0, ("empty_collection",)))
        self.assertEqual(list(adapt_records(document, document_url="https://example.test/data")), [])

    def test_identity_and_content_hash_distinguish_updates_and_ignore_key_order(self):
        mapping = JSONFieldMapping(("items",), "id", "title", "content")
        first = parse_document(b'{"items":[{"id":"stable","title":"One","content":"before"}]}', HEADERS,
                               max_bytes=1000, mapping=mapping)
        duplicate = parse_document(b'{"items": [{"content":"before","title":"One","id":"stable"}]}', HEADERS,
                                   max_bytes=1000, mapping=mapping)
        updated = parse_document(b'{"items":[{"id":"stable","title":"One","content":"after"}]}', HEADERS,
                                 max_bytes=1000, mapping=mapping)
        records = [list(adapt_records(value, document_url="https://example.test/data"))[0][0]
                   for value in (first, duplicate, updated)]
        self.assertEqual({record.identity for record in records}, {"stable"})
        self.assertNotEqual(first.content_hash, duplicate.content_hash)
        self.assertNotEqual(first.content_hash, updated.content_hash)

    def test_rejects_media_malformed_oversized_deep_and_unsafe_mapping(self):
        cases = [
            (lambda: decode_json(b"{}", {"Content-Type": "text/plain"}, max_bytes=10), "unsupported_content_type"),
            (lambda: decode_json(b"{", HEADERS, max_bytes=10), "malformed_json"),
            (lambda: decode_json(b"{}", HEADERS, max_bytes=1), "response_too_large"),
            (lambda: decode_json(json.dumps([[[[[[[[[[[[[[[[[[[[[1]]]]]]]]]]]]]]]]]]]]]).encode(), HEADERS, max_bytes=1000), "json_too_deep"),
            (lambda: JSONFieldMapping(title_field="__class__", content_field="content"), "invalid_mapping"),
        ]
        for operation, category in cases:
            with self.subTest(category=category), self.assertRaises(JSONIngestionError) as raised: operation()
            self.assertEqual(raised.exception.category, category)

    def test_schema_change_is_non_retryable_and_raw_data_is_not_in_errors(self):
        mapping = JSONFieldMapping(("posts",), "id", "title", "content")
        with self.assertRaises(JSONIngestionError) as raised:
            parse_document(b'{"items":[]}', HEADERS, max_bytes=1000, mapping=mapping)
        self.assertEqual((raised.exception.category, raised.exception.retryable), ("schema_changed", False))
        self.assertEqual(str(raised.exception), "schema_changed")


if __name__ == "__main__":
    unittest.main()
