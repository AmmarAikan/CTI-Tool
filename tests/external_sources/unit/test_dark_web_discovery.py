from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from backend.app.pipeline.ingestion.external.application.dark_web_discovery import (
    AhmiaHTMLDiscovery, CandidateVerifier, DiscoveryProvider, DynamicDiscoveryScanner,
    canonical_onion_url, normalize_keywords,
)
from backend.app.pipeline.ingestion.external.application.dark_web_watch_service import SQLiteDarkWebWatchStore
from backend.app.pipeline.ingestion.external.dark_web_connector import TorResponse

ONION="a"*56+".onion"

class FakeTor:
    def __init__(self, content:bytes): self.content=content; self.calls=[]
    def get(self,source,url): self.calls.append((source,url)); return TorResponse(200,self.content,"text/html")

class DarkWebDiscoveryTests(unittest.TestCase):
    def provider(self,fetch,max_candidates=20):
        config=DiscoveryProvider("ahmia",True,"ahmia_html","https://search.example/?q={query}&page={page}",False,"search.example",max_result_pages=1,max_candidates=max_candidates,rate_limit_seconds=0)
        return AhmiaHTMLDiscovery(config,fetch,sleeper=lambda _:None)

    def test_canonical_v3_validation_tracking_removal_and_deduplication(self):
        canonical=canonical_onion_url(f"http://{ONION}/reports/./one?utm_source=x&id=2")
        self.assertEqual(canonical,f"http://{ONION}/reports/one?id=2")
        for unsafe in ("https://example.org/",f"http://user:pass@{ONION}/",f"http://{ONION}:80/",f"http://{ONION}/#x",f"http://{ONION}/../x"):
            with self.assertRaises(ValueError): canonical_onion_url(unsafe)
        html=f'<a href="http://{ONION}/x?utm_source=a">fake snippet</a><a href="http://{ONION}/x">duplicate</a>'.encode()
        self.assertEqual(self.provider(lambda *_:html).discover(("Acme",)),[f"http://{ONION}/x"])

    def test_hostile_provider_results_are_bounded_and_snippets_are_not_evidence(self):
        links="".join(f'<a href="http://{ONION}/{i}">keyword only in search snippet</a>' for i in range(30))
        links+=f'<a href="http://user:secret@{ONION}/bad">bad</a><a href="javascript:alert(1)">bad</a>'
        candidates=self.provider(lambda *_:links.encode(),3).discover(("keyword",))
        self.assertEqual(len(candidates),3)
        verifier=CandidateVerifier(FakeTor(b"<html><title>Safe</title><p>unrelated fetched content</p></html>"))
        self.assertIsNone(verifier.verify(candidates[0],("keyword",),"any","ahmia"))

    def test_any_all_verification_hashes_and_safe_projection(self):
        client=FakeTor(b"<html><title>Report</title><p>Acme ransomware affected systems.</p></html>")
        verifier=CandidateVerifier(client)
        one=verifier.verify(f"http://{ONION}/report",("Acme","ransomware"),"all","ahmia")
        self.assertIsNotNone(one); self.assertEqual(one["matched_keywords"],["Acme","ransomware"])
        self.assertNotIn(".onion",one["excerpt"]); self.assertTrue(one["onion_reference"].startswith("onion-ref:"))
        self.assertIsNone(verifier.verify(f"http://{ONION}/report",("Acme","missing"),"all","ahmia"))
        self.assertIsNotNone(verifier.verify(f"http://{ONION}/report",("Acme","missing"),"any","ahmia"))

    def test_repeat_commit_updates_last_seen_and_promotion_is_idempotent(self):
        with tempfile.TemporaryDirectory() as root:
            store=SQLiteDarkWebWatchStore(Path(root)/"watch.sqlite3")
            watch=store.create_advanced(["Acme","ransomware"],"all","ahmia",3600)
            item=CandidateVerifier(FakeTor(b"<p>Acme ransomware</p>")).verify(f"http://{ONION}/x",tuple(watch["keywords"]),"all","ahmia")
            first=store.commit_scan(watch["watch_id"],[item],partial=False); second=store.commit_scan(watch["watch_id"],[item],partial=False)
            self.assertEqual(first["new_result_count"],1); self.assertEqual(second["new_result_count"],0)
            promoted=store.promote(watch["watch_id"],item["result_id"]); repeated=store.promote(watch["watch_id"],item["result_id"])
            self.assertEqual(promoted["source_id"],repeated["source_id"]); self.assertNotIn("protected_url",promoted)
            self.assertEqual(len(store.tracked_urls(watch["watch_id"])),1)

    def test_total_discovery_failure_does_not_advance_checkpoint(self):
        with tempfile.TemporaryDirectory() as root:
            store=SQLiteDarkWebWatchStore(Path(root)/"watch.sqlite3"); watch=store.create_advanced(["Acme"],"any","ahmia",3600)
            broken=self.provider(lambda *_: (_ for _ in ()).throw(OSError("offline")))
            scanner=DynamicDiscoveryScanner({"ahmia":broken},CandidateVerifier(FakeTor(b"Acme")))
            with self.assertRaises(Exception): scanner.scan(watch,[])
            self.assertIsNone(store.get(watch["watch_id"])["checkpoint_hash"])

    def test_keyword_bounds_and_normalization(self):
        self.assertEqual(normalize_keywords(["  Acme  Corp ","Ransomware"]),("Acme Corp","Ransomware"))
        for values in ([],["x"],["Acme","acme"],[str(i) for i in range(11)]):
            with self.assertRaises(ValueError): normalize_keywords(values)

if __name__=="__main__": unittest.main()
