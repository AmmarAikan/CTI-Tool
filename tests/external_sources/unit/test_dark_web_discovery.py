from __future__ import annotations

import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import Mock

import requests

from backend.app.pipeline.ingestion.external.application.dark_web_discovery import (
    AhmiaHTMLDiscovery, CandidateVerifier, DiscoveryProvider, DiscoveryUnavailable, DynamicDiscoveryScanner, ProviderHttpClient,
    ProviderDisabled, ProviderMissing,
    canonical_onion_url, normalize_keywords,
)
from backend.app.pipeline.ingestion.external.integration.jobs import InProcessJobRunner
from backend.app.pipeline.ingestion.external.application.dark_web_watch_service import SQLiteDarkWebWatchStore
from backend.app.pipeline.ingestion.external.application.dark_web_watch_service import DarkWebWatchService
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

    def test_provider_identity_is_revalidated_for_every_scan(self):
        enabled=self.provider(lambda *_:b"")
        disabled_config=DiscoveryProvider("disabled",False,"ahmia_html","https://search.example/?q={query}",False,"search.example")
        scanner=DynamicDiscoveryScanner({"ahmia":enabled,"disabled":AhmiaHTMLDiscovery(disabled_config,lambda *_:b"")},CandidateVerifier(FakeTor(b"")))
        with self.assertRaises(ProviderMissing): scanner.scan({"provider_id":"missing","keywords":["Acme"]},[])
        with self.assertRaises(ProviderDisabled): scanner.scan({"provider_id":"disabled","keywords":["Acme"]},[])
        self.assertEqual(scanner.scan({"provider_id":"ahmia","keywords":["Acme"]},[])[2]["discovered"],0)

    def test_watch_creation_validates_provider_before_database_mutation(self):
        enabled=self.provider(lambda *_:b"")
        disabled_config=DiscoveryProvider("disabled",False,"ahmia_html","https://search.example/?q={query}",False,"search.example")
        scanner=DynamicDiscoveryScanner({"ahmia":enabled,"disabled":AhmiaHTMLDiscovery(disabled_config,lambda *_:b"")},CandidateVerifier(FakeTor(b"")))
        store=Mock();store.create_advanced.return_value={"provider_id":"ahmia"}
        service=DarkWebWatchService(store,Mock(),scanner)
        with self.assertRaises(ProviderMissing): service.create_discovery_watch(["Acme"],"any","missing",3600)
        with self.assertRaises(ProviderDisabled): service.create_discovery_watch(["Acme"],"any","disabled",3600)
        store.create_advanced.assert_not_called()
        self.assertEqual(service.create_discovery_watch(["Acme"],"any","ahmia",3600)["provider_id"],"ahmia")
        store.create_advanced.assert_called_once_with(["Acme"],"any","ahmia",3600)

    def test_existing_discovery_watch_never_falls_back_when_provider_registry_is_missing(self):
        store=Mock();store.get.return_value={"watch_id":"dww-existing","enabled":True,"provider_id":"missing","keyword":"Acme"}
        service=DarkWebWatchService(store,Mock(),None)
        with self.assertRaises(ProviderMissing): service.scan("dww-existing")
        service.scanner.scan.assert_not_called();store.commit_scan.assert_not_called()

    def test_transient_discovery_failure_is_safe_and_retryable(self):
        discovery=self.provider(lambda *_: (_ for _ in ()).throw(requests.Timeout("secret endpoint")))
        with self.assertRaises(DiscoveryUnavailable) as raised: discovery.discover(("Acme",))
        self.assertTrue(raised.exception.retryable);self.assertEqual(raised.exception.code,"provider_temporarily_unavailable")
        self.assertNotIn("secret",raised.exception.public_message)
        runner=InProcessJobRunner(max_workers=1)
        try:
            job=runner.submit("cmd-safe",lambda: discovery.discover(("Acme",)))
            for _ in range(100):
                terminal=runner.get(job.job_id)
                if terminal and terminal.state=="failed": break
                time.sleep(.01)
            self.assertEqual(terminal.error,{"code":"provider_temporarily_unavailable","message":"discovery provider is temporarily unavailable","retryable":True,"details":{}})
            self.assertNotIn("secret",str(terminal.safe_dict()))
        finally: runner.shutdown()

    def test_rate_limit_and_server_failures_are_retryable_but_client_failure_is_not(self):
        for status,retryable in ((429,True),(503,True),(404,False)):
            response=Mock(status_code=status,headers={});response.close=Mock()
            session=Mock();session.cookies=Mock();session.get.return_value=response
            client=ProviderHttpClient("socks5h://proxy.invalid:9050",session)
            with self.assertRaises(DiscoveryUnavailable) as raised: client.fetch("https://search.example/",True,10)
            self.assertIs(raised.exception.retryable,retryable)
            self.assertNotIn("search.example",raised.exception.public_message)

    def test_keyword_bounds_and_normalization(self):
        self.assertEqual(normalize_keywords(["  Acme  Corp ","Ransomware"]),("Acme Corp","Ransomware"))
        for values in ([],["x"],["Acme","acme"],[str(i) for i in range(11)]):
            with self.assertRaises(ValueError): normalize_keywords(values)

if __name__=="__main__": unittest.main()
