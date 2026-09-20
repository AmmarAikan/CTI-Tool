from __future__ import annotations

import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import Mock
from urllib.parse import parse_qs, urlsplit

import requests
from bs4 import BeautifulSoup

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
        config=DiscoveryProvider("ahmia",True,"ahmia_html","https://search.example/search/?q={query}&page={page}",True,"search.example",max_result_pages=1,max_candidates=max_candidates,rate_limit_seconds=0)
        def tokenized(endpoint,*args):
            if urlsplit(endpoint).path=="/":return b'<form id="searchForm" action="/search/" method="get"><input type="hidden" name="abcdef" value="123abc"></form>'
            return fetch(endpoint,*args)
        return AhmiaHTMLDiscovery(config,tokenized,sleeper=lambda _:None)

    @staticmethod
    def results(*urls):
        links="".join(f'<li class="result"><h4><a href="/search/redirect?search_term=x&amp;redirect_url={url}">x</a></h4></li>' for url in urls)
        return f'<div id="ahmiaResultsPage"><ol class="searchResults">{links}</ol></div>'.encode()

    def test_canonical_v3_validation_tracking_removal_and_deduplication(self):
        canonical=canonical_onion_url(f"http://{ONION}/reports/./one?utm_source=x&id=2")
        self.assertEqual(canonical,f"http://{ONION}/reports/one?id=2")
        for unsafe in ("https://example.org/",f"http://user:pass@{ONION}/",f"http://{ONION}:80/",f"http://{ONION}/#x",f"http://{ONION}/../x"):
            with self.assertRaises(ValueError): canonical_onion_url(unsafe)
        html=self.results(f"http://{ONION}/x?utm_source=a",f"http://{ONION}/x")
        self.assertEqual(self.provider(lambda *_:html).discover(("Acme",)),[f"http://{ONION}/x"])

    def test_hostile_provider_results_are_bounded_and_snippets_are_not_evidence(self):
        links=[f"http://{ONION}/{i}" for i in range(30)]+[f"http://user:secret@{ONION}/bad","javascript:alert(1)"]
        candidates=self.provider(lambda *_:self.results(*links),3).discover(("keyword",))
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
            promoted=store.promote(watch["watch_id"],item["result_id"],item["content_sha256"]); repeated=store.promote(watch["watch_id"],item["result_id"],item["content_sha256"])
            self.assertEqual(promoted["source_id"],repeated["source_id"]); self.assertNotIn("protected_url",promoted)
            self.assertEqual(len(store.tracked_urls(watch["watch_id"])),1)

    def test_total_discovery_failure_does_not_advance_checkpoint(self):
        with tempfile.TemporaryDirectory() as root:
            store=SQLiteDarkWebWatchStore(Path(root)/"watch.sqlite3"); watch=store.create_advanced(["Acme"],"any","ahmia",3600)
            broken=self.provider(lambda *_: (_ for _ in ()).throw(OSError("offline")))
            scanner=DynamicDiscoveryScanner({"ahmia":broken},CandidateVerifier(FakeTor(b"Acme")))
            with self.assertRaises(Exception): scanner.scan(watch,[])
            self.assertIsNone(store.get(watch["watch_id"])["checkpoint_hash"])

    def test_provider_failure_does_not_block_direct_tracked_onion_verification(self):
        tracked=f"http://{ONION}/tracked"
        discovery=self.provider(lambda *_: (_ for _ in ()).throw(DiscoveryUnavailable("provider_server_failure",retryable=True)))
        verifier=CandidateVerifier(FakeTor(b"<p>Acme direct evidence</p>"))
        matches,partial,counts=DynamicDiscoveryScanner({"ahmia":discovery},verifier).scan(
            {"provider_id":"ahmia","keywords":["Acme"],"match_mode":"any"},[tracked])
        self.assertTrue(partial);self.assertEqual(len(matches),1)
        self.assertEqual(counts["discovered"],0);self.assertEqual(counts["verified"],1);self.assertEqual(counts["errors"],1)
        self.assertEqual(verifier.client.calls[0][1],tracked)

    def test_provider_failure_without_direct_sources_is_not_empty_success(self):
        discovery=self.provider(lambda *_: (_ for _ in ()).throw(DiscoveryUnavailable("provider_server_failure",retryable=True)))
        with self.assertRaises(DiscoveryUnavailable):
            DynamicDiscoveryScanner({"ahmia":discovery},CandidateVerifier(FakeTor(b""))).scan(
                {"provider_id":"ahmia","keywords":["Acme"],"match_mode":"any"},[])

    def test_provider_identity_is_revalidated_for_every_scan(self):
        enabled=self.provider(lambda *_:b'<div id="ahmiaResultsPage"><p id="noResults"></p></div>')
        disabled_config=DiscoveryProvider("disabled",False,"ahmia_html","https://search.example/search/?q={query}&page={page}",True,"search.example")
        scanner=DynamicDiscoveryScanner({"ahmia":enabled,"disabled":AhmiaHTMLDiscovery(disabled_config,lambda *_:b"")},CandidateVerifier(FakeTor(b"")))
        with self.assertRaises(ProviderMissing): scanner.scan({"provider_id":"missing","keywords":["Acme"]},[])
        with self.assertRaises(ProviderDisabled): scanner.scan({"provider_id":"disabled","keywords":["Acme"]},[])
        self.assertEqual(scanner.scan({"provider_id":"ahmia","keywords":["Acme"]},[])[2]["discovered"],0)

    def test_watch_creation_validates_provider_before_database_mutation(self):
        enabled=self.provider(lambda *_:b'<div id="ahmiaResultsPage"><p id="noResults"></p></div>')
        disabled_config=DiscoveryProvider("disabled",False,"ahmia_html","https://search.example/search/?q={query}&page={page}",True,"search.example")
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
            response=Mock(status_code=status,headers={},url="https://search.example/");response.close=Mock()
            session=Mock();session.cookies=Mock();session.get.return_value=response
            client=ProviderHttpClient("socks5h://proxy.invalid:9050",session,sleeper=lambda _:None,jitter=lambda *_:0)
            with self.assertRaises(DiscoveryUnavailable) as raised: client.fetch("https://search.example/",True,10)
            self.assertIs(raised.exception.retryable,retryable)
            self.assertNotIn("search.example",raised.exception.public_message)

    def test_provider_client_sends_application_identity_and_accepts_only_exact_html_response(self):
        response=Mock(status_code=200,headers={"Content-Type":"text/html; charset=utf-8"},url="https://search.example/search/?q=x&page=0")
        response.iter_content.return_value=[b"<html></html>"];session=Mock();session.cookies=Mock();session.get.return_value=response
        payload=ProviderHttpClient("socks5h://tor:9050",session).fetch(response.url,True,10)
        self.assertEqual(payload,b"<html></html>")
        kwargs=session.get.call_args.kwargs
        self.assertEqual(kwargs["headers"]["User-Agent"],"CTI-Tool-DarkWeb-Monitor/1.0")
        self.assertFalse(kwargs["allow_redirects"]);self.assertEqual(kwargs["proxies"]["https"],"socks5h://tor:9050")

    def test_official_form_contract_produces_exact_get_parameters(self):
        captured=[]
        homepage=b'''<form id="searchForm" action="/search/" method="get">
          <input name="q"><input type="hidden" name="abcdef" value="123abc">
        </form>'''
        empty=b'<main id="ahmiaResultsPage"><p id="noResults">None</p></main>'
        def fetch(endpoint,*_): captured.append(endpoint);return homepage if urlsplit(endpoint).path=="/" else empty
        provider=DiscoveryProvider("ahmia",True,"ahmia_html","https://search.example/search/?q={query}&page={page}",True,"search.example",max_result_pages=1)
        self.assertEqual(AhmiaHTMLDiscovery(provider,fetch).discover(("Acme & Co",)),[])
        request=urlsplit(captured[1]);params=parse_qs(request.query)
        self.assertEqual((request.scheme,request.hostname,request.path),("https","search.example","/search/"))
        self.assertEqual(params,{"q":["Acme & Co"],"page":["0"],"abcdef":["123abc"]})
        form=BeautifulSoup(homepage,"html.parser").select_one("#searchForm")
        self.assertEqual(form.get("method"),"get")

    def test_server_failures_retry_with_bounded_exponential_jitter(self):
        endpoint="https://search.example/search/?q=x&page=0"
        responses=[]
        for status in (503,502,200):
            response=Mock(status_code=status,headers={"Content-Type":"text/html"},url=endpoint)
            response.close=Mock();response.iter_content.return_value=[b"ok"];responses.append(response)
        session=Mock();session.cookies=Mock();session.get.side_effect=responses;delays=[]
        client=ProviderHttpClient("socks5h://tor:9050",session,sleeper=delays.append,jitter=lambda *_:.05)
        self.assertEqual(client.fetch(endpoint,True,10),b"ok")
        self.assertEqual(session.get.call_count,3);self.assertEqual(delays,[.3,.55])
        self.assertTrue(all(call.kwargs["allow_redirects"] is False for call in session.get.call_args_list))

    def test_server_failure_attempts_are_capped_and_remain_retryable(self):
        endpoint="https://search.example/search/?q=x&page=0"
        response=Mock(status_code=503,headers={"Content-Type":"text/html"},url=endpoint);response.close=Mock()
        session=Mock();session.cookies=Mock();session.get.return_value=response
        with self.assertRaises(DiscoveryUnavailable) as raised:
            ProviderHttpClient("socks5h://tor:9050",session,sleeper=lambda _:None,jitter=lambda *_:0).fetch(endpoint,True,10)
        self.assertEqual(session.get.call_count,3);self.assertTrue(raised.exception.retryable)
        self.assertEqual(raised.exception.reason,"provider_server_failure")

    def test_provider_redirects_home_unapproved_host_and_downgrade_are_rejected(self):
        for location in ("/","https://other.example/search/","http://search.example/search/"):
            response=Mock(status_code=302,headers={"Location":location},url="https://search.example/search/?q=x&page=0")
            session=Mock();session.cookies=Mock();session.get.return_value=response
            with self.subTest(location=location),self.assertRaises(DiscoveryUnavailable) as raised:
                ProviderHttpClient("socks5h://tor:9050",session).fetch(response.url,True,10)
            self.assertEqual(raised.exception.reason,"provider_redirect_blocked");session.get.assert_called_once()

    def test_homepage_challenge_and_unstructured_html_are_not_empty_results(self):
        for body in (b'<form id="searchForm"></form>',b'<html><title>Challenge</title></html>',b'<div id="ahmiaResultsPage"></div>'):
            discovery=self.provider(lambda *_:body)
            with self.subTest(body=body[:20]),self.assertRaises(DiscoveryUnavailable):discovery.discover(("Acme",))

    def test_content_type_size_and_safe_network_errors(self):
        endpoint="https://search.example/search/?q=private&page=0"
        wrong=Mock(status_code=200,headers={"Content-Type":"application/json"},url=endpoint);wrong.close=Mock()
        session=Mock();session.cookies=Mock();session.get.return_value=wrong
        with self.assertRaises(DiscoveryUnavailable) as raised:ProviderHttpClient("socks5h://tor:9050",session).fetch(endpoint,True,10)
        self.assertNotIn("private",raised.exception.public_message)
        large=Mock(status_code=200,headers={"Content-Type":"text/html"},url=endpoint);large.iter_content.return_value=[b"x"*1_048_577]
        session.get.return_value=large
        with self.assertRaises(DiscoveryUnavailable) as raised:ProviderHttpClient("socks5h://tor:9050",session).fetch(endpoint,True,10)
        self.assertEqual(raised.exception.reason,"provider_response_too_large")
        session.get.side_effect=requests.ConnectionError(f"secret {ONION}")
        with self.assertRaises(DiscoveryUnavailable) as raised:ProviderHttpClient("socks5h://tor:9050",session).fetch(endpoint,True,10)
        self.assertTrue(raised.exception.retryable);self.assertNotIn(ONION,raised.exception.public_message)

    def test_keyword_bounds_and_normalization(self):
        self.assertEqual(normalize_keywords(["  Acme  Corp ","Ransomware"]),("Acme Corp","Ransomware"))
        for values in ([],["x"],["Acme","acme"],[str(i) for i in range(11)]):
            with self.assertRaises(ValueError): normalize_keywords(values)

if __name__=="__main__": unittest.main()
