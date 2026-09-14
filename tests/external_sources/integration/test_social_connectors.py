from __future__ import annotations

import json
import unittest
import requests
from datetime import datetime, timezone
from pathlib import Path

from jsonschema import Draft202012Validator

from backend.app.pipeline.ingestion.external.classification.classification_service import ClassificationService
from backend.app.pipeline.ingestion.external.classification.classifier import ClassificationResult, MODEL_SHA256, MODEL_VERSION
from backend.app.pipeline.ingestion.external.common.http_client import HttpResponse, ResponseTooLargeError
from backend.app.pipeline.ingestion.external.crawler.web_crawler import CrawlResult
from backend.app.pipeline.ingestion.external.hackernews_connector import HackerNewsConnector, HackerNewsSource
from backend.app.pipeline.ingestion.external.reddit_connector import RedditAccessError, RedditConnector, RedditPost, RedditPublicRSSClient, RedditSource
from backend.app.pipeline.ingestion.external.reddit_playwright import RedditPlaywrightCollector
from backend.app.pipeline.ingestion.external.social_common import ConfiguredSocialCollector, SocialCollectionResult, SocialItemProcessor
from backend.app.pipeline.ingestion.external.telegram_connector import TelegramConnector, TelegramSource


FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"
ROOT = FIXTURES.parents[2]
NOW = datetime(2026, 8, 23, 12, 0, tzinfo=timezone.utc)


class StubClassifier:
    def __init__(self, status="accepted") -> None: self.status = status
    def classify(self, text):
        label = "cti_related" if self.status == "accepted" else None
        error = "prediction_failed" if self.status == "error" else None
        return ClassificationResult(self.status, label, None, MODEL_VERSION, MODEL_SHA256, error)


class StubCrawler:
    def __init__(self) -> None: self.calls = []
    def crawl(self, url, **kwargs):
        self.calls.append((url, kwargs))
        return CrawlResult(url, url, "success", title="Full article", page_type="article", confidence=0.9,
            extracted_text="A full sanitized external article describes malware behavior, technical indicators, and remediation guidance for defenders.",
            response_metadata={"etag": '"article-v1"'}, raw_content_hash="sha256:" + "a" * 64, extracted_content_hash="sha256:" + "b" * 64)


class StubHttpClient:
    def __init__(self, fixture): self.fixture, self.calls = fixture, []
    def get(self, url, **kwargs):
        self.calls.append((url, kwargs))
        content_type = "application/json" if self.fixture.endswith(".json") else "text/html"
        return HttpResponse(url, 200, {"Content-Type": content_type}, (FIXTURES / self.fixture).read_bytes())


def telegram_page(*message_ids: int, channel: str = "thehackernews") -> bytes:
    messages = "".join(
        f'<div class="tgme_widget_message" data-post="{channel}/{message_id}">'
        f'<div class="tgme_widget_message_text">Security bulletin {message_id} contains detailed defensive guidance and indicators.</div>'
        f'<time datetime="2026-08-22T12:00:00Z"></time><span class="tgme_widget_message_views">12K</span></div>'
        for message_id in message_ids
    )
    return f"<!doctype html><html><body>{messages}</body></html>".encode()


class TelegramPages:
    def __init__(self, pages): self.pages, self.calls = list(pages), []
    def get(self, before=None):
        self.calls.append(before)
        body = self.pages[min(len(self.calls) - 1, len(self.pages) - 1)]
        return HttpResponse("https://t.me/s/thehackernews", 200, {"Content-Type": "text/html"}, body)


class StubRedditApi:
    configured = True
    def __init__(self, error=None): self.error, self.calls = error, []
    def listing(self, subreddit, **kwargs):
        self.calls.append((subreddit, kwargs))
        if self.error: raise self.error
        return json.loads((FIXTURES / "reddit_listing.json").read_text(encoding="utf-8"))


class StubRedditFeed:
    def __init__(self, fixture="reddit_public_feed.xml", *, error=None, url="https://www.reddit.com/r/netsec/.rss", content_type="application/atom+xml"):
        self.fixture,self.error,self.url,self.content_type,self.calls=fixture,error,url,content_type,[]
    def get(self,url,**kwargs):
        self.calls.append((url,kwargs))
        if self.error: raise self.error
        return HttpResponse(self.url,200,{"Content-Type":self.content_type},(FIXTURES/self.fixture).read_bytes())


class StubRedditBrowser:
    def __init__(self, posts=(), error=None): self.posts,self.error,self.calls=list(posts),error,0
    def collect(self):
        self.calls += 1
        if self.error: raise self.error
        return self.posts


def fallback_source(**overrides):
    value={"source_id":"reddit-netsec","name":"Reddit netsec","source_type":"reddit","transport":"rss_with_browser_fallback","enabled":True,"subreddit":"netsec","max_items":10,"request_timeout_seconds":10,"rate_limit_delay_seconds":0,"fetch_linked_articles":True,"max_response_bytes":100000,"max_redirects":2,"fallback_enabled":True,"minimum_usable_posts":3,"target_count":5,"max_scrolls":3,"max_stale_scrolls":2,"navigation_timeout_seconds":5,"overall_fallback_timeout_seconds":10}
    value.update(overrides);return RedditSource.from_mapping(value)


def processor(*, state=None, classification="accepted"):
    return SocialItemProcessor(crawler=StubCrawler(), classification_service=ClassificationService(StubClassifier(classification)), state=state, clock=lambda: NOW)


class SocialConnectorTests(unittest.TestCase):
    def test_reddit_public_rss_self_text_link_empty_dedup_and_disabled(self) -> None:
        source=RedditSource.from_mapping({"source_id":"reddit-netsec","name":"Reddit netsec","source_type":"reddit","transport":"reddit_public_rss","enabled":True,"subreddit":"netsec","max_items":10,"request_timeout_seconds":10,"rate_limit_delay_seconds":0,"fetch_linked_articles":True,"max_response_bytes":100000,"max_redirects":2})
        client=StubRedditFeed();state={"sources":{},"items":{}}
        connector=RedditConnector(source,rss_client=RedditPublicRSSClient(source,http_client=client),processor=processor(state=state))
        first,second=connector.collect_result(),connector.collect_result()
        self.assertEqual((first.status,len(first.accepted_items),first.accepted_items[0].source_item_id),("completed",2,"t3_public1"))
        self.assertEqual(first.accepted_items[1].metadata["content_status"],"full_text")
        self.assertEqual(second.all_items,[])
        empty=RedditConnector(source,rss_client=RedditPublicRSSClient(source,http_client=StubRedditFeed("reddit_public_empty.xml")),processor=processor()).collect_result()
        self.assertEqual((empty.status,empty.all_items,empty.errors[0].category),("failed",[],"rss_insufficient_results"))
        disabled=RedditConnector(RedditSource("reddit-off","Off","netsec",False,transport="reddit_public_rss"),rss_client=object(),processor=processor()).collect_result()
        self.assertEqual(disabled.status,"disabled")

    def test_reddit_public_rss_rejects_contract_and_classifies_transport(self) -> None:
        source=RedditSource("reddit-netsec","Reddit","netsec",True,transport="reddit_public_rss")
        def http_error(status):
            response=requests.Response();response.status_code=status
            return requests.HTTPError(response=response)
        cases=[(StubRedditFeed(url="https://example.org/feed"),"rss_http_failure",False),
               (StubRedditFeed(content_type="text/html"),"rss_parsing_failure",False),
               (StubRedditFeed(error=ResponseTooLargeError()),"rss_parsing_failure",False),
               (StubRedditFeed(error=requests.Timeout()),"rss_timeout",True),
               (StubRedditFeed(error=http_error(403)),"rss_http_failure",False),
               (StubRedditFeed(error=http_error(429)),"rate_limited",True),
               (StubRedditFeed(error=http_error(503)),"rss_http_failure",True)]
        for client,category,retryable in cases:
            result=RedditConnector(source,rss_client=RedditPublicRSSClient(source,http_client=client),processor=processor()).collect_result()
            self.assertEqual((result.status,result.errors[0].category,result.errors[0].retryable),("failed",category,retryable))
        malformed=StubRedditFeed();malformed.fixture="reddit_public_empty.xml"
        malformed.get=lambda url,**kwargs:HttpResponse(url,200,{"Content-Type":"application/xml"},b"<broken")
        result=RedditConnector(source,rss_client=RedditPublicRSSClient(source,http_client=malformed),processor=processor()).collect_result()
        self.assertEqual(result.errors[0].category,"rss_parsing_failure")

    def test_reddit_fallback_quality_merge_dedup_and_safe_failure(self) -> None:
        browser_posts=[RedditPost("t3_public1","Browser duplicate","/r/netsec/comments/public1/browser/",body="Browser body with sufficient security context."),RedditPost("t3_browser2","Browser link","/r/netsec/comments/browser2/link/",external_url="https://example.test/report")]
        browser=StubRedditBrowser(browser_posts);source=fallback_source()
        result=RedditConnector(source,rss_client=RedditPublicRSSClient(source,http_client=StubRedditFeed()),browser=browser,processor=processor()).collect_result()
        self.assertEqual((browser.calls,result.status,len(result.all_items)),(1,"completed",3))
        self.assertTrue(all(item.metadata["collection_method"]=="reddit_browser_fallback" for item in result.all_items))
        self.assertEqual(len({item.source_item_id for item in result.all_items}),3)
        failed=RedditConnector(source,rss_client=RedditPublicRSSClient(source,http_client=StubRedditFeed("reddit_public_empty.xml")),browser=StubRedditBrowser(error=RedditAccessError("browser_launch_failure",retryable=True)),processor=processor()).collect_result()
        self.assertEqual((failed.status,failed.errors[0].category,failed.errors[0].retryable),("failed","browser_launch_failure",True))

    def test_reddit_rss_success_never_launches_browser_and_config_bounds_are_strict(self) -> None:
        browser=StubRedditBrowser();source=fallback_source(minimum_usable_posts=2)
        result=RedditConnector(source,rss_client=RedditPublicRSSClient(source,http_client=StubRedditFeed()),browser=browser,processor=processor()).collect_result()
        self.assertEqual((result.status,browser.calls),("completed",0))
        for invalid in ({"minimum_usable_posts":11},{"target_count":2},{"max_scrolls":21},{"max_stale_scrolls":0},{"navigation_timeout_seconds":4},{"overall_fallback_timeout_seconds":121},{"fallback_enabled":True,"transport":"reddit_public_rss"}):
            with self.assertRaises(ValueError):fallback_source(**invalid)

    def test_playwright_collector_bounds_scrolls_and_always_closes(self) -> None:
        class Locator:
            def __init__(self,page,selector):self.page,self.selector=page,selector
            def evaluate_all(self,_script):return self.page.pages[min(self.page.index,len(self.page.pages)-1)]
            def count(self):return 0
            def inner_text(self,timeout=0):return ""
        class Page:
            def __init__(self):self.pages=[[{"post_id":"t3_browser1","title":"Browser self","permalink":"/r/netsec/comments/browser1/self/","body":"Useful defensive security report."}]];self.index=0;self.closed=False;self.scrolls=0;self.url="https://www.reddit.com/r/netsec/new/"
            def set_default_timeout(self,_value):pass
            def route(self,*_args):pass
            def goto(self,*_args,**_kwargs):pass
            def wait_for_selector(self,*_args,**_kwargs):pass
            def locator(self,selector):return Locator(self,selector)
            def evaluate(self,_script):self.scrolls+=1;self.index+=1
            def wait_for_timeout(self,_value):pass
            def close(self):self.closed=True
        class Resource:
            def __init__(self):self.closed=False
            def close(self):self.closed=True
        page=Page();context=Resource();context.new_page=lambda:page;browser=Resource();browser.new_context=lambda **_kwargs:context
        class Manager:
            def __init__(self):self.chromium=type("Chromium",(),{"launch":lambda _self,**_kwargs:browser})();self.stopped=False
            def start(self):return self
            def stop(self):self.stopped=True
        manager=Manager();posts=RedditPlaywrightCollector(fallback_source(max_scrolls=3,max_stale_scrolls=2),playwright_factory=lambda:manager).collect()
        self.assertEqual((len(posts),page.scrolls),(1,2));self.assertTrue(page.closed and context.closed and browser.closed and manager.stopped)

    def test_reddit_uses_bounded_official_api_shape_and_enriches_link_posts(self) -> None:
        source = RedditSource("reddit-netsec", "Reddit - r/netsec", "netsec", True, 30)
        api, state = StubRedditApi(), {"sources": {}, "items": {}}
        result = RedditConnector(source, api_client=api, processor=processor(state=state)).collect_result()
        self.assertEqual(result.status, "completed")
        self.assertEqual(len(result.accepted_items), 2)
        self.assertEqual(api.calls[0], ("netsec", {"limit": 30, "after": None}))
        self.assertEqual(result.accepted_items[0].source_item_id, "t3_example1")
        self.assertEqual(result.accepted_items[1].metadata["content_status"], "full_text")
        self.assertNotIn("utm_source", result.accepted_items[1].metadata["external_url"])

    def test_reddit_empty_and_safe_failure_categories(self) -> None:
        class Empty(StubRedditApi):
            def listing(self,*args,**kwargs): return {"data":{"children":[],"after":None}}
        empty=RedditConnector(RedditSource("reddit-netsec","Reddit","netsec",True),api_client=Empty(),processor=processor()).collect_result()
        self.assertEqual((empty.status,empty.all_items,empty.errors),("completed",[],[]))
        for category,retryable in (("configuration_required",False),("authorization_failed",False),("rate_limited",True),("network_failure",True),("invalid_response",False)):
            result=RedditConnector(RedditSource("reddit-netsec","Reddit","netsec",True),api_client=StubRedditApi(RedditAccessError(category,retryable=retryable)),processor=processor()).collect_result()
            self.assertEqual((result.status,result.errors[0].category,result.errors[0].retryable),("failed",category,retryable))

    def test_hackernews_uses_algolia_window_and_skips_unchanged_hashes(self) -> None:
        state = {"sources": {"hackernews-cve": {"checkpoint_created_at_i": 1787300000}}, "items": {}}
        client = StubHttpClient("hackernews_search.json")
        connector = HackerNewsConnector(HackerNewsSource("hackernews-cve", "HN CVE", "CVE", limit=30, max_pages=1), http_client=client, processor=processor(state=state))
        first, second = connector.collect_result(), connector.collect_result()
        self.assertEqual(len(first.accepted_items), 2)
        self.assertEqual(second.all_items, [])
        self.assertEqual(second.skipped_items, 2)
        self.assertIn("numericFilters=created_at_i%3E1787300000", client.calls[0][0])
        self.assertEqual(state["sources"]["hackernews-cve"]["checkpoint_created_at_i"], 1787392800)

    def test_telegram_parses_only_public_channel_posts_and_tracks_message_ids(self) -> None:
        state = {"sources": {}, "items": {}}
        client = StubHttpClient("telegram_public_preview.html")
        connector = TelegramConnector(TelegramSource("telegram-thn", "Telegram THN", "thehackernews", max_pages=1), http_client=client, processor=processor(state=state))
        first, second = connector.collect_result(), connector.collect_result()
        self.assertEqual(len(first.accepted_items), 2)
        self.assertEqual(second.all_items, [])
        self.assertEqual(first.accepted_items[0].source_item_id, "12001")
        self.assertEqual(first.accepted_items[1].link, "https://t.me/thehackernews/12002")
        self.assertEqual(state["sources"]["telegram-thn"]["checkpoint_message_id"], 12002)
        self.assertTrue(client.calls[0][0].startswith("https://t.me/s/"))

    def test_telegram_pagination_is_bounded_and_stops_on_no_new_messages(self) -> None:
        source = TelegramSource("telegram-thn", "Telegram THN", "thehackernews", max_pages=5,
                                max_messages=10, rate_limit_delay_seconds=0)
        client = TelegramPages([telegram_page(12003, 12002), telegram_page(12002, 12001), telegram_page(12002, 12001)])
        result = TelegramConnector(source, public_client=client, processor=processor(), sleeper=lambda _: None).collect_result()
        self.assertEqual([item.source_item_id for item in result.all_items], ["12003", "12002", "12001"])
        self.assertEqual(client.calls, [None, 12002, 12001])

        bounded = TelegramPages([telegram_page(12003, 12002), telegram_page(12001)])
        TelegramConnector(TelegramSource("telegram-thn", "Telegram THN", "thehackernews", max_pages=1),
                          public_client=bounded, processor=processor()).collect_result()
        self.assertEqual(bounded.calls, [None])

    def test_telegram_safe_transport_failures_and_disabled_source(self) -> None:
        source = TelegramSource("telegram-thn", "Telegram THN", "thehackernews", max_pages=1)
        def http_error(status):
            response=requests.Response();response.status_code=status
            return requests.HTTPError(response=response)
        for error, category, retryable in ((ResponseTooLargeError(), "malformed_response", False),
                                           (requests.Timeout(), "network_timeout", True),
                                           (requests.ConnectionError(), "upstream_temporarily_unavailable", True),
                                           (http_error(429), "rate_limited", True),
                                           (http_error(503), "upstream_temporarily_unavailable", True)):
            class Failing:
                def get(self, *_args, **_kwargs): raise error
            result = TelegramConnector(source, http_client=Failing(), processor=processor()).collect_result()
            self.assertEqual((result.errors[0].category, result.errors[0].retryable), (category, retryable))
        class Forbidden:
            def get(self, *_args, **_kwargs):
                response = requests.Response(); response.status_code = 403
                raise requests.HTTPError(response=response)
        result = TelegramConnector(source, http_client=Forbidden(), processor=processor()).collect_result()
        self.assertEqual((result.errors[0].category, result.errors[0].retryable), ("source_access_unavailable", False))
        disabled = TelegramConnector(TelegramSource("telegram-off", "Off", "example_channel", enabled=False),
                                     public_client=object(), processor=processor()).collect_result()
        self.assertEqual(disabled.status, "disabled")

    def test_classification_failure_routes_social_item_to_review(self) -> None:
        result = HackerNewsConnector(HackerNewsSource("hn", "HN", "CVE", limit=1, max_pages=1), http_client=StubHttpClient("hackernews_search.json"), processor=processor(classification="error")).collect_result()
        self.assertEqual(len(result.review_items), 2)
        self.assertEqual(result.review_items[0].classification.status, "error")
        self.assertEqual(result.review_items[0].metadata["classification_stage"]["error_category"], "prediction_failed")

    def test_source_failure_isolation_and_configured_methods(self) -> None:
        class Good:
            source = type("Source", (), {"source_id": "good"})()
            def collect_result(self): return SocialCollectionResult("good")
        class Bad:
            source = type("Source", (), {"source_id": "bad"})()
            def collect_result(self): raise RuntimeError("safe outage")
        results = ConfiguredSocialCollector([Bad(), Good()]).collect_results()
        self.assertEqual([(r.source_id, r.status) for r in results], [("bad", "failed"), ("good", "completed")])

        config = json.loads((ROOT / "config" / "sources.json").read_text(encoding="utf-8"))
        self.assertTrue(all(value["transport"] == "rss_with_browser_fallback" and value["enabled"] for value in config["social_media_sources"]))
        self.assertTrue(all(value["transport"] == "telegram_public_preview" for value in config["telegram_sources"]))

    def test_social_item_validates_contract_and_is_not_trusted(self) -> None:
        result = RedditConnector(RedditSource("reddit-netsec", "Reddit", "netsec", True), api_client=StubRedditApi(), processor=processor()).collect_result()
        item = result.accepted_items[0]
        schema = json.loads((ROOT / "contracts" / "external_cti_item.schema.json").read_text(encoding="utf-8"))
        Draft202012Validator(schema).validate(item.to_dict())
        self.assertFalse(item.to_raw_record().trusted_cybersecurity_source)


if __name__ == "__main__": unittest.main()
