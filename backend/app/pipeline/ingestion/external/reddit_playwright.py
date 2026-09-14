from __future__ import annotations

import threading
import time
from typing import TYPE_CHECKING, Any
from urllib.parse import urlsplit

from backend.app.pipeline.ingestion.external.reddit_connector import RedditAccessError, RedditPost

if TYPE_CHECKING:
    from backend.app.pipeline.ingestion.external.reddit_connector import RedditSource

_BROWSER_SLOTS = threading.BoundedSemaphore(2)


class RedditPlaywrightCollector:
    """Bounded public-page fallback without login, private APIs, or evasion."""

    def __init__(self, source: "RedditSource", *, playwright_factory=None, clock=time.monotonic) -> None:
        self.source, self.playwright_factory, self.clock = source, playwright_factory, clock

    def collect(self) -> list[RedditPost]:
        if not _BROWSER_SLOTS.acquire(timeout=min(5, self.source.overall_fallback_timeout_seconds)):
            raise RedditAccessError("playwright_unavailable", retryable=True)
        manager = browser = context = page = None
        try:
            factory = self.playwright_factory
            if factory is None:
                try:
                    from playwright.sync_api import sync_playwright
                except ImportError as exc:
                    raise RedditAccessError("playwright_unavailable", retryable=False) from exc
                factory = sync_playwright
            started = self.clock(); manager = factory().start()
            try: browser = manager.chromium.launch(headless=True, timeout=int(self.source.overall_fallback_timeout_seconds * 1000))
            except Exception as exc: raise RedditAccessError("browser_launch_failure", retryable=True) from exc
            context = browser.new_context(service_workers="block"); page = context.new_page()
            page.set_default_timeout(int(self.source.navigation_timeout_seconds * 1000))
            page.route("**/*", lambda route: route.abort() if route.request.resource_type in {"image", "media", "font"} else route.continue_())
            try:
                page.goto(f"https://www.reddit.com/r/{self.source.subreddit}/new/", wait_until="domcontentloaded", timeout=int(self.source.navigation_timeout_seconds * 1000))
                expected_path = f"/r/{self.source.subreddit}/new/"; final = urlsplit(page.url)
                if final.scheme != "https" or final.hostname != "www.reddit.com" or final.port is not None or final.path.lower() != expected_path.lower():
                    raise RedditAccessError("browser_redirect_rejected", retryable=False)
                page.wait_for_selector("shreddit-post", timeout=int(self.source.navigation_timeout_seconds * 1000))
            except RedditAccessError: raise
            except Exception as exc:
                category = "navigation_timeout" if self.clock() - started >= self.source.overall_fallback_timeout_seconds else "blocked_challenge_page" if self._challenge(page) else "dom_contract_change"
                raise RedditAccessError(category, retryable=category != "dom_contract_change") from exc
            seen: dict[str, RedditPost] = {}; stale = 0
            for scroll in range(self.source.max_scrolls + 1):
                if self.clock() - started >= self.source.overall_fallback_timeout_seconds:
                    raise RedditAccessError("navigation_timeout", retryable=True)
                before = len(seen)
                for raw in self._extract(page):
                    post = self._post(raw)
                    if post is not None: seen[post.post_id] = post
                if len(seen) >= self.source.target_count: break
                stale = stale + 1 if len(seen) == before else 0
                if stale >= self.source.max_stale_scrolls or scroll >= self.source.max_scrolls: break
                page.evaluate("window.scrollTo(0, document.body.scrollHeight)")
                page.wait_for_timeout(int(self.source.rate_limit_delay_seconds * 1000))
            return list(seen.values())[:self.source.target_count]
        except RedditAccessError: raise
        except Exception as exc: raise RedditAccessError("unexpected_internal_failure", retryable=False) from exc
        finally:
            for resource in (page, context, browser):
                if resource is not None:
                    try: resource.close()
                    except Exception: pass
            if manager is not None:
                try: manager.stop()
                except Exception: pass
            _BROWSER_SLOTS.release()

    @staticmethod
    def _extract(page: Any) -> list[dict[str, Any]]:
        return page.locator("shreddit-post").evaluate_all("""posts => posts.map(post => ({
          post_id: post.getAttribute('id') || post.getAttribute('thingid') || '', title: post.getAttribute('post-title') || '',
          permalink: post.getAttribute('permalink') || '', author: post.getAttribute('author') || null,
          score: post.getAttribute('score') || null, comment_count: post.getAttribute('comment-count') || null,
          published: post.getAttribute('created-timestamp') || null, subreddit_name: post.getAttribute('subreddit-prefixed-name') || null,
          external_url: post.getAttribute('content-href') || null,
          body: post.querySelector('[slot="text-body"]')?.innerText || post.querySelector('[slot="text-body"]')?.textContent || ''
        }))""")

    @staticmethod
    def _challenge(page: Any) -> bool:
        try:
            if page.locator("[name='captcha'], shreddit-interstitial").count() > 0: return True
            text = page.locator("body").inner_text(timeout=1000).lower()[:4000]
            return any(marker in text for marker in ("verify you are human", "security check", "captcha"))
        except Exception: return False

    @staticmethod
    def _post(raw: Any) -> RedditPost | None:
        if not isinstance(raw, dict): return None
        return RedditPost(str(raw.get("post_id") or ""), str(raw.get("title") or "").strip(), str(raw.get("permalink") or "").strip(), str(raw.get("body") or "").strip(), str(raw.get("external_url") or "").strip() or None, str(raw.get("published") or "").strip() or None, str(raw.get("author") or "").strip() or None, str(raw.get("score") or "").strip() or None, str(raw.get("comment_count") or "").strip() or None, str(raw.get("subreddit_name") or "").strip() or None)
