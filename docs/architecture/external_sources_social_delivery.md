# External Sources social/community delivery methods

Verified on 2026-08-23 for Phase 7. Canonical implementations are under
`backend/app/pipeline/ingestion/external/`; the superseded prototype collectors
have been retired.

| Source | Delivery method | Access policy |
| --- | --- | --- |
| Reddit | Public subreddit RSS, then bounded Playwright fallback | Credential-free for explicitly configured subreddits; no login, challenge bypass, proxy rotation, or private endpoints |
| Hacker News | Algolia HN Search `search_by_date` JSON API | Public, bounded search with `created_at_i` incremental filter and page bounds |
| Telegram | Server-rendered `https://t.me/s/{channel}` public preview | Configured public channels only; no login, joining, messaging, private invite access, or MTProto session |

Official references:

- https://redditinc.com/policies/data-api-terms
- https://www.reddit.com/dev/api/
- https://hn.algolia.com/api
- https://telegram.org/blog/privacy-discussions-web-bots
- https://core.telegram.org/widgets/post

Every candidate uses a stable platform identifier and canonical URL. External
link posts use the shared `WebCrawler`. Cleaning, privacy handling, item/stage
hashing, and Phase 6 classification are applied before disposition. Missing or
failed classification routes the item to review. Collector failures remain
independent.

Social sources are configured in `config/sources.json`; safe disabled examples
are provided in `config/social_sources.example.json`. To add a subreddit, copy
the Reddit example, choose a unique `source_id`, set `subreddit`, review the
request/item bounds, and enable it. To monitor a Telegram channel, do the same
with an explicitly reviewed public username. Disable either source by setting
`enabled` to `false`. `max_items`/`max_messages` bound collected items and
`max_pages` bounds Telegram history requests.

Reddit application-only OAuth remains an optional, separate `reddit_oauth`
transport and requires all three Reddit environment variables. The public RSS
transport never uses them. Public platforms can return access-unavailable or
temporary-unavailable results; CTI-Tool does not attempt browser automation,
login, private-channel access, or access-control bypasses.

For `rss_with_browser_fallback`, RSS is sufficient only when at least
`minimum_usable_posts` entries pass all deterministic completeness checks: a
valid stable post ID, non-empty title, an HTTPS `www.reddit.com` permalink under
the configured subreddit, and either meaningful self-text or an external-link
target. Zero usable entries, a count below the configured minimum, timeout,
network/HTTP failure, or XML parsing failure triggers the browser fallback.
The fallback is bounded by `target_count`, `max_scrolls`,
`max_stale_scrolls`, `navigation_timeout_seconds`, and
`overall_fallback_timeout_seconds`. It stops at the target, the scroll limit,
the stale-scroll limit, or the overall deadline, whichever occurs first.
