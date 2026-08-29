# External Sources social/community delivery methods

Verified on 2026-08-23 for Phase 7. Canonical implementations are under
`backend/app/pipeline/ingestion/external/`; the superseded prototype collectors
have been retired.

| Source | Delivery method | Access policy |
| --- | --- | --- |
| Reddit | Registered Reddit Data API using application-only OAuth | Disabled until approved `REDDIT_CLIENT_ID`, `REDDIT_CLIENT_SECRET`, and identifiable `REDDIT_USER_AGENT` are configured; no anonymous scraping fallback |
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
