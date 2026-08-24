# CTI Tool — External Sources Module

> **Shared-repository migration status:** The sole final External Sources implementation is under `backend/app/pipeline/ingestion/external/`. The existing `src/` implementation documented below is a preserved prototype and must not be extended into a parallel final runtime. Phase 0 foundations and contracts live in the canonical backend package, `contracts/`, `config/`, `data/external/`, and `tests/external_sources/`. The dashboard is the sole production end-user interface; direct module/CLI usage is restricted to development, testing, and authorized maintenance.

The canonical backend now also includes the Phase 1 reusable `WebCrawler` and explainable `PageTypeDetector` under `backend/app/pipeline/ingestion/external/crawler/`. They are importable backend components, not end-user commands, and all default tests use sanitized local fixtures rather than live sites.

Phase 2 adds versioned, hash-aware External text preprocessing under `backend/app/pipeline/ingestion/external/preprocessing/` and a separate deterministic privacy review/redaction step under `backend/app/pipeline/ingestion/external/privacy/`. The implementation preserves CTI indicators, redacts only configured high-confidence personal data and secrets, and routes ambiguous values to review without storing detected secret values in metadata.

Phase 3 upgrades the existing canonical `backend/app/pipeline/ingestion/external/rss_connector.py` into the single RSS implementation. It supports configured bounds, conditional requests, per-feed/item state, full-article enrichment through the canonical crawler, cleaning followed by privacy review, trusted-source classification bypass, and explicit review handling for summary-only content. Default tests use sanitized local fixtures and make no claim about live feed availability.

Phase 4 adds the canonical `backend/app/pipeline/ingestion/external/cert_connector.py`. CERT-EU and CERT.at reuse the Phase 3 RSS implementation; CISA uses a bounded official-listing adapter and the shared crawler for advisory detail text. The preserved `src/cert/` module remains prototype code and is not a second final runtime.

Phase 5 replaces the narrow canonical NVD normalizer with the single `backend/app/pipeline/ingestion/external/vulnerability_connector.py`. It integrates the official NVD, CVE Program, GitHub Global Security Advisories, and CISA KEV structured interfaces, with incremental windows, bounded pagination, checkpoints, hashing, trusted-source bypass, and provenance-preserving CVE/GHSA deduplication. The vulnerability and GitHub collectors under `src/` remain preserved prototypes only.

Phase 6 adds the canonical External-only classification adapter under `backend/app/pipeline/ingestion/external/classification/`. It loads the approved model lazily, verifies its SHA-256, reproduces training-time CVE/IP substitution and lowercasing, returns typed results, bypasses trusted structured sources, and routes unavailable or failed inference to review. It does not import or modify the preserved `src/classification/` prototype.

Phase 7 adds independent canonical Reddit, Hacker News, and Telegram collectors under `backend/app/pipeline/ingestion/external/`, composed through shared social processing. Reddit uses approved application-only OAuth and is disabled until credentials are configured; Hacker News uses Algolia's public JSON API; Telegram reads configured public web previews without login. The `src/social_media/` implementations remain preserved prototypes.

Phase 8 adds the sole canonical curated dark-web collector at `backend/app/pipeline/ingestion/external/dark_web_connector.py`. It performs bounded GET-only requests through an explicitly configured `socks5h` Tor proxy, manually validates redirects, accepts only configured onion hosts and paths, and reuses canonical page detection, cleaning, privacy, classification, hashing, and state contracts. Copy the disabled fake `config/dark_web_sources.example.json` to the Git-ignored `config/dark_web_sources.local.json` and supply only operator-verified sources locally. No proxy port is assumed, no discovery or recursive crawling exists, and the collector never starts or stops Tor processes. The older `src/dark_web/` implementation and its tests remain preserved prototype code.

Phase 9 implements the framework-independent `CanonicalManualSourceService` application boundary for the future dashboard. It canonicalizes and DNS-validates URLs before state lookup, routes structured GitHub advisory, GitHub public, vulnerability, RSS, and approved onion URLs to configured adapters, and sends only ordinary public web pages through an SSRF-protected shared crawler. Listing traversal is same-host, deduplicated, limited to 20 links, and one level deep. This phase adds no dashboard UI, public API, or transport adapter.

Phase 10 adds the single canonical `ExternalDatasetExporter` under `backend/app/pipeline/ingestion/external/export/`. It accepts only run-tagged source outputs matching one `RunManifest`, validates accepted records, routes excluded records to a run-scoped review artifact, deduplicates External observations while preserving provenance, assigns deterministic SHA-256 IDs, and atomically writes the dataset, manifest, review output, and run state. It never scans unrelated “latest” prototype files.

Phase 11 adds an internal FastAPI adapter under `backend/app/pipeline/ingestion/external/integration/`. It exposes only versioned `/api/v1/external-sources` application operations, maps responses to the existing integration contracts, enforces replaceable authentication and role policy, and never imports collectors. The bundled thread-based runner, static token authentication, in-memory idempotency, and local source view are development adapters only; production deployment must replace them with the agreed identity provider, durable queue/job store, and composed application services.

Local adapter start (PowerShell):

```powershell
$env:EXTERNAL_API_TOKEN = "replace-with-a-strong-random-local-token"
$env:EXTERNAL_API_ROLES = "operator"
python -m uvicorn backend.app.pipeline.ingestion.external.integration.local:app --host 127.0.0.1 --port 8000
```

The local health endpoint is `http://127.0.0.1:8000/api/v1/external-sources/health`. This development composition does not provide the final production collector orchestration or a durable job queue and must not be exposed publicly.

Graduation project component responsible for collecting, extracting, and
cleaning cybersecurity data from external sources, then handing off a
unified dataset to the Content Classification / NER / IOC Extraction /
Database / Dashboard modules owned by the rest of the team.

## Status

- [x] **Phase 1 — RSS Feeds** (implemented)
- [x] **Phase 2 — General Web Crawler** (implemented)
- [x] **Phase 3 — Text Preprocessing** (implemented)
- [x] **Phase 4 — CERT Security Advisories** (implemented)
- [x] **Phase 5 — Vulnerability Databases** (implemented)
- [x] **Phase 6 — Social Media Sources** (implemented)
- [x] **Phase 7 — Dark Web Sources** (implemented, disabled by default — see below)

## Project Structure

```
CTI-Tool/
├── src/
│   ├── collectors/       # Source-specific collectors (RSS, etc.)
│   ├── crawler/          # Phase 2: full-article web crawler
│   ├── preprocessing/    # Phase 3: text cleaning
│   ├── social_media/     # Phase 6: social media collectors
│   ├── cert/             # Phase 4: CERT advisory collectors
│   ├── vulnerabilities/  # Phase 5: CVE/NVD collectors
│   ├── dark_web/         # Phase 7: curated onion sources via Tor (disabled by default)
│   │   ├── dark_web_collector.py
│   │   └── onion_sources.py    # source/proxy config loading, separate from collector logic
│   ├── utils/            # Shared logging, config, schema, storage helpers
│   ├── data/             # Collected JSON output (gitignored)
│   └── main.py           # Orchestration entry point
├── config/
│   ├── sources.json          # RSS/CERT/vuln/social source definitions
│   └── dark_web_sources.json # Dark Web sources + Tor proxy settings (placeholder-only by default)
├── tests/
│   ├── test_dark_web_collector.py  # no live Tor/onion site required
│   └── fixtures/sample_dark_web_page.html
├── logs/                 # Rotating log files (gitignored)
├── requirements.txt
└── README.md
```

## Setup

```bash
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

## Usage — Phase 1 (RSS Collection)

Run the RSS collector directly:

```bash
python -m src.collectors.rss_collector
```

Or via the main orchestrator:

```bash
python -m src.main
```

Both write a timestamped JSON file to `src/data/`, e.g.
`src/data/rss_articles_20260717_153000.json`, where each entry follows
the unified item schema:

```json
{
    "title": "...",
    "content": "",
    "summary": "...",
    "link": "...",
    "published": "...",
    "source": "...",
    "category": "...",
    "author": null,
    "tags": [],
    "collected_at": "...",
    "metadata": {}
}
```

`content` is intentionally empty at this stage — it is populated by the
Phase 2 crawler, which will read this JSON and fetch each article's full
body.

## Usage — Phase 2 (Web Crawler)

Run against the most recent Phase 1 output automatically:

```bash
python -m src.crawler.web_crawler
```

Or via the main orchestrator, which now runs Phase 1 then Phase 2 in sequence:

```bash
python -m src.main
```

This produces `src/data/crawled_articles_<timestamp>.json`, where each
item from Phase 1 now has its `content` field populated with the
cleaned main-article text (menus, ads, nav, comments, and sidebars
stripped). Items whose page couldn't be fetched or parsed are kept in
the output with `content` left empty rather than being dropped, so
downstream stages still see the full item count.

The crawler is generic (no per-website parsers) — it uses
`readability-lxml` to isolate the main content region of any article
page, then a BeautifulSoup pass to remove residual noise elements.

## Usage — Phase 3 (Text Preprocessing)

Run against the most recent Phase 2 output automatically:

```bash
python -m src.preprocessing.text_cleaner
```

Or via the main orchestrator, which now runs Phases 1 → 2 → 3 in sequence:

```bash
python -m src.main
```

This produces `src/data/clean_articles_<timestamp>.json`, where each
item's `content` and `summary` have had HTML entity remnants, invisible
characters, boilerplate lines (share bars, cookie notices, newsletter
prompts, comment counts, copyright lines), and duplicate whitespace
removed, while paragraph breaks and headings are preserved.

Boilerplate line patterns are configured in
`config/preprocessing_rules.json` (not hardcoded) — add a new regex
pattern there to strip additional recurring junk without touching code.
Items that failed to crawl (empty `content`) pass through unchanged
rather than causing an error.

## Usage — Phase 4 (CERT Security Advisories)

> **Prototype-only documentation:** Everything in this Phase 4 subsection below
> describes the preserved `src/cert/` prototype. It is not the final backend
> runtime. The canonical implementation is
> `backend/app/pipeline/ingestion/external/cert_connector.py`; its configured
> methods are `rss` and `official_listing`, and RSS handling reuses the canonical
> RSS connector. See `docs/architecture/external_sources_cert_delivery.md` for
> the verified source mapping. Do not extend or wire the prototype into the
> final runtime.

Prototype development command:

```bash
python -m src.cert.cert_collector
```

Or via the main orchestrator (now runs Phases 1 → 2 → 3 → 4):

```bash
python -m src.main
```

This produces `src/data/cert_advisories_<timestamp>.json`. Sources are
configured in `config/sources.json` under `cert_sources`, each with a
`method` of `"rss"` or `"scrape"`:

```json
{
  "name": "CISA",
  "url": "https://www.cisa.gov/news-events/cybersecurity-advisories",
  "category": "advisory",
  "method": "scrape"
}
```

- `"rss"` sources are parsed with `feedparser` for title/link/date/summary
  (implemented independently from the Phase 1 RSS collector per the
  project spec — no shared code between the two), and then **each
  entry's link is visited to extract the full advisory body**, since an
  RSS `<description>` is only ever a short summary.
- `"scrape"` sources are fetched with `requests`/BeautifulSoup to find
  links to individual advisory pages (not the listing page's own
  filter/category links), and **each advisory page is then visited** the
  same way, to extract its real title and full content. Used for CERTs
  with no advisory feed — e.g. **CISA retired its advisory RSS feeds in
  May 2025**, so it's configured as `scrape` here.

Both paths converge on the same "open link → extract full text" step
(a shared internal helper reusing the Phase 2 `WebCrawler`), so `content`
is populated the same way regardless of how the advisory was discovered:

```
Source
  ├── RSS available?
  │     ├── yes → get title/link/date/summary from feed
  │     │         → open link → extract full text → save as content
  │     └── no  → Web Scraping
  │               → open advisory page → extract full text → save as content
```

If a single advisory page fails to fetch or parse, it's logged and kept
in the output with `content` left empty, rather than dropping the item
or aborting the batch.

**Known limitation:** the scrape path relies on URL-pattern matching
rather than exact CSS selectors, since advisory listing pages don't
share a common structure. If a scrape source consistently returns
nothing (or garbage), the page structure has likely changed — recheck
`_ADVISORY_LINK_PATTERN` and `_find_nearby_date` in
`src/cert/cert_collector.py` against the live page.

## Usage — Phase 5 (Vulnerability Databases)

Run independently:

```bash
python -m src.vulnerabilities.vulnerability_collector
```

Or via the main orchestrator (now runs Phases 1 → 2 → 3 → 4 → 5):

```bash
python -m src.main
```

> **Prototype-only documentation:** This command and output describe preserved
> `src/` code. The final Phase 5 component is
> `backend.app.pipeline.ingestion.external.vulnerability_connector`; see
> `docs/architecture/external_sources_vulnerability_delivery.md`.

This prototype produces `src/data/vulnerabilities_<timestamp>.json`, with **CVE
ID, CVSS (score/severity/vector), description, published date, and
references** for each item, collected exclusively via official REST
APIs — no scraping, per the spec.

Sources are configured in `config/sources.json` under
`vulnerability_sources`:

```json
{ "name": "NVD", "type": "nvd", "base_url": "https://services.nvd.nist.gov/rest/json/cves/2.0", "days_back": 3, "results_per_page": 20, "max_pages": 3 },
{ "name": "MITRE CVE", "type": "mitre", "base_url": "https://cveawg.mitre.org/api/cve" }
```

- **NVD** is queried for CVEs published within a rolling window
  (`days_back`), paginated automatically up to `max_pages`. An optional
  API key can be set via the `NVD_API_KEY` environment variable (never
  put it in `sources.json`) — this raises NVD's rate limit from 5 to 50
  requests/30s; the collector adjusts its delay between pages
  accordingly.
- **MITRE CVE** looks up the canonical CNA record for each CVE ID NVD
  already returned in the same run, via `GET /api/cve/{cve_id}`.
  **Known limitation, documented honestly rather than worked around:**
  MITRE's public API has no bulk "list recently published CVEs"
  endpoint like NVD's — only per-ID lookup. If NVD collection fails or
  is not configured, the MITRE step is skipped with a warning (not
  treated as an error) since there's nothing to look up. A CVE that's
  since been rejected or withdrawn on MITRE's side is also skipped
  individually rather than aborting the batch.

## Usage — Phase 6 (Social Media Sources)

Covers Reddit via Playwright, plus Mastodon, GitHub Security Advisories,
and Telegram — all three as separate `requests`-only collectors (no
Playwright needed, see below for why).

**X/Twitter support was removed.** As of 2026, X aggressively gates
anonymous browsing and fingerprints automated Chromium sessions
independently of whether a saved login session's cookies are valid —
even with stealth mitigations and a manually generated session, results
stayed unreliable. Rather than keep maintaining a fragile workaround,
it's been replaced with **Mastodon** and **GitHub Security Advisories**
— both real, public, unauthenticated REST APIs, so they don't share
X's fragility at all. `scripts/generate_twitter_session.py` has been
removed along with it.

One-time setup for Reddit (installs the actual browser binary
Playwright drives):

```bash
pip install -r requirements.txt
playwright install chromium
```

Run independently:

```bash
python -m src.social_media.social_media_collector   # Reddit
python -m src.social_media.mastodon_collector        # Mastodon
python -m src.social_media.github_collector          # GitHub Security Advisories
python -m src.social_media.telegram_collector        # Telegram
```

Or via the main orchestrator (runs all four):

```bash
python -m src.main
```

- **Reddit**: public subreddits render without login. Posts are read
  from new Reddit's `<shreddit-post>` custom element attributes
  (`post-title`, `permalink`, `score`, `comment-count`, `author`,
  `created-timestamp`). The page only paints an initial batch and
  lazy-loads more on scroll, so the collector scrolls automatically
  (`max_scrolls`/`target_count` per source in config) to pull a larger
  volume — 4 subreddits are configured by default. `content` is
  populated from the post's inline self-text slot for text posts, or —
  for link posts — by reusing the Phase 2 `WebCrawler` to fetch and
  extract the linked article's body (same pattern as Phase 4's CERT
  collector), so downstream stages get real text rather than an empty
  field. Uses **Playwright, not Selenium**, per the spec.

- **Mastodon**: real, public, unauthenticated REST API —
  `GET /api/v1/timelines/tag/{hashtag}` — confirmed against Mastodon's
  own documentation. `src/social_media/mastodon_collector.py` uses
  `requests` only. Mastodon is **federated** — there's no single global
  timeline the way there was one `x.com`; each source in
  `config/sources.json` under `mastodon_sources` targets one instance's
  public hashtag timeline:

  ```json
  { "name": "Mastodon - #cybersecurity (infosec.exchange)", "instance": "infosec.exchange", "hashtag": "cybersecurity", "category": "social", "limit": 20 }
  ```

  `infosec.exchange` (a real, publicly documented Mastodon instance
  dedicated to the infosec/cybersecurity community, running since 2022)
  is the default instance. Add more instances/hashtags freely — querying
  more instances gives broader coverage, since an instance only
  federates posts it has actually seen. A status's `content` is HTML in
  Mastodon's API — stripped via BeautifulSoup before use, same rule as
  everywhere else in this pipeline (never pass raw HTML downstream). A
  media-only post with no text is skipped. One instance failing (down,
  disabled public preview, rate limited) is logged and skipped without
  affecting the others.

- **GitHub Security Advisories**: real, public REST API —
  `GET https://api.github.com/advisories` — confirmed against GitHub's
  own documentation, works unauthenticated for public resources.
  `src/social_media/github_collector.py` uses `requests` only.
  Configured under `github_sources`:

  ```json
  { "name": "GitHub Security Advisories", "category": "vulnerability", "per_page": 20 }
  ```

  An optional `GITHUB_TOKEN` environment variable raises the rate limit
  from 60/hour to 5000/hour — nothing here requires one, and a 403
  (rate limited) is logged with that suggestion rather than a generic
  error. **Worth noting honestly:** this data is closer in spirit to
  Phase 5's structured vulnerability databases (it always has a real
  CVE/GHSA-style record — `ghsa_id`, `cve_id`, `severity`, `cvss`) than
  to "social media" in the traditional sense. It lives under
  `src/social_media/` because that's where it replaced X, not because
  it's unstructured free text like a Reddit post or Mastodon toot.

- **Telegram**: **deliberately NOT built with Playwright.** A public
  channel's web preview at `https://t.me/s/{channel}` is plain,
  server-rendered static HTML — confirmed by inspection, no JS
  rendering or login needed — so this uses `requests` + BeautifulSoup
  instead (`src/social_media/telegram_collector.py`), the same stack
  already used by Phase 2's crawler and Phase 4's CERT scrape path.

  Sources are configured in `config/sources.json` under
  `telegram_sources`, each needing only a public channel username (no
  `@` or `t.me/` prefix):

  ```json
  { "name": "Telegram - The Hacker News", "channel": "thehackernews", "category": "social", "max_pages": 3 }
  ```

  Two verified, clearly legitimate channels are configured by default —
  an official news outlet's own channel, and a channel that auto-relays
  newly published CVEs. **Only public channels are supported** (that's
  what the web preview exposes) — private channels/groups would need
  the MTProto API (Telethon/Pyrogram) with a phone-number login, a
  materially different and heavier integration not needed here.

  Add more channels by username freely — many legitimate CTI/OSINT
  channels exist beyond the two defaults. One caution worth passing
  on: a lot of "top cybersecurity Telegram channels" lists mix in
  channels actually *operated by* ransomware gangs/hacktivist groups for
  announcing attacks — those are real OSINT sources professional CTI
  teams do monitor, but they're a different risk category than a news
  channel, and deliberately not defaulted into this project. Use your
  judgment (and your institution's guidance) before adding any.

  `content` is the **linked article's full body** when a post's link
  preview is present — fetched and extracted via the same reused
  Phase 2 `WebCrawler` already used by CERT and Reddit's link-post
  handling — while `summary` stays the short caption, so downstream
  stages get real text rather than a near-duplicate of the summary.
  Pagination follows Telegram's own `?before={message_id}` pattern
  (`max_pages` per source in config). A media-only post with no caption
  text is skipped, and one channel failing is logged and skipped
  without affecting the others.

A single source failing — an unknown platform, a timeout waiting for
Reddit posts to render, an instance with public preview disabled, a
rate limit — is logged and skipped; it never aborts collection from the
remaining sources.

## Usage — Phase 7 (Dark Web Sources)

### What it does

Collects CTI-relevant text content from a small, **explicitly curated**
list of approved `.onion` sources over Tor. It does **not** discover,
search, or crawl the dark web in any general sense — it only ever
visits the exact URLs an operator has manually added and enabled in
`config/dark_web_sources.json`.

Collection model:

```
Approved/curated onion sources (config file)
    → Tor network (SOCKS5 proxy)
    → HTTP GET request (one source at a time, with a delay between each)
    → HTML parsing (BeautifulSoup)
    → Text cleaning (reuses Phase 3's TextPreprocessor)
    → Normalized CTIItem
    → src/data/ (reuses existing storage.py)
```

**Disabled by default.** The only source in the config out of the box
is an unmistakable placeholder (`enabled: false`, a `REPLACE-WITH-...`
URL) — nothing is ever contacted until you add and enable a real,
manually verified source yourself.

### Why Tor is required

`.onion` addresses aren't resolvable or reachable over the normal
internet — they only exist within the Tor network. This collector
connects through a local Tor SOCKS5 proxy (the same one the Tor Browser
or a `tor` daemon exposes) rather than embedding any Tor client logic
itself.

### How to configure the Tor SOCKS5 proxy

Resolution order: **environment variables first**, then the config
file, then a built-in default:

```bash
export TOR_PROXY_HOST="127.0.0.1"
export TOR_PROXY_PORT="9050"    # Tor's own standard default
```

Or in `config/dark_web_sources.json`:

```json
{
  "tor_proxy": { "host": "127.0.0.1", "port": 9050 }
}
```

No credentials are involved — a SOCKS5 proxy for Tor doesn't need any,
and none are read from or written to any file.

**Running Tor locally**, e.g. on Debian/Ubuntu:

```bash
sudo apt install tor
sudo systemctl start tor    # now listening on 127.0.0.1:9050
```

Or run the Tor Browser, which exposes its own SOCKS5 proxy (commonly on
port `9150`) — point `TOR_PROXY_PORT` at that instead.

### How to add an approved onion source

Edit `config/dark_web_sources.json` and replace the placeholder entry
(or add a new one) with a source you've manually verified yourself:

```json
{
  "name": "Your Verified Source Name",
  "url": "http://<a-real-verified-onion-address>.onion/",
  "enabled": true,
  "category": "dark_web_cti",
  "description": "Why this source is approved for CTI collection",
  "timeout": 30,
  "max_pages": 1,
  "request_delay": 5,
  "collection_method": "tor_http"
}
```

This project will never suggest or hard-code a real onion address —
that verification step is deliberately left to you (or your
institution's threat intel process), since an AI assistant recommending
"real" dark web sources isn't a safe or appropriate thing to automate.

### How to run the collector

Independently:

```bash
python -m src.dark_web.dark_web_collector
```

Or via the main orchestrator (runs last, after Telegram):

```bash
python -m src.main
```

Either way, output goes to `src/data/dark_web_posts_<timestamp>.json`
via the existing `storage.py` — same convention as every other phase.

### What data is collected

For each approved, enabled source: `title`, `link` (the exact
configured URL), `published` date (if present in the page), `author`
(if present), the main textual `content` (menus/scripts/nav/footer
already stripped, then cleaned via Phase 3's `TextPreprocessor`),
`source` name, `category`, and `collected_at` timestamp — the same
unified shape every other collector already produces:

```json
{
  "title": "Analysis: New Data Exfiltration Toolkit Observed in the Wild",
  "link": "http://<configured-onion-address>.onion/",
  "source": "Your Verified Source Name",
  "category": "dark_web_cti",
  "content": "Researchers monitoring underground forums have identified a new data exfiltration toolkit...",
  "summary": "Researchers monitoring underground forums have identified a new data...",
  "published": "2026-07-23T10:00:00Z",
  "author": "research_contributor",
  "tags": [],
  "collected_at": "2026-07-23T18:12:04+00:00",
  "metadata": {
    "collection_method": "tor_http",
    "network": "tor",
    "source_type": "onion_service"
  }
}
```

### What data is deliberately NOT collected

- No arbitrary onion links found on a page are ever followed — only the
  exact URL configured per source.
- No accounts are created, no logins performed, no registration, no
  messaging, no purchasing, no transactions.
- No forms are submitted, no files are uploaded or downloaded, no
  CAPTCHA or authentication bypass is attempted.
- No credential collection, no interaction with threat actors.
- No navigation chrome, ads, scripts, or menus are saved — only the
  page's main text content.
- Only plain HTTP **GET** requests are ever issued — nothing else.

### How to test without connecting to a real onion site

```bash
python -m tests.test_dark_web_collector
```

This exercises: config loading, Tor proxy resolution (including env var
overrides), Tor-unavailable detection, parsing a local HTML fixture
(`tests/fixtures/sample_dark_web_page.html`) with a mocked session (no
network), the output schema, one-failed-source isolation, and that
every existing collector still imports cleanly — all without touching
Tor or the network.

### Troubleshooting when Tor is unavailable

If you see `Tor connection unavailable (host:port)` in the logs: Tor
isn't running, or is running on a different host/port than configured.
This is expected and handled gracefully — the Dark Web phase simply
produces no output for that run, and **every other collector in this
project continues to work normally**, since nothing else depends on
Tor. Start Tor (see above) and re-run, or double check
`TOR_PROXY_HOST`/`TOR_PROXY_PORT` match wherever your Tor proxy is
actually listening.

## Configuring Sources

Add or edit feeds in `config/sources.json` under `rss_sources`. No code
changes are required to add a new feed:

```json
{
  "name": "New Source",
  "url": "https://example.com/feed/",
  "category": "news"
}
```

## Design Notes

- Every collector implements the `BaseCollector` interface
  (`src/collectors/base_collector.py`), so future source types plug into
  the same orchestration pattern used by `main.py`.
- A single feed failing to parse or being unreachable is logged and
  skipped; it does not stop collection of the remaining feeds.
- All configuration lives in `config/sources.json` — no hardcoded URLs
  in the collector code.
