# External Sources CERT delivery methods

Verified on 2026-08-23 for Phase 4. The canonical implementation is
`backend/app/pipeline/ingestion/external/cert_connector.py`.

| Source | Official delivery used | Integration |
| --- | --- | --- |
| CISA | Cybersecurity Advisories listing and advisory detail pages | Bounded same-host listing discovery; shared `WebCrawler` extracts detail text |
| CERT-EU | Security Advisories RSS endpoint | Shared canonical `RSSConnector` |
| CERT.at | Warnings RSS 2.0 feed | Shared canonical `RSSConnector` |

CISA's public advisories listing was the current official delivery surface found
during verification; no current structured advisory-category endpoint was
identified. The listing adapter is consequently isolated behind configuration so
it can be replaced if CISA publishes an official structured delivery method.

Official references:

- https://www.cisa.gov/news-events/cybersecurity-advisories
- https://cert.europa.eu/blog/read-feed-and-lead-fresh-features-for-our-cyber-fans
- https://cert.europa.eu/publications/security-advisories-rss
- https://www.cert.at/de/services/feeds/
