"""
CTI Tool — External Sources Module entry point.

Orchestrates all data-gathering phases in sequence: RSS collection, web
crawling, text preprocessing, CERT advisories, vulnerability databases,
social media (Reddit + Hacker News + GitHub Security Advisories +
Telegram), Dark Web (Tor), and a final consolidation step that merges
every source's output into one file for handoff to the next team
(NER / IOC extraction).

Classification (src.classification.classifier) is applied inside each
general-purpose collector's own run() — Reddit, Hacker News, GitHub,
Telegram — so main.py doesn't need to know about it; RSS/CERT/
Vulnerability Databases are trusted sources and never call it.

The Dark Web phase is fully isolated: if Tor isn't running or no source
is configured, it logs that clearly and returns no output, exactly like
any other phase failing — it does not affect, delay, or depend on any
other collector.
"""

from src.cert.cert_collector import run as run_cert_collection
from src.collectors.rss_collector import run as run_rss_collection
from src.crawler.web_crawler import run as run_web_crawler
from src.dark_web.dark_web_collector import run as run_dark_web_collection
from src.export.final_dataset import run as run_final_dataset_export
from src.preprocessing.text_cleaner import run as run_text_preprocessing
from src.social_media.github_collector import run as run_github_collection
from src.social_media.hackernews_collector import run as run_hackernews_collection
from src.social_media.social_media_collector import run as run_social_media_collection
from src.social_media.telegram_collector import run as run_telegram_collection
from src.utils.logger import get_logger
from src.vulnerabilities.vulnerability_collector import run as run_vulnerability_collection

logger = get_logger(__name__)


def main() -> None:
    logger.info("Starting CTI Tool — External Sources Module")

    rss_output = run_rss_collection()
    if rss_output:
        logger.info("Phase 1 (RSS) complete. Output: %s", rss_output)
    else:
        logger.warning("Phase 1 (RSS) produced no output.")

    crawl_output = run_web_crawler(input_path=rss_output or None)
    if crawl_output:
        logger.info("Phase 2 (Crawler) complete. Output: %s", crawl_output)
    else:
        logger.warning("Phase 2 (Crawler) produced no output.")

    clean_output = run_text_preprocessing(input_path=crawl_output or None)
    if clean_output:
        logger.info("Phase 3 (Preprocessing) complete. Output: %s", clean_output)
    else:
        logger.warning("Phase 3 (Preprocessing) produced no output.")

    cert_output = run_cert_collection()
    if cert_output:
        logger.info("Phase 4 (CERT Advisories) complete. Output: %s", cert_output)
    else:
        logger.warning("Phase 4 (CERT Advisories) produced no output.")

    vuln_output = run_vulnerability_collection()
    if vuln_output:
        logger.info("Phase 5 (Vulnerability Databases) complete. Output: %s", vuln_output)
    else:
        logger.warning("Phase 5 (Vulnerability Databases) produced no output.")

    social_output = run_social_media_collection()
    if social_output:
        logger.info("Phase 6 (Social Media - Reddit) complete. Output: %s", social_output)
    else:
        logger.warning("Phase 6 (Social Media - Reddit) produced no output.")

    hackernews_output = run_hackernews_collection()
    if hackernews_output:
        logger.info("Phase 6 (Social Media - Hacker News) complete. Output: %s", hackernews_output)
    else:
        logger.warning("Phase 6 (Social Media - Hacker News) produced no output.")

    github_output = run_github_collection()
    if github_output:
        logger.info("Phase 6 (GitHub Security Advisories) complete. Output: %s", github_output)
    else:
        logger.warning("Phase 6 (GitHub Security Advisories) produced no output.")

    telegram_output = run_telegram_collection()
    if telegram_output:
        logger.info("Phase 6 (Social Media - Telegram) complete. Output: %s", telegram_output)
    else:
        logger.warning("Phase 6 (Social Media - Telegram) produced no output.")

    dark_web_output = run_dark_web_collection()
    if dark_web_output:
        logger.info("Phase 7 (Dark Web) complete. Output: %s", dark_web_output)
    else:
        logger.warning("Phase 7 (Dark Web) produced no output.")

    final_dataset_output = run_final_dataset_export()
    if final_dataset_output:
        logger.info("Phase 8 (Final Dataset Export) complete. Output: %s", final_dataset_output)
    else:
        logger.warning("Phase 8 (Final Dataset Export) produced no output.")

    logger.info("Run complete.")


if __name__ == "__main__":
    main()