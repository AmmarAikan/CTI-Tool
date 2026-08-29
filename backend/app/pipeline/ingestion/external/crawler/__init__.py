"""Reusable bounded web crawling and page-type detection."""

from backend.app.pipeline.ingestion.external.crawler.page_type_detector import PageTypeDetector, PageTypeResult
from backend.app.pipeline.ingestion.external.crawler.web_crawler import CrawlError, CrawlResult, WebCrawler

__all__ = ["CrawlError", "CrawlResult", "PageTypeDetector", "PageTypeResult", "WebCrawler"]
