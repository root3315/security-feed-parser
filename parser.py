"""
Core parsing logic for security feeds (RSS, Atom, JSON).
"""

import json
import re
import time
from datetime import datetime
from typing import Optional, List, Dict, Any
from urllib.parse import urlparse

import feedparser
import requests
from dateutil import parser as date_parser

from models import (
    Advisory,
    CVE,
    FeedInfo,
    FeedType,
    ParseResult,
    Severity,
)
from utils import RateLimiter


CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
CVSS_PATTERN = re.compile(r"CVSS:?\d*\.?\d*[:\s]*[0-9.]+", re.IGNORECASE)


def detect_feed_type(content: str, headers: Optional[Dict[str, str]] = None) -> FeedType:
    """Detect the type of feed from content and headers."""
    content_type = ""
    if headers:
        content_type = headers.get("Content-Type", "").lower()

    if "application/json" in content_type or "application/feed+json" in content_type:
        return FeedType.JSON

    content_stripped = content.strip()

    if content_stripped.startswith("{"):
        try:
            data = json.loads(content_stripped)
            if isinstance(data, dict):
                if "items" in data or "entries" in data or "feed" in data:
                    return FeedType.JSON
        except json.JSONDecodeError:
            pass
        return FeedType.JSON

    if content_stripped.startswith("<?xml") or content_stripped.startswith("<rss") or content_stripped.startswith("<feed"):
        if "<rss" in content_stripped or "<channel" in content_stripped:
            return FeedType.RSS
        if "<feed" in content_stripped and "xmlns=" in content_stripped:
            return FeedType.ATOM
        return FeedType.RSS

    return FeedType.UNKNOWN


def parse_date(date_str: Optional[str]) -> Optional[datetime]:
    """Parse various date formats into datetime."""
    if not date_str:
        return None

    try:
        return date_parser.parse(date_str)
    except (ValueError, TypeError):
        pass

    formats = [
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d",
        "%a, %d %b %Y %H:%M:%S %Z",
        "%a, %d %b %Y %H:%M:%S %z",
    ]

    for fmt in formats:
        try:
            return datetime.strptime(date_str, fmt)
        except ValueError:
            continue

    return None


def extract_cves(text: Optional[str]) -> List[CVE]:
    """Extract CVE identifiers from text."""
    if not text:
        return []

    matches = CVE_PATTERN.findall(text)
    cves = []
    seen = set()

    for match in matches:
        cve_id = match.upper()
        if cve_id not in seen:
            seen.add(cve_id)
            cves.append(CVE(cve_id=cve_id))

    return cves


def detect_severity_from_content(title: str, summary: Optional[str], content: Optional[str]) -> Severity:
    """Detect severity level from advisory content."""
    combined_text = f"{title} {(summary or '')} {(content or '')}".lower()

    critical_keywords = [
        "critical", "zero-day", "remote code execution", "rce",
        "arbitrary code execution", "authentication bypass"
    ]
    high_keywords = [
        "high", "severe", "privilege escalation", "sql injection",
        "xss", "buffer overflow", "use after free"
    ]
    medium_keywords = [
        "medium", "moderate", "cross-site", "information disclosure",
        "denial of service", "dos"
    ]
    low_keywords = [
        "low", "minor", "informational", "cosmetic"
    ]

    for keyword in critical_keywords:
        if keyword in combined_text:
            return Severity.CRITICAL

    for keyword in high_keywords:
        if keyword in combined_text:
            return Severity.HIGH

    for keyword in medium_keywords:
        if keyword in combined_text:
            return Severity.MEDIUM

    for keyword in low_keywords:
        if keyword in combined_text:
            return Severity.LOW

    return Severity.UNKNOWN


def parse_rss_atom_feed(content: str, source_url: Optional[str] = None) -> ParseResult:
    """Parse RSS or Atom feed content."""
    start_time = time.time()
    result = ParseResult(success=False)

    try:
        feed = feedparser.parse(content)

        if feed.bozo and not feed.entries:
            result.error = f"Failed to parse feed: {feed.bozo_exception}"
            return result

        feed_type = FeedType.ATOM if feed.version and "atom" in feed.version.lower() else FeedType.RSS

        feed_info = FeedInfo(
            title=feed.feed.get("title", "Unknown Feed"),
            link=feed.feed.get("link", feed.feed.get("links", [{}])[0].get("href") if feed.feed.get("links") else None),
            description=feed.feed.get("description", feed.feed.get("subtitle")),
            language=feed.feed.get("language"),
            feed_type=feed_type,
        )

        advisories = []
        for entry in feed.entries:
            title = entry.get("title", "No Title")
            link = entry.get("link", "")
            published = parse_date(entry.get("published") or entry.get("updated") or entry.get("created"))
            updated = parse_date(entry.get("updated"))
            summary = entry.get("summary", entry.get("description"))
            content_html = ""
            if "content" in entry and entry.content:
                content_html = entry.content[0].get("value", "") if isinstance(entry.content, list) else str(entry.content)

            full_content = f"{summary or ''} {content_html}"
            cves = extract_cves(full_content)
            severity = detect_severity_from_content(title, summary, content_html)

            categories = []
            for tag in entry.get("tags", []):
                if isinstance(tag, dict) and "term" in tag:
                    categories.append(tag["term"])
                elif isinstance(tag, str):
                    categories.append(tag)

            authors = []
            if "author" in entry:
                authors.append(entry.author)
            if "authors" in entry:
                for author in entry.authors:
                    if isinstance(author, dict) and "name" in author:
                        authors.append(author.name)

            advisory = Advisory(
                title=title,
                link=link,
                published=published,
                updated=updated,
                summary=summary,
                content=content_html,
                severity=severity,
                source=source_url,
                feed_type=feed_type,
                cves=cves,
                categories=categories,
                authors=list(set(authors)),
                raw_data=dict(entry),
            )
            advisories.append(advisory)

        feed_info.entry_count = len(advisories)
        feed_info.last_updated = max(
            (a.published for a in advisories if a.published),
            default=None,
        )

        result.success = True
        result.feed_info = feed_info
        result.advisories = advisories
        result.parse_time_ms = (time.time() - start_time) * 1000

    except Exception as e:
        result.error = str(e)
        result.parse_time_ms = (time.time() - start_time) * 1000

    return result


def parse_json_feed(content: str, source_url: Optional[str] = None) -> ParseResult:
    """Parse JSON-formatted security feed."""
    start_time = time.time()
    result = ParseResult(success=False)

    try:
        data = json.loads(content)

        if not isinstance(data, dict):
            result.error = "JSON feed must be an object"
            return result

        feed_data = data.get("feed", data.get("channel", data))
        items = data.get("items", data.get("entries", data.get("advisories", [])))

        if not isinstance(items, list):
            items = [data] if "title" in data else []

        feed_info = FeedInfo(
            title=feed_data.get("title", "Unknown Feed"),
            link=feed_data.get("link") or feed_data.get("home_page_url"),
            description=feed_data.get("description"),
            feed_type=FeedType.JSON,
        )

        advisories = []
        for item in items:
            if not isinstance(item, dict):
                continue

            title = item.get("title", item.get("headline", "No Title"))
            link = item.get("url") or item.get("link", item.get("external_url", ""))
            published = parse_date(item.get("date_published") or item.get("published") or item.get("published_at"))
            updated = parse_date(item.get("date_modified") or item.get("updated"))
            summary = item.get("summary", item.get("description", item.get("intro")))
            content = item.get("content_html") or item.get("content_text") or item.get("body")

            full_content = f"{title} {summary or ''} {content or ''}"
            cves = extract_cves(full_content)
            severity = Severity.from_string(item.get("severity", "unknown"))
            if severity == Severity.UNKNOWN:
                severity = detect_severity_from_content(title, summary, content)

            categories = item.get("tags", item.get("categories", []))
            if isinstance(categories, str):
                categories = [categories]

            authors = []
            author = item.get("author")
            if isinstance(author, str):
                authors.append(author)
            elif isinstance(author, dict):
                authors.append(author.get("name", ""))
            if "authors" in item:
                for a in item["authors"]:
                    if isinstance(a, str):
                        authors.append(a)
                    elif isinstance(a, dict):
                        authors.append(a.get("name", ""))

            advisory = Advisory(
                title=title,
                link=link,
                published=published,
                updated=updated,
                summary=summary,
                content=content,
                severity=severity,
                source=source_url,
                feed_type=FeedType.JSON,
                cves=cves,
                categories=categories if isinstance(categories, list) else [],
                authors=list(set(authors)),
                raw_data=item,
            )
            advisories.append(advisory)

        feed_info.entry_count = len(advisories)
        feed_info.last_updated = max(
            (a.published for a in advisories if a.published),
            default=None,
        )

        result.success = True
        result.feed_info = feed_info
        result.advisories = advisories
        result.parse_time_ms = (time.time() - start_time) * 1000

    except json.JSONDecodeError as e:
        result.error = f"Invalid JSON: {e}"
        result.parse_time_ms = (time.time() - start_time) * 1000
    except Exception as e:
        result.error = str(e)
        result.parse_time_ms = (time.time() - start_time) * 1000

    return result


def fetch_feed(url: str, timeout: int = 30, user_agent: Optional[str] = None) -> tuple:
    """Fetch feed content from URL."""
    headers = {
        "Accept": "application/feed+json, application/json, application/rss+xml, application/atom+xml, application/xml, text/xml, */*",
        "User-Agent": user_agent or "SecurityFeedParser/1.0",
    }

    response = requests.get(url, headers=headers, timeout=timeout, allow_redirects=True)
    response.raise_for_status()

    return response.text, dict(response.headers)


def parse_feed(
    source: str,
    is_url: bool = True,
    timeout: int = 30,
    user_agent: Optional[str] = None,
) -> ParseResult:
    """
    Parse a security feed from URL or raw content.

    Args:
        source: URL to fetch or raw feed content
        is_url: If True, fetch from URL; if False, treat source as raw content
        timeout: Request timeout in seconds
        user_agent: Custom User-Agent header

    Returns:
        ParseResult with parsed advisories and metadata
    """
    try:
        if is_url:
            content, headers = fetch_feed(source, timeout, user_agent)
            source_url = source
        else:
            content = source
            headers = {}
            source_url = None

        feed_type = detect_feed_type(content, headers)

        if feed_type == FeedType.UNKNOWN:
            return ParseResult(
                success=False,
                error="Unable to detect feed type. Supported formats: RSS, Atom, JSON",
            )

        if feed_type == FeedType.JSON:
            return parse_json_feed(content, source_url)
        else:
            return parse_rss_atom_feed(content, source_url)

    except requests.RequestException as e:
        return ParseResult(success=False, error=f"Failed to fetch feed: {e}")
    except Exception as e:
        return ParseResult(success=False, error=f"Parse error: {e}")


def parse_multiple_feeds(
    sources: List[str],
    timeout: int = 30,
    user_agent: Optional[str] = None,
    rate_limit: Optional[float] = None,
) -> Dict[str, ParseResult]:
    """
    Parse multiple feeds and return results keyed by source.

    Args:
        sources: List of feed URLs to parse
        timeout: Request timeout in seconds
        user_agent: Custom User-Agent header
        rate_limit: Maximum requests per second (None for no rate limiting)

    Returns:
        Dictionary mapping source URLs to their ParseResult objects
    """
    results = {}
    rate_limiter = None

    if rate_limit is not None and rate_limit > 0:
        rate_limiter = RateLimiter(requests_per_second=rate_limit)

    for source in sources:
        if rate_limiter is not None:
            rate_limiter.wait()

        results[source] = parse_feed(source, timeout=timeout, user_agent=user_agent)

    return results


def validate_feed_url(url: str) -> bool:
    """Validate that a URL is properly formatted for HTTP/HTTPS feeds."""
    try:
        result = urlparse(url)
        if not all([result.scheme, result.netloc]):
            return False
        if result.scheme not in ("http", "https"):
            return False
        return True
    except Exception:
        return False
