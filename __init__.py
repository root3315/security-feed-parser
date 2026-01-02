"""
Security Feed Parser - Parse security advisories from RSS, Atom, and JSON feeds.
"""

from models import Advisory, CVE, FeedInfo, FeedType, ParseResult, Severity
from parser import parse_feed, parse_multiple_feeds, validate_feed_url
from utils import (
    filter_advisories,
    sort_advisories,
    deduplicate_advisories,
    format_results_json,
    format_results_csv,
    generate_summary,
)

__version__ = "1.0.0"
__all__ = [
    "Advisory",
    "CVE",
    "FeedInfo",
    "FeedType",
    "ParseResult",
    "Severity",
    "parse_feed",
    "parse_multiple_feeds",
    "validate_feed_url",
    "filter_advisories",
    "sort_advisories",
    "deduplicate_advisories",
    "format_results_json",
    "format_results_csv",
    "generate_summary",
]
