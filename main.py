#!/usr/bin/env python3
"""
Security Feed Parser - Command Line Interface

A tool for parsing security advisories from RSS, Atom, and JSON feeds.
Supports filtering by severity, date, CVE presence, and more.
"""

import argparse
import sys
from datetime import datetime
from typing import List, Optional

from models import Severity, FeedType
from parser import parse_feed, parse_multiple_feeds, validate_feed_url
from utils import (
    filter_advisories,
    sort_advisories,
    format_results_text,
    format_results_json,
    format_results_csv,
    print_summary,
    generate_summary,
    deduplicate_advisories,
    group_by_severity,
    get_top_cves,
)


VERSION = "1.0.0"
DEFAULT_USER_AGENT = "SecurityFeedParser/1.0"


def parse_severity(value: str) -> Severity:
    """Parse severity string argument."""
    return Severity.from_string(value)


def create_parser() -> argparse.ArgumentParser:
    """Create and configure the argument parser."""
    parser = argparse.ArgumentParser(
        prog="security-feed-parser",
        description="Parse security advisories from RSS, Atom, and JSON feeds.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s https://example.com/security-feed.xml
  %(prog)s -f feed1.xml feed2.json --severity high
  %(prog)s https://feeds.example.com --json --output results.json
  %(prog)s -f local_feed.xml --search "CVE-2024" --cve-only
  %(prog)s --summary https://security.example.org/rss

Supported feed formats:
  - RSS 2.0
  - Atom 1.0
  - JSON Feed (RFC 8613)
  - Custom JSON security feeds
        """,
    )

    parser.add_argument(
        "urls",
        nargs="*",
        help="Feed URLs to parse",
    )

    parser.add_argument(
        "-f", "--files",
        nargs="+",
        metavar="FILE",
        help="Local feed files to parse",
    )

    parser.add_argument(
        "-o", "--output",
        metavar="FILE",
        help="Output file (default: stdout)",
    )

    parser.add_argument(
        "--format",
        choices=["text", "json", "csv"],
        default="text",
        help="Output format (default: text)",
    )

    parser.add_argument(
        "--severity",
        type=parse_severity,
        metavar="LEVEL",
        help="Minimum severity level (critical, high, medium, low, info)",
    )

    parser.add_argument(
        "--days",
        type=int,
        metavar="N",
        help="Only include advisories from the last N days",
    )

    parser.add_argument(
        "--search",
        nargs="+",
        metavar="TERM",
        help="Search terms to filter by (matches title and summary)",
    )

    parser.add_argument(
        "--cve-only",
        action="store_true",
        help="Only include advisories with CVE references",
    )

    parser.add_argument(
        "--no-cve",
        action="store_true",
        help="Exclude advisories with CVE references",
    )

    parser.add_argument(
        "--source",
        nargs="+",
        metavar="URL",
        help="Filter by source URLs",
    )

    parser.add_argument(
        "--category",
        nargs="+",
        metavar="CAT",
        help="Filter by categories",
    )

    parser.add_argument(
        "--sort",
        choices=["published", "severity", "title", "source"],
        default="published",
        help="Sort field (default: published)",
    )

    parser.add_argument(
        "--reverse",
        action="store_true",
        help="Reverse sort order",
    )

    parser.add_argument(
        "--limit",
        type=int,
        metavar="N",
        help="Limit number of output advisories",
    )

    parser.add_argument(
        "--summary",
        action="store_true",
        help="Show summary statistics instead of full output",
    )

    parser.add_argument(
        "--top-cves",
        type=int,
        nargs="?",
        const=10,
        metavar="N",
        help="Show top N CVEs (default: 10)",
    )

    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Verbose output (include summaries)",
    )

    parser.add_argument(
        "--timeout",
        type=int,
        default=30,
        metavar="SECONDS",
        help="Request timeout in seconds (default: 30)",
    )

    parser.add_argument(
        "--user-agent",
        metavar="STRING",
        help="Custom User-Agent header",
    )

    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {VERSION}",
    )

    return parser


def read_local_file(filepath: str) -> str:
    """Read content from a local file."""
    with open(filepath, "r", encoding="utf-8") as f:
        return f.read()


def process_feeds(
    urls: List[str],
    files: Optional[List[str]] = None,
    timeout: int = 30,
    user_agent: Optional[str] = None,
) -> List:
    """Process URLs and local files, returning list of ParseResult objects."""
    results = []
    user_agent = user_agent or DEFAULT_USER_AGENT

    for url in urls:
        if not validate_feed_url(url):
            print(f"Warning: Invalid URL format: {url}", file=sys.stderr)
            continue

        result = parse_feed(url, is_url=True, timeout=timeout, user_agent=user_agent)
        if not result.success:
            print(f"Error parsing {url}: {result.error}", file=sys.stderr)
        results.append(result)

    if files:
        for filepath in files:
            try:
                content = read_local_file(filepath)
                result = parse_feed(content, is_url=False, user_agent=user_agent)
                if not result.success:
                    print(f"Error parsing {filepath}: {result.error}", file=sys.stderr)
                results.append(result)
            except FileNotFoundError:
                print(f"Error: File not found: {filepath}", file=sys.stderr)
            except IOError as e:
                print(f"Error reading {filepath}: {e}", file=sys.stderr)

    return results


def apply_filters(
    advisories,
    severity: Optional[Severity] = None,
    days: Optional[int] = None,
    search_terms: Optional[List[str]] = None,
    cve_only: bool = False,
    no_cve: bool = False,
    sources: Optional[List[str]] = None,
    categories: Optional[List[str]] = None,
):
    """Apply all filters to advisories list."""
    has_cve = None
    if cve_only:
        has_cve = True
    elif no_cve:
        has_cve = False

    return filter_advisories(
        advisories,
        min_severity=severity,
        max_age_days=days,
        search_terms=search_terms,
        has_cve=has_cve,
        sources=sources,
        categories=categories,
    )


def write_output(content: str, output_file: Optional[str] = None) -> None:
    """Write content to file or stdout."""
    if output_file:
        with open(output_file, "w", encoding="utf-8") as f:
            f.write(content)
    else:
        print(content)


def main(argv: Optional[List[str]] = None) -> int:
    """Main entry point."""
    parser = create_parser()
    args = parser.parse_args(argv)

    if not args.urls and not args.files:
        parser.print_help()
        return 1

    results = process_feeds(
        urls=args.urls,
        files=args.files,
        timeout=args.timeout,
        user_agent=args.user_agent,
    )

    if not results:
        print("No feeds were processed.", file=sys.stderr)
        return 1

    all_advisories = []
    for result in results:
        all_advisories.extend(result.advisories)

    if not all_advisories:
        print("No advisories found in the provided feeds.", file=sys.stderr)
        return 1

    all_advisories = deduplicate_advisories(all_advisories)

    filtered = apply_filters(
        all_advisories,
        severity=args.severity,
        days=args.days,
        search_terms=args.search,
        cve_only=args.cve_only,
        no_cve=args.no_cve,
        sources=args.source,
        categories=args.category,
    )

    sorted_advisories = sort_advisories(
        filtered,
        by=args.sort,
        reverse=not args.reverse,
    )

    if args.limit:
        sorted_advisories = sorted_advisories[:args.limit]

    if args.summary:
        summary_result = type("SummaryResult", (), {
            "success": True,
            "advisories": all_advisories,
            "error": None,
            "parse_time_ms": sum(r.parse_time_ms for r in results),
            "feed_info": results[0].feed_info if results else None,
        })()
        print_summary(summary_result)
        return 0

    if args.top_cves is not None:
        top = get_top_cves(all_advisories, args.top_cves)
        print("\n=== Top CVEs ===")
        for cve_id, count in top:
            print(f"  {cve_id}: {count} advisory(ies)")
        return 0

    if args.format == "json":
        output_result = type("OutputResult", (), {
            "success": True,
            "advisories": sorted_advisories,
            "error": None,
            "parse_time_ms": sum(r.parse_time_ms for r in results),
            "feed_info": results[0].feed_info if results else None,
            "advisory_count": len(sorted_advisories),
        })()
        output = format_results_json(output_result)
    elif args.format == "csv":
        output = format_results_csv(sorted_advisories)
    else:
        output_result = type("OutputResult", (), {
            "success": True,
            "advisories": sorted_advisories,
            "error": None,
            "parse_time_ms": sum(r.parse_time_ms for r in results),
            "feed_info": results[0].feed_info if results else None,
            "advisory_count": len(sorted_advisories),
        })()
        output = format_results_text(output_result, verbose=args.verbose)

    write_output(output, args.output)

    if args.output:
        print(f"Output written to: {args.output}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
