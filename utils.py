"""
Utility functions for filtering, sorting, and output formatting.
"""

import csv
import io
import json
import time
from collections import deque
from datetime import datetime
from typing import List, Optional, Dict, Any, Callable

from models import Advisory, FeedInfo, ParseResult, Severity


def sort_advisories(
    advisories: List[Advisory],
    by: str = "published",
    reverse: bool = True,
) -> List[Advisory]:
    """
    Sort advisories by specified field.

    Args:
        advisories: List of advisories to sort
        by: Field to sort by (published, severity, title, source)
        reverse: Sort in descending order if True

    Returns:
        Sorted list of advisories
    """
    if by == "severity":
        return sorted(advisories, key=lambda a: a.severity.numeric_value, reverse=reverse)
    elif by == "published":
        return sorted(
            advisories,
            key=lambda a: a.published or datetime.min,
            reverse=reverse,
        )
    elif by == "title":
        return sorted(advisories, key=lambda a: a.title.lower(), reverse=reverse)
    elif by == "source":
        return sorted(advisories, key=lambda a: a.source or "", reverse=reverse)
    else:
        return advisories


def filter_advisories(
    advisories: List[Advisory],
    min_severity: Optional[Severity] = None,
    max_age_days: Optional[int] = None,
    search_terms: Optional[List[str]] = None,
    has_cve: Optional[bool] = None,
    sources: Optional[List[str]] = None,
    categories: Optional[List[str]] = None,
) -> List[Advisory]:
    """
    Filter advisories by multiple criteria.

    Args:
        advisories: List of advisories to filter
        min_severity: Minimum severity level to include
        max_age_days: Maximum age in days
        search_terms: List of terms to search for in title/summary
        has_cve: If True, only include advisories with CVEs; if False, exclude them
        sources: Only include advisories from these sources
        categories: Only include advisories with these categories

    Returns:
        Filtered list of advisories
    """
    result = advisories

    if min_severity is not None:
        result = [
            a for a in result
            if a.severity.numeric_value >= min_severity.numeric_value
        ]

    if max_age_days is not None:
        result = [
            a for a in result
            if a.age_days is not None and a.age_days <= max_age_days
        ]

    if search_terms:
        def matches_search(advisory: Advisory) -> bool:
            text = f"{advisory.title} {advisory.summary or ''} {advisory.content or ''}".lower()
            return any(term.lower() in text for term in search_terms)
        result = [a for a in result if matches_search(a)]

    if has_cve is True:
        result = [a for a in result if a.has_cve]
    elif has_cve is False:
        result = [a for a in result if not a.has_cve]

    if sources:
        sources_lower = [s.lower() for s in sources]
        result = [
            a for a in result
            if a.source and a.source.lower() in sources_lower
        ]

    if categories:
        categories_lower = [c.lower() for c in categories]
        result = [
            a for a in result
            if any(cat.lower() in categories_lower for cat in a.categories)
        ]

    return result


def deduplicate_advisories(advisories: List[Advisory]) -> List[Advisory]:
    """
    Remove duplicate advisories based on title and link.

    Keeps the first occurrence of each unique advisory.
    """
    seen = set()
    unique = []

    for advisory in advisories:
        key = (advisory.title.lower().strip(), advisory.link.lower().strip())
        if key not in seen:
            seen.add(key)
            unique.append(advisory)

    return unique


def merge_results(results: List[ParseResult]) -> ParseResult:
    """
    Merge multiple ParseResult objects into one.

    Args:
        results: List of ParseResult objects to merge

    Returns:
        Merged ParseResult with combined advisories
    """
    all_advisories = []
    all_warnings = []
    errors = []
    total_parse_time = 0.0
    feed_infos = []

    for result in results:
        all_advisories.extend(result.advisories)
        all_warnings.extend(result.warnings)
        total_parse_time += result.parse_time_ms
        if result.error:
            errors.append(result.error)
        if result.feed_info:
            feed_infos.append(result.feed_info)

    all_advisories = deduplicate_advisories(all_advisories)

    return ParseResult(
        success=all(r.success for r in results) if results else False,
        advisories=all_advisories,
        warnings=all_warnings,
        error="; ".join(errors) if errors else None,
        parse_time_ms=total_parse_time,
    )


def format_advisory_text(advisory: Advisory, verbose: bool = False) -> str:
    """Format a single advisory as human-readable text."""
    lines = []
    severity_str = f"[{advisory.severity.value.upper()}]"
    date_str = advisory.published.strftime("%Y-%m-%d") if advisory.published else "Unknown"

    lines.append(f"{severity_str} {advisory.title}")
    lines.append(f"  Published: {date_str}")
    lines.append(f"  Link: {advisory.link}")

    if advisory.source:
        lines.append(f"  Source: {advisory.source}")

    if advisory.cves:
        cve_ids = ", ".join(c.cve_id for c in advisory.cves)
        lines.append(f"  CVEs: {cve_ids}")

    if advisory.categories:
        lines.append(f"  Categories: {', '.join(advisory.categories)}")

    if verbose and advisory.summary:
        summary = advisory.summary.strip()
        if len(summary) > 500:
            summary = summary[:497] + "..."
        lines.append(f"  Summary: {summary}")

    return "\n".join(lines)


def format_results_text(
    result: ParseResult,
    verbose: bool = False,
    limit: Optional[int] = None,
) -> str:
    """Format parse results as human-readable text."""
    lines = []

    if result.feed_info:
        info = result.feed_info
        lines.append(f"Feed: {info.title}")
        if info.description:
            lines.append(f"Description: {info.description}")
        lines.append(f"Entries: {info.entry_count}")
        lines.append(f"Type: {info.feed_type.value.upper()}")
        lines.append("")

    if not result.success:
        lines.append(f"Error: {result.error}")
        return "\n".join(lines)

    advisories = result.advisories
    if limit:
        advisories = advisories[:limit]

    lines.append(f"Parsed {len(result.advisories)} advisories in {result.parse_time_ms:.1f}ms")
    lines.append("=" * 60)

    for advisory in advisories:
        lines.append(format_advisory_text(advisory, verbose))
        lines.append("")

    return "\n".join(lines)


def format_results_json(result: ParseResult, pretty: bool = True) -> str:
    """Format parse results as JSON."""
    data = {
        "success": result.success,
        "error": result.error,
        "parse_time_ms": result.parse_time_ms,
        "feed_info": result.feed_info.to_dict() if result.feed_info else None,
        "advisory_count": result.advisory_count,
        "advisories": [a.to_dict() for a in result.advisories],
    }

    if pretty:
        return json.dumps(data, indent=2, default=str)
    return json.dumps(data, default=str)


def format_results_csv(advisories: List[Advisory]) -> str:
    """Format advisories as CSV."""
    output = io.StringIO()
    fieldnames = [
        "title", "link", "published", "severity", "source",
        "cves", "categories", "summary"
    ]
    writer = csv.DictWriter(output, fieldnames=fieldnames, extrasaction="ignore")
    writer.writeheader()

    for advisory in advisories:
        row = {
            "title": advisory.title,
            "link": advisory.link,
            "published": advisory.published.isoformat() if advisory.published else "",
            "severity": advisory.severity.value,
            "source": advisory.source or "",
            "cves": ", ".join(c.cve_id for c in advisory.cves),
            "categories": ", ".join(advisory.categories),
            "summary": (advisory.summary or "").replace("\n", " ")[:500],
        }
        writer.writerow(row)

    return output.getvalue()


def generate_summary(result: ParseResult) -> Dict[str, Any]:
    """Generate a summary statistics dictionary."""
    if not result.success:
        return {"error": result.error}

    advisories = result.advisories

    severity_counts = {}
    for advisory in advisories:
        sev = advisory.severity.value
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    cve_count = sum(1 for a in advisories if a.has_cve)
    total_cves = sum(len(a.cves) for a in advisories)

    recent_count = sum(1 for a in advisories if a.is_recent)

    sources = {}
    for advisory in advisories:
        src = advisory.source or "unknown"
        sources[src] = sources.get(src, 0) + 1

    return {
        "total_advisories": len(advisories),
        "severity_breakdown": severity_counts,
        "advisories_with_cve": cve_count,
        "total_cves": total_cves,
        "recent_advisories": recent_count,
        "sources": sources,
        "parse_time_ms": result.parse_time_ms,
    }


def print_summary(result: ParseResult) -> None:
    """Print a formatted summary to stdout."""
    summary = generate_summary(result)

    if "error" in summary:
        print(f"Error: {summary['error']}")
        return

    print("\n=== Security Feed Summary ===")
    print(f"Total Advisories: {summary['total_advisories']}")
    print(f"Parse Time: {summary['parse_time_ms']:.1f}ms")
    print()

    print("Severity Breakdown:")
    for sev in ["critical", "high", "medium", "low", "info", "unknown"]:
        count = summary["severity_breakdown"].get(sev, 0)
        if count > 0:
            print(f"  {sev.upper()}: {count}")

    print()
    print(f"Advisories with CVEs: {summary['advisories_with_cve']}")
    print(f"Total CVEs Referenced: {summary['total_cves']}")
    print(f"Recent (last 7 days): {summary['recent_advisories']}")


def group_by_severity(advisories: List[Advisory]) -> Dict[Severity, List[Advisory]]:
    """Group advisories by severity level."""
    groups: Dict[Severity, List[Advisory]] = {}
    for advisory in advisories:
        sev = advisory.severity
        if sev not in groups:
            groups[sev] = []
        groups[sev].append(advisory)
    return groups


def group_by_source(advisories: List[Advisory]) -> Dict[str, List[Advisory]]:
    """Group advisories by source."""
    groups: Dict[str, List[Advisory]] = {}
    for advisory in advisories:
        src = advisory.source or "unknown"
        if src not in groups:
            groups[src] = []
        groups[src].append(advisory)
    return groups


def get_top_cves(advisories: List[Advisory], limit: int = 10) -> List[tuple]:
    """Get most frequently referenced CVEs."""
    cve_counts: Dict[str, int] = {}
    for advisory in advisories:
        for cve in advisory.cves:
            cve_counts[cve.cve_id] = cve_counts.get(cve.cve_id, 0) + 1

    sorted_cves = sorted(cve_counts.items(), key=lambda x: x[1], reverse=True)
    return sorted_cves[:limit]


class RateLimiter:
    """
    Rate limiter for controlling request frequency.

    Implements a sliding window rate limiting algorithm to ensure
    requests don't exceed a specified rate (requests per second).
    """

    def __init__(self, requests_per_second: float = 1.0):
        """
        Initialize the rate limiter.

        Args:
            requests_per_second: Maximum number of requests allowed per second.
                                Must be greater than 0.
        """
        if requests_per_second <= 0:
            raise ValueError("requests_per_second must be greater than 0")

        self.requests_per_second = requests_per_second
        self.min_interval = 1.0 / requests_per_second
        self._timestamps: deque = deque()
        self._last_request_time: Optional[float] = None

    def wait(self) -> float:
        """
        Wait if necessary to respect rate limit, then record the request.

        Ensures minimum interval between consecutive requests.

        Returns:
            Time waited in seconds (0 if no wait was needed)
        """
        now = time.time()
        wait_time = 0.0

        if self._last_request_time is not None:
            earliest_next = self._last_request_time + self.min_interval
            wait_time = max(0, earliest_next - now)

        if wait_time > 0:
            time.sleep(wait_time)

        actual_time = time.time()
        self._last_request_time = actual_time
        self._timestamps.append(actual_time)

        window_size = max(self.requests_per_second * 2, 10)
        while len(self._timestamps) > window_size:
            self._timestamps.popleft()

        return wait_time

    def reset(self) -> None:
        """Clear all recorded timestamps."""
        self._timestamps.clear()
        self._last_request_time = None

    @property
    def request_count(self) -> int:
        """Return the number of tracked requests."""
        return len(self._timestamps)
