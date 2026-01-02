"""
Tests for security feed parser.
"""

import json
import unittest
from datetime import datetime, timedelta

from models import (
    Advisory,
    CVE,
    FeedInfo,
    FeedType,
    ParseResult,
    Severity,
)
from parser import (
    detect_feed_type,
    extract_cves,
    parse_date,
    parse_rss_atom_feed,
    parse_json_feed,
    detect_severity_from_content,
    validate_feed_url,
)
from utils import (
    filter_advisories,
    sort_advisories,
    deduplicate_advisories,
    format_advisory_text,
    generate_summary,
    group_by_severity,
)


class TestSeverity(unittest.TestCase):
    """Tests for Severity enum."""

    def test_from_string_valid(self):
        self.assertEqual(Severity.from_string("critical"), Severity.CRITICAL)
        self.assertEqual(Severity.from_string("HIGH"), Severity.HIGH)
        self.assertEqual(Severity.from_string("Medium"), Severity.MEDIUM)
        self.assertEqual(Severity.from_string("low"), Severity.LOW)
        self.assertEqual(Severity.from_string("info"), Severity.INFO)

    def test_from_string_invalid(self):
        self.assertEqual(Severity.from_string(""), Severity.UNKNOWN)
        self.assertEqual(Severity.from_string("invalid"), Severity.UNKNOWN)
        self.assertEqual(Severity.from_string(None), Severity.UNKNOWN)

    def test_numeric_value(self):
        self.assertEqual(Severity.CRITICAL.numeric_value, 5)
        self.assertEqual(Severity.HIGH.numeric_value, 4)
        self.assertEqual(Severity.MEDIUM.numeric_value, 3)
        self.assertEqual(Severity.LOW.numeric_value, 2)
        self.assertEqual(Severity.INFO.numeric_value, 1)
        self.assertEqual(Severity.UNKNOWN.numeric_value, 0)


class TestCVE(unittest.TestCase):
    """Tests for CVE model."""

    def test_valid_cve(self):
        cve = CVE(cve_id="CVE-2024-1234")
        self.assertTrue(cve.is_valid)
        self.assertEqual(cve.cve_id, "CVE-2024-1234")

    def test_invalid_cve_format(self):
        cve = CVE(cve_id="INVALID-123")
        self.assertFalse(cve.is_valid)

    def test_invalid_cve_year(self):
        cve = CVE(cve_id="CVE-1990-1234")
        self.assertFalse(cve.is_valid)

    def test_empty_cve(self):
        cve = CVE(cve_id="")
        self.assertFalse(cve.is_valid)


class TestAdvisory(unittest.TestCase):
    """Tests for Advisory model."""

    def setUp(self):
        self.now = datetime.now()
        self.advisory = Advisory(
            title="Test Security Advisory",
            link="https://example.com/advisory/1",
            published=self.now - timedelta(days=5),
            summary="This is a test advisory",
            severity=Severity.HIGH,
            source="https://example.com",
        )

    def test_age_days(self):
        self.assertEqual(self.advisory.age_days, 5)

    def test_has_cve_false(self):
        self.assertFalse(self.advisory.has_cve)

    def test_has_cve_true(self):
        self.advisory.cves = [CVE(cve_id="CVE-2024-1234")]
        self.assertTrue(self.advisory.has_cve)

    def test_is_recent_true(self):
        self.assertTrue(self.advisory.is_recent)

    def test_is_recent_false(self):
        self.advisory.published = self.now - timedelta(days=10)
        self.assertFalse(self.advisory.is_recent)

    def test_to_dict(self):
        result = self.advisory.to_dict()
        self.assertEqual(result["title"], "Test Security Advisory")
        self.assertEqual(result["severity"], "high")
        self.assertIn("link", result)

    def test_str_representation(self):
        result = str(self.advisory)
        self.assertIn("HIGH", result)
        self.assertIn("Test Security Advisory", result)


class TestFeedTypeDetection(unittest.TestCase):
    """Tests for feed type detection."""

    def test_detect_rss(self):
        content = """<?xml version="1.0"?>
        <rss version="2.0">
            <channel><title>Test</title></channel>
        </rss>"""
        self.assertEqual(detect_feed_type(content), FeedType.RSS)

    def test_detect_atom(self):
        content = """<?xml version="1.0"?>
        <feed xmlns="http://www.w3.org/2005/Atom">
            <title>Test</title>
        </feed>"""
        self.assertEqual(detect_feed_type(content), FeedType.ATOM)

    def test_detect_json(self):
        content = '{"items": [{"title": "Test"}]}'
        self.assertEqual(detect_feed_type(content), FeedType.JSON)

    def test_detect_json_with_headers(self):
        content = '{"title": "Test"}'
        headers = {"Content-Type": "application/json"}
        self.assertEqual(detect_feed_type(content, headers), FeedType.JSON)

    def test_detect_unknown(self):
        content = "plain text content"
        self.assertEqual(detect_feed_type(content), FeedType.UNKNOWN)


class TestCVEExtraction(unittest.TestCase):
    """Tests for CVE extraction from text."""

    def test_extract_single_cve(self):
        text = "This vulnerability is tracked as CVE-2024-1234."
        cves = extract_cves(text)
        self.assertEqual(len(cves), 1)
        self.assertEqual(cves[0].cve_id, "CVE-2024-1234")

    def test_extract_multiple_cves(self):
        text = "Fixed CVE-2024-1234 and CVE-2024-5678 in this release."
        cves = extract_cves(text)
        self.assertEqual(len(cves), 2)

    def test_extract_no_cves(self):
        text = "No CVEs mentioned here."
        cves = extract_cves(text)
        self.assertEqual(len(cves), 0)

    def test_extract_deduplicates(self):
        text = "CVE-2024-1234 is serious. CVE-2024-1234 was patched."
        cves = extract_cves(text)
        self.assertEqual(len(cves), 1)


class TestDateParsing(unittest.TestCase):
    """Tests for date parsing."""

    def test_parse_iso_format(self):
        result = parse_date("2024-01-15T10:30:00Z")
        self.assertIsNotNone(result)
        self.assertEqual(result.year, 2024)
        self.assertEqual(result.month, 1)
        self.assertEqual(result.day, 15)

    def test_parse_simple_date(self):
        result = parse_date("2024-01-15")
        self.assertIsNotNone(result)
        self.assertEqual(result.year, 2024)

    def test_parse_none(self):
        self.assertIsNone(parse_date(None))
        self.assertIsNone(parse_date(""))

    def test_parse_invalid(self):
        self.assertIsNone(parse_date("not a date"))


class TestSeverityDetection(unittest.TestCase):
    """Tests for automatic severity detection from content."""

    def test_detect_critical_rce(self):
        severity = detect_severity_from_content(
            "Remote Code Execution in Component X",
            "An attacker can execute arbitrary code",
            None
        )
        self.assertEqual(severity, Severity.CRITICAL)

    def test_detect_critical_zero_day(self):
        severity = detect_severity_from_content(
            "Zero-Day Vulnerability",
            "Active exploitation in the wild",
            None
        )
        self.assertEqual(severity, Severity.CRITICAL)

    def test_detect_high_sql_injection(self):
        severity = detect_severity_from_content(
            "SQL Injection Vulnerability",
            "Allows unauthorized database access",
            None
        )
        self.assertEqual(severity, Severity.HIGH)

    def test_detect_medium_dos(self):
        severity = detect_severity_from_content(
            "Denial of Service Vulnerability",
            "May cause service interruption",
            None
        )
        self.assertEqual(severity, Severity.MEDIUM)

    def test_detect_unknown(self):
        severity = detect_severity_from_content(
            "Security Update",
            "General improvements",
            None
        )
        self.assertEqual(severity, Severity.UNKNOWN)


class TestRSSAtomParsing(unittest.TestCase):
    """Tests for RSS and Atom feed parsing."""

    def test_parse_rss_feed(self):
        content = """<?xml version="1.0" encoding="UTF-8"?>
        <rss version="2.0">
            <channel>
                <title>Security Advisories</title>
                <link>https://example.com</link>
                <description>Security feed</description>
                <item>
                    <title>Critical Vulnerability in Product X</title>
                    <link>https://example.com/advisory/1</link>
                    <pubDate>Mon, 15 Jan 2024 10:00:00 GMT</pubDate>
                    <description>A critical vulnerability CVE-2024-1234 was found.</description>
                </item>
            </channel>
        </rss>"""

        result = parse_rss_atom_feed(content, "https://example.com/feed.xml")
        self.assertTrue(result.success)
        self.assertIsNotNone(result.feed_info)
        self.assertEqual(result.feed_info.title, "Security Advisories")
        self.assertEqual(len(result.advisories), 1)
        self.assertEqual(result.advisories[0].title, "Critical Vulnerability in Product X")

    def test_parse_atom_feed(self):
        content = """<?xml version="1.0" encoding="UTF-8"?>
        <feed xmlns="http://www.w3.org/2005/Atom">
            <title>Security Updates</title>
            <link href="https://example.com"/>
            <entry>
                <title>Security Patch Released</title>
                <link href="https://example.com/patch/1"/>
                <published>2024-01-15T10:00:00Z</published>
                <summary>Patch for CVE-2024-5678</summary>
            </entry>
        </feed>"""

        result = parse_rss_atom_feed(content, "https://example.com/atom.xml")
        self.assertTrue(result.success)
        self.assertEqual(result.feed_info.feed_type, FeedType.ATOM)
        self.assertEqual(len(result.advisories), 1)


class TestJSONFeedParsing(unittest.TestCase):
    """Tests for JSON feed parsing."""

    def test_parse_json_feed(self):
        content = json.dumps({
            "version": "https://jsonfeed.org/version/1.1",
            "title": "Security Advisories",
            "home_page_url": "https://example.com",
            "items": [
                {
                    "id": "1",
                    "title": "Vulnerability Disclosure",
                    "url": "https://example.com/vuln/1",
                    "date_published": "2024-01-15T10:00:00Z",
                    "summary": "CVE-2024-9999 has been disclosed",
                    "tags": ["security", "critical"]
                }
            ]
        })

        result = parse_json_feed(content, "https://example.com/feed.json")
        self.assertTrue(result.success)
        self.assertEqual(result.feed_info.feed_type, FeedType.JSON)
        self.assertEqual(len(result.advisories), 1)
        self.assertEqual(result.advisories[0].categories, ["security", "critical"])

    def test_parse_invalid_json(self):
        content = "not valid json"
        result = parse_json_feed(content)
        self.assertFalse(result.success)
        self.assertIn("Invalid JSON", result.error)


class TestURLValidation(unittest.TestCase):
    """Tests for URL validation."""

    def test_valid_urls(self):
        self.assertTrue(validate_feed_url("https://example.com/feed.xml"))
        self.assertTrue(validate_feed_url("http://example.com/rss"))
        self.assertTrue(validate_feed_url("https://security.example.org/atom.xml"))

    def test_invalid_urls(self):
        self.assertFalse(validate_feed_url("not-a-url"))
        self.assertFalse(validate_feed_url(""))
        self.assertFalse(validate_feed_url("ftp://example.com"))


class TestFiltering(unittest.TestCase):
    """Tests for advisory filtering."""

    def setUp(self):
        now = datetime.now()
        self.advisories = [
            Advisory(
                title="Critical Advisory",
                link="https://example.com/1",
                published=now - timedelta(days=1),
                severity=Severity.CRITICAL,
                cves=[CVE(cve_id="CVE-2024-0001")],
            ),
            Advisory(
                title="High Advisory",
                link="https://example.com/2",
                published=now - timedelta(days=5),
                severity=Severity.HIGH,
            ),
            Advisory(
                title="Medium Advisory",
                link="https://example.com/3",
                published=now - timedelta(days=10),
                severity=Severity.MEDIUM,
            ),
            Advisory(
                title="Low Advisory",
                link="https://example.com/4",
                published=now - timedelta(days=30),
                severity=Severity.LOW,
                cves=[CVE(cve_id="CVE-2024-0002")],
            ),
        ]

    def test_filter_by_severity(self):
        result = filter_advisories(self.advisories, min_severity=Severity.HIGH)
        self.assertEqual(len(result), 2)

    def test_filter_by_age(self):
        result = filter_advisories(self.advisories, max_age_days=7)
        self.assertEqual(len(result), 2)

    def test_filter_by_cve_present(self):
        result = filter_advisories(self.advisories, has_cve=True)
        self.assertEqual(len(result), 2)

    def test_filter_by_cve_absent(self):
        result = filter_advisories(self.advisories, has_cve=False)
        self.assertEqual(len(result), 2)

    def test_filter_by_search_term(self):
        result = filter_advisories(self.advisories, search_terms=["Critical"])
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].title, "Critical Advisory")

    def test_combined_filters(self):
        result = filter_advisories(
            self.advisories,
            min_severity=Severity.MEDIUM,
            max_age_days=15,
        )
        self.assertEqual(len(result), 3)


class TestSorting(unittest.TestCase):
    """Tests for advisory sorting."""

    def setUp(self):
        now = datetime.now()
        self.advisories = [
            Advisory(
                title="Alpha Advisory",
                link="https://example.com/1",
                published=now - timedelta(days=10),
                severity=Severity.MEDIUM,
            ),
            Advisory(
                title="Beta Advisory",
                link="https://example.com/2",
                published=now - timedelta(days=1),
                severity=Severity.CRITICAL,
            ),
            Advisory(
                title="Gamma Advisory",
                link="https://example.com/3",
                published=now - timedelta(days=5),
                severity=Severity.HIGH,
            ),
        ]

    def test_sort_by_published(self):
        result = sort_advisories(self.advisories, by="published", reverse=True)
        self.assertEqual(result[0].title, "Beta Advisory")

    def test_sort_by_severity(self):
        result = sort_advisories(self.advisories, by="severity", reverse=True)
        self.assertEqual(result[0].severity, Severity.CRITICAL)

    def test_sort_by_title(self):
        result = sort_advisories(self.advisories, by="title", reverse=False)
        self.assertEqual(result[0].title, "Alpha Advisory")


class TestDeduplication(unittest.TestCase):
    """Tests for advisory deduplication."""

    def test_remove_duplicates(self):
        now = datetime.now()
        advisories = [
            Advisory(
                title="Duplicate Advisory",
                link="https://example.com/1",
                published=now,
            ),
            Advisory(
                title="Duplicate Advisory",
                link="https://example.com/1",
                published=now,
            ),
            Advisory(
                title="Unique Advisory",
                link="https://example.com/2",
                published=now,
            ),
        ]
        result = deduplicate_advisories(advisories)
        self.assertEqual(len(result), 2)

    def test_case_insensitive_dedup(self):
        now = datetime.now()
        advisories = [
            Advisory(
                title="Test Advisory",
                link="https://example.com/1",
                published=now,
            ),
            Advisory(
                title="TEST ADVISORY",
                link="https://EXAMPLE.COM/1",
                published=now,
            ),
        ]
        result = deduplicate_advisories(advisories)
        self.assertEqual(len(result), 1)


class TestFormatting(unittest.TestCase):
    """Tests for output formatting."""

    def test_format_advisory_text(self):
        advisory = Advisory(
            title="Test Advisory",
            link="https://example.com/1",
            severity=Severity.HIGH,
            cves=[CVE(cve_id="CVE-2024-1234")],
        )
        result = format_advisory_text(advisory)
        self.assertIn("[HIGH]", result)
        self.assertIn("Test Advisory", result)
        self.assertIn("CVE-2024-1234", result)

    def test_format_advisory_verbose(self):
        advisory = Advisory(
            title="Test Advisory",
            link="https://example.com/1",
            severity=Severity.HIGH,
            summary="This is a summary",
        )
        result = format_advisory_text(advisory, verbose=True)
        self.assertIn("Summary:", result)


class TestSummaryGeneration(unittest.TestCase):
    """Tests for summary generation."""

    def test_generate_summary(self):
        now = datetime.now()
        advisories = [
            Advisory(
                title="Critical",
                link="https://example.com/1",
                published=now - timedelta(days=1),
                severity=Severity.CRITICAL,
                cves=[CVE(cve_id="CVE-2024-0001")],
            ),
            Advisory(
                title="High",
                link="https://example.com/2",
                published=now - timedelta(days=2),
                severity=Severity.HIGH,
            ),
        ]
        result = type("Result", (), {
            "success": True,
            "advisories": advisories,
            "error": None,
            "parse_time_ms": 100.0,
        })()
        summary = generate_summary(result)
        self.assertEqual(summary["total_advisories"], 2)
        self.assertEqual(summary["advisories_with_cve"], 1)
        self.assertEqual(summary["total_cves"], 1)


class TestGrouping(unittest.TestCase):
    """Tests for grouping advisories."""

    def test_group_by_severity(self):
        advisories = [
            Advisory(title="A", link="1", severity=Severity.HIGH),
            Advisory(title="B", link="2", severity=Severity.HIGH),
            Advisory(title="C", link="3", severity=Severity.MEDIUM),
        ]
        groups = group_by_severity(advisories)
        self.assertEqual(len(groups[Severity.HIGH]), 2)
        self.assertEqual(len(groups[Severity.MEDIUM]), 1)


if __name__ == "__main__":
    unittest.main()
