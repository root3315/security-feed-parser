# Security Feed Parser

A Python tool for parsing security advisories from RSS, Atom, and JSON feeds. Automatically extracts CVE references, detects severity levels, and provides powerful filtering and output options.

## Features

- **Multiple Feed Formats**: Supports RSS 2.0, Atom 1.0, and JSON Feed formats
- **CVE Extraction**: Automatically detects and extracts CVE identifiers from feed content
- **Severity Detection**: Classifies advisories by severity (Critical, High, Medium, Low, Info)
- **Flexible Filtering**: Filter by severity, date range, CVE presence, search terms, and categories
- **Multiple Output Formats**: Text, JSON, and CSV output options
- **Batch Processing**: Parse multiple feeds simultaneously
- **Deduplication**: Automatically removes duplicate advisories

## Installation

### Requirements

- Python 3.8 or higher
- pip

### Install Dependencies

```bash
pip install -r requirements.txt
```

### Dependencies

- `feedparser` - RSS/Atom feed parsing
- `requests` - HTTP requests for fetching feeds
- `python-dateutil` - Date parsing utilities

## Usage

### Command Line Interface

#### Basic Usage

Parse a single feed URL:

```bash
python main.py https://example.com/security-feed.xml
```

Parse local feed files:

```bash
python main.py -f feed1.xml feed2.json
```

Combine URLs and local files:

```bash
python main.py https://example.com/feed.xml -f local_feed.json
```

#### Output Formats

Text output (default):

```bash
python main.py https://example.com/feed.xml
```

JSON output:

```bash
python main.py https://example.com/feed.xml --format json
python main.py https://example.com/feed.xml --format json -o results.json
```

CSV output:

```bash
python main.py https://example.com/feed.xml --format csv -o advisories.csv
```

#### Filtering

Filter by minimum severity:

```bash
python main.py https://example.com/feed.xml --severity high
python main.py https://example.com/feed.xml --severity critical
```

Filter by date (last N days):

```bash
python main.py https://example.com/feed.xml --days 7
python main.py https://example.com/feed.xml --days 30
```

Search by keywords:

```bash
python main.py https://example.com/feed.xml --search "CVE-2024"
python main.py https://example.com/feed.xml --search "remote code execution"
```

CVE filtering:

```bash
# Only advisories with CVEs
python main.py https://example.com/feed.xml --cve-only

# Exclude advisories with CVEs
python main.py https://example.com/feed.xml --no-cve
```

Filter by source or category:

```bash
python main.py https://example.com/feed.xml --source "https://vendor.com"
python main.py https://example.com/feed.xml --category "network" "authentication"
```

#### Sorting and Limiting

Sort by different fields:

```bash
python main.py https://example.com/feed.xml --sort severity
python main.py https://example.com/feed.xml --sort published
python main.py https://example.com/feed.xml --sort title
```

Reverse sort order:

```bash
python main.py https://example.com/feed.xml --sort severity --reverse
```

Limit output:

```bash
python main.py https://example.com/feed.xml --limit 10
```

#### Summary and Statistics

Show summary statistics:

```bash
python main.py https://example.com/feed.xml --summary
```

Show top CVEs:

```bash
python main.py https://example.com/feed.xml --top-cves
python main.py https://example.com/feed.xml --top-cves 20
```

Verbose output with summaries:

```bash
python main.py https://example.com/feed.xml --verbose
```

### Python API

```python
from parser import parse_feed, parse_multiple_feeds
from models import Severity
from utils import filter_advisories, sort_advisories, generate_summary

# Parse a single feed
result = parse_feed("https://example.com/security-feed.xml")

if result.success:
    print(f"Parsed {result.advisory_count} advisories")
    print(f"Feed: {result.feed_info.title}")

    # Filter and sort
    filtered = filter_advisories(
        result.advisories,
        min_severity=Severity.HIGH,
        max_age_days=7,
        has_cve=True,
    )
    sorted_advisories = sort_advisories(filtered, by="severity")

    # Generate summary
    summary = generate_summary(result)
    print(f"Critical: {summary['severity_breakdown'].get('critical', 0)}")
    print(f"Total CVEs: {summary['total_cves']}")

# Parse multiple feeds
results = parse_multiple_feeds([
    "https://example.com/feed1.xml",
    "https://example.com/feed2.json",
])

for url, result in results.items():
    if result.success:
        print(f"{url}: {result.advisory_count} advisories")
```

### Parsing Local Content

```python
from parser import parse_feed

# Parse RSS/Atom content directly
rss_content = """<?xml version="1.0"?>
<rss version="2.0">
    <channel>
        <title>Security Feed</title>
        <item>
            <title>Vulnerability</title>
            <description>CVE-2024-1234</description>
        </item>
    </channel>
</rss>"""

result = parse_feed(rss_content, is_url=False)
```

## How It Works

### Feed Detection

The parser automatically detects feed format by examining:
- HTTP Content-Type headers
- XML declaration and root elements (RSS vs Atom)
- JSON structure (items, entries, feed keys)

### CVE Extraction

CVE identifiers are extracted using regex pattern matching:
- Pattern: `CVE-YYYY-NNNN+` (case-insensitive)
- Automatic deduplication within each advisory
- Validation of CVE format and year range

### Severity Detection

When feeds don't explicitly specify severity, the parser analyzes content for keywords:

| Severity | Keywords |
|----------|----------|
| Critical | critical, zero-day, remote code execution, RCE, authentication bypass |
| High | high, severe, privilege escalation, SQL injection, XSS, buffer overflow |
| Medium | medium, moderate, cross-site, information disclosure, denial of service |
| Low | low, minor, informational, cosmetic |

### Data Models

- **Advisory**: Core data structure with title, link, dates, severity, CVEs, categories
- **CVE**: CVE identifier with validation
- **FeedInfo**: Feed metadata (title, description, entry count)
- **ParseResult**: Parsing result with advisories, errors, warnings
- **Severity**: Enum for severity levels with numeric comparison

## Project Structure

```
security-feed-parser/
├── main.py              # CLI entry point
├── parser.py            # Feed parsing logic
├── models.py            # Data models
├── utils.py             # Filtering and formatting utilities
├── requirements.txt     # Python dependencies
├── README.md            # This file
└── tests/
    └── test_parser.py   # Unit tests
```

## Running Tests

```bash
python -m unittest discover -s tests
```

## Examples

### Monitor Multiple Security Feeds

```bash
python main.py \
    https://us-cert.cisa.gov/ncas/alerts.xml \
    https://www.cisa.gov/news-events/cybersecurity-advisories.xml \
    --severity high \
    --days 7 \
    --format json \
    -o weekly_report.json
```

### Generate CVE Report

```bash
python main.py \
    https://example.com/security.xml \
    --cve-only \
    --top-cves 15 \
    --summary
```

### Export for Further Processing

```bash
python main.py \
    https://example.com/feed.xml \
    --format csv \
    --severity medium \
    -o advisories.csv
```

## License

MIT License
