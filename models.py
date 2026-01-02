"""
Data models for security advisories and feed entries.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional, List, Dict, Any


class Severity(Enum):
    """Security advisory severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
    UNKNOWN = "unknown"

    @classmethod
    def from_string(cls, value: str) -> "Severity":
        """Parse severity from string, case-insensitive."""
        if not value:
            return cls.UNKNOWN
        value_lower = value.lower().strip()
        for severity in cls:
            if severity.value == value_lower or severity.name == value_lower:
                return severity
        return cls.UNKNOWN

    @property
    def numeric_value(self) -> int:
        """Return numeric value for sorting (higher = more severe)."""
        mapping = {
            Severity.CRITICAL: 5,
            Severity.HIGH: 4,
            Severity.MEDIUM: 3,
            Severity.LOW: 2,
            Severity.INFO: 1,
            Severity.UNKNOWN: 0,
        }
        return mapping.get(self, 0)


class FeedType(Enum):
    """Supported feed types."""
    RSS = "rss"
    ATOM = "atom"
    JSON = "json"
    UNKNOWN = "unknown"


@dataclass
class CVE:
    """Common Vulnerabilities and Exposures identifier."""
    cve_id: str
    description: Optional[str] = None
    url: Optional[str] = None

    @property
    def is_valid(self) -> bool:
        """Check if CVE ID format is valid."""
        if not self.cve_id:
            return False
        parts = self.cve_id.upper().split("-")
        if len(parts) != 3:
            return False
        if parts[0] != "CVE":
            return False
        try:
            year = int(parts[1])
            if year < 1999 or year > datetime.now().year + 1:
                return False
            int(parts[2])
            return True
        except ValueError:
            return False


@dataclass
class Advisory:
    """Represents a security advisory entry."""
    title: str
    link: str
    published: Optional[datetime] = None
    updated: Optional[datetime] = None
    summary: Optional[str] = None
    content: Optional[str] = None
    severity: Severity = Severity.UNKNOWN
    source: Optional[str] = None
    feed_type: FeedType = FeedType.UNKNOWN
    cves: List[CVE] = field(default_factory=list)
    categories: List[str] = field(default_factory=list)
    authors: List[str] = field(default_factory=list)
    raw_data: Dict[str, Any] = field(default_factory=dict)
    parsed_at: datetime = field(default_factory=datetime.now)

    def __post_init__(self):
        """Normalize string severity to Severity enum."""
        if isinstance(self.severity, str):
            self.severity = Severity.from_string(self.severity)

    @property
    def age_days(self) -> Optional[int]:
        """Calculate age in days from published date."""
        if not self.published:
            return None
        delta = datetime.now() - self.published
        return delta.days

    @property
    def has_cve(self) -> bool:
        """Check if advisory contains CVE references."""
        return len(self.cves) > 0

    @property
    def is_recent(self) -> bool:
        """Check if advisory was published within last 7 days."""
        if not self.published:
            return False
        return self.age_days is not None and self.age_days <= 7

    def to_dict(self) -> Dict[str, Any]:
        """Convert advisory to dictionary representation."""
        return {
            "title": self.title,
            "link": self.link,
            "published": self.published.isoformat() if self.published else None,
            "updated": self.updated.isoformat() if self.updated else None,
            "summary": self.summary,
            "severity": self.severity.value,
            "source": self.source,
            "feed_type": self.feed_type.value,
            "cves": [{"cve_id": c.cve_id, "description": c.description} for c in self.cves],
            "categories": self.categories,
            "authors": self.authors,
            "age_days": self.age_days,
        }

    def __str__(self) -> str:
        """String representation for display."""
        severity_str = self.severity.value.upper()
        date_str = self.published.strftime("%Y-%m-%d") if self.published else "Unknown"
        cve_str = ", ".join(c.cve_id for c in self.cves[:3])
        if len(self.cves) > 3:
            cve_str += f" (+{len(self.cves) - 3} more)"

        return f"[{severity_str}] {self.title} ({date_str}){f' - {cve_str}' if cve_str else ''}"


@dataclass
class FeedInfo:
    """Metadata about a parsed feed."""
    title: str
    link: Optional[str] = None
    description: Optional[str] = None
    language: Optional[str] = None
    last_updated: Optional[datetime] = None
    entry_count: int = 0
    feed_type: FeedType = FeedType.UNKNOWN

    def to_dict(self) -> Dict[str, Any]:
        """Convert feed info to dictionary."""
        return {
            "title": self.title,
            "link": self.link,
            "description": self.description,
            "language": self.language,
            "last_updated": self.last_updated.isoformat() if self.last_updated else None,
            "entry_count": self.entry_count,
            "feed_type": self.feed_type.value,
        }


@dataclass
class ParseResult:
    """Result of parsing a security feed."""
    success: bool
    feed_info: Optional[FeedInfo] = None
    advisories: List[Advisory] = field(default_factory=list)
    error: Optional[str] = None
    warnings: List[str] = field(default_factory=list)
    parse_time_ms: float = 0.0

    def __bool__(self) -> bool:
        return self.success

    @property
    def advisory_count(self) -> int:
        """Return number of advisories parsed."""
        return len(self.advisories)

    def filter_by_severity(self, min_severity: Severity) -> List[Advisory]:
        """Filter advisories by minimum severity level."""
        return [
            a for a in self.advisories
            if a.severity.numeric_value >= min_severity.numeric_value
        ]

    def filter_by_date(self, days: int) -> List[Advisory]:
        """Filter advisories published within last N days."""
        return [a for a in self.advisories if a.age_days is not None and a.age_days <= days]

    def get_cve_advisories(self) -> List[Advisory]:
        """Get advisories that contain CVE references."""
        return [a for a in self.advisories if a.has_cve]
