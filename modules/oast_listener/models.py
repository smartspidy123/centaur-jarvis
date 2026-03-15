"""
models.py — Data structures for OAST Listener module.

Defines Callback and PayloadInfo with full serialization support,
validation, and edge-case handling for malformed data.
"""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional


class CallbackType(str, Enum):
    """Type of callback received."""
    HTTP = "HTTP"
    DNS = "DNS"
    UNKNOWN = "UNKNOWN"


class PayloadStatus(str, Enum):
    """Status of a registered payload."""
    ACTIVE = "ACTIVE"
    EXPIRED = "EXPIRED"
    TRIGGERED = "TRIGGERED"
    REVOKED = "REVOKED"


@dataclass
class Callback:
    """
    Represents a single inbound callback (HTTP request or DNS query).

    Attributes:
        callback_id:      Unique identifier for this callback event.
        callback_type:    HTTP or DNS.
        source_ip:        IP address of the requester.
        timestamp:        ISO-8601 timestamp of receipt.
        unique_id:        Extracted unique identifier from URL/subdomain (may be None).
        url:              Full URL for HTTP callbacks.
        domain:           Queried domain for DNS callbacks.
        method:           HTTP method (GET, POST, etc.) — HTTP only.
        headers:          HTTP headers dict — HTTP only.
        body:             Request body (truncated) — HTTP only.
        dns_record_type:  DNS record type (A, AAAA, TXT, etc.) — DNS only.
        raw:              Raw representation for debugging.
    """
    callback_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    callback_type: str = CallbackType.HTTP.value
    source_ip: str = "0.0.0.0"
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    unique_id: Optional[str] = None
    url: Optional[str] = None
    domain: Optional[str] = None
    method: Optional[str] = None
    headers: Dict[str, str] = field(default_factory=dict)
    body: Optional[str] = None
    dns_record_type: Optional[str] = None
    raw: Optional[str] = None

    # Maximum body size stored (bytes)
    MAX_BODY_SIZE: int = field(default=10240, repr=False, compare=False)

    def truncate_body(self) -> None:
        """Truncate body to MAX_BODY_SIZE to prevent memory bloat."""
        if self.body and len(self.body) > self.MAX_BODY_SIZE:
            self.body = self.body[: self.MAX_BODY_SIZE] + "...[TRUNCATED]"

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to dictionary, excluding internal fields."""
        d = asdict(self)
        d.pop("MAX_BODY_SIZE", None)
        return d

    def to_json(self) -> str:
        """Serialize to JSON string."""
        return json.dumps(self.to_dict(), default=str)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> Callback:
        """Deserialize from dictionary with safety checks."""
        data.pop("MAX_BODY_SIZE", None)
        # Filter only known fields
        known_fields = {f.name for f in cls.__dataclass_fields__.values()
                        if f.name != "MAX_BODY_SIZE"}
        filtered = {k: v for k, v in data.items() if k in known_fields}
        return cls(**filtered)

    @classmethod
    def from_json(cls, raw_json: str) -> Callback:
        """Deserialize from JSON string with error handling."""
        try:
            data = json.loads(raw_json)
            return cls.from_dict(data)
        except (json.JSONDecodeError, TypeError) as exc:
            # Return a minimal callback indicating parse failure
            return cls(
                callback_type=CallbackType.UNKNOWN.value,
                raw=raw_json[:1024] if raw_json else None,
                body=f"PARSE_ERROR: {exc}",
            )


@dataclass
class PayloadInfo:
    """
    Represents a registered OAST payload.

    Attributes:
        unique_id:   The unique identifier embedded in the callback URL/subdomain.
        task_id:     Task that owns this payload.
        scan_id:     Scan session identifier.
        vuln_type:   Vulnerability type (blind_xss, blind_ssrf, blind_sqli, etc.).
        subdomain:   Full subdomain (e.g., "s1-blind-xss-a3f2c1.oast.example.com").
        url:         Full callback URL.
        created_at:  ISO-8601 creation timestamp.
        ttl:         Time-to-live in seconds.
    """
    unique_id: str = ""
    task_id: str = ""
    scan_id: str = ""
    vuln_type: str = ""
    subdomain: str = ""
    url: str = ""
    created_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    ttl: int = 86400

    def is_expired(self) -> bool:
        """Check if payload has exceeded its TTL."""
        try:
            created = datetime.fromisoformat(self.created_at)
            if created.tzinfo is None:
                created = created.replace(tzinfo=timezone.utc)
            elapsed = (datetime.now(timezone.utc) - created).total_seconds()
            return elapsed > self.ttl
        except (ValueError, TypeError):
            # If we can't parse, treat as expired for safety
            return True

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), default=str)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> PayloadInfo:
        known_fields = {f.name for f in cls.__dataclass_fields__.values()}
        filtered = {k: v for k, v in data.items() if k in known_fields}
        # Ensure ttl is int
        if "ttl" in filtered:
            try:
                filtered["ttl"] = int(filtered["ttl"])
            except (ValueError, TypeError):
                filtered["ttl"] = 86400
        return cls(**filtered)

    @classmethod
    def from_json(cls, raw_json: str) -> PayloadInfo:
        try:
            data = json.loads(raw_json)
            return cls.from_dict(data)
        except (json.JSONDecodeError, TypeError):
            return cls()


@dataclass
class OASTFinding:
    """
    A confirmed blind vulnerability finding from OAST correlation.
    """
    finding_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    finding_type: str = ""  # e.g., "blind_xss", "blind_ssrf"
    severity: str = "HIGH"
    payload_url: str = ""
    callback: Dict[str, Any] = field(default_factory=dict)
    payload_info: Dict[str, Any] = field(default_factory=dict)
    detected_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# Severity mapping for different blind vuln types
VULN_SEVERITY_MAP: Dict[str, str] = {
    "blind_xss": "HIGH",
    "blind_ssrf": "CRITICAL",
    "blind_sqli": "CRITICAL",
    "blind_xxe": "HIGH",
    "blind_rce": "CRITICAL",
    "blind_ssti": "HIGH",
    "oob_dns": "MEDIUM",
    "oob_http": "MEDIUM",
}


def get_severity(vuln_type: str) -> str:
    """Get severity for a vulnerability type with fallback."""
    return VULN_SEVERITY_MAP.get(vuln_type.lower(), "MEDIUM")
