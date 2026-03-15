"""
modules/recon/parsers.py
========================
Deterministic output parsers for each recon tool.

Design Principles
-----------------
1. **Line-by-line streaming** — never load the full blob into memory.
2. **Graceful degradation** — malformed lines are skipped with a warning,
   they never crash the parse pass.
3. **Normalised output** — every parser returns a common envelope so that
   downstream modules (AI core, DB writer) don't need tool-specific logic.
4. **Regex fallback** — when a tool emits plain-text instead of JSON
   (e.g. subfinder without ``-oJ``), we still extract useful data.

Public API
----------
``get_parser(tool_name: str) -> BaseParser``
    Factory that returns the correct parser subclass.
"""

from __future__ import annotations

import abc
import ipaddress
import json
import re
from typing import Any, Dict, List, Optional, Tuple, Type

# ---------------------------------------------------------------------------
# Base Parser
# ---------------------------------------------------------------------------


class BaseParser(abc.ABC):
    """
    Abstract base class for all tool-output parsers.

    Subclasses MUST implement ``parse_line`` and ``normalize``.
    """

    def __init__(self) -> None:
        self.warnings: List[str] = []
        self.raw_line_count: int = 0
        self.parsed_records: List[Dict[str, Any]] = []
        self.failed_lines: int = 0

    # -- Template method -----------------------------------------------------

    def parse(self, raw_output: str) -> Dict[str, Any]:
        """
        Parse the *complete* stdout string emitted by a tool.

        Returns a normalised dict ready for ``TaskResult.data``.
        """
        self.warnings.clear()
        self.parsed_records.clear()
        self.raw_line_count = 0
        self.failed_lines = 0

        if not raw_output or not raw_output.strip():
            self.warnings.append("Tool produced empty output")
            return self.normalize()

        for line_no, line in enumerate(raw_output.splitlines(), start=1):
            self.raw_line_count += 1
            stripped = line.strip()
            if not stripped:
                continue
            try:
                record = self.parse_line(stripped)
                if record is not None:
                    self.parsed_records.append(record)
            except Exception as exc:  # noqa: BLE001
                self.failed_lines += 1
                self.warnings.append(
                    f"Line {line_no}: parse error — {exc!s:.200s}"
                )

        return self.normalize()

    @abc.abstractmethod
    def parse_line(self, line: str) -> Optional[Dict[str, Any]]:
        """Parse a single line; return a dict or ``None`` to skip."""
        ...

    @abc.abstractmethod
    def normalize(self) -> Dict[str, Any]:
        """Return the final normalised output envelope."""
        ...

    def get_metadata(self) -> Dict[str, Any]:
        """Common telemetry attached to every parser result."""
        return {
            "raw_lines": self.raw_line_count,
            "parsed_count": len(self.parsed_records),
            "failed_lines": self.failed_lines,
            "warnings": list(self.warnings),
        }


# ---------------------------------------------------------------------------
# Subfinder Parser
# ---------------------------------------------------------------------------

# Pre-compiled patterns for fallback
_DOMAIN_RE = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)"
    r"+[a-zA-Z]{2,63}$"
)


class SubfinderParser(BaseParser):
    """
    Parse ``subfinder -d <domain> -silent -oJ`` output.

    JSON line example::

        {"host":"sub.example.com","input":"example.com","source":"crtsh"}

    Fallback: plain-text lines containing one subdomain each.
    """

    def parse_line(self, line: str) -> Optional[Dict[str, Any]]:
        # Attempt JSON first
        if line.startswith("{"):
            try:
                obj = json.loads(line)
                host = obj.get("host", "").strip().lower()
                if not host:
                    self.warnings.append(f"JSON line missing 'host': {line[:120]}")
                    return None
                return {
                    "subdomain": host,
                    "source": obj.get("source", "unknown"),
                    "input": obj.get("input", ""),
                }
            except json.JSONDecodeError:
                pass  # fall through to regex

        # Regex fallback — plain-text subdomain
        candidate = line.strip().lower()
        if _DOMAIN_RE.match(candidate):
            return {
                "subdomain": candidate,
                "source": "text_fallback",
                "input": "",
            }

        self.warnings.append(f"Unrecognised line: {line[:120]}")
        return None

    def normalize(self) -> Dict[str, Any]:
        # De-duplicate while preserving order
        seen: set = set()
        unique: List[str] = []
        sources: Dict[str, List[str]] = {}
        for rec in self.parsed_records:
            sd = rec["subdomain"]
            if sd not in seen:
                seen.add(sd)
                unique.append(sd)
            sources.setdefault(rec["source"], []).append(sd)

        return {
            "subdomains": unique,
            "count": len(unique),
            "sources": {k: len(v) for k, v in sources.items()},
            "_meta": self.get_metadata(),
        }


# ---------------------------------------------------------------------------
# Httpx Parser
# ---------------------------------------------------------------------------


class HttpxParser(BaseParser):
    """
    Parse ``httpx -l <file> -silent -json`` output.

    Each JSON line contains rich probe data (status, title, tech, etc.).
    """

    def parse_line(self, line: str) -> Optional[Dict[str, Any]]:
        if not line.startswith("{"):
            # httpx occasionally emits progress/info lines
            return None
        try:
            obj = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"Invalid JSON: {exc}") from exc

        url = obj.get("url", obj.get("input", "")).strip()
        if not url:
            self.warnings.append(f"JSON line missing 'url': {line[:120]}")
            return None

        return {
            "url": url,
            "status_code": obj.get("status_code", obj.get("status-code")),
            "title": obj.get("title", ""),
            "webserver": obj.get("webserver", ""),
            "technologies": obj.get("tech", obj.get("technologies", [])),
            "content_length": obj.get("content_length", obj.get("content-length", 0)),
            "host": obj.get("host", ""),
            "ip": obj.get("a", obj.get("host_ip", [])),
            "cdn": obj.get("cdn", False),
            "tls": {
                "cipher": obj.get("tls", {}).get("cipher", "") if isinstance(obj.get("tls"), dict) else "",
                "version": obj.get("tls", {}).get("version", "") if isinstance(obj.get("tls"), dict) else "",
            },
            "response_time": obj.get("response_time", obj.get("time", "")),
            "method": obj.get("method", "GET"),
            "final_url": obj.get("final_url", url),
        }

    def normalize(self) -> Dict[str, Any]:
        urls: List[Dict[str, Any]] = []
        status_distribution: Dict[str, int] = {}
        tech_set: set = set()

        for rec in self.parsed_records:
            urls.append(rec)
            sc = str(rec.get("status_code", "unknown"))
            status_distribution[sc] = status_distribution.get(sc, 0) + 1
            for t in (rec.get("technologies") or []):
                tech_set.add(t)

        return {
            "urls": urls,
            "count": len(urls),
            "status_distribution": status_distribution,
            "unique_technologies": sorted(tech_set),
            "_meta": self.get_metadata(),
        }


# ---------------------------------------------------------------------------
# Nuclei Parser
# ---------------------------------------------------------------------------


class NucleiParser(BaseParser):
    """
    Parse ``nuclei -u <target> -json -silent`` output.

    Each JSON line is a finding / vulnerability hit.
    """

    # Severity ordering for downstream prioritisation
    _SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unknown": 5}

    def parse_line(self, line: str) -> Optional[Dict[str, Any]]:
        if not line.startswith("{"):
            return None
        try:
            obj = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"Invalid JSON: {exc}") from exc

        template_id = obj.get("template-id", obj.get("templateID", "unknown"))
        info = obj.get("info", {})
        severity = (info.get("severity", "unknown") if isinstance(info, dict) else "unknown").lower()

        return {
            "template_id": template_id,
            "template_name": info.get("name", "") if isinstance(info, dict) else "",
            "severity": severity,
            "severity_rank": self._SEV_ORDER.get(severity, 5),
            "type": obj.get("type", ""),
            "host": obj.get("host", ""),
            "matched_at": obj.get("matched-at", obj.get("matched_at", "")),
            "matcher_name": obj.get("matcher-name", obj.get("matcher_name", "")),
            "extracted_results": obj.get("extracted-results", []),
            "curl_command": obj.get("curl-command", ""),
            "tags": info.get("tags", []) if isinstance(info, dict) else [],
            "reference": info.get("reference", []) if isinstance(info, dict) else [],
            "description": info.get("description", "") if isinstance(info, dict) else "",
            "timestamp": obj.get("timestamp", ""),
        }

    def normalize(self) -> Dict[str, Any]:
        findings = sorted(self.parsed_records, key=lambda r: r.get("severity_rank", 5))
        severity_counts: Dict[str, int] = {}
        for f in findings:
            sev = f["severity"]
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        return {
            "findings": findings,
            "count": len(findings),
            "severity_counts": severity_counts,
            "unique_templates": list({f["template_id"] for f in findings}),
            "_meta": self.get_metadata(),
        }


# ---------------------------------------------------------------------------
# Naabu Parser
# ---------------------------------------------------------------------------


class NaabuParser(BaseParser):
    """
    Parse ``naabu -host <target> -silent -json`` output.

    JSON line example::

        {"host":"93.184.216.34","ip":"93.184.216.34","port":443,"protocol":"tcp"}
    """

    def parse_line(self, line: str) -> Optional[Dict[str, Any]]:
        # JSON attempt
        if line.startswith("{"):
            try:
                obj = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"Invalid JSON: {exc}") from exc

            port = obj.get("port")
            if port is None:
                self.warnings.append(f"JSON line missing 'port': {line[:120]}")
                return None

            return {
                "host": obj.get("host", ""),
                "ip": obj.get("ip", ""),
                "port": int(port),
                "protocol": obj.get("protocol", "tcp"),
            }

        # Plain text fallback — "host:port" or just "ip:port"
        match = re.match(r"^([\w.\-]+):(\d+)$", line)
        if match:
            return {
                "host": match.group(1),
                "ip": "",
                "port": int(match.group(2)),
                "protocol": "tcp",
            }

        self.warnings.append(f"Unrecognised line: {line[:120]}")
        return None

    def normalize(self) -> Dict[str, Any]:
        ports_by_host: Dict[str, List[int]] = {}
        all_ports: set = set()
        for rec in self.parsed_records:
            host = rec["host"] or rec["ip"]
            ports_by_host.setdefault(host, []).append(rec["port"])
            all_ports.add(rec["port"])

        return {
            "open_ports": sorted(all_ports),
            "count": len(all_ports),
            "hosts": {h: sorted(set(p)) for h, p in ports_by_host.items()},
            "details": self.parsed_records,
            "_meta": self.get_metadata(),
        }


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------

_PARSER_REGISTRY: Dict[str, Type[BaseParser]] = {
    "subfinder": SubfinderParser,
    "httpx": HttpxParser,
    "nuclei": NucleiParser,
    "naabu": NaabuParser,
    # Easy to extend: just add a new entry
}


def get_parser(tool_name: str) -> BaseParser:
    """
    Factory function — returns an instantiated parser for *tool_name*.

    Raises ``ValueError`` for unknown tools (no silent failures).
    """
    cls = _PARSER_REGISTRY.get(tool_name.lower())
    if cls is None:
        raise ValueError(
            f"No parser registered for tool '{tool_name}'. "
            f"Available: {list(_PARSER_REGISTRY.keys())}"
        )
    return cls()
