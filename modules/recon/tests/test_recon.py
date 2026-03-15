"""
modules/recon/tests/test_recon.py
=================================
Unit tests for parsers and task validation logic.

Run with:  pytest modules/recon/tests/ -v
"""

import json
import pytest
from modules.recon.parsers import (
    SubfinderParser,
    HttpxParser,
    NucleiParser,
    NaabuParser,
    get_parser,
)
from modules.recon.tasks import _validate_target, TaskExecResult


# ── Parser: Subfinder ──────────────────────────────────────────────────────


class TestSubfinderParser:
    def test_json_lines(self):
        raw = (
            '{"host":"a.example.com","input":"example.com","source":"crtsh"}\n'
            '{"host":"b.example.com","input":"example.com","source":"virustotal"}\n'
        )
        parser = SubfinderParser()
        result = parser.parse(raw)
        assert result["count"] == 2
        assert "a.example.com" in result["subdomains"]
        assert "b.example.com" in result["subdomains"]
        assert result["sources"]["crtsh"] == 1

    def test_plain_text_fallback(self):
        raw = "sub1.example.com\nsub2.example.com\n"
        parser = SubfinderParser()
        result = parser.parse(raw)
        assert result["count"] == 2
        assert all(s in result["subdomains"] for s in ["sub1.example.com", "sub2.example.com"])

    def test_deduplication(self):
        raw = (
            '{"host":"dup.example.com","source":"a"}\n'
            '{"host":"dup.example.com","source":"b"}\n'
        )
        parser = SubfinderParser()
        result = parser.parse(raw)
        assert result["count"] == 1

    def test_empty_output(self):
        parser = SubfinderParser()
        result = parser.parse("")
        assert result["count"] == 0
        assert "Tool produced empty output" in result["_meta"]["warnings"]

    def test_malformed_json_line(self):
        raw = '{"host":"good.example.com"}\n{bad json}\n'
        parser = SubfinderParser()
        result = parser.parse(raw)
        assert result["count"] == 1
        assert result["_meta"]["failed_lines"] == 1


# ── Parser: Httpx ──────────────────────────────────────────────────────────


class TestHttpxParser:
    def test_json_lines(self):
        raw = json.dumps({
            "url": "https://example.com",
            "status_code": 200,
            "title": "Example",
            "tech": ["Nginx"],
        }) + "\n"
        parser = HttpxParser()
        result = parser.parse(raw)
        assert result["count"] == 1
        assert result["urls"][0]["status_code"] == 200
        assert "Nginx" in result["unique_technologies"]

    def test_status_distribution(self):
        lines = []
        for sc in [200, 200, 301, 404]:
            lines.append(json.dumps({"url": f"https://{sc}.example.com", "status_code": sc}))
        raw = "\n".join(lines) + "\n"
        parser = HttpxParser()
        result = parser.parse(raw)
        assert result["status_distribution"]["200"] == 2
        assert result["status_distribution"]["404"] == 1


# ── Parser: Nuclei ─────────────────────────────────────────────────────────


class TestNucleiParser:
    def test_finding(self):
        finding = {
            "template-id": "cve-2021-44228",
            "info": {
                "name": "Log4j RCE",
                "severity": "critical",
                "tags": ["cve", "rce"],
                "reference": ["https://nvd.nist.gov/..."],
                "description": "Remote code execution in Log4j",
            },
            "type": "http",
            "host": "https://example.com",
            "matched-at": "https://example.com/api",
        }
        raw = json.dumps(finding) + "\n"
        parser = NucleiParser()
        result = parser.parse(raw)
        assert result["count"] == 1
        assert result["severity_counts"]["critical"] == 1
        assert result["findings"][0]["template_id"] == "cve-2021-44228"

    def test_sorting_by_severity(self):
        lines = []
        for sev in ["low", "critical", "medium"]:
            lines.append(json.dumps({
                "template-id": f"test-{sev}",
                "info": {"severity": sev, "name": f"Test {sev}"},
            }))
        raw = "\n".join(lines) + "\n"
        parser = NucleiParser()
        result = parser.parse(raw)
        severities = [f["severity"] for f in result["findings"]]
        assert severities == ["critical", "medium", "low"]


# ── Parser: Naabu ──────────────────────────────────────────────────────────


class TestNaabuParser:
    def test_json_lines(self):
        raw = (
            '{"host":"example.com","ip":"93.184.216.34","port":80,"protocol":"tcp"}\n'
            '{"host":"example.com","ip":"93.184.216.34","port":443,"protocol":"tcp"}\n'
        )
        parser = NaabuParser()
        result = parser.parse(raw)
        assert result["count"] == 2
        assert 80 in result["open_ports"]
        assert 443 in result["open_ports"]

    def test_plain_text_fallback(self):
        raw = "example.com:80\nexample.com:443\n"
        parser = NaabuParser()
        result = parser.parse(raw)
        assert result["count"] == 2

    def test_hosts_grouping(self):
        raw = (
            '{"host":"a.com","ip":"1.2.3.4","port":80}\n'
            '{"host":"b.com","ip":"5.6.7.8","port":443}\n'
        )
        parser = NaabuParser()
        result = parser.parse(raw)
        assert "a.com" in result["hosts"]
        assert "b.com" in result["hosts"]


# ── Parser Factory ─────────────────────────────────────────────────────────


class TestParserFactory:
    def test_valid_tools(self):
        for name in ["subfinder", "httpx", "nuclei", "naabu"]:
            p = get_parser(name)
            assert p is not None

    def test_unknown_tool_raises(self):
        with pytest.raises(ValueError, match="No parser registered"):
            get_parser("nonexistent_tool")


# ── Target Validation ─────────────────────────────────────────────────────


class TestTargetValidation:
    def test_valid_targets(self):
        for t in ["example.com", "sub.example.com", "192.168.1.1", "10.0.0.1:8080"]:
            assert _validate_target(t) is None

    def test_empty_target(self):
        assert _validate_target("") is not None

    def test_shell_injection(self):
        assert _validate_target("example.com; rm -rf /") is not None
        assert _validate_target("example.com && cat /etc/passwd") is not None
        assert _validate_target("$(whoami).evil.com") is not None

    def test_too_long(self):
        assert _validate_target("a" * 300) is not None
