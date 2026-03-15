"""
Centaur-Jarvis Reporting Module
===============================

Generates comprehensive VAPT reports from completed task results stored in Redis.

Supports HTML (Jinja2), JSON, and plain text (CLI) output formats.

Usage (standalone):
    python -m modules.reporting.generator --scan-id SCAN_ID --output-dir ./reports

Usage (programmatic):
    from modules.reporting import ReportEngine, generate_report

    engine = ReportEngine()
    paths = engine.generate(scan_id="my-scan-001")

Public API:
    - ReportEngine: Main report generation class
    - generate_report: Convenience function for quick report generation
    - HTMLFormatter, JSONFormatter, TextFormatter: Individual formatters
"""

from modules.reporting.generator import ReportEngine, generate_report
from modules.reporting.formatters import HTMLFormatter, JSONFormatter, TextFormatter

__all__ = [
    "ReportEngine",
    "generate_report",
    "HTMLFormatter",
    "JSONFormatter",
    "TextFormatter",
]

__version__ = "1.0.0"
__module_name__ = "reporting"
