"""
Centaur-Jarvis Reporting Module — Formatters
=============================================

Provides HTML (Jinja2), JSON, and plain text formatters for report generation.
Each formatter implements a consistent interface and handles its own edge cases.

CRITICAL ARCHITECTURE RULE compliance:
  - 360° edge-case handling in every formatter
  - No silent failures — all errors logged with context
  - Plug-and-play — each formatter is independently usable
  - Comprehensive telemetry — timing and stats for each format operation
"""

from __future__ import annotations

import json
import html as html_module
import os
import time
import traceback
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

# ---------------------------------------------------------------------------
# Conditional imports with graceful degradation
# ---------------------------------------------------------------------------
try:
    import jinja2

    JINJA2_AVAILABLE = True
except ImportError:
    JINJA2_AVAILABLE = False

# ---------------------------------------------------------------------------
# Logger setup — graceful fallback if shared.logger unavailable
# ---------------------------------------------------------------------------
try:
    from shared.logger import get_logger

    logger = get_logger("reporting.formatters")
except ImportError:
    import logging

    logger = logging.getLogger("reporting.formatters")
    if not logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(
            logging.Formatter(
                "%(asctime)s [%(name)s] %(levelname)s — %(message)s"
            )
        )
        logger.addHandler(handler)
        logger.setLevel(logging.DEBUG)


# ===========================================================================
# Data Structures
# ===========================================================================

class ReportData:
    """
    Normalized container for all data needed by formatters.
    Decouples Redis data shapes from formatting logic.
    """

    def __init__(
        self,
        scan_id: str,
        generated_at: str,
        summary: Dict[str, Any],
        findings: List[Dict[str, Any]],
        tasks: List[Dict[str, Any]],
        metadata: Optional[Dict[str, Any]] = None,
        include_raw_output: bool = False,
        severity_order: Optional[List[str]] = None,
    ):
        self.scan_id = scan_id or "unknown"
        self.generated_at = generated_at or datetime.now(timezone.utc).isoformat()
        self.summary = summary or {}
        self.findings = findings or []
        self.tasks = tasks or []
        self.metadata = metadata or {}
        self.include_raw_output = include_raw_output
        self.severity_order = severity_order or [
            "critical", "high", "medium", "low", "info", "unknown"
        ]

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to dictionary for JSON export."""
        return {
            "scan_id": self.scan_id,
            "generated_at": self.generated_at,
            "summary": self.summary,
            "findings": self.findings,
            "tasks": self.tasks,
            "metadata": self.metadata,
        }


# ===========================================================================
# Abstract Base Formatter
# ===========================================================================

class BaseFormatter(ABC):
    """
    Abstract base for all report formatters.
    Enforces consistent interface and telemetry.
    """

    FORMAT_NAME: str = "base"

    @abstractmethod
    def format(self, data: ReportData) -> str:
        """Generate formatted report content as string."""
        ...

    def write_to_file(self, content: str, filepath: Path) -> Path:
        """
        Write content to file with comprehensive error handling.

        Returns:
            The Path where the file was actually written (may differ from
            `filepath` if we had to fall back to current directory).
        """
        actual_path = filepath
        try:
            filepath.parent.mkdir(parents=True, exist_ok=True)
            filepath.write_text(content, encoding="utf-8")
            logger.info(
                f"[{self.FORMAT_NAME}] Report written to: {filepath} "
                f"({len(content)} bytes)"
            )
        except PermissionError:
            # EDGE CASE: output dir not writable → fallback to CWD
            fallback = Path.cwd() / filepath.name
            logger.warning(
                f"[{self.FORMAT_NAME}] Permission denied writing to {filepath}. "
                f"Falling back to: {fallback}"
            )
            try:
                fallback.write_text(content, encoding="utf-8")
                actual_path = fallback
            except Exception as e2:
                logger.error(
                    f"[{self.FORMAT_NAME}] Fallback write also failed: {e2}"
                )
                raise
        except OSError as e:
            logger.error(
                f"[{self.FORMAT_NAME}] OS error writing report: {e}"
            )
            raise

        return actual_path


# ===========================================================================
# HTML Formatter
# ===========================================================================

class HTMLFormatter(BaseFormatter):
    """
    Generates styled HTML reports using Jinja2 templates.
    Falls back to hardcoded HTML if template is missing or Jinja2 unavailable.
    """

    FORMAT_NAME = "html"

    def __init__(
        self,
        templates_dir: Optional[str] = None,
        max_findings_per_page: int = 500,
        include_expandable_raw: bool = True,
        title_prefix: str = "Centaur-Jarvis VAPT Report",
    ):
        self.templates_dir = templates_dir
        self.max_findings_per_page = max_findings_per_page
        self.include_expandable_raw = include_expandable_raw
        self.title_prefix = title_prefix

    def format(self, data: ReportData) -> str:
        """Generate HTML report."""
        start = time.monotonic()

        # Truncate findings for pagination
        total_findings = len(data.findings)
        display_findings = data.findings[: self.max_findings_per_page]
        truncated = total_findings > self.max_findings_per_page

        try:
            content = self._render_with_jinja2(
                data, display_findings, truncated, total_findings
            )
        except Exception as e:
            logger.warning(
                f"[html] Jinja2 rendering failed ({e}), using fallback HTML."
            )
            content = self._render_fallback(
                data, display_findings, truncated, total_findings
            )

        elapsed = time.monotonic() - start
        logger.info(
            f"[html] Report generated in {elapsed:.3f}s "
            f"({total_findings} findings, {'truncated' if truncated else 'complete'})"
        )
        return content

    def _render_with_jinja2(
        self,
        data: ReportData,
        display_findings: List[Dict],
        truncated: bool,
        total_findings: int,
    ) -> str:
        """Attempt Jinja2 template rendering."""
        if not JINJA2_AVAILABLE:
            raise RuntimeError("Jinja2 not installed")

        template_path = None
        if self.templates_dir:
            candidate = Path(self.templates_dir) / "report.html.j2"
            if candidate.is_file():
                template_path = candidate

        if template_path is None:
            # Try default location relative to this file
            default = Path(__file__).parent / "templates" / "report.html.j2"
            if default.is_file():
                template_path = default

        if template_path is None:
            raise FileNotFoundError("No Jinja2 template found")

        loader = jinja2.FileSystemLoader(str(template_path.parent))
        env = jinja2.Environment(
            loader=loader,
            autoescape=jinja2.select_autoescape(["html"]),
        )
        # Register custom filters
        env.filters["severity_badge"] = self._severity_badge_class
        template = env.get_template(template_path.name)

        return template.render(
            title=f"{self.title_prefix} — {data.scan_id}",
            scan_id=data.scan_id,
            generated_at=data.generated_at,
            summary=data.summary,
            findings=display_findings,
            tasks=data.tasks,
            truncated=truncated,
            total_findings=total_findings,
            displayed_count=len(display_findings),
            include_raw=data.include_raw_output and self.include_expandable_raw,
            severity_order=data.severity_order,
        )

    def _render_fallback(
        self,
        data: ReportData,
        display_findings: List[Dict],
        truncated: bool,
        total_findings: int,
    ) -> str:
        """Hardcoded fallback HTML — no Jinja2 dependency."""
        esc = html_module.escape

        severity_counts = data.summary.get("severity_counts", {})
        sev_rows = "".join(
            f"<tr><td><span class='badge {s}'>{esc(s.upper())}</span></td>"
            f"<td>{severity_counts.get(s, 0)}</td></tr>"
            for s in data.severity_order
        )

        finding_rows = []
        for i, f in enumerate(display_findings, 1):
            raw_section = ""
            if data.include_raw_output and self.include_expandable_raw:
                raw = esc(str(f.get("raw_output", "")))
                raw_section = (
                    f"<details><summary>Raw Output</summary>"
                    f"<pre>{raw}</pre></details>"
                )
            curl_cmd = esc(str(f.get("curl_command", "N/A")))
            finding_rows.append(
                f"<tr>"
                f"<td>{i}</td>"
                f"<td><span class='badge {esc(str(f.get('severity', 'unknown')))}'>"
                f"{esc(str(f.get('severity', 'unknown')).upper())}</span></td>"
                f"<td>{esc(str(f.get('template_name', 'N/A')))}</td>"
                f"<td>{esc(str(f.get('endpoint', 'N/A')))}</td>"
                f"<td>{esc(str(f.get('description', 'N/A')))}</td>"
                f"<td>{esc(str(f.get('remediation', 'N/A')))}</td>"
                f"<td><code>{curl_cmd}</code></td>"
                f"<td>{raw_section}</td>"
                f"</tr>"
            )
        findings_html = "\n".join(finding_rows)

        trunc_notice = ""
        if truncated:
            trunc_notice = (
                f"<div class='warning'>⚠ Showing {len(display_findings)} of "
                f"{total_findings} findings. Export JSON for full data.</div>"
            )

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{esc(self.title_prefix)} — {esc(data.scan_id)}</title>
<style>
  :root {{
    --critical: #dc3545; --high: #fd7e14; --medium: #ffc107;
    --low: #28a745; --info: #17a2b8; --unknown: #6c757d;
  }}
  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  body {{ font-family: 'Segoe UI', Tahoma, sans-serif; background: #f4f6f9;
         color: #333; padding: 20px; }}
  .container {{ max-width: 1400px; margin: 0 auto; }}
  h1 {{ color: #1a1a2e; margin-bottom: 5px; }}
  h2 {{ color: #16213e; margin: 25px 0 10px; border-bottom: 2px solid #0f3460;
       padding-bottom: 5px; }}
  .meta {{ color: #666; margin-bottom: 20px; }}
  .summary-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                   gap: 15px; margin: 15px 0; }}
  .summary-card {{ background: white; padding: 20px; border-radius: 8px;
                   box-shadow: 0 2px 4px rgba(0,0,0,0.1); text-align: center; }}
  .summary-card .number {{ font-size: 2em; font-weight: bold; color: #0f3460; }}
  .summary-card .label {{ color: #666; margin-top: 5px; }}
  table {{ width: 100%; border-collapse: collapse; background: white;
           border-radius: 8px; overflow: hidden;
           box-shadow: 0 2px 4px rgba(0,0,0,0.1); margin: 10px 0; }}
  th {{ background: #1a1a2e; color: white; padding: 12px 8px; text-align: left;
       font-size: 0.85em; }}
  td {{ padding: 10px 8px; border-bottom: 1px solid #eee; font-size: 0.85em;
       vertical-align: top; word-break: break-word; }}
  tr:hover {{ background: #f8f9fa; }}
  .badge {{ padding: 3px 10px; border-radius: 12px; color: white;
            font-size: 0.75em; font-weight: bold; text-transform: uppercase; }}
  .badge.critical {{ background: var(--critical); }}
  .badge.high {{ background: var(--high); }}
  .badge.medium {{ background: var(--medium); color: #333; }}
  .badge.low {{ background: var(--low); }}
  .badge.info {{ background: var(--info); }}
  .badge.unknown {{ background: var(--unknown); }}
  code {{ background: #f1f3f5; padding: 2px 6px; border-radius: 3px;
          font-size: 0.8em; word-break: break-all; }}
  details {{ margin-top: 5px; }}
  details pre {{ background: #2d2d2d; color: #f8f8f2; padding: 10px;
                 border-radius: 4px; overflow-x: auto; font-size: 0.75em;
                 max-height: 200px; }}
  .warning {{ background: #fff3cd; border: 1px solid #ffc107; padding: 10px;
              border-radius: 5px; margin: 10px 0; }}
  .empty-state {{ text-align: center; padding: 40px; color: #999; }}
  footer {{ margin-top: 30px; text-align: center; color: #999; font-size: 0.8em; }}
</style>
</head>
<body>
<div class="container">
  <h1>🛡️ {esc(self.title_prefix)}</h1>
  <p class="meta">Scan ID: <strong>{esc(data.scan_id)}</strong> |
     Generated: <strong>{esc(data.generated_at)}</strong></p>

  <h2>📊 Summary</h2>
  <div class="summary-grid">
    <div class="summary-card">
      <div class="number">{data.summary.get('total_tasks', 0)}</div>
      <div class="label">Total Tasks</div>
    </div>
    <div class="summary-card">
      <div class="number">{data.summary.get('completed_tasks', 0)}</div>
      <div class="label">Completed</div>
    </div>
    <div class="summary-card">
      <div class="number">{data.summary.get('failed_tasks', 0)}</div>
      <div class="label">Failed</div>
    </div>
    <div class="summary-card">
      <div class="number">{total_findings}</div>
      <div class="label">Total Findings</div>
    </div>
    <div class="summary-card">
      <div class="number">{data.summary.get('unique_endpoints', 0)}</div>
      <div class="label">Unique Endpoints</div>
    </div>
  </div>

  <h2>🔴 Severity Breakdown</h2>
  <table>
    <thead><tr><th>Severity</th><th>Count</th></tr></thead>
    <tbody>{sev_rows}</tbody>
  </table>

  <h2>🔍 Findings</h2>
  {trunc_notice}
  {"<p class='empty-state'>No findings detected. Target appears clean.</p>"
   if not display_findings else f'''
  <table>
    <thead>
      <tr>
        <th>#</th><th>Severity</th><th>Template</th><th>Endpoint</th>
        <th>Description</th><th>Remediation</th><th>cURL</th><th>Raw</th>
      </tr>
    </thead>
    <tbody>
      {findings_html}
    </tbody>
  </table>'''}

  <footer>
    <p>Generated by Centaur-Jarvis Reporting Module v1.0.0 |
       {esc(data.generated_at)}</p>
  </footer>
</div>
</body>
</html>"""

    @staticmethod
    def _severity_badge_class(severity: str) -> str:
        """Map severity to CSS class name."""
        valid = {"critical", "high", "medium", "low", "info"}
        s = str(severity).lower().strip()
        return s if s in valid else "unknown"


# ===========================================================================
# JSON Formatter
# ===========================================================================

class JSONFormatter(BaseFormatter):
    """
    Produces structured JSON output for machine consumption.
    """

    FORMAT_NAME = "json"

    def __init__(self, indent: int = 2, sort_keys: bool = True):
        self.indent = indent
        self.sort_keys = sort_keys

    def format(self, data: ReportData) -> str:
        """Generate JSON report string."""
        start = time.monotonic()

        output = {
            "report_version": "1.0.0",
            "generator": "centaur-jarvis-reporting",
            "scan_id": data.scan_id,
            "generated_at": data.generated_at,
            "summary": data.summary,
            "findings": data.findings,
            "tasks": data.tasks,
            "metadata": data.metadata,
        }

        try:
            content = json.dumps(
                output,
                indent=self.indent,
                sort_keys=self.sort_keys,
                default=str,  # handles datetime, bytes, etc.
                ensure_ascii=False,
            )
        except (TypeError, ValueError) as e:
            logger.error(f"[json] Serialization error: {e}")
            # Fallback: force-stringify everything
            sanitized = json.loads(json.dumps(output, default=str))
            content = json.dumps(
                sanitized, indent=self.indent, sort_keys=self.sort_keys
            )

        elapsed = time.monotonic() - start
        logger.info(
            f"[json] Report generated in {elapsed:.3f}s "
            f"({len(data.findings)} findings, {len(content)} bytes)"
        )
        return content


# ===========================================================================
# Text Formatter
# ===========================================================================

class TextFormatter(BaseFormatter):
    """
    Produces plain text reports suitable for terminal/CLI display.
    """

    FORMAT_NAME = "text"

    def __init__(
        self,
        max_width: int = 120,
        separator_char: str = "=",
        finding_separator_char: str = "-",
    ):
        self.max_width = max_width
        self.sep = separator_char
        self.fsep = finding_separator_char

    def format(self, data: ReportData) -> str:
        """Generate plain text report."""
        start = time.monotonic()
        lines: List[str] = []
        w = self.max_width

        # Header
        lines.append(self.sep * w)
        lines.append(
            f"  CENTAUR-JARVIS VAPT REPORT".center(w)
        )
        lines.append(self.sep * w)
        lines.append(f"  Scan ID      : {data.scan_id}")
        lines.append(f"  Generated At : {data.generated_at}")
        lines.append(self.sep * w)

        # Summary
        lines.append("")
        lines.append("  SUMMARY")
        lines.append(f"  {self.fsep * (w - 4)}")
        s = data.summary
        lines.append(f"  Total Tasks      : {s.get('total_tasks', 0)}")
        lines.append(f"  Completed        : {s.get('completed_tasks', 0)}")
        lines.append(f"  Failed           : {s.get('failed_tasks', 0)}")
        lines.append(f"  Total Findings   : {s.get('total_findings', 0)}")
        lines.append(f"  Unique Endpoints : {s.get('unique_endpoints', 0)}")
        lines.append("")

        # Severity breakdown
        lines.append("  SEVERITY BREAKDOWN")
        lines.append(f"  {self.fsep * (w - 4)}")
        sev_counts = s.get("severity_counts", {})
        for sev in data.severity_order:
            count = sev_counts.get(sev, 0)
            bar = "█" * min(count, 50)
            lines.append(f"  {sev.upper():>10s} : {count:>4d}  {bar}")
        lines.append("")

        # Findings
        lines.append(self.sep * w)
        lines.append("  DETAILED FINDINGS")
        lines.append(self.sep * w)

        if not data.findings:
            lines.append("")
            lines.append(
                "  ✅ No findings detected. Target appears clean.".center(w)
            )
            lines.append("")
        else:
            for i, f in enumerate(data.findings, 1):
                lines.append(f"  {self.fsep * (w - 4)}")
                lines.append(f"  [{i}] {f.get('template_name', 'N/A')}")
                lines.append(
                    f"      Severity    : {str(f.get('severity', 'unknown')).upper()}"
                )
                lines.append(f"      Endpoint    : {f.get('endpoint', 'N/A')}")
                lines.append(
                    f"      Description : {f.get('description', 'N/A')}"
                )
                lines.append(
                    f"      Remediation : {f.get('remediation', 'N/A')}"
                )
                curl = f.get("curl_command", "N/A")
                lines.append(f"      cURL        : {curl}")
                if data.include_raw_output:
                    raw = str(f.get("raw_output", ""))
                    if raw:
                        lines.append(f"      Raw Output  :")
                        for rline in raw.splitlines()[:20]:
                            lines.append(f"        {rline}")
                        if len(raw.splitlines()) > 20:
                            lines.append("        ... (truncated)")

        lines.append("")
        lines.append(self.sep * w)
        lines.append(
            f"  Report generated by Centaur-Jarvis v1.0.0 | {data.generated_at}"
        )
        lines.append(self.sep * w)

        content = "\n".join(lines)
        elapsed = time.monotonic() - start
        logger.info(
            f"[text] Report generated in {elapsed:.3f}s "
            f"({len(data.findings)} findings)"
        )
        return content
