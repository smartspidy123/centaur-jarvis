"""
Centaur-Jarvis Reporting Module — Generator
=============================================

Main entry point for report generation. Handles:
  - Redis data collection and validation
  - Finding aggregation and normalization
  - Orchestrating formatter pipeline
  - CLI interface

CRITICAL ARCHITECTURE RULE compliance:
  - 360° edge-case handling (see edge case table in README)
  - No silent failures — every error logged with context
  - Plug-and-play — usable standalone or via orchestrator import
  - Comprehensive telemetry — timing, counts, error stats
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import traceback
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# YAML import
# ---------------------------------------------------------------------------
try:
    import yaml

    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False

# ---------------------------------------------------------------------------
# Redis import
# ---------------------------------------------------------------------------
try:
    import redis as redis_lib

    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False

# ---------------------------------------------------------------------------
# Logger — graceful fallback
# ---------------------------------------------------------------------------
try:
    from shared.logger import get_logger

    logger = get_logger("reporting.generator")
except ImportError:
    import logging

    logger = logging.getLogger("reporting.generator")
    if not logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(
            logging.Formatter("%(asctime)s [%(name)s] %(levelname)s — %(message)s")
        )
        logger.addHandler(handler)
        logger.setLevel(logging.DEBUG)

# ---------------------------------------------------------------------------
# Shared schemas — graceful fallback
# ---------------------------------------------------------------------------
try:
    from shared.schemas import TaskResult
    SCHEMAS_AVAILABLE = True
except ImportError:
    SCHEMAS_AVAILABLE = False

# ---------------------------------------------------------------------------
# Local imports
# ---------------------------------------------------------------------------
from modules.reporting.formatters import (
    BaseFormatter,
    HTMLFormatter,
    JSONFormatter,
    TextFormatter,
    ReportData,
)


# ===========================================================================
# Configuration Loader
# ===========================================================================

def load_config(config_path: Optional[str] = None) -> Dict[str, Any]:
    """
    Load configuration from YAML file with layered defaults.
    Falls back to hardcoded defaults if YAML unavailable or file missing.
    """
    defaults: Dict[str, Any] = {
        "output_dir": "reports/",
        "formats": ["html", "json", "text"],
        "templates_dir": str(Path(__file__).parent / "templates"),
        "include_raw_output": False,
        "severity_order": ["critical", "high", "medium", "low", "info", "unknown"],
        "redis": {
            "host": os.environ.get("REDIS_HOST", "localhost"),
            "port": int(os.environ.get("REDIS_PORT", 6379)),
            "db": int(os.environ.get("REDIS_DB", 0)),
            "socket_timeout": 5,
            "retry_on_timeout": True,
        },
        "html": {
            "max_findings_per_page": 500,
            "include_expandable_raw": True,
            "title_prefix": "Centaur-Jarvis VAPT Report",
        },
        "text": {
            "max_width": 120,
            "separator_char": "=",
            "finding_separator_char": "-",
        },
        "json": {"indent": 2, "sort_keys": True},
        "telemetry": {"log_timing": True, "log_stats": True},
    }

    if config_path is None:
        config_path = str(Path(__file__).parent / "config.yaml")

    if YAML_AVAILABLE and os.path.isfile(config_path):
        try:
            with open(config_path, "r", encoding="utf-8") as f:
                file_config = yaml.safe_load(f) or {}
            # Deep merge (1 level)
            for key, value in file_config.items():
                if isinstance(value, dict) and isinstance(defaults.get(key), dict):
                    defaults[key].update(value)
                else:
                    defaults[key] = value
            logger.info(f"Configuration loaded from: {config_path}")
        except Exception as e:
            logger.warning(
                f"Failed to load config from {config_path}: {e}. "
                f"Using defaults."
            )
    else:
        logger.info("Using hardcoded default configuration.")

    return defaults


# ===========================================================================
# Redis Data Collector
# ===========================================================================

class RedisDataCollector:
    """
    Collects and validates task results from Redis.
    Handles connection failures, malformed data, and missing metadata.
    """

    def __init__(self, redis_config: Dict[str, Any]):
        self._config = redis_config
        self._client: Optional[Any] = None
        self._connected = False

    def connect(self) -> bool:
        """Establish Redis connection with error handling."""
        if not REDIS_AVAILABLE:
            logger.error(
                "redis package not installed. "
                "Install with: pip install redis"
            )
            return False

        try:
            self._client = redis_lib.Redis(
                host=self._config.get("host", "localhost"),
                port=self._config.get("port", 6379),
                db=self._config.get("db", 0),
                socket_timeout=self._config.get("socket_timeout", 5),
                retry_on_timeout=self._config.get("retry_on_timeout", True),
                decode_responses=True,
            )
            self._client.ping()
            self._connected = True
            logger.info(
                f"Connected to Redis at "
                f"{self._config.get('host')}:{self._config.get('port')}"
            )
            return True
        except redis_lib.ConnectionError as e:
            logger.error(f"Redis connection failed: {e}")
            self._connected = False
            return False
        except Exception as e:
            logger.error(f"Unexpected Redis error: {e}")
            self._connected = False
            return False

    def collect(
        self,
        scan_id: Optional[str] = None,
        target: Optional[str] = None,
    ) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        """
        Collect task results and metadata from Redis.

        Returns:
            Tuple of (tasks_list, findings_list)
        """
        if not self._connected or self._client is None:
            logger.error("Redis not connected. Cannot collect data.")
            return [], []

        tasks: List[Dict[str, Any]] = []
        findings: List[Dict[str, Any]] = []
        skipped = 0
        errors = 0

        try:
            # Scan for result keys
            result_keys = list(self._client.scan_iter(match="task:*:result", count=500))
            logger.info(f"Found {len(result_keys)} result keys in Redis.")

            for rkey in result_keys:
                try:
                    task_id = self._extract_task_id(rkey)
                    if task_id is None:
                        skipped += 1
                        continue

                    # Fetch result data
                    raw_result = self._client.get(rkey)
                    if raw_result is None:
                        logger.debug(f"Empty result for key {rkey}, skipping.")
                        skipped += 1
                        continue

                    result_data = self._parse_json_safe(raw_result, rkey)
                    if result_data is None:
                        errors += 1
                        continue

                    # Fetch task metadata
                    task_meta = self._get_task_metadata(task_id)

                    # Filter by scan_id if specified
                    if scan_id:
                        task_scan_id = task_meta.get("scan_id", "")
                        result_scan_id = result_data.get("scan_id", "")
                        if scan_id not in (task_scan_id, result_scan_id):
                            continue

                    # Filter by target if specified
                    if target:
                        task_target = task_meta.get("target", "")
                        if target.lower() not in task_target.lower():
                            continue

                    # Build normalized task record
                    task_record = {
                        "task_id": task_id,
                        "type": task_meta.get("type", "unknown"),
                        "target": task_meta.get("target", "N/A"),
                        "state": task_meta.get("state", "unknown"),
                        "scan_id": task_meta.get("scan_id", ""),
                        "exit_code": result_data.get("exit_code"),
                        "started_at": task_meta.get("started_at", ""),
                        "completed_at": task_meta.get("completed_at", ""),
                        "stdout": result_data.get("stdout", ""),
                        "stderr": result_data.get("stderr", ""),
                    }
                    tasks.append(task_record)

                    # Extract findings
                    task_findings = self._extract_findings(
                        result_data, task_meta, task_id
                    )
                    findings.extend(task_findings)

                except Exception as e:
                    logger.error(
                        f"Error processing result key {rkey}: {e}\n"
                        f"{traceback.format_exc()}"
                    )
                    errors += 1

        except redis_lib.ConnectionError as e:
            logger.error(f"Redis connection lost during collection: {e}")
        except Exception as e:
            logger.error(f"Unexpected error during collection: {e}")

        logger.info(
            f"Collection complete: {len(tasks)} tasks, {len(findings)} findings, "
            f"{skipped} skipped, {errors} errors."
        )
        return tasks, findings

    def _extract_task_id(self, result_key: str) -> Optional[str]:
        """Extract task ID from a result key like 'task:abc-123:result'."""
        parts = result_key.split(":")
        if len(parts) >= 3 and parts[0] == "task" and parts[-1] == "result":
            return ":".join(parts[1:-1])
        logger.warning(f"Malformed result key: {result_key}")
        return None

    def _parse_json_safe(
        self, raw: str, context: str
    ) -> Optional[Dict[str, Any]]:
        """Parse JSON with error handling."""
        try:
            data = json.loads(raw)
            if isinstance(data, dict):
                return data
            logger.warning(
                f"Result for {context} is not a dict (type={type(data).__name__}). "
                f"Wrapping in dict."
            )
            return {"data": data}
        except (json.JSONDecodeError, TypeError) as e:
            logger.error(
                f"Malformed JSON in {context}: {e}. "
                f"First 200 chars: {str(raw)[:200]}"
            )
            return None

    def _get_task_metadata(self, task_id: str) -> Dict[str, Any]:
        """
        Fetch task metadata from Redis hash `task:{id}`.
        Returns defaults if missing.
        """
        defaults = {
            "type": "unknown",
            "target": "N/A",
            "state": "unknown",
            "scan_id": "",
            "started_at": "",
            "completed_at": "",
        }

        if self._client is None:
            return defaults

        try:
            meta = self._client.hgetall(f"task:{task_id}")
            if meta:
                defaults.update(meta)
            else:
                logger.debug(
                    f"No metadata hash for task:{task_id}. Using defaults."
                )
        except Exception as e:
            logger.warning(f"Error fetching metadata for task:{task_id}: {e}")

        return defaults

    def _extract_findings(
        self,
        result_data: Dict[str, Any],
        task_meta: Dict[str, Any],
        task_id: str,
    ) -> List[Dict[str, Any]]:
        """
        Extract and normalize findings from task result.
        Supports nuclei output and generic finding lists.
        """
        findings: List[Dict[str, Any]] = []
        task_type = task_meta.get("type", "unknown")
        target = task_meta.get("target", "N/A")

        # Path 1: explicit findings list in result_data.data.findings
        data_section = result_data.get("data", {})
        if isinstance(data_section, dict):
            raw_findings = data_section.get("findings", [])
        elif isinstance(data_section, list):
            raw_findings = data_section
        else:
            raw_findings = []

        # Path 2: top-level findings key
        if not raw_findings:
            raw_findings = result_data.get("findings", [])

        # Path 3: if nuclei, try to parse stdout lines as JSON
        if not raw_findings and task_type.lower() in ("nuclei", "vulnerability_scan"):
            stdout = result_data.get("stdout", "")
            raw_findings = self._parse_nuclei_stdout(stdout)

        for rf in raw_findings:
            if not isinstance(rf, dict):
                logger.debug(f"Skipping non-dict finding in task {task_id}")
                continue

            finding = {
                "task_id": task_id,
                "task_type": task_type,
                "target": target,
                "template_name": (
                    rf.get("template", "")
                    or rf.get("template_name", "")
                    or rf.get("template-id", "")
                    or rf.get("name", "N/A")
                ),
                "severity": str(
                    rf.get("severity", "")
                    or rf.get("info", {}).get("severity", "unknown")
                    if isinstance(rf.get("info"), dict)
                    else rf.get("severity", "unknown")
                ).lower().strip() or "unknown",
                "endpoint": (
                    rf.get("matched-at", "")
                    or rf.get("endpoint", "")
                    or rf.get("host", "")
                    or rf.get("url", "")
                    or target
                ),
                "description": (
                    rf.get("description", "")
                    or (
                        rf.get("info", {}).get("description", "")
                        if isinstance(rf.get("info"), dict)
                        else ""
                    )
                    or "No description available"
                ),
                "remediation": (
                    rf.get("remediation", "")
                    or (
                        rf.get("info", {}).get("remediation", "")
                        if isinstance(rf.get("info"), dict)
                        else ""
                    )
                    or "N/A"
                ),
                "curl_command": rf.get("curl-command", rf.get("curl_command", "N/A")),
                "matcher_name": rf.get("matcher-name", rf.get("matcher_name", "")),
                "extracted_results": rf.get("extracted-results", []),
                "raw_output": rf.get("raw", rf.get("raw_output", "")),
                "timestamp": rf.get("timestamp", ""),
            }
            findings.append(finding)

        return findings

    def _parse_nuclei_stdout(self, stdout: str) -> List[Dict[str, Any]]:
        """
        Attempt to parse nuclei JSONL output from stdout.
        Each line may be a JSON object representing a finding.
        """
        findings = []
        if not stdout:
            return findings

        for line in stdout.strip().splitlines():
            line = line.strip()
            if not line or not line.startswith("{"):
                continue
            try:
                obj = json.loads(line)
                if isinstance(obj, dict):
                    findings.append(obj)
            except json.JSONDecodeError:
                continue

        if findings:
            logger.debug(f"Parsed {len(findings)} findings from nuclei stdout.")
        return findings

    def close(self):
        """Close Redis connection cleanly."""
        if self._client is not None:
            try:
                self._client.close()
            except Exception:
                pass


# ===========================================================================
# Aggregation Engine
# ===========================================================================

class AggregationEngine:
    """
    Aggregates raw findings and tasks into summary statistics.
    """

    def __init__(self, severity_order: List[str]):
        self.severity_order = severity_order

    def aggregate(
        self,
        tasks: List[Dict[str, Any]],
        findings: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """Produce summary statistics."""

        severity_counts: Dict[str, int] = {s: 0 for s in self.severity_order}
        endpoints = set()

        for f in findings:
            sev = f.get("severity", "unknown").lower()
            if sev not in severity_counts:
                severity_counts["unknown"] = severity_counts.get("unknown", 0)
                sev = "unknown"
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
            ep = f.get("endpoint", "")
            if ep:
                endpoints.add(ep)

        completed = sum(
            1
            for t in tasks
            if str(t.get("state", "")).lower() in ("completed", "done", "success")
        )
        failed = sum(
            1
            for t in tasks
            if str(t.get("state", "")).lower() in ("failed", "error")
        )

        return {
            "total_tasks": len(tasks),
            "completed_tasks": completed,
            "failed_tasks": failed,
            "total_findings": len(findings),
            "unique_endpoints": len(endpoints),
            "severity_counts": severity_counts,
            "endpoints": sorted(endpoints),
        }

    def sort_findings(
        self, findings: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Sort findings by severity (most critical first)."""
        order_map = {s: i for i, s in enumerate(self.severity_order)}

        def sort_key(f: Dict[str, Any]) -> int:
            sev = f.get("severity", "unknown").lower()
            return order_map.get(sev, len(self.severity_order))

        return sorted(findings, key=sort_key)

    def deduplicate_findings(
        self, findings: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Remove duplicate findings based on (template_name, endpoint, severity)."""
        seen = set()
        deduped = []
        for f in findings:
            key = (
                f.get("template_name", ""),
                f.get("endpoint", ""),
                f.get("severity", ""),
            )
            if key not in seen:
                seen.add(key)
                deduped.append(f)
            else:
                logger.debug(f"Deduplicated finding: {key}")
        if len(deduped) < len(findings):
            logger.info(
                f"Deduplicated {len(findings) - len(deduped)} findings "
                f"({len(findings)} → {len(deduped)})."
            )
        return deduped


# ===========================================================================
# Report Engine (Main Orchestrator)
# ===========================================================================

class ReportEngine:
    """
    Main report generation engine.
    Ties together data collection, aggregation, and formatting.

    Usage:
        engine = ReportEngine()
        report_paths = engine.generate(scan_id="scan-001")

        # Or with pre-collected data:
        engine = ReportEngine()
        report_paths = engine.generate_from_data(tasks, findings, scan_id="scan-001")
    """

    def __init__(self, config_path: Optional[str] = None):
        self.config = load_config(config_path)
        self.severity_order = self.config.get(
            "severity_order",
            ["critical", "high", "medium", "low", "info", "unknown"],
        )
        self.aggregator = AggregationEngine(self.severity_order)
        self._formatters: Dict[str, BaseFormatter] = {}
        self._init_formatters()

    def _init_formatters(self):
        """Initialize formatters based on config."""
        html_cfg = self.config.get("html", {})
        self._formatters["html"] = HTMLFormatter(
            templates_dir=self.config.get("templates_dir"),
            max_findings_per_page=html_cfg.get("max_findings_per_page", 500),
            include_expandable_raw=html_cfg.get("include_expandable_raw", True),
            title_prefix=html_cfg.get(
                "title_prefix", "Centaur-Jarvis VAPT Report"
            ),
        )

        json_cfg = self.config.get("json", {})
        self._formatters["json"] = JSONFormatter(
            indent=json_cfg.get("indent", 2),
            sort_keys=json_cfg.get("sort_keys", True),
        )

        text_cfg = self.config.get("text", {})
        self._formatters["text"] = TextFormatter(
            max_width=text_cfg.get("max_width", 120),
            separator_char=text_cfg.get("separator_char", "="),
            finding_separator_char=text_cfg.get("finding_separator_char", "-"),
        )

    def generate(
        self,
        scan_id: Optional[str] = None,
        target: Optional[str] = None,
        output_dir: Optional[str] = None,
        formats: Optional[List[str]] = None,
    ) -> Dict[str, Path]:
        """
        Full pipeline: collect from Redis → aggregate → format → write.

        Returns:
            Dictionary mapping format name to output file Path.
        """
        total_start = time.monotonic()

        logger.info(
            f"Starting report generation "
            f"(scan_id={scan_id}, target={target})"
        )

        # 1. Collect data from Redis
        collector = RedisDataCollector(self.config.get("redis", {}))
        if not collector.connect():
            logger.error(
                "Cannot connect to Redis. Generating empty report."
            )
            tasks, findings = [], []
        else:
            tasks, findings = collector.collect(
                scan_id=scan_id, target=target
            )
            collector.close()

        return self.generate_from_data(
            tasks=tasks,
            findings=findings,
            scan_id=scan_id or "all",
            output_dir=output_dir,
            formats=formats,
            _start_time=total_start,
        )

    def generate_from_data(
        self,
        tasks: List[Dict[str, Any]],
        findings: List[Dict[str, Any]],
        scan_id: str = "manual",
        output_dir: Optional[str] = None,
        formats: Optional[List[str]] = None,
        _start_time: Optional[float] = None,
    ) -> Dict[str, Path]:
        """
        Generate reports from pre-collected data (no Redis needed).
        Useful when orchestrator already has the data.

        Returns:
            Dictionary mapping format name to output file Path.
        """
        start = _start_time or time.monotonic()

        # 2. Deduplicate and sort
        findings = self.aggregator.deduplicate_findings(findings)
        findings = self.aggregator.sort_findings(findings)

        # 3. Aggregate summary
        summary = self.aggregator.aggregate(tasks, findings)

        # 4. Build ReportData
        timestamp_str = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        report_data = ReportData(
            scan_id=scan_id,
            generated_at=timestamp_str,
            summary=summary,
            findings=findings,
            tasks=tasks,
            metadata={
                "generator": "centaur-jarvis-reporting",
                "version": "1.0.0",
            },
            include_raw_output=self.config.get("include_raw_output", False),
            severity_order=self.severity_order,
        )

        # 5. Determine output directory
        out_dir = Path(output_dir or self.config.get("output_dir", "reports/"))
        try:
            out_dir.mkdir(parents=True, exist_ok=True)
        except PermissionError:
            fallback = Path.cwd() / "reports"
            logger.warning(
                f"Cannot create {out_dir}. Falling back to {fallback}"
            )
            out_dir = fallback
            out_dir.mkdir(parents=True, exist_ok=True)

        # 6. Determine formats
        active_formats = formats or self.config.get(
            "formats", ["html", "json", "text"]
        )

        # 7. Generate each format
        ts_file = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        base_name = f"report_{scan_id}_{ts_file}"
        output_paths: Dict[str, Path] = {}

        ext_map = {"html": ".html", "json": ".json", "text": ".txt"}

        for fmt in active_formats:
            fmt_lower = fmt.lower()
            formatter = self._formatters.get(fmt_lower)
            if formatter is None:
                logger.warning(f"Unknown format '{fmt}'. Skipping.")
                continue

            try:
                content = formatter.format(report_data)
                ext = ext_map.get(fmt_lower, f".{fmt_lower}")
                filepath = out_dir / f"{base_name}{ext}"
                actual_path = formatter.write_to_file(content, filepath)
                output_paths[fmt_lower] = actual_path
            except Exception as e:
                logger.error(
                    f"Failed to generate {fmt_lower} report: {e}\n"
                    f"{traceback.format_exc()}"
                )

        elapsed = time.monotonic() - start
        logger.info(
            f"Report generation complete in {elapsed:.3f}s. "
            f"Files: {', '.join(str(p) for p in output_paths.values())}"
        )

        # 8. Print text report to stdout for CLI convenience
        if "text" in output_paths:
            try:
                text_content = output_paths["text"].read_text(encoding="utf-8")
                print(text_content)
            except Exception:
                pass

        return output_paths


# ===========================================================================
# Convenience Function
# ===========================================================================

def generate_report(
    scan_id: Optional[str] = None,
    target: Optional[str] = None,
    output_dir: Optional[str] = None,
    formats: Optional[List[str]] = None,
    config_path: Optional[str] = None,
) -> Dict[str, Path]:
    """
    Convenience function for quick report generation.

    Example:
        paths = generate_report(scan_id="scan-001", output_dir="./reports")
    """
    engine = ReportEngine(config_path=config_path)
    return engine.generate(
        scan_id=scan_id,
        target=target,
        output_dir=output_dir,
        formats=formats,
    )


# ===========================================================================
# CLI Entry Point
# ===========================================================================

def main():
    """CLI entry point for the reporting module."""
    parser = argparse.ArgumentParser(
        prog="centaur-jarvis-reporting",
        description="Generate VAPT reports from Centaur-Jarvis scan results.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Generate report for specific scan
  python -m modules.reporting.generator --scan-id SCAN-001

  # Generate only HTML report to custom directory
  python -m modules.reporting.generator --scan-id SCAN-001 --output-dir ./my-reports --formats html

  # Generate report for all scans
  python -m modules.reporting.generator --output-dir ./reports

  # Filter by target
  python -m modules.reporting.generator --target juice-shop.local
        """,
    )

    parser.add_argument(
        "--scan-id",
        type=str,
        default=None,
        help="Filter results by scan ID (optional).",
    )
    parser.add_argument(
        "--target",
        type=str,
        default=None,
        help="Filter results by target (substring match).",
    )
    parser.add_argument(
        "--output-dir",
        type=str,
        default=None,
        help="Output directory for reports (default: from config).",
    )
    parser.add_argument(
        "--formats",
        type=str,
        nargs="+",
        choices=["html", "json", "text"],
        default=None,
        help="Report formats to generate (default: all).",
    )
    parser.add_argument(
        "--config",
        type=str,
        default=None,
        help="Path to config.yaml (default: modules/reporting/config.yaml).",
    )
    parser.add_argument(
        "--include-raw",
        action="store_true",
        default=False,
        help="Include raw stdout/stderr in reports.",
    )

    args = parser.parse_args()

    try:
        engine = ReportEngine(config_path=args.config)

        if args.include_raw:
            engine.config["include_raw_output"] = True

        paths = engine.generate(
            scan_id=args.scan_id,
            target=args.target,
            output_dir=args.output_dir,
            formats=args.formats,
        )

        if paths:
            print(f"\n✅ Reports generated successfully:")
            for fmt, path in paths.items():
                print(f"   [{fmt.upper():>4s}] {path}")
        else:
            print("\n⚠️  No reports were generated. Check logs for errors.")
            sys.exit(1)

    except KeyboardInterrupt:
        print("\n\n❌ Report generation cancelled by user.")
        sys.exit(130)
    except Exception as e:
        logger.error(f"Fatal error in report generation: {e}\n{traceback.format_exc()}")
        print(f"\n❌ Report generation failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
