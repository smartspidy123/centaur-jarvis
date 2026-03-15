#!/usr/bin/env python3
"""
renderer.py – Playwright Renderer worker for Centaur‑Jarvis.

Consumes tasks from Redis queue ``queue:playwright``, launches
``intercept.py`` as a subprocess, parses JSON‑line output, and
pushes structured results to ``results:incoming``.

Can be started directly:
    python -m modules.playwright_rend.renderer

Or imported and instantiated:
    from modules.playwright_rend.renderer import PlaywrightWorker
    worker = PlaywrightWorker()
    worker.run()
"""

from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import time
import uuid
from pathlib import Path
from typing import Any, Deque, Dict, List, Optional

import yaml

# ---------------------------------------------------------------------------
# Shared imports — with fallback
# ---------------------------------------------------------------------------

try:
    from shared.logger import get_logger
except ImportError:
    import logging
    import json as _json

    class _FallbackLogger:
        """Minimal JSON logger when shared.logger is unavailable."""

        def __init__(self, name: str = "playwright_rend"):
            self._logger = logging.getLogger(name)
            if not self._logger.handlers:
                handler = logging.StreamHandler(sys.stderr)
                handler.setFormatter(logging.Formatter("%(message)s"))
                self._logger.addHandler(handler)
                self._logger.setLevel(logging.DEBUG)

        def _log(self, level: str, msg: str, **kw: Any) -> None:
            payload = {"level": level, "module": "playwright_rend", "msg": msg, "ts": time.time()}
            payload.update(kw)
            self._logger.log(
                getattr(logging, level, logging.INFO),
                _json.dumps(payload, default=str),
            )

        def info(self, msg: str, **kw: Any) -> None:
            self._log("INFO", msg, **kw)

        def warning(self, msg: str, **kw: Any) -> None:
            self._log("WARNING", msg, **kw)

        def error(self, msg: str, **kw: Any) -> None:
            self._log("ERROR", msg, **kw)

        def debug(self, msg: str, **kw: Any) -> None:
            self._log("DEBUG", msg, **kw)

        def critical(self, msg: str, **kw: Any) -> None:
            self._log("CRITICAL", msg, **kw)

    def get_logger(name: str = "playwright_rend") -> _FallbackLogger:  # type: ignore[misc]
        return _FallbackLogger(name)

try:
    from shared.schemas import Task, TaskResult, TaskStatus  # noqa: F401
except ImportError:
    # Provide lightweight stand‑ins so the module remains independently runnable
    class TaskStatus:  # type: ignore[no-redef]
        PENDING = "PENDING"
        PROCESSING = "PROCESSING"
        COMPLETED = "COMPLETED"
        FAILED = "FAILED"
        TIMEOUT = "TIMEOUT"

try:
    import redis as redis_lib
except ImportError:
    redis_lib = None  # type: ignore[assignment]

from collections import deque

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

MODULE_DIR = Path(__file__).resolve().parent
INTERCEPT_SCRIPT = MODULE_DIR / "intercept.py"
DEFAULT_CONFIG = MODULE_DIR / "config.yaml"

logger = get_logger("playwright_rend")

# ---------------------------------------------------------------------------
# Configuration loader
# ---------------------------------------------------------------------------


def load_config(path: Optional[Path] = None) -> Dict[str, Any]:
    """Load config.yaml with sane defaults."""
    cfg_path = path or DEFAULT_CONFIG
    defaults: Dict[str, Any] = {
        "redis": {
            "task_queue": "queue:playwright",
            "result_queue": "results:incoming",
            "status_prefix": "task:status:",
            "host": "127.0.0.1",
            "port": 6379,
            "db": 0,
            "socket_timeout": 5,
            "retry_interval": 5,
            "max_buffer": 100,
        },
        "browser": {
            "headless": True,
            "timeout": 30000,
            "viewport": {"width": 1280, "height": 800},
            "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "launch_args": ["--disable-dev-shm-usage", "--no-sandbox"],
            "extra_http_headers": {},
        },
        "extraction": {
            "intercept_xhr": True,
            "intercept_fetch": True,
            "extract_forms": True,
            "max_response_body": 10240,
            "max_requests": 500,
            "depth": 1,
            "max_redirects": 10,
        },
        "worker": {
            "poll_interval": 1,
            "subprocess_extra_timeout": 15,
        },
    }

    if cfg_path.exists():
        try:
            with open(cfg_path, "r") as fh:
                file_cfg = yaml.safe_load(fh) or {}
            # Deep‑merge (one level)
            for section, values in file_cfg.items():
                if isinstance(values, dict) and section in defaults:
                    defaults[section].update(values)
                else:
                    defaults[section] = values
        except Exception as exc:
            logger.warning("Failed to load config file, using defaults", error=str(exc))

    return defaults


# ---------------------------------------------------------------------------
# Redis helper
# ---------------------------------------------------------------------------


class RedisClient:
    """Thin wrapper with auto‑reconnect and buffering."""

    def __init__(self, cfg: Dict[str, Any]):
        self._cfg = cfg
        self._conn: Optional[Any] = None
        self._buffer: Deque[Dict[str, Any]] = deque(maxlen=cfg.get("max_buffer", 100))

    def _connect(self) -> Any:
        if redis_lib is None:
            raise RuntimeError("redis package not installed")
        conn = redis_lib.Redis(
            host=self._cfg.get("host", "127.0.0.1"),
            port=int(self._cfg.get("port", 6379)),
            db=int(self._cfg.get("db", 0)),
            socket_timeout=int(self._cfg.get("socket_timeout", 5)),
            socket_connect_timeout=int(self._cfg.get("socket_timeout", 5)),
            decode_responses=True,
        )
        conn.ping()
        return conn

    @property
    def conn(self) -> Any:
        if self._conn is None:
            self._conn = self._connect()
        return self._conn

    def reconnect(self) -> bool:
        try:
            self._conn = self._connect()
            logger.info("Redis reconnected")
            return True
        except Exception as exc:
            logger.warning("Redis reconnect failed", error=str(exc))
            self._conn = None
            return False

    # ---- Queue operations -------------------------------------------------

    def pop_task(self, queue: str, timeout: int = 1) -> Optional[Dict[str, Any]]:
        try:
            result = self.conn.brpop(queue, timeout=timeout)
            if result is None:
                return None
            _, raw = result
            return json.loads(raw)
        except (json.JSONDecodeError, TypeError) as je:
            logger.error("Malformed task JSON on queue", error=str(je))
            return None
        except Exception as exc:
            logger.error("Redis pop_task error", error=str(exc))
            self._conn = None
            return None

    def set_status(self, task_id: str, status: str, prefix: str = "task:status:") -> None:
        try:
            self.conn.hset(f"task:{task_id}", "status", status)
            # Also set in the status‑prefix key for backward compat
            self.conn.set(f"{prefix}{task_id}", status, ex=86400)
        except Exception as exc:
            logger.warning("Failed to set status in Redis", task_id=task_id, error=str(exc))
            self._conn = None

    def push_result(self, queue: str, payload: Dict[str, Any]) -> bool:
        try:
            self.conn.lpush(queue, json.dumps(payload, default=str))
            return True
        except Exception as exc:
            logger.warning("Failed to push result, buffering", error=str(exc))
            self._conn = None
            self._buffer.append(payload)
            return False

    def flush_buffer(self, queue: str) -> None:
        """Try to push any buffered results."""
        if not self._buffer:
            return
        flushed = 0
        while self._buffer:
            payload = self._buffer[0]
            try:
                self.conn.lpush(queue, json.dumps(payload, default=str))
                self._buffer.popleft()
                flushed += 1
            except Exception:
                self._conn = None
                break
        if flushed:
            logger.info("Flushed buffered results", count=flushed, remaining=len(self._buffer))


# ---------------------------------------------------------------------------
# Task validation
# ---------------------------------------------------------------------------


def validate_task(raw: Dict[str, Any]) -> Dict[str, Any]:
    """
    Validate and normalise a task dict.
    Returns a clean task dict.  Raises ValueError on invalid input.
    """
    task_id = raw.get("task_id") or raw.get("id") or str(uuid.uuid4())

    target = raw.get("target")
    if not target or not isinstance(target, str):
        raise ValueError("Missing or invalid 'target' field")

    # Normalise URL
    if not target.startswith(("http://", "https://")):
        target = "https://" + target

    return {
        "task_id": str(task_id),
        "target": target,
        "wait_for_selector": raw.get("wait_for_selector"),
        "timeout": int(raw.get("timeout", 30)),
        "click_elements": raw.get("click_elements"),  # list of selectors
        "extract_forms": bool(raw.get("extract_forms", True)),
        "max_depth": int(raw.get("max_depth", 1)),
        "cookies": raw.get("cookies"),       # list of cookie dicts or None
        "extra_headers": raw.get("extra_headers"),  # dict or None
    }


# ---------------------------------------------------------------------------
# Subprocess execution
# ---------------------------------------------------------------------------


def build_intercept_cmd(task: Dict[str, Any], cfg: Dict[str, Any]) -> List[str]:
    """Build the CLI command list for intercept.py."""
    browser_cfg = cfg.get("browser", {})
    extraction_cfg = cfg.get("extraction", {})

    timeout_ms = task["timeout"] * 1000  # task timeout is in seconds
    viewport = browser_cfg.get("viewport", {})

    cmd = [
        sys.executable, str(INTERCEPT_SCRIPT),
        "--target", task["target"],
        "--headless", str(browser_cfg.get("headless", True)),
        "--timeout", str(timeout_ms),
        "--viewport-width", str(viewport.get("width", 1280)),
        "--viewport-height", str(viewport.get("height", 800)),
        "--user-agent", browser_cfg.get("user_agent", "Mozilla/5.0"),
        "--launch-args", json.dumps(browser_cfg.get("launch_args", [])),
        "--extract-forms", str(task.get("extract_forms", True)),
        "--max-requests", str(extraction_cfg.get("max_requests", 500)),
        "--max-response-body", str(extraction_cfg.get("max_response_body", 10240)),
        "--max-redirects", str(extraction_cfg.get("max_redirects", 10)),
        "--depth", str(task.get("max_depth", extraction_cfg.get("depth", 1))),
    ]

    if task.get("wait_for_selector"):
        cmd.extend(["--wait-for-selector", task["wait_for_selector"]])

    if task.get("click_elements"):
        cmd.extend(["--click-elements", json.dumps(task["click_elements"])])

    if task.get("cookies"):
        cmd.extend(["--cookies", json.dumps(task["cookies"])])

    extra_headers = task.get("extra_headers") or browser_cfg.get("extra_http_headers")
    if extra_headers:
        cmd.extend(["--extra-headers", json.dumps(extra_headers)])

    return cmd


def parse_intercept_output(stdout_data: str) -> Dict[str, Any]:
    """Parse JSON lines from intercept.py stdout into structured findings."""
    endpoints: List[Dict[str, Any]] = []
    forms: List[Dict[str, Any]] = []
    tokens: List[Dict[str, str]] = []
    errors: List[Dict[str, Any]] = []

    seen_endpoint_urls: set = set()
    seen_tokens: set = set()

    for line in stdout_data.strip().split("\n"):
        line = line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue

        rtype = record.get("type", "")

        if rtype == "endpoint_enriched":
            # Deduplicate by (url, method)
            key = (record.get("url", ""), record.get("method", ""))
            if key not in seen_endpoint_urls:
                seen_endpoint_urls.add(key)
                endpoints.append({
                    "url": record.get("url"),
                    "method": record.get("method"),
                    "params": record.get("params", {}),
                    "headers": record.get("headers", {}),
                    "request_body": record.get("request_body"),
                    "response_status": record.get("response_status"),
                    "response_body": record.get("response_body"),
                    "resource_type": record.get("resource_type"),
                })

        elif rtype == "endpoint":
            # Only keep if we never got an enriched version
            key = (record.get("url", ""), record.get("method", ""))
            if key not in seen_endpoint_urls:
                seen_endpoint_urls.add(key)
                endpoints.append({
                    "url": record.get("url"),
                    "method": record.get("method"),
                    "params": record.get("params", {}),
                    "headers": record.get("headers", {}),
                    "request_body": record.get("request_body"),
                    "response_status": None,
                    "response_body": None,
                    "resource_type": record.get("resource_type"),
                })

        elif rtype == "form":
            forms.append({
                "action": record.get("action", ""),
                "method": record.get("method", "GET"),
                "inputs": record.get("inputs", []),
                "inputs_detailed": record.get("inputs_detailed", []),
                "id": record.get("id"),
                "name": record.get("name"),
            })

        elif rtype == "token":
            key = (record.get("type_", record.get("type", "")), record.get("value", ""))
            if key not in seen_tokens:
                seen_tokens.add(key)
                tokens.append({
                    "type": record.get("type", "unknown"),
                    "value": record.get("value", ""),
                    "source": record.get("source", ""),
                })

        elif rtype == "error":
            errors.append({
                "error_type": record.get("error_type", "UNKNOWN"),
                "detail": record.get("detail", ""),
            })

    return {
        "endpoints": endpoints,
        "forms": forms,
        "tokens": tokens,
        "errors": errors,
    }


# ---------------------------------------------------------------------------
# Worker
# ---------------------------------------------------------------------------


class PlaywrightWorker:
    """Main event loop: pop task → run intercept → push result."""

    def __init__(self, config_path: Optional[Path] = None):
        self.cfg = load_config(config_path)
        self.redis = RedisClient(self.cfg["redis"])
        self._shutdown = False

        # Register SIGTERM handler
        signal.signal(signal.SIGTERM, self._handle_sigterm)
        signal.signal(signal.SIGINT, self._handle_sigterm)

    def _handle_sigterm(self, signum: int, frame: Any) -> None:
        logger.info("Shutdown signal received", signal=signum)
        self._shutdown = True

    # ----- Main loop -------------------------------------------------------

    def run(self) -> None:
        """Blocking main loop."""
        redis_cfg = self.cfg["redis"]
        task_queue = redis_cfg["task_queue"]
        result_queue = redis_cfg["result_queue"]
        status_prefix = redis_cfg.get("status_prefix", "task:status:")
        poll_interval = self.cfg["worker"].get("poll_interval", 1)

        logger.info("PlaywrightWorker starting", queue=task_queue)

        while not self._shutdown:
            # Try to flush any buffered results
            self.redis.flush_buffer(result_queue)

            # Pop next task
            raw_task = self.redis.pop_task(task_queue, timeout=poll_interval)
            if raw_task is None:
                # Reconnect attempt if connection was lost
                if self.redis._conn is None:
                    self.redis.reconnect()
                continue

            # Process the task
            self._process_task(raw_task, result_queue, status_prefix)

        # Shutdown – flush remaining buffer
        logger.info("Worker shutting down, flushing buffer")
        self.redis.flush_buffer(result_queue)
        logger.info("PlaywrightWorker stopped")

    def _process_task(
        self,
        raw_task: Dict[str, Any],
        result_queue: str,
        status_prefix: str,
    ) -> None:
        """Validate, execute, and report a single task."""
        start_time = time.time()

        # ── Validate ──
        try:
            task = validate_task(raw_task)
        except ValueError as ve:
            task_id = raw_task.get("task_id") or raw_task.get("id") or "unknown"
            logger.error("Task validation failed", task_id=task_id, error=str(ve))
            self.redis.set_status(str(task_id), TaskStatus.FAILED, status_prefix)
            self._push_result(result_queue, {
                "task_id": str(task_id),
                "module": "playwright_rend",
                "status": TaskStatus.FAILED,
                "data": {
                    "error": str(ve),
                    "error_type": "VALIDATION_ERROR",
                    "endpoints": [],
                    "forms": [],
                    "tokens": [],
                    "stats": {"total_endpoints": 0, "total_forms": 0, "requests_captured": 0, "elapsed_seconds": 0},
                },
            })
            return

        task_id = task["task_id"]
        logger.info("Processing task", task_id=task_id, target=task["target"])

        # ── Update status → PROCESSING ──
        self.redis.set_status(task_id, TaskStatus.PROCESSING, status_prefix)

        # ── Build subprocess command ──
        cmd = build_intercept_cmd(task, self.cfg)

        # ── Execute ──
        subprocess_timeout = task["timeout"] + self.cfg["worker"].get("subprocess_extra_timeout", 15)

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=subprocess_timeout,
                env={**os.environ, "PYTHONUNBUFFERED": "1"},
            )

            stdout_data = proc.stdout or ""
            stderr_data = proc.stderr or ""
            exit_code = proc.returncode

            # Log stderr lines
            if stderr_data.strip():
                for line in stderr_data.strip().split("\n"):
                    line = line.strip()
                    if line:
                        try:
                            parsed = json.loads(line)
                            log_level = parsed.get("level", "DEBUG").upper()
                            log_msg = parsed.get("msg", line)
                            getattr(logger, log_level.lower(), logger.debug)(
                                f"[intercept] {log_msg}",
                                task_id=task_id,
                            )
                        except json.JSONDecodeError:
                            logger.debug(f"[intercept] {line}", task_id=task_id)

        except subprocess.TimeoutExpired:
            logger.error("Subprocess timed out", task_id=task_id, timeout=subprocess_timeout)
            elapsed = time.time() - start_time
            self.redis.set_status(task_id, TaskStatus.FAILED, status_prefix)
            self._push_result(result_queue, {
                "task_id": task_id,
                "module": "playwright_rend",
                "status": "FAILED",
                "data": {
                    "error": f"Subprocess timed out after {subprocess_timeout}s",
                    "error_type": "TIMEOUT",
                    "endpoints": [],
                    "forms": [],
                    "tokens": [],
                    "stats": {"total_endpoints": 0, "total_forms": 0, "requests_captured": 0, "elapsed_seconds": round(elapsed, 2)},
                },
            })
            return

        except FileNotFoundError:
            logger.critical("intercept.py not found", path=str(INTERCEPT_SCRIPT))
            self.redis.set_status(task_id, TaskStatus.FAILED, status_prefix)
            self._push_result(result_queue, {
                "task_id": task_id,
                "module": "playwright_rend",
                "status": "FAILED",
                "data": {
                    "error": "intercept.py script not found",
                    "error_type": "INTERNAL_ERROR",
                    "endpoints": [],
                    "forms": [],
                    "tokens": [],
                    "stats": {"total_endpoints": 0, "total_forms": 0, "requests_captured": 0, "elapsed_seconds": 0},
                },
            })
            return

        except Exception as exc:
            logger.error("Subprocess launch error", task_id=task_id, error=str(exc))
            elapsed = time.time() - start_time
            self.redis.set_status(task_id, TaskStatus.FAILED, status_prefix)
            self._push_result(result_queue, {
                "task_id": task_id,
                "module": "playwright_rend",
                "status": "FAILED",
                "data": {
                    "error": str(exc),
                    "error_type": "BROWSER_ERROR",
                    "endpoints": [],
                    "forms": [],
                    "tokens": [],
                    "stats": {"total_endpoints": 0, "total_forms": 0, "requests_captured": 0, "elapsed_seconds": round(elapsed, 2)},
                },
            })
            return

        # ── Parse output ──
        elapsed = time.time() - start_time
        findings = parse_intercept_output(stdout_data)

        # Determine final status
        if exit_code == 0:
            status = TaskStatus.COMPLETED
        elif exit_code == 1:
            # Navigation error — may have partial results
            if findings["endpoints"] or findings["forms"]:
                status = TaskStatus.COMPLETED  # partial success
            else:
                status = TaskStatus.FAILED
        elif exit_code == 2:
            status = TaskStatus.FAILED
            findings.setdefault("errors", []).append({"error_type": "BROWSER_ERROR", "detail": "Browser launch failed"})
        else:
            status = TaskStatus.FAILED

        error_summary = None
        if findings.get("errors"):
            error_summary = findings["errors"][0].get("detail", "Unknown error")

        stats = {
            "total_endpoints": len(findings["endpoints"]),
            "total_forms": len(findings["forms"]),
            "total_tokens": len(findings["tokens"]),
            "requests_captured": len(findings["endpoints"]),
            "elapsed_seconds": round(elapsed, 2),
            "exit_code": exit_code,
        }

        result_payload: Dict[str, Any] = {
            "task_id": task_id,
            "module": "playwright_rend",
            "status": status,
            "data": {
                "endpoints": findings["endpoints"],
                "forms": findings["forms"],
                "tokens": findings["tokens"],
                "stats": stats,
            },
        }

        if error_summary:
            result_payload["data"]["error"] = error_summary
            result_payload["data"]["error_type"] = findings["errors"][0].get("error_type", "UNKNOWN")

        if findings.get("errors"):
            result_payload["data"]["errors"] = findings["errors"]

        # ── Update status and push result ──
        self.redis.set_status(task_id, status, status_prefix)
        self._push_result(result_queue, result_payload)

        logger.info(
            "Task completed",
            task_id=task_id,
            status=status,
            endpoints=stats["total_endpoints"],
            forms=stats["total_forms"],
            tokens=stats["total_tokens"],
            elapsed=stats["elapsed_seconds"],
        )

    def _push_result(self, queue: str, payload: Dict[str, Any]) -> None:
        """Push result with buffer fallback."""
        success = self.redis.push_result(queue, payload)
        if not success:
            logger.warning(
                "Result buffered (Redis unavailable)",
                task_id=payload.get("task_id"),
                buffer_size=len(self.redis._buffer),
            )


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------

def main() -> None:
    """CLI entry point."""
    import argparse

    parser = argparse.ArgumentParser(description="Playwright Renderer Worker")
    parser.add_argument("--config", type=str, default=None, help="Path to config.yaml")
    args = parser.parse_args()

    config_path = Path(args.config) if args.config else None
    worker = PlaywrightWorker(config_path=config_path)
    worker.run()


if __name__ == "__main__":
    main()
