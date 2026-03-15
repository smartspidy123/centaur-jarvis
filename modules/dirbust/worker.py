"""
Directory Bruteforcer Worker
=============================
Main worker process that:
1. Consumes tasks from Redis queue `queue:dirbust`.
2. Validates task payloads.
3. Resolves wordlists.
4. Runs ffuf (primary) or gobuster (fallback).
5. Publishes structured results to `results:incoming`.
6. Handles SIGTERM gracefully.
7. Buffers results in memory if Redis is temporarily unavailable.

All status strings are UPPERCASE per shared.schemas.TaskStatus.
All results contain a mandatory `data` field.
"""

import json
import os
import signal
import sys
import time
import traceback
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

# ── Logging Setup (shared.logger with fallback) ─────────────────────
try:
    from shared.logger import get_logger
    logger = get_logger("dirbust.worker")
except ImportError:
    import logging
    logging.basicConfig(
        level=logging.INFO,
        format='{"timestamp":"%(asctime)s","level":"%(levelname)s",'
               '"module":"%(name)s","message":"%(message)s"}'
    )
    logger = logging.getLogger("dirbust.worker")

# ── Redis ────────────────────────────────────────────────────────────
try:
    import redis as redis_lib
except ImportError:
    logger.critical("redis package not installed. Cannot start worker.")
    sys.exit(1)

# ── Internal imports ─────────────────────────────────────────────────
from modules.dirbust.wordlist_manager import WordlistManager, WordlistError
from modules.dirbust.ffuf_runner import (
    run_ffuf,
    check_ffuf,
    ToolMissingError,
    FfufResult,
)
from modules.dirbust.gobuster_runner import run_gobuster, check_gobuster


# ═════════════════════════════════════════════════════════════════════
#  CONSTANTS
# ═════════════════════════════════════════════════════════════════════

MODULE_NAME = "dirbust"
CONFIG_FILE = Path(__file__).parent / "config.yaml"

# Status constants — UPPERCASE per global rule
STATUS_QUEUED = "QUEUED"
STATUS_PROCESSING = "PROCESSING"
STATUS_COMPLETED = "COMPLETED"
STATUS_FAILED = "FAILED"

# Error type constants
ERROR_VALIDATION = "VALIDATION_ERROR"
ERROR_TOOL_MISSING = "TOOL_MISSING"
ERROR_WORDLIST = "WORDLIST_ERROR"
ERROR_TIMEOUT = "TIMEOUT"
ERROR_EXECUTION = "EXECUTION_ERROR"
ERROR_REDIS = "REDIS_ERROR"
ERROR_UNKNOWN = "UNKNOWN_ERROR"


# ═════════════════════════════════════════════════════════════════════
#  CONFIG LOADING
# ═════════════════════════════════════════════════════════════════════

def load_config(config_path: Optional[Path] = None) -> dict:
    """Load config.yaml with fallback to sensible defaults."""
    path = config_path or CONFIG_FILE
    defaults = {
        "wordlist": {
            "default": "/usr/share/seclists/Discovery/Web-Content/common.txt",
            "auto_download": True,
            "download_url": (
                "https://raw.githubusercontent.com/danielmiessler/SecLists/"
                "master/Discovery/Web-Content/common.txt"
            ),
            "cache_dir": "~/.centaur/wordlists",
        },
        "tools": {
            "ffuf": {"path": "ffuf"},
            "gobuster": {"path": "gobuster"},
        },
        "execution": {
            "default_threads": 40,
            "default_delay": 0.1,
            "default_extensions": ["php", "asp", "aspx", "jsp", "txt", "bak", "old", "inc"],
            "max_recursion_depth": 3,
            "timeout": 300,
            "max_retries": 2,
        },
        "rate_limit": {
            "per_host_rate": 10,
            "burst": 20,
        },
        "redis": {
            "task_queue": "queue:dirbust",
            "result_queue": "results:incoming",
            "status_prefix": "task:",
            "connection": {
                "host": "127.0.0.1",
                "port": 6379,
                "db": 0,
                "socket_timeout": 5,
                "retry_on_timeout": True,
            },
        },
        "worker": {
            "poll_interval": 1.0,
            "memory_buffer_max": 100,
            "graceful_shutdown_timeout": 30,
        },
    }

    if path.is_file():
        try:
            with open(path, "r") as f:
                file_config = yaml.safe_load(f) or {}
            # Deep merge: file_config over defaults
            merged = _deep_merge(defaults, file_config)
            logger.info("Config loaded", extra={"path": str(path)})
            return merged
        except Exception as e:
            logger.warning(
                "Failed to load config file, using defaults",
                extra={"path": str(path), "error": str(e)}
            )
    else:
        logger.info(
            "Config file not found, using defaults",
            extra={"path": str(path)}
        )

    return defaults


def _deep_merge(base: dict, override: dict) -> dict:
    """Recursively merge override into base."""
    result = base.copy()
    for key, value in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = value
    return result


# ═════════════════════════════════════════════════════════════════════
#  TASK VALIDATION
# ═════════════════════════════════════════════════════════════════════

def validate_task(task: dict) -> List[str]:
    """
    Validate a task payload. Returns list of error messages (empty = valid).
    """
    errors: List[str] = []

    if "task_id" not in task or not task["task_id"]:
        errors.append("Missing required field: 'task_id'")

    if "target" not in task or not task["target"]:
        errors.append("Missing required field: 'target'")
    else:
        target = task["target"]
        if not isinstance(target, str):
            errors.append("'target' must be a string")
        elif not (target.startswith("http://") or target.startswith("https://")):
            errors.append(
                f"'target' must start with http:// or https://, got: {target[:50]}"
            )

    if "extensions" in task:
        if not isinstance(task["extensions"], list):
            errors.append("'extensions' must be a list of strings")

    if "threads" in task:
        try:
            t = int(task["threads"])
            if t < 1 or t > 1000:
                errors.append("'threads' must be between 1 and 1000")
        except (ValueError, TypeError):
            errors.append("'threads' must be an integer")

    if "delay" in task:
        try:
            d = float(task["delay"])
            if d < 0:
                errors.append("'delay' must be non-negative")
        except (ValueError, TypeError):
            errors.append("'delay' must be a number")

    if "depth" in task:
        try:
            dp = int(task["depth"])
            if dp < 1:
                errors.append("'depth' must be >= 1")
        except (ValueError, TypeError):
            errors.append("'depth' must be an integer")

    return errors


# ═════════════════════════════════════════════════════════════════════
#  REDIS HELPERS
# ═════════════════════════════════════════════════════════════════════

class RedisClient:
    """
    Thin wrapper around redis.Redis with reconnection logic and
    an in-memory buffer for results when Redis is unavailable.
    """

    def __init__(self, config: dict):
        redis_cfg = config.get("redis", {})
        conn_cfg = redis_cfg.get("connection", {})
        self._host = conn_cfg.get("host", "127.0.0.1")
        self._port = conn_cfg.get("port", 6379)
        self._db = conn_cfg.get("db", 0)
        self._socket_timeout = conn_cfg.get("socket_timeout", 5)
        self._retry_on_timeout = conn_cfg.get("retry_on_timeout", True)

        self._task_queue = redis_cfg.get("task_queue", "queue:dirbust")
        self._result_queue = redis_cfg.get("result_queue", "results:incoming")
        self._status_prefix = redis_cfg.get("status_prefix", "task:")

        self._buffer_max = config.get("worker", {}).get("memory_buffer_max", 100)
        self._result_buffer: List[str] = []

        self._client: Optional[redis_lib.Redis] = None
        self._connect()

    def _connect(self):
        """Establish Redis connection."""
        try:
            self._client = redis_lib.Redis(
                host=self._host,
                port=self._port,
                db=self._db,
                socket_timeout=self._socket_timeout,
                retry_on_timeout=self._retry_on_timeout,
                decode_responses=True,
            )
            self._client.ping()
            logger.info(
                "Redis connected",
                extra={"host": self._host, "port": self._port, "db": self._db}
            )
        except redis_lib.RedisError as e:
            logger.error("Redis connection failed", extra={"error": str(e)})
            self._client = None

    @property
    def connected(self) -> bool:
        if self._client is None:
            return False
        try:
            self._client.ping()
            return True
        except redis_lib.RedisError:
            return False

    def _ensure_connection(self) -> bool:
        """Try to reconnect if disconnected. Returns True if connected."""
        if self.connected:
            return True
        logger.info("Attempting Redis reconnection...")
        self._connect()
        return self.connected

    def pop_task(self, timeout: int = 1) -> Optional[dict]:
        """
        Blocking pop from task queue. Returns parsed task dict or None.
        """
        if not self._ensure_connection():
            return None

        try:
            result = self._client.brpop(self._task_queue, timeout=timeout)
            if result is None:
                return None

            _, raw = result
            try:
                task = json.loads(raw)
                return task
            except json.JSONDecodeError as e:
                logger.error(
                    "Invalid JSON in task queue",
                    extra={"error": str(e), "raw_preview": raw[:200]}
                )
                return None

        except redis_lib.RedisError as e:
            logger.error("Redis error during task pop", extra={"error": str(e)})
            self._client = None
            return None

    def set_status(self, task_id: str, status: str, extra: Optional[dict] = None):
        """Set task status in Redis hash."""
        if not self._ensure_connection():
            logger.warning(
                "Cannot set status (Redis unavailable)",
                extra={"task_id": task_id, "status": status}
            )
            return

        key = f"{self._status_prefix}{task_id}"
        mapping = {
            "status": status,
            "module": MODULE_NAME,
            "updated_at": datetime.now(timezone.utc).isoformat(),
        }
        if extra:
            mapping.update(extra)

        try:
            self._client.hset(key, mapping=mapping)
        except redis_lib.RedisError as e:
            logger.error(
                "Failed to set task status",
                extra={"task_id": task_id, "error": str(e)}
            )

    def push_result(self, result: dict):
        """
        Push result to results queue. Buffers in memory if Redis is down.
        """
        result_json = json.dumps(result)

        if self._ensure_connection():
            # First, flush any buffered results
            self._flush_buffer()
            try:
                self._client.lpush(self._result_queue, result_json)
                logger.info(
                    "Result pushed to Redis",
                    extra={"task_id": result.get("task_id", "unknown")}
                )
                return
            except redis_lib.RedisError as e:
                logger.error(
                    "Failed to push result to Redis",
                    extra={"error": str(e)}
                )
                self._client = None

        # Buffer in memory
        if len(self._result_buffer) < self._buffer_max:
            self._result_buffer.append(result_json)
            logger.warning(
                "Result buffered in memory",
                extra={
                    "task_id": result.get("task_id", "unknown"),
                    "buffer_size": len(self._result_buffer),
                }
            )
        else:
            logger.critical(
                "Memory buffer full! Result DROPPED.",
                extra={
                    "task_id": result.get("task_id", "unknown"),
                    "buffer_max": self._buffer_max,
                }
            )

    def _flush_buffer(self):
        """Flush buffered results to Redis."""
        if not self._result_buffer:
            return

        if not self.connected:
            return

        flushed = 0
        remaining: List[str] = []

        for result_json in self._result_buffer:
            try:
                self._client.lpush(self._result_queue, result_json)
                flushed += 1
            except redis_lib.RedisError:
                remaining.append(result_json)
                break  # Stop trying on first failure

        # Keep unflushed items
        remaining.extend(self._result_buffer[flushed + len(remaining):])
        self._result_buffer = remaining

        if flushed > 0:
            logger.info(
                "Flushed buffered results to Redis",
                extra={"flushed": flushed, "remaining": len(self._result_buffer)}
            )


# ═════════════════════════════════════════════════════════════════════
#  TOOL CHECKER
# ═════════════════════════════════════════════════════════════════════

class ToolAvailability:
    """Track which tools are available at startup."""

    def __init__(self, config: dict):
        tools_cfg = config.get("tools", {})
        self.ffuf_path = tools_cfg.get("ffuf", {}).get("path", "ffuf")
        self.gobuster_path = tools_cfg.get("gobuster", {}).get("path", "gobuster")

        self.ffuf_available = False
        self.ffuf_version = ""
        self.gobuster_available = False
        self.gobuster_version = ""

        self._check_tools()

    def _check_tools(self):
        """Check tool availability at startup."""
        self.ffuf_available, self.ffuf_version = check_ffuf(self.ffuf_path)
        if self.ffuf_available:
            logger.info(
                "ffuf is available",
                extra={"version": self.ffuf_version, "path": self.ffuf_path}
            )
        else:
            logger.warning(
                "ffuf NOT available",
                extra={"reason": self.ffuf_version, "path": self.ffuf_path}
            )

        self.gobuster_available, self.gobuster_version = check_gobuster(
            self.gobuster_path
        )
        if self.gobuster_available:
            logger.info(
                "gobuster is available (fallback)",
                extra={"version": self.gobuster_version, "path": self.gobuster_path}
            )
        else:
            logger.warning(
                "gobuster NOT available",
                extra={"reason": self.gobuster_version, "path": self.gobuster_path}
            )

    @property
    def any_tool_available(self) -> bool:
        return self.ffuf_available or self.gobuster_available


# ═════════════════════════════════════════════════════════════════════
#  MAIN WORKER
# ═════════════════════════════════════════════════════════════════════

class DirbustWorker:
    """
    Main worker class for the directory bruteforcer module.
    """

    def __init__(self, config: Optional[dict] = None):
        self.config = config or load_config()
        self.redis_client = RedisClient(self.config)
        self.tools = ToolAvailability(self.config)
        self.wordlist_mgr = WordlistManager(self.config)

        self._shutdown_requested = False
        self._current_task_id: Optional[str] = None
        self._poll_interval = self.config.get("worker", {}).get("poll_interval", 1.0)
        self._shutdown_timeout = self.config.get("worker", {}).get(
            "graceful_shutdown_timeout", 30
        )

        # Register signal handlers
        signal.signal(signal.SIGTERM, self._handle_signal)
        signal.signal(signal.SIGINT, self._handle_signal)

    def _handle_signal(self, signum: int, frame):
        """Handle SIGTERM/SIGINT for graceful shutdown."""
        sig_name = signal.Signals(signum).name
        logger.info(
            f"Received {sig_name}, initiating graceful shutdown",
            extra={
                "signal": sig_name,
                "current_task": self._current_task_id,
            }
        )
        self._shutdown_requested = True

    def run(self):
        """Main event loop: poll Redis, process tasks."""
        logger.info(
            "Dirbust worker starting",
            extra={
                "ffuf_available": self.tools.ffuf_available,
                "gobuster_available": self.tools.gobuster_available,
                "queue": self.config["redis"]["task_queue"],
            }
        )

        if not self.tools.any_tool_available:
            logger.critical(
                "No scanning tools available (neither ffuf nor gobuster). "
                "Worker will start but all tasks will be marked FAILED with TOOL_MISSING."
            )

        while not self._shutdown_requested:
            try:
                task = self.redis_client.pop_task(
                    timeout=int(self._poll_interval)
                )
                if task is None:
                    continue

                self._process_task(task)

            except Exception as e:
                logger.error(
                    "Unexpected error in worker loop",
                    extra={
                        "error": str(e),
                        "traceback": traceback.format_exc(),
                    }
                )
                time.sleep(self._poll_interval)

        logger.info("Worker shutdown complete")

    def _process_task(self, task: dict):
        """Process a single task end-to-end."""
        task_id = task.get("task_id", f"unknown-{uuid.uuid4().hex[:8]}")
        self._current_task_id = task_id
        start_time = time.monotonic()

        logger.info(
            "Processing task",
            extra={"task_id": task_id, "target": task.get("target", "N/A")}
        )

        try:
            # ── 1. Validate ──────────────────────────────────────────
            validation_errors = validate_task(task)
            if validation_errors:
                self._fail_task(
                    task_id=task_id,
                    error_type=ERROR_VALIDATION,
                    error_message="; ".join(validation_errors),
                    target=task.get("target", ""),
                    elapsed=time.monotonic() - start_time,
                )
                return

            # ── 2. Set PROCESSING status ─────────────────────────────
            self.redis_client.set_status(task_id, STATUS_PROCESSING)

            # ── 3. Check tool availability ───────────────────────────
            if not self.tools.any_tool_available:
                self._fail_task(
                    task_id=task_id,
                    error_type=ERROR_TOOL_MISSING,
                    error_message=(
                        "Neither ffuf nor gobuster is available. "
                        "Install at least one tool."
                    ),
                    target=task["target"],
                    elapsed=time.monotonic() - start_time,
                )
                return

            # ── 4. Resolve wordlist ──────────────────────────────────
            try:
                wordlist_path = self.wordlist_mgr.get_wordlist_path(
                    task.get("wordlist")
                )
            except WordlistError as e:
                self._fail_task(
                    task_id=task_id,
                    error_type=ERROR_WORDLIST,
                    error_message=str(e),
                    target=task["target"],
                    elapsed=time.monotonic() - start_time,
                )
                return

            # ── 5. Resolve execution parameters ─────────────────────
            exec_cfg = self.config.get("execution", {})

            target = task["target"].rstrip("/")
            extensions = task.get(
                "extensions",
                exec_cfg.get("default_extensions", [])
            )
            threads = int(task.get(
                "threads",
                exec_cfg.get("default_threads", 40)
            ))
            delay = float(task.get(
                "delay",
                exec_cfg.get("default_delay", 0.1)
            ))
            recursive = bool(task.get("recursive", False))
            depth = int(task.get(
                "depth",
                exec_cfg.get("max_recursion_depth", 3)
            ))
            timeout = int(exec_cfg.get("timeout", 300))

            # Clamp depth
            max_depth = exec_cfg.get("max_recursion_depth", 3)
            if depth > max_depth:
                logger.warning(
                    "Requested depth exceeds max, clamping",
                    extra={"requested": depth, "max": max_depth}
                )
                depth = max_depth

            # ── 6. Execute tool ──────────────────────────────────────
            ffuf_result: Optional[FfufResult] = None
            tool_used = "none"

            if self.tools.ffuf_available:
                tool_used = "ffuf"
                try:
                    ffuf_result = run_ffuf(
                        target=target,
                        wordlist=str(wordlist_path),
                        extensions=extensions,
                        threads=threads,
                        delay=delay,
                        recursive=recursive,
                        depth=depth,
                        timeout=timeout,
                        binary_path=self.tools.ffuf_path,
                    )
                except ToolMissingError:
                    # Tool disappeared since startup check
                    logger.warning("ffuf disappeared, trying gobuster fallback")
                    self.tools.ffuf_available = False
                except OSError as e:
                    logger.error(
                        "ffuf execution failed, trying gobuster",
                        extra={"error": str(e)}
                    )

            if ffuf_result is None and self.tools.gobuster_available:
                tool_used = "gobuster"
                try:
                    ffuf_result = run_gobuster(
                        target=target,
                        wordlist=str(wordlist_path),
                        extensions=extensions,
                        threads=threads,
                        delay=delay,
                        recursive=recursive,
                        depth=depth,
                        timeout=timeout,
                        binary_path=self.tools.gobuster_path,
                    )
                except ToolMissingError:
                    self.tools.gobuster_available = False
                except OSError as e:
                    logger.error(
                        "gobuster execution also failed",
                        extra={"error": str(e)}
                    )

            if ffuf_result is None:
                self._fail_task(
                    task_id=task_id,
                    error_type=ERROR_EXECUTION,
                    error_message="All tool executions failed",
                    target=target,
                    elapsed=time.monotonic() - start_time,
                )
                return

            # ── Check if shutdown was requested during execution ─────
            if self._shutdown_requested:
                logger.info(
                    "Shutdown requested, but finishing current task",
                    extra={"task_id": task_id}
                )

            # ── 7. Build result ──────────────────────────────────────
            elapsed = round(time.monotonic() - start_time, 3)
            result_data = ffuf_result.to_dict()

            result = {
                "task_id": task_id,
                "module": MODULE_NAME,
                "status": STATUS_COMPLETED,
                "target": target,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "elapsed_seconds": elapsed,
                "tool_used": tool_used,
                # ── Mandatory `data` field ───────────────────────────
                "data": {
                    "findings": result_data["findings"],
                    "stats": {
                        **result_data["stats"],
                        "elapsed_seconds": elapsed,
                        "tool": tool_used,
                        "wordlist": str(wordlist_path),
                        "extensions": extensions,
                        "threads": threads,
                        "recursive": recursive,
                    },
                },
            }

            # ── 8. Publish result ────────────────────────────────────
            self.redis_client.push_result(result)
            self.redis_client.set_status(
                task_id,
                STATUS_COMPLETED,
                extra={
                    "findings_count": str(len(result_data["findings"])),
                    "elapsed": str(elapsed),
                }
            )

            logger.info(
                "Task completed successfully",
                extra={
                    "task_id": task_id,
                    "findings": len(result_data["findings"]),
                    "elapsed": elapsed,
                    "tool": tool_used,
                }
            )

        except Exception as e:
            elapsed = round(time.monotonic() - start_time, 3)
            logger.error(
                "Unhandled exception during task processing",
                extra={
                    "task_id": task_id,
                    "error": str(e),
                    "traceback": traceback.format_exc(),
                }
            )
            self._fail_task(
                task_id=task_id,
                error_type=ERROR_UNKNOWN,
                error_message=str(e),
                target=task.get("target", ""),
                elapsed=elapsed,
            )

        finally:
            self._current_task_id = None

    def _fail_task(
        self,
        task_id: str,
        error_type: str,
        error_message: str,
        target: str = "",
        elapsed: float = 0.0,
    ):
        """
        Mark a task as FAILED and publish error result.
        """
        logger.error(
            "Task failed",
            extra={
                "task_id": task_id,
                "error_type": error_type,
                "error_message": error_message,
            }
        )

        result = {
            "task_id": task_id,
            "module": MODULE_NAME,
            "status": STATUS_FAILED,
            "target": target,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "elapsed_seconds": round(elapsed, 3),
            "error_type": error_type,
            "error_message": error_message,
            # ── Mandatory `data` field (empty on failure) ────────────
            "data": {
                "findings": [],
                "stats": {
                    "total_requests": 0,
                    "total_findings": 0,
                    "errors": 1,
                    "elapsed_seconds": round(elapsed, 3),
                    "error_type": error_type,
                },
            },
        }

        self.redis_client.push_result(result)
        self.redis_client.set_status(
            task_id,
            STATUS_FAILED,
            extra={
                "error_type": error_type,
                "error_message": error_message[:500],
            }
        )


# ═════════════════════════════════════════════════════════════════════
#  ENTRYPOINT
# ═════════════════════════════════════════════════════════════════════

def main():
    """Module entrypoint — independently runnable."""
    logger.info("=" * 60)
    logger.info("Centaur-Jarvis  |  Directory Bruteforcer  |  Worker Starting")
    logger.info("=" * 60)

    config = load_config()
    worker = DirbustWorker(config)
    worker.run()


if __name__ == "__main__":
    main()
