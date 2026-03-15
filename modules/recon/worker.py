#!/usr/bin/env python3
"""
modules/recon/worker.py
=======================
Main Recon Worker — the beating heart of deterministic reconnaissance.

Lifecycle
---------
1. Load config → validate tools → connect to Redis.
2. Enter main loop: ``BLPOP queue:recon`` for tasks.
3. For each task: validate → execute → parse → push result.
4. Background thread sends heartbeats every N seconds.
5. On ``SIGTERM``/``SIGINT``: finish current task → exit cleanly.

Architecture Contract
---------------------
- **No silent failures**: every error path produces a ``TaskResult`` with
  an explicit ``error_type``.
- **Telemetry**: heartbeat, per-task execution time, parse warnings.
- **Resource awareness**: RAM guard via ``psutil``.
- **Redis resilience**: reconnect with exponential backoff; buffer results
  in memory up to a configurable limit.
"""

from __future__ import annotations

import json
import os
import platform
import signal
import socket
import sys
import threading
import time
import traceback
from pathlib import Path
from typing import Any, Dict, List, Optional
from datetime import datetime, timezone

import psutil
import redis
import yaml

# ── Project imports ────────────────────────────────────────────────────────
# Adjust the path so the worker can run standalone from repo root
_MODULE_DIR = Path(__file__).resolve().parent
_PROJECT_ROOT = _MODULE_DIR.parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from shared.logger import get_logger  # noqa: E402
from shared.schemas import (  # noqa: E402
    ErrorType,
    Task,
    TaskResult,
    TaskStatus,
    TaskType,
)
from modules.recon.parsers import get_parser  # noqa: E402
from modules.recon.tasks import TASK_DISPATCH, TaskExecResult  # noqa: E402


# ---------------------------------------------------------------------------
# Configuration Loader
# ---------------------------------------------------------------------------

def _load_config(config_path: Optional[str] = None) -> Dict[str, Any]:
    """
    Load YAML config with environment-variable overrides.

    Resolution order (highest priority first):
      1. Environment variables (``REDIS_HOST``, ``REDIS_PORT``, etc.)
      2. ``config.local.yaml`` (git-ignored, per-deployment)
      3. ``config.yaml`` (defaults shipped in repo)
    """
    search_paths = []
    if config_path:
        search_paths.append(Path(config_path))
    search_paths.extend([
        _MODULE_DIR / "config.local.yaml",
        _MODULE_DIR / "config.yaml",
    ])

    config: Dict[str, Any] = {}
    for p in search_paths:
        if p.is_file():
            with open(p, "r") as f:
                config = yaml.safe_load(f) or {}
            break

    if not config:
        raise FileNotFoundError(
            f"No config file found; searched: {[str(p) for p in search_paths]}"
        )

    # ── Env overrides ──────────────────────────────────────────────────────
    redis_cfg = config.setdefault("redis", {})
    redis_cfg["host"] = os.environ.get("REDIS_HOST", redis_cfg.get("host", "127.0.0.1"))
    redis_cfg["port"] = int(os.environ.get("REDIS_PORT", redis_cfg.get("port", 6379)))
    redis_cfg["db"] = int(os.environ.get("REDIS_DB", redis_cfg.get("db", 0)))
    redis_cfg["password"] = os.environ.get("REDIS_PASSWORD", redis_cfg.get("password"))
    if redis_cfg["password"] in (None, "", "null"):
        redis_cfg["password"] = None

    # Worker ID
    if config.get("worker_id", "auto") == "auto":
        hostname = socket.gethostname()
        pid = os.getpid()
        config["worker_id"] = f"recon-{hostname}-{pid}"

    return config


# ---------------------------------------------------------------------------
# Recon Worker Class
# ---------------------------------------------------------------------------

class ReconWorker:
    """
    A single-threaded recon worker that consumes from Redis and executes
    security tools via subprocess.

    Thread model:
      - **Main thread**: BLPOP loop → task execution.
      - **Heartbeat thread** (daemon): periodic Redis SETEX.
      - **Resource monitor thread** (daemon): periodic RAM check.
    """

    def __init__(self, config: Dict[str, Any]) -> None:
        self.config = config
        self.worker_id: str = config["worker_id"]
        self.queue_in: str = config.get("queue", {}).get("inbound", "queue:recon")
        self.queue_out: str = config.get("queue", {}).get("results", "results:incoming")
        self.blpop_timeout: int = int(config.get("queue", {}).get("blpop_timeout", 5))
        self.heartbeat_interval: int = int(config.get("heartbeat_interval", 30))
        self.heartbeat_ttl: int = int(config.get("heartbeat_ttl", 60))
        self.task_timeout: int = int(config.get("task_timeout", 300))
        self.shutdown_timeout: int = int(config.get("shutdown_timeout", 30))
        self.max_ram_pct: int = int(config.get("resources", {}).get("max_ram_pct", 90))
        self.ram_check_interval: int = int(config.get("resources", {}).get("ram_check_interval", 10))
        self.result_buffer_limit: int = int(config.get("resources", {}).get("result_buffer_limit", 100))
        self.tools_config: Dict[str, Any] = config.get("tools", {})

        # Logger
        log_cfg = config.get("logging", {})
        self.logger = get_logger(
            name="recon.worker",
            level=log_cfg.get("level", "INFO"),
            log_file=log_cfg.get("file"),
            worker_id=self.worker_id,
        )

        # State
        self._shutdown_event = threading.Event()
        self._currently_processing = threading.Event()  # set when a task is running
        self._redis: Optional[redis.Redis] = None
        self._result_buffer: List[Dict[str, Any]] = []  # buffered when Redis is down
        self._ram_ok = threading.Event()
        self._ram_ok.set()  # start accepting tasks
        self._tool_health: Dict[str, bool] = {}

    # -- Redis Connection ----------------------------------------------------

    def _connect_redis(self) -> redis.Redis:
        """
        Establish a Redis connection with exponential backoff.
        """
        rcfg = self.config.get("redis", {})
        max_attempts = int(rcfg.get("max_reconnect_attempts", 10))
        backoff_base = float(rcfg.get("reconnect_backoff_base", 2))

        for attempt in range(1, max_attempts + 1):
            try:
                conn = redis.Redis(
                    host=rcfg["host"],
                    port=rcfg["port"],
                    db=rcfg["db"],
                    password=rcfg.get("password"),
                    socket_timeout=float(rcfg.get("socket_timeout", 5)),
                    retry_on_timeout=rcfg.get("retry_on_timeout", True),
                    decode_responses=True,
                )
                conn.ping()
                self.logger.info(
                    f"Connected to Redis at {rcfg['host']}:{rcfg['port']} "
                    f"(attempt {attempt})"
                )
                return conn
            except (redis.ConnectionError, redis.TimeoutError) as exc:
                wait = min(backoff_base ** attempt, 60)
                self.logger.warning(
                    f"Redis connection failed (attempt {attempt}/{max_attempts}): "
                    f"{exc}. Retrying in {wait:.1f}s"
                )
                if attempt == max_attempts:
                    raise RuntimeError(
                        f"Could not connect to Redis after {max_attempts} attempts"
                    ) from exc
                time.sleep(wait)

        # Unreachable, but satisfies type checker
        raise RuntimeError("Redis connection exhausted")  # pragma: no cover

    def _ensure_redis(self) -> redis.Redis:
        """Return a live Redis connection, reconnecting if necessary."""
        if self._redis is None:
            self._redis = self._connect_redis()
            return self._redis
        try:
            self._redis.ping()
            return self._redis
        except (redis.ConnectionError, redis.TimeoutError, OSError):
            self.logger.warning("Redis connection lost; reconnecting…")
            self._redis = self._connect_redis()
            return self._redis

    # -- Tool Health Check ---------------------------------------------------

    def _check_tools(self) -> None:
        """
        Verify that every configured tool binary exists and is executable.
        Log results; mark worker unhealthy if *all* tools are missing.
        """
        import shutil

        all_missing = True
        for tool_name, tool_cfg in self.tools_config.items():
            raw_path = tool_cfg.get("path", tool_name)
            abs_path = shutil.which(raw_path) if not os.path.isabs(raw_path) else raw_path
            if abs_path and os.path.isfile(abs_path) and os.access(abs_path, os.X_OK):
                self._tool_health[tool_name] = True
                all_missing = False
                self.logger.info(f"Tool '{tool_name}' found at {abs_path}")
            else:
                self._tool_health[tool_name] = False
                self.logger.error(
                    f"Tool '{tool_name}' NOT FOUND at '{raw_path}'. "
                    f"Tasks requiring this tool will fail with TOOL_MISSING."
                )

        if all_missing and self.tools_config:
            self.logger.critical(
                "ALL configured tools are missing! Worker is effectively unhealthy."
            )

    # -- Heartbeat -----------------------------------------------------------

    def _heartbeat_loop(self) -> None:
        """
        Daemon thread that updates ``worker:heartbeat:{worker_id}`` every
        ``heartbeat_interval`` seconds with a JSON status blob.
        """
        key = f"worker:heartbeat:{self.worker_id}"
        while not self._shutdown_event.is_set():
            try:
                r = self._ensure_redis()
                payload = json.dumps({
                    "worker_id": self.worker_id,
                    "timestamp": time.time(),
                    "processing": self._currently_processing.is_set(),
                    "ram_pct": psutil.virtual_memory().percent,
                    "tools_healthy": self._tool_health,
                    "buffered_results": len(self._result_buffer),
                    "pid": os.getpid(),
                    "hostname": socket.gethostname(),
                })
                r.setex(key, self.heartbeat_ttl, str(time.time()))
            except Exception as exc:
                self.logger.warning(f"Heartbeat failed: {exc}")
            self._shutdown_event.wait(self.heartbeat_interval)

    # -- Resource Monitor ----------------------------------------------------

    def _resource_monitor_loop(self) -> None:
        """
        Daemon thread that pauses task acceptance when RAM exceeds threshold.
        """
        while not self._shutdown_event.is_set():
            try:
                ram = psutil.virtual_memory().percent
                if ram > self.max_ram_pct:
                    if self._ram_ok.is_set():
                        self.logger.warning(
                            f"RAM usage {ram:.1f}% > {self.max_ram_pct}%. "
                            f"Pausing task acceptance."
                        )
                    self._ram_ok.clear()
                else:
                    if not self._ram_ok.is_set():
                        self.logger.info(
                            f"RAM usage {ram:.1f}% back under threshold. Resuming."
                        )
                    self._ram_ok.set()
            except Exception as exc:
                self.logger.warning(f"Resource monitor error: {exc}")
            self._shutdown_event.wait(self.ram_check_interval)

    # -- Result Buffer Flush -------------------------------------------------

    def _flush_result_buffer(self) -> None:
        """
        Attempt to push any buffered results (from when Redis was down)
        back to the results queue.
        """
        if not self._result_buffer:
            return
        try:
            r = self._ensure_redis()
            flushed = 0
            while self._result_buffer:
                payload = self._result_buffer[0]
                r.rpush(self.queue_out, json.dumps(payload))
                self._result_buffer.pop(0)
                flushed += 1
            if flushed:
                self.logger.info(f"Flushed {flushed} buffered results to Redis")
        except Exception as exc:
            self.logger.warning(f"Buffer flush failed: {exc}")

    # -- Push Result ---------------------------------------------------------

    def _push_result(self, result: TaskResult) -> None:
        """
        Push a ``TaskResult`` to Redis ``results:incoming``, buffering
        in memory if Redis is unreachable.
        """
        payload = result.to_dict()
        try:
            r = self._ensure_redis()
            r.rpush(self.queue_out, json.dumps(payload))
            # Also try to flush any backlog
            self._flush_result_buffer()
        except Exception as exc:
            self.logger.warning(f"Failed to push result to Redis: {exc}")
            if len(self._result_buffer) < self.result_buffer_limit:
                self._result_buffer.append(payload)
                self.logger.info(
                    f"Result buffered in memory ({len(self._result_buffer)}/{self.result_buffer_limit})"
                )
            else:
                self.logger.error(
                    f"Result buffer full ({self.result_buffer_limit}). "
                    f"DROPPING result for task {result.task_id}!"
                )

    # -- Update Task Status --------------------------------------------------

    def _update_task_status(self, task_id: str, status: TaskStatus) -> None:
        """Update ``task:{id}`` hash in Redis."""
        try:
            r = self._ensure_redis()
            r.hset(f"task:{task_id}", mapping={
                "status": status.value,
                "worker_id": self.worker_id,
                "updated_at": datetime.now(timezone.utc).isoformat(),
            })
        except Exception as exc:
            self.logger.warning(
                f"Failed to update task status for {task_id}: {exc}"
            )

    # -- Task Execution Pipeline --------------------------------------------

    def _execute_task(self, task: Task) -> TaskResult:
        """
        Full execution pipeline: dispatch → run tool → parse → result.
        """
        start_time = time.time()

        # 1. Look up dispatcher
        dispatch_entry = TASK_DISPATCH.get(task.type.value)
        if dispatch_entry is None:
            return TaskResult(
                task_id=task.task_id,
                status=TaskStatus.FAILED,
                error=f"Unknown task type: {task.type.value}",
                error_type=ErrorType.UNKNOWN,
                worker_id=self.worker_id,
                execution_time=time.time() - start_time,
            )

        task_func, tool_key = dispatch_entry

        # 2. Resolve tool config
        tool_cfg = self.tools_config.get(tool_key, {})
        tool_path = tool_cfg.get("path", tool_key)
        default_params = tool_cfg.get("default_params", {})
        version_flag = tool_cfg.get("version_flag", "-version")

        # 3. Merge params: defaults ← task-specific
        merged_params = {**default_params, **task.params}

        # 4. Execute tool
        self.logger.info(
            f"Executing {task.type.value} on target={task.target} "
            f"(task_id={task.task_id})"
        )

        exec_result: TaskExecResult = task_func(
            target=task.target,
            params=merged_params,
            tool_path=tool_path,
            timeout=self.task_timeout,
            version_flag=version_flag,
        )

        execution_time = time.time() - start_time

        # 5. Handle execution errors
        if exec_result.error is not None:
            error_type = ErrorType(exec_result.error_type) if exec_result.error_type != "NONE" else ErrorType.TOOL_ERROR
            status = TaskStatus.TIMEOUT if error_type == ErrorType.TIMEOUT else TaskStatus.FAILED
            return TaskResult(
                task_id=task.task_id,
                status=status,
                error=exec_result.error,
                error_type=error_type,
                worker_id=self.worker_id,
                execution_time=execution_time,
                tool_version=exec_result.tool_version,
            )

        # 6. Parse output
        parse_warnings: List[str] = []
        parsed_data: Dict[str, Any] = {}
        try:
            parser = get_parser(tool_key)
            parsed_data = parser.parse(exec_result.stdout)
            parse_warnings = parser.warnings
            raw_line_count = parser.raw_line_count
        except Exception as exc:
            self.logger.warning(f"Parse error for task {task.task_id}: {exc}")
            parse_warnings.append(f"Parser exception: {exc}")
            parsed_data = {"raw_output_preview": exec_result.stdout[:2000]}
            raw_line_count = len(exec_result.stdout.splitlines())

        # 7. Build successful result
        return TaskResult(
            task_id=task.task_id,
            status=TaskStatus.COMPLETED,
            data=parsed_data,
            worker_id=self.worker_id,
            execution_time=execution_time,
            tool_version=exec_result.tool_version,
            raw_output_lines=raw_line_count,
            parse_warnings=parse_warnings,
        )

    # -- Main Loop -----------------------------------------------------------

    def _process_one(self, raw_payload: str) -> None:
        """
        Validate, execute, and return results for a single task JSON string.
        """
        task_id = "unknown"
        try:
            # 1. Deserialise
            data = json.loads(raw_payload)
            task_id = data.get("task_id", "unknown")

            # 2. Validate schema
            task = Task.from_dict(data)
            task_id = task.task_id

            # 3. Mark PROCESSING
            self._update_task_status(task_id, TaskStatus.PROCESSING)
            self._currently_processing.set()

            # 4. Execute
            result = self._execute_task(task)

            # 5. Update final status
            self._update_task_status(task_id, result.status)

            # 6. Push result
            self._push_result(result)

            self.logger.info(
                f"Task {task_id} completed: status={result.status.value}, "
                f"exec_time={result.execution_time:.2f}s"
            )

        except json.JSONDecodeError as exc:
            self.logger.error(f"Invalid JSON in task payload: {exc}")
            error_result = TaskResult(
                task_id=task_id,
                status=TaskStatus.FAILED,
                error=f"Invalid JSON payload: {exc}",
                error_type=ErrorType.UNKNOWN,
                worker_id=self.worker_id,
            )
            self._push_result(error_result)

        except (KeyError, ValueError) as exc:
            self.logger.error(f"Task schema validation failed: {exc}")
            error_result = TaskResult(
                task_id=task_id,
                status=TaskStatus.FAILED,
                error=f"Schema validation error: {exc}",
                error_type=ErrorType.UNKNOWN,
                worker_id=self.worker_id,
            )
            self._update_task_status(task_id, TaskStatus.FAILED)
            self._push_result(error_result)

        except Exception as exc:
            self.logger.error(
                f"Unexpected error processing task {task_id}: {exc}\n"
                f"{traceback.format_exc()}"
            )
            error_result = TaskResult(
                task_id=task_id,
                status=TaskStatus.FAILED,
                error=f"Unexpected worker error: {exc}",
                error_type=ErrorType.UNKNOWN,
                worker_id=self.worker_id,
            )
            self._update_task_status(task_id, TaskStatus.FAILED)
            self._push_result(error_result)

        finally:
            self._currently_processing.clear()

    def run(self) -> None:
        """
        Entry point — starts background threads, then enters the BLPOP loop.
        """
        self.logger.info(f"╔══════════════════════════════════════════════╗")
        self.logger.info(f"║  Centaur-Jarvis Recon Worker starting…      ║")
        self.logger.info(f"║  worker_id : {self.worker_id:<30s}  ║")
        self.logger.info(f"║  queue     : {self.queue_in:<30s}  ║")
        self.logger.info(f"║  PID       : {os.getpid():<30d}  ║")
        self.logger.info(f"╚══════════════════════════════════════════════╝")

        # Pre-flight checks
        self._check_tools()
        self._redis = self._connect_redis()

        # Start daemon threads
        heartbeat_thread = threading.Thread(
            target=self._heartbeat_loop, daemon=True, name="heartbeat"
        )
        heartbeat_thread.start()

        resource_thread = threading.Thread(
            target=self._resource_monitor_loop, daemon=True, name="resource-monitor"
        )
        resource_thread.start()

        # Main loop
        self.logger.info("Entering main BLPOP loop…")
        while not self._shutdown_event.is_set():
            try:
                # RAM guard — wait until RAM is acceptable
                if not self._ram_ok.is_set():
                    self.logger.debug("Waiting for RAM to free up…")
                    self._ram_ok.wait(timeout=self.ram_check_interval)
                    continue

                # Flush any buffered results
                self._flush_result_buffer()

                r = self._ensure_redis()
                result = r.blpop(self.queue_in, timeout=self.blpop_timeout)

                if result is None:
                    # Timeout — no task; loop back (allows shutdown check)
                    continue

                _queue_name, raw_payload = result
                self._process_one(raw_payload)

            except (redis.ConnectionError, redis.TimeoutError, OSError) as exc:
                self.logger.warning(f"Redis error in main loop: {exc}")
                self._redis = None  # force reconnect on next iteration
                time.sleep(2)

            except Exception as exc:
                self.logger.error(
                    f"Unhandled exception in main loop: {exc}\n"
                    f"{traceback.format_exc()}"
                )
                time.sleep(1)

        # Shutdown path
        self.logger.info("Shutdown event received. Exiting main loop.")
        self._flush_result_buffer()
        self.logger.info("Recon Worker shut down cleanly.")

    # -- Signal Handling -----------------------------------------------------

    def _handle_signal(self, signum: int, frame: Any) -> None:
        """
        Graceful shutdown handler for SIGTERM / SIGINT.
        """
        sig_name = signal.Signals(signum).name
        self.logger.info(f"Received {sig_name}. Initiating graceful shutdown…")
        self._shutdown_event.set()

        if self._currently_processing.is_set():
            self.logger.info(
                f"A task is in progress. Waiting up to {self.shutdown_timeout}s "
                f"for it to complete…"
            )
            # The main loop will finish after _process_one returns

    def install_signal_handlers(self) -> None:
        """Install SIGTERM/SIGINT handlers on the main thread."""
        signal.signal(signal.SIGTERM, self._handle_signal)
        signal.signal(signal.SIGINT, self._handle_signal)


# ---------------------------------------------------------------------------
# Entry Point
# ---------------------------------------------------------------------------

def main() -> None:
    """CLI entry point for the recon worker."""
    import argparse

    parser = argparse.ArgumentParser(
        description="Centaur-Jarvis Recon Worker",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "-c", "--config",
        help="Path to config YAML (default: auto-discover config.yaml)",
        default=None,
    )
    args = parser.parse_args()

    config = _load_config(args.config)
    worker = ReconWorker(config)
    worker.install_signal_handlers()
    worker.run()


if __name__ == "__main__":
    main()
