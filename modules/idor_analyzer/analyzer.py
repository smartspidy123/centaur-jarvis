#!/usr/bin/env python3
"""
analyzer.py — Main IDOR Analyzer worker.

Lifecycle:
    1. Read ``config.yaml``.
    2. Connect to Redis (with retry).
    3. BRPOP loop on ``queue:idor``.
    4. For each task:
       a. Validate payload.
       b. Load sessions (from payload or Redis).
       c. For each endpoint: send request as User A, then User B.
       d. Compare responses.
       e. Build findings list & stats.
       f. Push ``TaskResult`` to ``results:incoming``.
    5. On SIGTERM: finish current endpoint, drain buffer, exit.
"""

from __future__ import annotations

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

import requests as http_lib
import yaml

# ---------------------------------------------------------------------------
# Shared imports with graceful fallback
# ---------------------------------------------------------------------------
try:
    from shared.logger import get_logger
    logger = get_logger("idor_analyzer.worker")
except ImportError:
    import logging
    logging.basicConfig(
        level=logging.INFO,
        format='{"ts":"%(asctime)s","level":"%(levelname)s","module":"%(name)s","msg":"%(message)s"}',
    )
    logger = logging.getLogger("idor_analyzer.worker")

try:
    from shared.schemas import Task, TaskResult, TaskStatus
except ImportError:
    logger.warning("shared.schemas not available — using inline stubs")

    class TaskStatus:
        PENDING = "PENDING"
        PROCESSING = "PROCESSING"
        COMPLETED = "COMPLETED"
        FAILED = "FAILED"
        TIMEOUT = "TIMEOUT"

    class Task:
        """Minimal stub."""
        def __init__(self, **kwargs):
            for k, v in kwargs.items():
                setattr(self, k, v)

    class TaskResult:
        """Minimal stub."""
        def __init__(self, **kwargs):
            for k, v in kwargs.items():
                setattr(self, k, v)

try:
    import redis as redis_lib
except ImportError:
    redis_lib = None  # type: ignore[assignment]
    logger.error("redis package not installed — worker cannot start")

from modules.idor_analyzer.session_manager import SessionManager, SessionError
from modules.idor_analyzer.comparators import (
    ComparisonResult,
    ResponseComparator,
    ResponseData,
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
_THIS_DIR = Path(__file__).resolve().parent
_DEFAULT_CONFIG_PATH = _THIS_DIR / "config.yaml"


# ---------------------------------------------------------------------------
# Configuration loader
# ---------------------------------------------------------------------------
def load_config(path: Optional[Path] = None) -> Dict[str, Any]:
    """Load YAML config with env‑var overrides."""
    config_path = path or _DEFAULT_CONFIG_PATH
    config: Dict[str, Any] = {}
    if config_path.exists():
        with open(config_path, "r") as fh:
            config = yaml.safe_load(fh) or {}
        logger.info(f"Config loaded from {config_path}")
    else:
        logger.warning(f"Config file not found at {config_path} — using defaults")

    # Environment overrides
    redis_cfg = config.setdefault("redis", {})
    redis_cfg["host"] = os.getenv("REDIS_HOST", redis_cfg.get("host", "localhost"))
    redis_cfg["port"] = int(os.getenv("REDIS_PORT", str(redis_cfg.get("port", 6379))))
    redis_cfg["db"] = int(os.getenv("REDIS_DB", str(redis_cfg.get("db", 0))))
    redis_cfg["password"] = os.getenv("REDIS_PASSWORD", redis_cfg.get("password"))

    return config


# ---------------------------------------------------------------------------
# Redis helpers
# ---------------------------------------------------------------------------
class RedisManager:
    """Thin wrapper adding reconnection & buffering semantics."""

    def __init__(self, config: Dict[str, Any]):
        self._cfg = config.get("redis", {})
        self._worker_cfg = config.get("worker", {})
        self._client: Optional[Any] = None
        self._result_buffer: List[str] = []
        self._buffer_max = int(self._worker_cfg.get("result_buffer_max", 100))

    @property
    def client(self) -> Any:
        if self._client is None:
            self._connect()
        return self._client

    def _connect(self) -> None:
        if redis_lib is None:
            raise RuntimeError("redis package not installed")
        password = self._cfg.get("password")
        self._client = redis_lib.Redis(
            host=self._cfg.get("host", "localhost"),
            port=int(self._cfg.get("port", 6379)),
            db=int(self._cfg.get("db", 0)),
            password=password if password else None,
            decode_responses=True,
            socket_connect_timeout=5,
            socket_timeout=10,
            retry_on_timeout=True,
        )
        # Verify
        self._client.ping()
        logger.info("Redis connection established")

    def pop_task(self, queue: str, timeout: int = 1) -> Optional[str]:
        try:
            result = self.client.brpop(queue, timeout=timeout)
            if result:
                return result[1]  # (queue_name, payload)
        except redis_lib.ConnectionError:
            logger.warning("Redis connection lost during pop — reconnecting")
            self._client = None
            time.sleep(1)
        except Exception as exc:
            logger.error(f"Unexpected error during pop: {exc}")
            time.sleep(1)
        return None

    def set_status(self, task_id: str, status: str, extra: Optional[Dict] = None) -> None:
        prefix = self._cfg.get("status_prefix", "task:status:")
        key = f"{prefix}{task_id}"
        mapping: Dict[str, str] = {
            "status": status,
            "updated_at": datetime.now(timezone.utc).isoformat(),
        }
        if extra:
            mapping.update({k: str(v) for k, v in extra.items()})
        try:
            self.client.hset(key, mapping=mapping)
        except Exception as exc:
            logger.warning(f"Failed to set status for {task_id}: {exc}")

    def push_result(self, queue: str, result_json: str) -> None:
        try:
            self.client.lpush(queue, result_json)
            # Drain any buffered results
            self._drain_buffer(queue)
        except Exception as exc:
            logger.warning(f"Redis push failed — buffering result: {exc}")
            if len(self._result_buffer) < self._buffer_max:
                self._result_buffer.append(result_json)
            else:
                logger.error(
                    "Result buffer full — dropping oldest result to accommodate new one"
                )
                self._result_buffer.pop(0)
                self._result_buffer.append(result_json)

    def _drain_buffer(self, queue: str) -> None:
        """Push any buffered results that accumulated during outages."""
        drained = 0
        while self._result_buffer:
            item = self._result_buffer[0]
            try:
                self.client.lpush(queue, item)
                self._result_buffer.pop(0)
                drained += 1
            except Exception:
                break
        if drained:
            logger.info(f"Drained {drained} buffered results to Redis")

    def drain_all(self, queue: str) -> None:
        """Best‑effort drain at shutdown."""
        self._drain_buffer(queue)


# ---------------------------------------------------------------------------
# Worker
# ---------------------------------------------------------------------------
class IDORWorker:
    """Main worker loop for IDOR analysis."""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self._config = config or load_config()
        self._redis = RedisManager(self._config)
        self._comparator = ResponseComparator(
            ignore_fields=self._config.get("comparison", {}).get("ignore_fields", []),
            ignore_headers=self._config.get("comparison", {}).get("ignore_headers", []),
            diff_threshold=float(
                self._config.get("comparison", {}).get("diff_threshold", 0.80)
            ),
            max_diff_keys=int(
                self._config.get("comparison", {}).get("max_diff_keys", 200)
            ),
        )
        self._shutdown_requested = False
        self._current_task_id: Optional[str] = None

        # Register signal handlers
        signal.signal(signal.SIGTERM, self._handle_sigterm)
        signal.signal(signal.SIGINT, self._handle_sigterm)

    # ------------------------------------------------------------------
    # Signal handling
    # ------------------------------------------------------------------
    def _handle_sigterm(self, signum: int, frame: Any) -> None:
        sig_name = signal.Signals(signum).name if hasattr(signal, "Signals") else str(signum)
        logger.info(
            f"Received {sig_name} — will finish current endpoint and shut down"
        )
        self._shutdown_requested = True

    # ------------------------------------------------------------------
    # Main loop
    # ------------------------------------------------------------------
    def run(self) -> None:
        """Blocking main loop."""
        task_queue = self._config.get("redis", {}).get("task_queue", "queue:idor")
        poll_interval = int(
            self._config.get("worker", {}).get("poll_interval", 1)
        )

        logger.info(
            f"IDOR Analyzer worker started — listening on '{task_queue}'",
            extra={"config": {k: v for k, v in self._config.items() if k != "redis"}},
        )

        while not self._shutdown_requested:
            raw = self._redis.pop_task(task_queue, timeout=poll_interval)
            if raw is None:
                continue
            self._process_raw_task(raw)

        # Graceful drain
        result_queue = self._config.get("redis", {}).get("result_queue", "results:incoming")
        self._redis.drain_all(result_queue)
        logger.info("Worker shut down gracefully")

    # ------------------------------------------------------------------
    # Task processing
    # ------------------------------------------------------------------
    def _process_raw_task(self, raw: str) -> None:
        """Parse, validate, and execute a single task."""
        task_id = "unknown"
        result_queue = self._config.get("redis", {}).get("result_queue", "results:incoming")

        try:
            payload = json.loads(raw)
        except (json.JSONDecodeError, TypeError) as exc:
            logger.error(f"Invalid task JSON — skipping: {exc}", extra={"raw": raw[:500]})
            return

        task_id = payload.get("task_id", str(uuid.uuid4()))
        self._current_task_id = task_id

        logger.info(f"Processing task {task_id}", extra={"payload_keys": list(payload.keys())})

        try:
            # Validate
            errors = self._validate_payload(payload)
            if errors:
                self._fail_task(task_id, result_queue, errors, "VALIDATION_ERROR")
                return

            # Mark PROCESSING
            self._redis.set_status(task_id, TaskStatus.PROCESSING)

            # Execute
            result_data = self._execute_task(task_id, payload)

            # Push result
            status = TaskStatus.COMPLETED if not result_data.get("error") else TaskStatus.FAILED
            result_dict = {
                "task_id": task_id,
                "module": "idor_analyzer",
                "status": status,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "data": result_data,
            }
            self._redis.push_result(result_queue, json.dumps(result_dict, default=str))
            self._redis.set_status(task_id, status)
            logger.info(
                f"Task {task_id} finished with status {status}",
                extra={"findings_count": len(result_data.get("findings", []))},
            )

        except SessionError as exc:
            self._fail_task(task_id, result_queue, [str(exc)], exc.error_type)
        except Exception as exc:
            tb = traceback.format_exc()
            logger.error(f"Unhandled error for task {task_id}: {exc}\n{tb}")
            self._fail_task(task_id, result_queue, [str(exc), tb], "INTERNAL_ERROR")
        finally:
            self._current_task_id = None

    # ------------------------------------------------------------------
    # Validation
    # ------------------------------------------------------------------
    @staticmethod
    def _validate_payload(payload: Dict[str, Any]) -> List[str]:
        errors: List[str] = []
        if not payload.get("target"):
            errors.append("Missing required field: 'target'")
        if not payload.get("endpoints"):
            errors.append("Missing required field: 'endpoints'")
        elif not isinstance(payload["endpoints"], list):
            errors.append("'endpoints' must be a list")
        method = payload.get("method", "GET")
        if method.upper() not in ("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"):
            errors.append(f"Unsupported HTTP method: {method}")
        return errors

    # ------------------------------------------------------------------
    # Execution core
    # ------------------------------------------------------------------
    def _execute_task(
        self, task_id: str, payload: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Run IDOR tests across all endpoints and return result ``data``."""
        exec_cfg = self._config.get("execution", {})
        timeout = int(exec_cfg.get("timeout", 30))
        follow_redirects = bool(exec_cfg.get("follow_redirects", True))
        verify_ssl = bool(exec_cfg.get("verify_ssl", False))
        max_response_bytes = int(exec_cfg.get("max_response_bytes", 5 * 1024 * 1024))
        max_retries = int(exec_cfg.get("max_retries", 2))
        retry_backoff = float(exec_cfg.get("retry_backoff", 1.0))
        user_agent = exec_cfg.get("user_agent", "Centaur-Jarvis/IDOR-Analyzer/1.0")

        target = payload["target"].rstrip("/")
        endpoints: List[str] = payload["endpoints"]
        method = payload.get("method", "GET").upper()
        extra_params = payload.get("params")
        body = payload.get("body")
        extra_headers = payload.get("headers", {})

        # --- Session setup ---
        session_mgr = SessionManager(
            redis_client=self._redis.client,
            token_key_prefix=self._config.get("redis", {}).get(
                "token_key_prefix", "auth:token:"
            ),
        )
        session_mgr.load_sessions(payload.get("auth_tokens"))
        auth_a, auth_b = session_mgr.get_both_sessions()

        findings: List[Dict[str, Any]] = []
        stats = {
            "total_endpoints": len(endpoints),
            "tested": 0,
            "skipped": 0,
            "suspicious": 0,
            "errors": 0,
            "start_time": datetime.now(timezone.utc).isoformat(),
        }

        for idx, endpoint in enumerate(endpoints):
            if self._shutdown_requested:
                logger.info(
                    f"Shutdown requested — stopping after {idx}/{len(endpoints)} endpoints"
                )
                stats["skipped"] = len(endpoints) - idx
                break

            endpoint_url = self._build_url(target, endpoint)
            logger.info(
                f"[{idx+1}/{len(endpoints)}] Testing {method} {endpoint_url}"
            )

            # Build requests
            base_headers = {"User-Agent": user_agent}
            base_headers.update(extra_headers)

            # -- Request as User A --
            resp_a = self._make_request(
                method=method,
                url=endpoint_url,
                session_auth=auth_a,
                base_headers=base_headers,
                params=extra_params,
                body=body,
                timeout=timeout,
                follow_redirects=follow_redirects,
                verify_ssl=verify_ssl,
                max_bytes=max_response_bytes,
                max_retries=max_retries,
                retry_backoff=retry_backoff,
            )

            # -- Request as User B --
            resp_b = self._make_request(
                method=method,
                url=endpoint_url,
                session_auth=auth_b,
                base_headers=base_headers,
                params=extra_params,
                body=body,
                timeout=timeout,
                follow_redirects=follow_redirects,
                verify_ssl=verify_ssl,
                max_bytes=max_response_bytes,
                max_retries=max_retries,
                retry_backoff=retry_backoff,
            )

            # -- Compare --
            comparison = self._comparator.compare_responses(resp_a, resp_b)
            stats["tested"] += 1

            if comparison.suspicious:
                stats["suspicious"] += 1
                finding = self._build_finding(
                    endpoint=endpoint,
                    url=endpoint_url,
                    method=method,
                    comparison=comparison,
                    resp_a=resp_a,
                    resp_b=resp_b,
                )
                findings.append(finding)
                logger.warning(
                    f"IDOR SUSPECTED at {endpoint_url}",
                    extra={"confidence": comparison.confidence},
                )
            elif resp_a.error or resp_b.error:
                stats["errors"] += 1

        stats["end_time"] = datetime.now(timezone.utc).isoformat()
        stats["findings_count"] = len(findings)

        return {
            "findings": findings,
            "stats": stats,
            "target": target,
            "method": method,
        }

    # ------------------------------------------------------------------
    # HTTP request helper
    # ------------------------------------------------------------------
    def _make_request(
        self,
        method: str,
        url: str,
        session_auth: Any,
        base_headers: Dict[str, str],
        params: Optional[Dict] = None,
        body: Optional[Any] = None,
        timeout: int = 30,
        follow_redirects: bool = True,
        verify_ssl: bool = False,
        max_bytes: int = 5 * 1024 * 1024,
        max_retries: int = 2,
        retry_backoff: float = 1.0,
    ) -> ResponseData:
        """Make an HTTP request with retry logic; return ``ResponseData``."""
        headers = dict(base_headers)
        headers.update(session_auth.headers)
        cookies = dict(session_auth.cookies)

        kwargs: Dict[str, Any] = {
            "method": method,
            "url": url,
            "headers": headers,
            "cookies": cookies,
            "timeout": timeout,
            "allow_redirects": follow_redirects,
            "verify": verify_ssl,
            "params": params,
        }

        # Body handling
        if body is not None and method in ("POST", "PUT", "PATCH"):
            if isinstance(body, (dict, list)):
                kwargs["json"] = body
            else:
                kwargs["data"] = body

        last_error: Optional[str] = None
        for attempt in range(max_retries + 1):
            try:
                resp = http_lib.request(**kwargs)
                return ResponseData.from_requests_response(resp, max_bytes=max_bytes)
            except http_lib.exceptions.Timeout:
                last_error = f"Timeout after {timeout}s (attempt {attempt+1})"
                logger.warning(last_error)
            except http_lib.exceptions.ConnectionError as exc:
                last_error = f"Connection error: {exc} (attempt {attempt+1})"
                logger.warning(last_error)
            except http_lib.exceptions.RequestException as exc:
                last_error = f"Request failed: {exc} (attempt {attempt+1})"
                logger.warning(last_error)
            except Exception as exc:
                last_error = f"Unexpected error: {exc} (attempt {attempt+1})"
                logger.error(last_error)

            if attempt < max_retries:
                time.sleep(retry_backoff * (attempt + 1))

        return ResponseData.from_error(last_error or "Unknown request error")

    # ------------------------------------------------------------------
    # Finding builder
    # ------------------------------------------------------------------
    @staticmethod
    def _build_finding(
        endpoint: str,
        url: str,
        method: str,
        comparison: ComparisonResult,
        resp_a: ResponseData,
        resp_b: ResponseData,
    ) -> Dict[str, Any]:
        severity = "HIGH"
        if comparison.confidence >= 0.9:
            severity = "CRITICAL"
        elif comparison.confidence >= 0.7:
            severity = "HIGH"
        elif comparison.confidence >= 0.4:
            severity = "MEDIUM"
        else:
            severity = "LOW"

        return {
            "type": "IDOR",
            "severity": severity,
            "confidence": round(comparison.confidence, 4),
            "endpoint": endpoint,
            "url": url,
            "method": method,
            "details": {
                "status_code_a": resp_a.status_code,
                "status_code_b": resp_b.status_code,
                "body_similarity": round(comparison.body_similarity, 4),
                "notes": comparison.notes,
                "differences": comparison.differences,
            },
            "recommendation": (
                "Implement object‑level authorization checks. Ensure that "
                "the authenticated user owns or has permission to access "
                "the requested resource before returning it."
            ),
            "owasp": "API1:2023 Broken Object Level Authorization",
            "cwe": "CWE-639: Authorization Bypass Through User-Controlled Key",
            "detected_at": datetime.now(timezone.utc).isoformat(),
        }

    # ------------------------------------------------------------------
    # Failure helper
    # ------------------------------------------------------------------
    def _fail_task(
        self,
        task_id: str,
        result_queue: str,
        errors: List[str],
        error_type: str,
    ) -> None:
        result_dict = {
            "task_id": task_id,
            "module": "idor_analyzer",
            "status": TaskStatus.FAILED,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "error_type": error_type,
            "data": {
                "findings": [],
                "stats": {"errors": len(errors)},
                "errors": errors,
            },
        }
        self._redis.push_result(result_queue, json.dumps(result_dict, default=str))
        self._redis.set_status(task_id, TaskStatus.FAILED, {"error_type": error_type})
        logger.error(
            f"Task {task_id} failed: {error_type}",
            extra={"errors": errors},
        )

    # ------------------------------------------------------------------
    # URL builder
    # ------------------------------------------------------------------
    @staticmethod
    def _build_url(base: str, endpoint: str) -> str:
        """Join base URL and endpoint path, handling edge cases."""
        if endpoint.startswith(("http://", "https://")):
            return endpoint
        base = base.rstrip("/")
        endpoint = endpoint if endpoint.startswith("/") else f"/{endpoint}"
        return f"{base}{endpoint}"


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
def main() -> None:
    """CLI entry point."""
    config_path: Optional[Path] = None
    if len(sys.argv) > 1:
        config_path = Path(sys.argv[1])

    config = load_config(config_path)
    worker = IDORWorker(config)
    worker.run()


if __name__ == "__main__":
    main()
