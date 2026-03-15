"""
correlator.py — Callback correlator and payload generator for OAST Listener.

The correlator continuously pops callbacks from Redis (oast:callbacks),
matches them against registered payloads, deduplicates, checks TTL,
and pushes confirmed findings to results:incoming.

Also provides the `generate_payload()` function used by fuzzer/sniper modules.

Independently runnable:
    python -m modules.oast_listener.correlator

Signals:
    SIGTERM / SIGINT → graceful shutdown (finish current batch).
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
from typing import Any, Dict, List, Optional, Tuple

import yaml

# ── Attempt shared imports ──────────────────────────────────────────────────
try:
    from shared.logger import get_logger
    logger = get_logger("oast_listener.correlator")
except ImportError:
    import logging

    class _JsonFormatter(logging.Formatter):
        def format(self, record: logging.LogRecord) -> str:
            log_obj = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "level": record.levelname,
                "module": record.name,
                "message": record.getMessage(),
            }
            if record.exc_info and record.exc_info[0]:
                log_obj["exception"] = self.formatException(record.exc_info)
            return json.dumps(log_obj)

    _handler = logging.StreamHandler(sys.stdout)
    _handler.setFormatter(_JsonFormatter())
    logger = logging.getLogger("oast_listener.correlator")
    logger.addHandler(_handler)
    logger.setLevel(logging.INFO)

try:
    from shared.schemas import Task, TaskResult, TaskStatus
except ImportError:
    logger.warning("shared.schemas not available — using local stubs")

    class TaskStatus:
        COMPLETED = "COMPLETED"
        FAILED = "FAILED"
        RUNNING = "RUNNING"

    class TaskResult:
        pass

    class Task:
        pass

try:
    import redis as redis_lib
except ImportError:
    redis_lib = None  # type: ignore[assignment]
    logger.error("redis package not installed — correlator cannot function")

# ── Local imports ──────────────────────────────────────────────────────────
from modules.oast_listener.models import (
    Callback,
    CallbackType,
    OASTFinding,
    PayloadInfo,
    get_severity,
)

# ============================================================================
# Configuration
# ============================================================================

_CONFIG_PATH = Path(__file__).parent / "config.yaml"


def _load_config(path: Optional[Path] = None) -> Dict[str, Any]:
    """Load config with defaults (reuses server.py's pattern)."""
    cfg_path = path or _CONFIG_PATH
    defaults: Dict[str, Any] = {
        "server": {
            "http": {"port": 8080, "host": "0.0.0.0"},
            "dns": {"domain": "oast.example.com", "port": 5353},
        },
        "redis": {
            "host": "localhost",
            "port": 6379,
            "db": 0,
            "password": None,
            "callback_queue": "oast:callbacks",
            "payload_prefix": "oast:payload:",
            "result_queue": "results:incoming",
            "seen_set": "oast:seen",
            "stats_key": "oast:stats",
            "ttl": 86400,
            "connection_timeout": 5,
            "retry_interval": 3,
            "max_retries": 10,
        },
        "correlator": {
            "enabled": True,
            "poll_interval": 1,
            "batch_size": 10,
            "brpop_timeout": 5,
            "dedup_ttl": 172800,
        },
        "payload": {
            "id_separator": "-",
            "uuid_length": 8,
        },
    }
    try:
        if cfg_path.exists():
            with open(cfg_path, "r") as fh:
                file_cfg = yaml.safe_load(fh) or {}
            _deep_merge(defaults, file_cfg)
    except Exception as exc:
        logger.warning(f"Config load error: {exc}")

    # Env overrides
    defaults["redis"]["host"] = os.getenv("OAST_REDIS_HOST", defaults["redis"]["host"])
    defaults["redis"]["port"] = int(
        os.getenv("OAST_REDIS_PORT", str(defaults["redis"]["port"]))
    )
    defaults["redis"]["password"] = os.getenv(
        "OAST_REDIS_PASSWORD", defaults["redis"].get("password")
    )
    defaults["server"]["dns"]["domain"] = os.getenv(
        "OAST_DOMAIN", defaults["server"]["dns"]["domain"]
    )
    return defaults


def _deep_merge(base: dict, override: dict) -> None:
    for key, val in override.items():
        if key in base and isinstance(base[key], dict) and isinstance(val, dict):
            _deep_merge(base[key], val)
        else:
            base[key] = val


# ============================================================================
# Redis connection (re-usable by both correlator and generate_payload)
# ============================================================================

_redis_client: Optional[Any] = None
_module_config: Optional[Dict[str, Any]] = None


def _get_redis(config: Optional[Dict[str, Any]] = None) -> Any:
    """Lazy-init Redis client singleton."""
    global _redis_client, _module_config

    if config is not None:
        _module_config = config

    if _module_config is None:
        _module_config = _load_config()

    if _redis_client is not None:
        try:
            _redis_client.ping()
            return _redis_client
        except Exception:
            _redis_client = None

    if redis_lib is None:
        raise RuntimeError("redis package not installed")

    rcfg = _module_config.get("redis", {})
    _redis_client = redis_lib.Redis(
        host=rcfg.get("host", "localhost"),
        port=rcfg.get("port", 6379),
        db=rcfg.get("db", 0),
        password=rcfg.get("password"),
        socket_timeout=rcfg.get("connection_timeout", 5),
        socket_connect_timeout=rcfg.get("connection_timeout", 5),
        decode_responses=True,
        retry_on_timeout=True,
    )
    _redis_client.ping()
    return _redis_client


# ============================================================================
# Payload Generator (PUBLIC API)
# ============================================================================

def get_oast_url(config: Optional[Dict[str, Any]] = None) -> str:
    """Return the base OAST URL (HTTP) from config."""
    cfg = config or _module_config or _load_config()
    http_cfg = cfg.get("server", {}).get("http", {})
    host = http_cfg.get("host", "0.0.0.0")
    port = http_cfg.get("port", 8080)
    scheme = "https" if http_cfg.get("tls_enabled", False) else "http"

    # For external access, 0.0.0.0 isn't useful; use DNS domain as host
    dns_domain = cfg.get("server", {}).get("dns", {}).get("domain", "oast.example.com")
    base_host = dns_domain if host == "0.0.0.0" else host

    return f"{scheme}://{base_host}:{port}"


def generate_payload(
    task_id: str,
    scan_id: str,
    vuln_type: str,
    config: Optional[Dict[str, Any]] = None,
    redis_client: Optional[Any] = None,
) -> PayloadInfo:
    """
    Generate a unique OAST payload and register it in Redis.

    Used by fuzzer/sniper modules before injecting blind payloads.

    Args:
        task_id:      The parent task ID.
        scan_id:      The scan session ID.
        vuln_type:    Vulnerability type (e.g., "blind_xss", "blind_ssrf").
        config:       Optional config dict (uses module config if None).
        redis_client: Optional Redis client (uses module singleton if None).

    Returns:
        PayloadInfo with subdomain, URL, and unique_id.

    Raises:
        RuntimeError: If Redis is unavailable and payload can't be registered.
    """
    cfg = config or _module_config or _load_config()
    pcfg = cfg.get("payload", {})
    sep = pcfg.get("id_separator", "-")
    uid_len = pcfg.get("uuid_length", 8)
    ttl = cfg.get("redis", {}).get("ttl", 86400)
    prefix = cfg.get("redis", {}).get("payload_prefix", "oast:payload:")

    # Generate unique ID: {scan_id}-{vuln_type}-{short_uuid}
    short_uuid = uuid.uuid4().hex[:uid_len]
    # Sanitise scan_id and vuln_type (replace non-alnum with _)
    safe_scan = "".join(c if c.isalnum() or c == "_" else "_" for c in scan_id)
    safe_vuln = "".join(c if c.isalnum() or c == "_" else "_" for c in vuln_type)
    unique_id = f"{safe_scan}{sep}{safe_vuln}{sep}{short_uuid}"

    # Build subdomain and URL
    dns_domain = cfg.get("server", {}).get("dns", {}).get("domain", "oast.example.com")
    subdomain = f"{unique_id}.{dns_domain}"

    base_url = get_oast_url(cfg)
    callback_url = f"{base_url}/{unique_id}"

    now = datetime.now(timezone.utc).isoformat()

    payload = PayloadInfo(
        unique_id=unique_id,
        task_id=task_id,
        scan_id=scan_id,
        vuln_type=vuln_type,
        subdomain=subdomain,
        url=callback_url,
        created_at=now,
        ttl=ttl,
    )

    # Register in Redis
    try:
        r = redis_client or _get_redis(cfg)
        redis_key = f"{prefix}{unique_id}"
        r.set(redis_key, payload.to_json(), ex=ttl)
        logger.info(
            "Payload registered",
            extra={
                "unique_id": unique_id,
                "task_id": task_id,
                "scan_id": scan_id,
                "vuln_type": vuln_type,
                "ttl": ttl,
                "url": callback_url,
                "subdomain": subdomain,
            },
        )
    except Exception as exc:
        logger.error(
            "Failed to register payload in Redis",
            extra={"unique_id": unique_id, "error": str(exc)},
        )
        raise RuntimeError(
            f"Cannot register OAST payload — Redis unavailable: {exc}"
        ) from exc

    return payload


# ============================================================================
# Correlator statistics
# ============================================================================

class CorrelatorStats:
    """Thread-safe statistics tracker."""

    def __init__(self):
        self.total_callbacks: int = 0
        self.processed: int = 0
        self.expired: int = 0
        self.unknown: int = 0
        self.duplicates: int = 0
        self.errors: int = 0
        self.findings: List[Dict[str, Any]] = []

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_callbacks": self.total_callbacks,
            "processed": self.processed,
            "expired": self.expired,
            "unknown": self.unknown,
            "duplicates": self.duplicates,
            "errors": self.errors,
        }


# ============================================================================
# Correlator core logic
# ============================================================================

class Correlator:
    """
    OAST Callback Correlator.

    Continuously pops callbacks from Redis, correlates them against registered
    payloads, deduplicates, checks TTL, and pushes confirmed findings.
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self._config = config or _load_config()
        self._running = False
        self._stats = CorrelatorStats()
        self._redis: Optional[Any] = None

        # Config shortcuts
        rcfg = self._config.get("redis", {})
        ccfg = self._config.get("correlator", {})
        self._callback_queue = rcfg.get("callback_queue", "oast:callbacks")
        self._payload_prefix = rcfg.get("payload_prefix", "oast:payload:")
        self._result_queue = rcfg.get("result_queue", "results:incoming")
        self._seen_set = rcfg.get("seen_set", "oast:seen")
        self._poll_interval = ccfg.get("poll_interval", 1)
        self._batch_size = ccfg.get("batch_size", 10)
        self._brpop_timeout = ccfg.get("brpop_timeout", 5)
        self._dedup_ttl = ccfg.get("dedup_ttl", 172800)

    def _connect_redis(self) -> bool:
        """Connect or reconnect to Redis."""
        try:
            self._redis = _get_redis(self._config)
            return True
        except Exception as exc:
            logger.error(
                "Correlator Redis connection failed",
                extra={"error": str(exc)},
            )
            self._redis = None
            return False

    def _is_duplicate(self, callback_id: str) -> bool:
        """Check if this callback has already been processed."""
        if not self._redis:
            return False
        try:
            # SADD returns 0 if member already exists
            added = self._redis.sadd(self._seen_set, callback_id)
            if added == 0:
                return True
            # Set per-member expiry isn't possible on a set, so we manage
            # the entire set's TTL periodically, or use a sorted set.
            # For simplicity, we use a hash with TTL per key instead.
            # Actually, let's use individual keys for dedup:
            self._redis.delete(self._seen_set)  # Don't use set approach
            dedup_key = f"oast:dedup:{callback_id}"
            was_set = self._redis.set(dedup_key, "1", nx=True, ex=self._dedup_ttl)
            return was_set is None  # None means key already existed
        except Exception as exc:
            logger.warning(f"Dedup check error: {exc}")
            return False

    def _is_duplicate_v2(self, callback_id: str) -> bool:
        """
        Deduplicate using individual Redis keys with TTL.
        Returns True if this callback_id was already seen.
        """
        if not self._redis:
            return False
        try:
            dedup_key = f"oast:dedup:{callback_id}"
            # SET NX returns True if key was set (new), None if already existed
            result = self._redis.set(dedup_key, "1", nx=True, ex=self._dedup_ttl)
            if result is None:
                # Key already existed → duplicate
                return True
            return False
        except Exception as exc:
            logger.warning(f"Dedup check error: {exc}")
            return False

    def _lookup_payload(self, unique_id: str) -> Optional[PayloadInfo]:
        """Look up a registered payload by unique_id."""
        if not self._redis or not unique_id:
            return None
        try:
            redis_key = f"{self._payload_prefix}{unique_id}"
            raw = self._redis.get(redis_key)
            if raw is None:
                return None
            return PayloadInfo.from_json(raw)
        except Exception as exc:
            logger.warning(
                f"Payload lookup error for {unique_id}: {exc}"
            )
            return None

    def _build_finding(
        self,
        callback: Callback,
        payload: PayloadInfo,
    ) -> Dict[str, Any]:
        """Build a finding dictionary from matched callback + payload."""
        severity = get_severity(payload.vuln_type)

        finding = OASTFinding(
            finding_type=payload.vuln_type,
            severity=severity,
            payload_url=payload.url,
            callback={
                "timestamp": callback.timestamp,
                "source_ip": callback.source_ip,
                "url": callback.url,
                "domain": callback.domain,
                "method": callback.method,
                "headers": callback.headers,
                "body": callback.body,
                "callback_type": callback.callback_type,
                "dns_record_type": callback.dns_record_type,
            },
            payload_info={
                "task_id": payload.task_id,
                "scan_id": payload.scan_id,
                "vuln_type": payload.vuln_type,
                "subdomain": payload.subdomain,
                "created_at": payload.created_at,
            },
        )
        return finding.to_dict()

    def _build_result(
        self,
        task_id: str,
        findings: List[Dict[str, Any]],
        stats: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Build a TaskResult-compatible dictionary."""
        return {
            "task_id": task_id,
            "module": "oast_listener",
            "status": "COMPLETED",  # UPPERCASE per global rule
            "data": {
                "findings": findings,
                "stats": stats,
            },
        }

    def _push_result(self, result: Dict[str, Any]) -> bool:
        """Push a result to the results queue."""
        if not self._redis:
            return False
        try:
            self._redis.lpush(self._result_queue, json.dumps(result, default=str))
            logger.info(
                "Finding pushed to results queue",
                extra={
                    "task_id": result.get("task_id"),
                    "queue": self._result_queue,
                },
            )
            return True
        except Exception as exc:
            logger.error(f"Failed to push result: {exc}")
            return False

    def _process_callback(self, callback: Callback) -> None:
        """Process a single callback through the correlation pipeline."""
        self._stats.total_callbacks += 1

        # 1. Extract unique_id
        uid = callback.unique_id
        if not uid:
            # Try extracting from url or domain
            uid = None
            if callback.url:
                from modules.oast_listener.server import extract_unique_id
                uid = extract_unique_id(callback.url)
            if not uid and callback.domain:
                from modules.oast_listener.server import extract_unique_id
                uid = extract_unique_id(callback.domain)
            callback.unique_id = uid

        if not uid:
            # Malformed — no identifiable pattern
            logger.info(
                "Callback has no recognisable unique_id — discarding",
                extra={
                    "callback_id": callback.callback_id,
                    "url": callback.url,
                    "domain": callback.domain,
                },
            )
            self._stats.unknown += 1
            return

        # 2. Dedup check
        if self._is_duplicate_v2(callback.callback_id):
            logger.debug(
                "Duplicate callback — skipping",
                extra={"callback_id": callback.callback_id, "unique_id": uid},
            )
            self._stats.duplicates += 1
            return

        # 3. Lookup payload
        payload = self._lookup_payload(uid)
        if payload is None:
            logger.info(
                "No registered payload for unique_id — discarding",
                extra={"unique_id": uid, "callback_id": callback.callback_id},
            )
            self._stats.unknown += 1
            return

        # 4. Check TTL / expiry
        if payload.is_expired():
            logger.info(
                "Payload expired — callback ignored",
                extra={
                    "unique_id": uid,
                    "created_at": payload.created_at,
                    "ttl": payload.ttl,
                },
            )
            self._stats.expired += 1
            return

        # 5. Build finding and push result
        finding = self._build_finding(callback, payload)
        self._stats.findings.append(finding)
        self._stats.processed += 1

        result = self._build_result(
            task_id=payload.task_id,
            findings=[finding],
            stats=self._stats.to_dict(),
        )
        self._push_result(result)

        logger.info(
            "OAST finding confirmed",
            extra={
                "unique_id": uid,
                "vuln_type": payload.vuln_type,
                "severity": finding.get("severity", "UNKNOWN"),
                "task_id": payload.task_id,
                "source_ip": callback.source_ip,
            },
        )

    def _pop_callbacks(self) -> List[Callback]:
        """Pop up to batch_size callbacks from Redis."""
        callbacks: List[Callback] = []

        if not self._redis:
            return callbacks

        try:
            for _ in range(self._batch_size):
                # BRPOP with short timeout so we don't block forever
                result = self._redis.brpop(
                    self._callback_queue, timeout=self._brpop_timeout
                )
                if result is None:
                    break  # Queue empty / timeout
                _, raw_json = result
                cb = Callback.from_json(raw_json)
                callbacks.append(cb)
        except Exception as exc:
            logger.error(
                "Error popping callbacks from Redis",
                extra={"error": str(exc)},
            )

        return callbacks

    def run(self) -> None:
        """
        Main correlator loop. Runs until shutdown signal.
        """
        self._running = True
        logger.info("Correlator starting", extra={"config": {
            "queue": self._callback_queue,
            "batch_size": self._batch_size,
            "poll_interval": self._poll_interval,
        }})

        # Initial Redis connection
        retry_count = 0
        max_retries = self._config.get("redis", {}).get("max_retries", 10)
        retry_interval = self._config.get("redis", {}).get("retry_interval", 3)

        while self._running and not self._connect_redis():
            retry_count += 1
            if retry_count > max_retries:
                logger.error(
                    "Correlator giving up on Redis after max retries",
                    extra={"max_retries": max_retries},
                )
                return
            logger.warning(
                f"Redis not available, retrying ({retry_count}/{max_retries})"
            )
            time.sleep(retry_interval)
            if not self._running:
                return

        logger.info("Correlator connected to Redis and running")

        # Main loop
        while self._running:
            try:
                callbacks = self._pop_callbacks()
                if not callbacks:
                    time.sleep(self._poll_interval)
                    continue

                for cb in callbacks:
                    if not self._running:
                        logger.info("Shutdown during batch — finishing current callback")
                        self._process_callback(cb)
                        break
                    self._process_callback(cb)

            except Exception as exc:
                self._stats.errors += 1
                logger.error(
                    "Correlator loop error",
                    extra={"error": str(exc), "traceback": traceback.format_exc()},
                )
                # Brief sleep to avoid tight error loop
                time.sleep(self._poll_interval)

                # Attempt reconnect if Redis issue
                if not self._connect_redis():
                    logger.warning("Redis reconnection failed — will retry next cycle")

        # Final stats
        logger.info(
            "Correlator stopped",
            extra={"final_stats": self._stats.to_dict()},
        )

    def stop(self) -> None:
        """Signal the correlator to stop gracefully."""
        logger.info("Correlator stop requested")
        self._running = False

    @property
    def stats(self) -> CorrelatorStats:
        return self._stats


# ============================================================================
# Standalone entry point
# ============================================================================

_correlator_instance: Optional[Correlator] = None


def _signal_handler(signum: int, frame: Any) -> None:
    sig_name = signal.Signals(signum).name if hasattr(signal, "Signals") else str(signum)
    logger.info(f"Correlator received {sig_name}")
    if _correlator_instance:
        _correlator_instance.stop()


def run_correlator(config_path: Optional[Path] = None) -> None:
    """
    Run the correlator as a standalone process.
    """
    global _correlator_instance

    signal.signal(signal.SIGTERM, _signal_handler)
    signal.signal(signal.SIGINT, _signal_handler)

    config = _load_config(config_path)

    if not config.get("correlator", {}).get("enabled", True):
        logger.info("Correlator disabled in config — exiting")
        return

    _correlator_instance = Correlator(config)
    _correlator_instance.run()


if __name__ == "__main__":
    run_correlator()
