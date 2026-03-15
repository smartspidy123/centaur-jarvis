"""
server.py — HTTP + DNS callback server for OAST Listener.

Runs a FastAPI-based HTTP server (and optionally a DNS server) that captures
inbound callbacks from blind vulnerability payloads, serialises them, and
pushes them into Redis for the correlator to process.

Independently runnable:
    python -m modules.oast_listener.server

Signals:
    SIGTERM / SIGINT → graceful shutdown.
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import signal
import socket
import struct
import sys
import threading
import time
import traceback
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

import yaml

# ── Attempt shared logger; fall back to stdlib ──────────────────────────────
try:
    from shared.logger import get_logger
    logger = get_logger("oast_listener.server")
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
    logger = logging.getLogger("oast_listener.server")
    logger.addHandler(_handler)
    logger.setLevel(logging.INFO)

# ── Redis ───────────────────────────────────────────────────────────────────
try:
    import redis as redis_lib
except ImportError:
    redis_lib = None  # type: ignore[assignment]
    logger.warning("redis package not installed — callbacks will be logged only")

# ── FastAPI ─────────────────────────────────────────────────────────────────
try:
    from fastapi import FastAPI, Request, Response
    from fastapi.responses import PlainTextResponse
    import uvicorn
except ImportError:
    logger.error("fastapi/uvicorn not installed — HTTP server unavailable")
    FastAPI = None  # type: ignore[misc,assignment]

# ── dnslib (optional) ──────────────────────────────────────────────────────
try:
    from dnslib import DNSRecord, DNSHeader, RR, QTYPE, A as DNS_A
    from dnslib.server import DNSServer, BaseResolver, DNSLogger
    HAS_DNSLIB = True
except ImportError:
    HAS_DNSLIB = False
    logger.info("dnslib not installed — DNS server will not start")

# ── Local imports ──────────────────────────────────────────────────────────
from modules.oast_listener.models import Callback, CallbackType

# ============================================================================
# Configuration loader
# ============================================================================

_CONFIG_PATH = Path(__file__).parent / "config.yaml"


def load_config(path: Optional[Path] = None) -> Dict[str, Any]:
    """Load config.yaml with environment-variable overrides and safe defaults."""
    cfg_path = path or _CONFIG_PATH
    defaults: Dict[str, Any] = {
        "server": {
            "http": {
                "enabled": True,
                "host": "0.0.0.0",
                "port": 8080,
                "tls_enabled": False,
                "tls_cert": "",
                "tls_key": "",
                "max_body_size": 10240,
                "request_timeout": 30,
                "workers": 4,
            },
            "dns": {
                "enabled": False,
                "host": "0.0.0.0",
                "port": 5353,
                "domain": "oast.example.com",
                "response_ttl": 60,
                "resolve_ip": "127.0.0.1",
            },
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
            # Deep-merge file_cfg into defaults
            _deep_merge(defaults, file_cfg)
            logger.info("Configuration loaded", extra={"path": str(cfg_path)})
        else:
            logger.warning(
                "Config file not found, using defaults",
                extra={"path": str(cfg_path)},
            )
    except Exception as exc:
        logger.error(
            "Failed to load config, using defaults",
            extra={"error": str(exc)},
        )

    # Environment-variable overrides (highest priority)
    defaults["redis"]["host"] = os.getenv("OAST_REDIS_HOST", defaults["redis"]["host"])
    defaults["redis"]["port"] = int(
        os.getenv("OAST_REDIS_PORT", str(defaults["redis"]["port"]))
    )
    defaults["redis"]["password"] = os.getenv(
        "OAST_REDIS_PASSWORD", defaults["redis"].get("password")
    )
    defaults["server"]["http"]["port"] = int(
        os.getenv("OAST_HTTP_PORT", str(defaults["server"]["http"]["port"]))
    )
    defaults["server"]["dns"]["port"] = int(
        os.getenv("OAST_DNS_PORT", str(defaults["server"]["dns"]["port"]))
    )
    defaults["server"]["dns"]["domain"] = os.getenv(
        "OAST_DOMAIN", defaults["server"]["dns"]["domain"]
    )

    return defaults


def _deep_merge(base: dict, override: dict) -> None:
    """Recursively merge override into base."""
    for key, val in override.items():
        if key in base and isinstance(base[key], dict) and isinstance(val, dict):
            _deep_merge(base[key], val)
        else:
            base[key] = val


# ============================================================================
# Redis helper
# ============================================================================

class RedisConnection:
    """Resilient Redis connection with retry logic."""

    def __init__(self, config: Dict[str, Any]):
        self._config = config
        self._client: Optional[Any] = None
        self._connected = False

    def connect(self) -> bool:
        """Attempt to connect to Redis."""
        if redis_lib is None:
            logger.error("Redis library not installed")
            return False
        try:
            self._client = redis_lib.Redis(
                host=self._config["host"],
                port=self._config["port"],
                db=self._config.get("db", 0),
                password=self._config.get("password"),
                socket_timeout=self._config.get("connection_timeout", 5),
                socket_connect_timeout=self._config.get("connection_timeout", 5),
                decode_responses=True,
                retry_on_timeout=True,
            )
            self._client.ping()
            self._connected = True
            logger.info(
                "Redis connected",
                extra={
                    "host": self._config["host"],
                    "port": self._config["port"],
                },
            )
            return True
        except Exception as exc:
            self._connected = False
            logger.error("Redis connection failed", extra={"error": str(exc)})
            return False

    @property
    def client(self) -> Optional[Any]:
        return self._client

    @property
    def is_connected(self) -> bool:
        if not self._connected or not self._client:
            return False
        try:
            self._client.ping()
            return True
        except Exception:
            self._connected = False
            return False

    def push_callback(self, queue: str, callback: Callback) -> bool:
        """Push a callback to Redis list. Returns True on success."""
        if not self.is_connected:
            if not self.connect():
                return False
        try:
            self._client.lpush(queue, callback.to_json())  # type: ignore[union-attr]
            return True
        except Exception as exc:
            logger.error("Failed to push callback to Redis", extra={"error": str(exc)})
            self._connected = False
            return False


# ============================================================================
# Unique-ID extraction from URL / subdomain
# ============================================================================

# Pattern matches our generated unique IDs: {scan_id}-{vuln_type}-{hex8}
_UNIQUE_ID_PATTERN = re.compile(r"([a-zA-Z0-9_]+-[a-zA-Z0-9_]+-[a-f0-9]{8})")


def extract_unique_id(value: str) -> Optional[str]:
    """
    Extract the OAST unique identifier from a URL path or DNS subdomain.

    Examples:
        "/s1-blind_xss-a3f2c1d0"            → "s1-blind_xss-a3f2c1d0"
        "s1-blind_xss-a3f2c1d0.oast.ex.com" → "s1-blind_xss-a3f2c1d0"
        "/callback/s1-blind_xss-a3f2c1d0/x"  → "s1-blind_xss-a3f2c1d0"
    """
    if not value:
        return None
    match = _UNIQUE_ID_PATTERN.search(value)
    return match.group(1) if match else None


# ============================================================================
# FastAPI HTTP Server
# ============================================================================

# Module-level state for the server
_shutdown_event = threading.Event()
_redis_conn: Optional[RedisConnection] = None
_config: Dict[str, Any] = {}


def _create_app() -> "FastAPI":
    """Create and configure the FastAPI application."""
    if FastAPI is None:
        raise RuntimeError("FastAPI is not installed")

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        """Startup / shutdown lifecycle."""
        logger.info("OAST HTTP server starting up")
        yield
        logger.info("OAST HTTP server shutting down")

    app = FastAPI(
        title="Centaur-Jarvis OAST Listener",
        version="1.0.0",
        docs_url=None,    # Disable Swagger UI in production
        redoc_url=None,
        lifespan=lifespan,
    )

    # -- Catch-all route for every path and every method --
    @app.api_route(
        "/{full_path:path}",
        methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"],
    )
    async def catch_all(request: Request, full_path: str) -> Response:
        """Handle every inbound HTTP callback."""
        global _redis_conn, _config

        try:
            # Extract body safely
            body_bytes = b""
            try:
                body_bytes = await asyncio.wait_for(
                    request.body(),
                    timeout=_config.get("server", {})
                    .get("http", {})
                    .get("request_timeout", 30),
                )
            except asyncio.TimeoutError:
                body_bytes = b"[BODY_READ_TIMEOUT]"
            except Exception:
                body_bytes = b"[BODY_READ_ERROR]"

            max_body = (
                _config.get("server", {})
                .get("http", {})
                .get("max_body_size", 10240)
            )
            body_str = body_bytes[:max_body].decode("utf-8", errors="replace")
            if len(body_bytes) > max_body:
                body_str += "...[TRUNCATED]"

            # Extract headers safely
            headers_dict: Dict[str, str] = {}
            try:
                for k, v in request.headers.items():
                    headers_dict[k.lower()] = v
            except Exception:
                pass

            # Source IP
            source_ip = "0.0.0.0"
            if request.client:
                source_ip = request.client.host or "0.0.0.0"

            # Build full URL
            full_url = str(request.url)

            # Extract unique_id
            uid = extract_unique_id(full_path) or extract_unique_id(
                request.headers.get("host", "")
            )

            callback = Callback(
                callback_type=CallbackType.HTTP.value,
                source_ip=source_ip,
                url=full_url,
                method=request.method,
                headers=headers_dict,
                body=body_str,
                unique_id=uid,
            )
            callback.truncate_body()

            logger.info(
                "HTTP callback received",
                extra={
                    "source_ip": source_ip,
                    "method": request.method,
                    "path": full_path,
                    "unique_id": uid,
                },
            )

            # Push to Redis
            if _redis_conn:
                queue = (
                    _config.get("redis", {}).get("callback_queue", "oast:callbacks")
                )
                success = _redis_conn.push_callback(queue, callback)
                if not success:
                    logger.warning(
                        "Callback not persisted to Redis — will be lost",
                        extra={"callback_id": callback.callback_id},
                    )
            else:
                logger.warning("No Redis connection — callback logged only")

        except Exception as exc:
            logger.error(
                "Error processing HTTP callback",
                extra={"error": str(exc), "traceback": traceback.format_exc()},
            )

        # Always return 200 so the target doesn't retry / error out
        return PlainTextResponse("ok", status_code=200)

    # -- Health endpoint (excluded from catch-all by ordering) --
    @app.get("/healthz")
    async def healthz():
        redis_ok = _redis_conn.is_connected if _redis_conn else False
        return {
            "status": "UP",
            "redis": "CONNECTED" if redis_ok else "DISCONNECTED",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    return app


# ============================================================================
# DNS Server (optional, via dnslib)
# ============================================================================

class OASTDNSResolver:
    """Custom DNS resolver that logs every query as a callback."""

    def __init__(
        self,
        redis_conn: RedisConnection,
        config: Dict[str, Any],
    ):
        self._redis = redis_conn
        self._config = config
        self._base_domain = config.get("server", {}).get("dns", {}).get(
            "domain", "oast.example.com"
        )
        self._resolve_ip = config.get("server", {}).get("dns", {}).get(
            "resolve_ip", "127.0.0.1"
        )
        self._response_ttl = config.get("server", {}).get("dns", {}).get(
            "response_ttl", 60
        )

    def resolve(self, request, handler):
        """Handle a DNS request."""
        reply = request.reply()
        qname = str(request.q.qname).rstrip(".")
        qtype = QTYPE[request.q.qtype]

        # Extract source IP from handler
        source_ip = "0.0.0.0"
        try:
            source_ip = handler.client_address[0]
        except Exception:
            pass

        logger.info(
            "DNS callback received",
            extra={
                "domain": qname,
                "type": qtype,
                "source_ip": source_ip,
            },
        )

        # Extract unique_id from subdomain
        uid = extract_unique_id(qname)

        callback = Callback(
            callback_type=CallbackType.DNS.value,
            source_ip=source_ip,
            domain=qname,
            dns_record_type=str(qtype),
            unique_id=uid,
        )

        # Push to Redis
        queue = self._config.get("redis", {}).get("callback_queue", "oast:callbacks")
        self._redis.push_callback(queue, callback)

        # Always respond with configured IP so target sees a valid response
        if request.q.qtype == QTYPE.A:
            reply.add_answer(
                RR(qname, QTYPE.A, rdata=DNS_A(self._resolve_ip),
                   ttl=self._response_ttl)
            )

        return reply


def _start_dns_server(
    redis_conn: RedisConnection,
    config: Dict[str, Any],
) -> Optional[Any]:
    """Start the DNS server in a background thread. Returns DNSServer or None."""
    if not HAS_DNSLIB:
        logger.warning("dnslib not available — skipping DNS server")
        return None

    dns_cfg = config.get("server", {}).get("dns", {})
    if not dns_cfg.get("enabled", False):
        logger.info("DNS server disabled in config")
        return None

    try:
        resolver = OASTDNSResolver(redis_conn, config)
        dns_logger = DNSLogger(prefix=False)
        server = DNSServer(
            resolver,
            port=dns_cfg.get("port", 5353),
            address=dns_cfg.get("host", "0.0.0.0"),
            logger=dns_logger,
        )
        server.start_thread()
        logger.info(
            "DNS server started",
            extra={
                "host": dns_cfg.get("host"),
                "port": dns_cfg.get("port"),
                "domain": dns_cfg.get("domain"),
            },
        )
        return server
    except PermissionError:
        logger.error(
            "DNS server failed to start — insufficient permissions "
            "(port 53 requires root/CAP_NET_BIND_SERVICE). "
            "Continuing with HTTP only."
        )
        return None
    except Exception as exc:
        logger.error(
            "DNS server failed to start — continuing with HTTP only",
            extra={"error": str(exc), "traceback": traceback.format_exc()},
        )
        return None


# ============================================================================
# Graceful shutdown
# ============================================================================

def _signal_handler(signum: int, frame: Any) -> None:
    """Handle SIGTERM / SIGINT for graceful shutdown."""
    sig_name = signal.Signals(signum).name if hasattr(signal, "Signals") else str(signum)
    logger.info(f"Received {sig_name} — initiating graceful shutdown")
    _shutdown_event.set()


# ============================================================================
# Main entry point
# ============================================================================

def run_server(config_path: Optional[Path] = None) -> None:
    """
    Main entry point: load config, connect Redis, start HTTP + DNS servers.
    Blocks until shutdown signal received.
    """
    global _redis_conn, _config

    # Register signal handlers
    signal.signal(signal.SIGTERM, _signal_handler)
    signal.signal(signal.SIGINT, _signal_handler)

    # Load configuration
    _config = load_config(config_path)

    logger.info("OAST Listener server initializing", extra={"config_file": str(config_path or _CONFIG_PATH)})

    # Connect to Redis
    _redis_conn = RedisConnection(_config.get("redis", {}))
    redis_connected = _redis_conn.connect()
    if not redis_connected:
        logger.warning(
            "Starting without Redis — callbacks will be logged but not persisted. "
            "Retrying in background."
        )

    # Start DNS server (background thread)
    dns_server = _start_dns_server(_redis_conn, _config)

    # Start HTTP server
    http_cfg = _config.get("server", {}).get("http", {})
    if not http_cfg.get("enabled", True):
        logger.info("HTTP server disabled in config")
        # If DNS is also disabled, nothing to do
        if dns_server is None:
            logger.error("Both HTTP and DNS servers disabled — nothing to run")
            return
        # Wait for shutdown
        _shutdown_event.wait()
    else:
        if FastAPI is None:
            logger.error("FastAPI not installed — cannot start HTTP server")
            if dns_server is None:
                return
            _shutdown_event.wait()
        else:
            app = _create_app()

            ssl_keyfile = http_cfg.get("tls_key") or None
            ssl_certfile = http_cfg.get("tls_cert") or None
            if not http_cfg.get("tls_enabled", False):
                ssl_keyfile = None
                ssl_certfile = None

            uvicorn_config = uvicorn.Config(
                app,
                host=http_cfg.get("host", "0.0.0.0"),
                port=http_cfg.get("port", 8080),
                workers=1,  # We handle concurrency via async
                log_level="warning",  # We do our own logging
                ssl_keyfile=ssl_keyfile,
                ssl_certfile=ssl_certfile,
            )
            server = uvicorn.Server(uvicorn_config)

            logger.info(
                "HTTP server starting",
                extra={
                    "host": http_cfg.get("host"),
                    "port": http_cfg.get("port"),
                    "tls": http_cfg.get("tls_enabled", False),
                },
            )

            # Run uvicorn — it will block until shutdown
            # We set the shutdown event to stop uvicorn
            def _watch_shutdown():
                _shutdown_event.wait()
                server.should_exit = True

            watcher = threading.Thread(target=_watch_shutdown, daemon=True)
            watcher.start()

            try:
                server.run()
            except Exception as exc:
                logger.error(
                    "HTTP server error",
                    extra={"error": str(exc), "traceback": traceback.format_exc()},
                )

    # Cleanup
    if dns_server is not None:
        try:
            dns_server.stop()
            dns_server.server.server_close()
            logger.info("DNS server stopped")
        except Exception:
            pass

    logger.info("OAST Listener server shut down cleanly")


# ============================================================================
# Module direct execution
# ============================================================================

if __name__ == "__main__":
    run_server()
