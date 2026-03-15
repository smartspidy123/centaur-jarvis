"""
core/orchestrator.py — The Brain of Centaur-Jarvis

This module implements the central orchestrator responsible for:
- Task queue management with deduplication and dead-letter routing
- Worker heartbeat monitoring with stale detection and task requeue
- Token bucket rate limiting per target (atomic via Lua scripts)
- Circuit breaker per target (CLOSED → OPEN → HALF_OPEN state machine)
- Graceful shutdown with state persistence
- Advanced telemetry and Discord alerting

Architecture Philosophy:
    - No silent failures: every error is logged with context
    - Plug-and-play modularity: orchestrator survives component failures
    - Idempotency & Recovery: crash-safe, Redis-backed state
    - Telemetry first: every state change is observable

Dependencies:
    - redis (pip install redis)
    - pyyaml (pip install pyyaml)
    - requests (pip install requests)
    - shared.schemas (Task, TaskResult, TaskStatus, TaskType)
    - shared.logger (get_logger)

Sample config/core.yaml:
    ---
    redis:
      host: "127.0.0.1"
      port: 6379
      password: null
      db: 0
      max_connections: 50
      socket_timeout: 5
      socket_connect_timeout: 5
      retry_on_timeout: true

    orchestrator:
      task_timeout: 300          # seconds before PROCESSING tasks auto-fail
      max_retries: 3
      shutdown_timeout: 30       # seconds to wait for graceful shutdown
      dedup_expiry: 86400        # 24h in seconds
      delayed_queue_poll_interval: 1  # seconds between delayed queue checks
      heartbeat_check_interval: 60    # seconds between heartbeat scans
      heartbeat_stale_threshold: 90   # seconds before worker considered dead
      result_poll_timeout: 2          # BLPOP timeout for results
      task_poll_timeout: 2            # BLPOP timeout for incoming tasks

    rate_limit:
      default_rate: 10           # tokens per second
      default_burst: 20          # max tokens in bucket
      delay_on_empty: 1.0        # seconds to delay when no tokens
      overrides:                 # per-domain overrides
        example.com:
          rate: 5
          burst: 10

    circuit_breaker:
      failure_threshold: 5
      recovery_timeout: 30       # seconds in OPEN before HALF_OPEN
      half_open_max_calls: 2
      countable_errors:          # error types that increment failure count
        - "CONNECTION_ERROR"
        - "TIMEOUT"
        - "SERVER_ERROR_5XX"
      non_countable_errors:      # error types that do NOT affect circuit
        - "WAF_BLOCK_403"
        - "RATE_LIMIT_429"

    alerting:
      discord_webhook_url: null  # Set to Discord webhook URL for alerts
      webhook_max_retries: 3
      webhook_retry_delay: 2     # seconds between retry attempts

Testing (manual):
    1. Start Redis: redis-server
    2. Create config/core.yaml with above structure
    3. Push a test task:
       redis-cli LPUSH tasks:incoming '{"task_id":"test-001","type":"RECON_SUBDOMAIN","target":"https://example.com","params":{}}'
    4. Run orchestrator:
       python -c "from core.orchestrator import Orchestrator; o = Orchestrator(); o.start()"
    5. Check Redis keys:
       redis-cli KEYS "*"
       redis-cli HGETALL task:test-001
    6. Simulate worker result:
       redis-cli LPUSH results:incoming '{"task_id":"test-001","status":"COMPLETED","data":{"subdomains":["a.example.com"]}}'
    7. Test graceful shutdown: Ctrl+C
    8. Test circuit breaker: push 5+ failing results for same target
    9. Test rate limiting: push many tasks for same target rapidly

Author: Centaur-Jarvis Core Team
License: MIT
"""

from __future__ import annotations

import json
import os
import signal
import sys
import threading
import time
import traceback
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Optional
from urllib.parse import urlparse

import redis
import requests
import yaml

# ---------------------------------------------------------------------------
# External dependency stubs — in production these come from shared.*
# ---------------------------------------------------------------------------
try:
    from shared.logger import get_logger
except ImportError:
    import logging

    def get_logger(name: str = "orchestrator") -> logging.Logger:
        """Fallback logger when shared.logger is unavailable."""
        logger = logging.getLogger(name)
        if not logger.handlers:
            handler = logging.StreamHandler(sys.stdout)
            handler.setFormatter(
                logging.Formatter(
                    "[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s",
                    datefmt="%Y-%m-%dT%H:%M:%S%z",
                )
            )
            logger.addHandler(handler)
            logger.setLevel(logging.DEBUG)
        return logger

try:
    from shared.schemas import Task, TaskResult, TaskStatus, TaskType
except ImportError:
    # Minimal stubs so the orchestrator can run standalone for testing.
    # In production, shared/schemas.py provides full Pydantic models.

    class TaskStatus(str, Enum):
        PENDING = "PENDING"
        QUEUED = "QUEUED"
        PROCESSING = "PROCESSING"
        COMPLETED = "COMPLETED"
        FAILED = "FAILED"
        DEAD = "DEAD"
        DELAYED = "DELAYED"

    class TaskType(str, Enum):
        RECON_SUBDOMAIN = "RECON_SUBDOMAIN"
        RECON_PORT_SCAN = "RECON_PORT_SCAN"
        RECON_TECH_DETECT = "RECON_TECH_DETECT"
        RECON_CRAWL = "RECON_CRAWL"
        JS_ANALYSIS = "JS_ANALYSIS"
        IDOR_CHECK = "IDOR_CHECK"
        FUZZ = "FUZZ"
        NUCLEI_TEMPLATE_GEN = "NUCLEI_TEMPLATE_GEN"
        PLAYWRIGHT_RENDER = "PLAYWRIGHT_RENDER"
        GENERIC = "GENERIC"

    @dataclass
    class Task:
        task_id: str
        type: str  # TaskType value
        target: str
        params: dict = field(default_factory=dict)
        priority: int = 0
        webhook_url: str | None = None
        retry_count: int = 0
        max_retries: int = 3
        created_at: str = ""
        metadata: dict = field(default_factory=dict)

        def __post_init__(self):
            if not self.created_at:
                self.created_at = datetime.now(timezone.utc).isoformat()

        def to_dict(self) -> dict:
            return {
                "task_id": self.task_id,
                "type": self.type,
                "target": self.target,
                "params": self.params,
                "priority": self.priority,
                "webhook_url": self.webhook_url,
                "retry_count": self.retry_count,
                "max_retries": self.max_retries,
                "created_at": self.created_at,
                "metadata": self.metadata,
            }

        @classmethod
        def from_dict(cls, data: dict) -> "Task":
            return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})

    @dataclass
    class TaskResult:
        task_id: str
        status: str  # TaskStatus value
        data: dict = field(default_factory=dict)
        error: str | None = None
        error_type: str | None = None  # CONNECTION_ERROR, TIMEOUT, SERVER_ERROR_5XX, WAF_BLOCK_403, RATE_LIMIT_429
        worker_id: str | None = None
        completed_at: str = ""

        def __post_init__(self):
            if not self.completed_at:
                self.completed_at = datetime.now(timezone.utc).isoformat()

        @classmethod
        def from_dict(cls, data: dict) -> "TaskResult":
            return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
REDIS_KEY_INCOMING = "tasks:incoming"
REDIS_KEY_DEAD = "tasks:dead"
REDIS_KEY_DELAYED = "tasks:delayed"
REDIS_KEY_RESULTS = "results:incoming"
REDIS_KEY_PROCESSED_IDS = "processed_task_ids"
REDIS_KEY_TASK_PREFIX = "task:"
REDIS_KEY_WORKER_HB_PREFIX = "worker:heartbeat:"
REDIS_KEY_CIRCUIT_PREFIX = "circuit:"
REDIS_KEY_RATE_LIMIT_PREFIX = "rate_limit:"

# Queue routing map prefixes/names
QUEUE_RECON = "queue:recon"
QUEUE_AI_ROUTING = "queue:ai_routing"
QUEUE_NUCLEI = "queue:nuclei_sniper"
QUEUE_PLAYWRIGHT = "queue:playwright"
QUEUE_DEFAULT = "queue:default"

# Circuit breaker states
CB_CLOSED = "CLOSED"
CB_OPEN = "OPEN"
CB_HALF_OPEN = "HALF_OPEN"

# Error types that should trigger circuit breaker
CIRCUIT_COUNTABLE_DEFAULTS = {"CONNECTION_ERROR", "TIMEOUT", "SERVER_ERROR_5XX"}

# ---------------------------------------------------------------------------
# Lua Scripts — atomic Redis operations
# ---------------------------------------------------------------------------

# Token bucket: atomically check & consume a token.
# KEYS[1] = rate_limit:{domain}
# ARGV[1] = rate (tokens/sec), ARGV[2] = burst (max tokens), ARGV[3] = current timestamp (float)
# Returns: remaining tokens after consume, or -1 if bucket empty
LUA_TOKEN_BUCKET = """
local key = KEYS[1]
local rate = tonumber(ARGV[1])
local burst = tonumber(ARGV[2])
local now = tonumber(ARGV[3])

local bucket = redis.call('HMGET', key, 'tokens', 'last_refill')
local tokens = tonumber(bucket[1])
local last_refill = tonumber(bucket[2])

if tokens == nil then
    -- Initialize bucket
    tokens = burst
    last_refill = now
end

-- Refill tokens based on elapsed time
local elapsed = math.max(0, now - last_refill)
local refill = elapsed * rate
tokens = math.min(burst, tokens + refill)
last_refill = now

if tokens >= 1 then
    tokens = tokens - 1
    redis.call('HMSET', key, 'tokens', tostring(tokens), 'last_refill', tostring(last_refill))
    redis.call('EXPIRE', key, 3600)  -- 1h expiry for cleanup
    return tokens
else
    -- No tokens, update state but don't consume
    redis.call('HMSET', key, 'tokens', tostring(tokens), 'last_refill', tostring(last_refill))
    redis.call('EXPIRE', key, 3600)
    return -1
end
"""

# Circuit breaker: atomically increment failure and check threshold.
# KEYS[1] = circuit:{target}
# ARGV[1] = failure_threshold, ARGV[2] = current timestamp, ARGV[3] = recovery_timeout
# Returns: new state as string
LUA_CIRCUIT_RECORD_FAILURE = """
local key = KEYS[1]
local threshold = tonumber(ARGV[1])
local now = tonumber(ARGV[2])
local recovery_timeout = tonumber(ARGV[3])

local state = redis.call('HGET', key, 'state')
if state == false or state == nil then
    state = 'CLOSED'
end

if state == 'OPEN' then
    -- Check if recovery timeout has elapsed
    local open_time = tonumber(redis.call('HGET', key, 'open_time') or '0')
    if (now - open_time) >= recovery_timeout then
        state = 'HALF_OPEN'
        redis.call('HSET', key, 'state', 'HALF_OPEN')
        redis.call('HSET', key, 'half_open_calls', '0')
    end
    -- If still OPEN, just return
    return state
end

-- Increment failures
local failures = tonumber(redis.call('HGET', key, 'failures') or '0') + 1
redis.call('HSET', key, 'failures', tostring(failures))
redis.call('HSET', key, 'last_failure', tostring(now))

if state == 'HALF_OPEN' then
    -- Any failure in HALF_OPEN reopens circuit
    redis.call('HMSET', key, 'state', 'OPEN', 'open_time', tostring(now), 'failures', tostring(failures))
    redis.call('EXPIRE', key, 86400)
    return 'OPEN'
end

-- CLOSED state
if failures >= threshold then
    redis.call('HMSET', key, 'state', 'OPEN', 'open_time', tostring(now))
    redis.call('EXPIRE', key, 86400)
    return 'OPEN'
end

redis.call('EXPIRE', key, 86400)
return 'CLOSED'
"""

# Circuit breaker: record success (for HALF_OPEN → CLOSED transition)
# KEYS[1] = circuit:{target}
# ARGV[1] = half_open_max_calls
# Returns: new state
LUA_CIRCUIT_RECORD_SUCCESS = """
local key = KEYS[1]
local half_open_max = tonumber(ARGV[1])

local state = redis.call('HGET', key, 'state')
if state == false or state == nil then
    state = 'CLOSED'
end

if state == 'HALF_OPEN' then
    local calls = tonumber(redis.call('HGET', key, 'half_open_successes') or '0') + 1
    redis.call('HSET', key, 'half_open_successes', tostring(calls))
    if calls >= half_open_max then
        -- All test calls succeeded, close circuit
        redis.call('HMSET', key, 'state', 'CLOSED', 'failures', '0',
                    'half_open_successes', '0', 'half_open_calls', '0')
        redis.call('EXPIRE', key, 86400)
        return 'CLOSED'
    end
    redis.call('EXPIRE', key, 86400)
    return 'HALF_OPEN'
end

-- If CLOSED, reset failures on success
if state == 'CLOSED' then
    redis.call('HSET', key, 'failures', '0')
    redis.call('EXPIRE', key, 86400)
end

return state
"""

# Circuit breaker: check if target is allowed (returns state + remaining open time)
# KEYS[1] = circuit:{target}
# ARGV[1] = recovery_timeout, ARGV[2] = now, ARGV[3] = half_open_max_calls
# Returns: {state, remaining_open_seconds_or_0, half_open_calls_remaining}
LUA_CIRCUIT_CHECK = """
local key = KEYS[1]
local recovery_timeout = tonumber(ARGV[1])
local now = tonumber(ARGV[2])
local half_open_max = tonumber(ARGV[3])

local state = redis.call('HGET', key, 'state')
if state == false or state == nil then
    return {'CLOSED', '0', '0'}
end

if state == 'OPEN' then
    local open_time = tonumber(redis.call('HGET', key, 'open_time') or '0')
    local elapsed = now - open_time
    if elapsed >= recovery_timeout then
        -- Transition to HALF_OPEN
        redis.call('HMSET', key, 'state', 'HALF_OPEN', 'half_open_calls', '0', 'half_open_successes', '0')
        redis.call('EXPIRE', key, 86400)
        return {'HALF_OPEN', '0', tostring(half_open_max)}
    else
        local remaining = recovery_timeout - elapsed
        return {'OPEN', tostring(remaining), '0'}
    end
end

if state == 'HALF_OPEN' then
    local calls = tonumber(redis.call('HGET', key, 'half_open_calls') or '0')
    local remaining = half_open_max - calls
    if remaining <= 0 then
        -- No more half-open calls allowed; wait for results
        return {'HALF_OPEN', '0', '0'}
    end
    -- Increment half_open_calls
    redis.call('HSET', key, 'half_open_calls', tostring(calls + 1))
    redis.call('EXPIRE', key, 86400)
    return {'HALF_OPEN', '0', tostring(remaining - 1)}
end

return {'CLOSED', '0', '0'}
"""


# ---------------------------------------------------------------------------
# Configuration Loader
# ---------------------------------------------------------------------------
@dataclass
class RedisConfig:
    host: str = "127.0.0.1"
    port: int = 6379
    password: str | None = None
    db: int = 0
    max_connections: int = 50
    socket_timeout: int = 5
    socket_connect_timeout: int = 5
    retry_on_timeout: bool = True


@dataclass
class RateLimitConfig:
    default_rate: float = 10.0
    default_burst: float = 20.0
    delay_on_empty: float = 1.0
    overrides: dict[str, dict[str, float]] = field(default_factory=dict)

    def get_rate_for_domain(self, domain: str) -> tuple[float, float]:
        """Returns (rate, burst) for a given domain."""
        if domain in self.overrides:
            return (
                self.overrides[domain].get("rate", self.default_rate),
                self.overrides[domain].get("burst", self.default_burst),
            )
        return (self.default_rate, self.default_burst)


@dataclass
class CircuitBreakerConfig:
    failure_threshold: int = 5
    recovery_timeout: int = 30
    half_open_max_calls: int = 2
    countable_errors: set[str] = field(default_factory=lambda: CIRCUIT_COUNTABLE_DEFAULTS.copy())
    non_countable_errors: set[str] = field(default_factory=lambda: {"WAF_BLOCK_403", "RATE_LIMIT_429"})


@dataclass
class AlertingConfig:
    discord_webhook_url: str | None = None
    webhook_max_retries: int = 3
    webhook_retry_delay: float = 2.0


@dataclass
class OrchestratorConfig:
    task_timeout: int = 300
    max_retries: int = 3
    shutdown_timeout: int = 30
    dedup_expiry: int = 86400
    delayed_queue_poll_interval: float = 1.0
    heartbeat_check_interval: int = 60
    heartbeat_stale_threshold: int = 90
    result_poll_timeout: int = 2
    task_poll_timeout: int = 2


@dataclass
class FullConfig:
    redis: RedisConfig = field(default_factory=RedisConfig)
    orchestrator: OrchestratorConfig = field(default_factory=OrchestratorConfig)
    rate_limit: RateLimitConfig = field(default_factory=RateLimitConfig)
    circuit_breaker: CircuitBreakerConfig = field(default_factory=CircuitBreakerConfig)
    alerting: AlertingConfig = field(default_factory=AlertingConfig)


def load_config(config_path: str = "config/core.yaml") -> FullConfig:
    """Load configuration from YAML file with defaults fallback.

    If the config file is missing, defaults are used (allows running without config).
    Every config key has a sane default so partial configs are fine.
    """
    config = FullConfig()
    path = Path(config_path)

    if not path.exists():
        # Try relative to project root
        alt_path = Path(__file__).parent.parent / config_path
        if alt_path.exists():
            path = alt_path

    if path.exists():
        try:
            with open(path, "r") as f:
                raw = yaml.safe_load(f) or {}

            if "redis" in raw:
                config.redis = RedisConfig(**{
                    k: v for k, v in raw["redis"].items()
                    if k in RedisConfig.__dataclass_fields__
                })

            if "orchestrator" in raw:
                config.orchestrator = OrchestratorConfig(**{
                    k: v for k, v in raw["orchestrator"].items()
                    if k in OrchestratorConfig.__dataclass_fields__
                })

            if "rate_limit" in raw:
                rl_data = raw["rate_limit"]
                config.rate_limit = RateLimitConfig(
                    default_rate=rl_data.get("default_rate", 10.0),
                    default_burst=rl_data.get("default_burst", 20.0),
                    delay_on_empty=rl_data.get("delay_on_empty", 1.0),
                    overrides=rl_data.get("overrides", {}),
                )

            if "circuit_breaker" in raw:
                cb_data = raw["circuit_breaker"]
                config.circuit_breaker = CircuitBreakerConfig(
                    failure_threshold=cb_data.get("failure_threshold", 5),
                    recovery_timeout=cb_data.get("recovery_timeout", 30),
                    half_open_max_calls=cb_data.get("half_open_max_calls", 2),
                    countable_errors=set(cb_data.get("countable_errors", list(CIRCUIT_COUNTABLE_DEFAULTS))),
                    non_countable_errors=set(cb_data.get("non_countable_errors", ["WAF_BLOCK_403", "RATE_LIMIT_429"])),
                )

            if "alerting" in raw:
                config.alerting = AlertingConfig(**{
                    k: v for k, v in raw["alerting"].items()
                    if k in AlertingConfig.__dataclass_fields__
                })

        except Exception as e:
            # Config parse failure is serious but not fatal — use defaults
            print(f"[WARNING] Failed to parse config {config_path}: {e}. Using defaults.", file=sys.stderr)

    return config


# ---------------------------------------------------------------------------
# Utility Functions
# ---------------------------------------------------------------------------

def extract_domain(target: str) -> str | None:
    """Extract domain from a target URL or hostname.

    Returns None if the target is completely malformed.
    """
    if not target:
        return None

    # If no scheme, prepend one for urlparse
    t = target.strip()
    if not t.startswith(("http://", "https://", "//")):
        t = "https://" + t

    try:
        parsed = urlparse(t)
        host = parsed.hostname
        if host:
            return host.lower()
    except Exception:
        pass

    return None


def validate_target(target: str) -> bool:
    """Validate that a target string is a plausible URL or hostname."""
    domain = extract_domain(target)
    if not domain:
        return False
    # Basic sanity: must have at least one dot or be localhost
    if "." not in domain and domain not in ("localhost",):
        return False
    # Must not be empty after stripping
    if len(domain) < 1 or len(domain) > 253:
        return False
    return True


def determine_queue(task_type: str) -> str:
    """Route task to appropriate module queue based on type."""
    t = task_type.upper()

    if t.startswith("RECON"):
        return QUEUE_RECON

    if t in ("JS_ANALYSIS", "IDOR_CHECK", "FUZZ"):
        return QUEUE_AI_ROUTING

    if t == "NUCLEI_TEMPLATE_GEN":
        return QUEUE_NUCLEI

    if t == "PLAYWRIGHT_RENDER":
        return QUEUE_PLAYWRIGHT

    return QUEUE_DEFAULT


def now_ts() -> float:
    """Current UTC timestamp as float."""
    return time.time()


def now_iso() -> str:
    """Current UTC timestamp as ISO string."""
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------

class Orchestrator:
    """Central orchestrator for the Centaur-Jarvis VAPT agent.

    Manages:
    - Task ingestion, validation, deduplication, and routing
    - Worker heartbeat monitoring
    - Per-target rate limiting (token bucket)
    - Per-target circuit breaking
    - Task result processing and retry logic
    - Graceful shutdown and crash recovery
    - Telemetry and alerting
    """

    def __init__(self, config_path: str = "config/core.yaml"):
        self.logger = get_logger("orchestrator")
        self.logger.info("Initializing Centaur-Jarvis Orchestrator...")

        # Load configuration
        self.config = load_config(config_path)
        self.logger.info(f"Configuration loaded from {config_path}")

        # State flags
        self._shutdown_event = threading.Event()
        self._running = False
        self._redis_healthy = True  # Tracks Redis connectivity
        self._redis_down_since: float | None = None

        # Thread references for lifecycle management
        self._threads: list[threading.Thread] = []

        # Initialize Redis connection
        self._redis_pool: redis.ConnectionPool | None = None
        self._redis: redis.Redis | None = None
        self._connect_redis()

        # Register Lua scripts (after successful Redis connection)
        self._lua_token_bucket: redis.client.Script | None = None
        self._lua_circuit_failure: redis.client.Script | None = None
        self._lua_circuit_success: redis.client.Script | None = None
        self._lua_circuit_check: redis.client.Script | None = None
        self._register_lua_scripts()

        # Register signal handlers
        if threading.current_thread() is threading.main_thread():
            signal.signal(signal.SIGINT, self._signal_handler)
            signal.signal(signal.SIGTERM, self._signal_handler)
            self.logger.info("Signal handlers registered (main thread)")
        else:
            self.logger.warning("Not in main thread, signal handlers not registered. Graceful shutdown may not work.")
    # -----------------------------------------------------------------------
    # Redis Connection Management
    # -----------------------------------------------------------------------

    def _connect_redis(self) -> None:
        """Establish Redis connection with exponential backoff retry.

        Raises SystemExit if connection fails after max retries.
        """
        max_retries = 5
        base_delay = 1.0

        for attempt in range(1, max_retries + 1):
            try:
                self.logger.info(
                    f"Connecting to Redis at {self.config.redis.host}:{self.config.redis.port} "
                    f"(attempt {attempt}/{max_retries})"
                )

                self._redis_pool = redis.ConnectionPool(
                    host=self.config.redis.host,
                    port=self.config.redis.port,
                    password=self.config.redis.password,
                    db=self.config.redis.db,
                    max_connections=self.config.redis.max_connections,
                    socket_timeout=self.config.redis.socket_timeout,
                    socket_connect_timeout=self.config.redis.socket_connect_timeout,
                    retry_on_timeout=self.config.redis.retry_on_timeout,
                    decode_responses=True,
                )

                self._redis = redis.Redis(connection_pool=self._redis_pool)

                # Test connection
                pong = self._redis.ping()
                if pong:
                    self.logger.info("Redis connection established successfully.")
                    self._redis_healthy = True
                    self._redis_down_since = None
                    return

            except redis.ConnectionError as e:
                delay = base_delay * (2 ** (attempt - 1))
                self.logger.error(
                    f"Redis connection failed (attempt {attempt}/{max_retries}): {e}. "
                    f"Retrying in {delay:.1f}s..."
                )
                if attempt < max_retries:
                    time.sleep(delay)
            except Exception as e:
                self.logger.error(
                    f"Unexpected error connecting to Redis (attempt {attempt}/{max_retries}): "
                    f"{e}\n{traceback.format_exc()}"
                )
                delay = base_delay * (2 ** (attempt - 1))
                if attempt < max_retries:
                    time.sleep(delay)

        # All retries exhausted
        self.logger.critical(
            "FATAL: Cannot connect to Redis after 5 attempts. "
            "Orchestrator cannot function without Redis. Exiting."
        )
        self._send_discord_alert(
            "🚨 CRITICAL: Orchestrator failed to connect to Redis after 5 attempts. "
            "System is DOWN.",
            level="CRITICAL",
        )
        sys.exit(1)

    def _ensure_redis(self) -> redis.Redis:
        """Get a healthy Redis connection, reconnecting if necessary.

        Returns:
            redis.Redis instance

        Raises:
            redis.ConnectionError if reconnection fails and we're over threshold.
        """
        try:
            if self._redis is not None:
                self._redis.ping()
                if not self._redis_healthy:
                    self.logger.info("Redis connection recovered.")
                    self._redis_healthy = True
                    self._redis_down_since = None
                return self._redis
        except (redis.ConnectionError, redis.TimeoutError, OSError):
            pass

        # Connection lost
        if self._redis_healthy:
            self._redis_healthy = False
            self._redis_down_since = now_ts()
            self.logger.error("Redis connection lost. Attempting reconnection...")

        # Check how long Redis has been down
        if self._redis_down_since and (now_ts() - self._redis_down_since) > 60:
            self.logger.critical(
                "Redis has been down for >60 seconds. Pausing all processing."
            )
            self._send_discord_alert(
                "🚨 CRITICAL: Redis unreachable for >60 seconds. Processing paused.",
                level="CRITICAL",
            )

        # Attempt reconnection with brief backoff
        for attempt in range(3):
            try:
                self._redis_pool = redis.ConnectionPool(
                    host=self.config.redis.host,
                    port=self.config.redis.port,
                    password=self.config.redis.password,
                    db=self.config.redis.db,
                    max_connections=self.config.redis.max_connections,
                    socket_timeout=self.config.redis.socket_timeout,
                    socket_connect_timeout=self.config.redis.socket_connect_timeout,
                    retry_on_timeout=self.config.redis.retry_on_timeout,
                    decode_responses=True,
                )
                self._redis = redis.Redis(connection_pool=self._redis_pool)
                self._redis.ping()
                self._redis_healthy = True
                self._redis_down_since = None
                self._register_lua_scripts()  # Re-register after reconnect
                self.logger.info("Redis reconnection successful.")
                return self._redis
            except Exception:
                time.sleep(1 * (attempt + 1))

        raise redis.ConnectionError("Failed to reconnect to Redis")

    def _register_lua_scripts(self) -> None:
        """Register Lua scripts with Redis for atomic operations."""
        if self._redis is None:
            return

        try:
            self._lua_token_bucket = self._redis.register_script(LUA_TOKEN_BUCKET)
            self._lua_circuit_failure = self._redis.register_script(LUA_CIRCUIT_RECORD_FAILURE)
            self._lua_circuit_success = self._redis.register_script(LUA_CIRCUIT_RECORD_SUCCESS)
            self._lua_circuit_check = self._redis.register_script(LUA_CIRCUIT_CHECK)
            self.logger.debug("Lua scripts registered successfully.")
        except Exception as e:
            self.logger.error(f"Failed to register Lua scripts: {e}\n{traceback.format_exc()}")

    # -----------------------------------------------------------------------
    # Signal Handling & Graceful Shutdown
    # -----------------------------------------------------------------------

    def _signal_handler(self, signum: int, frame: Any) -> None:
        """Handle SIGINT/SIGTERM for graceful shutdown."""
        sig_name = signal.Signals(signum).name
        self.logger.warning(f"Received {sig_name}. Initiating graceful shutdown...")
        self._shutdown_event.set()

    def _graceful_shutdown(self) -> None:
        """Perform graceful shutdown: stop threads, flush state."""
        self.logger.info(
            f"Graceful shutdown in progress (timeout: {self.config.orchestrator.shutdown_timeout}s)..."
        )
        self._running = False

        # Wait for background threads to finish
        deadline = now_ts() + self.config.orchestrator.shutdown_timeout
        for t in self._threads:
            remaining = max(0.1, deadline - now_ts())
            if t.is_alive():
                self.logger.debug(f"Waiting for thread '{t.name}' to finish (max {remaining:.1f}s)...")
                t.join(timeout=remaining)
                if t.is_alive():
                    self.logger.warning(f"Thread '{t.name}' did not finish in time.")

        # Flush any in-memory state (currently all state is in Redis)
        self.logger.info("All state is persisted in Redis. Nothing to flush.")

        # Close Redis connection
        if self._redis_pool:
            try:
                self._redis_pool.disconnect()
            except Exception:
                pass

        self.logger.info("Graceful shutdown complete. Goodbye.")

    # -----------------------------------------------------------------------
    # Discord Alerting
    # -----------------------------------------------------------------------

    def _send_discord_alert(self, message: str, level: str = "WARNING") -> None:
        """Send alert to Discord webhook with retry logic.

        Args:
            message: Alert text
            level: Severity level (INFO, WARNING, ERROR, CRITICAL)
        """
        url = self.config.alerting.discord_webhook_url
        if not url:
            return  # No webhook configured

        emoji_map = {
            "INFO": "ℹ️",
            "WARNING": "⚠️",
            "ERROR": "❌",
            "CRITICAL": "🚨",
        }
        emoji = emoji_map.get(level, "🔔")

        payload = {
            "content": f"{emoji} **[{level}] Centaur-Jarvis Orchestrator**\n{message}\n"
                       f"_Timestamp: {now_iso()}_",
        }

        for attempt in range(1, self.config.alerting.webhook_max_retries + 1):
            try:
                resp = requests.post(url, json=payload, timeout=10)
                if resp.status_code in (200, 204):
                    self.logger.debug("Discord alert sent successfully.")
                    return
                elif resp.status_code == 429:
                    # Rate limited by Discord
                    retry_after = resp.json().get("retry_after", 5)
                    self.logger.warning(f"Discord rate limited. Retry after {retry_after}s.")
                    time.sleep(retry_after)
                else:
                    self.logger.warning(
                        f"Discord webhook returned {resp.status_code} on attempt {attempt}."
                    )
            except requests.RequestException as e:
                self.logger.warning(
                    f"Discord webhook delivery failed (attempt {attempt}): {e}"
                )

            if attempt < self.config.alerting.webhook_max_retries:
                time.sleep(self.config.alerting.webhook_retry_delay * attempt)

        self.logger.error(
            f"Failed to deliver Discord alert after {self.config.alerting.webhook_max_retries} attempts. "
            f"Message: {message[:200]}"
        )

    # -----------------------------------------------------------------------
    # Task Validation & Parsing
    # -----------------------------------------------------------------------

    def _parse_task(self, raw_json: str) -> Task | None:
        """Parse and validate a raw JSON string into a Task.

        Returns None if parsing/validation fails. Logs errors and moves malformed
        data to the dead-letter queue.
        """
        try:
            data = json.loads(raw_json)
        except (json.JSONDecodeError, TypeError) as e:
            self.logger.error(
                f"Malformed JSON in incoming task: {e}. Raw data: {raw_json[:500]}"
            )
            self._move_to_dead_letter(raw_json, reason=f"JSONDecodeError: {e}")
            return None

        # Validate required fields
        if not isinstance(data, dict):
            self.logger.error(f"Task data is not a dict: {type(data)}. Data: {str(data)[:500]}")
            self._move_to_dead_letter(raw_json, reason="Not a JSON object")
            return None

        required_fields = ("task_id", "type", "target")
        for field_name in required_fields:
            if field_name not in data or not data[field_name]:
                self.logger.error(f"Task missing required field '{field_name}'. Data: {str(data)[:500]}")
                self._move_to_dead_letter(raw_json, reason=f"Missing field: {field_name}")
                return None

        # Validate target
        if not validate_target(data["target"]):
            self.logger.error(
                f"Task {data.get('task_id', 'UNKNOWN')} has invalid target: {data['target']}"
            )
            self._move_to_dead_letter(raw_json, reason=f"Invalid target: {data['target']}")
            return None

        try:
            task = Task.from_dict(data)
            return task
        except Exception as e:
            self.logger.error(
                f"Failed to construct Task from data: {e}\n{traceback.format_exc()}"
            )
            self._move_to_dead_letter(raw_json, reason=f"Task construction failed: {e}")
            return None

    def _parse_result(self, raw_json: str) -> TaskResult | None:
        """Parse a raw JSON string into a TaskResult."""
        try:
            data = json.loads(raw_json)
        except (json.JSONDecodeError, TypeError) as e:
            self.logger.error(
                f"Malformed JSON in result: {e}. Raw: {raw_json[:500]}"
            )
            return None

        if not isinstance(data, dict):
            self.logger.error(f"Result data is not a dict: {type(data)}")
            return None

        if "task_id" not in data:
            self.logger.error(f"Result missing task_id. Data: {str(data)[:500]}")
            return None

        try:
            return TaskResult.from_dict(data)
        except Exception as e:
            self.logger.error(f"Failed to construct TaskResult: {e}\n{traceback.format_exc()}")
            return None

    def _move_to_dead_letter(self, raw_data: str, reason: str = "unknown") -> None:
        """Move a malformed or exhausted task to the dead-letter queue."""
        try:
            r = self._ensure_redis()
            dead_entry = json.dumps({
                "raw_data": raw_data[:10000],  # Cap size
                "reason": reason,
                "timestamp": now_iso(),
            })
            r.lpush(REDIS_KEY_DEAD, dead_entry)
            self.logger.warning(f"Moved item to dead-letter queue. Reason: {reason}")
        except Exception as e:
            self.logger.error(
                f"Failed to move item to dead-letter queue: {e}\n{traceback.format_exc()}"
            )

    # -----------------------------------------------------------------------
    # Task Deduplication
    # -----------------------------------------------------------------------

    def _is_duplicate(self, task_id: str) -> bool:
        """Check if a task_id has already been processed (within dedup window).

        Uses Redis SET with SADD + per-member expiry via a separate sorted set
        for cleanup efficiency.
        """
        try:
            r = self._ensure_redis()
            # Use SET NX semantics: SADD returns 0 if already exists
            added = r.sadd(REDIS_KEY_PROCESSED_IDS, task_id)
            if added == 0:
                # Already processed
                self.logger.info(
                    f"Duplicate task detected: {task_id}. Skipping."
                )
                return True

            # Set key-level expiry (refresh on each new member — acceptable trade-off)
            # For precise per-member expiry, we'd need a sorted set; but for 24h window
            # the set-level expiry is sufficient since we refresh it regularly.
            r.expire(REDIS_KEY_PROCESSED_IDS, self.config.orchestrator.dedup_expiry)
            return False
        except Exception as e:
            self.logger.error(
                f"Deduplication check failed for {task_id}: {e}\n{traceback.format_exc()}"
            )
            # Fail open: allow task through to avoid losing it
            return False

    # -----------------------------------------------------------------------
    # Rate Limiting (Token Bucket via Lua)
    # -----------------------------------------------------------------------

    def _check_rate_limit(self, domain: str) -> tuple[bool, float]:
        """Check and consume a rate limit token for the given domain.

        Returns:
            (allowed: bool, tokens_remaining: float)
            If not allowed, tokens_remaining is -1.
        """
        try:
            r = self._ensure_redis()
            rate, burst = self.config.rate_limit.get_rate_for_domain(domain)
            key = f"{REDIS_KEY_RATE_LIMIT_PREFIX}{domain}"

            result = self._lua_token_bucket(
                keys=[key],
                args=[str(rate), str(burst), str(now_ts())],
                client=r,
            )

            remaining = float(result)
            if remaining >= 0:
                self.logger.debug(
                    f"Rate limit OK for {domain}: {remaining:.1f} tokens remaining."
                )
                return (True, remaining)
            else:
                self.logger.info(
                    f"Rate limit exhausted for {domain}. Task will be delayed."
                )
                return (False, -1)

        except Exception as e:
            self.logger.error(
                f"Rate limit check failed for {domain}: {e}\n{traceback.format_exc()}"
            )
            # Fail open: allow task through
            return (True, 0)

    # -----------------------------------------------------------------------
    # Circuit Breaker
    # -----------------------------------------------------------------------

    def _circuit_check(self, target: str) -> tuple[str, float]:
        """Check circuit breaker state for a target.

        Returns:
            (state: str, remaining_open_seconds: float)
            If state is OPEN, remaining_open_seconds > 0.
            If state is HALF_OPEN and no more calls allowed, remaining = -1.
        """
        domain = extract_domain(target) or target
        key = f"{REDIS_KEY_CIRCUIT_PREFIX}{domain}"

        try:
            r = self._ensure_redis()
            result = self._lua_circuit_check(
                keys=[key],
                args=[
                    str(self.config.circuit_breaker.recovery_timeout),
                    str(now_ts()),
                    str(self.config.circuit_breaker.half_open_max_calls),
                ],
                client=r,
            )

            state = result[0]
            remaining = float(result[1])
            ho_remaining = int(float(result[2]))

            if state == CB_HALF_OPEN and ho_remaining <= 0:
                # Half-open but no more test calls allowed
                return (CB_HALF_OPEN, -1)

            return (state, remaining)

        except Exception as e:
            self.logger.error(
                f"Circuit check failed for {domain}: {e}\n{traceback.format_exc()}"
            )
            # Fail open: assume circuit closed
            return (CB_CLOSED, 0)

    def _circuit_record_failure(self, target: str, error_type: str | None) -> str:
        """Record a failure for a target's circuit breaker.

        Only countable errors (5xx, timeout, connection error) affect the circuit.

        Returns:
            New circuit state.
        """
        # Check if this error type should be counted
        if error_type and error_type in self.config.circuit_breaker.non_countable_errors:
            self.logger.debug(
                f"Error type '{error_type}' for {target} is non-countable. Circuit unchanged."
            )
            return CB_CLOSED  # Not affected

        if error_type and error_type not in self.config.circuit_breaker.countable_errors:
            # Unknown error type — be conservative, don't count
            self.logger.debug(
                f"Unknown error type '{error_type}' for {target}. Not counting for circuit."
            )
            return CB_CLOSED

        domain = extract_domain(target) or target
        key = f"{REDIS_KEY_CIRCUIT_PREFIX}{domain}"

        try:
            r = self._ensure_redis()

            # Get old state for logging
            old_state = r.hget(key, "state") or CB_CLOSED

            new_state = self._lua_circuit_failure(
                keys=[key],
                args=[
                    str(self.config.circuit_breaker.failure_threshold),
                    str(now_ts()),
                    str(self.config.circuit_breaker.recovery_timeout),
                ],
                client=r,
            )

            if new_state != old_state:
                self.logger.warning(
                    f"Circuit breaker state change for {domain}: {old_state} → {new_state}"
                )
                if new_state == CB_OPEN:
                    alert_msg = (
                        f"Circuit OPENED for target **{domain}**.\n"
                        f"Failure threshold ({self.config.circuit_breaker.failure_threshold}) reached.\n"
                        f"Recovery timeout: {self.config.circuit_breaker.recovery_timeout}s."
                    )
                    self._send_discord_alert(alert_msg, level="ERROR")

            return new_state

        except Exception as e:
            self.logger.error(
                f"Circuit failure recording failed for {domain}: {e}\n{traceback.format_exc()}"
            )
            return CB_CLOSED

    def _circuit_record_success(self, target: str) -> str:
        """Record a success for a target's circuit breaker.

        Used in HALF_OPEN state to determine if circuit should close.

        Returns:
            New circuit state.
        """
        domain = extract_domain(target) or target
        key = f"{REDIS_KEY_CIRCUIT_PREFIX}{domain}"

        try:
            r = self._ensure_redis()
            old_state = r.hget(key, "state") or CB_CLOSED

            new_state = self._lua_circuit_success(
                keys=[key],
                args=[str(self.config.circuit_breaker.half_open_max_calls)],
                client=r,
            )

            if new_state != old_state:
                self.logger.info(
                    f"Circuit breaker state change for {domain}: {old_state} → {new_state}"
                )
                if new_state == CB_CLOSED and old_state == CB_HALF_OPEN:
                    self._send_discord_alert(
                        f"Circuit CLOSED for target **{domain}**. Recovery confirmed.",
                        level="INFO",
                    )

            return new_state

        except Exception as e:
            self.logger.error(
                f"Circuit success recording failed for {domain}: {e}\n{traceback.format_exc()}"
            )
            return CB_CLOSED

    # -----------------------------------------------------------------------
    # Delayed Queue Management
    # -----------------------------------------------------------------------

    def _enqueue_delayed(self, task_json: str, delay_seconds: float) -> None:
        """Add a task to the delayed queue (Redis sorted set, scored by execute-at time)."""
        try:
            r = self._ensure_redis()
            execute_at = now_ts() + delay_seconds
            r.zadd(REDIS_KEY_DELAYED, {task_json: execute_at})
            self.logger.debug(
                f"Task enqueued to delayed queue. Execute at: {execute_at:.2f} "
                f"(in {delay_seconds:.1f}s)"
            )
        except Exception as e:
            self.logger.error(
                f"Failed to enqueue to delayed queue: {e}\n{traceback.format_exc()}"
            )
            # Fallback: push directly to incoming (may cause rate limit issues but won't lose task)
            try:
                r = self._ensure_redis()
                r.rpush(REDIS_KEY_INCOMING, task_json)
            except Exception:
                self.logger.critical(f"FAILED to save task anywhere! Data: {task_json[:500]}")

    def _process_delayed_queue(self) -> None:
        """Background thread: move ready tasks from delayed queue to incoming queue."""
        self.logger.info("Delayed queue processor started.")

        while not self._shutdown_event.is_set():
            try:
                r = self._ensure_redis()
                current_time = now_ts()

                # Get all tasks whose score (execute_at) <= current time
                # Use ZRANGEBYSCORE + ZREM atomically via pipeline
                pipe = r.pipeline()
                pipe.zrangebyscore(REDIS_KEY_DELAYED, "-inf", str(current_time), start=0, num=50)
                results = pipe.execute()

                ready_tasks = results[0] if results else []

                if ready_tasks:
                    # Remove from delayed and push to incoming
                    pipe2 = r.pipeline()
                    for task_json in ready_tasks:
                        pipe2.zrem(REDIS_KEY_DELAYED, task_json)
                        pipe2.rpush(REDIS_KEY_INCOMING, task_json)
                    pipe2.execute()

                    self.logger.info(
                        f"Moved {len(ready_tasks)} tasks from delayed to incoming queue."
                    )

            except redis.ConnectionError:
                self.logger.warning("Redis unavailable in delayed queue processor. Waiting...")
                self._shutdown_event.wait(5)
                continue
            except Exception as e:
                self.logger.error(
                    f"Error in delayed queue processor: {e}\n{traceback.format_exc()}"
                )

            self._shutdown_event.wait(self.config.orchestrator.delayed_queue_poll_interval)

        self.logger.info("Delayed queue processor stopped.")

    # -----------------------------------------------------------------------
    # Task State Management
    # -----------------------------------------------------------------------

    def _set_task_state(
        self,
        task_id: str,
        status: str,
        assigned_worker: str | None = None,
        retry_count: int | None = None,
        extra_fields: dict | None = None,
    ) -> None:
        """Update task state in Redis hash."""
        try:
            r = self._ensure_redis()
            key = f"{REDIS_KEY_TASK_PREFIX}{task_id}"

            fields: dict[str, str] = {
                "status": status,
                "updated_at": now_iso(),
            }

            if assigned_worker is not None:
                fields["assigned_worker"] = assigned_worker
            if retry_count is not None:
                fields["retry_count"] = str(retry_count)
            if extra_fields:
                fields.update({k: str(v) for k, v in extra_fields.items()})

            # Set created_at only if it doesn't exist
            if not r.hexists(key, "created_at"):
                fields["created_at"] = now_iso()

            r.hset(key, mapping=fields)
            # Expire after 7 days for cleanup
            r.expire(key, 7 * 86400)

            self.logger.debug(f"Task {task_id} state updated: status={status}")

        except Exception as e:
            self.logger.error(
                f"Failed to set task state for {task_id}: {e}\n{traceback.format_exc()}"
            )

    def _store_task_result(self, task_id: str, result_data: dict) -> None:
        print(f"!!! DEBUG: _store_task_result called for task {task_id}")
        try:
            r = self._ensure_redis()
            key = f"{REDIS_KEY_TASK_PREFIX}{task_id}:result"
            print(f"!!! DEBUG: Storing result under key {key}")
            r.set(key, json.dumps(result_data), ex=7 * 86400)
            self.logger.debug(f"Result stored for task {task_id}.")
        except Exception as e:
            self.logger.error(f"Failed to store result for {task_id}: {e}")
            print(f"!!! DEBUG: Exception in _store_task_result: {e}")

    # -----------------------------------------------------------------------
    # Task Routing
    # -----------------------------------------------------------------------

    def _route_task(self, task: Task) -> bool:
        """Route a validated, non-duplicate task to the appropriate module queue.

        Performs rate limiting and circuit breaker checks before routing.

        Returns:
            True if task was routed (or delayed), False if it should be retried later.
        """
        domain = extract_domain(task.target)
        if not domain:
            self.logger.error(f"Cannot extract domain from task {task.task_id} target: {task.target}")
            self._move_to_dead_letter(
                json.dumps(task.to_dict()),
                reason=f"Cannot extract domain from target: {task.target}",
            )
            return True  # Don't retry — it's dead

        task_json = json.dumps(task.to_dict())

        # --- Circuit Breaker Check ---
        cb_state, cb_remaining = self._circuit_check(task.target)

        if cb_state == CB_OPEN:
            delay = max(cb_remaining, 1.0)
            self.logger.info(
                f"Circuit OPEN for {domain}. Delaying task {task.task_id} by {delay:.1f}s."
            )
            self._enqueue_delayed(task_json, delay_seconds=delay)
            self._set_task_state(task.task_id, TaskStatus.DELAYED.value if hasattr(TaskStatus, 'DELAYED') else "DELAYED")
            return True

        if cb_state == CB_HALF_OPEN and cb_remaining == -1:
            # Half-open but no more test calls allowed — delay briefly
            delay = 5.0
            self.logger.info(
                f"Circuit HALF_OPEN for {domain}, no test slots available. "
                f"Delaying task {task.task_id} by {delay:.1f}s."
            )
            self._enqueue_delayed(task_json, delay_seconds=delay)
            self._set_task_state(task.task_id, TaskStatus.DELAYED.value if hasattr(TaskStatus, 'DELAYED') else "DELAYED")
            return True

        # --- Rate Limiting Check ---
        allowed, tokens_remaining = self._check_rate_limit(domain)

        if not allowed:
            delay = self.config.rate_limit.delay_on_empty
            self.logger.info(
                f"Rate limit exhausted for {domain}. Delaying task {task.task_id} by {delay:.1f}s. "
                f"Delayed queue size: (check manually)"
            )
            self._enqueue_delayed(task_json, delay_seconds=delay)
            self._set_task_state(task.task_id, TaskStatus.DELAYED.value if hasattr(TaskStatus, 'DELAYED') else "DELAYED")
            return True

        # --- Determine Target Queue ---
        target_queue = determine_queue(task.type)

        # --- Push to Module Queue ---
        try:
            r = self._ensure_redis()
            r.lpush(target_queue, task_json)

            self._set_task_state(
                task.task_id,
                TaskStatus.QUEUED.value,
                extra_fields={"assigned_queue": target_queue, "retry_count": str(task.retry_count)},
            )

            self.logger.info(
                f"Task routed: id={task.task_id}, type={task.type}, target={domain}, "
                f"queue={target_queue}, tokens_remaining={tokens_remaining:.1f}"
            )
            return True

        except Exception as e:
            self.logger.error(
                f"Failed to push task {task.task_id} to queue {target_queue}: {e}\n"
                f"{traceback.format_exc()}"
            )
            return False

    # -----------------------------------------------------------------------
    # Task Ingestion Loop
    # -----------------------------------------------------------------------

    def _task_ingestion_loop(self) -> None:
        """Main loop: consume tasks from incoming queue, validate, dedup, route."""
        self.logger.info("Task ingestion loop started.")

        while not self._shutdown_event.is_set():
            if not self._redis_healthy:
                self.logger.debug("Redis unhealthy, pausing ingestion for 5s...")
                self._shutdown_event.wait(5)
                continue

            try:
                r = self._ensure_redis()

                # BLPOP with timeout so we can check shutdown flag periodically
                result = r.blpop(
                    REDIS_KEY_INCOMING,
                    timeout=self.config.orchestrator.task_poll_timeout,
                )

                if result is None:
                    continue  # Timeout, no tasks — loop back

                queue_name, raw_json = result

                # Parse task
                task = self._parse_task(raw_json)
                if task is None:
                    continue  # Already moved to dead-letter

                # Deduplication check
                if self._is_duplicate(task.task_id):
                    continue

                # Route task
                success = self._route_task(task)
                if not success:
                    # Routing failed (likely Redis issue) — push back with small delay
                    self._enqueue_delayed(raw_json, delay_seconds=2.0)

            except redis.ConnectionError:
                self.logger.warning("Redis connection lost during task ingestion. Retrying...")
                self._redis_healthy = False
                self._shutdown_event.wait(2)
            except Exception as e:
                self.logger.error(
                    f"Unexpected error in task ingestion loop: {e}\n{traceback.format_exc()}"
                )
                self._shutdown_event.wait(1)

        self.logger.info("Task ingestion loop stopped.")

    # -----------------------------------------------------------------------
    # Result Processing Loop
    # -----------------------------------------------------------------------

    def _result_processing_loop(self) -> None:
        """Consume worker results, update task state, handle retries."""
        self.logger.info("Result processing loop started.")
        print("!!! DEBUG: _result_processing_loop is running")

        while not self._shutdown_event.is_set():
            if not self._redis_healthy:
                self._shutdown_event.wait(5)
                continue

            try:
                r = self._ensure_redis()

                result_data = r.blpop(
                    REDIS_KEY_RESULTS,
                    timeout=self.config.orchestrator.result_poll_timeout,
                )

                if result_data is None:
                    continue

                _, raw_json = result_data
                result = self._parse_result(raw_json)
                if result is None:
                    continue

                self.logger.info(
                    f"Processing result for task {result.task_id}: status={result.status}"
                )

                # Get task state to find target
                task_state = r.hgetall(f"{REDIS_KEY_TASK_PREFIX}{result.task_id}")

                if result.status == TaskStatus.COMPLETED.value or result.status == "COMPLETED":
                    self._handle_task_success(result, task_state)
                elif result.status == TaskStatus.FAILED.value or result.status == "FAILED":
                    self._handle_task_failure(result, task_state)
                else:
                    # Other statuses (PROCESSING, etc.) — just update state
                    self._set_task_state(
                        result.task_id,
                        result.status,
                        assigned_worker=result.worker_id,
                    )

            except redis.ConnectionError:
                self.logger.warning("Redis connection lost during result processing.")
                self._redis_healthy = False
                self._shutdown_event.wait(2)
            except Exception as e:
                self.logger.error(
                    f"Error in result processing loop: {e}\n{traceback.format_exc()}"
                )
                self._shutdown_event.wait(1)

        self.logger.info("Result processing loop stopped.")

    def _handle_task_success(self, result: TaskResult, task_state: dict) -> None:
        print(f"!!! DEBUG: _handle_task_success called for task {result.task_id}")
        """Handle a successful task result."""
        # Store result
        self._store_task_result(result.task_id, result.data)

        # Update task state
        self._set_task_state(
            result.task_id,
            TaskStatus.COMPLETED.value,
            assigned_worker=result.worker_id,
            extra_fields={"completed_at": result.completed_at},
        )

        # Record success for circuit breaker (helps HALF_OPEN → CLOSED transition)
        # Retrieve target from task state or result
        target = task_state.get("target") or self._get_task_target(result.task_id)
        if target:
            self._circuit_record_success(target)

        # Send webhook if configured on the task
        webhook_url = task_state.get("webhook_url")
        if webhook_url:
            self._send_task_webhook(webhook_url, result)

        self.logger.info(f"Task {result.task_id} completed successfully.")

    def _handle_task_failure(self, result: TaskResult, task_state: dict) -> None:
        """Handle a failed task result with retry logic."""
        # Update circuit breaker
        target = task_state.get("target") or self._get_task_target(result.task_id)
        if target:
            new_state = self._circuit_record_failure(target, result.error_type)
            self.logger.debug(
                f"Circuit state after failure for {target}: {new_state}"
            )

        # Get current retry count
        current_retries = int(task_state.get("retry_count", "0"))
        max_retries = int(task_state.get("max_retries", str(self.config.orchestrator.max_retries)))

        if current_retries < max_retries:
            # Retry with exponential backoff
            new_retry_count = current_retries + 1
            delay = min(2 ** new_retry_count, 60)  # Cap at 60s

            self.logger.warning(
                f"Task {result.task_id} failed (attempt {new_retry_count}/{max_retries}). "
                f"Error: {result.error}. Retrying in {delay}s."
            )

            # Reconstruct task for requeue
            requeue_task = self._reconstruct_task_for_retry(result.task_id, task_state, new_retry_count)
            if requeue_task:
                self._enqueue_delayed(requeue_task, delay_seconds=delay)
                self._set_task_state(
                    result.task_id,
                    TaskStatus.DELAYED.value if hasattr(TaskStatus, 'DELAYED') else "DELAYED",
                    retry_count=new_retry_count,
                )
            else:
                # Can't reconstruct task — move to dead letter
                self._set_task_state(result.task_id, TaskStatus.DEAD.value)
                self._move_to_dead_letter(
                    json.dumps(task_state),
                    reason=f"Cannot reconstruct task for retry. Error: {result.error}",
                )
        else:
            # Max retries exceeded — dead letter
            self.logger.error(
                f"Task {result.task_id} exhausted all {max_retries} retries. "
                f"Error: {result.error}. Moving to dead-letter queue."
            )
            self._set_task_state(result.task_id, TaskStatus.DEAD.value)
            self._move_to_dead_letter(
                json.dumps({"task_id": result.task_id, "task_state": task_state, "last_error": result.error}),
                reason=f"Max retries ({max_retries}) exceeded. Last error: {result.error}",
            )
            self._send_discord_alert(
                f"Task **{result.task_id}** exhausted all retries and moved to dead-letter queue.\n"
                f"Target: {target or 'unknown'}\n"
                f"Error: {result.error or 'unknown'}",
                level="ERROR",
            )

    def _reconstruct_task_for_retry(
        self, task_id: str, task_state: dict, new_retry_count: int
    ) -> str | None:
        """Reconstruct a task JSON for requeue from stored state.

        We need the original task data. We try to retrieve it from Redis state.
        """
        try:
            r = self._ensure_redis()
            # Try to get from task hash (we store some fields) plus original data
            # We need at least: task_id, type, target
            task_type = task_state.get("type") or task_state.get("task_type")
            target = task_state.get("target")

            if not task_type or not target:
                # Try loading from the full task state
                full_key = f"{REDIS_KEY_TASK_PREFIX}{task_id}"
                full_state = r.hgetall(full_key)
                task_type = full_state.get("type") or full_state.get("task_type")
                target = full_state.get("target")

            if not task_type or not target:
                self.logger.error(
                    f"Cannot reconstruct task {task_id}: missing type or target in state."
                )
                return None

            # Reconstruct minimal task
            task_data = {
                "task_id": task_id,
                "type": task_type,
                "target": target,
                "retry_count": new_retry_count,
                "max_retries": int(task_state.get("max_retries", str(self.config.orchestrator.max_retries))),
                "params": json.loads(task_state.get("params", "{}")) if isinstance(task_state.get("params"), str) else task_state.get("params", {}),
                "webhook_url": task_state.get("webhook_url"),
                "priority": int(task_state.get("priority", "0")),
                "created_at": task_state.get("created_at", now_iso()),
            }

            # Remove the task_id from dedup set so it can be reprocessed
            r.srem(REDIS_KEY_PROCESSED_IDS, task_id)

            return json.dumps(task_data)

        except Exception as e:
            self.logger.error(
                f"Failed to reconstruct task {task_id}: {e}\n{traceback.format_exc()}"
            )
            return None

    def _get_task_target(self, task_id: str) -> str | None:
        """Retrieve the target field for a task from Redis."""
        try:
            r = self._ensure_redis()
            return r.hget(f"{REDIS_KEY_TASK_PREFIX}{task_id}", "target")
        except Exception:
            return None

    def _send_task_webhook(self, webhook_url: str, result: TaskResult) -> None:
        """Send task result to a webhook URL (typically Discord)."""
        try:
            payload = {
                "content": (
                    f"📋 **Task Result: {result.task_id}**\n"
                    f"Status: {result.status}\n"
                    f"Worker: {result.worker_id or 'unknown'}\n"
                    f"Completed: {result.completed_at}\n"
                    f"Data keys: {list(result.data.keys()) if result.data else 'none'}"
                ),
            }

            for attempt in range(3):
                try:
                    resp = requests.post(webhook_url, json=payload, timeout=10)
                    if resp.status_code in (200, 204):
                        return
                except requests.RequestException:
                    pass
                time.sleep(1 * (attempt + 1))

            self.logger.error(
                f"Failed to deliver task webhook for {result.task_id} to {webhook_url}"
            )
        except Exception as e:
            self.logger.error(f"Task webhook error: {e}")

    # -----------------------------------------------------------------------
    # Worker Heartbeat Monitoring
    # -----------------------------------------------------------------------

    def _heartbeat_monitor_loop(self) -> None:
        """Background thread: detect dead workers and requeue their tasks."""
        self.logger.info("Heartbeat monitor started.")

        while not self._shutdown_event.is_set():
            self._shutdown_event.wait(self.config.orchestrator.heartbeat_check_interval)

            if self._shutdown_event.is_set():
                break

            if not self._redis_healthy:
                continue

            try:
                self._check_worker_heartbeats()
            except redis.ConnectionError:
                self.logger.warning("Redis unavailable during heartbeat check.")
                self._redis_healthy = False
            except Exception as e:
                self.logger.error(
                    f"Error in heartbeat monitor: {e}\n{traceback.format_exc()}"
                )

        self.logger.info("Heartbeat monitor stopped.")

    def _check_worker_heartbeats(self) -> None:
        """Scan worker heartbeat keys and handle stale workers."""
        r = self._ensure_redis()
        stale_threshold = self.config.orchestrator.heartbeat_stale_threshold
        current_time = now_ts()

        # Use SCAN to iterate worker heartbeat keys without blocking
        cursor = 0
        stale_workers: list[str] = []

        while True:
            cursor, keys = r.scan(
                cursor=cursor,
                match=f"{REDIS_KEY_WORKER_HB_PREFIX}*",
                count=100,
            )

            for key in keys:
                worker_id = key.replace(REDIS_KEY_WORKER_HB_PREFIX, "")
                try:
                    last_hb = r.get(key)
                    if last_hb is None:
                        # Key expired (Redis TTL) — worker is definitely stale
                        stale_workers.append(worker_id)
                        continue

                    last_hb_ts = float(last_hb)
                    age = current_time - last_hb_ts

                    if age > stale_threshold:
                        stale_workers.append(worker_id)
                        self.logger.warning(
                            f"Worker {worker_id} heartbeat is {age:.0f}s old "
                            f"(threshold: {stale_threshold}s). Marking as dead."
                        )
                except (ValueError, TypeError) as e:
                    self.logger.error(
                        f"Invalid heartbeat value for {worker_id}: {last_hb}. Error: {e}"
                    )
                    stale_workers.append(worker_id)

            if cursor == 0:
                break

        # Handle stale workers
        for worker_id in stale_workers:
            self._handle_dead_worker(worker_id)

    def _handle_dead_worker(self, worker_id: str) -> None:
        """Handle a dead worker: requeue its tasks, clean up."""
        self.logger.warning(f"Handling dead worker: {worker_id}")

        self._send_discord_alert(
            f"Worker **{worker_id}** is dead (heartbeat stale). Requeuing its tasks.",
            level="WARNING",
        )

        try:
            r = self._ensure_redis()

            # Find tasks assigned to this worker
            # We scan task:* keys (excluding task:*:result keys)
            cursor = 0
            requeued = 0
            dead_lettered = 0

            while True:
                cursor, keys = r.scan(
                    cursor=cursor,
                    match=f"{REDIS_KEY_TASK_PREFIX}*",
                    count=200,
                )

                # Filter out result keys
                task_keys = [k for k in keys if ":result" not in k]

                if task_keys:
                    # Use pipeline for efficient bulk reads
                    pipe = r.pipeline()
                    for key in task_keys:
                        pipe.hgetall(key)
                    all_states = pipe.execute()

                    for key, state in zip(task_keys, all_states):
                        if not isinstance(state, dict):
                            continue

                        if (
                            state.get("assigned_worker") == worker_id
                            and state.get("status") in (
                                TaskStatus.PROCESSING.value, "PROCESSING"
                            )
                        ):
                            task_id = key.replace(REDIS_KEY_TASK_PREFIX, "")
                            retry_count = int(state.get("retry_count", "0"))
                            max_retries = int(
                                state.get("max_retries", str(self.config.orchestrator.max_retries))
                            )

                            if retry_count < max_retries:
                                # Requeue
                                requeue_json = self._reconstruct_task_for_retry(
                                    task_id, state, retry_count + 1
                                )
                                if requeue_json:
                                    r.rpush(REDIS_KEY_INCOMING, requeue_json)
                                    self._set_task_state(
                                        task_id,
                                        TaskStatus.PENDING.value,
                                        retry_count=retry_count + 1,
                                    )
                                    requeued += 1
                                    self.logger.info(
                                        f"Requeued task {task_id} from dead worker {worker_id} "
                                        f"(retry {retry_count + 1}/{max_retries})."
                                    )
                                else:
                                    self._set_task_state(task_id, TaskStatus.DEAD.value)
                                    self._move_to_dead_letter(
                                        json.dumps(state),
                                        reason=f"Cannot reconstruct task after worker {worker_id} death",
                                    )
                                    dead_lettered += 1
                            else:
                                # Max retries exceeded
                                self._set_task_state(task_id, TaskStatus.DEAD.value)
                                self._move_to_dead_letter(
                                    json.dumps(state),
                                    reason=f"Max retries exceeded after worker {worker_id} death",
                                )
                                dead_lettered += 1

                if cursor == 0:
                    break

            # Clean up worker heartbeat key
            r.delete(f"{REDIS_KEY_WORKER_HB_PREFIX}{worker_id}")

            self.logger.info(
                f"Dead worker {worker_id} cleanup complete: "
                f"{requeued} tasks requeued, {dead_lettered} dead-lettered."
            )

        except Exception as e:
            self.logger.error(
                f"Error handling dead worker {worker_id}: {e}\n{traceback.format_exc()}"
            )

    # -----------------------------------------------------------------------
    # Task Timeout Monitor
    # -----------------------------------------------------------------------

    def _task_timeout_monitor_loop(self) -> None:
        """Background thread: detect tasks stuck in PROCESSING state too long."""
        self.logger.info("Task timeout monitor started.")

        while not self._shutdown_event.is_set():
            # Check every 60 seconds
            self._shutdown_event.wait(60)

            if self._shutdown_event.is_set():
                break

            if not self._redis_healthy:
                continue

            try:
                self._check_task_timeouts()
            except redis.ConnectionError:
                self.logger.warning("Redis unavailable during task timeout check.")
                self._redis_healthy = False
            except Exception as e:
                self.logger.error(
                    f"Error in task timeout monitor: {e}\n{traceback.format_exc()}"
                )

        self.logger.info("Task timeout monitor stopped.")

    def _check_task_timeouts(self) -> None:
        """Scan for tasks in PROCESSING state that have exceeded the timeout."""
        r = self._ensure_redis()
        timeout = self.config.orchestrator.task_timeout
        current_time = now_ts()

        cursor = 0
        timed_out = 0

        while True:
            cursor, keys = r.scan(
                cursor=cursor,
                match=f"{REDIS_KEY_TASK_PREFIX}*",
                count=200,
            )

            task_keys = [k for k in keys if ":result" not in k]

            if task_keys:
                pipe = r.pipeline()
                for key in task_keys:
                    pipe.hgetall(key)
                all_states = pipe.execute()

                for key, state in zip(task_keys, all_states):
                    if not isinstance(state, dict):
                        continue

                    if state.get("status") not in (TaskStatus.PROCESSING.value, "PROCESSING"):
                        continue

                    updated_at = state.get("updated_at", "")
                    if not updated_at:
                        continue

                    try:
                        updated_dt = datetime.fromisoformat(updated_at)
                        age = current_time - updated_dt.timestamp()
                    except (ValueError, TypeError):
                        age = timeout + 1  # Force timeout if we can't parse

                    if age > timeout:
                        task_id = key.replace(REDIS_KEY_TASK_PREFIX, "")
                        self.logger.warning(
                            f"Task {task_id} timed out (processing for {age:.0f}s, "
                            f"timeout: {timeout}s). Auto-failing and requeuing."
                        )

                        retry_count = int(state.get("retry_count", "0"))
                        max_retries = int(
                            state.get("max_retries", str(self.config.orchestrator.max_retries))
                        )

                        if retry_count < max_retries:
                            requeue_json = self._reconstruct_task_for_retry(
                                task_id, state, retry_count + 1
                            )
                            if requeue_json:
                                delay = min(2 ** (retry_count + 1), 60)
                                self._enqueue_delayed(requeue_json, delay_seconds=delay)
                                self._set_task_state(
                                    task_id,
                                    TaskStatus.FAILED.value,
                                    retry_count=retry_count + 1,
                                    extra_fields={"failure_reason": "TIMEOUT"},
                                )
                                timed_out += 1
                            else:
                                self._set_task_state(task_id, TaskStatus.DEAD.value)
                                self._move_to_dead_letter(
                                    json.dumps(state),
                                    reason="Timed out and cannot reconstruct for retry",
                                )
                        else:
                            self._set_task_state(task_id, TaskStatus.DEAD.value)
                            self._move_to_dead_letter(
                                json.dumps(state),
                                reason=f"Timed out after max retries ({max_retries})",
                            )

                        # Record timeout as failure for circuit breaker
                        target = state.get("target")
                        if target:
                            self._circuit_record_failure(target, "TIMEOUT")

            if cursor == 0:
                break

        if timed_out > 0:
            self.logger.info(f"Task timeout check: {timed_out} tasks timed out and requeued.")

    # -----------------------------------------------------------------------
    # Task State Enrichment (for retry reconstruction)
    # -----------------------------------------------------------------------

    def _enrich_task_state(self, task: Task) -> None:
        """Store additional task fields in Redis hash for later reconstruction.

        Called when a task is first routed, so we have enough data to reconstruct
        it if the worker dies or the task times out.
        """
        try:
            r = self._ensure_redis()
            key = f"{REDIS_KEY_TASK_PREFIX}{task.task_id}"

            extra_fields = {
                "type": task.type,
                "target": task.target,
                "params": json.dumps(task.params) if task.params else "{}",
                "priority": str(task.priority),
                "max_retries": str(task.max_retries),
            }

            if task.webhook_url:
                extra_fields["webhook_url"] = task.webhook_url

            r.hset(key, mapping=extra_fields)
            r.expire(key, 7 * 86400)

        except Exception as e:
            self.logger.error(
                f"Failed to enrich task state for {task.task_id}: {e}"
            )

    # -----------------------------------------------------------------------
    # Main Start & Stop
    # -----------------------------------------------------------------------

    def start(self) -> None:
        """Start the orchestrator and all background threads.

        This is the main entry point. It blocks until shutdown is signaled.
        """
        self.logger.info("=" * 70)
        self.logger.info("  Centaur-Jarvis Orchestrator Starting")
        self.logger.info(f"  PID: {os.getpid()}")
        self.logger.info(f"  Redis: {self.config.redis.host}:{self.config.redis.port}")
        self.logger.info(f"  Task timeout: {self.config.orchestrator.task_timeout}s")
        self.logger.info(f"  Max retries: {self.config.orchestrator.max_retries}")
        self.logger.info(f"  Rate limit: {self.config.rate_limit.default_rate} req/s "
                         f"(burst: {self.config.rate_limit.default_burst})")
        self.logger.info(f"  Circuit breaker threshold: {self.config.circuit_breaker.failure_threshold} failures")
        self.logger.info("=" * 70)

        self._running = True

        # Recovery check: detect any tasks that were PROCESSING at last shutdown
        self._recovery_check()

        # Start background threads
        threads_config = [
            ("task-ingestion", self._task_ingestion_loop),
            ("result-processor", self._result_processing_loop),
            ("delayed-queue", self._process_delayed_queue),
            ("heartbeat-monitor", self._heartbeat_monitor_loop),
            ("timeout-monitor", self._task_timeout_monitor_loop),
        ]

        for name, target in threads_config:
            t = threading.Thread(target=target, name=name, daemon=True)
            t.start()
            self._threads.append(t)
            self.logger.info(f"Started thread: {name}")

        self._send_discord_alert("Orchestrator started successfully.", level="INFO")

        # Block main thread until shutdown signal
        try:
            while not self._shutdown_event.is_set():
                self._shutdown_event.wait(1)
        except KeyboardInterrupt:
            self._shutdown_event.set()

        # Graceful shutdown
        self._graceful_shutdown()

    def run(self):
        self.start()

    def shutdown(self):
        self.logger.info("Shutdown requested via shutdown() method.")
        self._shutdown_event.set()    

    def _recovery_check(self) -> None:
        """On startup, check for tasks stuck in PROCESSING state from a previous crash.

        These will be caught by the heartbeat monitor and timeout monitor,
        but we do an immediate scan for faster recovery.
        """
        self.logger.info("Running recovery check for stuck tasks...")

        try:
            r = self._ensure_redis()
            cursor = 0
            stuck_count = 0

            while True:
                cursor, keys = r.scan(
                    cursor=cursor,
                    match=f"{REDIS_KEY_TASK_PREFIX}*",
                    count=200,
                )

                task_keys = [k for k in keys if ":result" not in k]

                if task_keys:
                    pipe = r.pipeline()
                    for key in task_keys:
                        pipe.hgetall(key)
                    all_states = pipe.execute()

                    for key, state in zip(task_keys, all_states):
                        if not isinstance(state, dict):
                            continue

                        if state.get("status") in (TaskStatus.PROCESSING.value, "PROCESSING"):
                            task_id = key.replace(REDIS_KEY_TASK_PREFIX, "")
                            self.logger.warning(
                                f"Recovery: Found stuck task {task_id} in PROCESSING state."
                            )
                            # Don't immediately requeue — let the timeout monitor handle it.
                            # But mark it with a fresh updated_at so the timeout starts now.
                            r.hset(key, "updated_at", now_iso())
                            stuck_count += 1

                if cursor == 0:
                    break

            if stuck_count > 0:
                self.logger.warning(
                    f"Recovery check found {stuck_count} stuck tasks. "
                    "They will be handled by the timeout monitor."
                )
            else:
                self.logger.info("Recovery check: no stuck tasks found.")

        except Exception as e:
            self.logger.error(
                f"Recovery check failed: {e}\n{traceback.format_exc()}"
            )

    # -----------------------------------------------------------------------
    # Override _route_task to also enrich task state
    # -----------------------------------------------------------------------
    # We already call _set_task_state in _route_task, but we need to store
    # the full task data for reconstruction. Let's hook into _route_task.
    # We do this by wrapping the original method.

    _original_route_task = None  # Will be set in __init_subclass__ or we just modify inline

    # Actually, let's just add the enrichment call inside _route_task.
    # Looking at _route_task above, we call _set_task_state but don't store
    # type/target/params. Let's fix that by calling _enrich_task_state.
    # Since the method is already defined, we'll add a wrapper.

    def route_task_with_enrichment(self, task: Task) -> bool:
        """Route task with state enrichment for crash recovery."""
        # Enrich first so we have data for reconstruction
        self._enrich_task_state(task)
        return self._route_task(task)


# We need to patch _route_task to include enrichment.
# Let's do this cleanly by modifying the _task_ingestion_loop to call
# route_task_with_enrichment instead. Actually, let's just modify _route_task
# inline. But since it's already defined... let's use a different approach.

# The cleanest solution: modify _task_ingestion_loop to call _enrich_task_state
# before _route_task. Let's redefine _task_ingestion_loop.

# Actually, let's just add the enrichment call at the top of _route_task.
# Since Python classes allow us to redefine, but we've already defined it...
# The simplest fix: add _enrich_task_state call inside _route_task.
# Let me update _route_task directly. Since we can't "re-open" the class,
# let's use a post-class monkey patch for clarity:

_original_route_task = Orchestrator._route_task


def _route_task_enriched(self: Orchestrator, task: Task) -> bool:
    """Enriched version of _route_task that stores full task data for reconstruction."""
    self._enrich_task_state(task)
    return _original_route_task(self, task)


Orchestrator._route_task = _route_task_enriched  # type: ignore[assignment]


# ---------------------------------------------------------------------------
# Main Entry Point
# ---------------------------------------------------------------------------

def main() -> None:
    """CLI entry point for the orchestrator."""
    import argparse

    parser = argparse.ArgumentParser(description="Centaur-Jarvis Core Orchestrator")
    parser.add_argument(
        "-c", "--config",
        default="config/core.yaml",
        help="Path to configuration file (default: config/core.yaml)",
    )
    args = parser.parse_args()

    orchestrator = Orchestrator(config_path=args.config)
    orchestrator.start()


if __name__ == "__main__":
    main()
