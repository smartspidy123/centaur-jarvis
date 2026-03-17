"""
Rate Limiter — Token Bucket (per-domain)
=========================================
Redis-backed for multi-worker consistency, with transparent in-memory fallback.

Uses Redis Lua scripts for atomic token consumption.

All status strings are UPPERCASE.
"""

import time
import threading
from typing import Dict, Optional, Tuple

try:
    from shared.logger import get_logger
    logger = get_logger("http_client.rate_limiter")
except ImportError:
    import logging
    import json as _json

    class _JsonFormatter(logging.Formatter):
        def format(self, record):
            return _json.dumps({
                "timestamp": self.formatTime(record),
                "level": record.levelname,
                "module": record.name,
                "message": record.getMessage(),
            })

    logger = logging.getLogger("http_client.rate_limiter")
    if not logger.handlers:
        _h = logging.StreamHandler()
        _h.setFormatter(_JsonFormatter())
        logger.addHandler(_h)
        logger.setLevel(logging.INFO)

try:
    import redis as redis_lib
except ImportError:
    redis_lib = None  # type: ignore[assignment]

# ---------------------------------------------------------------------------
# Lua script for atomic token bucket in Redis
# ---------------------------------------------------------------------------
_LUA_TOKEN_BUCKET = """
local key = KEYS[1]
local capacity = tonumber(ARGV[1])
local rate = tonumber(ARGV[2])
local now = tonumber(ARGV[3])
local ttl = tonumber(ARGV[4])

local bucket = redis.call('HMGET', key, 'tokens', 'last_refill')
local tokens = tonumber(bucket[1])
local last_refill = tonumber(bucket[2])

if tokens == nil then
    tokens = capacity
    last_refill = now
end

-- Refill tokens
local elapsed = math.max(0, now - last_refill)
local new_tokens = elapsed * rate
tokens = math.min(capacity, tokens + new_tokens)
last_refill = now

if tokens >= 1 then
    tokens = tokens - 1
    redis.call('HMSET', key, 'tokens', tostring(tokens), 'last_refill', tostring(last_refill))
    redis.call('EXPIRE', key, ttl)
    return {1, tostring(tokens)}
else
    redis.call('HMSET', key, 'tokens', tostring(tokens), 'last_refill', tostring(last_refill))
    redis.call('EXPIRE', key, ttl)
    -- Return wait time until 1 token available
    local wait = (1 - tokens) / rate
    return {0, tostring(wait)}
end
"""


class _InMemoryBucket:
    """Thread-safe in-memory token bucket for a single domain."""

    __slots__ = ("capacity", "rate", "tokens", "last_refill", "_lock")

    def __init__(self, capacity: float, rate: float) -> None:
        self.capacity = capacity
        self.rate = rate
        self.tokens = capacity
        self.last_refill = time.monotonic()
        self._lock = threading.Lock()

    def try_consume(self) -> Tuple[bool, float]:
        """Try to consume 1 token. Returns (allowed, wait_seconds)."""
        with self._lock:
            now = time.monotonic()
            elapsed = max(0.0, now - self.last_refill)
            self.tokens = min(self.capacity, self.tokens + elapsed * self.rate)
            self.last_refill = now

            if self.tokens >= 1.0:
                self.tokens -= 1.0
                return True, 0.0
            else:
                wait = (1.0 - self.tokens) / self.rate
                return False, wait


class RateLimiter:
    """Per-domain token bucket rate limiter.

    Uses Redis Lua script for atomic operations in multi-worker setups.
    Falls back to in-memory buckets when Redis is unavailable.

    Args:
        redis_client: Optional redis.Redis instance.
        default_rate: Default tokens per second per domain.
        default_capacity: Default bucket capacity (burst).
        domain_rates: Dict of domain → {"rate": float, "capacity": float}.
        redis_key_prefix: Redis key namespace.
        key_ttl: Auto-expire Redis keys (seconds).
    """

    def __init__(
        self,
        redis_client: Optional[object] = None,
        default_rate: float = 10.0,
        default_capacity: float = 20.0,
        domain_rates: Optional[Dict[str, Dict[str, float]]] = None,
        redis_key_prefix: str = "centaur:ratelimit",
        key_ttl: int = 3600,
    ) -> None:
        self._redis = redis_client
        self._default_rate = default_rate
        self._default_capacity = default_capacity
        self._domain_rates: Dict[str, Dict[str, float]] = domain_rates or {}
        self._prefix = redis_key_prefix
        self._key_ttl = key_ttl

        # In-memory fallback buckets
        self._mem_buckets: Dict[str, _InMemoryBucket] = {}
        self._mem_lock = threading.Lock()

        # Pre-register Lua script
        self._lua_sha: Optional[str] = None
        self._redis_available = False
        self._init_redis()

        logger.info(
            "RateLimiter initialised",
            extra={
                "redis_available": self._redis_available,
                "default_rate": default_rate,
                "default_capacity": default_capacity,
                "domain_overrides": len(self._domain_rates),
            },
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def acquire(self, domain: str) -> Tuple[bool, float]:
        """Try to acquire a token for the given domain.

        Returns:
            (allowed: bool, wait_seconds: float)
            If allowed=True, request may proceed. If False, caller should wait
            `wait_seconds` before retrying.
        """
        rate, capacity = self._get_domain_config(domain)

        if self._redis_available:
            try:
                return self._redis_acquire(domain, rate, capacity)
            except Exception as exc:
                logger.warning("Redis rate-limit failed, using in-memory fallback: %s", exc)
                self._redis_available = False

        return self._memory_acquire(domain, rate, capacity)

    def respect_retry_after(self, domain: str, retry_after: float) -> None:
        """Drain tokens for a domain to enforce Retry-After.

        This is a best-effort operation: we set remaining tokens to 0
        and let the refill naturally enforce the delay.
        """
        if self._redis_available:
            try:
                key = f"{self._prefix}:{domain}"
                self._redis.hset(key, "tokens", "0")  # type: ignore[union-attr]
                logger.info(
                    "Rate limiter: respecting Retry-After=%.1fs for %s (Redis)", retry_after, domain
                )
                return
            except Exception:
                pass

        with self._mem_lock:
            bucket = self._mem_buckets.get(domain)
            if bucket:
                with bucket._lock:
                    bucket.tokens = 0.0
        logger.info("Rate limiter: respecting Retry-After=%.1fs for %s (memory)", retry_after, domain)

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _get_domain_config(self, domain: str) -> Tuple[float, float]:
        cfg = self._domain_rates.get(domain, {})
        rate = cfg.get("rate", self._default_rate)
        capacity = cfg.get("capacity", self._default_capacity)
        return rate, capacity

    def _init_redis(self) -> None:
        if self._redis is None:
            logger.info("No Redis client provided — using in-memory rate limiter")
            return
        try:
            self._redis.ping()  # type: ignore[union-attr]
            self._lua_sha = self._redis.script_load(_LUA_TOKEN_BUCKET)  # type: ignore[union-attr]
            self._redis_available = True
        except Exception as exc:
            logger.warning("Redis unavailable for rate limiter: %s — using in-memory fallback", exc)
            self._redis_available = False

    def _redis_acquire(self, domain: str, rate: float, capacity: float) -> Tuple[bool, float]:
        key = f"{self._prefix}:{domain}"
        now = time.time()
        result = self._redis.evalsha(  # type: ignore[union-attr]
            self._lua_sha, 1, key, str(capacity), str(rate), str(now), str(self._key_ttl)
        )
        allowed = int(result[0]) == 1
        value = float(result[1])
        if not allowed:
            logger.info("RATE_LIMITED domain=%s wait=%.2fs (Redis)", domain, value)
        return allowed, value if not allowed else 0.0

    def _memory_acquire(self, domain: str, rate: float, capacity: float) -> Tuple[bool, float]:
        with self._mem_lock:
            if domain not in self._mem_buckets:
                self._mem_buckets[domain] = _InMemoryBucket(capacity, rate)
            bucket = self._mem_buckets[domain]

        allowed, wait = bucket.try_consume()
        if not allowed:
            logger.info("RATE_LIMITED domain=%s wait=%.2fs (memory)", domain, wait)
        return allowed, wait
