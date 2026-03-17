"""
Proxy Rotator
=============
Manages a pool of HTTP / HTTPS / SOCKS5 proxies with:
  - Automatic rotation on failure
  - Dead-proxy cooldown & resurrection
  - Health checking
  - Redis-backed state sharing (with in-memory fallback)

All status strings are UPPERCASE: 'ACTIVE', 'DEAD'.
"""

import time
import threading
import random
from typing import Dict, List, Optional
from urllib.parse import urlparse

try:
    from shared.logger import get_logger
    logger = get_logger("http_client.proxy_rotator")
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

    logger = logging.getLogger("http_client.proxy_rotator")
    if not logger.handlers:
        _h = logging.StreamHandler()
        _h.setFormatter(_JsonFormatter())
        logger.addHandler(_h)
        logger.setLevel(logging.INFO)

try:
    import redis as redis_lib
except ImportError:
    redis_lib = None  # type: ignore[assignment]


class _ProxyEntry:
    """In-memory state for a single proxy."""

    __slots__ = (
        "url", "status", "consecutive_failures",
        "last_failure_time", "total_requests", "total_failures",
    )

    def __init__(self, url: str) -> None:
        self.url: str = url
        self.status: str = "ACTIVE"
        self.consecutive_failures: int = 0
        self.last_failure_time: float = 0.0
        self.total_requests: int = 0
        self.total_failures: int = 0


class ProxyRotator:
    """Thread-safe proxy pool with rotation, health tracking, and resurrection.

    Args:
        proxies: List of proxy URLs.
        max_failures: Consecutive failures before marking DEAD.
        dead_cooldown: Seconds before resurrecting a DEAD proxy.
        fallback_direct: If True, return None (direct connection) when all dead.
        redis_client: Optional Redis client for shared state.
        redis_key_prefix: Redis key namespace.
    """

    def __init__(
        self,
        proxies: Optional[List[str]] = None,
        max_failures: int = 3,
        dead_cooldown: float = 60.0,
        fallback_direct: bool = True,
        redis_client: Optional[object] = None,
        redis_key_prefix: str = "centaur:proxy",
    ) -> None:
        self._lock = threading.Lock()
        self._max_failures = max_failures
        self._dead_cooldown = dead_cooldown
        self._fallback_direct = fallback_direct
        self._redis = redis_client
        self._redis_prefix = redis_key_prefix

        # Build proxy entries
        self._entries: Dict[str, _ProxyEntry] = {}
        self._order: List[str] = []
        for p in (proxies or []):
            p = p.strip()
            if not p:
                continue
            # Normalise socks5 → socks5h to avoid DNS leaks
            if p.startswith("socks5://"):
                p = "socks5h://" + p[len("socks5://"):]
                logger.info("Rewrote socks5:// → socks5h:// to prevent DNS leaks: %s", p)
            self._entries[p] = _ProxyEntry(p)
            self._order.append(p)

        self._index = 0
        logger.info(
            "ProxyRotator initialised",
            extra={"proxy_count": len(self._order), "fallback_direct": fallback_direct},
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def get_proxy(self) -> Optional[str]:
        """Return the next usable proxy URL, or None for direct connection.

        Resurrects dead proxies whose cooldown has expired.
        """
        with self._lock:
            self._resurrect_expired()

            active = [u for u in self._order if self._entries[u].status == "ACTIVE"]
            if not active:
                if self._fallback_direct:
                    logger.critical(
                        "ALL PROXIES DEAD — falling back to DIRECT connection"
                    )
                    return None
                else:
                    logger.critical("ALL PROXIES DEAD and fallback_direct=False")
                    return None

            # Round-robin among active proxies
            self._index = self._index % len(active)
            chosen = active[self._index]
            self._index = (self._index + 1) % len(active)
            self._entries[chosen].total_requests += 1

            logger.debug("Proxy selected: %s", self._mask_proxy(chosen))
            return chosen

    def get_proxy_dict(self) -> Optional[Dict[str, str]]:
        """Return proxy in requests-compatible dict format, or None."""
        url = self.get_proxy()
        if url is None:
            return None
        parsed = urlparse(url)
        scheme = parsed.scheme.lower()
        if scheme in ("socks5", "socks5h"):
            return {"http": url, "https": url}
        return {"http": url, "https": url}

    def report_success(self, proxy_url: str) -> None:
        """Mark a proxy as having succeeded."""
        with self._lock:
            entry = self._entries.get(proxy_url)
            if entry:
                entry.consecutive_failures = 0
                if entry.status != "ACTIVE":
                    logger.info("Proxy resurrected via success: %s", self._mask_proxy(proxy_url))
                    entry.status = "ACTIVE"
                self._sync_to_redis(proxy_url, "ACTIVE")

    def report_failure(self, proxy_url: str) -> None:
        """Record a failure. Mark DEAD if threshold crossed."""
        with self._lock:
            entry = self._entries.get(proxy_url)
            if not entry:
                return
            entry.consecutive_failures += 1
            entry.total_failures += 1
            entry.last_failure_time = time.monotonic()

            if entry.consecutive_failures >= self._max_failures:
                if entry.status != "DEAD":
                    entry.status = "DEAD"
                    logger.warning(
                        "Proxy marked DEAD after %d failures: %s",
                        entry.consecutive_failures,
                        self._mask_proxy(proxy_url),
                    )
                    self._sync_to_redis(proxy_url, "DEAD")

    @property
    def stats(self) -> Dict:
        """Return pool statistics."""
        with self._lock:
            active = sum(1 for e in self._entries.values() if e.status == "ACTIVE")
            dead = sum(1 for e in self._entries.values() if e.status == "DEAD")
            return {
                "total": len(self._entries),
                "active": active,
                "dead": dead,
                "data": {
                    url: {
                        "status": e.status,
                        "consecutive_failures": e.consecutive_failures,
                        "total_requests": e.total_requests,
                        "total_failures": e.total_failures,
                    }
                    for url, e in self._entries.items()
                },
            }

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _resurrect_expired(self) -> None:
        """Move DEAD proxies back to ACTIVE if cooldown has elapsed."""
        now = time.monotonic()
        for entry in self._entries.values():
            if entry.status == "DEAD" and (now - entry.last_failure_time) >= self._dead_cooldown:
                entry.status = "ACTIVE"
                entry.consecutive_failures = 0
                logger.info("Proxy resurrected (cooldown expired): %s", self._mask_proxy(entry.url))
                self._sync_to_redis(entry.url, "ACTIVE")

    def _sync_to_redis(self, proxy_url: str, status: str) -> None:
        """Persist proxy state to Redis (best-effort)."""
        if self._redis is None:
            return
        try:
            key = f"{self._redis_prefix}:{proxy_url}"
            self._redis.hset(key, mapping={"status": status, "updated": str(time.time())})  # type: ignore[union-attr]
            self._redis.expire(key, 3600)  # type: ignore[union-attr]
        except Exception as exc:
            logger.warning("Failed to sync proxy state to Redis: %s", exc)

    @staticmethod
    def _mask_proxy(url: str) -> str:
        """Mask credentials in proxy URL for safe logging."""
        parsed = urlparse(url)
        if parsed.username:
            return url.replace(f"{parsed.username}:{parsed.password}@", "****:****@")
        return url
