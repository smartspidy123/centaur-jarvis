"""
Circuit Breaker (per-domain)
============================
Implements the circuit breaker pattern to fast-fail requests to unresponsive
targets, preventing cascading timeouts.

States (UPPERCASE):
  CLOSED   — normal operation, requests flow through.
  OPEN     — target is down, requests immediately rejected.
  HALF_OPEN — recovery probe: limited test requests allowed.

All status strings are UPPERCASE per global architecture rule.
"""

import time
import threading
from typing import Dict, Optional, Tuple
from enum import Enum

try:
    from shared.logger import get_logger
    logger = get_logger("http_client.circuit_breaker")
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

    logger = logging.getLogger("http_client.circuit_breaker")
    if not logger.handlers:
        _h = logging.StreamHandler()
        _h.setFormatter(_JsonFormatter())
        logger.addHandler(_h)
        logger.setLevel(logging.INFO)


class CircuitState(str, Enum):
    CLOSED = "CLOSED"
    OPEN = "OPEN"
    HALF_OPEN = "HALF_OPEN"


class _DomainCircuit:
    """State for a single domain's circuit."""

    __slots__ = (
        "state", "failure_count", "success_count_half_open",
        "last_failure_time", "last_state_change",
    )

    def __init__(self) -> None:
        self.state: CircuitState = CircuitState.CLOSED
        self.failure_count: int = 0
        self.success_count_half_open: int = 0
        self.last_failure_time: float = 0.0
        self.last_state_change: float = time.monotonic()


class CircuitBreaker:
    """Per-domain circuit breaker.

    Args:
        failure_threshold: Consecutive failures to trip OPEN.
        recovery_timeout: Seconds in OPEN before moving to HALF_OPEN.
        half_open_max_calls: Successful calls in HALF_OPEN to close circuit.
        redis_client: Optional Redis for shared state (future use).
        redis_key_prefix: Redis key namespace.
    """

    def __init__(
        self,
        failure_threshold: int = 10,
        recovery_timeout: float = 30.0,
        half_open_max_calls: int = 2,
        redis_client: Optional[object] = None,
        redis_key_prefix: str = "centaur:circuit",
    ) -> None:
        self._threshold = failure_threshold
        self._recovery_timeout = recovery_timeout
        self._half_open_max = half_open_max_calls
        self._redis = redis_client
        self._prefix = redis_key_prefix
        self._lock = threading.Lock()
        self._circuits: Dict[str, _DomainCircuit] = {}

        logger.info(
            "CircuitBreaker initialised",
            extra={
                "failure_threshold": failure_threshold,
                "recovery_timeout": recovery_timeout,
                "half_open_max_calls": half_open_max_calls,
            },
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def allow_request(self, domain: str) -> Tuple[bool, str]:
        """Check whether a request to `domain` is allowed.

        Returns:
            (allowed: bool, state: str)
        """
        with self._lock:
            circuit = self._get_or_create(domain)

            if circuit.state == CircuitState.CLOSED:
                return True, CircuitState.CLOSED.value

            if circuit.state == CircuitState.OPEN:
                elapsed = time.monotonic() - circuit.last_state_change
                if elapsed >= self._recovery_timeout:
                    circuit.state = CircuitState.HALF_OPEN
                    circuit.success_count_half_open = 0
                    circuit.last_state_change = time.monotonic()
                    logger.info("Circuit HALF_OPEN for domain=%s", domain)
                    self._sync_redis(domain, CircuitState.HALF_OPEN.value)
                    return True, CircuitState.HALF_OPEN.value
                else:
                    return False, CircuitState.OPEN.value

            if circuit.state == CircuitState.HALF_OPEN:
                return True, CircuitState.HALF_OPEN.value

            return False, circuit.state.value  # fallback

    def record_success(self, domain: str) -> None:
        """Record a successful request."""
        with self._lock:
            circuit = self._get_or_create(domain)
            if circuit.state == CircuitState.HALF_OPEN:
                circuit.success_count_half_open += 1
                if circuit.success_count_half_open >= self._half_open_max:
                    circuit.state = CircuitState.CLOSED
                    circuit.failure_count = 0
                    circuit.last_state_change = time.monotonic()
                    logger.info("Circuit CLOSED (recovered) for domain=%s", domain)
                    self._sync_redis(domain, CircuitState.CLOSED.value)
            elif circuit.state == CircuitState.CLOSED:
                circuit.failure_count = 0  # reset on success

    def record_failure(self, domain: str) -> None:
        """Record a failed request."""
        with self._lock:
            circuit = self._get_or_create(domain)
            circuit.failure_count += 1
            circuit.last_failure_time = time.monotonic()

            if circuit.state == CircuitState.HALF_OPEN:
                # Any failure in HALF_OPEN re-opens
                circuit.state = CircuitState.OPEN
                circuit.last_state_change = time.monotonic()
                logger.warning("Circuit re-OPENED (HALF_OPEN failure) for domain=%s", domain)
                self._sync_redis(domain, CircuitState.OPEN.value)

            elif circuit.state == CircuitState.CLOSED:
                if circuit.failure_count >= self._threshold:
                    circuit.state = CircuitState.OPEN
                    circuit.last_state_change = time.monotonic()
                    logger.warning(
                        "Circuit OPENED after %d failures for domain=%s",
                        circuit.failure_count,
                        domain,
                    )
                    self._sync_redis(domain, CircuitState.OPEN.value)

    def get_state(self, domain: str) -> str:
        """Return the current circuit state string (UPPERCASE)."""
        with self._lock:
            circuit = self._circuits.get(domain)
            if circuit is None:
                return CircuitState.CLOSED.value
            # Check for automatic HALF_OPEN transition
            if circuit.state == CircuitState.OPEN:
                elapsed = time.monotonic() - circuit.last_state_change
                if elapsed >= self._recovery_timeout:
                    return CircuitState.HALF_OPEN.value
            return circuit.state.value

    def reset(self, domain: str) -> None:
        """Manually reset a domain's circuit to CLOSED."""
        with self._lock:
            if domain in self._circuits:
                c = self._circuits[domain]
                c.state = CircuitState.CLOSED
                c.failure_count = 0
                c.success_count_half_open = 0
                c.last_state_change = time.monotonic()
                logger.info("Circuit manually RESET to CLOSED for domain=%s", domain)
                self._sync_redis(domain, CircuitState.CLOSED.value)

    @property
    def stats(self) -> Dict:
        with self._lock:
            return {
                "data": {
                    domain: {
                        "state": c.state.value,
                        "failure_count": c.failure_count,
                    }
                    for domain, c in self._circuits.items()
                }
            }

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _get_or_create(self, domain: str) -> _DomainCircuit:
        if domain not in self._circuits:
            self._circuits[domain] = _DomainCircuit()
        return self._circuits[domain]

    def _sync_redis(self, domain: str, state: str) -> None:
        if self._redis is None:
            return
        try:
            key = f"{self._prefix}:{domain}"
            self._redis.hset(key, mapping={"state": state, "updated": str(time.time())})  # type: ignore[union-attr]
            self._redis.expire(key, 3600)  # type: ignore[union-attr]
        except Exception as exc:
            logger.warning("Failed to sync circuit state to Redis: %s", exc)
