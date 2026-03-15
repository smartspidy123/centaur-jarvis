"""
Fuzz Executor — Rate-limited HTTP sender for the Smart Fuzzer.

Responsibilities:
    1. Send fuzz payloads via HTTP using the shared http_client.
    2. Enforce per-target-host rate limiting (token bucket via Redis or in-memory fallback).
    3. Handle timeouts, connection errors, and WAF responses gracefully.
    4. Return structured response data for the fuzzer's analysis loop.

Design Principles:
    - Never throw uncaught exceptions — always return a FuzzResponse.
    - Respect Retry-After headers on 429 responses.
    - Log every request at DEBUG level for auditability.
"""

import time
import threading
from typing import Optional, Dict, Any
from dataclasses import dataclass, field
from urllib.parse import urlparse

from shared.logger import get_logger

logger = get_logger("smart_fuzzer.executor")

# Try importing the shared HTTP client
_HTTP_CLIENT_AVAILABLE = True
try:
    from modules.http_client.client import HttpClient
except ImportError as e:
    _HTTP_CLIENT_AVAILABLE = False
    logger.warning("HttpClient import failed: %s — executor will use requests directly.", e)
    import requests as _requests_lib


@dataclass
class FuzzResponse:
    """Structured result of a single fuzz request."""
    status_code: int = 0
    body: str = ""
    headers: Dict[str, str] = field(default_factory=dict)
    elapsed_ms: float = 0.0
    error: Optional[str] = None
    is_timeout: bool = False
    is_connection_error: bool = False
    is_waf_block: bool = False
    retry_after: Optional[float] = None  # Seconds to wait if 429

    @property
    def success(self) -> bool:
        return self.error is None and self.status_code > 0

    @property
    def body_snippet(self) -> str:
        """First 2000 chars of body for AI context."""
        return self.body[:2000] if self.body else ""


class _TokenBucket:
    """
    Thread-safe in-memory token bucket rate limiter.
    One bucket per target host.
    """

    def __init__(self, rate: float, burst: int):
        """
        Args:
            rate: Tokens added per second.
            burst: Maximum tokens (bucket capacity).
        """
        self._rate = max(rate, 0.1)
        self._burst = max(burst, 1)
        self._tokens = float(self._burst)
        self._last_refill = time.monotonic()
        self._lock = threading.Lock()

    def acquire(self, timeout: float = 30.0) -> bool:
        """
        Block until a token is available or timeout is reached.

        Returns:
            True if token acquired, False if timed out.
        """
        deadline = time.monotonic() + timeout
        while True:
            with self._lock:
                self._refill()
                if self._tokens >= 1.0:
                    self._tokens -= 1.0
                    return True

            # Calculate wait time for next token
            with self._lock:
                wait = (1.0 - self._tokens) / self._rate

            wait = min(wait, 0.5)  # Check at least every 500ms
            if time.monotonic() + wait > deadline:
                return False
            time.sleep(wait)

    def _refill(self):
        now = time.monotonic()
        elapsed = now - self._last_refill
        self._tokens = min(self._burst, self._tokens + elapsed * self._rate)
        self._last_refill = now


class FuzzExecutor:
    """
    Rate-limited HTTP executor for fuzzing payloads.

    Usage:
        executor = FuzzExecutor(config)
        response = executor.send(
            url="http://target/search",
            method="GET",
            params={"q": "<script>alert(1)</script>"},
        )
        if response.is_waf_block:
            # trigger mutation
    """

    # WAF-indicative status codes
    WAF_STATUS_CODES = frozenset({403, 429, 406, 501})
    WAF_BODY_PATTERNS = [
        "blocked", "firewall", "access denied", "not acceptable",
        "rate limit", "cloudflare", "akamai", "imperva", "mod_security",
    ]

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self._config = config or {}
        self._exec_config = self._config.get("executor", {})
        self._rl_config = self._config.get("rate_limit", {})

        # Executor settings
        self._timeout = self._exec_config.get("timeout", 10)
        self._follow_redirects = self._exec_config.get("follow_redirects", True)
        self._max_redirect_depth = self._exec_config.get("max_redirect_depth", 5)
        self._scope_check = self._exec_config.get("scope_check_redirects", True)
        self._snippet_max = self._exec_config.get("response_snippet_max_chars", 2000)

        # Rate limit settings
        self._default_rate = self._rl_config.get("default_rate", 5)
        self._default_burst = self._rl_config.get("default_burst", 10)
        self._backoff_base = self._rl_config.get("backoff_base", 2.0)
        self._backoff_max = self._rl_config.get("backoff_max", 60.0)
        self._respect_retry_after = self._rl_config.get("retry_after_respect", True)

        # Per-host rate limiters (lazily created)
        self._limiters: Dict[str, _TokenBucket] = {}
        self._limiters_lock = threading.Lock()

        # HTTP Client
        self._http_client = None
        if _HTTP_CLIENT_AVAILABLE:
            try:
                self._http_client = HttpClient()
                logger.info("FuzzExecutor using shared HttpClient.")
            except Exception as e:
                logger.warning("Failed to initialize HttpClient: %s — using raw requests.", e)

        # Track consecutive 429s per host for exponential backoff
        self._backoff_counts: Dict[str, int] = {}

    # ------------------------------------------------------------------
    # PUBLIC: send
    # ------------------------------------------------------------------
    def send(
        self,
        url: str,
        method: str = "GET",
        params: Optional[Dict[str, str]] = None,
        data: Optional[Dict[str, Any]] = None,
        json_body: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        allowed_scope: Optional[str] = None,
    ) -> FuzzResponse:
        """
        Send a single fuzz request with rate limiting.

        Args:
            url: Target URL.
            method: HTTP method.
            params: Query string parameters.
            data: Form-encoded body parameters.
            json_body: JSON body.
            headers: Additional headers.
            allowed_scope: Base domain for scope checking on redirects.

        Returns:
            FuzzResponse with status, body, headers, and metadata.
        """
        host = self._extract_host(url)

        # Acquire rate limit token
        limiter = self._get_limiter(host)
        if not limiter.acquire(timeout=30.0):
            logger.warning("Rate limit acquire timeout for host '%s'.", host)
            return FuzzResponse(
                error="Rate limit acquire timeout (local token bucket).",
                is_timeout=True,
            )

        # Check if we need exponential backoff (from previous 429s)
        backoff_wait = self._get_backoff_wait(host)
        if backoff_wait > 0:
            logger.debug("Backoff wait of %.1fs for host '%s'.", backoff_wait, host)
            time.sleep(backoff_wait)

        # Execute request
        logger.debug(
            "FUZZ REQUEST: %s %s | params=%s | data=%s | json=%s",
            method.upper(),
            url,
            self._mask_values(params),
            self._mask_values(data),
            "yes" if json_body else "no",
        )

        start_ts = time.monotonic()

        try:
            resp = self._do_request(
                url=url,
                method=method.upper(),
                params=params,
                data=data,
                json_body=json_body,
                headers=headers,
            )
            elapsed_ms = (time.monotonic() - start_ts) * 1000

            # Build response
            fuzz_resp = FuzzResponse(
                status_code=resp.status_code,
                body=self._safe_text(resp),
                headers=dict(resp.headers) if resp.headers else {},
                elapsed_ms=elapsed_ms,
            )

            # Check for WAF indicators
            fuzz_resp.is_waf_block = self._detect_waf(fuzz_resp)

            if fuzz_resp.is_waf_block:
                self._increment_backoff(host)

                # Extract Retry-After if present
                retry_after = resp.headers.get("Retry-After")
                if retry_after and self._respect_retry_after:
                    try:
                        fuzz_resp.retry_after = float(retry_after)
                    except ValueError:
                        fuzz_resp.retry_after = 5.0  # Default if unparseable
            else:
                # Reset backoff on successful non-WAF response
                self._reset_backoff(host)

            logger.debug(
                "FUZZ RESPONSE: %d in %.0fms | WAF=%s | body_len=%d",
                fuzz_resp.status_code,
                elapsed_ms,
                fuzz_resp.is_waf_block,
                len(fuzz_resp.body),
            )

            return fuzz_resp

        except Exception as e:
            elapsed_ms = (time.monotonic() - start_ts) * 1000
            err_type = type(e).__name__

            is_timeout = "timeout" in err_type.lower() or "timeout" in str(e).lower()
            is_conn = "connection" in err_type.lower() or "connect" in str(e).lower()

            logger.warning(
                "FUZZ REQUEST FAILED: %s %s | error=%s: %s | %.0fms",
                method.upper(),
                url,
                err_type,
                str(e)[:200],
                elapsed_ms,
            )

            return FuzzResponse(
                error=f"{err_type}: {str(e)[:500]}",
                elapsed_ms=elapsed_ms,
                is_timeout=is_timeout,
                is_connection_error=is_conn or (not is_timeout),
            )

    # ------------------------------------------------------------------
    # INTERNAL: HTTP execution
    # ------------------------------------------------------------------
    def _do_request(self, url, method, params, data, json_body, headers):
        """Execute HTTP request via shared client or raw requests."""
        kwargs = {
            "timeout": self._timeout,
            "allow_redirects": self._follow_redirects,
        }
        if params:
            kwargs["params"] = params
        if data:
            kwargs["data"] = data
        if json_body:
            kwargs["json"] = json_body
        if headers:
            kwargs["headers"] = headers

        if self._http_client:
            # Use shared HTTP client (has proxy rotation, etc.)
            return self._http_client.request(method=method, url=url, **kwargs)
        else:
            # Fallback to raw requests
            import requests
            return requests.request(method=method, url=url, **kwargs)

    # ------------------------------------------------------------------
    # WAF Detection
    # ------------------------------------------------------------------
    def _detect_waf(self, resp: FuzzResponse) -> bool:
        """Heuristic WAF detection based on status code and body patterns."""
        if resp.status_code in self.WAF_STATUS_CODES:
            return True

        body_lower = resp.body.lower() if resp.body else ""
        for pattern in self.WAF_BODY_PATTERNS:
            if pattern in body_lower:
                # Only flag as WAF if status is also suspicious (not 200 with word "firewall" in content)
                if resp.status_code >= 400:
                    return True

        return False

    # ------------------------------------------------------------------
    # Rate Limiting Helpers
    # ------------------------------------------------------------------
    def _get_limiter(self, host: str) -> _TokenBucket:
        with self._limiters_lock:
            if host not in self._limiters:
                self._limiters[host] = _TokenBucket(
                    rate=self._default_rate,
                    burst=self._default_burst,
                )
            return self._limiters[host]

    def _extract_host(self, url: str) -> str:
        try:
            parsed = urlparse(url)
            return parsed.netloc or parsed.hostname or "unknown"
        except Exception:
            return "unknown"

    def _get_backoff_wait(self, host: str) -> float:
        count = self._backoff_counts.get(host, 0)
        if count <= 0:
            return 0.0
        wait = min(self._backoff_base ** count, self._backoff_max)
        return wait

    def _increment_backoff(self, host: str):
        self._backoff_counts[host] = self._backoff_counts.get(host, 0) + 1

    def _reset_backoff(self, host: str):
        self._backoff_counts.pop(host, None)

    # ------------------------------------------------------------------
    # Utilities
    # ------------------------------------------------------------------
    @staticmethod
    def _safe_text(resp) -> str:
        """Safely extract response text, handling encoding issues."""
        try:
            return resp.text or ""
        except Exception:
            try:
                return resp.content.decode("utf-8", errors="replace")
            except Exception:
                return ""

    @staticmethod
    def _mask_values(d: Optional[Dict]) -> Optional[Dict]:
        """Mask dictionary values for logging (show first 30 chars)."""
        if not d:
            return d
        return {k: (str(v)[:30] + "..." if len(str(v)) > 30 else v) for k, v in d.items()}
