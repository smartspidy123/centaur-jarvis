"""
HttpClient — Main Advanced HTTP Client
=======================================
Central facade integrating:
  - TLS fingerprint randomisation (curl_cffi)
  - HTTP/2 support (httpx)
  - Proxy rotation
  - Per-domain rate limiting
  - Circuit breaker
  - User-Agent & header spoofing
  - Exponential backoff retries
  - Graceful fallback at every layer

All status strings are UPPERCASE.
"""

from __future__ import annotations

import os
import signal
import sys
import time
import threading
from typing import Any, Dict, List, Optional, Union
from urllib.parse import urlparse

import yaml

try:
    from shared.logger import get_logger
    logger = get_logger("http_client.client")
except ImportError:
    import logging
    import json as _json

    class _JsonFormatter(logging.Formatter):
        def format(self, record):
            log_obj = {
                "timestamp": self.formatTime(record),
                "level": record.levelname,
                "module": record.name,
                "message": record.getMessage(),
            }
            if record.exc_info and record.exc_info[0]:
                log_obj["exception"] = self.formatException(record.exc_info)
            return _json.dumps(log_obj)

    logger = logging.getLogger("http_client.client")
    if not logger.handlers:
        _h = logging.StreamHandler()
        _h.setFormatter(_JsonFormatter())
        logger.addHandler(_h)
        logger.setLevel(logging.INFO)

# ---------------------------------------------------------------------------
# Optional dependency imports with graceful fallback
# ---------------------------------------------------------------------------
CURL_CFFI_AVAILABLE = False
try:
    from curl_cffi import requests as curl_requests
    from curl_cffi.requests import Response as CurlResponse
    CURL_CFFI_AVAILABLE = True
except ImportError:
    curl_requests = None  # type: ignore[assignment]
    CurlResponse = None  # type: ignore[assignment, misc]

HTTPX_AVAILABLE = False
try:
    import httpx
    HTTPX_AVAILABLE = True
except ImportError:
    httpx = None  # type: ignore[assignment]

import requests as std_requests  # always available (hard dependency)

try:
    import redis as redis_lib
except ImportError:
    redis_lib = None  # type: ignore[assignment]

# Local imports
from modules.http_client.proxy_rotator import ProxyRotator
from modules.http_client.rate_limiter import RateLimiter
from modules.http_client.circuit_breaker import CircuitBreaker
from modules.http_client.tls_fingerprint import TLSFingerprinter
from modules.http_client.user_agents import UserAgentRotator
from modules.http_client.header_forger import HeaderForger


# ---------------------------------------------------------------------------
# Unified Response wrapper
# ---------------------------------------------------------------------------

class HttpResponse:
    """Unified response object normalising curl_cffi, httpx, and requests."""

    __slots__ = (
        "status_code", "headers", "text", "content", "url",
        "elapsed_ms", "proxy_used", "tls_profile", "http_version",
        "data",
    )

    def __init__(
        self,
        status_code: int,
        headers: Dict[str, str],
        text: str,
        content: bytes,
        url: str,
        elapsed_ms: float,
        proxy_used: Optional[str],
        tls_profile: Optional[str],
        http_version: str,
    ) -> None:
        self.status_code = status_code
        self.headers = headers
        self.text = text
        self.content = content
        self.url = url
        self.elapsed_ms = elapsed_ms
        self.proxy_used = proxy_used
        self.tls_profile = tls_profile
        self.http_version = http_version
        # Mandatory 'data' field per architecture rule
        self.data: Dict[str, Any] = {
            "status_code": status_code,
            "url": url,
            "elapsed_ms": elapsed_ms,
            "http_version": http_version,
        }

    def __repr__(self) -> str:
        return (
            f"<HttpResponse [{self.status_code}] url={self.url} "
            f"elapsed={self.elapsed_ms:.0f}ms via={self.http_version}>"
        )

    @property
    def ok(self) -> bool:
        return 200 <= self.status_code < 400

    def json(self) -> Any:
        import json
        return json.loads(self.text)


# ---------------------------------------------------------------------------
# Configuration loader
# ---------------------------------------------------------------------------

def _load_config(config_path: Optional[str] = None) -> Dict:
    """Load config.yaml with fallback defaults."""
    if config_path is None:
        config_path = os.path.join(os.path.dirname(__file__), "config.yaml")

    defaults: Dict[str, Any] = {
        "http_client": {
            "default_timeout": 30,
            "max_retries": 3,
            "retry_base_delay": 1.0,
            "retry_max_delay": 60.0,
            "verify_ssl": False,
            "prefer_http2": True,
            "prefer_curl_cffi": True,
        },
        "proxy": {
            "proxies": [],
            "max_failures": 3,
            "dead_proxy_cooldown": 60,
            "fallback_direct": True,
            "redis_key_prefix": "centaur:proxy",
        },
        "rate_limiter": {
            "default_rate": 10.0,
            "default_capacity": 20.0,
            "domain_rates": {},
            "redis_key_prefix": "centaur:ratelimit",
            "key_ttl": 3600,
        },
        "circuit_breaker": {
            "failure_threshold": 10,
            "recovery_timeout": 30,
            "half_open_max_calls": 2,
            "redis_key_prefix": "centaur:circuit",
        },
        "tls": {
            "impersonation_profiles": [
                "chrome110", "chrome107", "chrome104", "chrome101",
                "chrome100", "chrome99", "safari15_5", "safari15_3",
                "edge101", "edge99",
            ],
            "rotate_per_request": True,
        },
        "user_agent": {"rotate_per_request": True},
        "redis": {
            "host": "127.0.0.1", "port": 6379, "db": 0,
            "password": None, "socket_timeout": 5, "retry_on_timeout": True,
        },
    }

    try:
        with open(config_path, "r") as f:
            file_cfg = yaml.safe_load(f) or {}
        # Deep merge (1 level)
        for section, section_defaults in defaults.items():
            if isinstance(section_defaults, dict):
                file_section = file_cfg.get(section, {})
                if isinstance(file_section, dict):
                    merged = {**section_defaults, **file_section}
                    defaults[section] = merged
        logger.info("Configuration loaded from %s", config_path)
        return defaults
    except FileNotFoundError:
        logger.warning("Config file not found at %s — using defaults", config_path)
        return defaults
    except Exception as exc:
        logger.warning("Error loading config: %s — using defaults", exc)
        return defaults


# ---------------------------------------------------------------------------
# Helper: extract domain from URL
# ---------------------------------------------------------------------------

def _extract_domain(url: str) -> str:
    parsed = urlparse(url)
    return parsed.hostname or parsed.netloc or url


# ---------------------------------------------------------------------------
# Main HttpClient class
# ---------------------------------------------------------------------------

class HttpClient:
    """Advanced HTTP client with WAF evasion capabilities.

    Integrates TLS fingerprinting, proxy rotation, rate limiting,
    circuit breaking, and header spoofing into a single clean API.

    Usage:
        client = HttpClient()
        response = client.get("https://example.com")

        # Or with context manager for clean shutdown
        with HttpClient() as client:
            resp = client.get("https://example.com")
    """

    def __init__(
        self,
        config_path: Optional[str] = None,
        redis_client: Optional[object] = None,
        proxies: Optional[List[str]] = None,
    ) -> None:
        self._shutdown_event = threading.Event()
        self._config = _load_config(config_path)

        # ----- Redis connection -----
        self._redis = redis_client
        if self._redis is None:
            self._redis = self._connect_redis()

        # ----- Sub-components -----
        client_cfg = self._config["http_client"]
        proxy_cfg = self._config["proxy"]
        rl_cfg = self._config["rate_limiter"]
        cb_cfg = self._config["circuit_breaker"]
        tls_cfg = self._config["tls"]
        ua_cfg = self._config["user_agent"]

        self._timeout = client_cfg["default_timeout"]
        self._max_retries = client_cfg["max_retries"]
        self._retry_base = client_cfg["retry_base_delay"]
        self._retry_max = client_cfg["retry_max_delay"]
        self._verify_ssl = client_cfg["verify_ssl"]
        self._prefer_http2 = client_cfg["prefer_http2"]
        self._prefer_curl_cffi = client_cfg["prefer_curl_cffi"]

        proxy_list = proxies if proxies is not None else proxy_cfg.get("proxies", [])
        self._proxy_rotator = ProxyRotator(
            proxies=proxy_list,
            max_failures=proxy_cfg["max_failures"],
            dead_cooldown=proxy_cfg["dead_proxy_cooldown"],
            fallback_direct=proxy_cfg["fallback_direct"],
            redis_client=self._redis,
            redis_key_prefix=proxy_cfg["redis_key_prefix"],
        )

        self._rate_limiter = RateLimiter(
            redis_client=self._redis,
            default_rate=rl_cfg["default_rate"],
            default_capacity=rl_cfg["default_capacity"],
            domain_rates=rl_cfg["domain_rates"],
            redis_key_prefix=rl_cfg["redis_key_prefix"],
            key_ttl=rl_cfg["key_ttl"],
        )

        self._circuit_breaker = CircuitBreaker(
            failure_threshold=cb_cfg["failure_threshold"],
            recovery_timeout=cb_cfg["recovery_timeout"],
            half_open_max_calls=cb_cfg["half_open_max_calls"],
            redis_client=self._redis,
            redis_key_prefix=cb_cfg["redis_key_prefix"],
        )

        self._tls_fp = TLSFingerprinter(
            profiles=tls_cfg.get("impersonation_profiles"),
            rotate_per_request=tls_cfg["rotate_per_request"],
        )

        self._ua_rotator = UserAgentRotator(
            rotate_per_request=ua_cfg["rotate_per_request"],
        )

        self._header_forger = HeaderForger()

        # ----- httpx client (persistent for HTTP/2 connection reuse) -----
        self._httpx_client: Optional[Any] = None
        if HTTPX_AVAILABLE and self._prefer_http2:
            try:
                self._httpx_client = httpx.Client(
                    http2=True,
                    verify=self._verify_ssl,
                    timeout=self._timeout,
                    follow_redirects=True,
                )
                logger.info("httpx HTTP/2 client initialised")
            except Exception as exc:
                logger.warning("Failed to initialise httpx HTTP/2 client: %s", exc)
                self._httpx_client = None

        # ----- Graceful shutdown -----
        self._register_signal_handlers()

        logger.info(
            "HttpClient initialised",
            extra={
                "curl_cffi": CURL_CFFI_AVAILABLE,
                "httpx_http2": self._httpx_client is not None,
                "proxy_count": self._proxy_rotator.stats["total"],
                "redis_available": self._redis is not None,
            },
        )

    # ------------------------------------------------------------------
    # Context manager
    # ------------------------------------------------------------------

    def __enter__(self) -> "HttpClient":
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()

    # ------------------------------------------------------------------
    # Public API: HTTP methods
    # ------------------------------------------------------------------

    def get(self, url: str, **kwargs: Any) -> HttpResponse:
        return self.request("GET", url, **kwargs)

    def post(self, url: str, **kwargs: Any) -> HttpResponse:
        return self.request("POST", url, **kwargs)

    def put(self, url: str, **kwargs: Any) -> HttpResponse:
        return self.request("PUT", url, **kwargs)

    def delete(self, url: str, **kwargs: Any) -> HttpResponse:
        return self.request("DELETE", url, **kwargs)

    def head(self, url: str, **kwargs: Any) -> HttpResponse:
        return self.request("HEAD", url, **kwargs)

    def options(self, url: str, **kwargs: Any) -> HttpResponse:
        return self.request("OPTIONS", url, **kwargs)

    def patch(self, url: str, **kwargs: Any) -> HttpResponse:
        return self.request("PATCH", url, **kwargs)

    # ------------------------------------------------------------------
    # Core request orchestrator
    # ------------------------------------------------------------------

    def request(
        self,
        method: str,
        url: str,
        *,
        headers: Optional[Dict[str, str]] = None,
        params: Optional[Dict[str, str]] = None,
        data: Optional[Any] = None,
        json: Optional[Any] = None,
        timeout: Optional[float] = None,
        max_retries: Optional[int] = None,
        use_proxy: bool = True,
        impersonate: Optional[str] = None,
        allow_redirects: bool = True,
        verify: Optional[bool] = None,
    ) -> HttpResponse:
        """Execute an HTTP request with full WAF evasion pipeline.

        Flow:
            1. Circuit breaker check
            2. Rate limiter gate
            3. Proxy selection
            4. TLS fingerprint selection
            5. Header forging
            6. Send request (curl_cffi → httpx → requests)
            7. Handle response (retry logic, error recording)
        """
        domain = _extract_domain(url)
        effective_timeout = timeout or self._timeout
        effective_retries = max_retries if max_retries is not None else self._max_retries
        effective_verify = verify if verify is not None else self._verify_ssl

        last_error: Optional[Exception] = None

        for attempt in range(1, effective_retries + 2):  # +1 for initial attempt
            if self._shutdown_event.is_set():
                raise RuntimeError("HttpClient is shutting down")

            # ------ 1. Circuit breaker ------
            allowed, state = self._circuit_breaker.allow_request(domain)
            if not allowed:
                logger.warning(
                    "Circuit OPEN for %s — fast-failing request", domain
                )
                raise CircuitOpenError(
                    f"Circuit breaker OPEN for domain {domain}. State: {state}"
                )

            # ------ 2. Rate limiter ------
            rate_allowed, wait_time = self._rate_limiter.acquire(domain)
            if not rate_allowed:
                if attempt <= effective_retries:
                    logger.info(
                        "Rate limited for %s, waiting %.2fs (attempt %d/%d)",
                        domain, wait_time, attempt, effective_retries + 1,
                    )
                    time.sleep(min(wait_time, self._retry_max))
                    continue
                else:
                    raise RateLimitExceededError(
                        f"Rate limit exceeded for {domain}, wait={wait_time:.2f}s"
                    )

            # ------ 3. Proxy selection ------
            proxy_url: Optional[str] = None
            proxy_dict: Optional[Dict[str, str]] = None
            if use_proxy:
                proxy_url = self._proxy_rotator.get_proxy()
                if proxy_url:
                    proxy_dict = {"http": proxy_url, "https": proxy_url}

            # ------ 4. TLS fingerprint ------
            profile, browser_family = self._tls_fp.get_profile_and_family()
            if impersonate:
                profile = impersonate
                browser_family = self._tls_fp.get_browser_family(impersonate)

            # ------ 5. User-Agent & Headers ------
            ua = self._ua_rotator.get_for_browser(browser_family)
            forged = self._header_forger.forge(
                url=url,
                user_agent=ua,
                browser_family=browser_family,
                extra_headers=headers,
                randomise_order=True,
            )

            # ------ 6. Send request ------
            start = time.monotonic()
            try:
                response = self._dispatch(
                    method=method,
                    url=url,
                    headers=forged,
                    params=params,
                    data=data,
                    json_body=json,
                    proxy_url=proxy_url,
                    proxy_dict=proxy_dict,
                    profile=profile,
                    timeout=effective_timeout,
                    verify=effective_verify,
                    allow_redirects=allow_redirects,
                )
                elapsed_ms = (time.monotonic() - start) * 1000

                # ------ 7. Handle response ------
                http_resp = self._build_response(
                    response, elapsed_ms, proxy_url, profile
                )

                # Success path
                if http_resp.ok:
                    if proxy_url:
                        self._proxy_rotator.report_success(proxy_url)
                    self._circuit_breaker.record_success(domain)
                    logger.info(
                        "Request OK",
                        extra={
                            "method": method,
                            "url": url,
                            "status": http_resp.status_code,
                            "elapsed_ms": f"{elapsed_ms:.0f}",
                            "proxy": self._mask(proxy_url),
                            "tls_profile": profile,
                            "http_version": http_resp.http_version,
                        },
                    )
                    return http_resp

                # Rate limit (429)
                if http_resp.status_code == 429:
                    retry_after = self._parse_retry_after(http_resp.headers)
                    self._rate_limiter.respect_retry_after(domain, retry_after)
                    if proxy_url:
                        self._proxy_rotator.report_failure(proxy_url)
                    logger.warning(
                        "429 rate limited by server, Retry-After=%.1fs", retry_after
                    )
                    if attempt <= effective_retries:
                        time.sleep(min(retry_after, self._retry_max))
                        continue

                # WAF block (403)
                if http_resp.status_code == 403:
                    if proxy_url:
                        self._proxy_rotator.report_failure(proxy_url)
                    logger.warning("403 blocked — rotating proxy & fingerprint")
                    if attempt <= effective_retries:
                        self._backoff_sleep(attempt)
                        continue

                # Server error (5xx)
                if http_resp.status_code >= 500:
                    self._circuit_breaker.record_failure(domain)
                    if proxy_url:
                        self._proxy_rotator.report_failure(proxy_url)
                    logger.warning(
                        "Server error %d from %s", http_resp.status_code, domain
                    )
                    if attempt <= effective_retries:
                        self._backoff_sleep(attempt)
                        continue

                # Other non-ok (4xx etc.) — don't retry, just return
                if proxy_url:
                    self._proxy_rotator.report_success(proxy_url)
                self._circuit_breaker.record_success(domain)
                return http_resp

            except (ConnectionError, OSError, TimeoutError) as exc:
                elapsed_ms = (time.monotonic() - start) * 1000
                last_error = exc
                self._circuit_breaker.record_failure(domain)
                if proxy_url:
                    self._proxy_rotator.report_failure(proxy_url)
                logger.warning(
                    "Connection error (attempt %d/%d): %s | proxy=%s",
                    attempt, effective_retries + 1, exc, self._mask(proxy_url),
                )
                if attempt <= effective_retries:
                    self._backoff_sleep(attempt)
                    continue

            except Exception as exc:
                elapsed_ms = (time.monotonic() - start) * 1000
                last_error = exc
                self._circuit_breaker.record_failure(domain)
                if proxy_url:
                    self._proxy_rotator.report_failure(proxy_url)
                logger.error(
                    "Unexpected error (attempt %d/%d): %s", attempt, effective_retries + 1, exc
                )
                if attempt <= effective_retries:
                    self._backoff_sleep(attempt)
                    continue

        # All retries exhausted
        raise RequestFailedError(
            f"All {effective_retries + 1} attempts failed for {url}"
        ) from last_error

    # ------------------------------------------------------------------
    # Dispatch — choose backend engine
    # ------------------------------------------------------------------

    def _dispatch(
        self,
        method: str,
        url: str,
        headers: Dict[str, str],
        params: Optional[Dict],
        data: Optional[Any],
        json_body: Optional[Any],
        proxy_url: Optional[str],
        proxy_dict: Optional[Dict[str, str]],
        profile: str,
        timeout: float,
        verify: bool,
        allow_redirects: bool,
    ) -> Any:
        """Choose the best available backend and execute the request.

        Priority:
            1. curl_cffi (TLS impersonation + best WAF evasion)
            2. httpx (HTTP/2 support)
            3. requests (universal fallback)
        """
        # ----- Strategy 1: curl_cffi -----
        if CURL_CFFI_AVAILABLE and self._prefer_curl_cffi:
            try:
                return self._send_curl_cffi(
                    method, url, headers, params, data, json_body,
                    proxy_url, profile, timeout, verify, allow_redirects,
                )
            except Exception as exc:
                logger.debug("curl_cffi failed, trying next backend: %s", exc)

        # ----- Strategy 2: httpx HTTP/2 -----
        if self._httpx_client is not None and self._prefer_http2:
            try:
                return self._send_httpx(
                    method, url, headers, params, data, json_body,
                    proxy_url, timeout, verify, allow_redirects,
                )
            except Exception as exc:
                logger.debug("httpx failed, trying requests fallback: %s", exc)

        # ----- Strategy 3: requests (always available) -----
        return self._send_requests(
            method, url, headers, params, data, json_body,
            proxy_dict, timeout, verify, allow_redirects,
        )

    # ------------------------------------------------------------------
    # Backend: curl_cffi
    # ------------------------------------------------------------------

    def _send_curl_cffi(
        self, method, url, headers, params, data, json_body,
        proxy_url, profile, timeout, verify, allow_redirects,
    ) -> Any:
        kwargs: Dict[str, Any] = {
            "method": method,
            "url": url,
            "headers": headers,
            "params": params,
            "timeout": timeout,
            "verify": verify,
            "allow_redirects": allow_redirects,
            "impersonate": profile,
        }
        if data is not None:
            kwargs["data"] = data
        if json_body is not None:
            kwargs["json"] = json_body
        if proxy_url:
            kwargs["proxies"] = {"http": proxy_url, "https": proxy_url}

        logger.debug("Sending via curl_cffi [%s] profile=%s", method, profile)
        return curl_requests.request(**kwargs)

    # ------------------------------------------------------------------
    # Backend: httpx (HTTP/2)
    # ------------------------------------------------------------------

    def _send_httpx(
        self, method, url, headers, params, data, json_body,
        proxy_url, timeout, verify, allow_redirects,
    ) -> Any:
        # httpx client doesn't support per-request proxy easily on persistent clients
        # so we build a one-shot client if proxy is needed
        kwargs: Dict[str, Any] = {
            "method": method,
            "url": url,
            "headers": headers,
            "params": params,
            "timeout": timeout,
            "follow_redirects": allow_redirects,
        }
        if data is not None:
            kwargs["content"] = data if isinstance(data, bytes) else str(data).encode()
        if json_body is not None:
            kwargs["json"] = json_body

        if proxy_url:
            # Per-request httpx client with proxy
            with httpx.Client(
                http2=True,
                verify=verify,
                proxy=proxy_url,
                timeout=timeout,
                follow_redirects=allow_redirects,
            ) as client:
                logger.debug("Sending via httpx HTTP/2 [%s] proxy=%s", method, self._mask(proxy_url))
                return client.request(**kwargs)
        else:
            logger.debug("Sending via httpx HTTP/2 [%s] (direct)", method)
            return self._httpx_client.request(**kwargs)

    # ------------------------------------------------------------------
    # Backend: requests (fallback)
    # ------------------------------------------------------------------

    def _send_requests(
        self, method, url, headers, params, data, json_body,
        proxy_dict, timeout, verify, allow_redirects,
    ) -> Any:
        logger.debug("Sending via requests [%s] (HTTP/1.1 fallback)", method)
        session = std_requests.Session()
        req = std_requests.Request(
            method=method,
            url=url,
            headers=headers,
            params=params,
            data=data,
            json=json_body,
        )
        prepared = session.prepare_request(req)
        return session.send(
            prepared,
            proxies=proxy_dict or {},
            timeout=timeout,
            verify=verify,
            allow_redirects=allow_redirects,
        )

    # ------------------------------------------------------------------
    # Response builder
    # ------------------------------------------------------------------

    def _build_response(
        self, raw: Any, elapsed_ms: float,
        proxy_url: Optional[str], tls_profile: Optional[str],
    ) -> HttpResponse:
        """Normalise responses from different backends into HttpResponse."""
        status_code: int = getattr(raw, "status_code", 0) or getattr(raw, "status", 0)
        resp_headers: Dict[str, str] = {}
        text: str = ""
        content: bytes = b""
        url: str = ""
        http_version: str = "HTTP/1.1"

        try:
            # Headers
            raw_headers = getattr(raw, "headers", {})
            if hasattr(raw_headers, "items"):
                resp_headers = {k: v for k, v in raw_headers.items()}
            else:
                resp_headers = dict(raw_headers) if raw_headers else {}

            # Text / Content
            text = getattr(raw, "text", "") or ""
            content = getattr(raw, "content", b"") or b""

            # URL
            url = str(getattr(raw, "url", ""))

            # HTTP version detection
            if hasattr(raw, "http_version"):
                hv = raw.http_version
                if hv:
                    http_version = str(hv) if isinstance(hv, str) else f"HTTP/{hv}"
            elif HTTPX_AVAILABLE and isinstance(raw, httpx.Response):
                http_version = raw.http_version or "HTTP/2"

        except Exception as exc:
            logger.warning("Error extracting response fields: %s", exc)

        return HttpResponse(
            status_code=status_code,
            headers=resp_headers,
            text=text,
            content=content,
            url=url,
            elapsed_ms=elapsed_ms,
            proxy_used=proxy_url,
            tls_profile=tls_profile,
            http_version=http_version,
        )

    # ------------------------------------------------------------------
    # Retry / backoff helpers
    # ------------------------------------------------------------------

    def _backoff_sleep(self, attempt: int) -> None:
        delay = min(self._retry_base * (2 ** (attempt - 1)), self._retry_max)
        # Add jitter (±25%)
        import random
        jitter = delay * 0.25 * (2 * random.random() - 1)
        sleep_time = max(0.1, delay + jitter)
        logger.debug("Backing off %.2fs before retry", sleep_time)
        time.sleep(sleep_time)

    @staticmethod
    def _parse_retry_after(headers: Dict[str, str]) -> float:
        """Parse Retry-After header, returning seconds to wait."""
        val = headers.get("Retry-After") or headers.get("retry-after", "")
        if not val:
            return 5.0  # default
        try:
            return float(val)
        except ValueError:
            # Could be an HTTP-date — default to 30s
            return 30.0

    @staticmethod
    def _mask(proxy_url: Optional[str]) -> str:
        if not proxy_url:
            return "DIRECT"
        parsed = urlparse(proxy_url)
        if parsed.username:
            return proxy_url.replace(
                f"{parsed.username}:{parsed.password}@", "****:****@"
            )
        return proxy_url

    # ------------------------------------------------------------------
    # Redis connection
    # ------------------------------------------------------------------

    def _connect_redis(self) -> Optional[Any]:
        if redis_lib is None:
            logger.info("redis package not installed — Redis features disabled")
            return None
        cfg = self._config.get("redis", {})
        try:
            client = redis_lib.Redis(
                host=cfg.get("host", "127.0.0.1"),
                port=cfg.get("port", 6379),
                db=cfg.get("db", 0),
                password=cfg.get("password"),
                socket_timeout=cfg.get("socket_timeout", 5),
                retry_on_timeout=cfg.get("retry_on_timeout", True),
                decode_responses=True,
            )
            client.ping()
            logger.info("Redis connection established")
            return client
        except Exception as exc:
            logger.warning("Redis connection failed: %s — running without Redis", exc)
            return None

    # ------------------------------------------------------------------
    # Graceful shutdown
    # ------------------------------------------------------------------

    def _register_signal_handlers(self) -> None:
        """Register SIGTERM/SIGINT for graceful shutdown."""
        try:
            signal.signal(signal.SIGTERM, self._handle_shutdown)
            signal.signal(signal.SIGINT, self._handle_shutdown)
        except (ValueError, OSError):
            # Can't set signal handler from non-main thread
            pass

    def _handle_shutdown(self, signum: int, frame: Any) -> None:
        logger.info("Shutdown signal received (signal=%d)", signum)
        self._shutdown_event.set()
        self.close()

    def close(self) -> None:
        """Clean up resources."""
        self._shutdown_event.set()
        if self._httpx_client is not None:
            try:
                self._httpx_client.close()
                logger.debug("httpx client closed")
            except Exception:
                pass
        if self._redis is not None:
            try:
                self._redis.close()
                logger.debug("Redis connection closed")
            except Exception:
                pass
        logger.info("HttpClient closed")

    # ------------------------------------------------------------------
    # Diagnostics
    # ------------------------------------------------------------------

    @property
    def diagnostics(self) -> Dict[str, Any]:
        """Return a diagnostic summary."""
        return {
            "data": {
                "curl_cffi_available": CURL_CFFI_AVAILABLE,
                "httpx_available": HTTPX_AVAILABLE,
                "httpx_http2_active": self._httpx_client is not None,
                "redis_connected": self._redis is not None,
                "proxy_stats": self._proxy_rotator.stats,
                "circuit_breaker_stats": self._circuit_breaker.stats,
                "shutdown_requested": self._shutdown_event.is_set(),
            }
        }


# ---------------------------------------------------------------------------
# Custom exceptions
# ---------------------------------------------------------------------------

class HttpClientError(Exception):
    """Base exception for HttpClient."""
    pass


class CircuitOpenError(HttpClientError):
    """Raised when circuit breaker is OPEN for target domain."""
    pass


class RateLimitExceededError(HttpClientError):
    """Raised when rate limit is exhausted and no retries remain."""
    pass


class RequestFailedError(HttpClientError):
    """Raised when all retry attempts are exhausted."""
    pass


# ---------------------------------------------------------------------------
# Standalone execution (module self-test)
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Centaur-Jarvis HTTP Client self-test")
    parser.add_argument("--url", default="https://httpbin.org/get", help="Test URL")
    parser.add_argument("--config", default=None, help="Config file path")
    args = parser.parse_args()

    logging.basicConfig(level=logging.DEBUG)

    print("=" * 60)
    print("Centaur-Jarvis HttpClient Self-Test")
    print("=" * 60)

    with HttpClient(config_path=args.config) as client:
        print(f"\nDiagnostics: {client.diagnostics}")
        print(f"\nSending GET to {args.url}...")

        try:
            resp = client.get(args.url)
            print(f"\n{resp}")
            print(f"Status: {resp.status_code}")
            print(f"HTTP Version: {resp.http_version}")
            print(f"TLS Profile: {resp.tls_profile}")
            print(f"Proxy: {resp.proxy_used or 'DIRECT'}")
            print(f"Elapsed: {resp.elapsed_ms:.0f}ms")
            print(f"Body preview: {resp.text[:200]}...")
        except Exception as e:
            print(f"Error: {e}")
