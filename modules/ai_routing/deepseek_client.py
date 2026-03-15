"""
DeepSeek API Client — Wrapper for DeepSeek's chat completion API.

Key features:
    - OpenAI-compatible API format
    - Good for code generation tasks
    - Rate limiting and retry with exponential backoff
"""

from __future__ import annotations

import os
import time
import logging
from typing import Optional, Dict, Any

import requests
import aiohttp
from tenacity import (
    retry,
    stop_after_attempt,
    wait_exponential,
    retry_if_exception_type,
    before_sleep_log,
)

logger = logging.getLogger("centaur_jarvis.ai_routing.deepseek_client")


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class DeepSeekError(Exception):
    """Base exception for DeepSeek API errors."""


class DeepSeekRateLimitError(DeepSeekError):
    """Rate limit (429) hit."""


class DeepSeekQuotaExceededError(DeepSeekError):
    """Quota exhausted (insufficient balance)."""


class DeepSeekServerError(DeepSeekError):
    """Server-side error (5xx)."""


class DeepSeekAuthError(DeepSeekError):
    """Invalid or missing API key."""


class DeepSeekMalformedResponseError(DeepSeekError):
    """Response JSON is malformed."""


class DeepSeekUnavailableError(DeepSeekError):
    """Client is not configured."""


# ---------------------------------------------------------------------------
# Rate Limiter (reuse pattern from gemini_client)
# ---------------------------------------------------------------------------

class TokenBucketRateLimiter:
    """Simple in-process token bucket rate limiter."""

    def __init__(self, rate_per_minute: int):
        self._rate = rate_per_minute
        self._tokens = float(rate_per_minute)
        self._max_tokens = float(rate_per_minute)
        self._last_refill = time.monotonic()

    def acquire(self, timeout: float = 60.0) -> bool:
        deadline = time.monotonic() + timeout
        while True:
            self._refill()
            if self._tokens >= 1.0:
                self._tokens -= 1.0
                return True
            if time.monotonic() >= deadline:
                return False
            wait_time = min(
                (1.0 - self._tokens) * 60.0 / self._rate,
                deadline - time.monotonic(),
            )
            if wait_time > 0:
                time.sleep(wait_time)

    def _refill(self) -> None:
        now = time.monotonic()
        elapsed = now - self._last_refill
        self._tokens = min(
            self._max_tokens,
            self._tokens + elapsed * self._rate / 60.0,
        )
        self._last_refill = now


# ---------------------------------------------------------------------------
# Client
# ---------------------------------------------------------------------------

class DeepSeekClient:
    """
    DeepSeek API client (OpenAI-compatible format).

    Usage:
        client = DeepSeekClient(config={...})
        if client.is_available():
            result = client.generate("Generate a SQL injection payload for...")
    """

    PROVIDER_NAME = "deepseek"

    def __init__(self, config: Dict[str, Any]):
        self._config = config
        self._api_key: Optional[str] = None
        self._base_url = config.get("base_url", "https://api.deepseek.com/v1")
        self._model = config.get("model", "deepseek-chat")
        self._max_context = config.get("max_context_tokens", 128_000)
        self._max_output = config.get("max_output_tokens", 4096)
        self._timeout = config.get("request_timeout_seconds", 60)
        self._rate_limiter: Optional[TokenBucketRateLimiter] = None
        self._available = False

        self._initialize()

    def _initialize(self) -> None:
        env_var = self._config.get("api_key_env", "DEEPSEEK_API_KEY")
        self._api_key = os.environ.get(env_var)

        if not self._api_key:
            logger.error(
                "DeepSeek API key not found in env var '%s' — marking unavailable.",
                env_var,
            )
            self._available = False
            return

        rate_limit = self._config.get("rate_limit_rpm", 1000)
        self._rate_limiter = TokenBucketRateLimiter(rate_limit)
        self._available = True
        logger.info(
            "DeepSeek client initialized — model=%s, rate_limit=%d RPM",
            self._model,
            rate_limit,
        )

    def is_available(self) -> bool:
        return self._available

    @property
    def max_context_tokens(self) -> int:
        return self._max_context

    @property
    def provider_name(self) -> str:
        return self.PROVIDER_NAME

    def _classify_error(self, status_code: int, body: str) -> DeepSeekError:
        body_lower = body.lower()
        if status_code == 429:
            return DeepSeekRateLimitError(f"Rate limit hit: {body[:300]}")
        if status_code == 402 or "insufficient" in body_lower:
            return DeepSeekQuotaExceededError(f"Quota/balance exceeded: {body[:300]}")
        if status_code in (401, 403):
            return DeepSeekAuthError(f"Auth failed (HTTP {status_code}): {body[:300]}")
        if 500 <= status_code < 600:
            return DeepSeekServerError(f"Server error (HTTP {status_code}): {body[:300]}")
        return DeepSeekError(f"API error (HTTP {status_code}): {body[:300]}")

    def _build_request_body(
        self, prompt: str, max_tokens: int, temperature: float
    ) -> Dict[str, Any]:
        return {
            "model": self._model,
            "messages": [
                {"role": "user", "content": prompt}
            ],
            "max_tokens": min(max_tokens, self._max_output),
            "temperature": temperature,
        }

    def _parse_response(self, data: Dict[str, Any]) -> str:
        try:
            choices = data.get("choices", [])
            if not choices:
                raise DeepSeekMalformedResponseError("No choices in response.")
            message = choices[0].get("message", {})
            content = message.get("content", "")
            if not content:
                finish_reason = choices[0].get("finish_reason", "unknown")
                logger.warning(
                    "DeepSeek returned empty content. finish_reason=%s",
                    finish_reason,
                )
            return content
        except (IndexError, KeyError, TypeError) as exc:
            raise DeepSeekMalformedResponseError(
                f"Failed to parse DeepSeek response: {exc}"
            ) from exc

    def _get_headers(self) -> Dict[str, str]:
        return {
            "Authorization": f"Bearer {self._api_key}",
            "Content-Type": "application/json",
        }

    @retry(
        retry=retry_if_exception_type((DeepSeekServerError, DeepSeekRateLimitError)),
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=1, max=30),
        before_sleep=before_sleep_log(logger, logging.WARNING),
        reraise=True,
    )
    def generate(
        self,
        prompt: str,
        max_tokens: int = 4096,
        temperature: float = 0.7,
    ) -> str:
        if not self._available:
            raise DeepSeekUnavailableError("DeepSeek client is not available.")

        if self._rate_limiter and not self._rate_limiter.acquire(timeout=30.0):
            raise DeepSeekRateLimitError("Rate limit token not acquired within 30s.")

        url = f"{self._base_url}/chat/completions"
        body = self._build_request_body(prompt, max_tokens, temperature)
        headers = self._get_headers()

        start_time = time.monotonic()

        try:
            resp = requests.post(url, json=body, headers=headers, timeout=self._timeout)
        except requests.Timeout:
            elapsed = time.monotonic() - start_time
            raise DeepSeekServerError(f"Request timed out after {elapsed:.1f}s")
        except requests.ConnectionError as exc:
            raise DeepSeekServerError(f"Connection error: {exc}") from exc

        elapsed = time.monotonic() - start_time

        if resp.status_code != 200:
            error = self._classify_error(resp.status_code, resp.text)
            if isinstance(error, (DeepSeekAuthError, DeepSeekQuotaExceededError)):
                self._available = False
                logger.error("DeepSeek marked unavailable: %s", type(error).__name__)
            raise error

        try:
            data = resp.json()
        except ValueError as exc:
            raise DeepSeekMalformedResponseError(
                f"Non-JSON response: {resp.text[:300]}"
            ) from exc

        result = self._parse_response(data)

        usage = data.get("usage", {})
        logger.info(
            "DeepSeek generation complete — model=%s, prompt_tokens=%d, "
            "completion_tokens=%d, latency=%.2fs",
            self._model,
            usage.get("prompt_tokens", 0),
            usage.get("completion_tokens", 0),
            elapsed,
        )

        return result

    async def async_generate(
        self,
        prompt: str,
        max_tokens: int = 4096,
        temperature: float = 0.7,
    ) -> str:
        if not self._available:
            raise DeepSeekUnavailableError("DeepSeek client is not available.")

        if self._rate_limiter and not self._rate_limiter.acquire(timeout=30.0):
            raise DeepSeekRateLimitError("Rate limit token not acquired within 30s.")

        url = f"{self._base_url}/chat/completions"
        body = self._build_request_body(prompt, max_tokens, temperature)
        headers = self._get_headers()

        start_time = time.monotonic()
        timeout = aiohttp.ClientTimeout(total=self._timeout)

        try:
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.post(url, json=body, headers=headers) as resp:
                    resp_text = await resp.text()
                    if resp.status != 200:
                        error = self._classify_error(resp.status, resp_text)
                        if isinstance(error, (DeepSeekAuthError, DeepSeekQuotaExceededError)):
                            self._available = False
                        raise error
                    data = await resp.json()
        except aiohttp.ClientError as exc:
            raise DeepSeekServerError(f"Async request failed: {exc}") from exc

        elapsed = time.monotonic() - start_time
        result = self._parse_response(data)

        logger.info(
            "Async DeepSeek generation complete — model=%s, latency=%.2fs",
            self._model,
            elapsed,
        )

        return result
