"""
Gemini API Client — Wrapper for Google's Gemini 1.5 Pro API.

Key features:
    - 2M token context window (largest available)
    - Rate limiting (60 RPM free tier)
    - Retry with exponential backoff
    - Error classification
"""

from __future__ import annotations

import os
import time
import logging
from dataclasses import dataclass
from typing import Optional, Dict, Any

import requests
import aiohttp
from tenacity import (
    retry,
    stop_after_attempt,
    wait_exponential,
    retry_if_exception_type,
    before_sleep_log,
    RetryError,
)

logger = logging.getLogger("centaur_jarvis.ai_routing.gemini_client")


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class GeminiError(Exception):
    """Base exception for Gemini API errors."""


class GeminiRateLimitError(GeminiError):
    """Rate limit (429) hit."""


class GeminiQuotaExceededError(GeminiError):
    """Daily/monthly quota exhausted."""


class GeminiServerError(GeminiError):
    """Server-side error (5xx)."""


class GeminiAuthError(GeminiError):
    """Invalid or missing API key."""


class GeminiMalformedResponseError(GeminiError):
    """Response JSON is malformed or missing expected fields."""


class GeminiUnavailableError(GeminiError):
    """Client is not configured (missing API key, etc.)."""


# ---------------------------------------------------------------------------
# Rate Limiter (in-process token bucket)
# ---------------------------------------------------------------------------

class TokenBucketRateLimiter:
    """
    Simple in-process token bucket rate limiter.

    Thread-safe enough for single-process use. For multi-process,
    use Redis-based rate limiter from core.rate_limiter.
    """

    def __init__(self, rate_per_minute: int):
        self._rate = rate_per_minute
        self._tokens = float(rate_per_minute)
        self._max_tokens = float(rate_per_minute)
        self._last_refill = time.monotonic()

    def acquire(self, timeout: float = 60.0) -> bool:
        """
        Attempt to acquire a token. Blocks up to timeout seconds.
        Returns True if acquired, False if timed out.
        """
        deadline = time.monotonic() + timeout
        while True:
            self._refill()
            if self._tokens >= 1.0:
                self._tokens -= 1.0
                return True
            if time.monotonic() >= deadline:
                return False
            # Sleep until next token is available
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

    @property
    def available_tokens(self) -> float:
        self._refill()
        return self._tokens


# ---------------------------------------------------------------------------
# Client
# ---------------------------------------------------------------------------

class GeminiClient:
    """
    Google Gemini API client with rate limiting and retry logic.

    Usage:
        client = GeminiClient(config={...})
        if client.is_available():
            result = client.generate("Analyze this vulnerability...")
    """

    PROVIDER_NAME = "gemini"

    def __init__(self, config: Dict[str, Any]):
        self._config = config
        self._api_key: Optional[str] = None
        self._base_url = config.get("base_url", "https://generativelanguage.googleapis.com/v1beta")
        self._model = config.get("model", "gemini-1.5-pro-latest")
        self._max_context = config.get("max_context_tokens", 2_000_000)
        self._max_output = config.get("max_output_tokens", 8192)
        self._timeout = config.get("request_timeout_seconds", 60)
        self._rate_limiter: Optional[TokenBucketRateLimiter] = None
        self._available = False

        self._initialize()

    def _initialize(self) -> None:
        """Load API key and set up rate limiter."""
        env_var = self._config.get("api_key_env", "GEMINI_API_KEY")
        self._api_key = os.environ.get(env_var)

        if not self._api_key:
            logger.error(
                "Gemini API key not found in environment variable '%s' — "
                "marking Gemini unavailable.",
                env_var,
            )
            self._available = False
            return

        rate_limit = self._config.get("rate_limit_rpm", 60)
        self._rate_limiter = TokenBucketRateLimiter(rate_limit)
        self._available = True
        logger.info(
            "Gemini client initialized — model=%s, rate_limit=%d RPM, max_context=%d",
            self._model,
            rate_limit,
            self._max_context,
        )

    def is_available(self) -> bool:
        return self._available

    @property
    def max_context_tokens(self) -> int:
        return self._max_context

    @property
    def provider_name(self) -> str:
        return self.PROVIDER_NAME

    def _classify_error(self, status_code: int, body: str) -> GeminiError:
        """Classify HTTP error into specific exception type."""
        if status_code == 429:
            if "quota" in body.lower():
                return GeminiQuotaExceededError(f"Quota exceeded: {body[:300]}")
            return GeminiRateLimitError(f"Rate limit hit: {body[:300]}")
        if status_code == 401 or status_code == 403:
            return GeminiAuthError(f"Authentication failed (HTTP {status_code}): {body[:300]}")
        if 500 <= status_code < 600:
            return GeminiServerError(f"Server error (HTTP {status_code}): {body[:300]}")
        return GeminiError(f"API error (HTTP {status_code}): {body[:300]}")

    def _build_request_body(
        self, prompt: str, max_tokens: int, temperature: float
    ) -> Dict[str, Any]:
        return {
            "contents": [
                {
                    "parts": [{"text": prompt}]
                }
            ],
            "generationConfig": {
                "maxOutputTokens": min(max_tokens, self._max_output),
                "temperature": temperature,
            },
        }

    def _parse_response(self, data: Dict[str, Any]) -> str:
        """Extract text from Gemini response, handling malformed structures."""
        try:
            candidates = data.get("candidates", [])
            if not candidates:
                # Check for prompt-level errors
                prompt_feedback = data.get("promptFeedback", {})
                block_reason = prompt_feedback.get("blockReason", "")
                if block_reason:
                    raise GeminiMalformedResponseError(
                        f"Prompt blocked by Gemini: {block_reason}"
                    )
                raise GeminiMalformedResponseError("No candidates in Gemini response.")

            first_candidate = candidates[0]
            content = first_candidate.get("content", {})
            parts = content.get("parts", [])
            if not parts:
                finish_reason = first_candidate.get("finishReason", "unknown")
                raise GeminiMalformedResponseError(
                    f"No parts in candidate. finishReason={finish_reason}"
                )
            return parts[0].get("text", "")
        except (IndexError, KeyError, TypeError) as exc:
            raise GeminiMalformedResponseError(
                f"Failed to parse Gemini response structure: {exc}"
            ) from exc

    @retry(
        retry=retry_if_exception_type((GeminiServerError, GeminiRateLimitError)),
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
        """
        Synchronous text generation via Gemini API.

        Retries on 5xx and 429 with exponential backoff (max 3 attempts).
        """
        if not self._available:
            raise GeminiUnavailableError("Gemini client is not available.")

        # Rate limit check
        if self._rate_limiter and not self._rate_limiter.acquire(timeout=30.0):
            raise GeminiRateLimitError(
                "Could not acquire rate limit token within 30s."
            )

        url = (
            f"{self._base_url}/models/{self._model}:generateContent"
            f"?key={self._api_key}"
        )
        body = self._build_request_body(prompt, max_tokens, temperature)

        start_time = time.monotonic()

        try:
            resp = requests.post(url, json=body, timeout=self._timeout)
        except requests.Timeout:
            elapsed = time.monotonic() - start_time
            raise GeminiServerError(
                f"Gemini request timed out after {elapsed:.1f}s"
            )
        except requests.ConnectionError as exc:
            raise GeminiServerError(f"Connection error: {exc}") from exc

        elapsed = time.monotonic() - start_time

        if resp.status_code != 200:
            error = self._classify_error(resp.status_code, resp.text)
            logger.warning(
                "Gemini API error — status=%d, latency=%.2fs, error=%s",
                resp.status_code,
                elapsed,
                type(error).__name__,
            )
            # Mark unavailable on auth errors or quota exceeded
            if isinstance(error, (GeminiAuthError, GeminiQuotaExceededError)):
                self._available = False
                logger.error(
                    "Gemini marked unavailable due to: %s", type(error).__name__
                )
            raise error

        try:
            data = resp.json()
        except ValueError as exc:
            raise GeminiMalformedResponseError(
                f"Gemini returned non-JSON response: {resp.text[:300]}"
            ) from exc

        result = self._parse_response(data)

        # Telemetry
        usage = data.get("usageMetadata", {})
        prompt_tokens = usage.get("promptTokenCount", 0)
        completion_tokens = usage.get("candidatesTokenCount", 0)

        logger.info(
            "Gemini generation complete — model=%s, prompt_tokens=%d, "
            "completion_tokens=%d, latency=%.2fs",
            self._model,
            prompt_tokens,
            completion_tokens,
            elapsed,
        )

        return result

    async def async_generate(
        self,
        prompt: str,
        max_tokens: int = 4096,
        temperature: float = 0.7,
    ) -> str:
        """
        Asynchronous text generation via Gemini API.

        Note: Retry logic for async is handled at the router level.
        This method performs a single attempt.
        """
        if not self._available:
            raise GeminiUnavailableError("Gemini client is not available.")

        if self._rate_limiter and not self._rate_limiter.acquire(timeout=30.0):
            raise GeminiRateLimitError(
                "Could not acquire rate limit token within 30s."
            )

        url = (
            f"{self._base_url}/models/{self._model}:generateContent"
            f"?key={self._api_key}"
        )
        body = self._build_request_body(prompt, max_tokens, temperature)

        start_time = time.monotonic()
        timeout = aiohttp.ClientTimeout(total=self._timeout)

        try:
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.post(url, json=body) as resp:
                    resp_text = await resp.text()
                    if resp.status != 200:
                        error = self._classify_error(resp.status, resp_text)
                        if isinstance(error, (GeminiAuthError, GeminiQuotaExceededError)):
                            self._available = False
                        raise error
                    data = await resp.json()
        except aiohttp.ClientError as exc:
            raise GeminiServerError(f"Async request failed: {exc}") from exc

        elapsed = time.monotonic() - start_time
        result = self._parse_response(data)

        logger.info(
            "Async Gemini generation complete — model=%s, latency=%.2fs",
            self._model,
            elapsed,
        )

        return result
