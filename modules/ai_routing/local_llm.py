"""
Ollama Local LLM Client — Handles detection, model listing, and inference
against a local Ollama instance.

Responsibilities:
    - Health-check Ollama at startup
    - Enumerate available models via /api/tags
    - Interactive model selection (optional, CLI)
    - Synchronous and asynchronous generation
    - Graceful degradation when Ollama is unavailable
"""

from __future__ import annotations

import time
import logging
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any

import requests
import aiohttp

logger = logging.getLogger("centaur_jarvis.ai_routing.local_llm")


# ---------------------------------------------------------------------------
# Data Models
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class OllamaModel:
    """Represents a single model available in Ollama."""
    name: str
    size: int = 0                   # bytes
    digest: str = ""
    modified_at: str = ""
    parameter_size: str = ""        # e.g. "8B"
    quantization_level: str = ""    # e.g. "Q4_0"

    @classmethod
    def from_api_dict(cls, data: dict) -> "OllamaModel":
        """Parse from Ollama /api/tags response item."""
        details = data.get("details", {})
        return cls(
            name=data.get("name", "unknown"),
            size=data.get("size", 0),
            digest=data.get("digest", ""),
            modified_at=data.get("modified_at", ""),
            parameter_size=details.get("parameter_size", ""),
            quantization_level=details.get("quantization_level", ""),
        )

    def __str__(self) -> str:
        parts = [self.name]
        if self.parameter_size:
            parts.append(f"({self.parameter_size})")
        if self.quantization_level:
            parts.append(f"[{self.quantization_level}]")
        size_mb = self.size / (1024 * 1024) if self.size else 0
        if size_mb:
            parts.append(f"~{size_mb:.0f}MB")
        return " ".join(parts)


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class OllamaUnavailableError(Exception):
    """Ollama server is not reachable or not running."""


class OllamaGenerationError(Exception):
    """Error during generation from Ollama."""


# ---------------------------------------------------------------------------
# Client
# ---------------------------------------------------------------------------

class OllamaClient:
    """
    Client for local Ollama LLM inference.

    Usage:
        client = OllamaClient(base_url="http://localhost:11434")
        if client.is_available():
            models = client.list_models()
            response = client.generate("Explain SQL injection", model="llama3:8b")
    """

    def __init__(
        self,
        base_url: str = "http://localhost:11434",
        preferred_model: Optional[str] = None,
        health_check_timeout: float = 5.0,
        request_timeout: float = 120.0,
        interactive_selection: bool = False,
    ):
        self._base_url = base_url.rstrip("/")
        self._preferred_model = preferred_model
        self._health_check_timeout = health_check_timeout
        self._request_timeout = request_timeout
        self._interactive_selection = interactive_selection

        self._available: bool = False
        self._models: List[OllamaModel] = []
        self._selected_model: Optional[str] = None

        # Perform initial detection
        self._detect()

    # ------------------------------------------------------------------
    # Detection & Health
    # ------------------------------------------------------------------

    def _detect(self) -> None:
        """Check Ollama availability and enumerate models."""
        logger.info("Detecting local Ollama instance at %s ...", self._base_url)

        # Step 1: Health check
        try:
            resp = requests.get(
                f"{self._base_url}/",
                timeout=self._health_check_timeout,
            )
            if resp.status_code != 200:
                logger.warning(
                    "Ollama health-check returned HTTP %d — marking unavailable.",
                    resp.status_code,
                )
                self._available = False
                return
        except requests.ConnectionError:
            logger.warning(
                "Ollama not reachable at %s — marking local LLM unavailable.",
                self._base_url,
            )
            self._available = False
            return
        except requests.Timeout:
            logger.warning(
                "Ollama health-check timed out (%ss) — marking unavailable.",
                self._health_check_timeout,
            )
            self._available = False
            return
        except Exception as exc:
            logger.warning(
                "Unexpected error during Ollama health-check: %s — marking unavailable.",
                exc,
            )
            self._available = False
            return

        # Step 2: Enumerate models
        try:
            resp = requests.get(
                f"{self._base_url}/api/tags",
                timeout=self._health_check_timeout,
            )
            resp.raise_for_status()
            data = resp.json()
        except requests.RequestException as exc:
            logger.warning(
                "Failed to fetch Ollama model list: %s — marking unavailable.", exc
            )
            self._available = False
            return
        except (ValueError, KeyError) as exc:
            logger.warning(
                "Malformed JSON from Ollama /api/tags: %s — marking unavailable.", exc
            )
            self._available = False
            return

        raw_models = data.get("models", [])
        if not raw_models:
            logger.warning("Ollama is running but no models are installed.")
            self._available = False
            return

        self._models = [OllamaModel.from_api_dict(m) for m in raw_models]
        self._available = True

        logger.info(
            "Ollama detected with %d model(s): %s",
            len(self._models),
            ", ".join(m.name for m in self._models),
        )

        # Step 3: Select model
        self._select_model()

    def _select_model(self) -> None:
        """
        Choose which model to use.

        Priority:
            1. If only one model → use it.
            2. If preferred_model in config matches an available model → use it.
            3. If interactive_selection enabled → prompt user via CLI.
            4. Fallback: use first available model.
        """
        model_names = [m.name for m in self._models]

        # Single model — easy choice
        if len(self._models) == 1:
            self._selected_model = self._models[0].name
            logger.info("Single model available — selected: %s", self._selected_model)
            return

        # Preferred model matches
        if self._preferred_model and self._preferred_model in model_names:
            self._selected_model = self._preferred_model
            logger.info(
                "Preferred model '%s' found — selected.", self._selected_model
            )
            return

        # Interactive selection
        if self._interactive_selection:
            self._selected_model = self._interactive_model_prompt()
            if self._selected_model:
                logger.info("User selected model: %s", self._selected_model)
                return

        # Fallback: first model
        # If preferred model was set but not found, warn
        if self._preferred_model and self._preferred_model not in model_names:
            logger.warning(
                "Preferred model '%s' not found among available models %s. "
                "Falling back to first available.",
                self._preferred_model,
                model_names,
            )

        self._selected_model = self._models[0].name
        logger.info("Fallback — selected first available model: %s", self._selected_model)

    def _interactive_model_prompt(self) -> Optional[str]:
        """
        Prompt user via CLI to select a model.

        Handles:
            - Invalid input (non-numeric, out of range)
            - KeyboardInterrupt (user cancels → return None)
            - EOFError (non-interactive terminal → return None)
        """
        print("\n╔══════════════════════════════════════════╗")
        print("║   Multiple Local LLM Models Detected     ║")
        print("╚══════════════════════════════════════════╝")
        for idx, model in enumerate(self._models, 1):
            print(f"  [{idx}] {model}")
        print()

        try:
            raw = input(f"Select model [1-{len(self._models)}] (or press Enter for default): ").strip()
        except (KeyboardInterrupt, EOFError):
            logger.info("User interrupted model selection — using default.")
            return None

        if not raw:
            return None

        try:
            choice = int(raw)
        except ValueError:
            logger.warning("Invalid input '%s' — using default model.", raw)
            return None

        if 1 <= choice <= len(self._models):
            return self._models[choice - 1].name

        logger.warning("Choice %d out of range — using default model.", choice)
        return None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def is_available(self) -> bool:
        """Return True if Ollama is running and at least one model is available."""
        return self._available and self._selected_model is not None

    def get_selected_model(self) -> Optional[str]:
        """Return the currently selected model name."""
        return self._selected_model

    def list_models(self) -> List[OllamaModel]:
        """Return list of available Ollama models."""
        return list(self._models)

    def refresh(self) -> None:
        """Re-detect Ollama (useful after model pull/remove)."""
        self._detect()

    def generate(
        self,
        prompt: str,
        *,
        model: Optional[str] = None,
        max_tokens: int = 4096,
        temperature: float = 0.7,
        system_prompt: Optional[str] = None,
    ) -> str:
        """
        Synchronous generation via Ollama /api/generate.

        Args:
            prompt: The user prompt.
            model: Override model (default: selected model).
            max_tokens: Maximum tokens to generate.
            temperature: Sampling temperature.
            system_prompt: Optional system instruction.

        Returns:
            Generated text as string.

        Raises:
            OllamaUnavailableError: If Ollama is not available.
            OllamaGenerationError: If generation fails.
        """
        if not self.is_available():
            raise OllamaUnavailableError("Ollama is not available for generation.")

        use_model = model or self._selected_model

        payload: Dict[str, Any] = {
            "model": use_model,
            "prompt": prompt,
            "stream": False,
            "options": {
                "num_predict": max_tokens,
                "temperature": temperature,
            },
        }

        if system_prompt:
            payload["system"] = system_prompt

        start_time = time.monotonic()
        try:
            resp = requests.post(
                f"{self._base_url}/api/generate",
                json=payload,
                timeout=self._request_timeout,
            )
            resp.raise_for_status()
        except requests.Timeout:
            elapsed = time.monotonic() - start_time
            logger.error(
                "Ollama generation timed out after %.1fs for model '%s'.",
                elapsed,
                use_model,
            )
            raise OllamaGenerationError(
                f"Ollama generation timed out after {elapsed:.1f}s"
            )
        except requests.RequestException as exc:
            logger.error("Ollama generation request failed: %s", exc)
            raise OllamaGenerationError(f"Ollama request failed: {exc}") from exc

        elapsed = time.monotonic() - start_time

        try:
            data = resp.json()
        except ValueError as exc:
            logger.error("Ollama returned malformed JSON: %s", exc)
            raise OllamaGenerationError("Malformed JSON from Ollama") from exc

        response_text = data.get("response", "")
        if not response_text:
            logger.warning("Ollama returned empty response for model '%s'.", use_model)

        # Telemetry
        eval_count = data.get("eval_count", 0)
        logger.info(
            "Ollama generation complete — model=%s, tokens=%d, latency=%.2fs",
            use_model,
            eval_count,
            elapsed,
        )

        return response_text

    async def async_generate(
        self,
        prompt: str,
        *,
        model: Optional[str] = None,
        max_tokens: int = 4096,
        temperature: float = 0.7,
        system_prompt: Optional[str] = None,
    ) -> str:
        """
        Asynchronous generation via Ollama /api/generate.

        Same signature as generate() but uses aiohttp for non-blocking I/O.
        """
        if not self.is_available():
            raise OllamaUnavailableError("Ollama is not available for generation.")

        use_model = model or self._selected_model

        payload: Dict[str, Any] = {
            "model": use_model,
            "prompt": prompt,
            "stream": False,
            "options": {
                "num_predict": max_tokens,
                "temperature": temperature,
            },
        }
        if system_prompt:
            payload["system"] = system_prompt

        start_time = time.monotonic()
        timeout = aiohttp.ClientTimeout(total=self._request_timeout)

        try:
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.post(
                    f"{self._base_url}/api/generate",
                    json=payload,
                ) as resp:
                    if resp.status != 200:
                        body = await resp.text()
                        raise OllamaGenerationError(
                            f"Ollama returned HTTP {resp.status}: {body[:500]}"
                        )
                    data = await resp.json()
        except aiohttp.ClientError as exc:
            logger.error("Async Ollama generation failed: %s", exc)
            raise OllamaGenerationError(
                f"Async Ollama request failed: {exc}"
            ) from exc

        elapsed = time.monotonic() - start_time
        response_text = data.get("response", "")
        eval_count = data.get("eval_count", 0)

        logger.info(
            "Async Ollama generation complete — model=%s, tokens=%d, latency=%.2fs",
            use_model,
            eval_count,
            elapsed,
        )

        return response_text
