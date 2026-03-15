"""
AI Router — Central routing logic for all AI operations.

This is the **single entry point** other Centaur-Jarvis modules use
to request AI analysis, payload generation, or any LLM-powered task.

Routing Decision Tree:
    1. context_length > 100k tokens  →  Force Gemini (2M context)
    2. Local LLM available AND complexity == "simple"  →  Use local
    3. External APIs available  →  Use highest-priority available API
    4. No AI available  →  Raise NoAIAvailableError

All decisions are logged. Fallback cascades through the priority list.
"""

from __future__ import annotations

import os
import logging
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Optional, Dict, Any, List, Union

import yaml

from modules.ai_routing.local_llm import (
    OllamaClient,
    OllamaUnavailableError,
    OllamaGenerationError,
)
from modules.ai_routing.gemini_client import (
    GeminiClient,
    GeminiError,
    GeminiUnavailableError,
)
from modules.ai_routing.deepseek_client import (
    DeepSeekClient,
    DeepSeekError,
    DeepSeekUnavailableError,
)
from modules.ai_routing.groq_client import (
    GroqClient,
    GroqError,
    GroqUnavailableError,
)

logger = logging.getLogger("centaur_jarvis.ai_routing.router")


# ---------------------------------------------------------------------------
# Enums & Data Classes
# ---------------------------------------------------------------------------

class TaskComplexity(str, Enum):
    SIMPLE = "simple"
    MEDIUM = "medium"
    COMPLEX = "complex"


@dataclass
class TaskRequest:
    """
    Input to the router describing what the caller needs.

    Attributes:
        task_type: Descriptive label (e.g., "vuln_analysis", "payload_gen").
        prompt: The actual prompt text.
        context_length: Estimated token count of the prompt + context.
        complexity: Task complexity hint.
        max_tokens: Desired max output tokens.
        temperature: Sampling temperature.
        preferred_provider: Optional override (e.g., "gemini").
    """
    task_type: str
    prompt: str
    context_length: int = 0
    complexity: TaskComplexity = TaskComplexity.MEDIUM
    max_tokens: int = 4096
    temperature: float = 0.7
    preferred_provider: Optional[str] = None


@dataclass
class RoutingDecision:
    """
    Describes the routing outcome for telemetry and debugging.

    Attributes:
        provider: Which provider was selected ("local", "gemini", etc.).
        model: Specific model name.
        reason: Human-readable explanation.
        fallback_chain: List of providers attempted before success.
        latency_ms: Total time from request to response.
        success: Whether generation succeeded.
        error: Error message if failed.
    """
    provider: str
    model: str = ""
    reason: str = ""
    fallback_chain: List[str] = field(default_factory=list)
    latency_ms: float = 0.0
    success: bool = True
    error: str = ""


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class NoAIAvailableError(Exception):
    """
    Raised when no AI backend (local or remote) can serve the request.

    Callers MUST handle this — it means the system should fall back
    to deterministic (non-AI) mode or inform the user.
    """

    def __init__(self, message: str = "No AI backend available.", decision: Optional[RoutingDecision] = None):
        super().__init__(message)
        self.decision = decision


class ContextTooLargeError(Exception):
    """
    Raised when the context exceeds even the largest available API's limit.
    """


# ---------------------------------------------------------------------------
# Configuration Loader
# ---------------------------------------------------------------------------

def _load_config(config_override: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    Load configuration from config.yaml, optionally merged with overrides.

    Priority:
        1. config_override dict (from config/modules.yaml)
        2. modules/ai_routing/config.yaml (defaults)
    """
    default_config_path = Path(__file__).parent / "config.yaml"

    defaults: Dict[str, Any] = {}
    if default_config_path.exists():
        try:
            with open(default_config_path, "r") as f:
                defaults = yaml.safe_load(f) or {}
            logger.debug("Loaded default config from %s", default_config_path)
        except (yaml.YAMLError, IOError) as exc:
            logger.warning(
                "Failed to load default config from %s: %s — using built-in defaults.",
                default_config_path,
                exc,
            )

    if config_override:
        # Deep merge: override takes precedence
        merged = _deep_merge(defaults, config_override)
        logger.debug("Config merged with overrides.")
        return merged

    return defaults


def _deep_merge(base: Dict, override: Dict) -> Dict:
    """Recursively merge override into base."""
    result = dict(base)
    for key, value in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = value
    return result


# ---------------------------------------------------------------------------
# Router
# ---------------------------------------------------------------------------

class AIRouter:
    """
    Intelligent AI routing gateway.

    Manages local LLM (Ollama) and external API clients (Gemini, DeepSeek, Groq).
    Routes tasks based on context length, complexity, availability, and priority.

    Usage:
        router = AIRouter()        # Auto-detects everything
        result = router.generate(TaskRequest(
            task_type="vuln_analysis",
            prompt="Analyze this HTTP response for XSS...",
            context_length=2000,
            complexity=TaskComplexity.MEDIUM,
        ))
    """

    def __init__(self, config_override: Optional[Dict[str, Any]] = None):
        self._config = _load_config(config_override)

        # Sub-configs
        self._local_config = self._config.get("local_llm", {})
        self._external_config = self._config.get("external_apis", {})
        self._routing_config = self._config.get("routing", {})
        self._telemetry_config = self._config.get("telemetry", {})

        # Context thresholds
        thresholds = self._routing_config.get("context_thresholds", {})
        self._threshold_huge = thresholds.get("huge", 100_000)
        self._threshold_large = thresholds.get("large", 32_000)
        self._threshold_medium = thresholds.get("medium", 8_000)

        # Priority order
        self._priority_order: List[str] = self._external_config.get(
            "priority", ["gemini", "deepseek", "groq"]
        )

        # Retry config
        retry_config = self._routing_config.get("retry", {})
        self._max_retry_attempts = retry_config.get("max_attempts", 3)
        self._fallback_enabled = self._routing_config.get("fallback_enabled", True)

        # Initialize clients
        self._ollama: Optional[OllamaClient] = None
        self._external_clients: Dict[str, Any] = {}

        self._init_local_llm()
        self._init_external_clients()

        # Log summary
        self._log_availability_summary()

    # ------------------------------------------------------------------
    # Initialization
    # ------------------------------------------------------------------

    def _init_local_llm(self) -> None:
        """Initialize Ollama client if enabled."""
        if not self._local_config.get("enabled", True):
            logger.info("Local LLM disabled in configuration.")
            return

        try:
            self._ollama = OllamaClient(
                base_url=self._local_config.get("ollama_base_url", "http://localhost:11434"),
                preferred_model=self._local_config.get("preferred_model"),
                health_check_timeout=self._local_config.get("health_check_timeout_seconds", 5),
                request_timeout=self._local_config.get("request_timeout_seconds", 120),
                interactive_selection=self._local_config.get("interactive_model_selection", False),
            )
        except Exception as exc:
            logger.warning("Failed to initialize Ollama client: %s", exc)
            self._ollama = None

    def _init_external_clients(self) -> None:
        """Initialize all external API clients."""
        client_classes = {
            "gemini": GeminiClient,
            "deepseek": DeepSeekClient,
            "groq": GroqClient,
        }

        for provider_name in self._priority_order:
            provider_config = self._external_config.get(provider_name, {})
            client_class = client_classes.get(provider_name)

            if not client_class:
                logger.warning(
                    "Unknown provider '%s' in priority list — skipping.", provider_name
                )
                continue

            try:
                client = client_class(provider_config)
                self._external_clients[provider_name] = client
            except Exception as exc:
                logger.error(
                    "Failed to initialize %s client: %s — skipping.",
                    provider_name,
                    exc,
                )

    def _log_availability_summary(self) -> None:
        """Log a summary of all available AI backends."""
        local_status = "AVAILABLE" if self._ollama and self._ollama.is_available() else "UNAVAILABLE"
        local_model = ""
        if self._ollama and self._ollama.is_available():
            local_model = f" ({self._ollama.get_selected_model()})"

        lines = [
            "",
            "╔══════════════════════════════════════════════════════╗",
            "║          AI Router — Availability Summary            ║",
            "╠══════════════════════════════════════════════════════╣",
            f"║  Local LLM (Ollama): {local_status}{local_model}",
        ]

        for provider_name in self._priority_order:
            client = self._external_clients.get(provider_name)
            status = "AVAILABLE" if client and client.is_available() else "UNAVAILABLE"
            lines.append(f"║  {provider_name.capitalize():12s}: {status}")

        lines.append("╠══════════════════════════════════════════════════════╣")
        lines.append(f"║  Priority Order: {' → '.join(self._priority_order)}")
        lines.append(f"║  Fallback Enabled: {self._fallback_enabled}")
        lines.append("╚══════════════════════════════════════════════════════╝")

        summary = "\n".join(lines)
        logger.info(summary)

        # Critical warning if nothing is available
        if not self._has_any_ai():
            logger.warning(
                "⚠️  NO AI BACKEND IS AVAILABLE. "
                "All generate() calls will raise NoAIAvailableError. "
                "Ensure Ollama is running or set API keys in environment."
            )

    # ------------------------------------------------------------------
    # Availability Checks
    # ------------------------------------------------------------------

    def _has_any_ai(self) -> bool:
        """Check if at least one AI backend is available."""
        if self._ollama and self._ollama.is_available():
            return True
        for client in self._external_clients.values():
            if client.is_available():
                return True
        return False

    def _local_available(self) -> bool:
        return self._ollama is not None and self._ollama.is_available()

    def _get_available_external(self) -> List[str]:
        """Return list of available external providers in priority order."""
        return [
            name
            for name in self._priority_order
            if name in self._external_clients
            and self._external_clients[name].is_available()
        ]

    # ------------------------------------------------------------------
    # Routing Decision
    # ------------------------------------------------------------------

    def _decide_provider(self, request: TaskRequest) -> RoutingDecision:
        """
        Determine which provider to use based on the routing decision tree.

        Returns a RoutingDecision (which may indicate no provider if none available).
        """
        context = request.context_length

        # --- Override: caller requested specific provider ---
        if request.preferred_provider:
            prov = request.preferred_provider.lower()
            if prov == "local" and self._local_available():
                return RoutingDecision(
                    provider="local",
                    model=self._ollama.get_selected_model() or "",
                    reason=f"Caller explicitly requested local LLM.",
                )
            if prov in self._external_clients and self._external_clients[prov].is_available():
                return RoutingDecision(
                    provider=prov,
                    reason=f"Caller explicitly requested provider '{prov}'.",
                )
            logger.warning(
                "Preferred provider '%s' is not available — falling through to auto-routing.",
                prov,
            )

        # --- Rule 1: Huge context (>100k) → Force Gemini ---
        if context > self._threshold_huge:
            if "gemini" in self._external_clients and self._external_clients["gemini"].is_available():
                return RoutingDecision(
                    provider="gemini",
                    reason=f"Context length {context} > {self._threshold_huge} — "
                           f"forcing Gemini (2M context window).",
                )
            # Context is huge but Gemini not available — check if ANY api can handle it
            for name in self._priority_order:
                client = self._external_clients.get(name)
                if client and client.is_available() and context <= client.max_context_tokens:
                    return RoutingDecision(
                        provider=name,
                        reason=f"Context length {context} exceeds huge threshold but Gemini "
                               f"unavailable. {name} can handle {client.max_context_tokens} tokens.",
                    )
            # No API can handle this context
            return RoutingDecision(
                provider="none",
                reason=f"Context length {context} exceeds all available API limits.",
                success=False,
                error="ContextTooLargeError",
            )

        # --- Rule 2: Simple task + local available → Use local ---
        if (
            request.complexity == TaskComplexity.SIMPLE
            and self._local_available()
            and context <= self._threshold_medium
        ):
            return RoutingDecision(
                provider="local",
                model=self._ollama.get_selected_model() or "",
                reason=f"Simple task with small context ({context} tokens) — using local LLM.",
            )

        # --- Rule 3: Large context → External only ---
        if context > self._threshold_large:
            available = self._get_available_external()
            # Filter by context capacity
            for name in available:
                client = self._external_clients[name]
                if context <= client.max_context_tokens:
                    return RoutingDecision(
                        provider=name,
                        reason=f"Context length {context} > {self._threshold_large} — "
                               f"using external API '{name}' (capacity: {client.max_context_tokens}).",
                    )
            # Fallback to local if external can't handle
            if self._local_available():
                return RoutingDecision(
                    provider="local",
                    model=self._ollama.get_selected_model() or "",
                    reason=f"No external API can handle context length {context} — "
                           f"falling back to local (may truncate).",
                )

        # --- Rule 4: Medium context → External preferred ---
        if context > self._threshold_medium:
            available = self._get_available_external()
            if available:
                name = available[0]
                return RoutingDecision(
                    provider=name,
                    reason=f"Medium context ({context} tokens) — using external API '{name}' (preferred).",
                )
            if self._local_available():
                return RoutingDecision(
                    provider="local",
                    model=self._ollama.get_selected_model() or "",
                    reason=f"Medium context but no external APIs available — using local.",
                )

        # --- Rule 5: Small context → Any available, prefer local for simple ---
        if self._local_available():
            return RoutingDecision(
                provider="local",
                model=self._ollama.get_selected_model() or "",
                reason=f"Small context ({context} tokens) — using local LLM.",
            )

        available = self._get_available_external()
        if available:
            name = available[0]
            return RoutingDecision(
                provider=name,
                reason=f"Local LLM unavailable — using external API '{name}'.",
            )

        # --- No AI available ---
        return RoutingDecision(
            provider="none",
            reason="No AI backend available (local or external).",
            success=False,
            error="NoAIAvailableError",
        )

    # ------------------------------------------------------------------
    # Generation (Sync)
    # ------------------------------------------------------------------

    def generate(self, request: TaskRequest) -> str:
        """
        Main entry point — route task and generate response.

        Args:
            request: TaskRequest describing the task.

        Returns:
            Generated text as string.

        Raises:
            NoAIAvailableError: If no backend can serve the request.
            ContextTooLargeError: If context exceeds all API limits.
        """
        start_time = time.monotonic()
        decision = self._decide_provider(request)

        if self._telemetry_config.get("log_routing_decisions", True):
            logger.info(
                "Routing decision — task=%s, context=%d, complexity=%s, "
                "provider=%s, reason=%s",
                request.task_type,
                request.context_length,
                request.complexity.value,
                decision.provider,
                decision.reason,
            )

        # Handle no-AI and context-too-large up front
        if decision.provider == "none":
            elapsed = time.monotonic() - start_time
            decision.latency_ms = elapsed * 1000
            if decision.error == "ContextTooLargeError":
                raise ContextTooLargeError(decision.reason)
            raise NoAIAvailableError(decision.reason, decision=decision)

        # Build ordered list of providers to try (primary + fallbacks)
        providers_to_try = self._build_fallback_chain(decision.provider, request)
        decision.fallback_chain = list(providers_to_try)

        last_error: Optional[Exception] = None

        for idx, provider_name in enumerate(providers_to_try):
            if idx > 0:
                logger.warning(
                    "Falling back to provider '%s' (attempt %d/%d).",
                    provider_name,
                    idx + 1,
                    len(providers_to_try),
                )

            try:
                result = self._call_provider(provider_name, request)
                elapsed = time.monotonic() - start_time
                decision.provider = provider_name
                decision.latency_ms = elapsed * 1000
                decision.success = True

                if self._telemetry_config.get("log_api_latency", True):
                    logger.info(
                        "Generation successful — provider=%s, task=%s, latency=%.0fms",
                        provider_name,
                        request.task_type,
                        decision.latency_ms,
                    )

                return result

            except (
                OllamaUnavailableError,
                OllamaGenerationError,
                GeminiError,
                DeepSeekError,
                GroqError,
            ) as exc:
                last_error = exc
                logger.warning(
                    "Provider '%s' failed: %s: %s",
                    provider_name,
                    type(exc).__name__,
                    exc,
                )

                # If this was the last provider, break
                if idx == len(providers_to_try) - 1:
                    break

                # If fallback is disabled, break
                if not self._fallback_enabled:
                    logger.warning("Fallback disabled — not trying other providers.")
                    break

            except Exception as exc:
                # Unexpected error — log and continue to fallback
                last_error = exc
                logger.error(
                    "Unexpected error from provider '%s': %s: %s",
                    provider_name,
                    type(exc).__name__,
                    exc,
                    exc_info=True,
                )

                if idx == len(providers_to_try) - 1 or not self._fallback_enabled:
                    break

        # All providers failed
        elapsed = time.monotonic() - start_time
        decision.latency_ms = elapsed * 1000
        decision.success = False
        decision.error = str(last_error) if last_error else "Unknown error"

        logger.error(
            "All AI providers failed for task '%s'. "
            "Attempted chain: %s. Last error: %s",
            request.task_type,
            " → ".join(providers_to_try),
            decision.error,
        )

        raise NoAIAvailableError(
            f"All AI providers failed. Last error: {decision.error}",
            decision=decision,
        )

    # ------------------------------------------------------------------
    # Generation (Async)
    # ------------------------------------------------------------------

    async def async_generate(self, request: TaskRequest) -> str:
        """
        Async version of generate(). Same routing logic, async API calls.
        """
        start_time = time.monotonic()
        decision = self._decide_provider(request)

        if self._telemetry_config.get("log_routing_decisions", True):
            logger.info(
                "Async routing decision — task=%s, context=%d, complexity=%s, "
                "provider=%s, reason=%s",
                request.task_type,
                request.context_length,
                request.complexity.value,
                decision.provider,
                decision.reason,
            )

        if decision.provider == "none":
            elapsed = time.monotonic() - start_time
            decision.latency_ms = elapsed * 1000
            if decision.error == "ContextTooLargeError":
                raise ContextTooLargeError(decision.reason)
            raise NoAIAvailableError(decision.reason, decision=decision)

        providers_to_try = self._build_fallback_chain(decision.provider, request)
        last_error: Optional[Exception] = None

        for idx, provider_name in enumerate(providers_to_try):
            if idx > 0:
                logger.warning(
                    "Async fallback to provider '%s' (attempt %d/%d).",
                    provider_name,
                    idx + 1,
                    len(providers_to_try),
                )

            try:
                result = await self._async_call_provider(provider_name, request)
                elapsed = time.monotonic() - start_time
                decision.provider = provider_name
                decision.latency_ms = elapsed * 1000
                decision.success = True

                logger.info(
                    "Async generation successful — provider=%s, task=%s, latency=%.0fms",
                    provider_name,
                    request.task_type,
                    decision.latency_ms,
                )

                return result

            except Exception as exc:
                last_error = exc
                logger.warning(
                    "Async provider '%s' failed: %s: %s",
                    provider_name,
                    type(exc).__name__,
                    exc,
                )
                if idx == len(providers_to_try) - 1 or not self._fallback_enabled:
                    break

        elapsed = time.monotonic() - start_time
        decision.latency_ms = elapsed * 1000
        decision.success = False
        decision.error = str(last_error) if last_error else "Unknown error"

        raise NoAIAvailableError(
            f"All AI providers failed (async). Last error: {decision.error}",
            decision=decision,
        )

    # ------------------------------------------------------------------
    # Provider Invocation
    # ------------------------------------------------------------------

    def _call_provider(self, provider_name: str, request: TaskRequest) -> str:
        """Dispatch synchronous generation to the correct client."""
        if provider_name == "local":
            if not self._ollama or not self._ollama.is_available():
                raise OllamaUnavailableError("Ollama became unavailable.")
            return self._ollama.generate(
                prompt=request.prompt,
                max_tokens=request.max_tokens,
                temperature=request.temperature,
            )

        client = self._external_clients.get(provider_name)
        if not client or not client.is_available():
            raise NoAIAvailableError(f"Provider '{provider_name}' is not available.")

        return client.generate(
            prompt=request.prompt,
            max_tokens=request.max_tokens,
            temperature=request.temperature,
        )

    async def _async_call_provider(self, provider_name: str, request: TaskRequest) -> str:
        """Dispatch async generation to the correct client."""
        if provider_name == "local":
            if not self._ollama or not self._ollama.is_available():
                raise OllamaUnavailableError("Ollama became unavailable.")
            return await self._ollama.async_generate(
                prompt=request.prompt,
                max_tokens=request.max_tokens,
                temperature=request.temperature,
            )

        client = self._external_clients.get(provider_name)
        if not client or not client.is_available():
            raise NoAIAvailableError(f"Provider '{provider_name}' is not available.")

        return await client.async_generate(
            prompt=request.prompt,
            max_tokens=request.max_tokens,
            temperature=request.temperature,
        )

    def _build_fallback_chain(self, primary: str, request: TaskRequest) -> List[str]:
        """
        Build ordered list of providers to try.

        primary first, then remaining available providers in priority order.
        Filters out providers that can't handle the context length.
        """
        chain = [primary]

        if not self._fallback_enabled:
            return chain

        # Add remaining providers
        for name in self._priority_order:
            if name == primary:
                continue
            if name not in self._external_clients:
                continue
            client = self._external_clients[name]
            if not client.is_available():
                continue
            # Check context capacity
            if request.context_length > client.max_context_tokens:
                logger.debug(
                    "Excluding '%s' from fallback chain — context %d > max %d",
                    name,
                    request.context_length,
                    client.max_context_tokens,
                )
                continue
            chain.append(name)

        # Add local as last resort if not already primary
        if (
            primary != "local"
            and self._local_available()
            and self._local_config.get("fallback_to_external", True)
            and request.context_length <= self._threshold_medium
        ):
            chain.append("local")

        return chain

    # ------------------------------------------------------------------
    # Public Utility Methods
    # ------------------------------------------------------------------

    def get_available_providers(self) -> Dict[str, bool]:
        """Return dict of provider_name → is_available."""
        result = {
            "local": self._local_available(),
        }
        for name in self._priority_order:
            client = self._external_clients.get(name)
            result[name] = client.is_available() if client else False
        return result

    def refresh(self) -> None:
        """Re-detect all backends (e.g., after config change or network recovery)."""
        logger.info("Refreshing AI router — re-detecting all backends...")
        if self._ollama:
            self._ollama.refresh()
        # External clients: reinitialize (picks up new env vars if set)
        self._init_external_clients()
        self._log_availability_summary()


# ---------------------------------------------------------------------------
# Factory Function
# ---------------------------------------------------------------------------

_singleton_router: Optional[AIRouter] = None


def get_router(config_override: Optional[Dict[str, Any]] = None, force_new: bool = False) -> AIRouter:
    """
    Factory function returning a configured AIRouter instance (singleton by default).

    Args:
        config_override: Override configuration dict.
        force_new: If True, create a new instance even if one exists.

    Returns:
        AIRouter instance.
    """
    global _singleton_router

    if _singleton_router is None or force_new:
        _singleton_router = AIRouter(config_override=config_override)
        logger.info("AIRouter singleton created.")

    return _singleton_router
