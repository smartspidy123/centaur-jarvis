"""
modules/ai_routing/router.py

AI Router with RAG-Enhanced Context Injection.
Queries the SecurityKnowledgeBase (Zilliz Cloud) before every AI call,
injecting relevant security knowledge into prompts for dramatically
improved payload generation, analysis, and template quality.

Architecture:
  ┌─────────┐    ┌─────────┐    ┌──────────────┐    ┌────────────┐
  │ Caller  │───▶│ Router  │───▶│ RAG Search   │───▶│ AI Provider│
  │         │    │         │    │ (Zilliz)     │    │ (OpenAI/   │
  │         │    │         │    │              │    │  Claude/   │
  │         │◀───│         │◀───│              │◀───│  Ollama)   │
  └─────────┘    └─────────┘    └──────────────┘    └────────────┘

CRITICAL ARCHITECTURE RULE:
  - 360° edge-case handling on every code path
  - No silent failures; every anomaly is logged
  - Plug-and-play: RAG can be disabled without code changes
  - Comprehensive telemetry for observability
"""

from __future__ import annotations
from modules.rag.knowledge_base import SecurityKnowledgeBase
import asyncio
import enum
import hashlib
import logging
import threading
import time
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeoutError
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

import yaml

# ─────────────────────────────────────────────────────────────
# Logger Setup
# ─────────────────────────────────────────────────────────────
try:
    from shared.logger import get_logger
    logger = get_logger(__name__)
except ImportError:
    logger = logging.getLogger(__name__)
    if not logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(
            logging.Formatter(
                "%(asctime)s | %(name)s | %(levelname)s | %(message)s"
            )
        )
        logger.addHandler(handler)
        logger.setLevel(logging.DEBUG)
    logger.warning(
        "shared.logger unavailable; falling back to stdlib logging"
    )

# ─────────────────────────────────────────────────────────────
# RAG Import (Graceful Degradation)
# ─────────────────────────────────────────────────────────────
_RAG_AVAILABLE = False
SecurityKnowledgeBase = None  # type: ignore[assignment]

try:
    from modules.rag.knowledge_base import SecurityKnowledgeBase as _SKB
    SecurityKnowledgeBase = _SKB
    _RAG_AVAILABLE = True
    logger.info("RAG module imported successfully (modules.rag.knowledge_base)")
except ImportError as exc:
    logger.warning(
        "RAG module not importable (%s); RAG context injection DISABLED. "
        "Install modules.rag or check PYTHONPATH.",
        exc,
    )
except Exception as exc:  # pragma: no cover – unexpected import errors
    logger.error(
        "Unexpected error importing RAG module: %s. RAG DISABLED.", exc
    )

# ─────────────────────────────────────────────────────────────
# AI Provider Imports (Existing)
# ─────────────────────────────────────────────────────────────
try:
    import openai as _openai_lib
    _OPENAI_AVAILABLE = True
except ImportError:
    _OPENAI_AVAILABLE = False
    logger.debug("openai library not installed; OpenAI provider unavailable")

try:
    import anthropic as _anthropic_lib
    _ANTHROPIC_AVAILABLE = True
except ImportError:
    _ANTHROPIC_AVAILABLE = False
    logger.debug("anthropic library not installed; Anthropic provider unavailable")

try:
    import httpx as _httpx_lib
    _HTTPX_AVAILABLE = True
except ImportError:
    _HTTPX_AVAILABLE = False
    logger.debug("httpx library not installed; Ollama provider unavailable")

import os


# ═════════════════════════════════════════════════════════════
# Data Classes & Enums
# ═════════════════════════════════════════════════════════════

class TaskComplexity(enum.Enum):
    """Complexity levels for routing decisions."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class TaskRequest:
    """
    Encapsulates an AI generation request.

    Attributes:
        prompt: The user/system prompt to send.
        complexity: Task complexity for provider routing.
        task_type: Semantic label (e.g., "payload_generation", "analysis").
        metadata: Arbitrary key-value pairs forwarded to the provider.
        skip_rag: If True, bypass RAG even if globally enabled.
    """
    prompt: str
    complexity: TaskComplexity = TaskComplexity.MEDIUM
    task_type: str = "general"
    metadata: Dict[str, Any] = field(default_factory=dict)
    skip_rag: bool = False


@dataclass
class RAGContext:
    """
    Container for RAG search results injected into a prompt.

    Attributes:
        snippets: List of (text, score) tuples that passed filtering.
        total_chars: Total character count of combined snippets.
        search_time_ms: Time taken for the RAG search in milliseconds.
        truncated: Whether the context was truncated to fit max_context_length.
        query_hash: SHA-256 hash of the original query (for cache keying).
    """
    snippets: List[Tuple[str, float]] = field(default_factory=list)
    total_chars: int = 0
    search_time_ms: float = 0.0
    truncated: bool = False
    query_hash: str = ""

    @property
    def has_context(self) -> bool:
        return len(self.snippets) > 0


@dataclass
class GenerationResult:
    """
    Wraps the AI generation output with telemetry.

    The mandatory `data` field contains findings and stats (per architecture rule).
    """
    data: Dict[str, Any]
    provider_used: str = "none"
    model_used: str = "none"
    rag_context: Optional[RAGContext] = None
    generation_time_ms: float = 0.0
    success: bool = True
    error: Optional[str] = None


# ═════════════════════════════════════════════════════════════
# RAG Configuration Dataclass
# ═════════════════════════════════════════════════════════════

@dataclass
class RAGConfig:
    """Typed RAG configuration loaded from config.yaml."""
    enabled: bool = True
    knowledge_base_path: Optional[str] = None
    search_limit: int = 5
    min_score: float = 0.5
    max_context_length: int = 2000
    inject_mode: str = "prepend"  # "prepend" or "append"
    search_timeout: float = 5.0
    cache_enabled: bool = False
    cache_ttl: int = 300

    def __post_init__(self) -> None:
        # Validate inject_mode
        valid_modes = {"prepend", "append"}
        if self.inject_mode not in valid_modes:
            logger.warning(
                "Invalid inject_mode '%s'; defaulting to 'prepend'. "
                "Valid modes: %s",
                self.inject_mode,
                valid_modes,
            )
            self.inject_mode = "prepend"

        # Clamp numeric ranges
        if self.search_limit < 1:
            logger.warning("search_limit < 1; clamping to 1")
            self.search_limit = 1
        if self.search_limit > 20:
            logger.warning("search_limit > 20; clamping to 20")
            self.search_limit = 20

        if not (0.0 <= self.min_score <= 1.0):
            logger.warning("min_score %.2f out of [0,1]; clamping", self.min_score)
            self.min_score = max(0.0, min(1.0, self.min_score))

        if self.max_context_length < 100:
            logger.warning("max_context_length < 100; clamping to 100")
            self.max_context_length = 100

        if self.search_timeout < 0.5:
            logger.warning("search_timeout < 0.5s; clamping to 0.5")
            self.search_timeout = 0.5


# ═════════════════════════════════════════════════════════════
# AI Router
# ═════════════════════════════════════════════════════════════

class AIRouter:
    """
    Central AI Router with RAG-enhanced context injection.

    Flow:
      1. Receive TaskRequest
      2. Query RAG knowledge base for relevant context (if enabled)
      3. Inject context into prompt
      4. Select AI provider based on complexity routing
      5. Call provider with enhanced prompt
      6. Return GenerationResult with full telemetry

    Thread Safety:
      - RAG client (SecurityKnowledgeBase) is thread-safe
      - Config is read-only after __init__
      - Each generate() call is stateless
    """

    _CONFIG_FILE = Path(__file__).parent / "config.yaml"

    def __init__(
        self,
        config_path: Optional[Union[str, Path]] = None,
        rag_override: Optional[Any] = None,
    ) -> None:
        """
        Initialize the AI Router.

        Args:
            config_path: Optional path to config.yaml. Defaults to module directory.
            rag_override: Optional pre-initialized SecurityKnowledgeBase instance
                          (useful for testing / dependency injection).
        """
        # ── Load Configuration ──
        self._config_path = Path(config_path) if config_path else self._CONFIG_FILE
        self._raw_config = self._load_config(self._config_path)

        # ── Parse RAG Config ──
        self._rag_config = self._parse_rag_config(self._raw_config)

        # ── Initialize RAG Client ──
        self._rag: Optional[Any] = None
        self._rag_operational = False
        self._init_rag(rag_override)

        # ── Parse Provider Config ──
        self._providers_config = self._raw_config.get("providers", {})
        self._routing_config = self._raw_config.get("routing", {})
        self._retry_config = self._raw_config.get("retry", {})
        self._telemetry_config = self._raw_config.get("telemetry", {})

        # ── Thread Pool for Timeout-Bounded RAG Calls ──
        self._rag_executor = ThreadPoolExecutor(
            max_workers=4, thread_name_prefix="rag-search"
        )

        logger.info(
            "AIRouter initialized | RAG enabled=%s, operational=%s | "
            "Primary provider=%s",
            self._rag_config.enabled,
            self._rag_operational,
            self._providers_config.get("primary", "none"),
        )

    # ─────────────────────────────────────────────
    # Configuration Loading
    # ─────────────────────────────────────────────

    def _load_config(self, path: Path) -> Dict[str, Any]:
        """Load and parse config.yaml with graceful fallback."""
        if not path.exists():
            logger.warning(
                "Config file not found at %s; using empty defaults", path
            )
            return {}

        try:
            with path.open("r", encoding="utf-8") as fh:
                config = yaml.safe_load(fh)
                if not isinstance(config, dict):
                    logger.error(
                        "Config file %s did not parse to a dict; using defaults",
                        path,
                    )
                    return {}
                logger.debug("Configuration loaded from %s", path)
                return config
        except yaml.YAMLError as exc:
            logger.error("YAML parse error in %s: %s; using defaults", path, exc)
            return {}
        except OSError as exc:
            logger.error("Cannot read config %s: %s; using defaults", path, exc)
            return {}

    def _parse_rag_config(self, raw: Dict[str, Any]) -> RAGConfig:
        """Extract and validate the RAG section from raw config."""
        rag_section = raw.get("rag", {})
        if not isinstance(rag_section, dict):
            logger.warning("rag config section is not a dict; using defaults")
            return RAGConfig(enabled=False)

        try:
            return RAGConfig(**{
                k: v for k, v in rag_section.items()
                if k in RAGConfig.__dataclass_fields__
            })
        except TypeError as exc:
            logger.error("Invalid RAG config values: %s; disabling RAG", exc)
            return RAGConfig(enabled=False)

    # ─────────────────────────────────────────────
    # RAG Initialization
    # ─────────────────────────────────────────────

    def _init_rag(self, rag_override: Optional[Any] = None) -> None:
        """
        Initialize the RAG knowledge base client.

        Graceful degradation: if anything fails, RAG is disabled
        and the router continues without context injection.
        """
        # ── Check if RAG is configured off ──
        if not self._rag_config.enabled:
            logger.info("RAG integration disabled by configuration")
            self._rag = None
            self._rag_operational = False
            return

        # ── Check if RAG module is available ──
        if not _RAG_AVAILABLE and rag_override is None:
            logger.warning(
                "RAG enabled in config but modules.rag is not importable; "
                "RAG context injection will be SKIPPED"
            )
            self._rag = None
            self._rag_operational = False
            return

        # ── Use override if provided (DI / testing) ──
        if rag_override is not None:
            self._rag = rag_override
            self._rag_operational = True
            logger.info("RAG initialized via override/injection")
            return

        # ── Initialize SecurityKnowledgeBase ──
        try:
            init_kwargs: Dict[str, Any] = {}
            if self._rag_config.knowledge_base_path:
                init_kwargs["config_path"] = self._rag_config.knowledge_base_path

            self._rag = SecurityKnowledgeBase(**init_kwargs)  # type: ignore[misc]
            self._rag_operational = True
            logger.info(
                "SecurityKnowledgeBase initialized successfully "
                "(search_limit=%d, min_score=%.2f)",
                self._rag_config.search_limit,
                self._rag_config.min_score,
            )
        except Exception as exc:
            logger.error(
                "Failed to initialize SecurityKnowledgeBase: %s. "
                "RAG context injection DISABLED. The router will continue "
                "without knowledge base augmentation.",
                exc,
            )
            self._rag = None
            self._rag_operational = False

    # ─────────────────────────────────────────────
    # RAG Search & Context Building
    # ─────────────────────────────────────────────

    def _search_rag(self, query: str) -> RAGContext:
        """
        Search the RAG knowledge base with timeout protection.

        Returns a RAGContext (always; never raises).
        """
        ctx = RAGContext(query_hash=hashlib.sha256(query.encode()).hexdigest()[:16])

        if not self._rag_operational or self._rag is None:
            logger.debug("RAG not operational; skipping search")
            return ctx

        start_time = time.monotonic()

        try:
            # Execute search with timeout using thread pool
            future = self._rag_executor.submit(
                self._rag.search,
                query,
                limit=self._rag_config.search_limit,
            )
            raw_results = future.result(timeout=self._rag_config.search_timeout)

            elapsed_ms = (time.monotonic() - start_time) * 1000
            ctx.search_time_ms = elapsed_ms

            if not raw_results:
                logger.debug(
                    "RAG search returned no results (%.1fms)", elapsed_ms
                )
                return ctx

            # ── Filter by min_score ──
            filtered = self._filter_results(raw_results)

            if not filtered:
                logger.debug(
                    "All %d RAG results below min_score %.2f (%.1fms)",
                    len(raw_results),
                    self._rag_config.min_score,
                    elapsed_ms,
                )
                return ctx

            # ── Combine and truncate ──
            ctx = self._build_context(filtered, ctx)

            logger.info(
                "RAG context ready: %d snippets, %d chars, %.1fms, truncated=%s",
                len(ctx.snippets),
                ctx.total_chars,
                ctx.search_time_ms,
                ctx.truncated,
            )
            return ctx

        except FuturesTimeoutError:
            elapsed_ms = (time.monotonic() - start_time) * 1000
            ctx.search_time_ms = elapsed_ms
            logger.warning(
                "RAG search TIMED OUT after %.1fms (limit=%.1fs); "
                "proceeding without context",
                elapsed_ms,
                self._rag_config.search_timeout,
            )
            return ctx

        except Exception as exc:
            elapsed_ms = (time.monotonic() - start_time) * 1000
            ctx.search_time_ms = elapsed_ms
            logger.warning(
                "RAG search FAILED after %.1fms: %s; proceeding without context",
                elapsed_ms,
                exc,
            )
            return ctx

    def _filter_results(
        self, raw_results: List[Any]
    ) -> List[Tuple[str, float]]:
        """
        Filter RAG results by min_score and extract (text, score) pairs.

        Handles multiple result formats defensively:
          - List of dicts with 'text'/'content' and 'score' keys
          - List of tuples (text, score)
          - List of objects with .text/.content and .score attributes
        """
        filtered: List[Tuple[str, float]] = []

        for result in raw_results:
            text = ""
            score = 0.0

            try:
                if isinstance(result, dict):
                    text = str(
                        result.get("text", result.get("content", ""))
                    )
                    score = float(result.get("score", 0.0))
                elif isinstance(result, (list, tuple)) and len(result) >= 2:
                    text = str(result[0])
                    score = float(result[1])
                elif hasattr(result, "text") or hasattr(result, "content"):
                    text = str(
                        getattr(result, "text", "")
                        or getattr(result, "content", "")
                    )
                    score = float(getattr(result, "score", 0.0))
                else:
                    logger.debug(
                        "Unknown RAG result format: %s; skipping", type(result)
                    )
                    continue

                if score >= self._rag_config.min_score and text.strip():
                    filtered.append((text.strip(), score))

            except (ValueError, TypeError, AttributeError) as exc:
                logger.debug("Skipping malformed RAG result: %s", exc)
                continue

        # Sort by score descending (best first)
        filtered.sort(key=lambda x: x[1], reverse=True)
        return filtered

    def _build_context(
        self,
        filtered: List[Tuple[str, float]],
        ctx: RAGContext,
    ) -> RAGContext:
        """
        Combine filtered snippets into a single context block,
        respecting max_context_length.
        """
        max_len = self._rag_config.max_context_length
        combined_chars = 0
        accepted: List[Tuple[str, float]] = []

        for text, score in filtered:
            remaining = max_len - combined_chars
            if remaining <= 0:
                ctx.truncated = True
                logger.warning(
                    "RAG context truncated at %d chars (max=%d); "
                    "%d snippet(s) dropped",
                    combined_chars,
                    max_len,
                    len(filtered) - len(accepted),
                )
                break

            if len(text) > remaining:
                # Truncate this snippet to fit
                text = text[:remaining].rsplit(" ", 1)[0]  # word boundary
                if not text:
                    text = filtered[len(accepted)][0][:remaining]
                ctx.truncated = True

            accepted.append((text, score))
            combined_chars += len(text)

        ctx.snippets = accepted
        ctx.total_chars = combined_chars
        return ctx

    # ─────────────────────────────────────────────
    # Prompt Injection
    # ─────────────────────────────────────────────

    def _inject_context(self, prompt: str, ctx: RAGContext) -> str:
        """
        Inject RAG context into the prompt based on inject_mode.

        The context is clearly delimited so the AI model understands
        it is supplementary reference material, not the user's request.
        """
        if not ctx.has_context:
            return prompt

        # Build the context block
        context_parts = []
        for i, (text, score) in enumerate(ctx.snippets, 1):
            context_parts.append(
                f"[Snippet {i} | relevance: {score:.2f}]\n{text}"
            )

        context_block = "\n\n".join(context_parts)

        if self._rag_config.inject_mode == "prepend":
            enhanced_prompt = (
                "═══ SECURITY KNOWLEDGE BASE CONTEXT ═══\n"
                "The following snippets are retrieved from a curated security "
                "knowledge base (HackTricks, OWASP, CVE databases, etc.) and "
                "are provided as supplementary reference. Use them to inform "
                "your response, but follow the user's specific request below.\n\n"
                f"{context_block}\n\n"
                "═══ END OF CONTEXT ═══\n\n"
                "═══ USER REQUEST ═══\n"
                f"{prompt}"
            )
        else:  # append
            enhanced_prompt = (
                f"{prompt}\n\n"
                "═══ ADDITIONAL SECURITY KNOWLEDGE CONTEXT ═══\n"
                "The following snippets are from a curated security knowledge "
                "base. Use them as supplementary reference for your response.\n\n"
                f"{context_block}\n\n"
                "═══ END OF CONTEXT ═══"
            )

        logger.debug(
            "Prompt enhanced with RAG context: original=%d chars, "
            "context=%d chars, total=%d chars, mode=%s",
            len(prompt),
            ctx.total_chars,
            len(enhanced_prompt),
            self._rag_config.inject_mode,
        )

        return enhanced_prompt

    # ─────────────────────────────────────────────
    # Provider Selection (Existing Logic)
    # ─────────────────────────────────────────────

    def _decide_provider(self, complexity: TaskComplexity) -> str:
        """
        Select AI provider based on complexity and routing config.

        Returns provider name string (e.g., "openai", "anthropic", "ollama").
        """
        if self._routing_config.get("auto_select", True):
            thresholds = self._routing_config.get("complexity_thresholds", {})
            provider = thresholds.get(
                complexity.value,
                self._providers_config.get("primary", "openai"),
            )
        else:
            provider = self._providers_config.get("primary", "openai")

        logger.debug(
            "Provider selected: %s (complexity=%s, auto_select=%s)",
            provider,
            complexity.value,
            self._routing_config.get("auto_select", True),
        )
        return provider

    def _get_fallback_chain(self) -> List[str]:
        """Return the ordered fallback chain of providers."""
        return self._providers_config.get(
            "fallback_chain", ["openai", "anthropic", "ollama"]
        )

    # ─────────────────────────────────────────────
    # AI Provider Calls
    # ─────────────────────────────────────────────

    def _call_openai(self, prompt: str, config: Dict[str, Any]) -> str:
        """Call OpenAI API. Raises on failure."""
        if not _OPENAI_AVAILABLE:
            raise RuntimeError("openai library not installed")

        api_key = os.environ.get(config.get("api_key_env", "OPENAI_API_KEY"), "")
        if not api_key:
            raise RuntimeError(
                f"OpenAI API key not found in env var "
                f"{config.get('api_key_env', 'OPENAI_API_KEY')}"
            )

        client = _openai_lib.OpenAI(api_key=api_key)
        response = client.chat.completions.create(
            model=config.get("model", "gpt-4o"),
            messages=[{"role": "user", "content": prompt}],
            max_tokens=config.get("max_tokens", 4096),
            temperature=config.get("temperature", 0.3),
            timeout=config.get("timeout", 60),
        )
        return response.choices[0].message.content or ""

    def _call_anthropic(self, prompt: str, config: Dict[str, Any]) -> str:
        """Call Anthropic API. Raises on failure."""
        if not _ANTHROPIC_AVAILABLE:
            raise RuntimeError("anthropic library not installed")

        api_key = os.environ.get(
            config.get("api_key_env", "ANTHROPIC_API_KEY"), ""
        )
        if not api_key:
            raise RuntimeError(
                f"Anthropic API key not found in env var "
                f"{config.get('api_key_env', 'ANTHROPIC_API_KEY')}"
            )

        client = _anthropic_lib.Anthropic(api_key=api_key)
        response = client.messages.create(
            model=config.get("model", "claude-sonnet-4-20250514"),
            max_tokens=config.get("max_tokens", 4096),
            messages=[{"role": "user", "content": prompt}],
        )
        return response.content[0].text if response.content else ""

    def _call_ollama(self, prompt: str, config: Dict[str, Any]) -> str:
        """Call Ollama (local) API via HTTP. Raises on failure."""
        if not _HTTPX_AVAILABLE:
            raise RuntimeError("httpx library not installed for Ollama")

        base_url = config.get("base_url", "http://localhost:11434")
        timeout = config.get("timeout", 120)

        response = _httpx_lib.post(
            f"{base_url}/api/generate",
            json={
                "model": config.get("model", "llama3"),
                "prompt": prompt,
                "stream": False,
                "options": {
                    "num_predict": config.get("max_tokens", 4096),
                    "temperature": config.get("temperature", 0.3),
                },
            },
            timeout=timeout,
        )
        response.raise_for_status()
        return response.json().get("response", "")

    _PROVIDER_DISPATCH = {
        "openai": "_call_openai",
        "anthropic": "_call_anthropic",
        "ollama": "_call_ollama",
    }

    def _call_provider(self, provider: str, prompt: str) -> Tuple[str, str]:
        """
        Call a specific AI provider.

        Returns (response_text, model_name).
        Raises on failure.
        """
        method_name = self._PROVIDER_DISPATCH.get(provider)
        if not method_name:
            raise ValueError(f"Unknown provider: {provider}")

        config = self._providers_config.get(provider, {})
        method = getattr(self, method_name)
        response_text = method(prompt, config)
        model_name = config.get("model", "unknown")
        return response_text, model_name

    # ─────────────────────────────────────────────
    # Main Generate (Synchronous)
    # ─────────────────────────────────────────────

    def generate(self, request: TaskRequest) -> GenerationResult:
        """
        Generate an AI response with RAG-enhanced context.

        Flow:
          1. Search RAG knowledge base (if enabled & not skipped)
          2. Inject retrieved context into prompt
          3. Select provider based on complexity
          4. Call provider with fallback chain
          5. Return result with full telemetry

        Args:
            request: TaskRequest with prompt, complexity, etc.

        Returns:
            GenerationResult with mandatory `data` field.
        """
        overall_start = time.monotonic()

        # ── Validate Input ──
        if not request.prompt or not request.prompt.strip():
            logger.error("Empty prompt received; returning error result")
            return GenerationResult(
                data={
                    "findings": [],
                    "stats": {"error": "empty_prompt"},
                    "response": "",
                },
                success=False,
                error="Prompt cannot be empty",
            )

        # ── Step 1: RAG Search ──
        rag_ctx = RAGContext()
        if (
            self._rag_config.enabled
            and not request.skip_rag
            and self._rag_operational
        ):
            logger.debug("Initiating RAG search for prompt (%.50s...)", request.prompt)
            rag_ctx = self._search_rag(request.prompt)
        else:
            skip_reason = []
            if not self._rag_config.enabled:
                skip_reason.append("disabled_by_config")
            if request.skip_rag:
                skip_reason.append("skip_rag_flag")
            if not self._rag_operational:
                skip_reason.append("rag_not_operational")
            logger.debug("RAG search skipped: %s", ", ".join(skip_reason))

        # ── Step 2: Inject Context ──
        enhanced_prompt = self._inject_context(request.prompt, rag_ctx)

        # ── Step 3: Select Provider ──
        primary_provider = self._decide_provider(request.complexity)
        fallback_chain = self._get_fallback_chain()

        # Ensure primary is tried first, then the rest of the chain
        providers_to_try = [primary_provider]
        for p in fallback_chain:
            if p != primary_provider:
                providers_to_try.append(p)

        # ── Step 4: Call Provider with Fallback ──
        max_retries = self._retry_config.get("max_retries", 3)
        backoff_factor = self._retry_config.get("backoff_factor", 2.0)
        last_error = ""
        provider_used = "none"
        model_used = "none"

        for provider in providers_to_try:
            for attempt in range(1, max_retries + 1):
                try:
                    logger.debug(
                        "Calling provider=%s attempt=%d/%d",
                        provider,
                        attempt,
                        max_retries,
                    )
                    call_start = time.monotonic()
                    response_text, model_used = self._call_provider(
                        provider, enhanced_prompt
                    )
                    call_elapsed = (time.monotonic() - call_start) * 1000

                    logger.info(
                        "AI generation SUCCESS: provider=%s, model=%s, "
                        "%.1fms, response_len=%d",
                        provider,
                        model_used,
                        call_elapsed,
                        len(response_text),
                    )

                    overall_elapsed = (time.monotonic() - overall_start) * 1000

                    return GenerationResult(
                        data={
                            "findings": [response_text],
                            "stats": {
                                "provider": provider,
                                "model": model_used,
                                "generation_time_ms": round(call_elapsed, 1),
                                "total_time_ms": round(overall_elapsed, 1),
                                "rag_snippets_used": len(rag_ctx.snippets),
                                "rag_context_chars": rag_ctx.total_chars,
                                "rag_search_time_ms": round(
                                    rag_ctx.search_time_ms, 1
                                ),
                                "rag_truncated": rag_ctx.truncated,
                                "prompt_enhanced": rag_ctx.has_context,
                            },
                            "response": response_text,
                        },
                        provider_used=provider,
                        model_used=model_used,
                        rag_context=rag_ctx,
                        generation_time_ms=round(overall_elapsed, 1),
                        success=True,
                    )

                except Exception as exc:
                    last_error = f"{provider}[attempt {attempt}]: {exc}"
                    logger.warning(
                        "Provider %s attempt %d failed: %s",
                        provider,
                        attempt,
                        exc,
                    )
                    if attempt < max_retries:
                        sleep_time = backoff_factor ** (attempt - 1)
                        logger.debug("Backing off %.1fs before retry", sleep_time)
                        time.sleep(sleep_time)

            logger.warning(
                "Provider %s exhausted all %d retries; moving to next fallback",
                provider,
                max_retries,
            )

        # ── All Providers Failed ──
        overall_elapsed = (time.monotonic() - overall_start) * 1000
        logger.error(
            "ALL providers failed after full fallback chain. "
            "Last error: %s. Total time: %.1fms",
            last_error,
            overall_elapsed,
        )

        return GenerationResult(
            data={
                "findings": [],
                "stats": {
                    "error": "all_providers_failed",
                    "last_error": last_error,
                    "total_time_ms": round(overall_elapsed, 1),
                    "rag_snippets_used": len(rag_ctx.snippets),
                    "rag_context_chars": rag_ctx.total_chars,
                },
                "response": "",
            },
            provider_used="none",
            model_used="none",
            rag_context=rag_ctx,
            generation_time_ms=round(overall_elapsed, 1),
            success=False,
            error=f"All providers failed. Last: {last_error}",
        )

    # ─────────────────────────────────────────────
    # Async Generate
    # ─────────────────────────────────────────────

    async def async_generate(self, request: TaskRequest) -> GenerationResult:
        """
        Async version of generate().

        Delegates to the synchronous generate() in a thread pool
        to avoid blocking the event loop, while maintaining identical
        RAG integration, fallback logic, and telemetry.
        """
        loop = asyncio.get_running_loop()
        try:
            result = await loop.run_in_executor(None, self.generate, request)
            return result
        except Exception as exc:
            logger.error("async_generate unexpected error: %s", exc)
            return GenerationResult(
                data={
                    "findings": [],
                    "stats": {"error": str(exc)},
                    "response": "",
                },
                success=False,
                error=str(exc),
            )

    # ─────────────────────────────────────────────
    # Health Check & Diagnostics
    # ─────────────────────────────────────────────

    def health_check(self) -> Dict[str, Any]:
        """
        Return a diagnostic snapshot of the router's state.

        Useful for monitoring dashboards and integration tests.
        """
        return {
            "router_operational": True,
            "rag": {
                "config_enabled": self._rag_config.enabled,
                "module_available": _RAG_AVAILABLE,
                "client_operational": self._rag_operational,
                "search_limit": self._rag_config.search_limit,
                "min_score": self._rag_config.min_score,
                "max_context_length": self._rag_config.max_context_length,
                "inject_mode": self._rag_config.inject_mode,
                "search_timeout": self._rag_config.search_timeout,
            },
            "providers": {
                "primary": self._providers_config.get("primary", "none"),
                "fallback_chain": self._get_fallback_chain(),
                "openai_available": _OPENAI_AVAILABLE,
                "anthropic_available": _ANTHROPIC_AVAILABLE,
                "ollama_available": _HTTPX_AVAILABLE,
            },
            "config_path": str(self._config_path),
        }

    def shutdown(self) -> None:
        """Clean up resources (thread pool)."""
        logger.info("AIRouter shutting down...")
        self._rag_executor.shutdown(wait=False)
        logger.info("AIRouter shutdown complete")