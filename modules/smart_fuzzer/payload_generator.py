"""
Payload Generator — AI-driven payload creation and adaptive mutation.

Responsibilities:
    1. Generate initial diverse payloads for a given parameter + vuln type via AI Router.
    2. Mutate/obfuscate payloads when WAF blocks or other failures occur.
    3. Fall back to static payloads from config when AI is unavailable.
    4. Deduplicate all generated payloads.
    5. Log all AI interactions with latency and token metrics.

Design Principles:
    - Never silently fail: always return usable payloads (AI or fallback).
    - All AI calls are wrapped with retry + fallback logic.
    - Mutation uses higher temperature for creative bypass generation.
"""

import time
import json
import re
from typing import List, Optional, Dict, Any
from pathlib import Path

import yaml

from shared.logger import get_logger

logger = get_logger("smart_fuzzer.payload_generator")

# ---------------------------------------------------------------------------
# Attempt to import the AI Router; if unavailable, we set a flag so we can
# gracefully degrade to static payloads everywhere.
# ---------------------------------------------------------------------------
_AI_ROUTER_AVAILABLE = True
try:
    from modules.ai_routing.router import AIRouter, TaskComplexity
except ImportError as _import_err:
    _AI_ROUTER_AVAILABLE = False
    logger.warning(
        "AI Router import failed — all payload generation will use static fallbacks. "
        "Error: %s",
        _import_err,
    )

# ---------------------------------------------------------------------------
# Attempt to import OAST Listener; if unavailable, we set a flag for graceful fallback
# ---------------------------------------------------------------------------
_OAST_AVAILABLE = True
try:
    from modules.oast_listener import generate_payload as oast_generate_payload
except ImportError as _import_err:
    _OAST_AVAILABLE = False
    logger.info(
        "OAST Listener import failed — OAST payload generation will be skipped. "
        "Error: %s",
        _import_err,
    )

# Sentinel for "no AI available" so we can catch it uniformly
class NoAIAvailableError(Exception):
    """Raised when no AI backend is reachable after exhausting the fallback chain."""


def _load_config() -> dict:
    """Load config.yaml with absolute path resolution, caching on first call."""
    config_path = Path(__file__).parent / "config.yaml"
    if not config_path.exists():
        logger.error("config.yaml not found at %s — using empty defaults", config_path)
        return {}
    with open(config_path, "r") as f:
        return yaml.safe_load(f) or {}


# Module-level config cache (loaded once)
_CONFIG: dict = _load_config()


class PayloadGenerator:
    print("DEBUG: PayloadGenerator class is being parsed")
    """
    Generates and mutates fuzzing payloads using AI with static fallbacks.

    Usage:
        gen = PayloadGenerator(ai_router_instance)
        payloads = gen.generate_initial("q", "string", ["xss", "sqli"], context={...})
        mutated = gen.mutate_on_failure(original, response_snippet, "xss")
    """

    def __init__(self, ai_router=None):
        """
        Args:
            ai_router: An instance of AIRouter. If None and the module is importable,
                       a default instance is created. If the module is not importable,
                       all calls degrade to static payloads.
        """
        self._config = _CONFIG
        self._ai_config = self._config.get("ai", {})
        self._fallbacks = self._config.get("payloads", {})
        self._detection = self._config.get("detection", {})
        self._initial_count = self._config.get("initial_payloads_per_type", 5)
        self._gen_retries = self._ai_config.get("generation_retries", 2)
        self._gen_temp = self._ai_config.get("generation_temperature", 0.7)
        self._mut_temp = self._ai_config.get("mutation_temperature", 0.9)
        self._prompt_max = self._ai_config.get("prompt_max_length", 4000)

        # AI Router instance
        self._router = ai_router
        if self._router is None and _AI_ROUTER_AVAILABLE:
            try:
                self._router = AIRouter()
                logger.info("PayloadGenerator initialized with default AIRouter instance.")
            except Exception as e:
                logger.warning("Failed to create default AIRouter: %s — static fallbacks only.", e)
                self._router = None

        # Seen payloads for deduplication (per generator lifetime)
        self._seen: set = set()

    # ------------------------------------------------------------------
    # PUBLIC: generate_initial
    # ------------------------------------------------------------------
    def generate_initial(
        self,
        parameter_name: str,
        param_type: str,
        vuln_types: List[str],
        context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, List[str]]:
        """
        Generate initial payloads for each requested vulnerability type.

        Args:
            parameter_name: Name of the HTTP parameter being fuzzed.
            param_type: Type hint (e.g., "string", "integer"). Defaults to "string".
            vuln_types: List of vuln classes (e.g., ["xss", "sqli"]).
            context: Optional dict with extra context (URL, method, headers, etc.).

        Returns:
            Dict mapping vuln_type → list of unique payload strings.
            Example: {"xss": ["<script>...", ...], "sqli": ["' OR ...", ...]}
        """
        if not param_type:
            param_type = "string"
            logger.debug(
                "No param_type_hint for '%s', defaulting to 'string'.", parameter_name
            )

        context = context or {}
        results: Dict[str, List[str]] = {}

        for vtype in vuln_types:
            vtype_lower = vtype.lower().strip()
            payloads = self._generate_for_type(
                parameter_name, param_type, vtype_lower, context
            )
            # Deduplicate
            unique = self._deduplicate(payloads)
            results[vtype_lower] = unique
            logger.info(
                "Generated %d unique initial payloads for param='%s', vuln_type='%s'.",
                len(unique),
                parameter_name,
                vtype_lower,
            )

        return results

    # ------------------------------------------------------------------
    # PUBLIC: mutate_on_failure
    # ------------------------------------------------------------------
    def mutate_on_failure(
        self,
        original_payload: str,
        server_response: str,
        vuln_type: str,
    ) -> Optional[str]:
        """
        Request an obfuscated/encoded mutation of a payload that was blocked.

        Args:
            original_payload: The payload that failed (WAF block, etc.).
            server_response: Snippet of the server response (truncated to 2000 chars).
            vuln_type: The vulnerability class being tested.

        Returns:
            A new mutated payload string, or None if mutation fails entirely.
        """
        vuln_type = vuln_type.lower().strip()
        # Truncate response to avoid prompt overflow
        snippet = (server_response or "")[:2000]

        if not self._router:
            logger.warning(
                "AI Router unavailable for mutation — returning None for payload '%s'.",
                original_payload[:80],
            )
            return None

        prompt = self._build_mutation_prompt(original_payload, snippet, vuln_type)

        for attempt in range(1, self._gen_retries + 1):
            try:
                start_ts = time.monotonic()
                response = self._call_ai(
                    prompt=prompt,
                    complexity="MEDIUM",
                    temperature=self._mut_temp,
                )
                elapsed = time.monotonic() - start_ts

                mutated = self._parse_single_payload(response)
                if mutated and mutated != original_payload:
                    logger.info(
                        "Mutation succeeded (attempt %d, %.2fs): '%s' → '%s'",
                        attempt,
                        elapsed,
                        original_payload[:60],
                        mutated[:60],
                    )
                    return mutated
                else:
                    logger.debug(
                        "Mutation attempt %d returned same/empty payload — retrying.",
                        attempt,
                    )

            except NoAIAvailableError:
                logger.warning("AI unavailable during mutation attempt %d.", attempt)
                return None
            except Exception as e:
                logger.error(
                    "Mutation attempt %d failed with unexpected error: %s", attempt, e
                )

        logger.warning(
            "All %d mutation attempts failed for payload '%s'.",
            self._gen_retries,
            original_payload[:80],
        )
        
        # Optionally generate OAST payload as fallback for blind vulnerabilities
        if vuln_type in ["blind_xss", "blind_ssrf", "blind_sqli", "blind_rce"]:
            logger.info(
                "Mutation failed for blind vulnerability '%s' — attempting OAST payload generation",
                vuln_type
            )
            # We need task_id and scan_id; they're not available here.
            # For now, generate a generic OAST payload without task/scan context
            # In practice, the caller should provide these via additional parameters
            # or we should fetch from context.
            # For now, we'll log that OAST is available but skip.
            if _OAST_AVAILABLE:
                logger.debug("OAST module available but missing task_id/scan_id — skipping")
        
        return None

    # ------------------------------------------------------------------
    # INTERNAL: per-type generation
    # ------------------------------------------------------------------
    def _generate_for_type(
        self,
        param_name: str,
        param_type: str,
        vuln_type: str,
        context: Dict[str, Any],
    ) -> List[str]:
        """Try AI generation with retries; fall back to static if needed."""

        if not self._router:
            logger.info(
                "AI Router not available — using static fallback for vuln_type='%s'.",
                vuln_type,
            )
            return self._get_static_fallback(vuln_type)

        prompt = self._build_generation_prompt(
            param_name, param_type, vuln_type, context
        )

        for attempt in range(1, self._gen_retries + 1):
            try:
                start_ts = time.monotonic()
                response = self._call_ai(
                    prompt=prompt,
                    complexity="MEDIUM",
                    temperature=self._gen_temp,
                )
                elapsed = time.monotonic() - start_ts

                payloads = self._parse_payload_list(response, vuln_type)
                if payloads:
                    logger.info(
                        "AI generated %d payloads for '%s/%s' (attempt %d, %.2fs).",
                        len(payloads),
                        param_name,
                        vuln_type,
                        attempt,
                        elapsed,
                    )
                    return payloads
                else:
                    logger.warning(
                        "AI returned unparseable payload list (attempt %d) — retrying.",
                        attempt,
                    )

            except NoAIAvailableError:
                logger.warning(
                    "AI unavailable (attempt %d) for '%s/%s' — will try fallback.",
                    attempt,
                    param_name,
                    vuln_type,
                )
                break
            except Exception as e:
                logger.error(
                    "AI generation attempt %d failed: %s", attempt, e, exc_info=True
                )

        # Exhausted retries → static fallback
        logger.warning(
            "Falling back to static payloads for vuln_type='%s' after %d failed AI attempts.",
            vuln_type,
            self._gen_retries,
        )
        return self._get_static_fallback(vuln_type)

    # ------------------------------------------------------------------
    # AI CALL WRAPPER
    # ------------------------------------------------------------------
    def _call_ai(
        self,
        prompt: str,
        complexity: str = "MEDIUM",
        temperature: float = 0.7,
    ) -> str:
        """Unified AI call through the router using TaskRequest."""
        if not self._router:
            raise NoAIAvailableError("AI Router instance is None.")

        # Truncate prompt to configured max
        if len(prompt) > self._prompt_max:
            prompt = prompt[: self._prompt_max]
            logger.debug("Prompt truncated to %d chars.", self._prompt_max)

        from modules.ai_routing.router import TaskRequest, TaskComplexity

        # Map complexity string to enum
        complexity_enum = getattr(TaskComplexity, complexity.upper(), TaskComplexity.MEDIUM)

        request = TaskRequest(
            task_type="fuzzer_generation",
            prompt=prompt,
            context_length=len(prompt) // 4,  # rough token estimate
            complexity=complexity_enum,
            max_tokens=200,
            temperature=temperature,
        )

        start_ts = time.monotonic()
        try:
            result = self._router.generate(request)  # returns string
            elapsed = time.monotonic() - start_ts
            logger.debug("AI call completed in %.2fs | prompt_len: %d", elapsed, len(prompt))
            return result
        except Exception as e:
            elapsed = time.monotonic() - start_ts
            err_name = type(e).__name__
            if "NoAI" in err_name or "Unavailable" in err_name:
                logger.warning("AI Router reported no availability (%.2fs): %s", elapsed, e)
                raise NoAIAvailableError(str(e)) from e
            raise
    # ------------------------------------------------------------------
    # PROMPT BUILDERS
    # ------------------------------------------------------------------
    def _build_generation_prompt(
        self,
        param_name: str,
        param_type: str,
        vuln_type: str,
        context: Dict[str, Any],
    ) -> str:
        target_url = context.get("target", "unknown")
        method = context.get("method", "GET")

        return f"""You are an expert penetration tester generating fuzzing payloads.

Target: {target_url}
HTTP Method: {method}
Parameter: {param_name} (type: {param_type})
Vulnerability Type: {vuln_type.upper()}

Generate exactly {self._initial_count} diverse, creative payloads for testing {vuln_type.upper()} vulnerabilities in the '{param_name}' parameter.

Requirements:
- Each payload should test a different attack vector or encoding technique.
- Include both basic and advanced/obfuscated variants.
- Consider WAF evasion techniques (case variation, encoding, null bytes, comments).
- For {param_type} type parameters, ensure payloads are contextually appropriate.
- If the parameter type is "integer", include payloads that start with valid integers but inject malicious content.

Output format: Return ONLY a JSON array of strings, one per payload. No explanation, no markdown.
Example: ["payload1", "payload2", "payload3"]
"""

    def _build_mutation_prompt(
        self,
        original_payload: str,
        server_response: str,
        vuln_type: str,
    ) -> str:
        return f"""You are an expert penetration tester specializing in WAF bypass techniques.

The following {vuln_type.upper()} payload was BLOCKED by the target's defenses:
Payload: {original_payload}

Server response snippet (first 2000 chars):
---
{server_response}
---

Generate ONE new mutated payload that:
1. Achieves the same {vuln_type.upper()} attack goal.
2. Uses different encoding, obfuscation, or evasion technique.
3. Attempts to bypass the detected defense mechanism.

Techniques to consider:
- URL encoding (single, double, unicode)
- Case variation
- HTML entity encoding
- String concatenation / splitting
- Comment injection (SQL: /**/, XSS: <!--)
- Alternative syntax (e.g., different JS event handlers, SQL keywords)
- Null byte injection
- Polyglot payloads

Output format: Return ONLY the single payload string. No explanation, no quotes, no markdown.
"""

    def _build_verification_prompt(
        self,
        payload: str,
        response_snippet: str,
        vuln_type: str,
    ) -> str:
        """Build prompt for verifying a potential finding. (Used by fuzzer.py)"""
        return f"""You are a senior security analyst verifying vulnerability findings.

Vulnerability Type: {vuln_type.upper()}
Payload Sent: {payload}

Response Snippet (first 2000 chars):
---
{response_snippet}
---

Analyze whether this response indicates a TRUE {vuln_type.upper()} vulnerability:

1. Is the payload reflected in the response without proper sanitization?
2. Are there error messages revealing backend technology or query structure?
3. Could this be a false positive (e.g., generic error page, payload not actually executed)?

Respond with ONLY a JSON object:
{{"is_vulnerable": true/false, "confidence": 0.0-1.0, "evidence": "brief explanation"}}
"""

    # ------------------------------------------------------------------
    # RESPONSE PARSERS
    # ------------------------------------------------------------------
    def _parse_payload_list(self, ai_response: str, vuln_type: str) -> List[str]:
        """
        Parse AI response expecting a JSON array of payload strings.
        Falls back to line-by-line extraction if JSON parsing fails.
        """
        if not ai_response or not ai_response.strip():
            return []

        text = ai_response.strip()

        # Strategy 1: Try direct JSON parse
        try:
            # Find JSON array in response (may be wrapped in markdown code blocks)
            json_match = re.search(r'\[.*?\]', text, re.DOTALL)
            if json_match:
                parsed = json.loads(json_match.group())
                if isinstance(parsed, list):
                    result = [str(p).strip() for p in parsed if p and str(p).strip()]
                    if result:
                        return result[:self._initial_count + 2]  # Allow slight over-generation
        except (json.JSONDecodeError, ValueError):
            pass

        # Strategy 2: Line-by-line extraction
        lines = text.split("\n")
        payloads = []
        for line in lines:
            line = line.strip()
            # Skip empty lines, comments, numbered prefixes
            if not line:
                continue
            # Remove common prefixes like "1.", "- ", "* "
            cleaned = re.sub(r'^[\d]+[\.\)\-]\s*', '', line)
            cleaned = re.sub(r'^[\-\*]\s*', '', cleaned)
            # Remove surrounding quotes
            cleaned = cleaned.strip('"').strip("'").strip('`')
            if cleaned and len(cleaned) > 1:
                payloads.append(cleaned)

        if payloads:
            return payloads[:self._initial_count + 2]

        logger.debug("Could not parse any payloads from AI response: %s", text[:200])
        return []

    def _parse_single_payload(self, ai_response: str) -> Optional[str]:
        """Parse AI response expecting a single payload string."""
        if not ai_response or not ai_response.strip():
            return None

        text = ai_response.strip()
        # Remove markdown code fences if present
        text = re.sub(r'^```[a-z]*\n?', '', text)
        text = re.sub(r'\n?```$', '', text)
        text = text.strip().strip('"').strip("'")

        if text and len(text) > 0:
            return text
        return None

    def parse_verification_response(self, ai_response: str) -> Dict[str, Any]:
        """
        Parse AI verification response. Returns dict with is_vulnerable, confidence, evidence.
        Safe against malformed responses.
        """
        default = {"is_vulnerable": False, "confidence": 0.0, "evidence": "Verification parse failed."}

        if not ai_response or not ai_response.strip():
            return default

        try:
            json_match = re.search(r'\{.*?\}', ai_response, re.DOTALL)
            if json_match:
                parsed = json.loads(json_match.group())
                return {
                    "is_vulnerable": bool(parsed.get("is_vulnerable", False)),
                    "confidence": float(parsed.get("confidence", 0.0)),
                    "evidence": str(parsed.get("evidence", "No evidence provided.")),
                }
        except (json.JSONDecodeError, ValueError, TypeError) as e:
            logger.debug("Verification response parse error: %s | Response: %s", e, ai_response[:200])

        # Heuristic fallback: look for keywords
        lower = ai_response.lower()
        if "true" in lower or "is_vulnerable\": true" in lower or "vulnerable" in lower:
            return {"is_vulnerable": True, "confidence": 0.6, "evidence": "Heuristic parse — AI indicated vulnerable."}

        return default

    # ------------------------------------------------------------------
    # OAST PAYLOAD GENERATION
    # ------------------------------------------------------------------
    def generate_oast_payload(self, vuln_type: str, task_id: str, scan_id: str) -> Optional[str]:
        """
        Generate an OAST payload for blind vulnerability detection.
        
        Args:
            vuln_type: Vulnerability type (e.g., "blind_xss", "blind_ssrf")
            task_id: Parent task ID
            scan_id: Scan session ID
            
        Returns:
            OAST payload URL string, or None if OAST module unavailable
        """
        if not _OAST_AVAILABLE:
            logger.debug("OAST module not available — skipping OAST payload generation")
            return None
        
        try:
            # Import here to avoid circular imports
            from modules.oast_listener import generate_payload as oast_generate_payload
            
            payload_info = oast_generate_payload(
                task_id=task_id,
                scan_id=scan_id,
                vuln_type=vuln_type,
                config=None,  # Uses module config
                redis_client=None,  # Uses module singleton
            )
            logger.info(
                "Generated OAST payload",
                extra={
                    "vuln_type": vuln_type,
                    "task_id": task_id,
                    "scan_id": scan_id,
                    "url": payload_info.url,
                }
            )
            return payload_info.url
        except Exception as e:
            logger.warning(
                "Failed to generate OAST payload: %s",
                e,
                exc_info=True
            )
            return None

    # ------------------------------------------------------------------
    # STATIC FALLBACKS & DEDUP
    # ------------------------------------------------------------------
    def _get_static_fallback(self, vuln_type: str) -> List[str]:
        """Return static fallback payloads for a given vulnerability type."""
        key = f"fallback_{vuln_type.lower()}"
        payloads = self._fallbacks.get(key, [])
        if not payloads:
            logger.warning(
                "No static fallback payloads defined for vuln_type='%s' (key='%s'). "
                "Returning generic probe.",
                vuln_type,
                key,
            )
            # Absolute last resort: return a generic probe
            return [f"<test_{vuln_type}>", f"' OR '{vuln_type}'='{vuln_type}"]
        return list(payloads)  # Return a copy

    def _deduplicate(self, payloads: List[str]) -> List[str]:
        """Remove duplicates while preserving order. Tracks across calls within this instance."""
        unique = []
        for p in payloads:
            if p not in self._seen:
                self._seen.add(p)
                unique.append(p)
        return unique

    def reset_dedup_cache(self):
        """Clear the deduplication cache (call between unrelated tasks)."""
        self._seen.clear()