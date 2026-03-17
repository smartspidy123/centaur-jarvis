"""
AI Template Generator
=====================
Consumes CVE tasks from the nuclei_sniper queue, uses the AI Router
to generate Nuclei YAML templates, and passes them to the validator.

Edge Cases Handled:
- EC3:  AI router unavailable → fallback to static template stub
- EC4:  AI returns malformed YAML → retry with error feedback
- EC5:  Validation error feedback → re-prompt AI with error details
- EC8:  Rate limiting on AI calls
- EC9:  Redis connection lost → graceful handling
"""

import json
import re
import time
from typing import Optional, Tuple, Dict, Any, List

import redis
import yaml as pyyaml

# OAST Listener integration with graceful fallback
try:
    from modules.oast_listener.correlator import generate_payload, get_oast_url
    from modules.oast_listener.models import PayloadInfo
    OAST_AVAILABLE = True
except ImportError:
    OAST_AVAILABLE = False
    generate_payload = None
    get_oast_url = None
    PayloadInfo = None
    logger.warning(
        "OAST Listener module not available; blind vulnerability detection "
        "will not include OAST payloads."
    )

try:
    from tenacity import (
        retry,
        stop_after_attempt,
        wait_exponential,
        retry_if_exception_type,
        before_sleep_log,
    )
    HAS_TENACITY = True
except ImportError:
    HAS_TENACITY = False

try:
    from shared.logger import get_logger
    from modules.ai_routing.router import TaskRequest, TaskComplexity, AIRouter
except ImportError:
    import logging
    def get_logger(name):
        logger = logging.getLogger(name)
        if not logger.handlers:
            handler = logging.StreamHandler()
            handler.setFormatter(logging.Formatter(
                "%(asctime)s [%(name)s] %(levelname)s %(message)s"
            ))
            logger.addHandler(handler)
            logger.setLevel(logging.INFO)
        return logger

    # Stubs for standalone testing
    class TaskComplexity:
        SIMPLE = "SIMPLE"
        MODERATE = "MODERATE"
        COMPLEX = "COMPLEX"

    class TaskRequest:
        def __init__(self, **kwargs):
            self.__dict__.update(kwargs)

    AIRouter = None

logger = get_logger("nuclei_sniper.generator")

# OAST Listener integration with graceful fallback
try:
    from modules.oast_listener.correlator import generate_payload, get_oast_url
    from modules.oast_listener.models import PayloadInfo
    OAST_AVAILABLE = True
except ImportError:
    OAST_AVAILABLE = False
    generate_payload = None
    get_oast_url = None
    PayloadInfo = None
    logger.warning(
        "OAST Listener module not available; blind vulnerability detection "
        "will not include OAST payloads."
    )


# ---------------------------------------------------------------------------
# Configuration loader
# ---------------------------------------------------------------------------
def _load_config(config_path: str = None) -> dict:
    """Load module configuration."""
    if config_path is None:
        import os
        config_path = os.path.join(os.path.dirname(__file__), "config.yaml")
    try:
        with open(config_path, "r") as f:
            return pyyaml.safe_load(f) or {}
    except (FileNotFoundError, pyyaml.YAMLError) as exc:
        logger.warning("Config load error: %s; using defaults", exc)
        return {}


# ---------------------------------------------------------------------------
# Blind vulnerability detection
# ---------------------------------------------------------------------------
def _is_blind_vulnerability(description: str) -> Tuple[bool, str]:
    """
    Detect if a CVE description indicates a blind vulnerability.
    
    Returns:
        Tuple of (is_blind, vuln_type)
        vuln_type can be 'blind_xss', 'blind_ssrf', 'blind_sqli', 'blind_rce', or 'blind'
    """
    desc_lower = description.lower()
    
    # Keywords for blind vulnerabilities
    blind_keywords = [
        "blind", "out-of-band", "oast", "out of band", "time-based",
        "delayed", "asynchronous", "callback", "external", "dns",
        "http callback", "second-order"
    ]
    
    # Specific vulnerability type detection
    if any(kw in desc_lower for kw in ["xss", "cross-site scripting"]):
        return True, "blind_xss"
    elif any(kw in desc_lower for kw in ["ssrf", "server-side request forgery"]):
        return True, "blind_ssrf"
    elif any(kw in desc_lower for kw in ["sql injection", "sqli", "sql"]):
        return True, "blind_sqli"
    elif any(kw in desc_lower for kw in ["rce", "remote code execution", "command injection"]):
        return True, "blind_rce"
    elif any(kw in desc_lower for kw in blind_keywords):
        return True, "blind"
    
    return False, ""


# ---------------------------------------------------------------------------
# Static fallback template
# ---------------------------------------------------------------------------
FALLBACK_TEMPLATE = """id: {cve_id_lower}-manual-review

info:
  name: "{cve_id} - Manual Review Required"
  author: nuclei-sniper-auto
  severity: unknown
  description: |
    Auto-generated stub for {cve_id}.
    AI generation failed after maximum retries.
    Manual template creation required.
    
    Original description: {description_truncated}
  tags: cve,{cve_id_lower},manual-review
  reference:
    - https://nvd.nist.gov/vuln/detail/{cve_id}

# TODO: This is a placeholder template that requires manual completion.
# The following sections need to be filled in based on the vulnerability details.

http:
  - method: GET
    path:
      - "{{{{BaseURL}}}}/"
    matchers:
      - type: word
        words:
          - "REPLACE_WITH_ACTUAL_DETECTION_STRING"
        condition: and
"""


def generate_fallback_template(cve_id: str, description: str = "") -> str:
    """
    Generate a static fallback template when AI is unavailable (EC3).

    This template requires manual review and completion.
    """
    desc_truncated = description[:500] if description else "No description available"
    return FALLBACK_TEMPLATE.format(
        cve_id=cve_id,
        cve_id_lower=cve_id.lower(),
        description_truncated=desc_truncated.replace('"', "'"),
    )


# ---------------------------------------------------------------------------
# AI Prompt Builder
# ---------------------------------------------------------------------------
class PromptBuilder:
    """Constructs optimized prompts for Nuclei template generation."""

    SYSTEM_PROMPT = """You are an expert security researcher and Nuclei template author.
Your task is to generate a valid Nuclei YAML template for detecting a specific CVE.

RULES:
1. Output ONLY the YAML template. No explanations, no markdown code blocks, no extra text.
2. The template must be valid YAML that passes `nuclei -validate`.
3. Use proper Nuclei template syntax (v2+).
4. Include appropriate matchers (status codes, words, regex, etc.).
5. Set realistic severity based on the CVE description.
6. Include proper metadata (id, info, author, tags, references).
7. Use {{BaseURL}} for the target URL placeholder.
8. If the CVE involves a specific path or parameter, include it.
9. Prefer detection over exploitation (safe checks).
"""

    @staticmethod
    def build_generation_prompt(cve_id: str, description: str,
                                 poc_links: list = None,
                                 oast_payload_url: Optional[str] = None,
                                 max_length: int = 4000) -> str:
        """Build the initial generation prompt."""
        prompt_parts = [
            f"Generate a Nuclei YAML template for {cve_id}.",
            f"\nVulnerability Description:\n{description[:max_length - 500]}",
        ]

        if poc_links:
            links_text = "\n".join(f"  - {link}" for link in poc_links[:5])
            prompt_parts.append(f"\nPoC/Reference Links:\n{links_text}")

        # Include OAST payload URL for blind vulnerabilities
        if oast_payload_url:
            prompt_parts.append(
                f"\nIMPORTANT: This is a BLIND vulnerability. "
                f"Include an OAST (Out-of-Band) payload in the template. "
                f"Use this callback URL: {oast_payload_url}"
                f"\nThe template should trigger a callback to this URL when the vulnerability is exploited."
            )

        prompt_parts.append(
            "\nRemember: Output ONLY the raw YAML template. "
            "No markdown formatting, no code blocks, no explanations."
        )

        prompt = "\n".join(prompt_parts)

        # Truncate if exceeding max length
        if len(prompt) > max_length:
            prompt = prompt[:max_length - 100] + "\n[Description truncated]"

        return prompt

    @staticmethod
    def build_correction_prompt(cve_id: str, original_yaml: str,
                                 validation_error: str,
                                 max_length: int = 4000) -> str:
        """Build a correction prompt when validation fails (EC5)."""
        prompt = (
            f"The following Nuclei YAML template for {cve_id} failed validation.\n\n"
            f"VALIDATION ERROR:\n{validation_error[:500]}\n\n"
            f"ORIGINAL TEMPLATE:\n{original_yaml[:max_length - 800]}\n\n"
            "Please fix the template to pass `nuclei -validate`. "
            "Output ONLY the corrected YAML template. "
            "No markdown formatting, no code blocks, no explanations."
        )
        return prompt[:max_length]


# ---------------------------------------------------------------------------
# YAML Extractor
# ---------------------------------------------------------------------------
def extract_yaml_from_response(response: str) -> str:
    """
    Extract YAML content from AI response, handling common issues (EC4):
    - Markdown code blocks (```yaml ... ```)
    - Leading/trailing whitespace
    - Preamble text before the YAML
    """
    if not response or not response.strip():
        raise ValueError("Empty response from AI")

    text = response.strip()

    # Remove markdown code blocks if present
    # Pattern: ```yaml\n...\n``` or ```\n...\n```
    code_block_pattern = re.compile(
        r"```(?:ya?ml)?\s*\n(.*?)```", re.DOTALL
    )
    matches = code_block_pattern.findall(text)
    if matches:
        text = matches[0].strip()

    # If response starts with explanatory text before YAML, try to find
    # the YAML start (typically "id:" is the first line)
    lines = text.split("\n")
    yaml_start = None
    for i, line in enumerate(lines):
        stripped = line.strip()
        if stripped.startswith("id:") or stripped.startswith("id :"):
            yaml_start = i
            break

    if yaml_start is not None and yaml_start > 0:
        logger.debug("Stripped %d preamble lines from AI response", yaml_start)
        text = "\n".join(lines[yaml_start:])

    # Validate it's parseable YAML
    try:
        parsed = pyyaml.safe_load(text)
        if not isinstance(parsed, dict):
            raise ValueError(
                f"Parsed YAML is not a dictionary (got {type(parsed).__name__})"
            )
        if "id" not in parsed:
            raise ValueError("YAML missing required 'id' field")
        if "info" not in parsed:
            raise ValueError("YAML missing required 'info' field")
    except pyyaml.YAMLError as exc:
        raise ValueError(f"Invalid YAML syntax: {exc}")

    return text


# ---------------------------------------------------------------------------
# Rate Limiter
# ---------------------------------------------------------------------------
class RateLimiter:
    """Simple token-bucket rate limiter for AI calls (EC8)."""

    def __init__(self, max_per_minute: int = 10):
        self._max_per_minute = max_per_minute
        self._timestamps: list = []

    def acquire(self) -> float:
        """
        Block until a request slot is available.

        Returns:
            Wait time in seconds (0.0 if no wait was needed).
        """
        now = time.time()
        # Remove timestamps older than 60 seconds
        self._timestamps = [t for t in self._timestamps if now - t < 60]

        if len(self._timestamps) >= self._max_per_minute:
            # Need to wait
            oldest = self._timestamps[0]
            wait_time = 60 - (now - oldest) + 0.1
            if wait_time > 0:
                logger.info(
                    "Rate limiter: waiting %.1fs (limit: %d/min)",
                    wait_time, self._max_per_minute
                )
                time.sleep(wait_time)

            # Clean again after waiting
            now = time.time()
            self._timestamps = [t for t in self._timestamps if now - t < 60]

            return wait_time
        else:
            self._timestamps.append(now)
            return 0.0


# ---------------------------------------------------------------------------
# Template Generator
# ---------------------------------------------------------------------------
class TemplateGenerator:
    """
    Main generator class that consumes CVE tasks and produces Nuclei templates.
    """

    def __init__(self, redis_client: redis.Redis = None,
                 ai_router=None, config_path: str = None):
        self._config = _load_config(config_path)
        self._redis_client = redis_client
        self._ai_router = ai_router
        self._prompt_builder = PromptBuilder()

        ai_config = self._config.get("ai", {})
        self._max_retries = ai_config.get("generation_retries", 3)
        self._temperature = ai_config.get("generation_temperature", 0.7)
        self._max_prompt_length = ai_config.get("max_prompt_length", 4000)
        self._complexity = ai_config.get("complexity", "COMPLEX")
        self._backoff_base = ai_config.get("retry_backoff_base", 2)
        self._rate_limiter = RateLimiter(
            ai_config.get("max_calls_per_minute", 10)
        )

        redis_config = self._config.get("redis", {})
        self._task_queue = redis_config.get("task_queue", "queue:nuclei_sniper")
        self._status_prefix = redis_config.get("status_prefix",
                                                "nuclei_sniper:status:")
        self._manual_review_key = redis_config.get("manual_review_key",
                                                     "nuclei_sniper:manual_review")
        self._running = False

        self._stats = {
            "tasks_consumed": 0,
            "templates_generated": 0,
            "ai_calls_made": 0,
            "ai_calls_failed": 0,
            "fallbacks_used": 0,
            "ai_total_latency": 0.0,
        }

    @property
    def stats(self) -> dict:
        return self._stats.copy()

    # ----- Redis helpers -----

    def _set_status(self, cve_id: str, status: str, details: str = ""):
        """Set CVE status in Redis (UPPERCASE enforced)."""
        status = status.upper()
        if not self._redis_client:
            logger.warning("No Redis client; cannot set status for %s", cve_id)
            return
        try:
            status_data = json.dumps({
                "status": status,
                "details": details,
                "timestamp": time.time(),
            })
            self._redis_client.set(
                f"{self._status_prefix}{cve_id}", status_data, ex=86400 * 7
            )
        except redis.RedisError as exc:
            logger.error("Redis error setting status for %s: %s", cve_id, exc)

    def _consume_task(self, timeout: int = 5) -> Optional[dict]:
        """Consume a task from the Redis queue (blocking pop)."""
        if not self._redis_client:
            logger.error("No Redis client; cannot consume tasks")
            return None
        try:
            result = self._redis_client.brpop(self._task_queue, timeout=timeout)
            if result:
                _, task_json = result
                return json.loads(task_json)
            return None
        except redis.RedisError as exc:
            logger.error("Redis error consuming task: %s", exc)
            time.sleep(5)  # Back off on Redis error
            return None
        except json.JSONDecodeError as exc:
            logger.error("Failed to decode task JSON: %s", exc)
            return None

    def _store_for_manual_review(self, cve_id: str, template_yaml: str,
                                  reason: str):
        """Store a template that couldn't be auto-generated for manual review."""
        if not self._redis_client:
            logger.warning("No Redis; cannot store %s for manual review", cve_id)
            return
        try:
            review_data = json.dumps({
                "cve_id": cve_id,
                "template": template_yaml,
                "reason": reason,
                "timestamp": time.time(),
            })
            self._redis_client.lpush(self._manual_review_key, review_data)
            logger.info("Stored %s for manual review: %s", cve_id, reason)
        except redis.RedisError as exc:
            logger.error("Failed to store %s for manual review: %s",
                         cve_id, exc)

    # ----- AI interaction -----

    def _call_ai(self, prompt: str, system_prompt: str = None) -> Optional[str]:
        """
        Call the AI Router to generate content.

        Uses TaskRequest + generate() as per architectural rules.
        Falls back gracefully if AI is unavailable (EC3).
        """
        if self._ai_router is None:
            logger.warning("AI Router not available; cannot generate template")
            return None

        self._rate_limiter.acquire()

        start_time = time.time()
        self._stats["ai_calls_made"] += 1

        try:
            # Use TaskRequest + generate() — per architectural rules
            task_request = TaskRequest(
                task_type="nuclei_template_generation",
                prompt=prompt,
                context_length=len(prompt) // 4,  # rough token estimate
                complexity=self._complexity,
                max_tokens=4000,
                temperature=self._temperature,
            )

            response = self._ai_router.generate(task_request)

            elapsed = time.time() - start_time
            self._stats["ai_total_latency"] += elapsed

            # Log telemetry
            log_payloads = self._config.get("logging", {}).get(
                "log_ai_payloads", False
            )
            if log_payloads:
                logger.debug("AI prompt: %s", prompt[:200])
                logger.debug("AI response: %s", str(response)[:200])

            logger.info("AI call completed in %.2fs", elapsed)

            # Extract the text content from the response
            if hasattr(response, "text"):
                return response.text
            elif hasattr(response, "content"):
                return response.content
            elif isinstance(response, str):
                return response
            elif isinstance(response, dict):
                return response.get("text") or response.get("content", "")
            else:
                logger.warning(
                    "Unexpected AI response type: %s", type(response).__name__
                )
                return str(response)

        except Exception as exc:
            elapsed = time.time() - start_time
            self._stats["ai_calls_failed"] += 1
            logger.error("AI call failed after %.2fs: %s", elapsed, exc)
            return None

    # ----- Main generation logic -----

    def generate_template(self, cve_id: str, description: str,
                           poc_links: list = None,
                           validation_error: str = None,
                           task_id: str = None,
                           scan_id: str = None) -> Tuple[str, bool]:
        """
        Generate a Nuclei template for a CVE.

        Args:
            cve_id: CVE identifier
            description: CVE description
            poc_links: List of PoC URLs
            validation_error: If provided, this is a retry with error feedback
            task_id: Optional task ID for OAST payload generation
            scan_id: Optional scan ID for OAST payload generation

        Returns:
            Tuple of (yaml_string, is_ai_generated)
            is_ai_generated is False when fallback template is used.
        """
        oast_payload_url = None
        
        # Detect blind vulnerabilities and generate OAST payloads
        if not validation_error and OAST_AVAILABLE and task_id and scan_id:
            is_blind, vuln_type = _is_blind_vulnerability(description)
            if is_blind:
                try:
                    payload = generate_payload(
                        task_id=task_id,
                        scan_id=scan_id,
                        vuln_type=vuln_type,
                        config=self._config,
                        redis_client=self._redis_client,
                    )
                    oast_payload_url = payload.url
                    logger.info(
                        "Generated OAST payload for blind %s vulnerability: %s",
                        vuln_type, oast_payload_url
                    )
                except Exception as exc:
                    logger.warning(
                        "Failed to generate OAST payload for %s: %s",
                        cve_id, exc
                    )
                    # Continue without OAST payload
        
        if validation_error:
            # Correction prompt (EC5)
            prompt = PromptBuilder.build_correction_prompt(
                cve_id=cve_id,
                original_yaml=description,  # In correction mode, description = original YAML
                validation_error=validation_error,
                max_length=self._max_prompt_length,
            )
            logger.info(
                "Generating corrected template for %s (error: %s)",
                cve_id, validation_error[:100]
            )
        else:
            prompt = PromptBuilder.build_generation_prompt(
                cve_id=cve_id,
                description=description,
                poc_links=poc_links,
                oast_payload_url=oast_payload_url,
                max_length=self._max_prompt_length,
            )
            logger.info("Generating initial template for %s", cve_id)

        # Retry loop with exponential backoff
        for attempt in range(1, self._max_retries + 1):
            logger.info(
                "AI generation attempt %d/%d for %s",
                attempt, self._max_retries, cve_id
            )

            raw_response = self._call_ai(prompt)

            if raw_response is None:
                # EC3: AI unavailable
                logger.warning(
                    "AI unavailable on attempt %d/%d for %s",
                    attempt, self._max_retries, cve_id
                )
                if attempt < self._max_retries:
                    backoff = self._backoff_base ** attempt
                    logger.info("Backing off for %ds before retry", backoff)
                    time.sleep(backoff)
                continue

            try:
                yaml_template = extract_yaml_from_response(raw_response)
                logger.info(
                    "✅ Template generated for %s on attempt %d",
                    cve_id, attempt
                )
                return yaml_template, True
            except ValueError as exc:
                # EC4: Malformed YAML
                logger.warning(
                    "Malformed YAML on attempt %d/%d for %s: %s",
                    attempt, self._max_retries, cve_id, exc
                )
                # Update prompt to include error feedback for next attempt
                prompt = PromptBuilder.build_correction_prompt(
                    cve_id=cve_id,
                    original_yaml=raw_response[:2000],
                    validation_error=str(exc),
                    max_length=self._max_prompt_length,
                )
                if attempt < self._max_retries:
                    backoff = self._backoff_base ** attempt
                    time.sleep(backoff)

        # All retries exhausted — fallback (EC3)
        logger.warning(
            "All %d AI attempts exhausted for %s; using fallback template",
            self._max_retries, cve_id
        )
        self._stats["fallbacks_used"] += 1
        fallback = generate_fallback_template(cve_id, description)
        return fallback, False

    def process_task(self, task: dict) -> dict:
        """
        Process a single CVE task: generate template and return result.

        Args:
            task: Dict with cve_id, description, poc_links, etc.

        Returns:
            Result dict with template, status, and metadata.
        """
        cve_id = task.get("cve_id", "UNKNOWN")
        description = task.get("description", "")
        poc_links = task.get("poc_links", [])

        self._stats["tasks_consumed"] += 1
        self._set_status(cve_id, "GENERATING", "AI template generation started")

        logger.info(
            "Processing CVE task: %s (description length: %d, poc_links: %d)",
            cve_id, len(description), len(poc_links)
        )

        template_yaml, is_ai_generated = self.generate_template(
            cve_id=cve_id,
            description=description,
            poc_links=poc_links,
        )

        if is_ai_generated:
            self._stats["templates_generated"] += 1
            self._set_status(cve_id, "GENERATED",
                            "Template generated by AI")
        else:
            self._set_status(cve_id, "FALLBACK",
                            "Fallback template (requires manual review)")
            self._store_for_manual_review(
                cve_id, template_yaml,
                "AI generation failed; fallback template used"
            )

        return {
            "cve_id": cve_id,
            "template_yaml": template_yaml,
            "is_ai_generated": is_ai_generated,
            "task": task,
            "status": "GENERATED" if is_ai_generated else "FALLBACK",
        }

    def run_continuous(self):
        """
        Run the generator in a continuous loop, consuming from the queue.
        """
        logger.info("Starting continuous template generator")
        self._running = True

        while self._running:
            try:
                task = self._consume_task(timeout=5)
                if task is None:
                    continue

                result = self.process_task(task)

                # The result needs to be passed to the validator
                # We'll push it to a validation queue
                if self._redis_client:
                    try:
                        self._redis_client.lpush(
                            "queue:nuclei_sniper:validate",
                            json.dumps(result)
                        )
                    except redis.RedisError as exc:
                        logger.error(
                            "Failed to push to validation queue: %s", exc
                        )

            except Exception as exc:
                logger.error("Unhandled error in generator loop: %s", exc,
                             exc_info=True)
                time.sleep(5)

        logger.info("Template generator stopped. Stats: %s", self._stats)

    def stop(self):
        """Signal the generator to stop."""
        logger.info("Stop signal received for template generator")
        self._running = False


# ---------------------------------------------------------------------------
# Standalone execution
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="Nuclei Sniper Template Generator"
    )
    parser.add_argument("--redis-host", default="localhost")
    parser.add_argument("--redis-port", type=int, default=6379)
    parser.add_argument("--redis-db", type=int, default=0)
    parser.add_argument("--config", default=None)
    parser.add_argument("--test-cve", type=str, default=None,
                        help="Test generation for a specific CVE ID")
    args = parser.parse_args()

    r = redis.Redis(host=args.redis_host, port=args.redis_port,
                    db=args.redis_db, decode_responses=True)

    # Try to import real AI router
    try:
        from modules.ai_routing.router import AIRouter as RealRouter
        ai = RealRouter()
    except ImportError:
        logger.warning("AI Router not available; will use fallback templates")
        ai = None

    gen = TemplateGenerator(redis_client=r, ai_router=ai, config_path=args.config)

    if args.test_cve:
        result = gen.process_task({
            "cve_id": args.test_cve,
            "description": (
                f"Test CVE: {args.test_cve}. "
                "This is a test vulnerability for template generation."
            ),
            "poc_links": [],
        })
        print(f"\n--- Generated Template for {args.test_cve} ---")
        print(result["template_yaml"])
        print(f"\nAI Generated: {result['is_ai_generated']}")
    else:
        try:
            gen.run_continuous()
        except KeyboardInterrupt:
            gen.stop()
