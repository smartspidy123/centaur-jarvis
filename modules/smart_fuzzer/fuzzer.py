"""
Smart Fuzzer — Main state machine and task processing loop.

This is the core orchestration file that:
    1. Consumes tasks from Redis queue `queue:smart_fuzzer` via BLPOP.
    2. For each parameter × vuln_type combination:
       a. Generates initial payloads (AI or fallback).
       b. Executes payloads via the rate-limited executor.
       c. Analyzes responses for vulnerability indicators.
       d. On WAF blocks, mutates payloads with AI and retries.
       e. Optionally verifies potential findings with a second AI call.
    3. Pushes structured TaskResult to `results:incoming`.

State Machine per parameter/vuln_type:
    GENERATE → EXECUTE → ANALYZE → {MUTATE → EXECUTE (loop)} → VERIFY → REPORT

CRITICAL ARCHITECTURE RULE compliance:
    - 360-degree edge-case handling (see edge case table in config.yaml comments).
    - No silent failures — every error is logged and handled.
    - Plug-and-play: swap AI router, HTTP client, or detection logic independently.
    - Comprehensive telemetry via shared.logger.
"""

import json
import time
import uuid
import traceback
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field, asdict
from pathlib import Path
from datetime import datetime, timezone
from dataclasses import asdict

import yaml

from shared.logger import get_logger

logger = get_logger("smart_fuzzer.fuzzer")

# ---------------------------------------------------------------------------
# Redis import with graceful degradation
# ---------------------------------------------------------------------------
_REDIS_AVAILABLE = True
try:
    import redis
except ImportError:
    _REDIS_AVAILABLE = False
    logger.error("Redis library not available — SmartFuzzer cannot operate.")

# ---------------------------------------------------------------------------
# Internal module imports
# ---------------------------------------------------------------------------
from modules.smart_fuzzer.payload_generator import PayloadGenerator, NoAIAvailableError
from modules.smart_fuzzer.executor import FuzzExecutor, FuzzResponse

# ---------------------------------------------------------------------------
# Try importing shared schemas
# ---------------------------------------------------------------------------
_SCHEMAS_AVAILABLE = True
try:
    from shared.schemas import Task, TaskResult
except ImportError:
    _SCHEMAS_AVAILABLE = False
    logger.warning("shared.schemas not available — using internal dataclasses.")


# ---------------------------------------------------------------------------
# Internal data structures
# ---------------------------------------------------------------------------
@dataclass
class Finding:
    """A single potential or confirmed vulnerability finding."""
    parameter: str
    vuln_type: str
    payload: str
    evidence: str
    confidence: float  # 0.0 – 1.0
    verified: bool = False
    status_code: int = 0
    response_snippet: str = ""
    iteration: int = 0  # Which mutation cycle produced this


@dataclass
class FuzzTaskResult:
    """Complete result for a fuzzing task."""
    task_id: str
    target: str
    status: str = "completed"  # completed | failed | partial
    findings: List[Dict[str, Any]] = field(default_factory=list)
    stats: Dict[str, Any] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)
    started_at: str = ""
    completed_at: str = ""


# ---------------------------------------------------------------------------
# Configuration loader
# ---------------------------------------------------------------------------
def _load_config() -> dict:
    config_path = Path(__file__).parent / "config.yaml"
    if not config_path.exists():
        logger.error("config.yaml not found at %s", config_path)
        return {}
    with open(config_path, "r") as f:
        return yaml.safe_load(f) or {}


class SmartFuzzer:
    """
    Main Smart Fuzzer class — task consumer and fuzzing state machine.

    Usage:
        fuzzer = SmartFuzzer(redis_url="redis://localhost:6379/0")
        fuzzer.run()  # Blocking loop — consumes from queue:smart_fuzzer
    """

    def __init__(
        self,
        redis_url: str = "redis://localhost:6379/0",
        config_override: Optional[Dict[str, Any]] = None,
    ):
        # Load configuration
        self._config = _load_config()
        if config_override:
            self._deep_merge(self._config, config_override)

        # Redis config
        self._redis_config = self._config.get("redis", {})
        self._task_queue = self._redis_config.get("task_queue", "queue:smart_fuzzer")
        self._result_queue = self._redis_config.get("result_queue", "results:incoming")
        self._status_prefix = self._redis_config.get("status_prefix", "task:status:")
        self._blpop_timeout = self._redis_config.get("blpop_timeout", 5)
        self._reconnect_max = self._redis_config.get("reconnect_max_retries", 10)
        self._reconnect_delay = self._redis_config.get("reconnect_delay", 2.0)
        self._memory_buffer_max = self._redis_config.get("memory_buffer_max", 50)

        # Fuzzing config
        self._max_iterations = self._config.get("max_iterations", 3)
        self._verify_with_ai = self._config.get("verify_with_ai", True)
        self._max_verify_attempts = self._config.get("max_verification_attempts", 1)
        self._initial_count = self._config.get("initial_payloads_per_type", 5)

        # Detection config
        self._detection = self._config.get("detection", {})

        # Memory buffer for results when Redis is down
        self._result_buffer: List[Dict[str, Any]] = []          # <-- move here

        # Initialize Redis
        self._redis_url = redis_url
        self._redis: Optional[redis.Redis] = None
        self._connect_redis()

        # Initialize sub-modules
        self._generator = PayloadGenerator()
        self._executor = FuzzExecutor(config=self._config)
        # Running flag
        self._running = False

        logger.info(
            "SmartFuzzer initialized | queue=%s | max_iterations=%d | verify=%s",
            self._task_queue,
            self._max_iterations,
            self._verify_with_ai,
        )

    # ==================================================================
    # REDIS CONNECTION MANAGEMENT
    # ==================================================================
    def _connect_redis(self):
        """Establish Redis connection with retry logic."""
        if not _REDIS_AVAILABLE:
            logger.error("Redis library not installed. SmartFuzzer cannot start.")
            return

        for attempt in range(1, self._reconnect_max + 1):
            try:
                self._redis = redis.Redis.from_url(
                    self._redis_url,
                    decode_responses=True,
                    socket_connect_timeout=5,
                    socket_timeout=10,
                    retry_on_timeout=True,
                )
                self._redis.ping()
                logger.info("Redis connected (attempt %d).", attempt)

                # Flush any buffered results
                self._flush_result_buffer()
                return

            except Exception as e:
                logger.warning(
                    "Redis connection attempt %d/%d failed: %s",
                    attempt,
                    self._reconnect_max,
                    e,
                )
                if attempt < self._reconnect_max:
                    time.sleep(self._reconnect_delay)

        logger.error(
            "Failed to connect to Redis after %d attempts. Fuzzer will not process tasks.",
            self._reconnect_max,
        )

    def _ensure_redis(self) -> bool:
        """Check Redis connectivity; attempt reconnect if needed."""
        if not self._redis:
            self._connect_redis()
            return self._redis is not None

        try:
            self._redis.ping()
            return True
        except Exception:
            logger.warning("Redis connection lost — attempting reconnect.")
            self._connect_redis()
            return self._redis is not None

    # ==================================================================
    # MAIN LOOP
    # ==================================================================
    def run(self):
        """
        Blocking main loop: continuously consume tasks from Redis queue.
        Call this from the module's entry point or orchestrator.
        """
        self._running = True
        logger.info("SmartFuzzer main loop starting — listening on '%s'.", self._task_queue)

        while self._running:
            try:
                if not self._ensure_redis():
                    logger.error("Redis unavailable — sleeping %ds.", self._reconnect_delay)
                    time.sleep(self._reconnect_delay)
                    continue

                # BLPOP with timeout (non-infinite block to allow clean shutdown)
                result = self._redis.blpop(self._task_queue, timeout=self._blpop_timeout)
                if result is None:
                    # Timeout — no task available, loop back
                    continue

                _, task_json = result
                self._process_task_wrapper(task_json)

            except KeyboardInterrupt:
                logger.info("SmartFuzzer received keyboard interrupt — shutting down.")
                self._running = False
            except redis.ConnectionError as e:
                logger.error("Redis connection error in main loop: %s", e)
                time.sleep(self._reconnect_delay)
            except Exception as e:
                logger.critical(
                    "Unexpected error in main loop: %s\n%s",
                    e,
                    traceback.format_exc(),
                )
                time.sleep(1)  # Prevent tight error loop

        logger.info("SmartFuzzer main loop stopped.")

    def stop(self):
        """Signal the main loop to stop gracefully."""
        self._running = False
        logger.info("SmartFuzzer stop requested.")

    def process_single_task(self, task_dict: Dict[str, Any]) -> Dict[str, Any]:
        """
        Process a single task synchronously (useful for testing).

        Args:
            task_dict: Task dictionary (same format as queue messages).

        Returns:
            Result dictionary.
        """
        return self._process_task(task_dict)

    # ==================================================================
    # TASK PROCESSING
    # ==================================================================
    def _process_task_wrapper(self, task_json: str):
        """Parse JSON, validate, and process a task. Handles all errors."""
        task_id = "unknown"
        try:
            task_dict = json.loads(task_json)
            task_id = task_dict.get("task_id", f"auto-{uuid.uuid4().hex[:8]}")
            logger.info("Received task '%s' from queue.", task_id)

            # No status update here – removed

            result = self._process_task(task_dict)
            print("DEBUG: Result JSON:", json.dumps(result, indent=2))

            # Push result
            self._push_result(result)

            logger.info(
                "Task '%s' completed | findings=%d | status=%s",
                task_id,
                len(result.get("findings", [])),
                result.get("status"),
            )

        except json.JSONDecodeError as e:
            logger.error("Invalid JSON in task: %s | Error: %s", task_json[:200], e)
            self._push_error_result(task_id, f"Invalid JSON: {e}")

        except Exception as e:
            logger.error(
                "Task '%s' failed with exception: %s\n%s",
                task_id,
                e,
                traceback.format_exc(),
            )
            self._push_error_result(task_id, f"Unhandled exception: {e}")
            # No status update here – removed

    def _process_task(self, task_dict: Dict[str, Any]) -> Dict[str, Any]:
        """
        Core task processing logic — the fuzzing state machine.

        For each parameter × vuln_type:
            GENERATE → EXECUTE → ANALYZE → {MUTATE → EXECUTE → ANALYZE}* → VERIFY → REPORT
        """
        started_at = datetime.now(timezone.utc).isoformat()

        # ------- VALIDATE TASK -------
        validation_error = self._validate_task(task_dict)
        if validation_error:
            return {
                "task_id": task_dict.get("task_id", "unknown"),
                "target": task_dict.get("target", ""),
                "status": "failed",
                "findings": [],
                "errors": [validation_error],
                "stats": {},
                "started_at": started_at,
                "completed_at": datetime.now(timezone.utc).isoformat(),
            }

        # ------- EXTRACT FIELDS -------
        task_id = task_dict["task_id"]
        target = task_dict["target"]
        method = task_dict.get("method", "GET").upper()
        params = task_dict.get("params", {})
        param_type_hints = task_dict.get("param_type_hints", {})
        vuln_types = task_dict.get("vuln_types", ["xss", "sqli"])
        max_iterations = task_dict.get("max_iterations", self._max_iterations)

        # Context for AI prompt building
        context = {
            "target": target,
            "method": method,
            "all_params": params,
        }

        # ------- STATS TRACKING -------
        stats = {
            "total_requests": 0,
            "total_payloads_generated": 0,
            "total_mutations": 0,
            "total_waf_blocks": 0,
            "total_timeouts": 0,
            "total_errors": 0,
            "ai_calls": 0,
            "parameters_tested": 0,
            "vuln_types_tested": len(vuln_types),
        }

        all_findings: List[Finding] = []
        errors: List[str] = []

        # Reset dedup cache for this task
        self._generator.reset_dedup_cache()

        # ------- MAIN FUZZING LOOP -------
        for param_name, param_value in params.items():
            param_type = param_type_hints.get(param_name, "string")
            stats["parameters_tested"] += 1

            logger.info(
                "Fuzzing param='%s' (type=%s) | vuln_types=%s | target=%s",
                param_name,
                param_type,
                vuln_types,
                target,
            )

            # Generate initial payloads for ALL vuln types at once (efficiency)
            try:
                payloads_by_type = self._generator.generate_initial(
                    parameter_name=param_name,
                    param_type=param_type,
                    vuln_types=vuln_types,
                    context=context,
                )
                for vt, plist in payloads_by_type.items():
                    stats["total_payloads_generated"] += len(plist)
                    stats["ai_calls"] += 1
            except Exception as e:
                logger.error("Payload generation failed for param='%s': %s", param_name, e)
                errors.append(f"Generation failed for {param_name}: {e}")
                continue

            # For each vuln type, execute payloads
            for vuln_type in vuln_types:
                vt_lower = vuln_type.lower().strip()
                initial_payloads = payloads_by_type.get(vt_lower, [])

                if not initial_payloads:
                    logger.warning(
                        "No payloads available for param='%s', vuln='%s' — skipping.",
                        param_name,
                        vt_lower,
                    )
                    continue

                logger.debug(
                    "Testing %d payloads for param='%s', vuln='%s'.",
                    len(initial_payloads),
                    param_name,
                    vt_lower,
                )

                for payload in initial_payloads:
                    self._execute_payload_cycle(
                        target=target,
                        method=method,
                        params=params,
                        param_name=param_name,
                        payload=payload,
                        vuln_type=vt_lower,
                        max_iterations=max_iterations,
                        stats=stats,
                        findings=all_findings,
                        errors=errors,
                        context=context,
                    )

        # ------- OPTIONAL VERIFICATION -------
        if self._verify_with_ai and all_findings:
            self._verify_findings(all_findings, stats)
        print(f"DEBUG: After verification, all_findings has {len(all_findings)} items.")

        # ------- BUILD RESULT -------
        completed_at = datetime.now(timezone.utc).isoformat()

        # Determine overall status
        status = "COMPLETED"
        if errors and not all_findings:
            status = "completed_with_errors"
        if len(errors) > len(params) * len(vuln_types):
            status = "partial"
        
        print(f"DEBUG: Before building result, all_findings has {len(all_findings)} items.")
        findings_list = [asdict(f) for f in all_findings]
        print(f"DEBUG: findings_list has {len(findings_list)} items.")

        result = {
            "task_id": task_id,
            "module": "smart_fuzzer",
            "target": target,
            "status": status,
            "data": {
                "findings": [asdict(f) for f in all_findings],
                "stats": stats,
            },
            "errors": errors[:50],
            "started_at": started_at,
            "completed_at": completed_at,
        }

        return result

    # ==================================================================
    # PAYLOAD EXECUTION CYCLE (with mutation loop)
    # ==================================================================
    def _execute_payload_cycle(
        self,
        target: str,
        method: str,
        params: Dict[str, str],
        param_name: str,
        payload: str,
        vuln_type: str,
        max_iterations: int,
        stats: Dict[str, int],
        findings: List[Finding],
        errors: List[str],
        context: Dict[str, Any],
    ):
        """
        Execute a single payload with mutation retry loop.

        State machine:
            EXECUTE → ANALYZE → if WAF, MUTATE → EXECUTE → ANALYZE (up to max_iterations)
        """
        current_payload = payload
        iteration = 0

        while iteration <= max_iterations:
            # Build request params (inject payload into target parameter)
            fuzz_params = self._inject_payload(
                params=params,
                param_name=param_name,
                payload=current_payload,
                method=method,
            )

            # Determine how to send (query params vs body)
            send_kwargs = self._build_request_kwargs(
                target=target,
                method=method,
                fuzz_params=fuzz_params,
                param_name=param_name,
            )

            # EXECUTE
            response = self._executor.send(**send_kwargs)
            stats["total_requests"] += 1

            # ANALYZE
            if response.is_timeout:
                stats["total_timeouts"] += 1
                logger.debug(
                    "Timeout for payload '%s' on param='%s' — skipping.",
                    current_payload[:50],
                    param_name,
                )
                return  # Skip this payload entirely

            if response.is_connection_error:
                stats["total_errors"] += 1
                logger.debug(
                    "Connection error for payload '%s' on param='%s' — skipping.",
                    current_payload[:50],
                    param_name,
                )
                return

            if response.is_waf_block:
                stats["total_waf_blocks"] += 1
                logger.debug(
                    "WAF block (HTTP %d) for payload on param='%s' (iteration %d/%d).",
                    response.status_code,
                    param_name,
                    iteration,
                    max_iterations,
                )

                # If we can still mutate, do so
                if iteration < max_iterations:
                    # Respect Retry-After before mutation attempt
                    if response.retry_after and response.retry_after > 0:
                        wait_time = min(response.retry_after, 30.0)
                        logger.debug("Respecting Retry-After: %.1fs", wait_time)
                        time.sleep(wait_time)

                    mutated = self._generator.mutate_on_failure(
                        original_payload=current_payload,
                        server_response=response.body_snippet,
                        vuln_type=vuln_type,
                    )
                    stats["ai_calls"] += 1
                    stats["total_mutations"] += 1

                    if mutated:
                        current_payload = mutated
                        iteration += 1
                        continue
                    else:
                        logger.debug(
                            "Mutation returned None — giving up on this payload for param='%s'.",
                            param_name,
                        )
                        return
                else:
                    logger.debug(
                        "Max iterations reached for WAF-blocked payload on param='%s'.",
                        param_name,
                    )
                    return

            # Non-WAF response — check for vulnerability indicators
            is_suspicious, evidence = self._detect_vulnerability(
                payload=current_payload,
                response=response,
                vuln_type=vuln_type,
            )

            if is_suspicious:
                finding = Finding(
                    parameter=param_name,
                    vuln_type=vuln_type,
                    payload=current_payload,
                    evidence=evidence,
                    confidence=0.7,  # Pre-verification confidence
                    verified=False,
                    status_code=response.status_code,
                    response_snippet=response.body_snippet[:500],
                    iteration=iteration,
                )
                findings.append(finding)
                logger.info(
                    "⚡ POTENTIAL FINDING: %s on param='%s' | payload='%s' | evidence='%s'",
                    vuln_type.upper(),
                    param_name,
                    current_payload[:60],
                    evidence[:100],
                )

            # No WAF block and we've analyzed — done with this payload
            return

    # ==================================================================
    # VULNERABILITY DETECTION
    # ==================================================================
    def _detect_vulnerability(
        self,
        payload: str,
        response: FuzzResponse,
        vuln_type: str,
    ) -> tuple:
        """
        Analyze response for vulnerability indicators.

        Returns:
            (is_suspicious: bool, evidence: str)
        """
        body = response.body or ""
        body_lower = body.lower()
        status = response.status_code
        evidence_parts = []

        # --- Status-based heuristics ---
        if status == 500:
            evidence_parts.append(f"Server error (HTTP {status})")

        # --- Vuln-type-specific detection ---
        indicator_key = f"{vuln_type}_indicators"
        indicators = self._detection.get(indicator_key, [])

        for indicator in indicators:
            if indicator == "__PAYLOAD_REFLECTED__":
                # Special: check if exact payload is reflected in response
                if payload in body:
                    evidence_parts.append(f"Payload reflected verbatim in response")
                elif payload.lower() in body_lower:
                    evidence_parts.append(f"Payload reflected (case-insensitive) in response")
            else:
                if indicator.lower() in body_lower:
                    evidence_parts.append(f"Indicator matched: '{indicator}'")

        # --- Generic error-based detection ---
        generic_error_patterns = [
            "traceback", "exception", "stack trace", "fatal error",
            "warning:", "parse error", "syntax error",
        ]
        for pat in generic_error_patterns:
            if pat in body_lower and status >= 400:
                evidence_parts.append(f"Error pattern detected: '{pat}'")
                break  # One generic error indicator is enough

        is_suspicious = len(evidence_parts) > 0
        evidence = "; ".join(evidence_parts) if evidence_parts else ""

        return is_suspicious, evidence

    # ==================================================================
    # AI VERIFICATION
    # ==================================================================
    def _verify_findings(self, findings: List[Finding], stats: Dict[str, int]):
        """
        Verify potential findings with a second AI call.
        Only ONE verification attempt per finding (hard cap).
        """
        logger.info("Verifying %d potential findings with AI...", len(findings))

        verified_count = 0
        removed_count = 0

        for finding in findings:
            if finding.verified:
                continue  # Already verified (shouldn't happen, but defensive)

            try:
                prompt = self._generator._build_verification_prompt(
                    payload=finding.payload,
                    response_snippet=finding.response_snippet,
                    vuln_type=finding.vuln_type,
                )

                ai_response = self._generator._call_ai(
                    prompt=prompt,
                    complexity="MEDIUM",
                    temperature=0.3,  # Low temperature for analytical response
                )
                stats["ai_calls"] += 1

                verification = self._generator.parse_verification_response(ai_response)

                if verification.get("is_vulnerable", False):
                    finding.verified = True
                    finding.confidence = max(
                        finding.confidence,
                        verification.get("confidence", 0.7),
                    )
                    finding.evidence += f" | AI Verification: {verification.get('evidence', 'Confirmed.')}"
                    verified_count += 1
                    logger.info(
                        "✅ VERIFIED: %s on param='%s' (confidence=%.2f)",
                        finding.vuln_type.upper(),
                        finding.parameter,
                        finding.confidence,
                    )
                else:
                    finding.confidence *= 0.3  # Drastically reduce confidence
                    finding.evidence += f" | AI Verification: NOT confirmed — {verification.get('evidence', 'Likely false positive.')}"
                    removed_count += 1
                    logger.info(
                        "❌ NOT VERIFIED: %s on param='%s' — likely false positive.",
                        finding.vuln_type.upper(),
                        finding.parameter,
                    )

            except NoAIAvailableError:
                logger.warning(
                    "AI unavailable for verification of %s on param='%s' — keeping as unverified.",
                    finding.vuln_type,
                    finding.parameter,
                )
                finding.evidence += " | AI verification unavailable — unverified."

            except Exception as e:
                logger.error(
                    "Verification failed for finding on param='%s': %s",
                    finding.parameter,
                    e,
                )
                finding.evidence += f" | Verification error: {e}"

        logger.info(
            "Verification complete: %d verified, %d not confirmed, %d total.",
            verified_count,
            removed_count,
            len(findings),
        )

    # ==================================================================
    # HELPER METHODS
    # ==================================================================
    def _validate_task(self, task_dict: Dict[str, Any]) -> Optional[str]:
        """Validate required task fields. Returns error message or None."""
        required = ["task_id", "target"]
        for field_name in required:
            if field_name not in task_dict or not task_dict[field_name]:
                return f"Missing required field: '{field_name}'"

        target = task_dict["target"]
        if not target.startswith(("http://", "https://")):
            return f"Invalid target URL (must start with http/https): {target}"

        params = task_dict.get("params", {})
        if not params or not isinstance(params, dict):
            return "Task 'params' must be a non-empty dictionary of parameters to fuzz."

        vuln_types = task_dict.get("vuln_types", [])
        if not vuln_types or not isinstance(vuln_types, list):
            return "Task 'vuln_types' must be a non-empty list."

        return None  # Valid

    def _inject_payload(
        self,
        params: Dict[str, str],
        param_name: str,
        payload: str,
        method: str,
    ) -> Dict[str, str]:
        """Create a copy of params with the target parameter replaced by the payload."""
        fuzz_params = dict(params)
        fuzz_params[param_name] = payload
        return fuzz_params

    def _build_request_kwargs(
        self,
        target: str,
        method: str,
        fuzz_params: Dict[str, str],
        param_name: str,
    ) -> Dict[str, Any]:
        """Build kwargs for executor.send() based on HTTP method."""
        kwargs: Dict[str, Any] = {
            "url": target,
            "method": method,
        }

        if method in ("GET", "HEAD", "DELETE", "OPTIONS"):
            kwargs["params"] = fuzz_params
        elif method in ("POST", "PUT", "PATCH"):
            # Determine if body should be JSON or form data
            # Simple heuristic: if any value looks like JSON, use json; else form data
            is_json = any(
                isinstance(v, (dict, list))
                for v in fuzz_params.values()
            )
            if is_json:
                kwargs["json_body"] = fuzz_params
            else:
                kwargs["data"] = fuzz_params
        else:
            # Unknown method — default to query params
            kwargs["params"] = fuzz_params

        return kwargs

    def _push_result(self, result: Dict[str, Any]):
        """Push result to Redis results queue, with in-memory fallback."""
        result_json = json.dumps(result, default=str)

        try:
            if self._redis:
                self._redis.rpush(self._result_queue, result_json)
                logger.debug(
                    "Result pushed to '%s' for task '%s'.",
                    self._result_queue,
                    result.get("task_id"),
                )
                # Try flushing buffer too
                self._flush_result_buffer()
                return
        except Exception as e:
            logger.warning("Failed to push result to Redis: %s — buffering in memory.", e)

        # Buffer in memory
        if len(self._result_buffer) < self._memory_buffer_max:
            self._result_buffer.append(result)
            logger.info(
                "Result buffered in memory (%d/%d).",
                len(self._result_buffer),
                self._memory_buffer_max,
            )
        else:
            logger.error(
                "Memory buffer full (%d items) — DROPPING result for task '%s'!",
                self._memory_buffer_max,
                result.get("task_id"),
            )

    def _push_error_result(self, task_id: str, error_msg: str):
        """Push an error result for a failed task."""
        result = {
            "task_id": task_id,
            "module": "smart_fuzzer",
            "target": "",
            "status": "failed",
            "data": {
                "findings": [],
                "stats": {},
            },
            "errors": [error_msg],
            "started_at": datetime.now(timezone.utc).isoformat(),
            "completed_at": datetime.now(timezone.utc).isoformat(),
        }
        self._push_result(result)

    def _flush_result_buffer(self):
        """Attempt to flush buffered results to Redis."""
        if not self._result_buffer or not self._redis:
            return

        flushed = 0
        while self._result_buffer:
            try:
                result = self._result_buffer[0]
                self._redis.rpush(self._result_queue, json.dumps(result, default=str))
                self._result_buffer.pop(0)
                flushed += 1
            except Exception as e:
                logger.debug("Buffer flush failed: %s — %d items remaining.", e, len(self._result_buffer))
                break

        if flushed:
            logger.info("Flushed %d buffered results to Redis.", flushed)

    @staticmethod
    def _deep_merge(base: dict, override: dict):
        """Recursively merge override into base dict."""
        for k, v in override.items():
            if k in base and isinstance(base[k], dict) and isinstance(v, dict):
                SmartFuzzer._deep_merge(base[k], v)
            else:
                base[k] = v


# ==================================================================
# MODULE ENTRY POINT (for standalone execution)
# ==================================================================
def main():
    """Entry point for running the SmartFuzzer as a standalone process."""
    import os

    redis_url = os.environ.get("REDIS_URL", "redis://localhost:6379/0")
    logger.info("Starting SmartFuzzer with REDIS_URL=%s", redis_url)

    fuzzer = SmartFuzzer(redis_url=redis_url)
    fuzzer.run()


if __name__ == "__main__":
    main()
