"""
Template Validator
==================
Validates generated Nuclei templates using `nuclei -validate` and
implements a self-healing feedback loop with the generator.

Edge Cases Handled:
- EC4:  Malformed YAML → retry with error feedback to AI
- EC5:  Nuclei validation fails → parse error, send to generator for correction
- EC6:  Nuclei binary not found → log critical, disable validation, fallback
- EC9:  Redis connection lost → graceful handling
"""

import json
import os
import shutil
import subprocess
import tempfile
import time
from typing import Optional, Tuple

import redis
import yaml as pyyaml

try:
    from shared.logger import get_logger
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

logger = get_logger("nuclei_sniper.validator")


# ---------------------------------------------------------------------------
# Configuration loader
# ---------------------------------------------------------------------------
def _load_config(config_path: str = None) -> dict:
    """Load module configuration."""
    if config_path is None:
        config_path = os.path.join(os.path.dirname(__file__), "config.yaml")
    try:
        with open(config_path, "r") as f:
            return pyyaml.safe_load(f) or {}
    except (FileNotFoundError, pyyaml.YAMLError) as exc:
        logger.warning("Config load error: %s; using defaults", exc)
        return {}


# ---------------------------------------------------------------------------
# Nuclei Binary Checker
# ---------------------------------------------------------------------------
def check_nuclei_binary(nuclei_path: str) -> Tuple[bool, str]:
    """
    Verify nuclei binary exists and is executable (EC6).

    Returns:
        Tuple of (is_available, version_or_error_message)
    """
    # Check explicit path first
    if os.path.isfile(nuclei_path) and os.access(nuclei_path, os.X_OK):
        try:
            result = subprocess.run(
                [nuclei_path, "-version"],
                capture_output=True, text=True, timeout=10
            )
            version = result.stdout.strip() or result.stderr.strip()
            logger.info("Nuclei binary found at %s: %s", nuclei_path, version)
            return True, version
        except (subprocess.SubprocessError, OSError) as exc:
            logger.warning("Nuclei at %s failed version check: %s",
                           nuclei_path, exc)

    # Fallback: check PATH
    nuclei_in_path = shutil.which("nuclei")
    if nuclei_in_path:
        try:
            result = subprocess.run(
                [nuclei_in_path, "-version"],
                capture_output=True, text=True, timeout=10
            )
            version = result.stdout.strip() or result.stderr.strip()
            logger.info("Nuclei binary found in PATH: %s (%s)",
                        nuclei_in_path, version)
            return True, version
        except (subprocess.SubprocessError, OSError) as exc:
            logger.warning("Nuclei in PATH failed: %s", exc)

    error_msg = (
        f"Nuclei binary not found at '{nuclei_path}' or in PATH. "
        "Validation will be disabled."
    )
    logger.critical(error_msg)
    return False, error_msg


# ---------------------------------------------------------------------------
# Validation Result
# ---------------------------------------------------------------------------
class ValidationResult:
    """Encapsulates the result of a template validation."""

    def __init__(self, is_valid: bool, template_yaml: str,
                 errors: list = None, stdout: str = "", stderr: str = "",
                 return_code: int = -1):
        self.is_valid = is_valid
        self.template_yaml = template_yaml
        self.errors = errors or []
        self.stdout = stdout
        self.stderr = stderr
        self.return_code = return_code

    def error_summary(self) -> str:
        """Return a concise error summary for AI feedback."""
        if self.is_valid:
            return ""
        parts = []
        if self.errors:
            parts.extend(self.errors[:3])  # Cap at 3 errors
        if self.stderr:
            # Extract relevant error lines
            for line in self.stderr.split("\n"):
                line = line.strip()
                if line and ("error" in line.lower() or "invalid" in line.lower()
                             or "failed" in line.lower()):
                    parts.append(line)
                    if len(parts) >= 5:
                        break
        return "; ".join(parts) if parts else f"Validation failed (rc={self.return_code})"

    def to_dict(self) -> dict:
        return {
            "is_valid": self.is_valid,
            "errors": self.errors,
            "error_summary": self.error_summary(),
            "return_code": self.return_code,
        }


# ---------------------------------------------------------------------------
# Template Validator
# ---------------------------------------------------------------------------
class TemplateValidator:
    """
    Validates Nuclei YAML templates and implements self-healing via
    AI feedback loop.
    """

    def __init__(self, redis_client: redis.Redis = None,
                 generator=None, config_path: str = None):
        self._config = _load_config(config_path)
        self._redis_client = redis_client
        self._generator = generator  # Reference to TemplateGenerator for corrections

        val_config = self._config.get("validation", {})
        self._nuclei_path = val_config.get("nuclei_path", "/usr/local/bin/nuclei")
        self._max_retries = val_config.get("max_retries", 3)
        self._validation_timeout = val_config.get("validation_timeout", 60)
        self._temp_dir = val_config.get("temp_dir",
                                         "/tmp/nuclei_sniper_templates")

        redis_config = self._config.get("redis", {})
        self._status_prefix = redis_config.get("status_prefix",
                                                "nuclei_sniper:status:")
        self._manual_review_key = redis_config.get("manual_review_key",
                                                     "nuclei_sniper:manual_review")

        # Check nuclei availability (EC6)
        self._nuclei_available, self._nuclei_info = check_nuclei_binary(
            self._nuclei_path
        )
        if self._nuclei_available:
            # Use the found path
            nuclei_in_path = shutil.which("nuclei")
            if not os.path.isfile(self._nuclei_path):
                if nuclei_in_path:
                    self._nuclei_path = nuclei_in_path

        # Ensure temp directory exists
        os.makedirs(self._temp_dir, exist_ok=True)

        self._running = False
        self._stats = {
            "validations_attempted": 0,
            "validations_passed": 0,
            "validations_failed": 0,
            "corrections_attempted": 0,
            "corrections_succeeded": 0,
            "discarded_templates": 0,
        }

    @property
    def stats(self) -> dict:
        return self._stats.copy()

    @property
    def nuclei_available(self) -> bool:
        return self._nuclei_available

    # ----- Redis helpers -----

    def _set_status(self, cve_id: str, status: str, details: str = ""):
        """Set CVE status in Redis (UPPERCASE enforced)."""
        status = status.upper()
        if not self._redis_client:
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
            logger.error("Redis status error for %s: %s", cve_id, exc)

    def _store_for_manual_review(self, cve_id: str, template_yaml: str,
                                  reason: str):
        """Store template for manual review."""
        if not self._redis_client:
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
            logger.error("Manual review store failed for %s: %s", cve_id, exc)

    # ----- Core validation -----

    def validate_template(self, template_yaml: str) -> ValidationResult:
        """
        Validate a Nuclei YAML template using `nuclei -validate`.

        If nuclei is unavailable (EC6), performs basic YAML syntax check only.
        """
        self._stats["validations_attempted"] += 1

        # Basic YAML syntax check first
        try:
            parsed = pyyaml.safe_load(template_yaml)
            if not isinstance(parsed, dict):
                return ValidationResult(
                    is_valid=False,
                    template_yaml=template_yaml,
                    errors=["Template is not a valid YAML dictionary"],
                )
            if "id" not in parsed:
                return ValidationResult(
                    is_valid=False,
                    template_yaml=template_yaml,
                    errors=["Missing required 'id' field"],
                )
            if "info" not in parsed:
                return ValidationResult(
                    is_valid=False,
                    template_yaml=template_yaml,
                    errors=["Missing required 'info' field"],
                )
        except pyyaml.YAMLError as exc:
            return ValidationResult(
                is_valid=False,
                template_yaml=template_yaml,
                errors=[f"YAML syntax error: {exc}"],
            )

        # EC6: If nuclei binary not available, accept YAML-valid templates
        if not self._nuclei_available:
            logger.warning(
                "Nuclei binary not available; skipping nuclei -validate. "
                "Template passes basic YAML check only."
            )
            self._stats["validations_passed"] += 1
            return ValidationResult(
                is_valid=True,
                template_yaml=template_yaml,
                errors=["WARNING: nuclei binary unavailable; YAML-only validation"],
            )

        # Write template to temp file
        temp_file = None
        try:
            temp_file = tempfile.NamedTemporaryFile(
                mode="w", suffix=".yaml", dir=self._temp_dir,
                delete=False, prefix="nuclei_template_"
            )
            temp_file.write(template_yaml)
            temp_file.flush()
            temp_path = temp_file.name
            temp_file.close()

            # Run nuclei -validate
            logger.debug("Running: %s -validate -t %s",
                         self._nuclei_path, temp_path)
            result = subprocess.run(
                [self._nuclei_path, "-validate", "-t", temp_path],
                capture_output=True,
                text=True,
                timeout=self._validation_timeout,
            )

            stdout = result.stdout.strip()
            stderr = result.stderr.strip()
            rc = result.returncode

            logger.debug("Validation stdout: %s", stdout[:500])
            logger.debug("Validation stderr: %s", stderr[:500])

            # Parse validation result
            # nuclei returns 0 on success, non-zero on failure
            # Output may contain "[INF]" for valid or "[ERR]" for invalid
            errors = []
            is_valid = rc == 0

            # Also check for explicit error indicators in output
            combined_output = f"{stdout}\n{stderr}".lower()
            if "error" in combined_output or "invalid" in combined_output:
                is_valid = False
                for line in (stdout + "\n" + stderr).split("\n"):
                    line = line.strip()
                    if ("error" in line.lower() or "invalid" in line.lower()
                            or "failed" in line.lower()):
                        errors.append(line)

            if "valid" in combined_output and "invalid" not in combined_output:
                # Positive validation message found
                if rc == 0:
                    is_valid = True

            if is_valid:
                self._stats["validations_passed"] += 1
                logger.info("✅ Template validation PASSED")
            else:
                self._stats["validations_failed"] += 1
                logger.warning("❌ Template validation FAILED: %s",
                               "; ".join(errors) if errors else f"rc={rc}")

            return ValidationResult(
                is_valid=is_valid,
                template_yaml=template_yaml,
                errors=errors,
                stdout=stdout,
                stderr=stderr,
                return_code=rc,
            )

        except subprocess.TimeoutExpired:
            self._stats["validations_failed"] += 1
            logger.error("Nuclei validation timed out after %ds",
                         self._validation_timeout)
            return ValidationResult(
                is_valid=False,
                template_yaml=template_yaml,
                errors=[f"Validation timed out after {self._validation_timeout}s"],
            )
        except OSError as exc:
            # EC6: Binary issues at runtime
            self._stats["validations_failed"] += 1
            logger.error("OS error running nuclei: %s", exc)
            self._nuclei_available = False
            return ValidationResult(
                is_valid=False,
                template_yaml=template_yaml,
                errors=[f"OS error: {exc}"],
            )
        finally:
            # Clean up temp file
            if temp_file and os.path.exists(temp_file.name):
                try:
                    os.unlink(temp_file.name)
                except OSError:
                    pass

    def validate_with_correction(self, cve_id: str, template_yaml: str,
                                  task: dict) -> Tuple[Optional[str], bool]:
        """
        Validate a template and attempt AI-powered correction if it fails.

        Implements the self-healing feedback loop (EC5):
        1. Validate template
        2. If invalid, send error back to generator for correction
        3. Repeat up to max_retries times

        Args:
            cve_id: CVE identifier
            template_yaml: The generated YAML template
            task: Original CVE task dict (for re-generation context)

        Returns:
            Tuple of (validated_yaml_or_None, is_valid)
        """
        current_yaml = template_yaml

        for attempt in range(1, self._max_retries + 1):
            logger.info(
                "Validation attempt %d/%d for %s",
                attempt, self._max_retries, cve_id
            )

            self._set_status(
                cve_id, "VALIDATING",
                f"Attempt {attempt}/{self._max_retries}"
            )

            result = self.validate_template(current_yaml)

            if result.is_valid:
                self._set_status(cve_id, "VALIDATED",
                                "Template passed validation")
                logger.info(
                    "✅ Template for %s validated on attempt %d",
                    cve_id, attempt
                )
                return current_yaml, True

            # Validation failed — attempt correction via AI
            error_summary = result.error_summary()
            logger.warning(
                "Validation failed for %s on attempt %d: %s",
                cve_id, attempt, error_summary
            )

            if attempt >= self._max_retries:
                break

            # EC5: Feed error back to generator for correction
            if self._generator is None:
                logger.warning(
                    "No generator available for correction; "
                    "cannot self-heal template for %s", cve_id
                )
                break

            self._stats["corrections_attempted"] += 1
            self._set_status(
                cve_id, "CORRECTING",
                f"AI correction attempt {attempt}"
            )

            # Call generator with the validation error
            corrected_yaml, is_ai = self._generator.generate_template(
                cve_id=cve_id,
                description=current_yaml,  # Pass current YAML as "description"
                poc_links=[],
                validation_error=error_summary,
            )

            if is_ai and corrected_yaml != current_yaml:
                self._stats["corrections_succeeded"] += 1
                current_yaml = corrected_yaml
                logger.info(
                    "AI correction produced updated template for %s", cve_id
                )
            else:
                logger.warning(
                    "AI correction did not produce a different template for %s",
                    cve_id
                )
                # Still try validating the result
                current_yaml = corrected_yaml

        # All retries exhausted
        self._stats["discarded_templates"] += 1
        self._set_status(
            cve_id, "VALIDATION_FAILED",
            f"Failed after {self._max_retries} attempts"
        )

        # Store for manual review
        self._store_for_manual_review(
            cve_id, current_yaml,
            f"Validation failed after {self._max_retries} attempts"
        )

        logger.error(
            "❌ Template for %s failed validation after %d attempts; "
            "stored for manual review", cve_id, self._max_retries
        )
        return None, False

    def process_validation_queue(self):
        """
        Consume items from the validation queue and process them.
        """
        logger.info("Starting validation queue processor")
        self._running = True

        validation_queue = "queue:nuclei_sniper:validate"
        execution_queue = "queue:nuclei_sniper:execute"

        while self._running:
            try:
                if not self._redis_client:
                    logger.error("No Redis client for validator")
                    time.sleep(10)
                    continue

                result = self._redis_client.brpop(
                    validation_queue, timeout=5
                )
                if result is None:
                    continue

                _, item_json = result
                item = json.loads(item_json)

                cve_id = item.get("cve_id", "UNKNOWN")
                template_yaml = item.get("template_yaml", "")
                task = item.get("task", {})

                if not template_yaml:
                    logger.warning("Empty template for %s; skipping", cve_id)
                    continue

                validated_yaml, is_valid = self.validate_with_correction(
                    cve_id=cve_id,
                    template_yaml=template_yaml,
                    task=task,
                )

                if is_valid and validated_yaml:
                    # Push to execution queue
                    exec_item = {
                        "cve_id": cve_id,
                        "template_yaml": validated_yaml,
                        "task": task,
                        "status": "VALIDATED",
                    }
                    try:
                        self._redis_client.lpush(
                            execution_queue, json.dumps(exec_item)
                        )
                        logger.info(
                            "Pushed validated template for %s to execution queue",
                            cve_id
                        )
                    except redis.RedisError as exc:
                        logger.error(
                            "Failed to push %s to execution queue: %s",
                            cve_id, exc
                        )

            except json.JSONDecodeError as exc:
                logger.error("Invalid JSON in validation queue: %s", exc)
            except Exception as exc:
                logger.error(
                    "Unhandled error in validation loop: %s", exc,
                    exc_info=True
                )
                time.sleep(5)

        logger.info("Validation processor stopped. Stats: %s", self._stats)

    def stop(self):
        """Signal the validator to stop."""
        logger.info("Stop signal received for validator")
        self._running = False


# ---------------------------------------------------------------------------
# Standalone execution
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="Nuclei Sniper Template Validator"
    )
    parser.add_argument("--redis-host", default="localhost")
    parser.add_argument("--redis-port", type=int, default=6379)
    parser.add_argument("--redis-db", type=int, default=0)
    parser.add_argument("--config", default=None)
    parser.add_argument("--test-file", type=str, default=None,
                        help="Validate a specific YAML file")
    parser.add_argument("--check-binary", action="store_true",
                        help="Check nuclei binary availability")
    args = parser.parse_args()

    if args.check_binary:
        config = _load_config(args.config)
        nuclei_path = config.get("validation", {}).get(
            "nuclei_path", "/usr/local/bin/nuclei"
        )
        available, info = check_nuclei_binary(nuclei_path)
        print(f"Available: {available}")
        print(f"Info: {info}")
    elif args.test_file:
        r = redis.Redis(host=args.redis_host, port=args.redis_port,
                        db=args.redis_db, decode_responses=True)
        validator = TemplateValidator(redis_client=r, config_path=args.config)

        with open(args.test_file, "r") as f:
            template = f.read()

        result = validator.validate_template(template)
        print(f"\nValid: {result.is_valid}")
        print(f"Errors: {result.errors}")
        print(f"Return Code: {result.return_code}")
        if result.stdout:
            print(f"Stdout: {result.stdout}")
        if result.stderr:
            print(f"Stderr: {result.stderr}")
    else:
        r = redis.Redis(host=args.redis_host, port=args.redis_port,
                        db=args.redis_db, decode_responses=True)
        validator = TemplateValidator(redis_client=r, config_path=args.config)
        try:
            validator.process_validation_queue()
        except KeyboardInterrupt:
            validator.stop()
