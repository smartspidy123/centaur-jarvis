"""
Template Executor
=================
Pushes validated Nuclei templates to the recon worker queue for execution
against configured targets. Also handles result collection and reporting.

Edge Cases Handled:
- EC9:  Redis connection lost → retry with backoff
- EC10: No targets configured → log warning, wait
- EC11: Target unreachable → handled by recon worker
"""

import json
import tempfile
import os
import time
import uuid
from typing import Optional

import redis
import yaml as pyyaml

try:
    from shared.logger import get_logger
    from shared.schemas import TaskStatus
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

    class TaskStatus:
        COMPLETED = "COMPLETED"
        FAILED = "FAILED"
        RUNNING = "RUNNING"
        QUEUED = "QUEUED"

logger = get_logger("nuclei_sniper.executor")


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
# Template Executor
# ---------------------------------------------------------------------------
class TemplateExecutor:
    """
    Consumes validated templates and pushes them as scan tasks to the
    recon worker queue.
    """

    def __init__(self, redis_client: redis.Redis = None,
                 config_path: str = None):
        self._config = _load_config(config_path)
        self._redis_client = redis_client

        exec_config = self._config.get("execution", {})
        self._default_targets = exec_config.get("default_targets", [])
        self._push_queue = exec_config.get("push_to_queue", "queue:recon")
        self._results_queue = exec_config.get("results_queue",
                                               "results:incoming")
        self._scan_timeout = exec_config.get("scan_timeout", 300)

        redis_config = self._config.get("redis", {})
        self._status_prefix = redis_config.get("status_prefix",
                                                "nuclei_sniper:status:")
        self._execution_queue = "queue:nuclei_sniper:execute"

        self._running = False
        self._stats = {
            "templates_executed": 0,
            "tasks_pushed": 0,
            "targets_scanned": 0,
            "results_received": 0,
            "errors": 0,
            "no_targets_warnings": 0,
        }

    @property
    def stats(self) -> dict:
        return self._stats.copy()

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

    def _push_to_queue(self, queue: str, data: dict) -> bool:
        """Push data to a Redis queue with retry."""
        if not self._redis_client:
            logger.error("No Redis client; cannot push to %s", queue)
            return False

        max_retries = 3
        for attempt in range(1, max_retries + 1):
            try:
                self._redis_client.lpush(queue, json.dumps(data))
                return True
            except redis.RedisError as exc:
                logger.warning(
                    "Redis push to %s failed (attempt %d/%d): %s",
                    queue, attempt, max_retries, exc
                )
                if attempt < max_retries:
                    time.sleep(2 ** attempt)

        logger.error("Failed to push to %s after %d attempts", queue, max_retries)
        return False

    # ----- Target resolution -----

    def _resolve_targets(self, task: dict) -> list:
        """
        Resolve the list of targets for a scan.

        Priority:
        1. Per-CVE targets (from task)
        2. Default targets (from config)
        3. Global target list (from Redis key 'global:targets')

        EC10: If no targets, log warning.
        """
        # Per-CVE targets
        targets = task.get("targets", [])
        if targets:
            logger.info("Using %d per-CVE target(s)", len(targets))
            return targets

        # Default targets from config
        if self._default_targets:
            logger.info("Using %d default target(s)", len(self._default_targets))
            return self._default_targets

        # Try global target list from Redis
        if self._redis_client:
            try:
                global_targets = self._redis_client.smembers("global:targets")
                if global_targets:
                    targets = list(global_targets)
                    logger.info(
                        "Using %d global target(s) from Redis", len(targets)
                    )
                    return targets
            except redis.RedisError as exc:
                logger.warning("Failed to fetch global targets: %s", exc)

        # EC10: No targets
        self._stats["no_targets_warnings"] += 1
        logger.warning(
            "⚠️ No targets configured for scanning. "
            "Set default_targets in config, per-CVE targets, or "
            "add to 'global:targets' set in Redis."
        )
        return []

    # ----- Task construction -----

    def _build_recon_task(self, cve_id: str, template_yaml: str,
                        target: str) -> dict:
        # Create a temporary file to store the template
        fd, temp_path = tempfile.mkstemp(
            suffix=".yaml",
            prefix=f"nuclei_{cve_id}_",
            dir="/tmp"
        )
        with os.fdopen(fd, "w") as f:
            f.write(template_yaml)
        logger.debug("Wrote template for %s to %s", cve_id, temp_path)

        task_id = f"nuclei_sniper_{cve_id}_{uuid.uuid4().hex[:8]}"

        return {
            "task_id": task_id,
            "type": "RECON_NUCLEI",                # CRITICAL: task type
            "target": target,
            "params": {
                "templates": temp_path,             # path to template file
                "cve_id": cve_id,
                "timeout": self._scan_timeout,
                "source": "nuclei_sniper",
            },
            "max_retries": 2,
            "created_at": time.time(),
        }

    def _build_result(self, cve_id: str, targets: list,
                       task_ids: list, status: str,
                       error_msg: str = "") -> dict:
        """
        Build a result dictionary conforming to the required schema.

        CRITICAL: Must include `data` field as per architectural rules.
        """
        return {
            "module": "nuclei_sniper",
            "target": ", ".join(targets) if targets else "none",
            "status": status.upper(),  # UPPERCASE enforced
            "errors": [error_msg] if error_msg else [],
            # MANDATORY `data` field per architectural rules
            "data": {
                "findings": [],  # Will be populated by recon worker results
                "stats": {
                    "cve_id": cve_id,
                    "targets_scanned": len(targets),
                    "task_ids": task_ids,
                    "timestamp": time.time(),
                },
                "template_cve": cve_id,
            },
        }

    # ----- Main execution logic -----

    def execute_template(self, cve_id: str, template_yaml: str,
                          task: dict = None) -> dict:
        """
        Push a validated template to the recon worker for execution.

        Args:
            cve_id: CVE identifier
            template_yaml: Validated Nuclei YAML template
            task: Original CVE task metadata

        Returns:
            Result dictionary with execution status.
        """
        task = task or {}
        self._stats["templates_executed"] += 1

        logger.info("Executing template for %s", cve_id)
        self._set_status(cve_id, "EXECUTING", "Pushing to recon worker")

        # Resolve targets
        targets = self._resolve_targets(task)

        if not targets:
            # EC10: No targets
            self._set_status(cve_id, "WAITING",
                            "No targets configured; waiting")
            result = self._build_result(
                cve_id=cve_id,
                targets=[],
                task_ids=[],
                status="WAITING",
                error_msg="No targets configured for scanning",
            )
            # Still push to results for tracking
            self._push_to_queue(self._results_queue, result)
            return result

        # Push a scan task for each target
        task_ids = []
        push_failures = 0

        for target in targets:
            recon_task = self._build_recon_task(cve_id, template_yaml, target)
            task_id = recon_task["task_id"]

            if self._push_to_queue(self._push_queue, recon_task):
                task_ids.append(task_id)
                self._stats["tasks_pushed"] += 1
                self._stats["targets_scanned"] += 1
                logger.info(
                    "Pushed scan task %s for %s → %s",
                    task_id, cve_id, target
                )
            else:
                push_failures += 1
                self._stats["errors"] += 1
                logger.error(
                    "Failed to push scan task for %s → %s",
                    cve_id, target
                )

        # Build and report results
        if task_ids:
            status = "COMPLETED" if push_failures == 0 else "PARTIAL"
            self._set_status(
                cve_id, "SCANNING",
                f"Pushed {len(task_ids)} scan tasks ({push_failures} failures)"
            )
        else:
            status = "FAILED"
            self._set_status(cve_id, "FAILED",
                            "All scan task pushes failed")

        result = self._build_result(
            cve_id=cve_id,
            targets=targets,
            task_ids=task_ids,
            status=status,
            error_msg=(
                f"{push_failures} out of {len(targets)} pushes failed"
                if push_failures else ""
            ),
        )

        # Push final result
        self._push_to_queue(self._results_queue, result)

        logger.info(
            "Template execution for %s: %s (%d/%d tasks pushed)",
            cve_id, status, len(task_ids), len(targets)
        )

        return result

    # ----- Continuous execution loop -----

    def run_continuous(self):
        """
        Run the executor in a continuous loop, consuming from the
        execution queue.
        """
        logger.info("Starting continuous template executor")
        self._running = True

        while self._running:
            try:
                if not self._redis_client:
                    logger.error("No Redis client for executor")
                    time.sleep(10)
                    continue

                result = self._redis_client.brpop(
                    self._execution_queue, timeout=5
                )
                if result is None:
                    continue

                _, item_json = result
                item = json.loads(item_json)

                cve_id = item.get("cve_id", "UNKNOWN")
                template_yaml = item.get("template_yaml", "")
                task = item.get("task", {})

                if not template_yaml:
                    logger.warning(
                        "Empty template for %s in execution queue; skipping",
                        cve_id
                    )
                    continue

                self.execute_template(
                    cve_id=cve_id,
                    template_yaml=template_yaml,
                    task=task,
                )

            except json.JSONDecodeError as exc:
                logger.error("Invalid JSON in execution queue: %s", exc)
            except Exception as exc:
                logger.error(
                    "Unhandled error in executor loop: %s", exc,
                    exc_info=True
                )
                self._stats["errors"] += 1
                time.sleep(5)

        logger.info("Template executor stopped. Stats: %s", self._stats)

    def stop(self):
        """Signal the executor to stop."""
        logger.info("Stop signal received for executor")
        self._running = False

    # ----- Utility: add targets at runtime -----

    def add_target(self, target: str) -> bool:
        """Add a target to the global target set in Redis."""
        if not self._redis_client:
            logger.error("No Redis client; cannot add target")
            return False
        try:
            self._redis_client.sadd("global:targets", target)
            logger.info("Added target: %s", target)
            return True
        except redis.RedisError as exc:
            logger.error("Failed to add target %s: %s", target, exc)
            return False

    def remove_target(self, target: str) -> bool:
        """Remove a target from the global target set."""
        if not self._redis_client:
            return False
        try:
            self._redis_client.srem("global:targets", target)
            logger.info("Removed target: %s", target)
            return True
        except redis.RedisError as exc:
            logger.error("Failed to remove target %s: %s", target, exc)
            return False


# ---------------------------------------------------------------------------
# Standalone execution
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="Nuclei Sniper Template Executor"
    )
    parser.add_argument("--redis-host", default="localhost")
    parser.add_argument("--redis-port", type=int, default=6379)
    parser.add_argument("--redis-db", type=int, default=0)
    parser.add_argument("--config", default=None)
    parser.add_argument("--add-target", type=str, default=None,
                        help="Add a target to the global target list")
    parser.add_argument("--list-targets", action="store_true",
                        help="List current global targets")
    args = parser.parse_args()

    r = redis.Redis(host=args.redis_host, port=args.redis_port,
                    db=args.redis_db, decode_responses=True)
    executor = TemplateExecutor(redis_client=r, config_path=args.config)

    if args.add_target:
        executor.add_target(args.add_target)
    elif args.list_targets:
        try:
            targets = r.smembers("global:targets")
            print(f"Global targets ({len(targets)}):")
            for t in sorted(targets):
                print(f"  - {t}")
        except redis.RedisError as exc:
            print(f"Error: {exc}")
    else:
        try:
            executor.run_continuous()
        except KeyboardInterrupt:
            executor.stop()
