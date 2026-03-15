"""
Executor — Centaur-Jarvis Chain Attack Module
===============================================
Consumes approved plans from Redis, translates steps into tasks,
pushes them to appropriate module queues, and tracks execution.
"""

from __future__ import annotations

import json
import os
import signal
import sys
import threading
import time
import uuid
from typing import Any, Dict, List, Optional, Set

# ---------------------------------------------------------------------------
# Logger
# ---------------------------------------------------------------------------
try:
    from shared.logger import get_logger
    logger = get_logger("chain_attack.executor")
except ImportError:
    import logging
    logging.basicConfig(
        level=logging.INFO,
        format='{"time":"%(asctime)s","level":"%(levelname)s","module":"%(name)s","msg":"%(message)s"}'
    )
    logger = logging.getLogger("chain_attack.executor")

# ---------------------------------------------------------------------------
# Redis
# ---------------------------------------------------------------------------
try:
    import redis as redis_lib
except ImportError:
    redis_lib = None  # type: ignore

# ---------------------------------------------------------------------------
# Shared schemas
# ---------------------------------------------------------------------------
try:
    from shared.schemas import Task, TaskResult, TaskStatus
except ImportError:
    logger.warning("shared.schemas not available — using local constants.")
    class TaskStatus:
        COMPLETED = "COMPLETED"
        FAILED = "FAILED"
        PENDING = "PENDING"
        RUNNING = "RUNNING"

# ---------------------------------------------------------------------------
# Internal imports
# ---------------------------------------------------------------------------
from modules.chain_attack.models import (
    AttackPlan, PlanStep, PlanStatus, StepAction, StepStatus
)
from modules.chain_attack.ai_planner import AIPlanner
from modules.chain_attack.knowledge_graph import KnowledgeGraph

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
try:
    import yaml
    _cfg_path = os.path.join(os.path.dirname(__file__), "config.yaml")
    if os.path.exists(_cfg_path):
        with open(_cfg_path, "r") as _f:
            _CONFIG = yaml.safe_load(_f) or {}
    else:
        _CONFIG = {}
except Exception:
    _CONFIG = {}

_REDIS_CFG = _CONFIG.get("redis", {})
_EXEC_CFG = _CONFIG.get("executor", {})

PLAN_QUEUE = _REDIS_CFG.get("plan_queue", "chain:plans")
STEP_QUEUE = _REDIS_CFG.get("step_queue", "chain:steps")
RESULT_QUEUE = _REDIS_CFG.get("result_queue", "results:incoming")
AUTO_APPROVE = _EXEC_CFG.get("auto_approve", False)
MAX_STEPS_PER_PLAN = int(_EXEC_CFG.get("max_steps_per_plan", 10))
STEP_TIMEOUT = int(_EXEC_CFG.get("step_timeout", 300))

# ---------------------------------------------------------------------------
# Action → Queue mapping
# ---------------------------------------------------------------------------

ACTION_QUEUE_MAP: Dict[str, str] = {
    StepAction.RECON.value: "queue:recon",
    StepAction.FUZZ_PARAMS.value: "queue:smart_fuzzer",
    StepAction.NUCLEI_SCAN.value: "queue:nuclei_sniper",
    StepAction.EXPLOIT_SQLI.value: "queue:nuclei_sniper",
    StepAction.EXPLOIT_XSS.value: "queue:nuclei_sniper",
    StepAction.EXPLOIT_RCE.value: "queue:nuclei_sniper",
    StepAction.EXPLOIT_LFI.value: "queue:nuclei_sniper",
    StepAction.BRUTE_FORCE.value: "queue:brute_forcer",
    StepAction.ENUMERATE_USERS.value: "queue:recon",
    StepAction.DUMP_DATABASE.value: "queue:nuclei_sniper",
    StepAction.ESCALATE_PRIVILEGE.value: "queue:nuclei_sniper",
    # login, fetch_url, custom → executed directly
}

# Actions executed directly by the executor (not queued)
DIRECT_ACTIONS: Set[str] = {
    StepAction.LOGIN.value,
    StepAction.FETCH_URL.value,
    StepAction.CUSTOM.value,
}


class ChainExecutor:
    """
    Executes approved attack plans by dispatching steps to module queues
    and tracking results.
    """

    def __init__(
        self,
        graph: Optional[KnowledgeGraph] = None,
        planner: Optional[AIPlanner] = None,
        redis_client: Optional[Any] = None,
        step_timeout: int = STEP_TIMEOUT,
    ):
        self._step_timeout = step_timeout
        self._running = False
        self._lock = threading.Lock()
        self._active_plans: Dict[str, AttackPlan] = {}

        # Redis
        self._redis: Optional[Any] = redis_client
        if not self._redis and redis_lib is not None:
            try:
                self._redis = redis_lib.Redis(
                    host=os.getenv("REDIS_HOST", "localhost"),
                    port=int(os.getenv("REDIS_PORT", 6379)),
                    db=int(os.getenv("REDIS_DB", 0)),
                    decode_responses=True,
                    socket_connect_timeout=5,
                    socket_timeout=5,
                    retry_on_timeout=True,
                )
                self._redis.ping()
            except Exception as exc:
                logger.error(f"Executor Redis unavailable: {exc}")
                self._redis = None

        # Dependencies
        self._graph = graph or KnowledgeGraph(redis_client=self._redis)
        self._planner = planner or AIPlanner(graph=self._graph, redis_client=self._redis)

        # HTTP client for direct actions
        self._http_session: Optional[Any] = None
        try:
            import requests
            self._http_session = requests.Session()
            self._http_session.headers.update({
                "User-Agent": "Centaur-Jarvis/1.0 ChainAttack"
            })
        except ImportError:
            logger.warning("requests library not available. Direct HTTP actions will fail.")

        logger.info(
            f"ChainExecutor initialized. step_timeout={self._step_timeout}s, "
            f"redis={'connected' if self._redis else 'unavailable'}"
        )

    # ------------------------------------------------------------------
    # Main execution loop
    # ------------------------------------------------------------------

    def start(self):
        """Start the executor loop — listens for approved plans."""
        if not self._redis:
            logger.error("Executor cannot start without Redis connection.")
            return

        self._running = True
        logger.info("ChainExecutor started. Listening for approved plans...")

        # Start result watcher in a thread
        result_thread = threading.Thread(
            target=self._watch_results, daemon=True, name="exec-result-watcher"
        )
        result_thread.start()

        while self._running:
            try:
                # Pop from plan queue
                result = self._redis.brpop(PLAN_QUEUE, timeout=2)
                if result is None:
                    continue

                _, raw = result
                try:
                    msg = json.loads(raw)
                except (json.JSONDecodeError, TypeError):
                    logger.warning("Invalid JSON in plan queue.")
                    continue

                plan_id = msg.get("plan_id", "")
                status = msg.get("status", "")

                if status != PlanStatus.APPROVED.value:
                    logger.debug(
                        f"Plan {plan_id} status is {status}, skipping."
                    )
                    continue

                # Retrieve full plan
                plan = self._planner.get_plan(plan_id)
                if not plan:
                    logger.warning(f"Plan {plan_id} not found in Redis.")
                    continue

                if plan.status != PlanStatus.APPROVED.value:
                    logger.warning(
                        f"Plan {plan_id} status mismatch: {plan.status} (expected APPROVED)"
                    )
                    continue

                logger.info(f"Executing plan {plan_id} ({len(plan.steps)} steps)")
                self._execute_plan(plan)

            except Exception as exc:
                logger.error(f"Executor loop error: {exc}", exc_info=True)
                time.sleep(2)

        logger.info("ChainExecutor stopped.")

    def stop(self):
        """Gracefully stop the executor."""
        self._running = False
        logger.info("ChainExecutor stopping...")

    # ------------------------------------------------------------------
    # Plan execution
    # ------------------------------------------------------------------

    def _execute_plan(self, plan: AttackPlan):
        """Execute all steps of a plan in order, respecting dependencies."""
        plan.status = PlanStatus.EXECUTING.value
        self._planner.update_plan(plan)
        self._active_plans[plan.plan_id] = plan

        steps_executed = 0
        max_steps = min(len(plan.steps), MAX_STEPS_PER_PLAN)

        try:
            for step in plan.steps[:max_steps]:
                if not self._running:
                    logger.info("Executor stopping mid-plan.")
                    plan.status = PlanStatus.ABORTED.value
                    plan.error = "Executor shutdown during execution"
                    break

                # Check dependencies
                if not self._dependencies_met(plan, step):
                    logger.info(
                        f"Step {step.step_id[:8]} dependencies not met, skipping."
                    )
                    step.status = StepStatus.SKIPPED.value
                    continue

                # Execute step
                success = self._execute_step(plan, step)
                steps_executed += 1

                if not success and step.retry_count < step.max_retries:
                    step.retry_count += 1
                    logger.info(
                        f"Retrying step {step.step_id[:8]} "
                        f"(attempt {step.retry_count + 1}/{step.max_retries + 1})"
                    )
                    success = self._execute_step(plan, step)

                # Update plan in Redis after each step
                self._planner.update_plan(plan)

            # Determine final status
            if plan.status != PlanStatus.ABORTED.value:
                if plan.steps_failed == 0:
                    plan.status = PlanStatus.COMPLETED.value
                elif plan.steps_succeeded > 0:
                    plan.status = PlanStatus.PARTIAL.value
                else:
                    plan.status = PlanStatus.FAILED.value

            plan.completed_at = time.time()
            self._planner.update_plan(plan)

            # Push final result
            self._push_plan_result(plan)

        except Exception as exc:
            logger.error(f"Plan execution error: {exc}", exc_info=True)
            plan.status = PlanStatus.FAILED.value
            plan.error = str(exc)
            plan.completed_at = time.time()
            self._planner.update_plan(plan)
            self._push_plan_result(plan)

        finally:
            self._active_plans.pop(plan.plan_id, None)

        logger.info(
            f"Plan {plan.plan_id} finished: status={plan.status}, "
            f"attempted={plan.steps_attempted}, succeeded={plan.steps_succeeded}, "
            f"failed={plan.steps_failed}"
        )

    def _dependencies_met(self, plan: AttackPlan, step: PlanStep) -> bool:
        """Check if all dependency steps are completed."""
        if not step.depends_on:
            return True

        step_map = {s.step_id: s for s in plan.steps}
        for dep_id in step.depends_on:
            dep_step = step_map.get(dep_id)
            if not dep_step:
                logger.warning(
                    f"Dependency {dep_id} not found for step {step.step_id[:8]}"
                )
                return False
            if dep_step.status != StepStatus.COMPLETED.value:
                return False
        return True

    # ------------------------------------------------------------------
    # Step execution
    # ------------------------------------------------------------------

    def _execute_step(self, plan: AttackPlan, step: PlanStep) -> bool:
        """Execute a single plan step. Returns True on success."""
        step.status = StepStatus.RUNNING.value
        step.started_at = time.time()

        logger.info(
            f"Executing step {step.order}: action={step.action}, "
            f"target={step.target[:60]}"
        )

        try:
            if step.action in DIRECT_ACTIONS:
                return self._execute_direct(plan, step)
            else:
                return self._dispatch_to_queue(plan, step)
        except Exception as exc:
            step.status = StepStatus.FAILED.value
            step.error = str(exc)
            step.completed_at = time.time()
            logger.error(
                f"Step {step.step_id[:8]} failed with exception: {exc}"
            )
            return False

    def _execute_direct(self, plan: AttackPlan, step: PlanStep) -> bool:
        """Execute a step directly (login, fetch_url, custom)."""
        if not self._http_session:
            step.status = StepStatus.FAILED.value
            step.error = "HTTP client not available (requests library missing)"
            step.completed_at = time.time()
            return False

        try:
            if step.action == StepAction.FETCH_URL.value:
                return self._action_fetch_url(step)
            elif step.action == StepAction.LOGIN.value:
                return self._action_login(step)
            elif step.action == StepAction.CUSTOM.value:
                return self._action_custom(step)
            else:
                step.status = StepStatus.FAILED.value
                step.error = f"Unknown direct action: {step.action}"
                step.completed_at = time.time()
                return False
        except Exception as exc:
            step.status = StepStatus.FAILED.value
            step.error = str(exc)
            step.completed_at = time.time()
            return False

    def _action_fetch_url(self, step: PlanStep) -> bool:
        """Fetch a URL and store the response."""
        url = step.target or step.params.get("url", "")
        if not url:
            step.status = StepStatus.FAILED.value
            step.error = "No URL specified"
            step.completed_at = time.time()
            return False

        try:
            method = step.params.get("method", "GET").upper()
            timeout = step.params.get("timeout", 30)
            headers = step.params.get("headers", {})

            resp = self._http_session.request(
                method, url, timeout=timeout,
                headers=headers, allow_redirects=True, verify=False
            )

            step.result = {
                "status_code": resp.status_code,
                "url": resp.url,
                "headers": dict(resp.headers),
                "body_length": len(resp.text),
                "body_preview": resp.text[:1000],
            }
            step.status = StepStatus.COMPLETED.value
            step.completed_at = time.time()

            # Add URL node to graph
            from modules.chain_attack.models import NodeType
            from modules.chain_attack.knowledge_graph import GraphNode
            node = GraphNode(
                node_type=NodeType.URL.value,
                label=url[:80],
                attributes={
                    "url": url,
                    "status_code": resp.status_code,
                    "content_length": len(resp.text),
                },
                source_module="chain_attack",
            )
            self._graph.add_node(node)

            logger.info(f"fetch_url: {url} → {resp.status_code}")
            return True

        except Exception as exc:
            step.status = StepStatus.FAILED.value
            step.error = f"HTTP request failed: {exc}"
            step.completed_at = time.time()
            return False

    def _action_login(self, step: PlanStep) -> bool:
        """Attempt login with credentials."""
        url = step.target or step.params.get("url", "")
        username = step.params.get("username", "")
        password = step.params.get("password", "")
        token = step.params.get("token", "")

        if not url:
            step.status = StepStatus.FAILED.value
            step.error = "No login URL specified"
            step.completed_at = time.time()
            return False

        try:
            login_data = {}
            if username:
                login_data["username"] = username
                login_data["password"] = password
            if token:
                self._http_session.headers["Authorization"] = f"Bearer {token}"

            if login_data:
                resp = self._http_session.post(
                    url, data=login_data, timeout=30,
                    allow_redirects=True, verify=False
                )
            else:
                resp = self._http_session.get(
                    url, timeout=30, allow_redirects=True, verify=False
                )

            # Heuristic: check if login succeeded
            success_indicators = [
                resp.status_code in (200, 302),
                "dashboard" in resp.url.lower(),
                "admin" in resp.url.lower(),
                "welcome" in resp.text.lower()[:500],
                "logout" in resp.text.lower()[:2000],
            ]
            login_success = any(success_indicators)

            step.result = {
                "status_code": resp.status_code,
                "redirect_url": resp.url,
                "login_success": login_success,
                "cookies": dict(resp.cookies),
                "body_preview": resp.text[:500],
            }

            if login_success:
                step.status = StepStatus.COMPLETED.value
                # Add session node
                from modules.chain_attack.models import NodeType
                from modules.chain_attack.knowledge_graph import GraphNode
                session_node = GraphNode(
                    node_type=NodeType.SESSION.value,
                    label=f"Session:{username or 'token'}",
                    attributes={
                        "target": url,
                        "username": username,
                        "cookies": dict(resp.cookies),
                    },
                    source_module="chain_attack",
                )
                self._graph.add_node(session_node)
                logger.info(f"login: Success at {url} as {username}")
            else:
                step.status = StepStatus.FAILED.value
                step.error = "Login appears unsuccessful (heuristic check)"
                logger.info(f"login: Failed at {url} as {username}")

            step.completed_at = time.time()
            return login_success

        except Exception as exc:
            step.status = StepStatus.FAILED.value
            step.error = f"Login request failed: {exc}"
            step.completed_at = time.time()
            return False

    def _action_custom(self, step: PlanStep) -> bool:
        """Execute a custom step — marks as needing human intervention if unclear."""
        description = step.params.get("description", step.params.get("command", ""))
        if not description:
            step.status = StepStatus.HUMAN_INTERVENTION_REQUIRED.value
            step.error = "Custom step with no description — needs human review"
            step.completed_at = time.time()
            logger.warning(f"Custom step {step.step_id[:8]} requires human intervention.")
            return False

        # For now, mark as completed with a note
        step.result = {
            "note": f"Custom action recorded: {description}",
            "requires_manual_execution": True,
        }
        step.status = StepStatus.HUMAN_INTERVENTION_REQUIRED.value
        step.completed_at = time.time()
        return False

    # ------------------------------------------------------------------
    # Queue dispatch
    # ------------------------------------------------------------------

    def _dispatch_to_queue(self, plan: AttackPlan, step: PlanStep) -> bool:
        """Dispatch a step as a task to the appropriate module queue."""
        if not self._redis:
            step.status = StepStatus.FAILED.value
            step.error = "Redis unavailable — cannot dispatch task"
            step.completed_at = time.time()
            return False

        queue_name = ACTION_QUEUE_MAP.get(step.action, "queue:generic")
        task_id = f"chain_{plan.plan_id}_{step.step_id[:8]}"

        task_payload = {
            "task_id": task_id,
            "module": self._action_to_module(step.action),
            "target": step.target,
            "params": step.params,
            "metadata": {
                "chain_plan_id": plan.plan_id,
                "chain_step_id": step.step_id,
                "chain_step_action": step.action,
            },
            "created_at": time.time(),
        }

        try:
            self._redis.lpush(queue_name, json.dumps(task_payload, default=str))
            step.task_id = task_id
            step.queue_name = queue_name
            step.status = StepStatus.RUNNING.value

            # Register step for result tracking
            self._redis.hset(
                "chain:step_tracking",
                task_id,
                json.dumps({
                    "plan_id": plan.plan_id,
                    "step_id": step.step_id,
                    "dispatched_at": time.time(),
                }, default=str),
            )

            logger.info(
                f"Step dispatched: task_id={task_id}, queue={queue_name}, "
                f"action={step.action}"
            )

            # Wait for result (with timeout)
            return self._wait_for_step_result(plan, step)

        except Exception as exc:
            step.status = StepStatus.FAILED.value
            step.error = f"Failed to dispatch to queue: {exc}"
            step.completed_at = time.time()
            return False

    def _wait_for_step_result(self, plan: AttackPlan, step: PlanStep) -> bool:
        """Wait for a dispatched step's result to appear."""
        if not self._redis:
            return False

        result_key = f"chain:step_result:{step.task_id}"
        deadline = time.time() + self._step_timeout

        while time.time() < deadline and self._running:
            try:
                raw = self._redis.get(result_key)
                if raw:
                    result = json.loads(raw)
                    status = result.get("status", "FAILED").upper()

                    if status == "COMPLETED":
                        step.status = StepStatus.COMPLETED.value
                        step.result = result.get("data", {})
                        step.completed_at = time.time()

                        # Ingest findings into graph
                        self._graph.ingest_findings(result)

                        logger.info(
                            f"Step {step.step_id[:8]} completed via queue."
                        )
                        return True
                    elif status == "FAILED":
                        step.status = StepStatus.FAILED.value
                        step.error = result.get("error", "Unknown error")
                        step.completed_at = time.time()
                        return False
                    # else: still running, keep waiting
            except Exception as exc:
                logger.warning(f"Error checking step result: {exc}")

            time.sleep(2)

        # Timeout
        if time.time() >= deadline:
            step.status = StepStatus.TIMEOUT.value
            step.error = f"Step timed out after {self._step_timeout}s"
            step.completed_at = time.time()
            logger.warning(f"Step {step.step_id[:8]} timed out.")

        return False

    def _action_to_module(self, action: str) -> str:
        """Map step action to module name."""
        mapping = {
            StepAction.RECON.value: "recon",
            StepAction.FUZZ_PARAMS.value: "smart_fuzzer",
            StepAction.NUCLEI_SCAN.value: "nuclei_sniper",
            StepAction.EXPLOIT_SQLI.value: "nuclei_sniper",
            StepAction.EXPLOIT_XSS.value: "nuclei_sniper",
            StepAction.EXPLOIT_RCE.value: "nuclei_sniper",
            StepAction.EXPLOIT_LFI.value: "nuclei_sniper",
            StepAction.BRUTE_FORCE.value: "brute_forcer",
            StepAction.ENUMERATE_USERS.value: "recon",
            StepAction.DUMP_DATABASE.value: "nuclei_sniper",
            StepAction.ESCALATE_PRIVILEGE.value: "nuclei_sniper",
        }
        return mapping.get(action, "generic")

    # ------------------------------------------------------------------
    # Result watcher
    # ------------------------------------------------------------------

    def _watch_results(self):
        """
        Background thread that watches for task results relevant to chain steps
        and stores them for the step wait loop.
        """
        if not self._redis:
            return

        # Subscribe to a dedicated channel or poll a result hash
        logger.info("Result watcher thread started.")

        while self._running:
            try:
                # Check the generic results queue for chain-related results
                # We use a secondary queue to avoid consuming results meant for others
                result = self._redis.brpop("chain:results", timeout=2)
                if result is None:
                    continue

                _, raw = result
                try:
                    data = json.loads(raw)
                except (json.JSONDecodeError, TypeError):
                    continue

                task_id = data.get("task_id", "")
                if not task_id:
                    continue

                # Check if this is a chain task
                tracking = self._redis.hget("chain:step_tracking", task_id)
                if tracking:
                    # Store result for the waiting step
                    self._redis.set(
                        f"chain:step_result:{task_id}",
                        json.dumps(data, default=str),
                    )
                    self._redis.expire(f"chain:step_result:{task_id}", 3600)
                    logger.debug(f"Result stored for chain task {task_id}")

            except Exception as exc:
                logger.warning(f"Result watcher error: {exc}")
                time.sleep(2)

        logger.info("Result watcher thread stopped.")

    # ------------------------------------------------------------------
    # Final result push
    # ------------------------------------------------------------------

    def _push_plan_result(self, plan: AttackPlan):
        """Push the final plan result to results:incoming."""
        if not self._redis:
            logger.warning("Cannot push plan result — Redis unavailable.")
            return

        # Collect findings from all steps
        all_findings = []
        for step in plan.steps:
            if step.result and isinstance(step.result, dict):
                all_findings.append({
                    "step_order": step.order,
                    "action": step.action,
                    "target": step.target,
                    "result": step.result,
                })

        # Build graph snapshot
        graph_stats = self._graph.stats()

        result = {
            "task_id": f"chain_{plan.plan_id}",
            "module": "chain_attack",
            "status": plan.status,  # Already UPPERCASE per PlanStatus enum
            "data": {
                "plan_id": plan.plan_id,
                "goal": plan.goal,
                "source": plan.source,
                "steps_total": len(plan.steps),
                "steps_attempted": plan.steps_attempted,
                "steps_succeeded": plan.steps_succeeded,
                "steps_failed": plan.steps_failed,
                "findings": all_findings,
                "final_state": graph_stats,
                "execution_time_seconds": (
                    (plan.completed_at - plan.created_at)
                    if plan.completed_at and plan.created_at
                    else 0
                ),
            },
            "error": plan.error or "",
            "completed_at": plan.completed_at or time.time(),
        }

        try:
            self._redis.lpush(RESULT_QUEUE, json.dumps(result, default=str))
            logger.info(
                f"Plan result pushed: plan_id={plan.plan_id}, status={plan.status}"
            )
        except Exception as exc:
            logger.error(f"Failed to push plan result: {exc}")

    # ------------------------------------------------------------------
    # Replan on failure
    # ------------------------------------------------------------------

    def replan(self, plan: AttackPlan) -> Optional[AttackPlan]:
        """
        If a plan partially failed, ask the AI planner to generate a new plan
        considering what succeeded and what failed.
        """
        logger.info(f"Replanning for plan {plan.plan_id}...")

        previous_plan_summary = {
            "plan_id": plan.plan_id,
            "goal": plan.goal,
            "status": plan.status,
            "steps": [
                {
                    "action": s.action,
                    "target": s.target,
                    "status": s.status,
                    "error": s.error or "",
                }
                for s in plan.steps
            ],
        }

        try:
            new_plan = self._planner.generate_plan(
                goal=plan.goal,
                previous_plans=[previous_plan_summary],
            )
            logger.info(
                f"Replan generated: {new_plan.plan_id}, {len(new_plan.steps)} steps"
            )
            return new_plan
        except Exception as exc:
            logger.error(f"Replan failed: {exc}")
            return None


# ---------------------------------------------------------------------------
# Main (standalone execution)
# ---------------------------------------------------------------------------

def main():
    """Run the Chain Executor as a standalone process."""
    executor = ChainExecutor()

    def _signal_handler(sig, frame):
        logger.info(f"Received signal {sig}, shutting down ChainExecutor...")
        executor.stop()

    signal.signal(signal.SIGTERM, _signal_handler)
    signal.signal(signal.SIGINT, _signal_handler)

    executor.start()


if __name__ == "__main__":
    main()
