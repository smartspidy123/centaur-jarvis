"""
AI Planner — Centaur-Jarvis Chain Attack Module
=================================================
Uses AI Router to propose attack chains based on knowledge graph state.
Falls back to static heuristic templates when AI is unavailable.
"""

from __future__ import annotations

import json
import os
import signal
import time
import uuid
from typing import Any, Dict, List, Optional

# ---------------------------------------------------------------------------
# Logger
# ---------------------------------------------------------------------------
try:
    from shared.logger import get_logger
    logger = get_logger("chain_attack.ai_planner")
except ImportError:
    import logging
    logging.basicConfig(
        level=logging.INFO,
        format='{"time":"%(asctime)s","level":"%(levelname)s","module":"%(name)s","msg":"%(message)s"}'
    )
    logger = logging.getLogger("chain_attack.ai_planner")

# ---------------------------------------------------------------------------
# Redis
# ---------------------------------------------------------------------------
try:
    import redis as redis_lib
except ImportError:
    redis_lib = None  # type: ignore

# ---------------------------------------------------------------------------
# AI Router
# ---------------------------------------------------------------------------
try:
    from modules.ai_routing.router import AIRouter, TaskRequest, TaskComplexity
    HAS_AI_ROUTER = True
except ImportError:
    HAS_AI_ROUTER = False
    logger.warning("AI Router not available. Will use static templates only.")

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
_AI_CFG = _CONFIG.get("ai", {})
_EXEC_CFG = _CONFIG.get("executor", {})

PLAN_QUEUE = _REDIS_CFG.get("plan_queue", "chain:plans")
AI_ENABLED = _AI_CFG.get("enabled", True)
AI_COMPLEXITY = _AI_CFG.get("complexity", "HIGH")
AI_MAX_RETRIES = int(_AI_CFG.get("max_retries", 2))
AI_TEMPERATURE = float(_AI_CFG.get("temperature", 0.5))
AUTO_APPROVE = _EXEC_CFG.get("auto_approve", False)
MAX_STEPS_PER_PLAN = int(_EXEC_CFG.get("max_steps_per_plan", 10))


# ---------------------------------------------------------------------------
# Prompt Template
# ---------------------------------------------------------------------------

PLANNER_SYSTEM_PROMPT = """You are a senior penetration tester AI assistant. Given the current knowledge graph of a target application, propose the next attack chain to achieve the specified goal.

RULES:
1. Return ONLY a valid JSON object with the structure below.
2. Each step must have: "action", "target", "params", "reason".
3. Valid actions: fetch_url, login, exploit_sqli, exploit_xss, exploit_rce, exploit_lfi, fuzz_params, brute_force, nuclei_scan, recon, dump_database, escalate_privilege, enumerate_users, custom.
4. Steps should be ordered logically. Earlier steps' outputs feed into later steps.
5. Maximum {max_steps} steps.
6. Be specific about targets (use node IDs or URLs from the graph).
7. Do NOT repeat steps that have already been completed successfully.

Response format:
{{
  "goal_assessment": "Brief assessment of feasibility",
  "plan": [
    {{
      "action": "action_name",
      "target": "node_id_or_url",
      "params": {{}},
      "reason": "Why this step is needed",
      "depends_on": []
    }}
  ],
  "confidence": 0.0-1.0,
  "notes": "Any caveats or warnings"
}}"""

PLANNER_USER_PROMPT = """GOAL: {goal}

CURRENT KNOWLEDGE GRAPH:
{graph_summary}

PREVIOUS PLANS (if any):
{previous_plans}

Propose the next attack chain to achieve the goal. Consider what has already been discovered and what gaps remain."""


# ---------------------------------------------------------------------------
# Static fallback templates
# ---------------------------------------------------------------------------

STATIC_TEMPLATES: Dict[str, List[Dict[str, Any]]] = {
    "default": [
        {"action": "recon", "target": "{base_url}", "params": {}, "reason": "Initial reconnaissance"},
        {"action": "fuzz_params", "target": "{base_url}", "params": {"wordlist": "common"}, "reason": "Parameter discovery"},
        {"action": "nuclei_scan", "target": "{base_url}", "params": {"templates": "default"}, "reason": "Vulnerability scanning"},
    ],
    "credential_found": [
        {"action": "login", "target": "{login_url}", "params": {"username": "{username}", "password": "{password}"}, "reason": "Test discovered credentials"},
        {"action": "fetch_url", "target": "{admin_url}", "params": {}, "reason": "Access admin panel with session"},
        {"action": "escalate_privilege", "target": "{base_url}", "params": {}, "reason": "Attempt privilege escalation"},
    ],
    "sqli_found": [
        {"action": "exploit_sqli", "target": "{vuln_url}", "params": {"payload": "{payload}"}, "reason": "Exploit SQL injection"},
        {"action": "dump_database", "target": "{vuln_url}", "params": {}, "reason": "Extract database contents"},
        {"action": "enumerate_users", "target": "{vuln_url}", "params": {}, "reason": "Find user accounts"},
    ],
    "xss_found": [
        {"action": "exploit_xss", "target": "{vuln_url}", "params": {"payload": "{payload}"}, "reason": "Exploit XSS to steal session"},
        {"action": "login", "target": "{login_url}", "params": {"token": "{stolen_token}"}, "reason": "Use stolen session"},
    ],
}


# ---------------------------------------------------------------------------
# AI Planner
# ---------------------------------------------------------------------------

class AIPlanner:
    """
    Proposes attack chains using the AI Router.
    Falls back to static templates if AI is unavailable.
    """

    def __init__(
        self,
        graph: KnowledgeGraph,
        redis_client: Optional[Any] = None,
        ai_enabled: bool = AI_ENABLED,
        auto_approve: bool = AUTO_APPROVE,
    ):
        self._graph = graph
        self._ai_enabled = ai_enabled and HAS_AI_ROUTER
        self._auto_approve = auto_approve
        self._ai_router: Optional[Any] = None

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
                )
                self._redis.ping()
            except Exception as exc:
                logger.warning(f"AIPlanner Redis unavailable: {exc}")
                self._redis = None

        # AI Router
        if self._ai_enabled:
            try:
                self._ai_router = AIRouter()
                logger.info("AIPlanner connected to AI Router.")
            except Exception as exc:
                logger.warning(f"AI Router initialization failed: {exc}")
                self._ai_enabled = False

        logger.info(
            f"AIPlanner initialized. ai_enabled={self._ai_enabled}, "
            f"auto_approve={self._auto_approve}"
        )

    # ------------------------------------------------------------------
    # Plan generation
    # ------------------------------------------------------------------

    def generate_plan(
        self,
        goal: str = "Find and exploit vulnerabilities to gain maximum access",
        previous_plans: Optional[List[Dict]] = None,
    ) -> AttackPlan:
        """
        Generate an attack plan using AI or static templates.
        Returns an AttackPlan with status AWAITING_APPROVAL (or APPROVED if auto_approve).
        """
        logger.info(f"Generating plan for goal: {goal}")

        graph_summary = self._graph.summary(max_nodes=80, max_edges=150)

        # Try AI first
        plan = None
        if self._ai_enabled:
            for attempt in range(AI_MAX_RETRIES + 1):
                try:
                    plan = self._generate_ai_plan(goal, graph_summary, previous_plans)
                    if plan and plan.steps:
                        logger.info(
                            f"AI plan generated: {plan.plan_id}, {len(plan.steps)} steps"
                        )
                        break
                    else:
                        logger.warning(
                            f"AI returned empty plan (attempt {attempt + 1}/{AI_MAX_RETRIES + 1})"
                        )
                        plan = None
                except Exception as exc:
                    logger.warning(
                        f"AI plan generation failed (attempt {attempt + 1}): {exc}"
                    )
                    plan = None

        # Fallback to static templates
        if not plan:
            logger.info("Falling back to static template plan.")
            plan = self._generate_static_plan(goal, graph_summary)

        # Cycle detection
        if plan.has_cycle():
            logger.warning(
                f"Plan {plan.plan_id} has circular dependencies. Removing depends_on."
            )
            for step in plan.steps:
                step.depends_on = []

        # Cap steps
        if len(plan.steps) > MAX_STEPS_PER_PLAN:
            logger.warning(
                f"Plan has {len(plan.steps)} steps, capping to {MAX_STEPS_PER_PLAN}"
            )
            plan.steps = plan.steps[:MAX_STEPS_PER_PLAN]

        # Set approval status
        if self._auto_approve:
            plan.status = PlanStatus.APPROVED.value
            plan.approved_at = time.time()
            plan.approved_by = "auto"
        else:
            plan.status = PlanStatus.AWAITING_APPROVAL.value

        # Persist plan
        self._persist_plan(plan)

        return plan

    def _generate_ai_plan(
        self,
        goal: str,
        graph_summary: Dict[str, Any],
        previous_plans: Optional[List[Dict]] = None,
    ) -> Optional[AttackPlan]:
        """Use AI Router to generate a plan."""
        if not self._ai_router:
            return None

        # Build prompt
        system_prompt = PLANNER_SYSTEM_PROMPT.format(max_steps=MAX_STEPS_PER_PLAN)
        user_prompt = PLANNER_USER_PROMPT.format(
            goal=goal,
            graph_summary=json.dumps(graph_summary, indent=2, default=str)[:8000],
            previous_plans=json.dumps(previous_plans or [], indent=2, default=str)[:2000],
        )

        # Call AI Router
        try:
            request = TaskRequest(
                task_id=f"chain_plan_{uuid.uuid4().hex[:8]}",
                module="chain_attack",
                prompt=user_prompt,
                system_prompt=system_prompt,
                complexity=AI_COMPLEXITY,
                temperature=AI_TEMPERATURE,
                max_tokens=4096,
            )
            response = self._ai_router.generate(request)

            if not response or not hasattr(response, "content"):
                logger.warning("AI Router returned empty response.")
                return None

            content = response.content
        except Exception as exc:
            logger.error(f"AI Router call failed: {exc}")
            return None

        # Parse AI response
        return self._parse_ai_response(content, goal)

    def _parse_ai_response(self, content: str, goal: str) -> Optional[AttackPlan]:
        """Parse AI response JSON into an AttackPlan."""
        # Try to extract JSON from the response
        json_str = content.strip()

        # Handle markdown code blocks
        if "```json" in json_str:
            start = json_str.index("```json") + 7
            end = json_str.index("```", start)
            json_str = json_str[start:end].strip()
        elif "```" in json_str:
            start = json_str.index("```") + 3
            end = json_str.index("```", start)
            json_str = json_str[start:end].strip()

        # Find JSON object boundaries
        brace_start = json_str.find("{")
        brace_end = json_str.rfind("}")
        if brace_start != -1 and brace_end != -1:
            json_str = json_str[brace_start:brace_end + 1]

        try:
            parsed = json.loads(json_str)
        except json.JSONDecodeError as exc:
            logger.error(f"Failed to parse AI response as JSON: {exc}")
            logger.debug(f"Raw content: {content[:500]}")
            return None

        if not isinstance(parsed, dict):
            logger.error("AI response is not a dict.")
            return None

        raw_steps = parsed.get("plan", [])
        if not isinstance(raw_steps, list) or not raw_steps:
            logger.warning("AI response has no 'plan' array or it's empty.")
            return None

        steps: List[PlanStep] = []
        for i, rs in enumerate(raw_steps):
            if not isinstance(rs, dict):
                continue
            action_str = rs.get("action", "custom")
            # Validate action
            valid_actions = {a.value for a in StepAction}
            if action_str not in valid_actions:
                action_str = StepAction.CUSTOM.value

            step = PlanStep(
                order=i,
                action=action_str,
                target=str(rs.get("target", "")),
                params=rs.get("params", {}) if isinstance(rs.get("params"), dict) else {},
                depends_on=rs.get("depends_on", []) if isinstance(rs.get("depends_on"), list) else [],
            )
            steps.append(step)

        plan = AttackPlan(
            goal=goal,
            steps=steps,
            source="ai_planner",
            metadata={
                "confidence": parsed.get("confidence", 0.5),
                "goal_assessment": parsed.get("goal_assessment", ""),
                "notes": parsed.get("notes", ""),
            },
        )

        return plan

    def _generate_static_plan(
        self, goal: str, graph_summary: Dict[str, Any]
    ) -> AttackPlan:
        """Generate a plan from static templates based on graph state."""
        type_counts = graph_summary.get("type_counts", {})
        nodes = graph_summary.get("nodes", [])

        # Determine which template to use
        template_name = "default"
        template_vars: Dict[str, str] = {}

        # Extract useful info from graph
        base_url = ""
        for n in nodes:
            if n["type"] in ("URL", "ENDPOINT"):
                url = n.get("attrs", {}).get("url", "")
                if url:
                    base_url = url
                    break

        template_vars["base_url"] = base_url or "http://target"

        if type_counts.get("CREDENTIAL", 0) > 0:
            template_name = "credential_found"
            for n in nodes:
                if n["type"] == "CREDENTIAL":
                    template_vars["username"] = n.get("attrs", {}).get("username", "admin")
                    template_vars["password"] = n.get("attrs", {}).get("password", "")
                    template_vars["login_url"] = n.get("attrs", {}).get("target", base_url)
                    break
            template_vars["admin_url"] = base_url + "/admin"

        elif type_counts.get("VULNERABILITY", 0) > 0:
            for n in nodes:
                if n["type"] == "VULNERABILITY":
                    vuln_type = n.get("attrs", {}).get("vuln_type", "").lower()
                    vuln_url = n.get("attrs", {}).get("url", base_url)
                    template_vars["vuln_url"] = vuln_url
                    template_vars["payload"] = n.get("attrs", {}).get("payload", "")

                    if "sql" in vuln_type:
                        template_name = "sqli_found"
                    elif "xss" in vuln_type:
                        template_name = "xss_found"
                        template_vars["login_url"] = base_url + "/login"
                        template_vars["stolen_token"] = ""
                    break

        # Build plan from template
        template = STATIC_TEMPLATES.get(template_name, STATIC_TEMPLATES["default"])
        steps: List[PlanStep] = []
        for i, t in enumerate(template):
            # Substitute variables
            target = t["target"]
            params = dict(t["params"])
            for var_name, var_val in template_vars.items():
                target = target.replace(f"{{{var_name}}}", var_val)
                for pk, pv in params.items():
                    if isinstance(pv, str):
                        params[pk] = pv.replace(f"{{{var_name}}}", var_val)

            step = PlanStep(
                order=i,
                action=t["action"],
                target=target,
                params=params,
            )
            steps.append(step)

        plan = AttackPlan(
            goal=goal,
            steps=steps,
            source="static_template",
            metadata={"template_name": template_name},
        )

        logger.info(f"Static plan generated: template={template_name}, {len(steps)} steps")
        return plan

    # ------------------------------------------------------------------
    # Plan persistence
    # ------------------------------------------------------------------

    def _persist_plan(self, plan: AttackPlan):
        """Store plan in Redis."""
        if self._redis:
            try:
                key = f"chain:plan:{plan.plan_id}"
                self._redis.set(key, json.dumps(plan.to_dict(), default=str))
                self._redis.expire(key, 86400 * 7)  # 7 days

                # Push to plan queue for executor
                self._redis.lpush(PLAN_QUEUE, json.dumps({
                    "plan_id": plan.plan_id,
                    "status": plan.status,
                    "timestamp": time.time(),
                }, default=str))

                logger.info(f"Plan {plan.plan_id} persisted to Redis (status={plan.status})")
            except Exception as exc:
                logger.error(f"Failed to persist plan to Redis: {exc}")

    def get_plan(self, plan_id: str) -> Optional[AttackPlan]:
        """Retrieve a plan from Redis."""
        if not self._redis:
            return None
        try:
            raw = self._redis.get(f"chain:plan:{plan_id}")
            if raw:
                return AttackPlan.from_dict(json.loads(raw))
        except Exception as exc:
            logger.error(f"Failed to get plan {plan_id}: {exc}")
        return None

    def update_plan(self, plan: AttackPlan):
        """Update an existing plan in Redis."""
        if self._redis:
            try:
                key = f"chain:plan:{plan.plan_id}"
                self._redis.set(key, json.dumps(plan.to_dict(), default=str))
                logger.debug(f"Plan {plan.plan_id} updated (status={plan.status})")
            except Exception as exc:
                logger.error(f"Failed to update plan: {exc}")

    def approve_plan(self, plan_id: str, approved_by: str = "human") -> bool:
        """Approve a plan for execution."""
        plan = self.get_plan(plan_id)
        if not plan:
            logger.warning(f"Plan {plan_id} not found for approval.")
            return False
        if plan.status != PlanStatus.AWAITING_APPROVAL.value:
            logger.warning(
                f"Plan {plan_id} is not awaiting approval (status={plan.status})."
            )
            return False

        plan.status = PlanStatus.APPROVED.value
        plan.approved_at = time.time()
        plan.approved_by = approved_by
        self.update_plan(plan)

        # Notify executor
        if self._redis:
            try:
                self._redis.lpush(PLAN_QUEUE, json.dumps({
                    "plan_id": plan.plan_id,
                    "status": plan.status,
                    "timestamp": time.time(),
                }, default=str))
            except Exception:
                pass

        logger.info(f"Plan {plan_id} approved by {approved_by}.")
        return True

    def reject_plan(self, plan_id: str, reason: str = "") -> bool:
        """Reject a plan."""
        plan = self.get_plan(plan_id)
        if not plan:
            return False
        plan.status = PlanStatus.ABORTED.value
        plan.error = f"Rejected: {reason}"
        self.update_plan(plan)
        logger.info(f"Plan {plan_id} rejected: {reason}")
        return True


# ---------------------------------------------------------------------------
# Main (standalone execution)
# ---------------------------------------------------------------------------

def main():
    """Run AI Planner as a one-shot or periodic process."""
    graph = KnowledgeGraph()
    planner = AIPlanner(graph=graph)

    goal = os.getenv(
        "CHAIN_ATTACK_GOAL",
        "Find and exploit vulnerabilities to gain maximum access"
    )

    plan = planner.generate_plan(goal=goal)
    logger.info(
        f"Plan generated: id={plan.plan_id}, status={plan.status}, "
        f"steps={len(plan.steps)}, source={plan.source}"
    )

    for step in plan.steps:
        logger.info(
            f"  Step {step.order}: action={step.action}, target={step.target}"
        )


if __name__ == "__main__":
    main()
