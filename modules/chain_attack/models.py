"""
Data structures for the Chain Attack Module.
Nodes, Edges, Plans, Steps — all with full validation and serialization.
"""

from __future__ import annotations

import json
import time
import uuid
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any, Dict, List, Optional


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class NodeType(str, Enum):
    URL = "URL"
    CREDENTIAL = "CREDENTIAL"
    SESSION = "SESSION"
    PARAMETER = "PARAMETER"
    VULNERABILITY = "VULNERABILITY"
    FILE = "FILE"
    PORT = "PORT"
    HOST = "HOST"
    ENDPOINT = "ENDPOINT"
    TECHNOLOGY = "TECHNOLOGY"
    USER = "USER"
    DATABASE = "DATABASE"
    API_KEY = "API_KEY"


class EdgeRelation(str, Enum):
    HAS_CREDENTIAL = "has_credential"
    ACCESSIBLE_FROM = "accessible_from"
    VULNERABLE_TO = "vulnerable_to"
    LEADS_TO = "leads_to"
    RUNS_ON = "runs_on"
    EXPOSES = "exposes"
    AUTHENTICATES = "authenticates"
    CONTAINS = "contains"
    DISCOVERED_VIA = "discovered_via"
    RELATED_TO = "related_to"


class StepAction(str, Enum):
    FETCH_URL = "fetch_url"
    LOGIN = "login"
    EXPLOIT_SQLI = "exploit_sqli"
    EXPLOIT_XSS = "exploit_xss"
    EXPLOIT_RCE = "exploit_rce"
    EXPLOIT_LFI = "exploit_lfi"
    FUZZ_PARAMS = "fuzz_params"
    BRUTE_FORCE = "brute_force"
    NUCLEI_SCAN = "nuclei_scan"
    RECON = "recon"
    DUMP_DATABASE = "dump_database"
    ESCALATE_PRIVILEGE = "escalate_privilege"
    ENUMERATE_USERS = "enumerate_users"
    CUSTOM = "custom"


class StepStatus(str, Enum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    SKIPPED = "SKIPPED"
    HUMAN_INTERVENTION_REQUIRED = "HUMAN_INTERVENTION_REQUIRED"
    TIMEOUT = "TIMEOUT"


class PlanStatus(str, Enum):
    DRAFT = "DRAFT"
    AWAITING_APPROVAL = "AWAITING_APPROVAL"
    APPROVED = "APPROVED"
    EXECUTING = "EXECUTING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    ABORTED = "ABORTED"
    PARTIAL = "PARTIAL"


# ---------------------------------------------------------------------------
# Data Classes
# ---------------------------------------------------------------------------

@dataclass
class GraphNode:
    """Represents a single entity in the knowledge graph."""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    node_type: str = NodeType.URL.value
    label: str = ""
    attributes: Dict[str, Any] = field(default_factory=dict)
    source_module: str = ""
    source_task_id: str = ""
    created_at: float = field(default_factory=time.time)
    ttl: Optional[int] = None  # seconds; None = no expiry

    def __post_init__(self):
        # Validate node_type
        valid_types = {t.value for t in NodeType}
        if self.node_type not in valid_types:
            raise ValueError(
                f"Invalid node_type '{self.node_type}'. Must be one of {valid_types}"
            )
        if not self.label:
            self.label = f"{self.node_type}:{self.id[:8]}"

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        # Ensure attributes are JSON-serializable
        d["attributes"] = json.dumps(d["attributes"]) if isinstance(d["attributes"], dict) else d["attributes"]
        return d

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "GraphNode":
        if isinstance(data.get("attributes"), str):
            try:
                data["attributes"] = json.loads(data["attributes"])
            except (json.JSONDecodeError, TypeError):
                data["attributes"] = {}
        if isinstance(data.get("created_at"), str):
            try:
                data["created_at"] = float(data["created_at"])
            except (ValueError, TypeError):
                data["created_at"] = time.time()
        if isinstance(data.get("ttl"), str):
            data["ttl"] = int(data["ttl"]) if data["ttl"] != "None" else None
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})

    def fingerprint(self) -> str:
        """Deterministic ID based on type + key attributes for deduplication."""
        key_parts = [self.node_type]
        # Use specific attributes for fingerprinting based on type
        fp_keys = {
            NodeType.URL.value: ["url"],
            NodeType.CREDENTIAL.value: ["username", "password", "target"],
            NodeType.SESSION.value: ["token", "target"],
            NodeType.PORT.value: ["host", "port"],
            NodeType.HOST.value: ["hostname", "ip"],
            NodeType.VULNERABILITY.value: ["cve", "url", "vuln_type"],
            NodeType.PARAMETER.value: ["name", "url"],
            NodeType.FILE.value: ["path", "host"],
            NodeType.ENDPOINT.value: ["url", "method"],
            NodeType.TECHNOLOGY.value: ["name", "version"],
            NodeType.USER.value: ["username", "target"],
            NodeType.DATABASE.value: ["name", "host"],
            NodeType.API_KEY.value: ["key", "service"],
        }
        for k in fp_keys.get(self.node_type, []):
            val = self.attributes.get(k, "")
            if val:
                key_parts.append(f"{k}={val}")
        return ":".join(key_parts)


@dataclass
class GraphEdge:
    """Represents a relationship between two nodes."""
    from_id: str = ""
    to_id: str = ""
    relation: str = EdgeRelation.RELATED_TO.value
    attributes: Dict[str, Any] = field(default_factory=dict)
    created_at: float = field(default_factory=time.time)
    confidence: float = 1.0  # 0.0 to 1.0

    def __post_init__(self):
        valid_relations = {r.value for r in EdgeRelation}
        if self.relation not in valid_relations:
            raise ValueError(
                f"Invalid relation '{self.relation}'. Must be one of {valid_relations}"
            )
        if not (0.0 <= self.confidence <= 1.0):
            self.confidence = max(0.0, min(1.0, self.confidence))

    def edge_key(self) -> str:
        return f"{self.from_id}|{self.relation}|{self.to_id}"

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["attributes"] = json.dumps(d["attributes"]) if isinstance(d["attributes"], dict) else d["attributes"]
        return d

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "GraphEdge":
        if isinstance(data.get("attributes"), str):
            try:
                data["attributes"] = json.loads(data["attributes"])
            except (json.JSONDecodeError, TypeError):
                data["attributes"] = {}
        if isinstance(data.get("created_at"), str):
            try:
                data["created_at"] = float(data["created_at"])
            except (ValueError, TypeError):
                data["created_at"] = time.time()
        if isinstance(data.get("confidence"), str):
            try:
                data["confidence"] = float(data["confidence"])
            except (ValueError, TypeError):
                data["confidence"] = 1.0
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})


@dataclass
class PlanStep:
    """A single step in an attack plan."""
    step_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    order: int = 0
    action: str = StepAction.CUSTOM.value
    target: str = ""  # node ID or URL
    params: Dict[str, Any] = field(default_factory=dict)
    depends_on: List[str] = field(default_factory=list)  # step_ids
    status: str = StepStatus.PENDING.value
    result: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    started_at: Optional[float] = None
    completed_at: Optional[float] = None
    task_id: Optional[str] = None  # ID of spawned task
    queue_name: Optional[str] = None  # which queue the task was pushed to
    retry_count: int = 0
    max_retries: int = 1

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        for k in ("params", "result"):
            if isinstance(d.get(k), dict):
                d[k] = json.dumps(d[k])
            elif d.get(k) is None:
                d[k] = ""
        if isinstance(d.get("depends_on"), list):
            d["depends_on"] = json.dumps(d["depends_on"])
        return d

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "PlanStep":
        for k in ("params", "result"):
            if isinstance(data.get(k), str):
                try:
                    data[k] = json.loads(data[k]) if data[k] else None
                except (json.JSONDecodeError, TypeError):
                    data[k] = {} if k == "params" else None
        if isinstance(data.get("depends_on"), str):
            try:
                data["depends_on"] = json.loads(data["depends_on"]) if data["depends_on"] else []
            except (json.JSONDecodeError, TypeError):
                data["depends_on"] = []
        for k in ("order", "retry_count", "max_retries"):
            if isinstance(data.get(k), str):
                try:
                    data[k] = int(data[k])
                except (ValueError, TypeError):
                    data[k] = 0
        for k in ("started_at", "completed_at"):
            if isinstance(data.get(k), str):
                try:
                    data[k] = float(data[k]) if data[k] else None
                except (ValueError, TypeError):
                    data[k] = None
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})


@dataclass
class AttackPlan:
    """An ordered collection of steps forming an attack chain."""
    plan_id: str = field(default_factory=lambda: f"plan_{uuid.uuid4().hex[:12]}")
    goal: str = ""
    steps: List[PlanStep] = field(default_factory=list)
    status: str = PlanStatus.DRAFT.value
    created_at: float = field(default_factory=time.time)
    approved_at: Optional[float] = None
    approved_by: Optional[str] = None  # "auto" or human ID
    completed_at: Optional[float] = None
    source: str = "ai_planner"  # "ai_planner" or "static_template"
    metadata: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "plan_id": self.plan_id,
            "goal": self.goal,
            "steps": [s.to_dict() for s in self.steps],
            "status": self.status,
            "created_at": self.created_at,
            "approved_at": self.approved_at,
            "approved_by": self.approved_by,
            "completed_at": self.completed_at,
            "source": self.source,
            "metadata": json.dumps(self.metadata),
            "error": self.error or "",
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AttackPlan":
        steps_raw = data.pop("steps", [])
        if isinstance(steps_raw, str):
            try:
                steps_raw = json.loads(steps_raw)
            except (json.JSONDecodeError, TypeError):
                steps_raw = []
        steps = []
        for s in steps_raw:
            if isinstance(s, dict):
                steps.append(PlanStep.from_dict(s))
            elif isinstance(s, PlanStep):
                steps.append(s)
        if isinstance(data.get("metadata"), str):
            try:
                data["metadata"] = json.loads(data["metadata"])
            except (json.JSONDecodeError, TypeError):
                data["metadata"] = {}
        for k in ("created_at", "approved_at", "completed_at"):
            if isinstance(data.get(k), str):
                try:
                    data[k] = float(data[k]) if data[k] else None
                except (ValueError, TypeError):
                    data[k] = None
        valid_keys = {f for f in cls.__dataclass_fields__ if f != "steps"}
        filtered = {k: v for k, v in data.items() if k in valid_keys}
        return cls(steps=steps, **filtered)

    @property
    def steps_attempted(self) -> int:
        return sum(
            1 for s in self.steps
            if s.status not in (StepStatus.PENDING.value, StepStatus.SKIPPED.value)
        )

    @property
    def steps_succeeded(self) -> int:
        return sum(1 for s in self.steps if s.status == StepStatus.COMPLETED.value)

    @property
    def steps_failed(self) -> int:
        return sum(1 for s in self.steps if s.status == StepStatus.FAILED.value)

    def has_cycle(self) -> bool:
        """Detect cycles in step dependencies."""
        visited = set()
        rec_stack = set()
        adj: Dict[str, List[str]] = {s.step_id: s.depends_on for s in self.steps}

        def dfs(node: str) -> bool:
            visited.add(node)
            rec_stack.add(node)
            for dep in adj.get(node, []):
                if dep not in visited:
                    if dfs(dep):
                        return True
                elif dep in rec_stack:
                    return True
            rec_stack.discard(node)
            return False

        for step in self.steps:
            if step.step_id not in visited:
                if dfs(step.step_id):
                    return True
        return False
