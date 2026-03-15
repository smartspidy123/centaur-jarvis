"""
shared/schemas.py — Canonical Data Models for Centaur-Jarvis
=============================================================

Pydantic models with validation for all inter-module communication.
Every schema enforces strict typing so invalid data never propagates.
"""

from pydantic import BaseModel, Field, field_validator
from typing import Optional, Dict, Any, List
from enum import Enum
from datetime import datetime
import uuid


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

class TaskType(str, Enum):
    """All possible task types across all modules."""
    # Reconnaissance
    RECON_SUBDOMAIN = "RECON_SUBDOMAIN"
    RECON_PORT_SCAN = "RECON_PORT_SCAN"
    RECON_TECH_DETECT = "RECON_TECH_DETECT"
    RECON_CRAWL = "RECON_CRAWL"
    RECON_HTTPX = "RECON_HTTPX"
    RECON_NUCLEI = "RECON_NUCLEI"
    RECON_PORTSCAN = "RECON_PORTSCAN"  # alias for port scan
    
    # AI Analysis
    JS_ANALYSIS = "JS_ANALYSIS"
    IDOR_CHECK = "IDOR_CHECK"
    FUZZ = "FUZZ"
    
    # Exploit / Payload
    NUCLEI_TEMPLATE_GEN = "NUCLEI_TEMPLATE_GEN"
    
    # Dynamic Rendering
    PLAYWRIGHT_RENDER = "PLAYWRIGHT_RENDER"
    
    # Generic / Fallback
    GENERIC = "GENERIC"


class TaskStatus(str, Enum):
    """Lifecycle states of a task."""
    PENDING = "PENDING"
    QUEUED = "QUEUED"
    PROCESSING = "PROCESSING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    RETRY = "RETRY"
    DEAD = "DEAD"
    DELAYED = "DELAYED"
    TIMEOUT = "TIMEOUT"
    CANCELLED = "CANCELLED"


class ErrorType(str, Enum):
    """Standardised error types for TaskResult."""
    NONE = "NONE"
    TOOL_MISSING = "TOOL_MISSING"
    TOOL_ERROR = "TOOL_ERROR"
    TIMEOUT = "TIMEOUT"
    INVALID_TARGET = "INVALID_TARGET"
    PARSE_ERROR = "PARSE_ERROR"
    RESOURCE_EXHAUSTED = "RESOURCE_EXHAUSTED"
    REDIS_ERROR = "REDIS_ERROR"
    CONNECTION_ERROR = "CONNECTION_ERROR"
    SERVER_ERROR_5XX = "SERVER_ERROR_5XX"
    WAF_BLOCK_403 = "WAF_BLOCK_403"
    RATE_LIMIT_429 = "RATE_LIMIT_429"
    UNKNOWN = "UNKNOWN"


# ---------------------------------------------------------------------------
# Core Models
# ---------------------------------------------------------------------------

class Task(BaseModel):
    """
    A unit of work submitted to the orchestrator.
    All fields are validated at construction.
    """
    task_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    type: TaskType
    target: str
    params: Dict[str, Any] = Field(default_factory=dict)
    priority: int = 0
    webhook_url: Optional[str] = None
    retry_count: int = 0
    max_retries: int = 3
    created_at: datetime = Field(default_factory=datetime.utcnow)
    metadata: Dict[str, Any] = Field(default_factory=dict)

    @field_validator('target')
    @classmethod
    def validate_target(cls, v: str) -> str:
        """Basic target validation — orchestrator does deeper checks."""
        if not v or not v.strip():
            raise ValueError('target cannot be empty')
        return v.strip()

    def to_dict(self) -> Dict[str, Any]:
        """Convert to JSON-serializable dict (for Redis)."""
        data = self.model_dump()
        data['type'] = self.type.value
        data['created_at'] = self.created_at.isoformat()
        return data

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Task':
        """Create Task from dict (e.g., parsed JSON from Redis)."""
        # Convert string type to Enum
        if 'type' in data and isinstance(data['type'], str):
            data['type'] = TaskType(data['type'])
        # Convert string datetime to datetime object
        if 'created_at' in data and isinstance(data['created_at'], str):
            data['created_at'] = datetime.fromisoformat(data['created_at'])
        return cls(**data)


class TaskResult(BaseModel):
    """
    Result of a task execution, pushed to results queue.
    """
    task_id: str
    status: TaskStatus
    data: Dict[str, Any] = Field(default_factory=dict)
    error: Optional[str] = None
    error_type: ErrorType = ErrorType.NONE
    worker_id: Optional[str] = None
    execution_time: float = 0.0  # seconds
    completed_at: datetime = Field(default_factory=datetime.utcnow)
    tool_version: str = ""
    raw_output_lines: int = 0
    parse_warnings: List[str] = Field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        data = self.model_dump()
        data['status'] = self.status.value
        data['error_type'] = self.error_type.value
        data['completed_at'] = self.completed_at.isoformat()
        return data

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'TaskResult':
        if 'status' in data and isinstance(data['status'], str):
            data['status'] = TaskStatus(data['status'])
        if 'error_type' in data and isinstance(data['error_type'], str):
            data['error_type'] = ErrorType(data['error_type'])
        if 'completed_at' in data and isinstance(data['completed_at'], str):
            data['completed_at'] = datetime.fromisoformat(data['completed_at'])
        return cls(**data)