"""
Pydantic models for API requests/responses and SQLAlchemy ORM models.
"""

from datetime import datetime
from typing import Optional, List, Dict, Any
from enum import Enum
from pydantic import BaseModel, Field
import uuid


# ---------- Enums ----------
class ScanStatus(str, Enum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


# ---------- Pydantic Request/Response Models ----------

class ScanCreate(BaseModel):
    target: str = Field(..., description="Target URL or domain")
    profile: str = Field(default="default", description="Scan profile")
    scan_id: Optional[str] = Field(default=None, description="Optional custom scan ID")


class ScanResponse(BaseModel):
    scan_id: str
    target: str
    profile: str
    status: ScanStatus
    start_time: datetime
    end_time: Optional[datetime] = None
    summary_stats: Optional[Dict[str, Any]] = None


class FindingResponse(BaseModel):
    id: int
    scan_id: str
    severity: Severity
    type: str
    endpoint: str
    payload: Optional[str] = None
    evidence: Optional[str] = None
    timestamp: datetime


class StatsResponse(BaseModel):
    total_scans: int
    total_findings: int
    findings_by_severity: Dict[str, int]
    scans_by_status: Dict[str, int]
    redis_connected: bool


class HealthResponse(BaseModel):
    status: str
    redis: bool
    database: bool
    timestamp: datetime


class WebSocketMessage(BaseModel):
    type: str  # "finding", "progress", "log"
    data: Dict[str, Any]


# ---------- SQLAlchemy Models (for database) ----------
# We'll define these in a separate module or later.
# For now, placeholder.
