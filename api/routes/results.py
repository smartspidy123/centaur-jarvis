from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from typing import List, Optional

from ..dependencies import get_db
from ..models import FindingResponse
from ..db_models import Finding, Scan

router = APIRouter(prefix="/results", tags=["results"])


@router.get("/findings", response_model=List[FindingResponse])
async def get_all_findings(
    severity: Optional[str] = Query(None, regex="^(CRITICAL|HIGH|MEDIUM|LOW|INFO)$"),
    scan_id: Optional[str] = None,
    type: Optional[str] = None,
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    db: AsyncSession = Depends(get_db),
):
    """Get findings across all scans with filters."""
    query = select(Finding)
    if severity:
        query = query.where(Finding.severity == severity)
    if scan_id:
        query = query.where(Finding.scan_id == scan_id)
    if type:
        query = query.where(Finding.type == type)
    
    query = query.order_by(Finding.timestamp.desc()).offset(skip).limit(limit)
    result = await db.execute(query)
    findings = result.scalars().all()
    return [
        FindingResponse(
            id=f.id,
            scan_id=f.scan_id,
            severity=f.severity,
            type=f.type,
            endpoint=f.endpoint,
            payload=f.payload,
            evidence=f.evidence,
            timestamp=f.timestamp,
        )
        for f in findings
    ]


@router.get("/stats")
async def get_findings_stats(db: AsyncSession = Depends(get_db)):
    """Get aggregated statistics about findings."""
    # Count by severity
    severity_stmt = select(Finding.severity, func.count(Finding.id)).group_by(Finding.severity)
    severity_result = await db.execute(severity_stmt)
    severity_counts = {row[0]: row[1] for row in severity_result.all()}
    
    # Total findings
    total_stmt = select(func.count(Finding.id))
    total_result = await db.execute(total_stmt)
    total = total_result.scalar() or 0
    
    return {
        "total_findings": total,
        "by_severity": severity_counts,
        "by_type": {},  # could add later
    }
