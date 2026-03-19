from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from datetime import datetime

from ..dependencies import get_db, get_redis
from ..models import StatsResponse, HealthResponse
from ..db_models import Scan, Finding

router = APIRouter(prefix="/status", tags=["status"])


@router.get("/health", response_model=HealthResponse)
async def health_check():
    """Check health of API, Redis, and database."""
    redis_ok = False
    db_ok = False
    try:
        redis_client = get_redis()
        redis_client.ping()
        redis_ok = True
    except Exception:
        pass
    
    # Check database connectivity
    try:
        from ..dependencies import AsyncSessionLocal
        async with AsyncSessionLocal() as session:
            await session.execute(select(1))
            db_ok = True
    except Exception:
        pass
    
    overall = "OK" if redis_ok and db_ok else "DEGRADED"
    return HealthResponse(
        status=overall,
        redis=redis_ok,
        database=db_ok,
        timestamp=datetime.utcnow(),
    )


@router.get("/stats", response_model=StatsResponse)
async def global_stats(db: AsyncSession = Depends(get_db)):
    """Get global statistics."""
    # Total scans
    total_scans_stmt = select(func.count(Scan.id))
    total_scans_result = await db.execute(total_scans_stmt)
    total_scans = total_scans_result.scalar() or 0
    
    # Total findings
    total_findings_stmt = select(func.count(Finding.id))
    total_findings_result = await db.execute(total_findings_stmt)
    total_findings = total_findings_result.scalar() or 0
    
    # Findings by severity
    severity_stmt = select(Finding.severity, func.count(Finding.id)).group_by(Finding.severity)
    severity_result = await db.execute(severity_stmt)
    findings_by_severity = {row[0]: row[1] for row in severity_result.all()}
    
    # Scans by status
    status_stmt = select(Scan.status, func.count(Scan.id)).group_by(Scan.status)
    status_result = await db.execute(status_stmt)
    scans_by_status = {row[0]: row[1] for row in status_result.all()}
    
    # Redis connection
    redis_connected = False
    try:
        redis_client = get_redis()
        redis_client.ping()
        redis_connected = True
    except Exception:
        pass
    
    return StatsResponse(
        total_scans=total_scans,
        total_findings=total_findings,
        findings_by_severity=findings_by_severity,
        scans_by_status=scans_by_status,
        redis_connected=redis_connected,
    )
