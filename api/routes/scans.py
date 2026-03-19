import uuid
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from typing import List, Optional

from ..dependencies import get_db, get_redis
from ..models import ScanCreate, ScanResponse, FindingResponse
from ..db_models import Scan, Finding
from ..utils.task_runner import start_scan_via_cli, create_scan_in_db
from shared.logger import get_logger

router = APIRouter(prefix="/scans", tags=["scans"])
logger = get_logger(__name__)


@router.post("", response_model=ScanResponse, status_code=202)
async def create_scan(
    scan_data: ScanCreate,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
):
    """Start a new scan."""
    scan_id = scan_data.scan_id or str(uuid.uuid4())
    # Check if scan already exists
    stmt = select(Scan).where(Scan.scan_id == scan_id)
    result = await db.execute(stmt)
    existing = result.scalar_one_or_none()
    if existing:
        raise HTTPException(status_code=409, detail=f"Scan {scan_id} already exists")
    
    # Create scan in DB
    scan = await create_scan_in_db(db, scan_id, scan_data.target, scan_data.profile)
    
    # Start scan in background
    background_tasks.add_task(start_scan_via_cli, scan_data.target, scan_data.profile, scan_id)
    
    return ScanResponse(
        scan_id=scan.scan_id,
        target=scan.target,
        profile=scan.profile,
        status=scan.status,
        start_time=scan.start_time,
        end_time=scan.end_time,
        summary_stats=scan.summary_stats,
    )


@router.get("", response_model=List[ScanResponse])
async def list_scans(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    db: AsyncSession = Depends(get_db),
):
    """List all scans with pagination."""
    stmt = select(Scan).order_by(Scan.start_time.desc()).offset(skip).limit(limit)
    result = await db.execute(stmt)
    scans = result.scalars().all()
    return [
        ScanResponse(
            scan_id=s.scan_id,
            target=s.target,
            profile=s.profile,
            status=s.status,
            start_time=s.start_time,
            end_time=s.end_time,
            summary_stats=s.summary_stats,
        )
        for s in scans
    ]


@router.get("/{scan_id}", response_model=ScanResponse)
async def get_scan(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
):
    """Get details of a specific scan."""
    stmt = select(Scan).where(Scan.scan_id == scan_id)
    result = await db.execute(stmt)
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return ScanResponse(
        scan_id=scan.scan_id,
        target=scan.target,
        profile=scan.profile,
        status=scan.status,
        start_time=scan.start_time,
        end_time=scan.end_time,
        summary_stats=scan.summary_stats,
    )


@router.delete("/{scan_id}", status_code=204)
async def delete_scan(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
):
    """Delete a scan and its findings."""
    stmt = select(Scan).where(Scan.scan_id == scan_id)
    result = await db.execute(stmt)
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    await db.delete(scan)
    await db.commit()
    return None


@router.patch("/{scan_id}/pause")
async def pause_scan(scan_id: str, db: AsyncSession = Depends(get_db)):
    """Pause a running scan."""
    stmt = select(Scan).where(Scan.scan_id == scan_id)
    result = await db.execute(stmt)
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    if scan.status != "RUNNING":
        raise HTTPException(status_code=400, detail="Can only pause running scans")
    
    scan.status = "PAUSED"
    await db.commit()
    
    return {"message": f"Scan {scan_id} paused successfully", "status": "PAUSED"}


@router.patch("/{scan_id}/resume")
async def resume_scan(scan_id: str, db: AsyncSession = Depends(get_db)):
    """Resume a paused scan."""
    stmt = select(Scan).where(Scan.scan_id == scan_id)
    result = await db.execute(stmt)
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    if scan.status != "PAUSED":
        raise HTTPException(status_code=400, detail="Can only resume paused scans")
    
    scan.status = "RUNNING"
    await db.commit()
    
    return {"message": f"Scan {scan_id} resumed successfully", "status": "RUNNING"}


@router.get("/{scan_id}/findings", response_model=List[FindingResponse])
async def list_findings(
    scan_id: str,
    severity: Optional[str] = Query(None, regex="^(CRITICAL|HIGH|MEDIUM|LOW|INFO)$"),
    type: Optional[str] = None,
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    db: AsyncSession = Depends(get_db),
):
    """List findings for a scan with optional filters."""
    # Verify scan exists
    stmt = select(Scan).where(Scan.scan_id == scan_id)
    result = await db.execute(stmt)
    if not result.scalar_one_or_none():
        raise HTTPException(status_code=404, detail="Scan not found")
    
    query = select(Finding).where(Finding.scan_id == scan_id)
    if severity:
        query = query.where(Finding.severity == severity)
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
