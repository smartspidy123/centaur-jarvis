import subprocess
import threading
import uuid
from typing import Optional
from datetime import datetime, timezone
from ..dependencies import get_redis
from ..db_models import Scan
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
import asyncio
from shared.logger import get_logger

logger = get_logger(__name__)


def start_scan_via_cli(target: str, profile: str = "default", scan_id: Optional[str] = None) -> str:
    """
    Start a scan by pushing tasks through the orchestrator system.
    Returns scan_id.
    """
    if scan_id is None:
        scan_id = str(uuid.uuid4())
    
    logger.info(f"Starting scan {scan_id} for target {target} with profile {profile}")
    
    # Run scan in background thread
    def run():
        try:
            # Import orchestrator and scan controller
            from core.orchestrator import Orchestrator, Task, TaskType
            from cli.scan_controller import ScanController
            from cli.main import load_config
            
            # Load configuration
            config = load_config()
            
            # Initialize scan controller
            controller = ScanController(config=config)
            controller.scan_id = scan_id
            
            # Initialize scan
            if not controller.initialize_scan(
                target_input=target,
                profile_name=profile,
                scan_id=scan_id,
            ):
                logger.error(f"Scan {scan_id} initialization failed")
                async def update_db_status():
                    from ..dependencies import AsyncSessionLocal
                    async with AsyncSessionLocal() as session:
                        await update_scan_status(session, scan_id, "FAILED")
                
                import asyncio
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                loop.run_until_complete(update_db_status())
                loop.close()
                return
            
            # Mark scan as RUNNING
            async def update_db_status():
                from ..dependencies import AsyncSessionLocal
                async with AsyncSessionLocal() as session:
                    await update_scan_status(session, scan_id, "RUNNING")
            
            import asyncio
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            loop.run_until_complete(update_db_status())
            loop.close()
            
            # Get tasks from scan controller and push through orchestrator
            logger.info(f"Starting scan execution for {scan_id} via orchestrator")
            
            # Get phase tasks and push them through orchestrator
            phases = controller.profile_phases
            for phase in phases:
                tasks = controller._get_phase_tasks(phase)
                for task_def in tasks:
                    tool = task_def["tool"]
                    params = task_def.get("params", {})
                    
                    # Create orchestrator task
                    task_id = f"{scan_id}_{tool}_{uuid.uuid4().hex[:6]}"
                    
                    # Map tools to appropriate TaskType (matching recon worker's TASK_DISPATCH)
                    if tool == "nuclei":
                        task_type = TaskType.RECON_NUCLEI
                    elif tool == "httpx":
                        task_type = TaskType.RECON_HTTPX
                    elif tool == "subfinder":
                        task_type = TaskType.RECON_SUBDOMAIN
                    elif tool == "naabu":
                        task_type = TaskType.RECON_PORTSCAN
                    else:
                        task_type = TaskType.GENERIC
                    
                    task = Task(
                        task_id=task_id,
                        type=task_type,
                        target=target,
                        params=params,
                        retry_count=0,
                        metadata={
                            "scan_id": scan_id,
                            "phase": phase,
                            "tool": tool
                        }
                    )
                    
                    # Use the running orchestrator instance by pushing task directly to Redis
                    # The orchestrator running in Terminal 3 will pick it up
                    import redis
                    import json
                    
                    # Connect to Redis
                    r = redis.Redis(host='localhost', port=6379, db=0, decode_responses=True)
                    
                    # Push task to the appropriate queue - use the queue name that recon worker listens to
                    queue_name = "queue:recon"
                    task_json = json.dumps({
                        "task_id": task.task_id,
                        "type": task.type,
                        "target": task.target,
                        "params": task.params,
                        "metadata": task.metadata,
                        "retry_count": task.retry_count,
                        "created_at": task.created_at.isoformat() if hasattr(task.created_at, 'isoformat') else task.created_at
                    })
                    
                    r.lpush(queue_name, task_json)
                    logger.info(f"Task {task_id} pushed to {queue_name}")
            
            # Wait for tasks to complete
            logger.info(f"Scan {scan_id} tasks submitted to orchestrator")
            
            # For now, mark as completed since orchestrator handles execution
            final_status = "RUNNING"  # Let orchestrator handle completion
            logger.info(f"Scan {scan_id} submitted to orchestrator workflow")
            
            # Update status to RUNNING (orchestrator will update to COMPLETED)
            async def update_final_status():
                from ..dependencies import AsyncSessionLocal
                async with AsyncSessionLocal() as session:
                    await update_scan_status(session, scan_id, final_status)
            
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            loop.run_until_complete(update_final_status())
            loop.close()
            
        except Exception as e:
            logger.error(f"Failed to run scan {scan_id}: {e}")
            
            # Mark as FAILED on exception
            async def update_failed_status():
                from ..dependencies import AsyncSessionLocal
                async with AsyncSessionLocal() as session:
                    await update_scan_status(session, scan_id, "FAILED")
            
            import asyncio
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            loop.run_until_complete(update_failed_status())
            loop.close()
    
    # Start scan thread as non-daemon to prevent premature termination
    thread = threading.Thread(target=run, daemon=False)
    thread.start()
    return scan_id


async def create_scan_in_db(session: AsyncSession, scan_id: str, target: str, profile: str) -> Scan:
    """
    Create a scan record in the database.
    """
    scan = Scan(
        scan_id=scan_id,
        target=target,
        profile=profile,
        status="RUNNING",
        summary_stats={}
    )
    session.add(scan)
    await session.commit()
    await session.refresh(scan)
    return scan


async def update_scan_status(session: AsyncSession, scan_id: str, status: str, summary: Optional[dict] = None) -> None:
    """
    Update scan status in database.
    """
    stmt = select(Scan).where(Scan.scan_id == scan_id)
    result = await session.execute(stmt)
    scan = result.scalar_one_or_none()
    if scan:
        scan.status = status
        if summary is not None:
            scan.summary_stats = summary
        if status in ["COMPLETED", "FAILED", "CANCELLED"]:
            from datetime import datetime
            scan.end_time = datetime.utcnow()
        await session.commit()
        logger.info(f"Updated scan {scan_id} status to {status}")
    else:
        logger.warning(f"Scan {scan_id} not found in database")
