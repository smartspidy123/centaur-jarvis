import asyncio
import json
from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Depends
from typing import Dict, Any

from ..dependencies import get_redis
from ..utils.redis_client import pop_result, get_scan_status
from shared.logger import get_logger

router = APIRouter()
logger = get_logger(__name__)


class ConnectionManager:
    def __init__(self):
        self.active_connections: Dict[str, WebSocket] = {}

    async def connect(self, websocket: WebSocket, scan_id: str):
        await websocket.accept()
        self.active_connections[scan_id] = websocket
        logger.info(f"WebSocket connected for scan {scan_id}")

    def disconnect(self, scan_id: str):
        if scan_id in self.active_connections:
            del self.active_connections[scan_id]
            logger.info(f"WebSocket disconnected for scan {scan_id}")

    async def send_message(self, scan_id: str, message: Dict[str, Any]):
        websocket = self.active_connections.get(scan_id)
        if websocket:
            try:
                await websocket.send_json(message)
            except Exception as e:
                logger.error(f"Failed to send message to {scan_id}: {e}")
                self.disconnect(scan_id)

    async def broadcast(self, message: Dict[str, Any]):
        for scan_id, websocket in list(self.active_connections.items()):
            try:
                await websocket.send_json(message)
            except Exception:
                self.disconnect(scan_id)


manager = ConnectionManager()


@router.websocket("/ws/{scan_id}")
async def websocket_endpoint(websocket: WebSocket, scan_id: str):
    await manager.connect(websocket, scan_id)
    try:
        # Send initial status
        status = get_scan_status(scan_id)
        if status:
            await websocket.send_json({"type": "status", "data": status})
        
        # Keep connection alive and forward incoming results
        while True:
            # Wait for any incoming message from client (optional)
            data = await websocket.receive_text()
            # Could handle client commands later
    except WebSocketDisconnect:
        manager.disconnect(scan_id)
    except Exception as e:
        logger.error(f"WebSocket error for {scan_id}: {e}")
        manager.disconnect(scan_id)


async def result_consumer():
    """Background task that consumes results from Redis and forwards to WebSocket."""
    while True:
        result = pop_result()
        if result:
            # Determine scan_id from result (maybe in metadata)
            scan_id = result.get("scan_id") or result.get("task_id")
            if scan_id:
                await manager.send_message(scan_id, {"type": "finding", "data": result})
            else:
                # Broadcast to all connections
                await manager.broadcast({"type": "finding", "data": result})
        await asyncio.sleep(0.5)  # Poll interval
