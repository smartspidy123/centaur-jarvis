"""
Redis helper functions for reading results and status.
"""

import json
from typing import Optional, Dict, Any
from ..dependencies import get_redis
from shared.logger import get_logger

logger = get_logger(__name__)


def get_scan_status(scan_id: str) -> Optional[Dict[str, Any]]:
    """
    Retrieve status hash for a scan from Redis.
    Key: task:status:<scan_id>
    """
    redis_client = get_redis()
    key = f"task:status:{scan_id}"
    try:
        status = redis_client.hgetall(key)
        if status:
            # Convert bytes to str
            return {k.decode() if isinstance(k, bytes) else k: 
                    v.decode() if isinstance(v, bytes) else v 
                    for k, v in status.items()}
    except Exception as e:
        logger.error(f"Failed to get scan status {scan_id}: {e}")
    return None


def pop_result() -> Optional[Dict[str, Any]]:
    """
    Pop a result from jarvis:results queue (non-blocking).
    Returns parsed JSON dict or None if empty.
    """
    redis_client = get_redis()
    try:
        result = redis_client.lpop("jarvis:results")
        if result:
            data = json.loads(result)
            # Ensure data field exists
            if "data" not in data:
                data["data"] = {}
            return data
    except json.JSONDecodeError as e:
        logger.error(f"Invalid JSON in jarvis:results: {e}")
    except Exception as e:
        logger.error(f"Failed to pop result: {e}")
    return None


def get_scan_progress(scan_id: str) -> Optional[Dict[str, Any]]:
    """
    Get progress information for a scan from Redis.
    Looks for keys like task:status:<scan_id>:progress.
    """
    redis_client = get_redis()
    key = f"task:status:{scan_id}:progress"
    try:
        progress = redis_client.get(key)
        if progress:
            return json.loads(progress)
    except Exception as e:
        logger.error(f"Failed to get scan progress {scan_id}: {e}")
    return None


def publish_websocket_message(channel: str, message: Dict[str, Any]) -> None:
    """
    Publish a message to Redis pub/sub channel (optional).
    """
    redis_client = get_redis()
    try:
        redis_client.publish(channel, json.dumps(message))
    except Exception as e:
        logger.error(f"Failed to publish to channel {channel}: {e}")
