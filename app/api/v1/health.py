import os
from fastapi import APIRouter
import redis
from typing import Dict

router = APIRouter()

def check_redis() -> Dict[str, str]:
    """
    Check Redis connection status.
    
    Returns:
        Dict containing status and message
    """
    url = os.getenv("REDIS_URL")
    if not url:
        return {"status": "error", "message": "REDIS_URL environment variable not set"}
    
    try:
        r = redis.from_url(url, socket_connect_timeout=2)
        r.ping()
        return {"status": "ok", "message": "Redis connection successful"}
    except redis.exceptions.ConnectionError as e:
        return {"status": "error", "message": f"Redis connection failed: {str(e)}"}
    except Exception as e:
        return {"status": "error", "message": f"Unexpected error: {str(e)}"}

@router.get("/health")
async def health() -> Dict[str, str]:
    """
    Health check endpoint that verifies API and Redis status.
    
    Returns:
        Dict containing overall status and component details
    """
    redis_status = check_redis()
    
    return {
        "status": "ok" if redis_status["status"] == "ok" else "degraded",
        "api": "ok",
        "redis": redis_status
    }