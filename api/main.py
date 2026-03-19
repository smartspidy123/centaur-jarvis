import asyncio
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
import uvicorn

from .config import settings
from .dependencies import init_db, close_redis
from .routes import scans, results, status, websocket
from shared.logger import get_logger

logger = get_logger(__name__)

app = FastAPI(
    title="Centaur-Jarvis Web API",
    description="Web UI backend for Centaur-Jarvis VAPT agent",
    version="1.0.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json",
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://localhost:8000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(scans.router, prefix="/api")
app.include_router(results.router, prefix="/api")
app.include_router(status.router, prefix="/api")

# Include WebSocket router at root level (no prefix) - BEFORE static files
app.include_router(websocket.router)

# Mount frontend static files
app.mount("/", StaticFiles(directory=settings.FRONTEND_DIR, html=True), name="frontend")


@app.on_event("startup")
async def startup_event():
    """Initialize database and start background tasks."""
    logger.info("Starting Centaur-Jarvis Web API")
    await init_db()
    # Start result consumer in background
    asyncio.create_task(websocket.result_consumer())


@app.on_event("shutdown")
async def shutdown_event():
    """Cleanup on shutdown."""
    close_redis()
    logger.info("Shutting down Centaur-Jarvis Web API")


@app.get("/")
def root():
    return {"message": "Centaur-Jarvis Web API", "docs": "/api/docs"}


if __name__ == "__main__":
    uvicorn.run(
        "api.main:app",
        host=settings.API_HOST,
        port=settings.API_PORT,
        reload=settings.DEBUG,
    )
