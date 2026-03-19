"""
Configuration loader for the web API.
Loads settings from environment variables with defaults.
"""

import os
from typing import Optional
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    # Redis configuration
    REDIS_HOST: str = os.getenv("REDIS_HOST", "127.0.0.1")
    REDIS_PORT: int = int(os.getenv("REDIS_PORT", 6379))
    REDIS_DB: int = int(os.getenv("REDIS_DB", 0))
    REDIS_PASSWORD: Optional[str] = os.getenv("REDIS_PASSWORD", None)
    REDIS_SOCKET_TIMEOUT: int = int(os.getenv("REDIS_SOCKET_TIMEOUT", 5))
    REDIS_SOCKET_CONNECT_TIMEOUT: int = int(os.getenv("REDIS_SOCKET_CONNECT_TIMEOUT", 5))
    REDIS_MAX_CONNECTIONS: int = int(os.getenv("REDIS_MAX_CONNECTIONS", 50))
    REDIS_RETRY_ON_TIMEOUT: bool = os.getenv("REDIS_RETRY_ON_TIMEOUT", "true").lower() == "true"

    # Database (SQLite)
    DATABASE_URL: str = os.getenv("DATABASE_URL", "sqlite:///./centaur.db")

    # API server
    API_HOST: str = os.getenv("API_HOST", "0.0.0.0")
    API_PORT: int = int(os.getenv("API_PORT", 8000))
    DEBUG: bool = os.getenv("DEBUG", "false").lower() == "true"

    # Frontend static files path
    FRONTEND_DIR: str = os.getenv("FRONTEND_DIR", "./frontend/dist")

    # Frontend base URL for static assets
    FRONTEND_BASE_URL: str = os.getenv("FRONTEND_BASE_URL", "/")

    # Scan CLI command
    CLI_COMMAND: str = os.getenv("CLI_COMMAND", "python -m cli.main")

    class Config:
        env_file = ".env"
        extra = "ignore"


settings = Settings()
