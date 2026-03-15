"""
shared/logger.py
================
Structured JSON logging for every Centaur-Jarvis module.

Features:
  - JSON-formatted log records for machine parsing
  - Automatic context injection (module, worker_id, timestamp)
  - File + console handlers with independent levels
  - Thread-safe, re-entrant
"""

from __future__ import annotations

import json
import logging
import os
import sys
import time
from typing import Any, Dict, Optional


class JSONFormatter(logging.Formatter):
    """Emit each log record as a single JSON line."""

    def format(self, record: logging.LogRecord) -> str:
        log_entry: Dict[str, Any] = {
            "timestamp": self.formatTime(record, self.datefmt),
            "level": record.levelname,
            "module": record.module,
            "func": record.funcName,
            "line": record.lineno,
            "message": record.getMessage(),
        }
        # Merge any extra context attached by callers
        if hasattr(record, "context"):
            log_entry["context"] = record.context
        if record.exc_info and record.exc_info[0] is not None:
            log_entry["exception"] = self.formatException(record.exc_info)
        return json.dumps(log_entry, default=str)


def get_logger(
    name: str,
    level: str = "INFO",
    log_file: Optional[str] = None,
    worker_id: Optional[str] = None,
) -> logging.Logger:
    """
    Return a configured ``logging.Logger`` instance.

    Parameters
    ----------
    name : str
        Logger name (usually ``__name__`` of the calling module).
    level : str
        Minimum severity: DEBUG | INFO | WARNING | ERROR | CRITICAL.
    log_file : str, optional
        Path to a log file.  If ``None``, only console output is used.
    worker_id : str, optional
        Injected into every record for correlation.
    """
    logger = logging.getLogger(name)

    # Prevent duplicate handlers when called multiple times
    if logger.handlers:
        return logger

    logger.setLevel(getattr(logging, level.upper(), logging.INFO))
    formatter = JSONFormatter()

    # Console handler — always present
    console = logging.StreamHandler(sys.stdout)
    console.setFormatter(formatter)
    logger.addHandler(console)

    # File handler — optional
    if log_file:
        os.makedirs(os.path.dirname(log_file) or ".", exist_ok=True)
        fh = logging.FileHandler(log_file, encoding="utf-8")
        fh.setFormatter(formatter)
        logger.addHandler(fh)

    # Inject worker_id via a filter
    if worker_id:
        class WorkerFilter(logging.Filter):
            def filter(self, record: logging.LogRecord) -> bool:
                record.worker_id = worker_id  # type: ignore[attr-defined]
                return True
        logger.addFilter(WorkerFilter())

    return logger