"""
Structured logging configuration for AgentShield.
Call setup_logging() once at application startup.
"""

import logging
import logging.handlers
import sys
from pathlib import Path


def setup_logging(log_level: str = "INFO", log_file: Path | None = None) -> None:
    """Configure root logger with console + optional rotating file handler."""
    numeric_level = getattr(logging, log_level.upper(), logging.INFO)

    fmt = logging.Formatter(
        fmt="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
    )

    root = logging.getLogger()
    root.setLevel(numeric_level)

    # Console handler
    console = logging.StreamHandler(sys.stdout)
    console.setLevel(numeric_level)
    console.setFormatter(fmt)
    root.addHandler(console)

    # Rotating file handler (optional)
    if log_file is not None:
        log_file.parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.handlers.RotatingFileHandler(
            log_file,
            maxBytes=10 * 1024 * 1024,  # 10 MB
            backupCount=5,
            encoding="utf-8",
        )
        file_handler.setLevel(numeric_level)
        file_handler.setFormatter(fmt)
        root.addHandler(file_handler)

    # Suppress overly verbose third-party loggers
    for noisy in ("uvicorn.access", "httpx", "asyncio"):
        logging.getLogger(noisy).setLevel(logging.WARNING)


def get_logger(name: str) -> logging.Logger:
    """Return a named logger (child of root)."""
    return logging.getLogger(name)
