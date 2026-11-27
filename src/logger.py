"""
src/logger.py — Centralized Structured Logging Subsystem
=========================================================
Provides production-grade structured logging for the AutoSOC platform.
Unifies Python standard library logging and `structlog` under a single
configurable pipeline.

Key Capabilities:
1. Environment-Aware Formatting:
   - Development/Staging: Human-readable, colorized terminal output with timestamps.
   - Production: High-throughput, single-line JSON output optimized for SIEM/log shippers
     (Datadog, Elastic, Vector, FluentBit).
2. Dynamic Contextvars Injection:
   - Automatically attaches correlation IDs (`request_id`, `incident_id`, `batch_id`)
     across asynchronous coroutines and tasks without threading leaks.
3. Standard Library Interception:
   - Captures and formats logs from third-party libraries (uvicorn, fastapi, qdrant, aio-pika)
     so all application output conforms to a uniform schema.
4. Centralized Factory:
   - Every module imports `from src.logger import get_logger`.
"""

import logging
import sys
from typing import Any

import structlog

from src.config import settings

_CONFIGURED = False


def configure_logging(
    log_level: str | None = None,
    app_env: str | None = None,
    force_json: bool = False,
) -> None:
    """
    Configures standard library logging and structlog.
    Idempotent: can be called multiple times (e.g. in tests) to reconfigure.
    """
    global _CONFIGURED

    level_name = (log_level or settings.log_level).upper()
    env = (app_env or settings.app_env).lower()
    numeric_level = getattr(logging, level_name, logging.INFO)

    shared_processors: list[Any] = [
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="iso", utc=True),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.UnicodeDecoder(),
    ]

    if force_json or env == "production":
        final_processor = structlog.processors.JSONRenderer()
    else:
        final_processor = structlog.dev.ConsoleRenderer(colors=True)

    # Formatter for standard library logging
    formatter = structlog.stdlib.ProcessorFormatter(
        foreign_pre_chain=shared_processors,
        processors=[
            structlog.stdlib.ProcessorFormatter.remove_processors_meta,
            final_processor,
        ],
    )

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(formatter)

    root_logger = logging.getLogger()
    root_logger.handlers = [handler]
    root_logger.setLevel(numeric_level)

    # Configure structlog
    structlog.configure(
        processors=shared_processors + [
            structlog.stdlib.ProcessorFormatter.wrap_for_formatter,
        ],
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )

    _CONFIGURED = True


def get_logger(name: str | None = None) -> structlog.stdlib.BoundLogger:
    """
    Obtain a configured structured logger.
    Automatically initializes logging configuration if not yet invoked.

    Usage:
        from src.logger import get_logger
        logger = get_logger(__name__)
        logger.info("incident_triaged", incident_id="INC-101", severity="HIGH")
    """
    global _CONFIGURED
    if not _CONFIGURED:
        configure_logging()
    return structlog.get_logger(name)


def bind_context(**kwargs: Any) -> None:
    """
    Bind contextual key-values to the current async execution context.
    All subsequent log lines in the same task/coroutine will include these fields.

    Usage:
        bind_context(incident_id="INC-101", analyst="viper")
    """
    structlog.contextvars.bind_contextvars(**kwargs)


def unbind_context(*keys: str) -> None:
    """
    Remove specific contextual keys from the current async execution context.
    """
    structlog.contextvars.unbind_contextvars(*keys)


def clear_context() -> None:
    """
    Clear all contextual variables for the current async execution context.
    """
    structlog.contextvars.clear_contextvars()


def get_context() -> dict[str, Any]:
    """
    Return all current context variables bound in this async execution context.
    """
    return structlog.contextvars.get_contextvars()
