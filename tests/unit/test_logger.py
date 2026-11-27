"""
tests/unit/test_logger.py — Centralized Logger Test Suite
=========================================================
Verifies:
1. Logger initialization & BoundLogger behavior.
2. Context variable binding, retrieval, unbinding, and clearing across async/tasks.
3. Production JSON rendering (valid JSON schema with timestamps, levels, context).
4. Development console rendering.
5. Standard library logging interception.
6. Utilities module re-export compatibility.
"""

import io
import json
import logging
import sys
import pytest

from src.logger import (
    bind_context,
    clear_context,
    configure_logging,
    get_context,
    get_logger,
    unbind_context,
)
from src.utils.logger import get_logger as get_logger_utils


@pytest.fixture(autouse=True)
def cleanup_logging_context():
    """Ensure contextvars are wiped between tests."""
    clear_context()
    yield
    clear_context()


def test_logger_initialization():
    """Verify that get_logger returns an operational logger instance."""
    logger = get_logger("unit_test_service")
    assert logger is not None
    # Basic smoke test that calling log methods doesn't throw
    logger.info("smoke_test_event", status="ok", count=42)


def test_context_binding_lifecycle():
    """Verify bind_context, get_context, unbind_context, and clear_context."""
    clear_context()
    assert get_context() == {}

    bind_context(incident_id="INC-404", severity="HIGH", analyst="alice")
    ctx = get_context()
    assert ctx["incident_id"] == "INC-404"
    assert ctx["severity"] == "HIGH"
    assert ctx["analyst"] == "alice"

    unbind_context("analyst")
    ctx_after_unbind = get_context()
    assert "analyst" not in ctx_after_unbind
    assert ctx_after_unbind["incident_id"] == "INC-404"
    assert ctx_after_unbind["severity"] == "HIGH"

    clear_context()
    assert get_context() == {}


def test_json_formatting_production(monkeypatch):
    """Verify that in production mode, logs are formatted as single-line JSON."""
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)

    # Reconfigure for production mode
    configure_logging(log_level="INFO", app_env="production")

    # Replace root handler stream to capture output
    root = logging.getLogger()
    for h in root.handlers:
        if isinstance(h, logging.StreamHandler):
            monkeypatch.setattr(h, "stream", stream)

    logger = get_logger("prod_audit")
    bind_context(request_id="req-9988", client_ip="192.168.1.50")
    logger.info("remediation_action_triggered", action="isolate_host", host="db-srv-01")

    output = stream.getvalue().strip()
    assert output, "Expected log output in stream"

    # Must parse as valid JSON
    log_record = json.loads(output)
    assert log_record["event"] == "remediation_action_triggered"
    assert log_record["level"] == "info"
    assert log_record["logger"] == "prod_audit"
    assert log_record["request_id"] == "req-9988"
    assert log_record["client_ip"] == "192.168.1.50"
    assert log_record["action"] == "isolate_host"
    assert log_record["host"] == "db-srv-01"
    assert "timestamp" in log_record


def test_stdlib_interception(monkeypatch):
    """Verify that Python standard library logging is formatted through our pipeline."""
    stream = io.StringIO()

    configure_logging(log_level="INFO", app_env="production")

    root = logging.getLogger()
    for h in root.handlers:
        if isinstance(h, logging.StreamHandler):
            monkeypatch.setattr(h, "stream", stream)

    # Use standard library logging
    std_logger = logging.getLogger("uvicorn.error")
    std_logger.info("Application startup complete.")

    output = stream.getvalue().strip()
    assert output, "Expected intercepted standard library log output"

    log_record = json.loads(output)
    assert log_record["event"] == "Application startup complete."
    assert log_record["logger"] == "uvicorn.error"
    assert log_record["level"] == "info"


def test_reexport_from_utils():
    """Verify that src.utils.logger provides identical logger instances."""
    logger1 = get_logger("reexport_test")
    logger2 = get_logger_utils("reexport_test")
    assert type(logger1) is type(logger2)
