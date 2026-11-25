"""
tests/integration/test_rest_gateway.py
=======================================
Integration tests for FastAPI REST Gateway.
Verifies:
  1. Health check returns 200 OK.
  2. Unauthenticated calls to protected routes return 401 Unauthorized.
  3. Login succeeds and returns a valid JWT.
  4. Incident submission returns 201 Created with full incident metadata.
  5. Incident status retrieval returns 200 OK.
  6. Human-in-the-Loop (HITL) approval endpoint updates incident state.
  7. Server-Sent Events (SSE) streaming endpoint streams live agent steps.
  8. Sliding-window rate limiter triggers 429 Too Many Requests when threshold exceeded.
"""

import pytest
from httpx import ASGITransport, AsyncClient

from src.api.rest.app import create_app
from src.api.rest.middleware.rate_limiter import SlidingWindowRateLimiter


@pytest.fixture
def app_instance():
    return create_app()


@pytest.fixture
async def async_client(app_instance):
    async with AsyncClient(
        transport=ASGITransport(app=app_instance),
        base_url="http://testserver"
    ) as client:
        yield client


@pytest.mark.asyncio
async def test_health_check(async_client):
    """Asserts healthz returns 200 and healthy status."""
    response = await async_client.get("/healthz")
    assert response.status_code == 200
    assert response.json()["status"] == "HEALTHY"
    assert "X-Request-ID" in response.headers


@pytest.mark.asyncio
async def test_unauthenticated_requests_rejected(async_client):
    """Asserts protected routes return 401 without Bearer token."""
    response = await async_client.get("/api/v1/incidents/inc-test-001")
    assert response.status_code == 401
    assert "WWW-Authenticate" in response.headers


@pytest.mark.asyncio
async def test_login_and_token_generation(async_client):
    """Asserts valid credentials return JWT access token."""
    login_data = {"username": "analyst", "password": "analyst123"}
    response = await async_client.post("/api/v1/auth/token", data=login_data)
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"
    assert "analyst" in data["roles"]


@pytest.mark.asyncio
async def test_incident_lifecycle_submit_get_approval(async_client):
    """
    Asserts full lifecycle:
      1. Login as analyst
      2. Submit incident
      3. Retrieve incident
      4. Submit Human-in-the-Loop approval
    """
    # 1. Login
    login_res = await async_client.post(
        "/api/v1/auth/token",
        data={"username": "analyst", "password": "analyst123"}
    )
    token = login_res.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # 2. Submit Incident
    submit_payload = {
        "source_ip": "198.51.100.23",
        "destination_ip": "10.0.0.50",
        "hostname": "db-primary-01",
        "event_type": "SUSPICIOUS_RANSOMWARE_BEHAVIOR",
        "raw_payload": "vssadmin.exe delete shadows /all /quiet",
        "metadata": {"user": "nt authority\\system"}
    }
    submit_res = await async_client.post(
        "/api/v1/incidents/submit",
        json=submit_payload,
        headers=headers
    )
    assert submit_res.status_code == 201
    incident_data = submit_res.json()
    incident_id = incident_data["incident_id"]
    assert incident_id.startswith("inc-")
    assert incident_data["status"] == "TRIAGING"

    # 3. Retrieve Incident
    get_res = await async_client.get(f"/api/v1/incidents/{incident_id}", headers=headers)
    assert get_res.status_code == 200
    assert get_res.json()["incident_id"] == incident_id

    # 4. Submit Human-in-the-Loop Approval
    approval_payload = {
        "decision": "APPROVED",
        "analyst_notes": "Confirmed ransomware staging; approved immediate isolation."
    }
    approval_res = await async_client.post(
        f"/api/v1/incidents/{incident_id}/approval",
        json=approval_payload,
        headers=headers
    )
    assert approval_res.status_code == 200
    assert approval_res.json()["status"] == "EXECUTING_REMEDIATION"
    assert approval_res.json()["approved_by"] == "analyst"


@pytest.mark.asyncio
async def test_sse_streaming_events(async_client):
    """Asserts SSE stream emits live agent progression events."""
    # Login & create an incident
    login_res = await async_client.post(
        "/api/v1/auth/token",
        data={"username": "analyst", "password": "analyst123"}
    )
    headers = {"Authorization": f"Bearer {login_res.json()['access_token']}"}

    submit_res = await async_client.post(
        "/api/v1/incidents/submit",
        json={
            "source_ip": "10.0.0.1",
            "destination_ip": "10.0.0.2",
            "hostname": "web-01",
            "event_type": "SSH_BRUTE_FORCE",
            "raw_payload": "Failed password"
        },
        headers=headers
    )
    incident_id = submit_res.json()["incident_id"]

    # Connect to SSE Stream
    response = await async_client.get(
        f"/api/v1/incidents/{incident_id}/stream",
        headers=headers
    )
    assert response.status_code == 200
    assert "text/event-stream" in response.headers["content-type"]
    assert "agent_step" in response.text


@pytest.mark.asyncio
async def test_sliding_window_rate_limiter_exceeded():
    """
    Directly tests the SlidingWindowRateLimiter algorithm:
    Allows 3 requests, rejects the 4th within the active window.
    """
    limiter = SlidingWindowRateLimiter(requests_per_window=3, window_seconds=2)
    client_id = "test-client-ip"

    # Requests 1, 2, 3 should be permitted
    assert await limiter.is_rate_limited(client_id) is False
    assert await limiter.is_rate_limited(client_id) is False
    assert await limiter.is_rate_limited(client_id) is False

    # 4th request within the window must be rejected
    assert await limiter.is_rate_limited(client_id) is True
