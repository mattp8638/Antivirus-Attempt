from __future__ import annotations

from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from . import models
from .dependencies import get_db

router = APIRouter(prefix="/api/v1", tags=["legacy-agent"])


@router.post("/agents/register")
def register_agent(payload: dict[str, Any], db: Session = Depends(get_db)):
    endpoint_id = int(payload.get("endpoint_id") or 1)
    hostname = str(payload.get("hostname") or "unknown")
    agent_version = str(payload.get("agent_version") or "1.0.0")

    existing = (
        db.query(models.AgentHeartbeat)
        .filter(models.AgentHeartbeat.endpoint_id == endpoint_id)
        .first()
    )

    metadata = {
        "agent_id": payload.get("agent_id"),
        "os_version": payload.get("os_version"),
        "ip_address": payload.get("ip_address"),
        "legacy_protocol": True,
    }

    if existing:
        existing.hostname = hostname
        existing.agent_version = agent_version
        existing.status = "online"
        existing.metadata_json = metadata
        existing.last_seen = datetime.utcnow()
        db.commit()
        db.refresh(existing)
        return {"status": "ok", "endpoint_id": existing.endpoint_id}

    heartbeat = models.AgentHeartbeat(
        endpoint_id=endpoint_id,
        hostname=hostname,
        agent_version=agent_version,
        status="online",
        metadata_json=metadata,
    )
    db.add(heartbeat)
    db.commit()
    db.refresh(heartbeat)
    return {"status": "ok", "endpoint_id": heartbeat.endpoint_id}


@router.post("/events")
def ingest_events(
    payload: list[dict[str, Any]] | dict[str, Any],
    db: Session = Depends(get_db),
):
    events = payload if isinstance(payload, list) else [payload]
    created = 0

    for event in events:
        if not isinstance(event, dict):
            continue

        endpoint_id = int(event.get("endpoint_id") or 1)
        severity = str(event.get("severity") or "low").lower()
        event_type = str(event.get("type") or "legacy_event").lower()
        title = str(event.get("title") or event_type or "legacy_event")
        description = str(event.get("description") or "Legacy event from /api/v1/events")
        status = str(event.get("status") or "new")

        alert = models.Alert(
            title=title[:255],
            description=description,
            severity=severity[:32],
            mitre_attack_techniques=event.get("mitre_attack_techniques") or [],
            endpoint_id=endpoint_id,
            event_id=event.get("event_id"),
            rule_id=event.get("rule_id"),
            timestamp=datetime.utcnow(),
            status=status[:32],
            details=event,
        )
        db.add(alert)
        created += 1

        if event_type == "fim_violation":
            db.add(
                models.FimViolation(
                    path=str(event.get("path") or "unknown"),
                    violation_type=str(event.get("violation_type") or "modified"),
                    expected_hash=event.get("expected_hash"),
                    actual_hash=event.get("actual_hash"),
                    detected_at=datetime.utcnow(),
                    endpoint_id=endpoint_id,
                )
            )
        elif event_type == "threat_indicator":
            now = datetime.utcnow()
            db.add(
                models.ThreatIndicator(
                    indicator_type=str(event.get("indicator_type") or "hash"),
                    value=str(event.get("value") or "unknown"),
                    source=str(event.get("source") or "legacy_agent"),
                    severity=severity,
                    confidence=float(event.get("confidence") or 0.5),
                    tags=event.get("tags") or ["legacy"],
                    first_seen=now,
                    last_seen=now,
                    expires_at=None,
                    metadata_json=event,
                )
            )
        elif event_type == "response_action":
            command_id = event.get("command_id")
            updated_existing = False
            if command_id is not None:
                existing_action = db.query(models.ResponseActionRecord).get(int(command_id))
                if existing_action is not None:
                    existing_action.status = str(event.get("response_status") or "completed")
                    existing_action.executed_at = datetime.utcnow()
                    existing_action.completed_at = datetime.utcnow()
                    existing_action.details = {
                        **(existing_action.details or {}),
                        "agent_report": event,
                    }
                    updated_existing = True

            if not updated_existing:
                db.add(
                    models.ResponseActionRecord(
                        action_type=str(event.get("action_type") or "observe"),
                        status=str(event.get("response_status") or "completed"),
                        endpoint_id=endpoint_id,
                        parameters=event.get("parameters") or {},
                        executed_at=datetime.utcnow(),
                        completed_at=datetime.utcnow(),
                        details=event,
                    )
                )
        elif event_type == "response_playbook":
            db.add(
                models.ResponsePlaybookRecord(
                    name=str(event.get("name") or "legacy_playbook"),
                    status=str(event.get("response_status") or "completed"),
                    endpoint_id=endpoint_id,
                    actions=event.get("actions") or [],
                    completed_at=datetime.utcnow(),
                    details=event,
                )
            )

    if created > 0:
        db.commit()

    return {"status": "ok", "received": len(events), "created_alerts": created}


@router.get("/commands")
def get_commands(
    endpoint_id: int = Query(default=1, ge=1),
    limit: int = Query(default=10, ge=1, le=100),
    db: Session = Depends(get_db),
):
    pending = (
        db.query(models.ResponseActionRecord)
        .filter(models.ResponseActionRecord.endpoint_id == endpoint_id)
        .filter(models.ResponseActionRecord.status.in_(["queued", "pending"]))
        .order_by(models.ResponseActionRecord.created_at.asc())
        .limit(limit)
        .all()
    )

    now = datetime.utcnow()
    commands = []
    for item in pending:
        item.status = "dispatched"
        item.executed_at = now
        commands.append(
            {
                "command_id": item.id,
                "action": item.action_type,
                "endpoint_id": item.endpoint_id,
                "parameters": item.parameters or {},
                "issued_at": item.created_at.isoformat(),
            }
        )

    if pending:
        db.commit()

    return commands
