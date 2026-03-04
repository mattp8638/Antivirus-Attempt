from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from . import models, schemas, service
from .dependencies import get_db, require_api_key

router = APIRouter(prefix="/edr", tags=["edr"], dependencies=[Depends(require_api_key)])


@router.post("/alerts/memory")
def ingest_memory_alert(
    alert: schemas.MemoryAlertIn,
    db: Session = Depends(get_db),
):
    service.handle_memory_alert(db, alert)
    return {"status": "ok"}


@router.post("/alerts/fim")
def ingest_fim_violation(
    violation: schemas.FimViolationIn,
    db: Session = Depends(get_db),
):
    service.handle_fim_violation(db, violation)
    return {"status": "ok"}


@router.post("/baseline/fim")
def ingest_fim_baseline(
    baseline: schemas.FimBaselineIn,
    db: Session = Depends(get_db),
):
    service.handle_fim_baseline(db, baseline)
    return {"status": "ok"}
@router.post("/alerts/behavioral")
def ingest_behavioral_alert(
    alert: schemas.BehavioralAlertIn,
    db: Session = Depends(get_db),
):
    service.handle_behavioral_alert(db, alert)
    return {"status": "ok"}


@router.get("/alerts", response_model=list[schemas.AlertOut])
def list_alerts(
    db: Session = Depends(get_db),
    endpoint_id: int | None = Query(default=None),
    severity: str | None = Query(default=None),
    status: str | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
):
    query = db.query(models.Alert)
    if endpoint_id is not None:
        query = query.filter(models.Alert.endpoint_id == endpoint_id)
    if severity is not None:
        query = query.filter(models.Alert.severity == severity)
    if status is not None:
        query = query.filter(models.Alert.status == status)
    return query.order_by(models.Alert.timestamp.desc()).offset(offset).limit(limit).all()


@router.get("/alerts/{alert_id}", response_model=schemas.AlertOut)
def get_alert(alert_id: int, db: Session = Depends(get_db)):
    alert = db.query(models.Alert).get(alert_id)
    if alert is None:
        raise HTTPException(status_code=404, detail="Alert not found")
    return alert


@router.patch("/alerts/{alert_id}/status", response_model=schemas.AlertOut)
def update_alert_status(
    alert_id: int,
    payload: schemas.AlertStatusUpdateIn,
    db: Session = Depends(get_db),
):
    alert = db.query(models.Alert).get(alert_id)
    if alert is None:
        raise HTTPException(status_code=404, detail="Alert not found")
    alert.status = payload.status
    db.commit()
    db.refresh(alert)
    return alert


@router.post("/alerts/{alert_id}/resolve", response_model=schemas.AlertOut)
def resolve_alert(alert_id: int, db: Session = Depends(get_db)):
    alert = db.query(models.Alert).get(alert_id)
    if alert is None:
        raise HTTPException(status_code=404, detail="Alert not found")
    alert.status = "resolved"
    db.commit()
    db.refresh(alert)
    return alert


@router.get("/fim/violations", response_model=list[schemas.FimViolationOut])
def list_fim_violations(
    db: Session = Depends(get_db),
    endpoint_id: int | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
):
    query = db.query(models.FimViolation)
    if endpoint_id is not None:
        query = query.filter(models.FimViolation.endpoint_id == endpoint_id)
    return query.order_by(models.FimViolation.detected_at.desc()).offset(offset).limit(limit).all()


@router.get("/fim/baselines", response_model=list[schemas.FimBaselineOut])
def list_fim_baselines(
    db: Session = Depends(get_db),
    endpoint_id: int | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
):
    query = db.query(models.FimBaseline)
    if endpoint_id is not None:
        query = query.filter(models.FimBaseline.endpoint_id == endpoint_id)
    return query.order_by(models.FimBaseline.created_at.desc()).offset(offset).limit(limit).all()


@router.post("/threat-intel/indicators", response_model=schemas.ThreatIndicatorOut)
def create_threat_indicator(
    indicator: schemas.ThreatIndicatorIn,
    db: Session = Depends(get_db),
):
    db_indicator = models.ThreatIndicator(**indicator.model_dump())
    db.add(db_indicator)
    db.commit()
    db.refresh(db_indicator)
    return db_indicator


@router.get("/threat-intel/indicators", response_model=list[schemas.ThreatIndicatorOut])
def list_threat_indicators(
    db: Session = Depends(get_db),
    indicator_type: str | None = Query(default=None),
    severity: str | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
):
    query = db.query(models.ThreatIndicator)
    if indicator_type is not None:
        query = query.filter(models.ThreatIndicator.indicator_type == indicator_type)
    if severity is not None:
        query = query.filter(models.ThreatIndicator.severity == severity)
    return query.order_by(models.ThreatIndicator.last_seen.desc()).offset(offset).limit(limit).all()


@router.post("/agents/heartbeat", response_model=schemas.AgentHeartbeatOut)
def upsert_agent_heartbeat(
    heartbeat: schemas.AgentHeartbeatIn,
    db: Session = Depends(get_db),
):
    existing = (
        db.query(models.AgentHeartbeat)
        .filter(models.AgentHeartbeat.endpoint_id == heartbeat.endpoint_id)
        .first()
    )
    if existing:
        existing.hostname = heartbeat.hostname
        existing.agent_version = heartbeat.agent_version
        existing.status = heartbeat.status
        existing.metadata_json = heartbeat.metadata_json
        existing.last_seen = datetime.utcnow()
        db.commit()
        db.refresh(existing)
        return existing

    db_heartbeat = models.AgentHeartbeat(
        endpoint_id=heartbeat.endpoint_id,
        hostname=heartbeat.hostname,
        agent_version=heartbeat.agent_version,
        status=heartbeat.status,
        metadata_json=heartbeat.metadata_json,
    )
    db.add(db_heartbeat)
    db.commit()
    db.refresh(db_heartbeat)
    return db_heartbeat


@router.get("/agents", response_model=list[schemas.AgentHeartbeatOut])
def list_agents(
    db: Session = Depends(get_db),
    status: str | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
):
    query = db.query(models.AgentHeartbeat)
    if status is not None:
        query = query.filter(models.AgentHeartbeat.status == status)
    return query.order_by(models.AgentHeartbeat.last_seen.desc()).offset(offset).limit(limit).all()


@router.get("/response/actions", response_model=list[schemas.ResponseActionOut])
def list_response_actions(
    db: Session = Depends(get_db),
    endpoint_id: int | None = Query(default=None),
    status: str | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
):
    query = db.query(models.ResponseActionRecord)
    if endpoint_id is not None:
        query = query.filter(models.ResponseActionRecord.endpoint_id == endpoint_id)
    if status is not None:
        query = query.filter(models.ResponseActionRecord.status == status)
    return query.order_by(models.ResponseActionRecord.created_at.desc()).offset(offset).limit(limit).all()


@router.post("/response/actions", response_model=schemas.ResponseActionOut)
def create_response_action(
    action: schemas.ResponseActionCreateIn,
    db: Session = Depends(get_db),
):
    db_action = models.ResponseActionRecord(
        action_type=action.action_type,
        status="queued",
        endpoint_id=action.endpoint_id,
        parameters=action.parameters,
        details=action.details,
    )
    db.add(db_action)
    db.commit()
    db.refresh(db_action)
    return db_action


@router.get("/response/playbooks", response_model=list[schemas.ResponsePlaybookOut])
def list_response_playbooks(
    db: Session = Depends(get_db),
    endpoint_id: int | None = Query(default=None),
    status: str | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
):
    query = db.query(models.ResponsePlaybookRecord)
    if endpoint_id is not None:
        query = query.filter(models.ResponsePlaybookRecord.endpoint_id == endpoint_id)
    if status is not None:
        query = query.filter(models.ResponsePlaybookRecord.status == status)
    return query.order_by(models.ResponsePlaybookRecord.created_at.desc()).offset(offset).limit(limit).all()
