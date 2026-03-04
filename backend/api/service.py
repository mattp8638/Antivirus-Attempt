from __future__ import annotations

from sqlalchemy.orm import Session

from . import models, schemas
from backend.enrichment.hash_reputation import get_hash_reputation_client


_SEVERITY_RANK = {
    "low": 0,
    "medium": 1,
    "high": 2,
    "critical": 3,
}


def _bump_severity(current: str, target: str) -> str:
    current_rank = _SEVERITY_RANK.get(current, 0)
    target_rank = _SEVERITY_RANK.get(target, current_rank)
    return target if target_rank > current_rank else current


def handle_memory_alert(db: Session, alert: schemas.MemoryAlertIn) -> models.Alert:
    mitre_ids = [m.id for m in alert.mitre_techniques]
    db_alert = models.Alert(
        title=alert.title,
        description=alert.description,
        severity=alert.severity.value,
        mitre_attack_techniques=mitre_ids,
        endpoint_id=alert.endpoint_id,
        event_id=None,
        rule_id=None,
        timestamp=alert.timestamp,
        status="new",
        details={
            "source_pid": alert.source_pid,
            "source_image": alert.source_image,
            "target_pid": alert.target_pid,
            "target_image": alert.target_image,
            "address": alert.address,
            "size": alert.size,
            "old_protection": alert.old_protection,
            "new_protection": alert.new_protection,
            "mitre_techniques": [
                {"id": t.id, "name": t.name} for t in alert.mitre_techniques
            ],
        },
    )
    db.add(db_alert)
    db.commit()
    db.refresh(db_alert)
    return db_alert


    db.commit()
    db.refresh(db_alert)
    return db_alert


def handle_fim_violation(db: Session, violation: schemas.FimViolationIn) -> models.FimViolation:
    db_violation = models.FimViolation(
        path=violation.path,
        violation_type=violation.violation_type,
        expected_hash=violation.expected_hash,
        actual_hash=violation.actual_hash,
        detected_at=violation.detected_at,
        endpoint_id=violation.endpoint_id,
    )
    db.add(db_violation)
    db.commit()
    db.refresh(db_violation)
    return db_violation


def handle_fim_baseline(db: Session, baseline: schemas.FimBaselineIn) -> models.FimBaseline:
    entries = [entry.model_dump() for entry in baseline.entries]
    db_baseline = models.FimBaseline(
        endpoint_id=baseline.endpoint_id,
        entries=entries,
    )
    db.add(db_baseline)
    db.commit()
    db.refresh(db_baseline)
    return db_baseline
def handle_behavioral_alert(
    db: Session, alert: schemas.BehavioralAlertIn
) -> models.Alert:
    severity_value = alert.severity.value
    is_yara = bool(alert.rule_name or alert.file_path)
    if is_yara:
        mitre_list = [alert.mitre_technique] if alert.mitre_technique else []
        details = {
            "rule_name": alert.rule_name,
            "rule_family": alert.rule_family,
            "category": alert.category,
            "file_path": alert.file_path,
            "file_hash_sha256": alert.file_hash_sha256,
            "file_size": alert.file_size,
            "matched_strings": alert.matched_strings,
        }
        title = alert.title or alert.rule_name or "YARA detection"
        description = alert.description or "YARA rule matched"

        if alert.file_hash_sha256:
            reputation = get_hash_reputation_client().check_hash(alert.file_hash_sha256)
            if reputation:
                details["hash_reputation"] = {
                    "verdict": reputation.verdict,
                    "provider": reputation.provider,
                    "malicious": reputation.malicious,
                    "score": reputation.score,
                    "details": reputation.details,
                }
                if reputation.verdict == "malicious":
                    severity_value = _bump_severity(severity_value, "critical")
                elif reputation.verdict == "suspicious":
                    severity_value = _bump_severity(severity_value, "high")
    else:
        mitre_list = [t.id for t in alert.mitre_techniques]
        details = {
            "process_image": alert.process_image,
            "command_line": alert.process_command_line,
            "parent_image": alert.parent_image,
            "pid": alert.pid,
            "ppid": alert.ppid,
            "mitre_techniques": [
                {"id": t.id, "name": t.name} for t in alert.mitre_techniques
            ],
        }
        title = alert.title or "Behavioral alert"
        description = alert.description or "Behavioral detection"

    db_alert = models.Alert(
        title=title,
        description=description,
        severity=severity_value,
        mitre_attack_techniques=mitre_list,
        endpoint_id=alert.endpoint_id,
        event_id=None,
        rule_id=None,
        timestamp=alert.timestamp,
        status="new",
        details=details,
    )
    db.add(db_alert)
    db.commit()
    db.refresh(db_alert)
    return db_alert
