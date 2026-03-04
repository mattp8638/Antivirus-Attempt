from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, List, Optional

from pydantic import BaseModel, Field, conint, constr


class StrictModel(BaseModel):
    class Config:
        extra = "forbid"


class SeverityLevel(str, Enum):
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class MitreTechnique(StrictModel):
    id: constr(strip_whitespace=True, min_length=1)
    name: constr(strip_whitespace=True, min_length=1)


class MemoryAlertIn(StrictModel):
    severity: SeverityLevel
    title: constr(strip_whitespace=True, min_length=1)
    description: constr(strip_whitespace=True, min_length=1)
    mitre_techniques: List[MitreTechnique] = Field(default_factory=list)
    source_pid: conint(ge=0)
    source_image: constr(strip_whitespace=True, min_length=1)
    target_pid: Optional[conint(ge=0)] = None
    target_image: Optional[constr(strip_whitespace=True, min_length=1)] = None
    address: Optional[conint(ge=0)] = None
    size: Optional[conint(ge=0)] = None
    old_protection: Optional[conint(ge=0)] = None
    new_protection: Optional[conint(ge=0)] = None
    timestamp: datetime
    endpoint_id: conint(gt=0)


class BehavioralAlertIn(StrictModel):
    severity: SeverityLevel
    timestamp: datetime
    endpoint_id: conint(ge=0) = 0

    title: Optional[constr(strip_whitespace=True, min_length=1)] = None
    description: Optional[constr(strip_whitespace=True, min_length=1)] = None
    mitre_techniques: List[MitreTechnique] = Field(default_factory=list)
    process_image: Optional[constr(strip_whitespace=True, min_length=1)] = None
    process_command_line: Optional[constr(strip_whitespace=True, min_length=0)] = None
    parent_image: Optional[constr(strip_whitespace=True, min_length=1)] = None
    pid: Optional[conint(ge=0)] = None
    ppid: Optional[conint(ge=0)] = None

    rule_name: Optional[constr(strip_whitespace=True, min_length=1)] = None
    rule_family: Optional[constr(strip_whitespace=True, min_length=1)] = None
    category: Optional[constr(strip_whitespace=True, min_length=1)] = None
    file_path: Optional[constr(strip_whitespace=True, min_length=1)] = None
    file_hash_sha256: Optional[constr(strip_whitespace=True, min_length=1)] = None
    file_size: Optional[conint(ge=0)] = None
    matched_strings: List[dict[str, Any]] = Field(default_factory=list)
    mitre_technique: Optional[constr(strip_whitespace=True, min_length=1)] = None


class FimViolationIn(StrictModel):
    path: str
    violation_type: str
    expected_hash: Optional[str] = None
    actual_hash: Optional[str] = None
    detected_at: datetime
    endpoint_id: int


class FimBaselineEntry(StrictModel):
    path: str
    sha256_hash: str
    size: int
    modified_time: datetime
    baseline_timestamp: datetime


class FimBaselineIn(StrictModel):
    endpoint_id: int
    entries: List[FimBaselineEntry]


class AlertOut(BaseModel):
    id: int
    title: str
    description: str
    severity: str
    mitre_attack_techniques: List[str]
    endpoint_id: int
    event_id: Optional[int]
    rule_id: Optional[int]
    timestamp: datetime
    status: str
    details: dict


class AlertStatusUpdateIn(StrictModel):
    status: constr(strip_whitespace=True, min_length=1)


class FimViolationOut(BaseModel):
    id: int
    path: str
    violation_type: str
    expected_hash: Optional[str]
    actual_hash: Optional[str]
    detected_at: datetime
    endpoint_id: int
    created_at: datetime


class FimBaselineOut(BaseModel):
    id: int
    endpoint_id: int
    created_at: datetime
    entries: List[dict]


class ThreatIndicatorIn(StrictModel):
    indicator_type: str
    value: str
    source: str
    severity: str
    confidence: float = 0.0
    tags: List[str] = Field(default_factory=list)
    first_seen: datetime
    last_seen: datetime
    expires_at: Optional[datetime] = None
    metadata_json: dict = Field(default_factory=dict)


class ThreatIndicatorOut(ThreatIndicatorIn):
    id: int


class AgentHeartbeatIn(StrictModel):
    endpoint_id: int
    hostname: str
    agent_version: str
    status: str = "online"
    metadata_json: dict = Field(default_factory=dict)


class AgentHeartbeatOut(AgentHeartbeatIn):
    id: int
    last_seen: datetime


class ResponseActionOut(BaseModel):
    id: int
    action_type: str
    status: str
    endpoint_id: int
    parameters: dict
    created_at: datetime
    executed_at: Optional[datetime]
    completed_at: Optional[datetime]
    details: dict


class ResponseActionCreateIn(StrictModel):
    action_type: constr(strip_whitespace=True, min_length=1)
    endpoint_id: conint(gt=0)
    parameters: dict = Field(default_factory=dict)
    details: dict = Field(default_factory=dict)


class LegacyCommandOut(BaseModel):
    command_id: int
    action: str
    endpoint_id: int
    parameters: dict
    issued_at: datetime


class ResponsePlaybookOut(BaseModel):
    id: int
    name: str
    status: str
    endpoint_id: int
    actions: List[dict]
    created_at: datetime
    completed_at: Optional[datetime]
    details: dict
