#!/usr/bin/env python3.14
"""Pydantic Schemas for API Request/Response Validation"""

from pydantic import BaseModel, Field
from typing import Optional, List
from datetime import datetime
from enum import Enum

class SeverityLevel(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

class ThreatStatus(str, Enum):
    DETECTED = "DETECTED"
    INVESTIGATING = "INVESTIGATING"
    CONFIRMED = "CONFIRMED"
    RESOLVED = "RESOLVED"
    FALSE_POSITIVE = "FALSE_POSITIVE"

class ThreatBase(BaseModel):
    threat_type: str
    source_ip: str
    target_url: str
    description: str
    severity: SeverityLevel = SeverityLevel.MEDIUM
    confidence_score: float = Field(0.0, ge=0.0, le=1.0)
    mitre_tactic: Optional[str] = None
    mitre_technique: Optional[str] = None

class ThreatCreate(ThreatBase):
    threat_id: str

class ThreatUpdate(BaseModel):
    severity: Optional[SeverityLevel] = None
    status: Optional[ThreatStatus] = None
    confidence_score: Optional[float] = None
    analyst_notes: Optional[str] = None

class ThreatResponse(ThreatBase):
    id: int
    threat_id: str
    status: ThreatStatus
    detected_at: datetime
    updated_at: datetime
    is_archived: bool

    class Config:
        from_attributes = True

class AlertBase(BaseModel):
    alert_type: str
    message: str
    severity: SeverityLevel
    triggered_by: str

class AlertCreate(AlertBase):
    alert_id: str
    threat_id: int

class AlertResponse(AlertBase):
    id: int
    alert_id: str
    threat_id: int
    created_at: datetime

    class Config:
        from_attributes = True

class DashboardResponse(BaseModel):
    timestamp: str
    active_threats: int
    unacknowledged_alerts: int
    recent_scans: int
    critical_threats: int
    high_threats: int
