#!/usr/bin/env python3.14
"""SQLAlchemy ORM Models for Threats, Alerts, and Scans"""

from sqlalchemy import Column, Integer, String, Float, DateTime, Boolean, Text, Enum
from sqlalchemy.sql import func
from datetime import datetime
import enum
from csf.api.database import Base

class SeverityLevel(str, enum.Enum):
    """Threat severity levels"""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

class ThreatStatus(str, enum.Enum):
    """Threat status"""
    DETECTED = "DETECTED"
    INVESTIGATING = "INVESTIGATING"
    CONFIRMED = "CONFIRMED"
    RESOLVED = "RESOLVED"
    FALSE_POSITIVE = "FALSE_POSITIVE"

class Threat(Base):
    """Threat Model - Stores detected threats"""
    __tablename__ = "threats"

    id = Column(Integer, primary_key=True, index=True)
    threat_id = Column(String(50), unique=True, index=True)
    threat_type = Column(String(100), index=True)
    source_ip = Column(String(45), index=True)
    target_url = Column(String(500))
    description = Column(Text)
    severity = Column(Enum(SeverityLevel), default=SeverityLevel.MEDIUM, index=True)
    status = Column(Enum(ThreatStatus), default=ThreatStatus.DETECTED, index=True)
    confidence_score = Column(Float, default=0.0)
    mitre_tactic = Column(String(100), nullable=True)
    mitre_technique = Column(String(100), nullable=True)
    
    detected_at = Column(DateTime(timezone=True), server_default=func.now(), index=True)
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    resolved_at = Column(DateTime(timezone=True), nullable=True)
    
    analyst_notes = Column(Text, nullable=True)
    is_archived = Column(Boolean, default=False, index=True)

    def __repr__(self):
        return f"<Threat(id={self.id}, type={self.threat_type}, severity={self.severity})>"

class Alert(Base):
    """Alert Model - Real-time security alerts"""
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)
    alert_id = Column(String(50), unique=True, index=True)
    threat_id = Column(Integer, index=True)
    alert_type = Column(String(100), index=True)
    message = Column(Text)
    severity = Column(Enum(SeverityLevel), index=True)
    
    triggered_by = Column(String(100))
    enrichment_data = Column(Text, nullable=True)
    
    is_acknowledged = Column(Boolean, default=False, index=True)
    acknowledged_by = Column(String(100), nullable=True)
    acknowledged_at = Column(DateTime(timezone=True), nullable=True)
    
    created_at = Column(DateTime(timezone=True), server_default=func.now(), index=True)
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

    def __repr__(self):
        return f"<Alert(id={self.id}, type={self.alert_type}, threat_id={self.threat_id})>"

class SecurityScan(Base):
    """SecurityScan Model - Vulnerability & security scan results"""
    __tablename__ = "security_scans"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(String(50), unique=True, index=True)
    scan_type = Column(String(100), index=True)
    target = Column(String(500), index=True)
    
    vulnerabilities_found = Column(Integer, default=0)
    critical_count = Column(Integer, default=0)
    high_count = Column(Integer, default=0)
    medium_count = Column(Integer, default=0)
    low_count = Column(Integer, default=0)
    
    status = Column(String(50), default="completed", index=True)
    duration_seconds = Column(Float)
    results_data = Column(Text, nullable=True)
    
    started_at = Column(DateTime(timezone=True), server_default=func.now())
    completed_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), index=True)

    def __repr__(self):
        return f"<SecurityScan(id={self.id}, type={self.scan_type}, vulns={self.vulnerabilities_found})>"

class User(Base):
    """User Model - For authentication & RBAC"""
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(100), unique=True, index=True)
    email = Column(String(100), unique=True, index=True)
    hashed_password = Column(String(255))
    is_active = Column(Boolean, default=True, index=True)
    role = Column(String(50), default="analyst")
    
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    last_login = Column(DateTime(timezone=True), nullable=True)

    def __repr__(self):
        return f"<User(id={self.id}, username={self.username}, role={self.role})>"

class AnomalyDetection(Base):
    """AnomalyDetection Model - ML-based anomaly detection results"""
    __tablename__ = "anomaly_detections"

    id = Column(Integer, primary_key=True, index=True)
    anomaly_id = Column(String(50), unique=True, index=True)
    detector_model = Column(String(100))
    
    anomaly_type = Column(String(100), index=True)
    anomaly_score = Column(Float)
    threshold_triggered = Column(Float)
    
    source_metric = Column(String(100))
    metric_value = Column(Float)
    baseline_value = Column(Float)
    deviation_percent = Column(Float)
    
    is_confirmed = Column(Boolean, default=False)
    investigation_notes = Column(Text, nullable=True)
    
    detected_at = Column(DateTime(timezone=True), server_default=func.now(), index=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    def __repr__(self):
        return f"<AnomalyDetection(id={self.id}, type={self.anomaly_type}, score={self.anomaly_score})>"
