#!/usr/bin/env python3.14
"""FastAPI Application - Main Entry Point"""

from fastapi import FastAPI, Depends, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session
from datetime import datetime
import logging
from typing import List

from csf.api.database import get_db, init_db
from csf.api.models.threat import Threat, Alert, SecurityScan

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="CSF Security API",
    description="Complete Cybersecurity Framework REST API",
    version="2.0.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.on_event("startup")
async def startup_event():
    logger.info("🚀 CSF Security API Starting...")
    init_db()
    logger.info("✅ Database initialized")

@app.get("/")
async def root():
    return {
        "status": "operational",
        "service": "CSF Security API",
        "version": "2.0.0",
        "timestamp": datetime.utcnow().isoformat()
    }

@app.get("/health")
async def health():
    return {"status": "healthy", "timestamp": datetime.utcnow().isoformat()}

@app.post("/api/threats")
async def create_threat(threat_data: dict, db: Session = Depends(get_db)):
    try:
        threat = Threat(
            threat_id=threat_data.get("threat_id"),
            threat_type=threat_data.get("threat_type"),
            source_ip=threat_data.get("source_ip"),
            target_url=threat_data.get("target_url"),
            description=threat_data.get("description"),
            severity=threat_data.get("severity", "MEDIUM"),
            confidence_score=threat_data.get("confidence_score", 0.0)
        )
        db.add(threat)
        db.commit()
        db.refresh(threat)
        logger.info(f"✅ Threat created: {threat.threat_id}")
        return {"status": "success", "threat_id": threat.threat_id, "id": threat.id}
    except Exception as e:
        db.rollback()
        logger.error(f"❌ Error creating threat: {str(e)}")
        raise HTTPException(status_code=400, detail=str(e))

@app.get("/api/threats")
async def list_threats(skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
    query = db.query(Threat).filter(Threat.is_archived == False)
    total = query.count()
    threats = query.offset(skip).limit(limit).all()
    
    return {
        "total": total,
        "page": skip // limit,
        "per_page": limit,
        "threats": [
            {
                "id": t.id,
                "threat_id": t.threat_id,
                "threat_type": t.threat_type,
                "source_ip": t.source_ip,
                "severity": t.severity,
                "status": t.status,
                "confidence_score": t.confidence_score,
                "detected_at": t.detected_at.isoformat() if t.detected_at else None
            }
            for t in threats
        ]
    }

@app.get("/api/threats/{threat_id}")
async def get_threat(threat_id: str, db: Session = Depends(get_db)):
    threat = db.query(Threat).filter(Threat.threat_id == threat_id).first()
    if not threat:
        raise HTTPException(status_code=404, detail="Threat not found")
    
    return {
        "id": threat.id,
        "threat_id": threat.threat_id,
        "threat_type": threat.threat_type,
        "source_ip": threat.source_ip,
        "target_url": threat.target_url,
        "description": threat.description,
        "severity": threat.severity,
        "status": threat.status,
        "confidence_score": threat.confidence_score,
        "detected_at": threat.detected_at.isoformat() if threat.detected_at else None
    }

@app.get("/api/alerts")
async def list_alerts(limit: int = 100, db: Session = Depends(get_db)):
    alerts = db.query(Alert).order_by(Alert.created_at.desc()).limit(limit).all()
    return {
        "total": len(alerts),
        "alerts": [
            {
                "id": a.id,
                "alert_id": a.alert_id,
                "threat_id": a.threat_id,
                "alert_type": a.alert_type,
                "message": a.message,
                "severity": a.severity,
                "created_at": a.created_at.isoformat() if a.created_at else None
            }
            for a in alerts
        ]
    }

@app.get("/api/statistics/threats")
async def get_threat_statistics(db: Session = Depends(get_db)):
    all_threats = db.query(Threat).filter(Threat.is_archived == False).all()
    
    return {
        "total_threats": len(all_threats),
        "critical": len([t for t in all_threats if t.severity == "CRITICAL"]),
        "high": len([t for t in all_threats if t.severity == "HIGH"]),
        "medium": len([t for t in all_threats if t.severity == "MEDIUM"]),
        "low": len([t for t in all_threats if t.severity == "LOW"]),
        "resolved": len([t for t in all_threats if t.status == "RESOLVED"])
    }

@app.get("/api/statistics/dashboard")
async def get_dashboard(db: Session = Depends(get_db)):
    active_threats = db.query(Threat).filter(
        Threat.status.in_(["DETECTED", "INVESTIGATING", "CONFIRMED"]),
        Threat.is_archived == False
    ).all()
    
    unacknowledged_alerts = db.query(Alert).filter(Alert.is_acknowledged == False).count()
    
    return {
        "timestamp": datetime.utcnow().isoformat(),
        "active_threats": len(active_threats),
        "unacknowledged_alerts": unacknowledged_alerts,
        "critical_threats": len([t for t in active_threats if t.severity == "CRITICAL"]),
        "high_threats": len([t for t in active_threats if t.severity == "HIGH"]),
        "threat_types": list(set([t.threat_type for t in active_threats])),
        "source_ips": list(set([t.source_ip for t in active_threats]))
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("csf.api.main:app", host="0.0.0.0", port=8000, reload=True)
