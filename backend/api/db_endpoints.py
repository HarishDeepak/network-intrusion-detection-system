"""
api/db_endpoints.py

Database query endpoints for retrieving attacks and alerts from SQLite database.
Provides filtering, sorting, and aggregation capabilities.
"""

from fastapi import APIRouter, Query, Depends
from sqlalchemy import desc, func
from sqlalchemy.orm import Session
from typing import List, Optional
from models.database import AttackLog, AlertLog, get_db

router = APIRouter(tags=["Database Queries"])


# ============================================================================
# ATTACK LOG ENDPOINTS
# ============================================================================

@router.get("/db/attacks", response_model=List[dict])
def get_attacks_from_db(
    limit: int = Query(100, ge=1, le=1000),
    severity: Optional[str] = Query(None),
    attack_type: Optional[str] = Query(None),
    db: Session = Depends(get_db)
):
    """
    Get attacks from database with optional filtering.
    
    Query parameters:
    - limit: Max records to return (1-1000, default 100)
    - severity: Filter by severity (LOW, MEDIUM, HIGH, CRITICAL)
    - attack_type: Filter by attack type (Scan, DoS, BruteForce, etc.)
    """
    query = db.query(AttackLog).order_by(desc(AttackLog.timestamp))
    
    if severity:
        query = query.filter(AttackLog.severity == severity.upper())
    if attack_type:
        query = query.filter(AttackLog.attack_type == attack_type)
    
    attacks = query.limit(limit).all()
    return [a.to_dict() for a in attacks]


@router.get("/db/attacks/stats")
def get_attacks_statistics(db: Session = Depends(get_db)):
    """
    Get comprehensive attack statistics from database.
    """
    total = db.query(func.count(AttackLog.id)).scalar() or 0
    
    # By severity
    severity_stats = db.query(
        AttackLog.severity,
        func.count(AttackLog.id).label("count")
    ).group_by(AttackLog.severity).all()
    
    # By type
    type_stats = db.query(
        AttackLog.attack_type,
        func.count(AttackLog.id).label("count")
    ).group_by(AttackLog.attack_type).all()
    
    # Average confidence
    avg_confidence = db.query(func.avg(AttackLog.confidence)).scalar() or 0.0
    
    return {
        "total_attacks": total,
        "by_severity": {s: c for s, c in severity_stats},
        "by_type": {t: c for t, c in type_stats},
        "average_confidence": round(float(avg_confidence), 4),
    }


@router.get("/db/attacks/by_severity/{severity}")
def get_attacks_by_severity(
    severity: str,
    limit: int = Query(100, ge=1, le=1000),
    db: Session = Depends(get_db)
):
    """Get attacks filtered by severity level"""
    attacks = db.query(AttackLog).filter(
        AttackLog.severity == severity.upper()
    ).order_by(desc(AttackLog.timestamp)).limit(limit).all()
    
    return [a.to_dict() for a in attacks]


@router.get("/db/attacks/by_type/{attack_type}")
def get_attacks_by_type(
    attack_type: str,
    limit: int = Query(100, ge=1, le=1000),
    db: Session = Depends(get_db)
):
    """Get attacks filtered by type"""
    attacks = db.query(AttackLog).filter(
        AttackLog.attack_type == attack_type
    ).order_by(desc(AttackLog.timestamp)).limit(limit).all()
    
    return [a.to_dict() for a in attacks]


@router.get("/db/attacks/high-confidence")
def get_high_confidence_attacks(
    min_confidence: float = Query(0.8, ge=0.0, le=1.0),
    limit: int = Query(100, ge=1, le=1000),
    db: Session = Depends(get_db)
):
    """Get attacks with confidence above threshold"""
    attacks = db.query(AttackLog).filter(
        AttackLog.confidence >= min_confidence
    ).order_by(desc(AttackLog.confidence)).limit(limit).all()
    
    return [a.to_dict() for a in attacks]


# ============================================================================
# ALERT LOG ENDPOINTS
# ============================================================================

@router.get("/db/alerts", response_model=List[dict])
def get_alerts_from_db(
    limit: int = Query(100, ge=1, le=1000),
    status: Optional[str] = Query(None),
    db: Session = Depends(get_db)
):
    """
    Get alerts from database with optional filtering.
    
    Query parameters:
    - limit: Max records to return
    - status: Filter by status (SENT, LOGGED, FAILED)
    """
    query = db.query(AlertLog).order_by(desc(AlertLog.timestamp))
    
    if status:
        query = query.filter(AlertLog.status == status.upper())
    
    alerts = query.limit(limit).all()
    return [a.to_dict() for a in alerts]


@router.get("/db/alerts/stats")
def get_alerts_statistics(db: Session = Depends(get_db)):
    """
    Get comprehensive alert statistics from database.
    """
    total = db.query(func.count(AlertLog.id)).scalar() or 0
    
    # By status
    status_stats = db.query(
        AlertLog.status,
        func.count(AlertLog.id).label("count")
    ).group_by(AlertLog.status).all()
    
    # Success rate
    sent = db.query(func.count(AlertLog.id)).filter(
        AlertLog.status == "SENT"
    ).scalar() or 0
    success_rate = (sent / total * 100) if total > 0 else 0
    
    # By method
    method_stats = db.query(
        AlertLog.method,
        func.count(AlertLog.id).label("count")
    ).group_by(AlertLog.method).all()
    
    return {
        "total_alerts": total,
        "success_rate": round(success_rate, 2),
        "by_status": {s: c for s, c in status_stats},
        "by_method": {m: c for m, c in method_stats},
    }


@router.get("/db/alerts/failures")
def get_failed_alerts(
    limit: int = Query(100, ge=1, le=1000),
    db: Session = Depends(get_db)
):
    """Get alerts that failed to send"""
    alerts = db.query(AlertLog).filter(
        AlertLog.status == "FAILED"
    ).order_by(desc(AlertLog.timestamp)).limit(limit).all()
    
    return [a.to_dict() for a in alerts]


# ============================================================================
# COMBINED ANALYTICS ENDPOINTS
# ============================================================================

@router.get("/db/analytics/dashboard")
def get_dashboard_analytics(
    days: int = Query(7, ge=1, le=30),
    db: Session = Depends(get_db)
):
    """
    Get comprehensive dashboard analytics from database.
    """
    attack_stats = get_attacks_statistics(db)
    alert_stats = get_alerts_statistics(db)
    
    return {
        "attacks": attack_stats,
        "alerts": alert_stats,
        "dashboard_summary": {
            "total_attacks": attack_stats["total_attacks"],
            "total_alerts_sent": alert_stats["total_alerts"],
            "alert_success_rate": alert_stats["success_rate"],
            "primary_attack_type": max(
                attack_stats["by_type"].items(),
                key=lambda x: x[1],
                default=("N/A", 0)
            )[0],
            "primary_severity": max(
                attack_stats["by_severity"].items(),
                key=lambda x: x[1],
                default=("N/A", 0)
            )[0],
        }
    }


@router.get("/db/database-info")
def get_database_info(db: Session = Depends(get_db)):
    """Get information about database status and size"""
    attack_count = db.query(func.count(AttackLog.id)).scalar() or 0
    alert_count = db.query(func.count(AlertLog.id)).scalar() or 0
    
    return {
        "status": "healthy",
        "total_attack_records": attack_count,
        "total_alert_records": alert_count,
        "database_type": "SQLite",
        "note": "Using SQLite for persistent storage"
    }
