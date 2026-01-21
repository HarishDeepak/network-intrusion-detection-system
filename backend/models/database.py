"""
database.py

SQLAlchemy ORM models and database configuration for attack logging.
Stores attacks and alerts in SQLite database for querying and analysis.
"""

import os
from datetime import datetime
from sqlalchemy import create_engine, Column, Integer, String, Float, DateTime, Index
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

# Database configuration
SCRIPT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WORKSPACE_ROOT = os.path.dirname(SCRIPT_DIR)
DATABASE_PATH = os.path.join(WORKSPACE_ROOT, "nids.db")
DATABASE_URL = f"sqlite:///{DATABASE_PATH}"

# Create engine
engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False},
    echo=False  # Set to True for SQL logging
)

# Create session factory
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Base class for models
Base = declarative_base()


class AttackLog(Base):
    """
    Attack detection log - stores all detected attack events
    """
    __tablename__ = "attack_logs"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    attack_type = Column(String(100), index=True)  # Scan, DoS, BruteForce, etc.
    src_ip = Column(String(50))
    dest_ip = Column(String(50))
    protocol = Column(String(10))  # TCP, UDP, ICMP, etc.
    packet_length = Column(Integer)
    confidence = Column(Float)  # 0.0-1.0
    severity = Column(String(20), index=True)  # LOW, MEDIUM, HIGH, CRITICAL
    
    # Fusion pipeline details
    ae_score = Column(Float, nullable=True)  # Autoencoder reconstruction error
    xgb_confidence = Column(Float, nullable=True)  # Supervised model confidence
    fusion_score = Column(Float, nullable=True)  # Combined fusion score
    
    __table_args__ = (
        Index('idx_timestamp_severity', 'timestamp', 'severity'),
        Index('idx_attack_type', 'attack_type'),
    )

    def to_dict(self):
        """Convert to dictionary for JSON serialization"""
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "attack_type": self.attack_type,
            "src_ip": self.src_ip,
            "dest_ip": self.dest_ip,
            "protocol": self.protocol,
            "packet_length": self.packet_length,
            "confidence": self.confidence,
            "severity": self.severity,
            "ae_score": self.ae_score,
            "xgb_confidence": self.xgb_confidence,
            "fusion_score": self.fusion_score,
        }


class AlertLog(Base):
    """
    Alert delivery log - tracks email sending and notifications
    """
    __tablename__ = "alert_logs"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    attack_type = Column(String(100), index=True)
    severity = Column(String(20), index=True)
    status = Column(String(20), index=True)  # SENT, LOGGED, FAILED
    method = Column(String(20))  # EMAIL, STDOUT
    src_ip = Column(String(50))
    dest_ip = Column(String(50))
    recipients = Column(String(500))  # Comma-separated emails
    error = Column(String(500), nullable=True)  # Error message if failed
    
    __table_args__ = (
        Index('idx_timestamp_status', 'timestamp', 'status'),
        Index('idx_alert_type', 'attack_type'),
    )

    def to_dict(self):
        """Convert to dictionary for JSON serialization"""
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "attack_type": self.attack_type,
            "severity": self.severity,
            "status": self.status,
            "method": self.method,
            "src_ip": self.src_ip,
            "dest_ip": self.dest_ip,
            "recipients": self.recipients.split(",") if self.recipients else [],
            "error": self.error,
        }


# Create tables
def init_db():
    """Initialize database tables"""
    Base.metadata.create_all(bind=engine)
    print(f"[DB] Database initialized at: {DATABASE_PATH}")


def get_db():
    """Dependency for FastAPI to get database session"""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# Initialize on import
init_db()
