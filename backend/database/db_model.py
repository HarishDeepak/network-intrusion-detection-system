# db_models.py

from sqlalchemy import Column, Integer, String, Float, BigInteger, TIMESTAMP
from database.database import Base


class TrafficLog(Base):
    __tablename__ = "traffic_logs"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(TIMESTAMP)
    src_ip = Column(String)
    dest_ip = Column(String)
    protocol = Column(String)
    bytes = Column(BigInteger)
    packets = Column(Integer)

class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(TIMESTAMP)
    src_ip = Column(String)
    dest_ip = Column(String)
    attack_type = Column(String)
    confidence = Column(Float)
    severity = Column(String)
    status = Column(String)
