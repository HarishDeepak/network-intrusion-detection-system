# models/packet.py

from pydantic import BaseModel
from typing import List, Dict, Optional

class PacketData(BaseModel):
    id: int
    src_ip: str
    dest_ip: str
    length: int          # packet size in bytes
    protocol: str
    timestamp: float     # epoch time

class PredictionResult(BaseModel):
    label: str           # e.g. "normal" or "attack"
    confidence: float    # e.g. 0.85
    attack_type: Optional[str] = None  # e.g. "DDoS", if label is "attack"

class PacketWithPrediction(BaseModel):
    packet: PacketData
    prediction: PredictionResult
