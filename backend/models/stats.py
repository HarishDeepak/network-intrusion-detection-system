# models/stats.py

from pydantic import BaseModel

class StatsResponse(BaseModel):
    packet_count: int
    byte_count: int
    detection_rate: float   # fraction of packets labeled as attacks
