# models/charts.py

from pydantic import BaseModel
from typing import List, Dict

class AttackDistribution(BaseModel):
    distribution: Dict[str, int]  
    # e.g., {"Normal": 120, "DDoS": 10, "PortScan": 5}

class TimeTrends(BaseModel):
    timestamps: List[float]       # list of epoch times
    packet_rate: List[int]        # packets per time interval
    flow_rate: List[int]          # flows per time interval
    bytes_per_sec: List[int]      # throughput per time interval
