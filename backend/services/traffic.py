# services/traffic.py

import random
import time
from models.packet import PacketData, PredictionResult, PacketWithPrediction
from models.stats import StatsResponse
from models.charts import AttackDistribution, TimeTrends

def get_basic_stats() -> StatsResponse:
    # Dummy aggregated stats (could be based on in-memory counters or random)
    packet_count = random.randint(1000, 2000)
    byte_count = random.randint(500000, 2000000)
    detection_rate = round(random.uniform(0.0, 0.2), 2)  # e.g. 0.12 means 12% attacks
    return StatsResponse(packet_count=packet_count, byte_count=byte_count, detection_rate=detection_rate)

def get_attack_distribution() -> AttackDistribution:
    # Dummy attack counts (keys: types of traffic)
    dist = {
        "Normal": random.randint(800, 1200),
        "DDoS": random.randint(0, 100),
        "PortScan": random.randint(0, 50),
        "Malware": random.randint(0, 30)
    }
    return AttackDistribution(distribution=dist)

def get_time_trends(intervals: int = 10) -> TimeTrends:
    # Generate time-series data for the last `intervals` points
    now = time.time()
    timestamps = [now - i*60 for i in reversed(range(intervals))]  # one-minute intervals
    packet_rate = [random.randint(50, 150) for _ in range(intervals)]
    flow_rate = [random.randint(20, 80) for _ in range(intervals)]
    bytes_rate = [random.randint(10000, 50000) for _ in range(intervals)]
    return TimeTrends(
        timestamps=timestamps,
        packet_rate=packet_rate,
        flow_rate=flow_rate,
        bytes_per_sec=bytes_rate
    )

def predict_packet(packet: PacketData) -> PredictionResult:
    # Dummy "ML model" logic: classify based on packet size
    if packet.length > 1000:
        return PredictionResult(label="attack", confidence=0.9, attack_type="DDoS")
    else:
        return PredictionResult(label="normal", confidence=0.9, attack_type=None)

def generate_packets(count: int = 5):
    # Create a list of packets with random attributes and dummy predictions
    protocols = ["TCP", "UDP", "ICMP"]
    packets = []
    for i in range(count):
        pkt = PacketData(
            id=i,
            src_ip=f"192.168.1.{random.randint(1,254)}",
            dest_ip=f"10.0.0.{random.randint(1,254)}",
            length=random.randint(60, 1500),
            protocol=random.choice(protocols),
            timestamp=time.time()
        )
        pred = predict_packet(pkt)
        packets.append(PacketWithPrediction(packet=pkt, prediction=pred))
    return packets
