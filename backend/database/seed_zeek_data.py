# database/seed_zeek_data.py

from datetime import datetime, timedelta
import random

from database.db_session import SessionLocal
from database.db_model import TrafficLog

def seed_traffic_logs():
    db = SessionLocal()

    now = datetime.utcnow()

    logs = []
    for i in range(20):
        log = TrafficLog(
            timestamp=now - timedelta(seconds=i * 5),
            src_ip=f"192.168.1.{random.randint(1, 254)}",
            dest_ip=f"10.0.0.{random.randint(1, 254)}",
            protocol=random.choice(["TCP", "UDP", "ICMP"]),
            bytes=random.randint(1000, 50000),
            packets=random.randint(10, 300),
        )
        logs.append(log)

    db.add_all(logs)
    db.commit()
    db.close()

    print("✅ Dummy Zeek traffic data inserted")

if __name__ == "__main__":
    seed_traffic_logs()
