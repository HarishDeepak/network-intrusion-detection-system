"""
api/dashboard.py

Dashboard endpoints for frontend visualization.
Combines flow metadata from CSV and confirmed attacks from database.
"""
import os
import pandas as pd
import numpy as np
from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from sqlalchemy import func
from typing import List, Dict

from models.database import AttackLog, get_db
from fastapi.responses import JSONResponse

router = APIRouter(tags=["Dashboard"])

# -------------------------
# Load CSV once at startup
# -------------------------
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))  # api/
CSV_PATH = os.path.join(SCRIPT_DIR, "..", "attack_predictions.csv")
CSV_PATH = os.path.abspath(CSV_PATH)

def load_flows_df():
    """
    Safe CSV loader.
    Prevents blocking if file is being written by prediction script.
    Always returns a valid DataFrame.
    """
    if not os.path.exists(CSV_PATH):
        return pd.DataFrame(columns=[
            'timestamp', 'src_ip', 'dst_ip', 'protocol',
            'attack_score_supervised', 'attack_score_unsupervised',
            'combined_score', 'predicted_label_encoded', 'explanation'
        ])

    try:
        df = pd.read_csv(CSV_PATH)

        if 'timestamp' in df.columns:
            df['timestamp'] = pd.to_datetime(df['timestamp'], format="%d/%m/%Y %H:%M:%S", errors='coerce')
            print(df['timestamp'].iloc[0])

        return df

    except Exception:
        # If file is being written → return empty dataframe
        return pd.DataFrame(columns=[
            'timestamp', 'src_ip', 'dst_ip', 'protocol',
            'attack_score_supervised', 'attack_score_unsupervised',
            'combined_score', 'predicted_label_encoded', 'explanation'
        ])


# -------------------------
# Confirmed attacks lookup
# -------------------------
# confirmed_attacks_lookup = set()
#
# def refresh_confirmed_attacks(db: Session):
#     """
#     Refresh the in-memory set of confirmed attacks from DB.
#     Each entry is a tuple: (timestamp_iso, src_ip, dst_ip)
#     """
#     global confirmed_attacks_lookup
#     confirmed_attacks_lookup.clear()
#     attacks = db.query(AttackLog.timestamp, AttackLog.src_ip, AttackLog.dest_ip).all()
#     confirmed_attacks_lookup = set(
#         (ts.isoformat(), src, dst) for ts, src, dst in attacks
#     )

# -------------------------
# 1️⃣ Overview Endpoint
# -------------------------
@router.get("/overview")
def overview(db: Session = Depends(get_db)):
    # refresh_confirmed_attacks(db)

    flows_df = load_flows_df()
    total_flows = len(flows_df)
    total_attacks = db.query(AttackLog).count()


    if "explanation" in flows_df.columns:
        current_attacks = flows_df[
            flows_df["explanation"].notna() &
            (flows_df["explanation"].astype(str).str.strip() != "")
        ].shape[0]
    else:
        current_attacks = 0

    detection_rate = current_attacks / total_flows if total_flows > 0 else 0.0

    # Combined anomaly index (0-1)
    if total_flows == 0:
        avg_anomaly_index = 0.0
    else:
        supervised = flows_df.get('attack_score_supervised', pd.Series(0))
        unsupervised = flows_df.get('attack_score_unsupervised', pd.Series(0))

        combined_scores = pd.to_numeric(supervised, errors='coerce').fillna(0) + \
                          pd.to_numeric(unsupervised, errors='coerce').fillna(0)

        max_score = combined_scores.max() if combined_scores.max() > 0 else 1
        normalized_scores = np.log1p(combined_scores) / np.log1p(max_score)
        avg_anomaly_index = float(np.mean(normalized_scores))

    return {
        "total_flows": total_flows,
        "current_attacks": current_attacks,
        "total_attacks": total_attacks,
        "detection_rate": round(detection_rate, 4),
        "average_anomaly_index": round(avg_anomaly_index, 4)
    }

# -------------------------
# 2️⃣ Live Traffic Endpoint
# -------------------------
@router.get("/live-traffic", response_model=List[Dict])
def live_traffic(limit: int = Query(50, ge=1, le=100), db: Session = Depends(get_db)):

    flows_df = load_flows_df()

    if flows_df.empty:
        return []

    last_flows = flows_df.tail(limit)
    live_data = []

    for _, row in last_flows.iterrows():

        ts = row.get('timestamp')
        if pd.isna(ts):
            continue

        src = row.get('src_ip')
        dst = row.get('dst_ip')

        attack_entry = db.query(AttackLog).filter(
            AttackLog.timestamp == ts,
            AttackLog.src_ip == src,
            AttackLog.dest_ip == dst
        ).first()

        is_attack = attack_entry is not None

        attack_info = {}
        if is_attack:
            attack_info = {
                "attack_type": attack_entry.attack_type,
                "severity": attack_entry.severity,
                "fusion_score": float(attack_entry.fusion_score) if attack_entry.fusion_score else None
            }

        live_data.append({
            "timestamp": ts.isoformat(),
            "src_ip": src,
            "dst_ip": dst,
            "protocol": row.get('protocol', 'UNKNOWN'),
            "attack_score_supervised": float(row.get('attack_score_supervised', 0)),
            "attack_score_unsupervised": float(row.get('attack_score_unsupervised', 0)),
            "combined_score": float(row.get('combined_score', 0)),
            "predicted_label": int(row.get('predicted_label_encoded', 0)),
            "is_confirmed_attack": is_attack,
            **attack_info,
            "explanation": row.get('explanation', None)
        })

    return live_data


# -------------------------
# 3️⃣ Flow Summary Endpoint
# -------------------------
@router.get("/flow-summary")
def flow_summary(db: Session = Depends(get_db)):
    # refresh_confirmed_attacks(db)
    flows_df = load_flows_df()

    total_flows = len(flows_df)
    attack_count = db.query(AttackLog).count()
    normal_flows = total_flows - attack_count

    # Average anomaly index (0-1)
    if total_flows == 0:
        avg_anomaly_index = 0.0
    else:
        supervised = pd.to_numeric(
            flows_df.get('attack_score_supervised', pd.Series(0)),
            errors='coerce'
        ).fillna(0)

        unsupervised = pd.to_numeric(
            flows_df.get('attack_score_unsupervised', pd.Series(0)),
            errors='coerce'
        ).fillna(0)

        combined_scores = supervised + unsupervised

        max_score = combined_scores.max() if combined_scores.max() > 0 else 1
        normalized_scores = np.log1p(combined_scores) / np.log1p(max_score)
        avg_anomaly_index = float(np.mean(normalized_scores))

    # Attacks over time
    daily_attacks = (
        db.query(func.date(AttackLog.timestamp).label("date"), func.count(AttackLog.id).label("count"))
        .group_by(func.date(AttackLog.timestamp))
        .order_by(func.date(AttackLog.timestamp))
        .all()
    )
    attacks_over_time = [{"date": str(date), "count": count} for date, count in daily_attacks]

    return {
        "flow_class_counts": {
            "normal": int(normal_flows),
            "attack": attack_count
        },
        "average_anomaly_index": round(avg_anomaly_index, 4),
        "attacks_over_time": attacks_over_time
    }

# -------------------------
# 4️⃣ All Attack Classes (for frontend plotting)
# -------------------------
ALL_ATTACK_CLASSES = ["Normal", "Scan", "Brute Force", "DDoS", "Other Attack"]
