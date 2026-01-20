"""
decision_engine.py

Decision Brain for NIDS:
- Takes model outputs (AE score + supervised label/confidence)
- Applies fusion logic (rule-based + weighted)
- Assigns severity
- Returns structured results (attack flag, severity, reason, timestamps)


"""

import numpy as np
import pandas as pd
from datetime import datetime

# ==============================
# Thresholds & weights (tunable)
# ==============================

# Rule-based thresholds
AE_THRESHOLD_RULE = 1e7        # AE reconstruction error threshold
CONF_THRESHOLD_RULE = 0.00001  # Supervised confidence threshold (very low - capture all predictions)

# Weighted fusion parameters
WEIGHT_AE = 0.0                # Don't use AE score (attacks don't always have high reconstruction error)
WEIGHT_XGB = 1.0               # Use only supervised model predictions
FUSION_THRESHOLD = 0.0000001   # Very low threshold for weighted fusion

# Severity thresholds
AE_THRESHOLD_HIGH = 5e7
CONF_THRESHOLD_HIGH = 0.8

# ==============================
# Utility functions
# ==============================

def normalize_ae(ae_scores: np.ndarray) -> np.ndarray:
    """Min-max normalize AE scores safely"""
    min_v = np.min(ae_scores)
    max_v = np.max(ae_scores)
    return (ae_scores - min_v) / (max_v - min_v + 1e-9)


# ==============================
# Fusion decision logic
# ==============================

def fusion_decision(row, ae_norm):
    """
    Determine if a flow is an attack using:
    - Rule-based fusion
    - Weighted fusion
    Returns:
        attack (bool), fusion_score (float), reason (str)
    """
    # --- Rule-based fusion ---
    rule_attack = (
        row["ae_score"] > AE_THRESHOLD_RULE
        and row["xgb_label"] != "Benign"
        and row["xgb_confidence"] >= CONF_THRESHOLD_RULE
    )

    # --- Weighted fusion ---
    fusion_score = (
        WEIGHT_AE * ae_norm +
        WEIGHT_XGB * row["xgb_confidence"]
    )

    # Weighted attack: use supervised model prediction (xgb_label != "Benign")
    weighted_attack = (
        row["xgb_label"] != "Benign"
        and fusion_score > FUSION_THRESHOLD
    )

    # --- Final decision ---
    attack = rule_attack or weighted_attack

    reason = (
        "Rule-based fusion triggered" if rule_attack else
        "Weighted fusion triggered" if weighted_attack else
        "No attack conditions met"
    )

    return attack, fusion_score, reason


# ==============================
# Severity scoring
# ==============================

def severity_score(row):
    """
    Assign severity: Low / Medium / High
    Based on AE score and supervised confidence
    """
    if row["ae_score"] > AE_THRESHOLD_HIGH and row["xgb_confidence"] >= CONF_THRESHOLD_HIGH:
        return "High"
    elif row["ae_score"] > AE_THRESHOLD_RULE and row["xgb_confidence"] >= CONF_THRESHOLD_RULE:
        return "Medium"
    else:
        return "Low"


# ==============================
# Main decision engine
# ==============================

def run_decision_engine(results_df: pd.DataFrame) -> pd.DataFrame:
    """
    Run fusion + severity scoring on a results DataFrame.
    Input DataFrame must contain:
        - ae_score
        - xgb_label
        - xgb_confidence
    Returns a DataFrame with:
        - attack (bool)
        - attack_type
        - ae_score
        - xgb_confidence
        - fusion_score
        - severity
        - reason
        - timestamp
    """
    # Normalize AE scores for weighted fusion
    ae_norm = normalize_ae(results_df["ae_score"].values)

    decisions = []

    for idx, row in results_df.iterrows():
        attack, fusion_score, reason = fusion_decision(row, ae_norm[idx])
        severity = severity_score(row) if attack else "None"

        decisions.append({
            "timestamp": datetime.utcnow().isoformat(),
            "attack": attack,
            "attack_type": row["xgb_label"] if attack else "None",
            "ae_score": float(row["ae_score"]),
            "xgb_confidence": float(row["xgb_confidence"]),
            "fusion_score": float(fusion_score),
            "severity": severity,
            "reason": reason
        })

    return pd.DataFrame(decisions)


