import os
import sys
# Ensure 'backend' is in sys.path for direct execution
sys.path.append(os.path.dirname(os.path.dirname(__file__)))
import glob
import pickle
import numpy as np
import pandas as pd
import json

from scipy.stats import entropy, zscore
from sklearn.preprocessing import MinMaxScaler
from services.explainability import ExplainabilityService
from run_fusion import decode_labels

# -----------------------------
# 1. Load models & preprocessors
# -----------------------------
BASE_DIR = os.path.dirname(
    os.path.dirname(
        os.path.dirname(os.path.abspath(__file__))
    )
)
BACKEND_DIR = os.path.join(BASE_DIR, "backend")

# Supervised model
supervised_model_path = os.path.join(BASE_DIR, "Supervised", "final_model.pkl")
with open(supervised_model_path, "rb") as f:
    supervised_model = pickle.load(f)

# Autoencoder artifacts
autoencoder_path = os.path.join(BASE_DIR, "Unsupervised_learning", "autoencoder_full.pkl")
with open(autoencoder_path, "rb") as f:
    autoencoder = pickle.load(f)

# Scaler
scaler_path = os.path.join(BASE_DIR, "Data_cleaning", "scaler.pkl")
with open(scaler_path, "rb") as f:
    scaler = pickle.load(f)

# Final features
features_path = os.path.join(BASE_DIR, "Data_cleaning", "final_features.pkl")
with open(features_path, "rb") as f:
    FEATURES = pickle.load(f)

# Imputer
imputer_path = os.path.join(BASE_DIR, "Data_cleaning", "imputer_final.pkl")
with open(imputer_path, "rb") as f:
    imputer = pickle.load(f)

# Label encoder
label_encoder_path = os.path.join(BASE_DIR, "Supervised", "labelencoder_xgb.pkl")
with open(label_encoder_path, "rb") as f:
    label_encoder = pickle.load(f)

print("LabelEncoder loaded with classes:", label_encoder.classes_)
print(f"Loaded {len(FEATURES)} final features")
print("Scaler expects:", scaler.n_features_in_)
print("Imputer features:", imputer.statistics_.shape[0])

# -----------------------------
# Initialize ExplainabilityService
# -----------------------------
explainer = ExplainabilityService(supervised_model, autoencoder, max_shap_samples=3000)

# --------------------------------------------------
# 2. Load and concatenate all 7 CSVs for prediction
# --------------------------------------------------
CSV_DIR = os.path.join(BACKEND_DIR, "attackcsv")
csv_files = glob.glob(os.path.join(CSV_DIR, "*.csv"))

if len(csv_files) == 0:
    raise FileNotFoundError(f"No CSVs found in {CSV_DIR}")

dfs = []
for f in csv_files:
    df = pd.read_csv(f)
    dfs.append(df)

df_all = pd.concat(dfs, ignore_index=True)
print("Raw concatenated shape:", df_all.shape)

# --------------------------------
# 3. Basic cleaning / normalization
# --------------------------------

# Match training: lower-case and underscores for column names
df_all.columns = df_all.columns.str.replace(" ", "_").str.lower()

# ========================================
# PRINT ALL COLUMNS - DEBUG
# ========================================
print("\n=== ALL COLUMNS AFTER NORMALIZATION ===")
print("Total columns:", len(df_all.columns))
print("Column names:")
for i, col in enumerate(df_all.columns, 1):
    print(f"  {i:2d}. {col}")
print("=======================================\n")

# Map custom names -> CICFlowMeter-style names (normalized to lower/underscore)
rename_map = {
    "flow_duration": "flow_duration",
    "tot_fwd_pkts": "total_fwd_packets",
    "tot_bwd_pkts": "total_backward_packets",
    "totlen_fwd_pkts": "fwd_packets_length_total",
    "totlen_bwd_pkts": "bwd_packets_length_total",
    "fwd_pkt_len_max": "fwd_packet_length_max",
    "fwd_pkt_len_min": "fwd_packet_length_min",
    "fwd_pkt_len_mean": "fwd_packet_length_mean",
    "fwd_pkt_len_std": "fwd_packet_length_std",
    "bwd_pkt_len_max": "bwd_packet_length_max",
    "bwd_pkt_len_min": "bwd_packet_length_min",
    "bwd_pkt_len_mean": "bwd_packet_length_mean",
    "bwd_pkt_len_std": "bwd_packet_length_std",
    "flow_byts/s": "flow_bytes/s",
    "flow_pkts/s": "flow_packets/s",
    "flow_iat_mean": "flow_iat_mean",
    "flow_iat_std": "flow_iat_std",
    "flow_iat_max": "flow_iat_max",
    "flow_iat_min": "flow_iat_min",
    "fwd_iat_tot": "fwd_iat_total",
    "fwd_iat_mean": "fwd_iat_mean",
    "fwd_iat_std": "fwd_iat_std",
    "fwd_iat_max": "fwd_iat_max",
    "fwd_iat_min": "fwd_iat_min",
    "bwd_iat_tot": "bwd_iat_total",
    "bwd_iat_mean": "bwd_iat_mean",
    "bwd_iat_std": "bwd_iat_std",
    "bwd_iat_max": "bwd_iat_max",
    "bwd_iat_min": "bwd_iat_min",
    "fwd_psh_flags": "fwd_psh_flags",
    "bwd_psh_flags": "bwd_psh_flags",
    "fwd_urg_flags": "fwd_urg_flags",
    "bwd_urg_flags": "bwd_urg_flags",
    "fwd_header_len": "fwd_header_length",
    "bwd_header_len": "bwd_header_length",
    "fwd_pkts/s": "fwd_packets/s",
    "bwd_pkts/s": "bwd_packets/s",
    "pkt_len_min": "packet_length_min",
    "pkt_len_max": "packet_length_max",
    "pkt_len_mean": "packet_length_mean",
    "pkt_len_std": "packet_length_std",
    "pkt_len_var": "packet_length_variance",
    "fin_flag_cnt": "fin_flag_count",
    "syn_flag_cnt": "syn_flag_count",
    "rst_flag_cnt": "rst_flag_count",
    "psh_flag_cnt": "psh_flag_count",
    "ack_flag_cnt": "ack_flag_count",
    "urg_flag_cnt": "urg_flag_count",
    "cwe_flag_count": "cwe_flag_count",
    "ece_flag_cnt": "ece_flag_count",
    "down/up_ratio": "down/up_ratio",
    "pkt_size_avg": "avg_packet_size",
    "fwd_seg_size_avg": "avg_fwd_segment_size",
    "bwd_seg_size_avg": "avg_bwd_segment_size",
    "fwd_byts/b_avg": "fwd_avg_bytes/bulk",
    "fwd_pkts/b_avg": "fwd_avg_packets/bulk",
    "fwd_blk_rate_avg": "fwd_avg_bulk_rate",
    "bwd_byts/b_avg": "bwd_avg_bytes/bulk",
    "bwd_pkts/b_avg": "bwd_avg_packets/bulk",
    "bwd_blk_rate_avg": "bwd_avg_bulk_rate",
    "subflow_fwd_pkts": "subflow_fwd_packets",
    "subflow_fwd_byts": "subflow_fwd_bytes",
    "subflow_bwd_pkts": "subflow_bwd_packets",
    "subflow_bwd_byts": "subflow_bwd_bytes",
    "init_fwd_win_byts": "init_fwd_win_bytes",
    "init_bwd_win_byts": "init_bwd_win_bytes",
    "fwd_act_data_pkts": "fwd_act_data_packets",
    "fwd_seg_size_min": "fwd_seg_size_min",
    "active_mean": "active_mean",
    "active_std": "active_std",
    "active_max": "active_max",
    "active_min": "active_min",
    "idle_mean": "idle_mean",
    "idle_std": "idle_std",
    "idle_max": "idle_max",
    "idle_min": "idle_min",
}

# Only rename columns that actually exist, to avoid KeyErrors
existing_rename_map = {
    old: new for old, new in rename_map.items()
    if old in df_all.columns
}
print("Renaming these columns:", list(existing_rename_map.keys()))

df_all = df_all.rename(columns=existing_rename_map)
print("Columns after rename:", [col for col in df_all.columns if col in FEATURES][:5])

# Protocol one-hot (only if protocol column exists)
if "protocol" in df_all.columns:
    df_all = pd.get_dummies(df_all, columns=["protocol"], prefix="proto")

# Ensure numeric for columns with these patterns (same enforce_numeric idea)
def enforce_numeric(df: pd.DataFrame) -> pd.DataFrame:
    patterns = ["count", "packet", "packets", "bytes", "length", "duration",
                "rate", "mean", "std", "max", "min", "iat", "segment"]
    for col in df.columns:
        if any(pat in col for pat in patterns):
            df[col] = pd.to_numeric(df[col], errors="coerce")
    return df

df_all = enforce_numeric(df_all)

# Replace infinities and handle NaN later via imputer
df_all = df_all.replace([np.inf, -np.inf], np.nan)


# -------------------------------------------------
# 4. Feature engineering (inference-safe subset)
# -------------------------------------------------
eps = 1e-3

if "flow_duration" in df_all.columns:
    df_all["flow_duration"] = df_all["flow_duration"].clip(lower=eps)

    # total_packets
    if {"total_fwd_packets", "total_backward_packets"}.issubset(df_all.columns):
        df_all["total_packets"] = (
            df_all["total_fwd_packets"] + df_all["total_backward_packets"] + eps
        )

    # total_bytes
    if {"fwd_packets_length_total", "bwd_packets_length_total"}.issubset(df_all.columns):
        df_all["total_bytes"] = (
            df_all["fwd_packets_length_total"] + df_all["bwd_packets_length_total"] + eps
        )

    # packet_rate
    if "total_packets" in df_all.columns:
        df_all["packet_rate"] = df_all["total_packets"] / (df_all["flow_duration"] / 1e6)

    # bytes_per_packet
    if {"total_bytes", "total_packets"}.issubset(df_all.columns):
        df_all["bytes_per_packet"] = df_all["total_bytes"] / df_all["total_packets"]

# idle_cv / active_cv
if "idle_mean" in df_all.columns and "idle_std" in df_all.columns:
    df_all["idle_mean_safe"] = df_all["idle_mean"].replace(0, eps)
    df_all["idle_cv"] = df_all["idle_std"] / df_all["idle_mean_safe"]
if "active_mean" in df_all.columns and "active_std" in df_all.columns:
    df_all["active_mean_safe"] = df_all["active_mean"].replace(0, eps)
    df_all["active_cv"] = df_all["active_std"] / df_all["active_mean_safe"]

for col in ["idle_mean_safe", "active_mean_safe"]:
    if col in df_all.columns:
        df_all.drop(columns=[col], inplace=True)

# tcp_behavior
if "flow_duration" in df_all.columns:
    proto_cols = [c for c in df_all.columns if c.startswith("proto_")]
    if "proto_6" in df_all.columns:
        df_all["tcp_behavior"] = df_all["proto_6"] * df_all["flow_duration"]
    else:
        df_all["tcp_behavior"] = 0

# burst_ratio
if "fwd_packets/s" in df_all.columns and "flow_packets/s" in df_all.columns:
    df_all["burst_ratio"] = df_all["fwd_packets/s"] / (df_all["flow_packets/s"] + 1e-5)

# packet_entropy
if {"fwd_packet_length_std", "bwd_packet_length_std"}.issubset(df_all.columns):
    df_all["packet_entropy"] = df_all[
        ["fwd_packet_length_std", "bwd_packet_length_std"]
    ].apply(
        lambda x: entropy([x[0] + 1e-9, x[1] + 1e-9], base=2),
        axis=1,
    )

# total_flag_count
flag_cols = [
    "fin_flag_count", "syn_flag_count", "rst_flag_count",
    "psh_flag_count", "ack_flag_count", "urg_flag_count",
    "cwe_flag_count", "ece_flag_count"
]
if set(flag_cols).issubset(df_all.columns):
    df_all["total_flag_count"] = df_all[flag_cols].sum(axis=1)

    df_all["syn_fin_ratio"] = (df_all["syn_flag_count"] + 1e-5) / (
        df_all["fin_flag_count"] + 1e-5
    )
    df_all["psh_ack_ratio"] = (df_all["psh_flag_count"] + 1e-5) / (
        df_all["ack_flag_count"] + 1e-5
    )

# segment_ratio
if {"avg_fwd_segment_size", "avg_bwd_segment_size"}.issubset(df_all.columns):
    df_all["segment_ratio"] = (df_all["avg_fwd_segment_size"] + 1e-5) / (
        df_all["avg_bwd_segment_size"] + 1e-5
    )

# IAT CV features
if {"fwd_iat_std", "fwd_iat_mean"}.issubset(df_all.columns):
    df_all["fwd_iat_cv"] = (df_all["fwd_iat_std"] + 1e-5) / (
        df_all["fwd_iat_mean"] + 1e-5
    )
if {"bwd_iat_std", "bwd_iat_mean"}.issubset(df_all.columns):
    df_all["bwd_iat_cv"] = (df_all["bwd_iat_std"] + 1e-5) / (
        df_all["bwd_iat_mean"] + 1e-5
    )

# skew features
if {"fwd_packet_length_mean", "fwd_packet_length_min", "fwd_packet_length_std"}.issubset(df_all.columns):
    df_all["fwd_packet_skew"] = (
        df_all["fwd_packet_length_mean"] - df_all["fwd_packet_length_min"]
    ) / (df_all["fwd_packet_length_std"] + 1e-5)

if {"bwd_packet_length_mean", "bwd_packet_length_min", "bwd_packet_length_std"}.issubset(df_all.columns):
    df_all["bwd_packet_skew"] = (
        df_all["bwd_packet_length_mean"] - df_all["bwd_packet_length_min"]
    ) / (df_all["bwd_packet_length_std"] + 1e-5)

# log_flow_duration + abnormal_flow_duration
if "flow_duration" in df_all.columns:
    df_all["log_flow_duration"] = np.log1p(df_all["flow_duration"])
    df_all["flow_duration_zscore"] = zscore(df_all["log_flow_duration"].fillna(0))
    df_all["abnormal_flow_duration"] = (
        np.abs(df_all["flow_duration_zscore"]) > 3
    ).astype(int)
    df_all.drop(["log_flow_duration", "flow_duration_zscore"], axis=1, inplace=True)

# activity_period_ratio
if {"active_mean", "idle_mean"}.issubset(df_all.columns):
    df_all["activity_period_ratio"] = (df_all["active_mean"] + eps) / (
        df_all["idle_mean"] + eps
    )

# proto_*_flag_rate and flag_change_rate + flow_anomaly_index
if "total_flag_count" in df_all.columns and "flow_duration" in df_all.columns:
    proto_cols = [c for c in df_all.columns if c.startswith("proto_")]
    for proto in proto_cols:
        df_all[f"{proto}_flag_rate"] = df_all["total_flag_count"] * df_all[proto] / (
            df_all["flow_duration"] / 1e6 + 1e-5
        )

    df_all["flag_change_rate"] = df_all["total_flag_count"] / (
        (df_all["flow_duration"] / 1e6) + eps
    )

    anomaly_feats = []
    for col in ["burst_ratio", "active_cv", "flag_change_rate"]:
        if col in df_all.columns:
            scaler_tmp = MinMaxScaler()
            df_all[col + "_scaled"] = scaler_tmp.fit_transform(
                df_all[[col]].fillna(0.0)
            )
            anomaly_feats.append(col + "_scaled")

    if anomaly_feats:
        df_all["flow_anomaly_index"] = df_all[anomaly_feats].sum(axis=1)
        df_all.drop(columns=anomaly_feats, inplace=True)

print("Shape after feature engineering:", df_all.shape)

# -----------------------------------------
# 5. Align with 48 FEATURES (final_features)
# -----------------------------------------
# Keep only columns that exist in df_all
available_features = [f for f in FEATURES if f in df_all.columns]
print(f"Available features: {len(available_features)} out of {len(FEATURES)}")
print("Available feature names:")
for f in available_features:
    print("  -", f)

# Add missing feature columns as zeros
missing_features = [f for f in FEATURES if f not in df_all.columns]
print(f"\nMissing features: {len(missing_features)}")
print("Missing feature names:")
for f in missing_features:
    print("  -", f)
for col in missing_features:
    df_all[col] = 0.0

# Reorder exactly as in FEATURES
X_raw = df_all[FEATURES].copy()

print(f"Using {len(available_features)} existing features, "
      f"{len(missing_features)} added as zeros.")
print("X_raw shape:", X_raw.shape)

# print("\n===== IMPUTER FEATURES (FIT ORDER) =====")
# for i, f in enumerate(imputer.feature_names_in_, 1):
#     print(f"{i:02d}. {f}")
# print("Total imputer features:", len(imputer.feature_names_in_))
#
# print("\n===== X_raw FEATURES (CURRENT ORDER) =====")
# for i, f in enumerate(X_raw.columns, 1):
#     print(f"{i:02d}. {f}")
# print("Total X_raw features:", X_raw.shape[1])

X_raw = X_raw[imputer.feature_names_in_]


# -----------------------------------------
# 6. Impute → scale
# -----------------------------------------
X_imputed = imputer.transform(X_raw)
X_scaled = scaler.transform(X_imputed)

# Add this right before predictions:
print("\n=== FULL DEBUG ===")
print("1. Data shape:", X_raw.shape)
print("2. Features match:", X_raw.shape[1] == len(FEATURES))
print("3. Sample values:", X_raw.iloc[0,:5].values)
print("4. After imputer:", pd.Series(X_imputed[0]).describe())
print("5. After scaler:", pd.Series(X_scaled[0]).describe())

# Test prediction
test_pred = supervised_model.predict(X_scaled[:10])
test_proba = supervised_model.predict_proba(X_scaled[:10])
print("6. Test predictions:", test_pred)
print("7. Test proba:", test_proba)
print("8. Model classes:", supervised_model.classes_)

# -----------------------------------------
# 7. Supervised model prediction (UPDATED)
# -----------------------------------------
supervised_predictions = supervised_model.predict(X_scaled)  # Get class predictions (encoded)
supervised_proba = supervised_model.predict_proba(X_scaled)  # Get probabilities

# Convert encoded predictions back to original labels
supervised_labels = label_encoder.inverse_transform(supervised_predictions)
supervised_label = decode_labels(
    pd.Series(supervised_predictions)
).values

label_counts = pd.Series(supervised_labels).value_counts()
label_percent = 100 * label_counts / len(supervised_labels)

print("\n===== Unique Predicted Labels =====")
print("Label counts:")
print(label_counts)
print("\nLabel percentages:")
print(label_percent)

print("\nUnique labels predicted:", list(label_counts.index))

# Use probability of positive class (index 1) as attack score
attack_score_supervised = supervised_proba[:, 1] if supervised_proba.shape[1] > 1 else supervised_predictions.astype(float)

print(f"Supervised predictions shape: {supervised_predictions.shape}")
print(f"Sample supervised labels: {supervised_labels[:10]}")
print(f"Unique predicted labels: {np.unique(supervised_labels)}")

# -----------------------------------------
# 8. Autoencoder anomaly score
# -----------------------------------------
# autoencoder_full.pkl may be a dict like {"model": ..., "threshold": ..., ...}
if isinstance(autoencoder, dict) and "model" in autoencoder:
    ae_model = autoencoder["model"]
else:
    ae_model = autoencoder

# Forward pass
if hasattr(ae_model, "predict"):
    X_recon = ae_model.predict(X_imputed)
else:
    # If stored differently, adapt here
    raise RuntimeError("Autoencoder object does not support predict().")

# Reconstruction error as anomaly score (MSE per row)
recon_error = np.mean((X_imputed - X_recon) ** 2, axis=1)
attack_score_unsupervised = recon_error

# -----------------------------------------
# 9. Combine scores
# -----------------------------------------
# Simple weighted sum (tune weights as desired)
w_sup = 0.3
w_unsup = 0.7
combined_score = w_sup * attack_score_supervised + w_unsup * attack_score_unsupervised

# Optionally, create a result DataFrame
results = pd.DataFrame({
    "attack_score_supervised": attack_score_supervised,
    "attack_score_unsupervised": attack_score_unsupervised,
    "combined_score": combined_score,
})


# 10. Explainability 
results["explanation"] = None

# Indices of attacks
attack_idx = np.where(supervised_label != "Benign")[0]

print(f"Found {len(attack_idx)} attacks for explanation.")

MAX_EXPLAIN = 200
attack_idx = attack_idx[:MAX_EXPLAIN]

# Run batch explain
explanations = explainer.explain_attacks(
    X_raw,
    supervised_label,
    attack_idx
)

# Store results
for i, text in explanations:
    results.at[i, "explanation"] = text


# If you want a hard label from supervised model:
if hasattr(supervised_model, "predict"):
    predicted_label_encoded = supervised_model.predict(X_scaled)
    results["predicted_label_encoded"] = predicted_label_encoded

# Save results if needed
out_path = os.path.join(BACKEND_DIR, "attack_predictions.csv")
results.to_csv(out_path, index=False)
print(f"Saved predictions to: {out_path}")
