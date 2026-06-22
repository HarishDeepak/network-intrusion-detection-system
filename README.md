# Network Intrusion Detection System (NIDS)

An end-to-end machine learning pipeline for detecting and classifying network attacks in real time, built on the **CICIDS2017** benchmark dataset. The system combines a supervised XGBoost classifier with an unsupervised Keras autoencoder through a hybrid fusion engine, and surfaces results via a FastAPI backend and a live Streamlit dashboard.

---

## Architecture

```
.pcap captures
      │
      ▼
 CICFlowMeter               ← extracts 80+ flow-level features
      │
      ▼
 Data Cleaning & Feature Engineering    (Data_cleaning/)
   • Handle NaN / inf, remove duplicates
   • Engineer 48 features: IAT stats, TCP flag ratios,
     burst indicators, anomaly z-scores, protocol one-hots
   • 5-method selection: ANOVA · MI · Boruta · RF Importance · correlation pruning
      │
      ├──────────────────────────────────────────┐
      ▼                                          ▼
 Supervised Model (Supervised/)         Unsupervised Model (Unsupervised_learning/)
   XGBoost classifier                     Keras Autoencoder (128→64→128)
   8 attack classes + Benign               trained on benign-only traffic
   LabelEncoder + class-balanced           reconstruction error = anomaly score
      │                                          │
      └──────────────┬───────────────────────────┘
                     ▼
          Hybrid Fusion Decision Engine   (backend/models/decision_engine.py)
            rule-based + weighted fusion
            severity: Low / Medium / High
            structured decision trace per flow
                     │
          ┌──────────┴──────────┐
          ▼                     ▼
   SHAP Explainability     FastAPI Backend    (backend/)
   per-prediction NL       async pipeline
   attack summaries        SQLite dual-log
                                │
                          Streamlit Dashboard  (frontend/)
                          10s auto-refresh · KPI cards
                          Plotly charts · alert feed
                                │
                          Email Alert System
                          SMTP · severity-tagged
                          AI-generated explanation body
```

---

## Key Results

| Model | Macro F1 | Accuracy | FPR (macro) | Notes |
|---|---|---|---|---|
| **XGBoost (supervised)** | **0.897** | **99.9%** | **0.04%** | best model, selected by macro F1 |
| Random Forest | 0.830 | 99.4% | — | strong baseline |
| Logistic Regression | 0.500 | 90.1% | — | did not converge (saga) |
| Keras Autoencoder | — | — | **2.0%** | ROC-AUC 0.964, unsupervised |
| Isolation Forest | — | — | — | ROC-AUC 0.839, comparison only |

**XGBoost per-class F1 (8-class, Rare removed):**

| Class | Precision | Recall | F1 |
|---|---|---|---|
| Benign | 1.00 | 1.00 | 1.00 |
| DoS | 1.00 | 1.00 | 1.00 |
| BruteForce | 0.97 | 0.95 | 0.96 |
| Scan | 0.96 | 0.99 | 0.98 |
| Malware | 0.88 | 0.99 | 0.93 |
| Web | 0.44 | 0.60 | 0.51 |

Dataset: **585k flows** from CICIDS2017 (467k train / 116k test), 8 attack classes.

**Experiment tracking:** [![W&B](https://img.shields.io/badge/Weights_&_Biases-FFBE00?logo=weightsandbiases&logoColor=black)](https://wandb.ai/harishdeepak77718-tu-darmstadt/nids-attack-classification)

---

## Project Structure

```
network-intrusion-detection-system/
│
├── DataSet/                    # CICIDS2017 parquet files (one per attack day)
├── Data_cleaning/              # Preprocessing, feature engineering, feature selection
│   ├── copy_of_preprocessing.ipynb
│   ├── copy_of_preprocessing.py
│   └── *.pkl / *.parquet       # saved scaler, imputer, selected features, train/test splits
│
├── Supervised/                 # XGBoost training and evaluation
│   ├── supervised.ipynb
│   ├── supervised.py
│   └── final_model.pkl         # trained XGBoost model
│
├── Unsupervised_learning/      # Autoencoder + Isolation Forest
│   ├── Unsupervised_Learning.ipynb
│   ├── autoencoder_full.pkl    # model + scaler + threshold bundled
│   ├── isolation_forest.pkl
│   ├── ae_normalization_params.json
│   ├── drift_detector.py       # DriftMonitor class for production monitoring
│   └── fp_analysis_report.txt
│
├── SHAP_AI/                    # SHAP explainability notebooks
│   └── ExplainableAI.ipynb
│
├── backend/
│   ├── main.py                 # FastAPI app: upload, pipeline trigger, status polling
│   ├── run_fusion.py           # fusion orchestration script
│   ├── models/
│   │   ├── decision_engine.py  # hybrid fusion + severity logic
│   │   ├── Prediction.py       # inference: load models → predict → explain
│   │   ├── database.py         # SQLite models (AttackLog, AlertLog)
│   │   ├── charts.py
│   │   ├── stats.py
│   │   └── packet.py
│   ├── api/
│   │   ├── alerts.py           # /api/alerts endpoints
│   │   ├── dashboard.py        # /dashboard endpoints
│   │   └── db_endpoints.py     # DB query endpoints
│   ├── services/
│   │   ├── email_services.py   # SMTP alert system + dual JSON/DB logging
│   │   └── explainability.py   # SHAP TreeExplainer + AE deviation analysis
│   └── attackcsv/              # uploaded CSVs from CICFlowMeter
│
├── frontend/
│   ├── streamlit_dashboard.py  # main dashboard (KPIs, charts, auto-refresh)
│   └── pages/
│       └── logs_viewer.py      # paginated attack + alert log viewer
│
└── logs/
    ├── attack_log.json
    └── alert_log.json
```

---

## Components

### 1. Feature Engineering (`Data_cleaning/`)

Raw CICFlowMeter CSV → clean 48-feature dataset:

- Flow-level stats: `flow_duration`, `packet_rate`, `bytes_per_packet`
- IAT features: mean, std, CV for forward/backward inter-arrival times
- TCP flag ratios: `syn_fin_ratio`, `psh_ack_ratio`, `total_flag_count`
- Anomaly indicators: `abnormal_flow_duration` (z-score > 3), `flow_anomaly_index`
- Protocol-normalized rates: `proto_*_flag_rate`, `flag_change_rate`

**Feature selection** — five methods in parallel, final set is union of top-ranked features:
- Correlation pruning (threshold > 0.95)
- ANOVA F-score
- Mutual Information
- Random Forest Importance
- Boruta (wrapper around RF)

### 2. Supervised Model (`Supervised/`)

XGBoost multi-class classifier over 8 labels. Training details:
- Rare-class filtering before training
- LabelEncoder fitted separately for XGBoost (`labelencoder_xgb.pkl`)
- Evaluated by macro F1 and per-class classification report
- Baseline comparison: Logistic Regression (saga, multinomial)

### 3. Unsupervised Model (`Unsupervised_learning/`)

Keras autoencoder trained **exclusively on benign traffic**; attacks manifest as high reconstruction error.

Architecture:
```
Input(48) → Dense(128, relu) → BatchNorm → Dropout(0.2)
          → Dense(64, relu)
          → Dense(128, relu) → BatchNorm
          → Dense(48, linear)
```

Threshold selection: ROC-curve optimal (maximise TPR − FPR).  
Also includes: Isolation Forest (200 trees, contamination=0.05) for comparison.  
Production artifact: `drift_detector.py` — sliding-window monitor for reconstruction error drift.

### 4. Hybrid Fusion Decision Engine (`backend/models/decision_engine.py`)

Two fusion paths run in parallel:

| Path | Logic |
|---|---|
| Rule-based | `ae_score > threshold AND xgb_label != Benign AND xgb_confidence > threshold` |
| Weighted | `WEIGHT_AE * ae_norm + WEIGHT_XGB * xgb_confidence > fusion_threshold` |

Final decision: `attack = rule_attack OR weighted_attack`  
Severity: **High** (high AE + high XGB confidence) / **Medium** / **Low**  
Output per flow: `attack`, `attack_type`, `ae_score`, `xgb_confidence`, `fusion_score`, `severity`, `reason`, `timestamp`

### 5. Explainability (`backend/services/explainability.py`, `SHAP_AI/`)

- **SHAP TreeExplainer**: background built once from 3k random samples, cached across requests
- **Autoencoder deviation**: per-feature absolute deviation `|X_scaled − X_recon|`, top-2 anomalous features extracted
- Output: natural language sentence per attack — `"The flow was classified as DDoS due to high influence from [feat1, feat2]. Abnormal behavior detected in [ae_feat1, ae_feat2]."`
- Batch mode with progress ETA; up to 200 explanations per pipeline run

### 6. FastAPI Backend (`backend/main.py`)

| Endpoint | Description |
|---|---|
| `POST /upload-and-run/` | Upload CICFlowMeter CSV → triggers async `Prediction.py → run_fusion.py` pipeline |
| `GET /pipeline-status/` | Returns `{prediction: running/completed/failed, fusion: ...}` |
| `GET /api/alerts` | Recent alerts from DB |
| `GET /dashboard/*` | Aggregated stats for frontend |
| `GET /api/db/*` | Raw DB query endpoints |

Pipeline status is written to `pipeline_status.json` at each stage; frontend polls this every 10s.

### 7. Streamlit Dashboard (`frontend/`)

- Auto-refresh every 10 seconds via `streamlit-autorefresh`
- 5-column KPI row: total flows, attacks detected, benign, high-severity, active alerts
- Plotly bar chart: attack type distribution
- Plotly time-series: detections over time
- Severity gauge (anomaly index)
- Paginated attack log and alert log viewer

### 8. Email Alert System (`backend/services/email_services.py`)

Triggered on every detected attack:
- Severity inferred from fusion engine output (High/Medium/Low) or attack-type map
- Email body includes: attack type, source/dest IP, protocol, confidence %, AI-generated explanation
- Dual logging: JSON flat file (`logs/attack_log.json`) + SQLite (`AttackLog`, `AlertLog` tables)
- Graceful fallback: stdout logging in test mode (`use_email=False`)

---

## Setup

### Requirements

```bash
pip install -r requirements.txt
```

Key dependencies: `fastapi`, `uvicorn`, `streamlit`, `streamlit-autorefresh`, `xgboost`, `tensorflow`, `shap`, `scikit-learn`, `boruta`, `pandas`, `numpy`, `plotly`, `sqlalchemy`

### Running the backend

```bash
cd backend
uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```

### Running the dashboard

```bash
cd frontend
streamlit run streamlit_dashboard.py
```

### Running a prediction pipeline manually

1. Place a CICFlowMeter-generated CSV in `backend/attackcsv/`
2. `POST /upload-and-run/` via curl or the dashboard upload button
3. Poll `GET /pipeline-status/` until `fusion: completed`
4. Attack results written to `backend/attack_predictions.csv` and SQLite DB

### Training from scratch

1. Download CICIDS2017 from [Kaggle](https://www.kaggle.com/datasets/dhoogla/cicids2017) and place parquets in `DataSet/`
2. Run `Data_cleaning/copy_of_preprocessing.ipynb` — outputs train/test splits and saved artifacts
3. Run `Supervised/supervised.ipynb` — trains and saves XGBoost model
4. Run `Unsupervised_learning/Unsupervised_Learning.ipynb` — trains autoencoder and Isolation Forest

---

## Dataset

**CICIDS2017** — Canadian Institute for Cybersecurity Intrusion Detection Evaluation Dataset 2017  
~2.8M network flows, 80 features per flow, 8 attack categories captured over 5 days.

| Day | Attack Types |
|---|---|
| Monday | Benign only |
| Tuesday | BruteForce (FTP, SSH) |
| Wednesday | DoS (Slowloris, Hulk, GoldenEye) |
| Thursday | WebAttacks (XSS, SQLi, Infiltration) |
| Friday | DDoS, PortScan, Botnet |

Reference: [https://www.kaggle.com/datasets/dhoogla/cicids2017](https://www.kaggle.com/datasets/dhoogla/cicids2017)

---

## Team

Built as a team data science project. Contributions span: data preprocessing, feature engineering, supervised and unsupervised model training, fusion engine design, SHAP explainability, FastAPI backend, Streamlit dashboard, and email alerting.

---

## License

[MIT License](LICENSE)

---

## References

- CICIDS2017 Dataset: [https://www.kaggle.com/datasets/dhoogla/cicids2017](https://www.kaggle.com/datasets/dhoogla/cicids2017)
- Scikit-learn Documentation: [https://scikit-learn.org/stable/](https://scikit-learn.org/stable/)
- BorutaPy Documentation: [https://github.com/scikit-learn-contrib/boruta_py](https://github.com/scikit-learn-contrib/boruta_py)
- SHAP Documentation: [https://shap.readthedocs.io/](https://shap.readthedocs.io/)
- XGBoost Documentation: [https://xgboost.readthedocs.io/](https://xgboost.readthedocs.io/)
