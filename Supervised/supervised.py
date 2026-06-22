import pandas as pd
import numpy as np
import pickle

from sklearn.metrics import classification_report, confusion_matrix, f1_score
import matplotlib.pyplot as plt
import seaborn as sns
import wandb

# Load datasets
X_train_selected = pd.read_parquet("../Data_cleaning/X_train_selected.parquet")
X_test_selected = pd.read_parquet("../Data_cleaning/X_test_selected.parquet")

#def add_web_flow_features(df):
#    eps = 1e-6  # prevent division by zero

    # 1️⃣ Request–response asymmetry (Web attacks are client-heavy)
#    df["web_req_resp_ratio"] = (
#        df["fwd_packet_length_max"] + eps
#    ) / (
#         df["bwd_packet_length_max"] + eps
#     )

#     # 2️⃣ Short-lived flow indicator (XSS, SQLi)
#     df["web_short_flow"] = (df["flow_duration"] < 1e5).astype(int)

#     # 3️⃣ Small payload dominance
#     df["web_small_payload"] = (df["fwd_packet_length_mean"] < 200).astype(int)

#     # 4️⃣ Burst behavior (optional but useful)
#     df["web_burst_rate"] = (
#         df["flow_packets/s"] / (df["flow_duration"] + eps)
#     )

#     return df

#X_train_selected = add_web_flow_features(X_train_selected)
#X_test_selected  = add_web_flow_features(X_test_selected)


y_train = pd.read_parquet("../Data_cleaning/y_train.parquet")["label"]
y_test = pd.read_parquet("../Data_cleaning/y_test.parquet")["label"]

# Load artifacts
with open("../Data_cleaning/labelencoder.pkl", "rb") as f:
    le = pickle.load(f)

# ==============================
# FILTER RARE ATTACK CLASS (SUPERVISED ONLY)
# ==============================

X_train_selected = X_train_selected.reset_index(drop=True)
y_train = y_train.reset_index(drop=True)

X_test_selected = X_test_selected.reset_index(drop=True)
y_test = y_test.reset_index(drop=True)

# Identify label index for 'Rare'
rare_label = list(le.classes_).index("Rare")
print("Rare label index:", rare_label)

train_mask = y_train != rare_label
test_mask = y_test != rare_label
#Filter train data
X_train_selected = X_train_selected.loc[train_mask].reset_index(drop=True)
y_train = y_train.loc[train_mask].reset_index(drop=True)

# Filter test data
X_test_selected = X_test_selected.loc[test_mask].reset_index(drop=True)
y_test = y_test.loc[test_mask].reset_index(drop=True)

from sklearn.preprocessing import LabelEncoder
le_xgb = LabelEncoder()
y_train_xgb = le_xgb.fit_transform(y_train)
y_test_xgb = le_xgb.transform(y_test)

with open("labelencoder_xgb.pkl", "wb") as f:
    pickle.dump(le_xgb, f)

print("XGB classes (no Rare):", le_xgb.classes_)


print("After filtering Rare:")
print("Train label distribution:\n", y_train.value_counts())
print("Test label distribution:\n", y_test.value_counts())


print("Data loaded successfully")
print("Train shape:", X_train_selected.shape)
print("Test shape:", X_test_selected.shape)


def evaluate_model(model, X_test, y_test, model_name):
    classes = le_xgb.classes_
    y_pred = model.predict(X_test)

    print(f"\n===== {model_name} =====")
    print("Macro F1:", f1_score(y_test, y_pred, average="macro"))
    print("Weighted F1:", f1_score(y_test, y_pred, average="weighted"))

    print("\nClassification Report:")
    print(classification_report(y_test, y_pred, target_names=classes))

    cm = confusion_matrix(y_test, y_pred)
    plt.figure(figsize=(10, 7))
    sns.heatmap(cm, annot=False, cmap="Blues",
                xticklabels=classes,
                yticklabels=classes)
    plt.title(f"{model_name} Confusion Matrix")
    plt.xlabel("Predicted")
    plt.ylabel("Actual")
    plt.savefig(f"{model_name.replace(' ', '_')}_confusion_matrix.png", bbox_inches="tight")
    plt.close()

wandb.init(
    project="nids-attack-classification",
    config={
        "dataset": "CICIDS2017",
        "attack_classes": 8,
        "rare_class_removed": True,
        "xgb_n_estimators": 300,
        "xgb_max_depth": 6,
        "xgb_learning_rate": 0.1,
        "xgb_subsample": 0.8,
        "xgb_colsample_bytree": 0.8,
        "xgb_objective": "multi:softprob",
        "rf_n_estimators": 300,
        "rf_max_depth": 20,
        "class_weighting": "balanced",
        "feature_selection": "5-method ensemble (ANOVA, MI, Boruta, RF, correlation)",
    }
)

from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, confusion_matrix

lr = LogisticRegression(
    solver="saga",
    max_iter=200,
    n_jobs=-1,
    class_weight="balanced",
    random_state=42
)

lr.fit(X_train_selected, y_train)

y_pred_lr = lr.predict(X_test_selected)

print("Logistic Regression Results")
print(classification_report(y_test, y_pred_lr))

from sklearn.ensemble import RandomForestClassifier

rf = RandomForestClassifier(
    n_estimators=300,
    max_depth=20,
    min_samples_split=10,
    min_samples_leaf=5,
    n_jobs=-1,
    class_weight="balanced",
    random_state=42
)

rf.fit(X_train_selected, y_train)

y_pred_rf = rf.predict(X_test_selected)

print("Random Forest Results")
print(classification_report(y_test, y_pred_rf))

from xgboost import XGBClassifier

from sklearn.utils.class_weight import compute_class_weight
import numpy as np
from sklearn.metrics import classification_report


# ------------------------------
# CLASS WEIGHT BOOSTING
# ------------------------------
classes = np.unique(y_train_xgb)
class_weights = compute_class_weight(
    class_weight="balanced",
    classes=classes,
    y=y_train_xgb
)
class_weight_dict = dict(zip(classes, class_weights))

print("classes:",classes)
print("class_weights",class_weights)

sample_weights = np.array([class_weight_dict[y] for y in y_train_xgb])

# ------------------------------
# XGBOOST MODEL (WEB-FRIENDLY)
# ------------------------------
xgb = XGBClassifier(
    n_estimators=300,
    max_depth=6,              # reduced for minority classes (Web)
    learning_rate=0.1,
    subsample=0.8,
    colsample_bytree=0.8,
    objective="multi:softprob", # better class decision
    num_class=len(le_xgb.classes_),
    eval_metric="merror",
    tree_method="hist",
    n_jobs=-1,
    random_state=42
)

# Train with class weights
xgb.fit(
    X_train_selected,
    y_train_xgb,
    sample_weight=sample_weights
)



y_pred_xgb = xgb.predict(X_test_selected)

print("XGBoost Results(Rare removed)")
# class_names_no_rare = [
#     cls for cls in le.classes_ if cls != "Rare"
# ]
class_names_no_rare = [str(cls) for cls in le_xgb.classes_]

print(classification_report(y_test_xgb, 
                            y_pred_xgb,
                            target_names= class_names_no_rare
))

# ==============================
# Precision–Recall Curve + Precision Floor
# ==============================

from sklearn.metrics import precision_recall_curve
from sklearn.preprocessing import label_binarize

# Binarize labels for multi-class PR curve
y_test_bin = label_binarize(
    y_test_xgb,
    classes=np.arange(len(le_xgb.classes_))
)

# Get prediction probabilities (REQUIRED for PR curve)
y_score = xgb.predict_proba(X_test_selected)

precision_floor = 0.90  # as per NAD requirement

print("\nPrecision Floor Analysis (>= 0.90):")

for i, class_name in enumerate(le_xgb.classes_):
    precision, recall, thresholds = precision_recall_curve(
        y_test_bin[:, i],
        y_score[:, i]
    )

    # Find first threshold where precision >= floor
    valid_idx = np.where(precision >= precision_floor)[0]

    if len(valid_idx) > 0:
        idx = valid_idx[0]
        print(
            f"Class: {str(class_name):12s} | "
            f"Threshold: {thresholds[idx-1]:.4f} | "
            f"Precision: {precision[idx]:.3f} | "
            f"Recall: {recall[idx]:.3f}"
        )
    else:
        print(
            f"Class: {str(class_name):12s} | "
            f"No threshold meets precision floor"
        )

#printing false positive rate(FPR)
cm = confusion_matrix(y_test_xgb, y_pred_xgb)
class_names = le_xgb.classes_

#computing the FPR per class
fpr_per_class = {}

for i, cls in enumerate(class_names):
    FP = cm[:, i].sum() - cm[i, i]
    TN = cm.sum() - (cm[i, :].sum() + cm[:, i].sum() - cm[i, i])

    fpr = FP / (FP + TN)
    fpr_per_class[cls] = fpr

#printing the FPR per class
print("False Positive Rate per class:")
for cls, fpr in fpr_per_class.items():
    print(f"{str(cls):12s}: {fpr:.4f}")


overall_fpr = np.mean(list(fpr_per_class.values()))
print(f"\nOverall False Positive Rate (macro): {overall_fpr:.4f}")


import seaborn as sns
import matplotlib.pyplot as plt
#from sklearn.metrics import confusion_matrix

def plot_confusion(y_true, y_pred, title):
    cm = confusion_matrix(y_true, y_pred)
    plt.figure(figsize=(8, 6))
    sns.heatmap(cm, annot=False, cmap="Blues", fmt="d")
    plt.title(title)
    plt.xlabel("Predicted")
    plt.ylabel("Actual")
    plt.savefig(f"{title.replace(' ', '_')}.png", bbox_inches="tight")
    plt.close()

plot_confusion(y_test_xgb, y_pred_xgb, "XGBoost Confusion Matrix")

from sklearn.metrics import f1_score, classification_report

# Collect predictions
predictions = {
    "Logistic Regression": y_pred_lr,
    "Random Forest": y_pred_rf,
    "XGBoost": y_pred_xgb
}

# Evaluate F1-score (macro-average for multi-class)
f1_scores = {}
for name, y_pred in predictions.items():
    if name == "XGBoost":
        # XGBoost uses encoded labels
        f1 = f1_score(y_test_xgb, y_pred, average="macro")
        class_names_no_rare = [cls for cls in le.classes_ if cls != "Rare"]

        print(classification_report(
            y_test_xgb,
            y_pred,
            target_names=class_names_no_rare
        ))
    else:
        # Other models use original labels
        f1 = f1_score(y_test, y_pred, average="macro")
        print(classification_report(y_test, y_pred))

    f1_scores[name] = f1
    wandb.log({f"{name.lower().replace(' ', '_')}_macro_f1": f1})

# Log all model F1 scores together for easy comparison
wandb.log({
    "lr_macro_f1":  f1_scores.get("Logistic Regression", 0),
    "rf_macro_f1":  f1_scores.get("Random Forest", 0),
    "xgb_macro_f1": f1_scores.get("XGBoost", 0),
})

# Log per-class XGBoost F1 scores
xgb_report = classification_report(
    y_test_xgb, predictions["XGBoost"],
    target_names=[str(c) for c in le_xgb.classes_],
    output_dict=True
)
for cls, metrics in xgb_report.items():
    if isinstance(metrics, dict):
        wandb.log({f"xgb_f1_{cls.replace(' ', '_')}": metrics["f1-score"]})

# Log XGBoost confusion matrix
cm_xgb = confusion_matrix(y_test_xgb, predictions["XGBoost"])
class_labels = [str(c) for c in le_xgb.classes_]
wandb.log({
    "xgb_confusion_matrix": wandb.plot.confusion_matrix(
        probs=None,
        y_true=y_test_xgb.tolist(),
        preds=predictions["XGBoost"].tolist(),
        class_names=class_labels,
    )
})

# Log overall FPR
wandb.log({"overall_fpr_macro": overall_fpr})
for cls, fpr in fpr_per_class.items():
    wandb.log({f"fpr_{str(cls).replace(' ', '_')}": fpr})

# Select best model
best_model_name = max(f1_scores, key=f1_scores.get)
print(f"\n Best model based on F1-score: {best_model_name}")
wandb.log({"best_model": best_model_name, "best_model_macro_f1": f1_scores[best_model_name]})

# Map model name to trained object
models = {
    "Logistic Regression": lr,
    "Random Forest": rf,
    "XGBoost": xgb
}
best_model = models[best_model_name]

# Save the final model
import pickle
with open("final_model.pkl", "wb") as f:
    pickle.dump(best_model, f)

print(f"Final model saved: {best_model_name}")

wandb.finish()

