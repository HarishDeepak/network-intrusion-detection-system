import os
import pickle
import numpy as np
import pandas as pd
import shap

def decode_labels(label_encoded_series):
    """
    Decode numeric label indices to attack type names
    Uses the label encoder from the training process
    """
    BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

    # Load the XGB label encoder
    with open(os.path.join(BASE_DIR, "Supervised/labelencoder_xgb.pkl"), "rb") as f:
        xgb_le = pickle.load(f)

    # Load the original label encoder
    with open(os.path.join(BASE_DIR, "Data_cleaning/labelencoder.pkl"), "rb") as f:
        original_le = pickle.load(f)

    # Map numeric indices to attack names
    original_labels = original_le.inverse_transform(xgb_le.classes_)
    label_map = {i: original_labels[i] for i in range(len(original_labels))}

    return label_encoded_series.map(label_map)


class ExplainabilityService:
    def __init__(self, supervised_model, autoencoder_artifacts, max_shap_samples=5000):
        self.max_shap_samples = max_shap_samples
        self.supervised_model = supervised_model
        self.autoencoder = autoencoder_artifacts["model"]
        self.scaler = autoencoder_artifacts["scaler"]
        self.feature_columns = autoencoder_artifacts["feature_columns"]
        self.shap_explainer = shap.TreeExplainer(self.supervised_model)

    def _explain_shap(self, sample_df):
        X_shap = sample_df.sample(min(len(sample_df), self.max_shap_samples), random_state=42)
        shap_values = self.shap_explainer.shap_values(X_shap)
        mean_shap = np.abs(shap_values).mean(axis=(0, 2))
        shap_importance = pd.DataFrame({
            "feature": X_shap.columns,
            "importance": mean_shap
        }).sort_values(by="importance", ascending=False)
        return shap_importance

    def explain_batch(self, sample_df, attack_labels=None):
        # ------------------------
        # Autoencoder deviation
        # ------------------------
        sample_df_ordered = sample_df[self.scaler.feature_names_in_]
        x_scaled = self.scaler.transform(sample_df_ordered)
        x_reconstructed = self.autoencoder.predict(x_scaled, verbose=0)
        deviations = np.abs(x_scaled - x_reconstructed)

        # ------------------------
        # SHAP explanation
        # ------------------------
        shap_importance = self._explain_shap(sample_df)

        # Decode attack labels if numeric
        if attack_labels is not None and np.issubdtype(attack_labels.dtype, np.integer):
            attack_labels = decode_labels(pd.Series(attack_labels)).values

        explanations = []
        for i in range(len(sample_df)):
            top5_shap = shap_importance.head(5)
            top5_ae_idx = np.argsort(-deviations[i])[:5]
            top5_ae = pd.DataFrame({
                "feature": self.feature_columns,
                "deviation": deviations[i]
            }).iloc[top5_ae_idx]

            shap_features = ", ".join(top5_shap["feature"].values[:2])
            ae_features = ", ".join(top5_ae["feature"].values[:2])
            attack_label = attack_labels[i] if attack_labels is not None else "unknown"

            explanation = (
                f"The network flow was classified as {attack_label} due to high influence "
                f"from features such as {shap_features}. "
                f"Additionally, abnormal behavior was detected in "
                f"{ae_features}, which deviated significantly from normal traffic patterns."
            )
            explanations.append(explanation)

        return explanations