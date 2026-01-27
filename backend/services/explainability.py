import os
import shap
import numpy as np
import pandas as pd
import pickle
import tensorflow as tf


class ExplainabilityService:
    def __init__(self):
        BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))

        # ---- supervised model (xgboost) ----
        with open(os.path.join(BASE_DIR, "Supervised", "final_model.pkl"), "rb") as f:
            self.xgb_model = pickle.load(f)

        # ---- autoencoder (SAFE load for py3.11) ----
        AUTOENCODER_PATH = os.path.join(BASE_DIR, "Unsupervised_learning", "autoencoder_model.keras")
        self.autoencoder = tf.keras.models.load_model(
            AUTOENCODER_PATH,
            compile=False
        )

        # ---- preprocessors ----
        with open(os.path.join(BASE_DIR, "Data_cleaning", "scaler.pkl"), "rb") as f:
            self.scaler = pickle.load(f)

        with open(os.path.join(BASE_DIR, "Data_cleaning", "final_features.pkl"), "rb") as f:
            self.feature_columns = pickle.load(f)

        # ---- SHAP explainer ----
        self.explainer = shap.TreeExplainer(self.xgb_model)

    def explain(self, sample_df: pd.DataFrame, attack_label: str):

        # ---------- SHAP ----------
        shap_values = self.explainer.shap_values(sample_df)
        mean_shap = np.abs(shap_values).mean(axis=0)

        shap_df = (
            pd.DataFrame({
                "feature": sample_df.columns,
                "importance": mean_shap
            })
            .sort_values(by="importance", ascending=False)
            .head(5)
        )

        # ---------- Autoencoder ----------
        x_scaled = self.scaler.transform(sample_df)
        x_recon = self.autoencoder.predict(x_scaled, verbose=0)
        deviation = np.abs(x_scaled - x_recon)[0]

        ae_df = (
            pd.DataFrame({
                "feature": self.feature_columns,
                "deviation": deviation
            })
            .sort_values(by="deviation", ascending=False)
            .head(5)
        )

        # ---------- Text explanation ----------
        text = (
            f"The flow was classified as {attack_label} due to high influence from "
            f"{', '.join(shap_df.feature[:2])}. "
            f"Abnormal behavior was observed in "
            f"{', '.join(ae_df.feature[:2])}."
        )

        return {
            "shap_top_features": shap_df.to_dict(orient="records"),
            "ae_top_features": ae_df.to_dict(orient="records"),
            "text": text
        }
