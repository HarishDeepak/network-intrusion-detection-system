import numpy as np
import pandas as pd
import shap
import time


class ExplainabilityService:

    def __init__(self, supervised_model, autoencoder_artifacts, max_shap_samples=2000):

        self.model = supervised_model

        self.autoencoder = autoencoder_artifacts["model"]
        self.scaler = autoencoder_artifacts["scaler"]
        self.features = autoencoder_artifacts["feature_columns"]

        self.max_shap_samples = max_shap_samples

        # Init once
        self.explainer = shap.TreeExplainer(self.model)

        self._shap_cache = None


   
    # Build SHAP background once    
    def build_background(self, X):

        if self._shap_cache is not None:
            return


        print("[Explainability] Building SHAP background...")

        bg = X.sample(
            min(len(X), self.max_shap_samples),
            random_state=42
        )

        shap_vals = self.explainer.shap_values(bg)

        mean_vals = np.abs(shap_vals).mean(axis=(0, 2))

        self._shap_cache = pd.DataFrame({
            "feature": bg.columns,
            "importance": mean_vals
        }).sort_values("importance", ascending=False)


    # Batch explain (FAST, cached)
    # --------------------------------------------------
    def explain_attacks(self, X, labels, attack_idx):
        # Build SHAP cache (once) 
        self.build_background(X)
      
        # Autoencoder (run once)    
        X_ord = X[self.scaler.feature_names_in_]
        X_scaled = self.scaler.transform(X_ord)
        X_recon = self.autoencoder.predict(X_scaled, verbose=0)
        deviations = np.abs(X_scaled - X_recon)
        explanations = []

        # Progress tracking
        start = time.time()
        total = len(attack_idx)
        print(f"[Explainability] Generating {total} explanations...")

           # Main loop
        for count, i in enumerate(attack_idx, 1):

            # SHAP
            top_shap = self._shap_cache.head(5)
            shap_feats = ", ".join(
                top_shap["feature"].values[:2]
            )


            # Autoencoder
            ae_idx = np.argsort(-deviations[i])[:5]

            ae_feats = ", ".join(
                self.features[j] for j in ae_idx[:2]
            )


            # Label
            label = labels[i]

            # Build explanation
            text = (
                f"The network flow was classified as {label} due to high influence "
                f"from features such as {shap_feats}. "
                f"Additionally, abnormal behavior was detected in "
                f"{ae_feats}, which deviated significantly from normal traffic patterns."
            )

            explanations.append((i, text))

            # Progress log
            if count % 5 == 0 or count == total:

                elapsed = time.time() - start
                avg = elapsed / count
                remaining = avg * (total - count)

                print(
                    f"[Explainability] {count}/{total} done "
                    f"({count/total:.1%}) | "
                    f"ETA: {int(remaining)}s"
                )

        return explanations
