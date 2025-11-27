# Network Intrusion Detection System (NIDS)

This repository contains a **Network Intrusion Detection System (NIDS)** built using the **CICIDS2017 dataset**. The project focuses on **data ingestion, cleaning, feature engineering, and feature selection** to prepare the dataset for machine learning models.

---

## Project Structure

* `DataSet/` - Folder containing `.parquet` files from CICIDS2017 dataset.
* `Data_Cleaning/` - Jupyter notebooks containing code for data preprocessing, feature engineering, and feature selection.
* `README.md` - Project documentation.

---

## Overview

This project follows the standard workflow for building an NIDS:

### 1. Data Ingestion and Cleaning

* Load all `.parquet` files from the dataset.
* Handle missing or infinite values.
* Remove duplicate or corrupted rows.
* Fix column data types.
* Produce a clean, unified master dataset.

### 2. Feature Engineering

#### Core Features

* Flow-level network features: `flow_duration`, `packet_rate`, `bytes_per_packet`.
* Forward and backward packet statistics.
* TCP/UDP/ICMP protocol features.
* Flag counts, ratios, and burst indicators.
* Inter-arrival time (IAT) features.

#### Advanced Features

* Statistical aggregates: mean, std, max/min per flow.
* Coefficient of Variation (CV) for idle and active periods.
* Flow anomaly indicators using z-score.
* Expanding cumulative mean and std for packet size and IAT.
* Activity period ratios and normalized protocol flag rates.

### 3. Feature Selection

* **Correlation Analysis:** Remove highly correlated features (`>0.95` correlation).
* **ANOVA F-score:** Select top features based on variance with respect to labels.
* **Mutual Information (MI):** Identify features with high predictive power.
* **Random Forest Importance:** Rank features based on ensemble model importance.
* **Boruta Feature Selection:** Robust wrapper method using Random Forest.
* **Final Feature Set:** Union of top features from ANOVA, MI, and RF.

### 4. Data Preparation for Modeling

* Split dataset into `X_train`, `X_test`, `y_train`, `y_test`.
* Standard scaling of numerical features.
* Filter datasets using selected features for model input.

---

## Dependencies

* Python 3.8+
* Pandas
* NumPy
* Scikit-learn
* Boruta
* Seaborn, Matplotlib
* SciPy

---

## How to Use

1. Place `.parquet` files in the `DataSet/` folder.
2. Open the Jupyter notebook in `Data_Cleaning/`.
3. Run cells sequentially for:

   * Data ingestion and cleaning
   * Feature engineering
   * Feature selection
4. Output will be scaled and filtered datasets ready for modeling:
   `X_train_final`, `X_test_final`, `y_train`, `y_test`.

---

## Next Steps

* // To be added: Model training, evaluation, and comparison using classifiers like Random Forest, XGBoost, Neural Networks, etc.
* // To be added: Deployment of NIDS for real-time network monitoring.

---

## License

[MIT License](LICENSE)

---

## References

* CICIDS2017 Dataset: [https://www.kaggle.com/datasets/dhoogla/cicids2017](https://www.kaggle.com/datasets/dhoogla/cicids2017)
* Scikit-learn Documentation: [https://scikit-learn.org/stable/](https://scikit-learn.org/stable/)
* BorutaPy Documentation: [https://github.com/scikit-learn-contrib/boruta_py](https://github.com/scikit-learn-contrib/boruta_py)
