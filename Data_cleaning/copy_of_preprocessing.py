# monday_df = pd.read_parquet("../DataSet/Benign-Monday-no-metadata.parquet")
# wednesday_df = pd.read_parquet("../DataSet/DoS-Wednesday-no-metadata.parquet")
# tuesday_df = pd.read_parquet("../DataSet/Bruteforce-Tuesday-no-metadata.parquet")
# thursday_df = pd.read_parquet("../DataSet/Infiltration-Thursday-no-metadata.parquet")
# friday_df = pd.read_parquet("../DataSet/Botnet-Friday-no-metadata.parquet")

import pandas as pd
from glob import glob
import matplotlib.pylab as plt
import seaborn as sns
import numpy as np

from sklearn.preprocessing import LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from scipy.stats import entropy



files = glob("../DataSet/*.parquet")
dfs = [pd.read_parquet(f) for f in files]
df_all = pd.concat(dfs, ignore_index=True)
df_all.count()

# Convert them to all lowercase letters
# Replace spaces with underscores

df_all.columns = df_all.columns.str.replace(' ', '_').str.lower()

df_all.head(5)

# Enforce numeric columns ONLY based on patterns
def enforce_numeric(df):
    patterns = ["count", "packet", "bytes", "length", "duration",
                "rate", "mean", "std", "max", "min"]

    for col in df.columns:
        if any(pat in col for pat in patterns):
            df[col] = pd.to_numeric(df[col], errors="coerce")
    return df

df_all = enforce_numeric(df_all)

# only for sanity check

df_all = pd.get_dummies(df_all, columns=["protocol"], prefix="proto")

df_all.head(5)
# df_all['protocol'].nunique()

# limited the Benign to 250000 rows to make the other fields balanced so that model predicts correclty.
df_benign = df_all[df_all['label'] == "Benign"].sample(250000, random_state=42)
df_others = df_all[df_all['label'] != "Benign"]

df_balanced = pd.concat([df_benign, df_others])

# Shuffle after concatenation
df_balanced = df_balanced.sample(frac=1, random_state=42).reset_index(drop=True)

df_balanced.head(5)

# Find and handle null values

# Get the count of null values in each column
null_counts = df_balanced.isnull().sum()

# Print the total number of null entries in the dataset
print(f"Total null entries found: {null_counts.sum()}\n")

# Drop rows with any null values
df_balanced.dropna(inplace=True)

# Find and handle duplicates

# Get the count of duplicate rows
duplicate_count = df_balanced.duplicated().sum()

# # Print the number of duplicate entries found
print(f"Total duplicate entries found: {duplicate_count}\n")

# Remove duplicate rows from the dataset
df_balanced.drop_duplicates(inplace=True)

# Inform that duplicates have been removed
print("All duplicate entries have been removed.\n")

# Reset the index after dropping rows
df_balanced.reset_index(drop=True, inplace=True)

df_balanced.size

# Inspect categorical columns
categorical_columns = df_balanced.select_dtypes(include=['object']).columns.tolist()
print(f"Categorical columns: {categorical_columns}\n")

# Display the first 5 rows of the cleaned dataset
df_balanced.head(20)

# Encode the attack labels into numeric format (e.g., Benign=0, DoS=1, Botnet=2, etc.)

le = LabelEncoder()
df_balanced['label_encoded'] = le.fit_transform(df_balanced['label'])

# Convert only numeric columns
numeric_cols = df_balanced.columns.drop(['label', 'label_encoded'])
df_balanced[numeric_cols] = df_balanced[numeric_cols].apply(pd.to_numeric, errors='coerce')

# Remove invalid values
df_balanced = df_balanced.replace([np.inf, -np.inf], np.nan)
df_balanced.dropna(inplace=True)

attack_data = df_balanced['label'].value_counts()
print(attack_data)

plt.figure(figsize=(12,7))
sns.barplot(x=attack_data.values, y=attack_data.index, palette="viridis")

plt.title("Number of Attacks (CICIDS2017)")
plt.xlabel("Count")
plt.ylabel("Attack Type")
plt.tight_layout()
plt.show()

class_dist = df_balanced["label"].value_counts(normalize=True) * 100
print(class_dist)
plt.figure()
plt.bar(class_dist.index.astype(str), class_dist.values)
plt.title("Combined Class Distribution (%)")
plt.xlabel("Class Label")
plt.ylabel("Percentage")
plt.xticks(rotation=90, ha="right")
plt.tight_layout()
plt.show()



# Display value counts
print(df_balanced["label"].value_counts())

df_balanced.head(5)

label_mapping = {i: label for i, label in enumerate(le.classes_)}
print(label_mapping)

df_balanced.info()

df_balanced['label'].value_counts()

# Feature engineering
# Raw features (like total packets, bytes, flow duration) are useful, but ratios, rates, and normalized features often provide better signals for anomaly detection
# We also need to handle zero or negative values to prevent errors during feature calculation or ML training.

eps = 1e-3  # small number to avoid division by zero
df_balanced['flow_duration'] = df_balanced['flow_duration'].clip(lower=eps)


# rate / ratio features
df_balanced['total_packets'] = df_balanced['total_fwd_packets'] + df_balanced['total_backward_packets'] + eps
df_balanced['total_bytes'] = df_balanced['fwd_packets_length_total'] + df_balanced['bwd_packets_length_total'] + eps


# packet_rate → packets per second (flow_duration is in microseconds, divide by 1e6).
# bytes_per_packet → average size of a packet.
# High packet rate or unusual bytes per packet are often indicators of attacks (DoS, scanning, bursty flows).

df_balanced['packet_rate'] = df_balanced['total_packets'] / (df_balanced['flow_duration'] / 1e6)
df_balanced['bytes_per_packet'] = df_balanced['total_bytes'] / df_balanced['total_packets']



# Coefficient of Variation (CV) features
#CV = standard deviation / mean → measures relative variability.
# idle and active CV can indicate irregular traffic patterns, useful for detecting attacks.

df_balanced['idle_mean_safe'] = df_balanced['idle_mean'].replace(0, eps)
df_balanced['active_mean_safe'] = df_balanced['active_mean'].replace(0, eps)

df_balanced['idle_cv'] = df_balanced['idle_std'] / df_balanced['idle_mean_safe']
df_balanced['active_cv'] = df_balanced['active_std'] / df_balanced['active_mean_safe']

# Drop temporary safe columns
df_balanced.drop(columns=['idle_mean_safe', 'active_mean_safe'], inplace=True)

# TCP Behavior Feature ML can learn TCP-specific behavior patterns
protocol_cols = [col for col in df_balanced.columns if col.startswith('proto_')]

if 'proto_6' in df_balanced.columns:
    df_balanced['tcp_behavior'] = df_balanced['proto_6'] * df_balanced['flow_duration']
else:
    df_balanced['tcp_behavior'] = 0


# Burst Ratio
# burst_ratio ≈ 1 → almost all packets are forward → could indicate DoS or bursty traffic.
# burst_ratio ≈ 0.5 → traffic is balanced forward/backward.

if 'fwd_packets/s' in df_balanced.columns and 'flow_packets/s' in df_balanced.columns:
    df_balanced['burst_ratio'] = df_balanced['fwd_packets/s'] / (df_balanced['flow_packets/s'] + 1e-5)
else:
    df_balanced['burst_ratio'] = 0

# Packet Entropy
# Malicious traffic often has different entropy patterns compared to normal traffic.
df_balanced['packet_entropy'] = df_balanced[['fwd_packet_length_std', 'bwd_packet_length_std']].apply(
    lambda x: entropy([x[0] + 1e-9, x[1] + 1e-9], base=2),  # Add epsilon to avoid log(0)
    axis=1
)


# before feature selction or extraction do split and scale it so there is no imbalance.
X = df_balanced.drop(['label', 'label_encoded'], axis=1)
y = df_balanced['label_encoded']

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)



scaler = StandardScaler()

X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled = scaler.transform(X_test)


X_train_scaled[:1]

# Attack traffic often has unusual flag patterns SYN floods, FIN scans
# Total flags in the flow
df_balanced['total_flag_count'] = df_balanced[['fin_flag_count','syn_flag_count','rst_flag_count',
                                               'psh_flag_count','ack_flag_count','urg_flag_count',
                                               'cwe_flag_count','ece_flag_count']].sum(axis=1)

# SYN/FIN ratio → scanning or SYN flood
df_balanced['syn_fin_ratio'] = (df_balanced['syn_flag_count'] + 1e-5) / (df_balanced['fin_flag_count'] + 1e-5)

# PSH/ACK ratio → bursty traffic indicator
df_balanced['psh_ack_ratio'] = (df_balanced['psh_flag_count'] + 1e-5) / (df_balanced['ack_flag_count'] + 1e-5)


# Attack traffic can have unusual segment size distributions.
df_balanced['segment_ratio'] = (df_balanced['avg_fwd_segment_size'] + 1e-5) / (df_balanced['avg_bwd_segment_size'] + 1e-5)


# Captures variability of packet timing. Bursty attacks often have high CV.
df_balanced['fwd_iat_cv'] = (df_balanced['fwd_iat_std'] + 1e-5) / (df_balanced['fwd_iat_mean'] + 1e-5)
df_balanced['bwd_iat_cv'] = (df_balanced['bwd_iat_std'] + 1e-5) / (df_balanced['bwd_iat_mean'] + 1e-5)


# Skewed packet length distributions are often attack indicators.
df_balanced['fwd_packet_skew'] = (df_balanced['fwd_packet_length_mean'] - df_balanced['fwd_packet_length_min']) / (df_balanced['fwd_packet_length_std'] + 1e-5)
df_balanced['bwd_packet_skew'] = (df_balanced['bwd_packet_length_mean'] - df_balanced['bwd_packet_length_min']) / (df_balanced['bwd_packet_length_std'] + 1e-5)


df_balanced.info()

# import pandas as pd

# monday_df = pd.read_parquet("../DataSet/Benign-Monday-no-metadata.parquet")
# wednesday_df = pd.read_parquet("../DataSet/DoS-Wednesday-no-metadata.parquet")
# tuesday_df = pd.read_parquet("../DataSet/Bruteforce-Tuesday-no-metadata.parquet")
# thursday_df = pd.read_parquet("../DataSet/Infiltration-Thursday-no-metadata.parquet")
# friday_df = pd.read_parquet("../DataSet/Botnet-Friday-no-metadata.parquet")

import pandas as pd
from glob import glob
import matplotlib.pylab as plt
import seaborn as sns
import numpy as np


from sklearn.preprocessing import LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.preprocessing import MinMaxScaler
from scipy.stats import entropy
from scipy.stats import zscore



files = glob("../DataSet/*.parquet")
dfs = [pd.read_parquet(f) for f in files]
df_all = pd.concat(dfs, ignore_index=True)
df_all.count()
# Convert them to all lowercase letters
# Replace spaces with underscores

df_all.columns = df_all.columns.str.replace(' ', '_').str.lower()

df_all.head(5)
# Enforce numeric columns ONLY based on patterns
def enforce_numeric(df):
    patterns = ["count", "packet", "bytes", "length", "duration",
                "rate", "mean", "std", "max", "min"]

    for col in df.columns:
        if any(pat in col for pat in patterns):
            df[col] = pd.to_numeric(df[col], errors="coerce")
    return df

df_all = enforce_numeric(df_all)

# only for sanity check 
df_all = pd.get_dummies(df_all, columns=["protocol"], prefix="proto")

df_all.head(5)
# df_all['protocol'].nunique()
# limited the Benign to 250000 rows to make the other fields balanced so that model predicts correclty.
df_benign = df_all[df_all['label'] == "Benign"].sample(250000, random_state=42)
df_others = df_all[df_all['label'] != "Benign"]

df_balanced = pd.concat([df_benign, df_others])

# Shuffle after concatenation
df_balanced = df_balanced.sample(frac=1, random_state=42).reset_index(drop=True)

df_balanced.head(5)
# Find and handle null values

# Get the count of null values in each column
null_counts = df_balanced.isnull().sum()

# Print the total number of null entries in the dataset
print(f"Total null entries found: {null_counts.sum()}\n")

# Drop rows with any null values
df_balanced.dropna(inplace=True)  

# Find and handle duplicates

# Get the count of duplicate rows
duplicate_count = df_balanced.duplicated().sum()

# # Print the number of duplicate entries found
print(f"Total duplicate entries found: {duplicate_count}\n")

# Remove duplicate rows from the dataset
df_balanced.drop_duplicates(inplace=True) 

# Inform that duplicates have been removed
print("All duplicate entries have been removed.\n")

# Reset the index after dropping rows
df_balanced.reset_index(drop=True, inplace=True)

df_balanced.size

# Inspect categorical columns
categorical_columns = df_balanced.select_dtypes(include=['object']).columns.tolist()
print(f"Categorical columns: {categorical_columns}\n")

# Display the first 5 rows of the cleaned dataset
df_balanced.head(20)

# Encode the attack labels into numeric format (e.g., Benign=0, DoS=1, Botnet=2, etc.)

le = LabelEncoder()
df_balanced['label_encoded'] = le.fit_transform(df_balanced['label'])

# Convert only numeric columns
numeric_cols = df_balanced.columns.drop(['label', 'label_encoded'])
df_balanced[numeric_cols] = df_balanced[numeric_cols].apply(pd.to_numeric, errors='coerce')

# Remove invalid values
df_balanced = df_balanced.replace([np.inf, -np.inf], np.nan)
df_balanced.dropna(inplace=True)
attack_data = df_balanced['label'].value_counts()
print(attack_data)
plt.figure(figsize=(12,7))
sns.barplot(x=attack_data.values, y=attack_data.index, palette="viridis")

plt.title("Number of Attacks (CICIDS2017)")
plt.xlabel("Count")
plt.ylabel("Attack Type")
plt.tight_layout()
plt.show()
class_dist = df_balanced["label"].value_counts(normalize=True) * 100
print(class_dist)
plt.figure()
plt.bar(class_dist.index.astype(str), class_dist.values)
plt.title("Combined Class Distribution (%)")
plt.xlabel("Class Label")
plt.ylabel("Percentage")
plt.xticks(rotation=90, ha="right")
plt.tight_layout()
plt.show()


# Display value counts
print(df_balanced["label"].value_counts())
df_balanced.head(5)
label_mapping = {i: label for i, label in enumerate(le.classes_)}
print(label_mapping)
df_balanced.info()
df_balanced['label'].value_counts()
# Feature engineering
# Raw features (like total packets, bytes, flow duration) are useful, but ratios, rates, and normalized features often provide better signals for anomaly detection
# We also need to handle zero or negative values to prevent errors during feature calculation or ML training.

eps = 1e-3  # small number to avoid division by zero
df_balanced['flow_duration'] = df_balanced['flow_duration'].clip(lower=eps)

# rate / ratio features
df_balanced['total_packets'] = df_balanced['total_fwd_packets'] + df_balanced['total_backward_packets'] + eps
df_balanced['total_bytes'] = df_balanced['fwd_packets_length_total'] + df_balanced['bwd_packets_length_total'] + eps

# packet_rate → packets per second (flow_duration is in microseconds, divide by 1e6).
# bytes_per_packet → average size of a packet.
# High packet rate or unusual bytes per packet are often indicators of attacks (DoS, scanning, bursty flows).

df_balanced['packet_rate'] = df_balanced['total_packets'] / (df_balanced['flow_duration'] / 1e6)
df_balanced['bytes_per_packet'] = df_balanced['total_bytes'] / df_balanced['total_packets']


# Coefficient of Variation (CV) features
#CV = standard deviation / mean → measures relative variability.
# idle and active CV can indicate irregular traffic patterns, useful for detecting attacks.

df_balanced['idle_mean_safe'] = df_balanced['idle_mean'].replace(0, eps)
df_balanced['active_mean_safe'] = df_balanced['active_mean'].replace(0, eps)

df_balanced['idle_cv'] = df_balanced['idle_std'] / df_balanced['idle_mean_safe']
df_balanced['active_cv'] = df_balanced['active_std'] / df_balanced['active_mean_safe']

# Drop temporary safe columns
df_balanced.drop(columns=['idle_mean_safe', 'active_mean_safe'], inplace=True)
# TCP Behavior Feature ML can learn TCP-specific behavior patterns
protocol_cols = [col for col in df_balanced.columns if col.startswith('proto_')]

if 'proto_6' in df_balanced.columns:
    df_balanced['tcp_behavior'] = df_balanced['proto_6'] * df_balanced['flow_duration']
else:
    df_balanced['tcp_behavior'] = 0

# Burst Ratio
# burst_ratio ≈ 1 → almost all packets are forward → could indicate DoS or bursty traffic.
# burst_ratio ≈ 0.5 → traffic is balanced forward/backward.

if 'fwd_packets/s' in df_balanced.columns and 'flow_packets/s' in df_balanced.columns:
    df_balanced['burst_ratio'] = df_balanced['fwd_packets/s'] / (df_balanced['flow_packets/s'] + 1e-5)
else:
    df_balanced['burst_ratio'] = 0
# Packet Entropy
# Malicious traffic often has different entropy patterns compared to normal traffic.
df_balanced['packet_entropy'] = df_balanced[['fwd_packet_length_std', 'bwd_packet_length_std']].apply(
    lambda x: entropy([x[0] + 1e-9, x[1] + 1e-9], base=2),  # Add epsilon to avoid log(0)
    axis=1
)


# Attack traffic often has unusual flag patterns SYN floods, FIN scans
# Total flags in the flow
df_balanced['total_flag_count'] = df_balanced[['fin_flag_count','syn_flag_count','rst_flag_count',
                                               'psh_flag_count','ack_flag_count','urg_flag_count',
                                               'cwe_flag_count','ece_flag_count']].sum(axis=1)

# SYN/FIN ratio → scanning or SYN flood
df_balanced['syn_fin_ratio'] = (df_balanced['syn_flag_count'] + 1e-5) / (df_balanced['fin_flag_count'] + 1e-5)

# PSH/ACK ratio → bursty traffic indicator
df_balanced['psh_ack_ratio'] = (df_balanced['psh_flag_count'] + 1e-5) / (df_balanced['ack_flag_count'] + 1e-5)

# Attack traffic can have unusual segment size distributions.
df_balanced['segment_ratio'] = (df_balanced['avg_fwd_segment_size'] + 1e-5) / (df_balanced['avg_bwd_segment_size'] + 1e-5)

# Captures variability of packet timing. Bursty attacks often have high CV.
df_balanced['fwd_iat_cv'] = (df_balanced['fwd_iat_std'] + 1e-5) / (df_balanced['fwd_iat_mean'] + 1e-5)
df_balanced['bwd_iat_cv'] = (df_balanced['bwd_iat_std'] + 1e-5) / (df_balanced['bwd_iat_mean'] + 1e-5)

# Skewed packet length distributions are often attack indicators.
df_balanced['fwd_packet_skew'] = (df_balanced['fwd_packet_length_mean'] - df_balanced['fwd_packet_length_min']) / (df_balanced['fwd_packet_length_std'] + 1e-5)
df_balanced['bwd_packet_skew'] = (df_balanced['bwd_packet_length_mean'] - df_balanced['bwd_packet_length_min']) / (df_balanced['bwd_packet_length_std'] + 1e-5)

df_balanced.info()
# Binary flag indicating whether the flow's duration is considered statistically abnormal.
# useful for detecting unusually short or long-lived flows that may be associated with network attacks or misbehavior.
# Step 1: Calculate z-score across all flows
# log-transform duration to reduce skew (common in network traffic)
df_balanced['log_flow_duration'] = np.log1p(df_balanced['flow_duration'])

# Step 2: Compute z-score for log flow duration
df_balanced['flow_duration_zscore'] = zscore(df_balanced['log_flow_duration'])

# Step 3: Flag abnormal flows (e.g., abs(z-score) > 3)
threshold = 3  # You can tune this threshold based on your inspection
df_balanced['abnormal_flow_duration'] = (np.abs(df_balanced['flow_duration_zscore']) > threshold).astype(int)

# Step 4: Drop intermediate columns to keep only the binary flag
df_balanced = df_balanced.drop(['log_flow_duration', 'flow_duration_zscore'], axis=1)
# Calculate activity (active/idle period) ratio for each flow
df_balanced['activity_period_ratio'] = (df_balanced['active_mean'] + eps) / (df_balanced['idle_mean'] + eps)
# Compute skewness using mean, std, min, max; normalized difference between fwd and bwd
def iat_skewness(mean, std, minval, maxval, eps=1e-5):
    return ((mean - minval) / (std + eps)), ((mean - maxval) / (std + eps))

df_balanced['fwd_iat_skew'] = (df_balanced['fwd_iat_mean'] - df_balanced['fwd_iat_min']) / (df_balanced['fwd_iat_std'] + 1e-5)
df_balanced['bwd_iat_skew'] = (df_balanced['bwd_iat_mean'] - df_balanced['bwd_iat_min']) / (df_balanced['bwd_iat_std'] + 1e-5)

# Optionally, relative difference/ratio:
df_balanced['normalized_iat_skewness'] = df_balanced['fwd_iat_skew'] / (np.abs(df_balanced['bwd_iat_skew']) + 1e-5)

df_balanced.head(5)
df_balanced.head(5)
# Use existing proto_* columns and flow duration to normalize flag count per protocol
proto_cols = [col for col in df_balanced.columns if col.startswith('proto_')]
for proto in proto_cols:
    df_balanced[f"{proto}_flag_rate"] = df_balanced['total_flag_count'] * df_balanced[proto] / (df_balanced['flow_duration']/1e6 + 1e-5)
df_balanced.head(5)
#df_balanced = df_balanced.drop(['proto_0_flag_rate_flag_rate', 'proto_6_flag_rate_flag_rate', 'proto_17_flag_rate_flag_rate'], axis=1)
df_balanced['flag_change_rate'] = df_balanced['total_flag_count'] / ((df_balanced['flow_duration'] / 1e6) + eps)
anomaly_feats = ['burst_ratio', 'active_cv', 'flag_change_rate']  # Check these really exist!
for col in anomaly_feats:
    df_balanced[col + "_scaled"] = MinMaxScaler().fit_transform(df_balanced[[col]])

df_balanced['flow_anomaly_index'] = df_balanced[[c + "_scaled" for c in anomaly_feats]].sum(axis=1)
# Step 4: Drop intermediate columns to keep only the binary flag
df_balanced = df_balanced.drop(['burst_ratio_scaled', 'active_cv_scaled','flag_change_rate_scaled'], axis=1)
df_balanced.head(5)
# For each flow, using cumulative expanding mean/std for packet size or IAT, entire DataFrame:
df_balanced['exp_packet_size_mean'] = df_balanced['bytes_per_packet'].expanding().mean()
df_balanced['exp_packet_size_std'] = df_balanced['bytes_per_packet'].expanding().std()

# For IAT (forward direction)
df_balanced['exp_fwd_iat_mean'] = df_balanced['fwd_iat_mean'].expanding().mean()
df_balanced['exp_fwd_iat_std'] = df_balanced['fwd_iat_mean'].expanding().std()

has_nans = df_balanced.isnull().values.any()
print(f"Are there any NaN values? {has_nans}")

total_nans = df_balanced.isnull().sum().sum()
print(f"Total NaN values: {total_nans}")

nan_per_column = df_balanced.isnull().sum()
print(nan_per_column[nan_per_column > 0])

df_balanced = df_balanced.replace([np.inf, -np.inf], np.nan)
df_balanced.dropna(inplace=True)

# Calculate activity (active/idle period) ratio for each flow
df_balanced['activity_period_ratio'] = (df_balanced['active_mean'] + eps) / (df_balanced['idle_mean'] + eps)

# Use existing proto_* columns and flow duration to normalize flag count per protocol
proto_cols = [col for col in df_balanced.columns if col.startswith('proto_')]
for proto in proto_cols:
    df_balanced[f"{proto}_flag_rate"] = df_balanced['total_flag_count'] * df_balanced[proto] / (df_balanced['flow_duration']/1e6 + 1e-5)
df_balanced.head(5)
#df_balanced = df_balanced.drop(['proto_0_flag_rate_flag_rate', 'proto_6_flag_rate_flag_rate', 'proto_17_flag_rate_flag_rate'], axis=1)

df_balanced['flag_change_rate'] = df_balanced['total_flag_count'] / ((df_balanced['flow_duration'] / 1e6) + eps)
anomaly_feats = ['burst_ratio', 'active_cv', 'flag_change_rate']  # Check these really exist!
for col in anomaly_feats:
    df_balanced[col + "_scaled"] = MinMaxScaler().fit_transform(df_balanced[[col]])

df_balanced['flow_anomaly_index'] = df_balanced[[c + "_scaled" for c in anomaly_feats]].sum(axis=1)
# Step 4: Drop intermediate columns to keep only the binary flag
df_balanced = df_balanced.drop(['burst_ratio_scaled', 'active_cv_scaled','flag_change_rate_scaled'], axis=1)
df_balanced.head(5)

# For each flow, using cumulative expanding mean/std for packet size or IAT, entire DataFrame:
df_balanced['exp_packet_size_mean'] = df_balanced['bytes_per_packet'].expanding().mean()
df_balanced['exp_packet_size_std'] = df_balanced['bytes_per_packet'].expanding().std()

# For IAT (forward direction)
df_balanced['exp_fwd_iat_mean'] = df_balanced['fwd_iat_mean'].expanding().mean()
df_balanced['exp_fwd_iat_std'] = df_balanced['fwd_iat_mean'].expanding().std()


# before feature selction or extraction do split and scale it so there is no imbalance.
X = df_balanced.drop(['label', 'label_encoded'], axis=1)
y = df_balanced['label_encoded']

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)


scaler = StandardScaler()

X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled = scaler.transform(X_test)

X_train_scaled[:1]