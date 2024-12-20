import numpy as np
import pandas as pd
from matplotlib import pyplot as plt
from scipy.stats import skew, zscore
from sklearn.decomposition import PCA
from sklearn.preprocessing import StandardScaler
from sklearn.preprocessing import LabelEncoder
from sklearn.feature_selection import chi2

csv_data = pd.read_csv("cybersecurity_attacks.csv")

#Printing the data types
print("Data types for each field:")
print(csv_data.dtypes)
print()

#Counting the number of fields
field_count = len(csv_data.columns)
print(f"Number of fields: {field_count}")
print()

#count, mean, minimum, maximum values - aggregation functions
print("Summary statistics for numeric columns:")
print(csv_data.describe())
print()

#Check for missing values
missing_values = csv_data.isnull().sum()
missing_values = missing_values[missing_values > 0]
print("Missing values in columns:")
print(missing_values)
print()

#Check for duplicates
print("Duplicate values: ")
print(csv_data.duplicated().sum())
print()

#Integration of field Packet Efficiency
csv_data['Payload Length'] = csv_data['Payload Data'].apply(len)
csv_data['Packet Efficiency'] = csv_data['Packet Length'] / csv_data['Payload Length']

#Aggregation of all attack types
aggregated_data = csv_data.groupby('Attack Type').size()
print("Aggregated data (count of each attack type):")
print(aggregated_data)
print()

#Sampling random data
data_portion = csv_data.sample(frac=0.1)

#Filling missing values (String type)
malware = csv_data["Malware Indicators"].mode()[0]
csv_data["Malware Indicators"] = csv_data["Malware Indicators"].fillna(malware)

alerts_warnings = csv_data["Alerts/Warnings"].mode()[0]
csv_data["Alerts/Warnings"] = csv_data["Alerts/Warnings"].fillna(alerts_warnings)

csv_data["Proxy Information"] = csv_data["Proxy Information"].fillna("No Proxy Information")

firewall_logs = csv_data["Firewall Logs"].mode()[0]
csv_data["Firewall Logs"] = csv_data["Firewall Logs"].fillna(firewall_logs)

ids_ips_alerts = csv_data["IDS/IPS Alerts"].mode()[0]
csv_data["IDS/IPS Alerts"] = csv_data["IDS/IPS Alerts"].fillna(ids_ips_alerts)

# Discretize 'Source Port' labels
csv_data['Source Port Binned'] = pd.cut(csv_data['Source Port'], 
                                    bins=[0, 1023, 49151, 65535], 
                                    labels=["System", "User", "Dynamic/Private"])

# Discretize 'Destination Port' with labels
csv_data['Destination Port Binned'] = pd.cut(csv_data['Destination Port'], 
                                         bins=[0, 1023, 49151, 65535], 
                                         labels=["System", "Registered", "Dynamic/Private"])

# Discretize 'Packet Length' with labels
csv_data['Packet Length Binned'] = pd.cut(csv_data['Packet Length'], 
                                      bins=3, 
                                      labels=["Small", "Medium", "Large"])

# Discretize 'Anomaly Scores' with labels
csv_data['Anomaly Scores Binned'] = pd.cut(csv_data['Anomaly Scores'], 
                                       bins=3, 
                                       labels=["Normal", "Suspicious", "Critical"])

# Discretize IP Adresses
def classify_ip(ip):
    first_octet = int(ip.split('.')[0])
    if 1 <= first_octet <= 126:
        return "Class A"
    elif 128 <= first_octet <= 191:
        return "Class B"
    elif 192 <= first_octet <= 223:
        return "Class C"
    elif 224 <= first_octet <= 239:
        return "Class D"
    else:
        return "Class E"

csv_data['Source IP Class'] = csv_data['Source IP Address'].apply(classify_ip)
csv_data['Destination IP Class'] = csv_data['Destination IP Address'].apply(classify_ip)

pd.set_option('display.max_rows', None)   # Display all rows
pd.set_option('display.max_colwidth', None) # Display entire column width
pd.set_option('display.max_columns', None)  # Display all columns
print()

print(csv_data[['Source Port', 'Source Port Binned',
                'Destination Port', 'Destination Port Binned',
                'Packet Length', 'Packet Length Binned',
                'Source IP Address', 'Source IP Class',
                'Destination IP Address', 'Destination IP Class',
                'Anomaly Scores', 'Anomaly Scores Binned']].head())
print()

#2D array for binarized values
packet_type = csv_data['Packet Type'].values.reshape(-1, 1)
log_source = csv_data['Log Source'].values.reshape(-1, 1)

# Display of the original values of binarizated columns
print("\nOriginal Packet Type data values:\n", packet_type.flatten())
print("\nOriginal Log Source data values:\n", log_source.flatten())
print()

# Binarize 'Packet Type' field
csv_data['Packet Type Bin'] = csv_data['Packet Type'].apply(lambda x: 1 if x == "Control" else 0)

# Binarize 'Log Source' field
csv_data['Log Source Bin'] = csv_data['Log Source'].apply(lambda x: 1 if x == "Firewall" else 0)

#Displaying result of binarization
print("\nBinarized Packet Type:\n", csv_data['Packet Type Bin'].values)
print("\nBinarized Log Source:\n", csv_data['Log Source Bin'].values)
print()


#Transformation
standard_scaler = StandardScaler()

numerical_cols = ['Source Port', 'Destination Port', 'Packet Length',
                  'Payload Length', 'Packet Efficiency', 'Anomaly Scores']

scaled_data = standard_scaler.fit_transform(csv_data[numerical_cols])

# PCA implementing
pca = PCA(n_components=2)
pca.fit(scaled_data)

pca_components_df = pd.DataFrame(np.round(pca.components_, 4),
                                 columns=numerical_cols,
                                 index=[f'PC{i + 1}' for i in range(pca.n_components_)])

print("PCA Components with feature weights:")
print(pca_components_df)
print()

for i in range(pca.n_components_):
    print(f"\nTop features for PC{i + 1}:")
    sorted_features = pca_components_df.iloc[i].sort_values(ascending=False)
    print(sorted_features.head(3))

print("Explained Variance Ratio:", pca.explained_variance_ratio_)
print()

pca_transformed = pca.fit_transform(scaled_data)

colors = np.random.rand(pca_transformed.shape[0])

plt.figure(figsize=(10, 7))
plt.scatter(pca_transformed[:, 0], pca_transformed[:, 1], c=colors, cmap='rainbow', s=50, edgecolor='k')

plt.title('PCA Colored Randomly')
plt.xlabel(f'PC1 ({pca.explained_variance_ratio_[0]*100:.2f}% variance)')
plt.ylabel(f'PC2 ({pca.explained_variance_ratio_[1]*100:.2f}% variance)')
plt.grid(True)
plt.show()


# Calculate skewness
skewness_values = csv_data[numerical_cols].apply(skew)

for col in numerical_cols:
    plt.figure(figsize=(8, 5))
    plt.hist(csv_data[col], bins=30, color='skyblue', edgecolor='black', alpha=0.7)
    plt.axvline(csv_data[col].mean(), color='red', linestyle='--', label='Mean')
    plt.axvline(csv_data[col].median(), color='orange', linestyle='-', label='Median')
    plt.title(f"Distribution of {col} with Skewness: {skew(csv_data[col]):.2f}", fontsize=14)
    plt.xlabel(col, fontsize=12)
    plt.ylabel("Frequency", fontsize=12)
    plt.legend()
    plt.grid(axis='y', linestyle='--', alpha=0.7)
    plt.show()

print("Skewness of Numerical Columns:")
print(skewness_values)

numerical_columns = ['Payload Length', 'Packet Efficiency']

z_scores = csv_data[numerical_columns].apply(zscore)

threshold_z = 2
outlier_indices = np.where(z_scores > threshold_z)[0]

no_outliers = csv_data.drop(outlier_indices)

#Cleaned data csv file without missing values
no_outliers.to_csv('cleaned_data.csv', index=False)

#Feature Selection using chi-square
target = 'Attack Type'
features = ['Action Taken', 'Severity Level', 'Traffic Type', 'Protocol', 'Attack Signature', 'Geo-location Data', 'Device Information']

label_encoders = {}
for col in [target] + features:
    le = LabelEncoder()
    csv_data[col] = le.fit_transform(csv_data[col].astype(str))
    label_encoders[col] = le

X = csv_data[features]
y = csv_data[target]

chi2_stats, _ = chi2(X, y)


print("Chi-Square Test Results (Target: 'Attack Type'):\n")
for feature, chi2_stat in zip(features, chi2_stats):
    print(f"Feature: {feature}")
    print(f"  Chi2 Statistic: {chi2_stat:.4f}")
print()


new_skewness = no_outliers[numerical_columns].apply(skew)

print("\nSkewness after removing outliers:")
print(new_skewness)

for col in numerical_columns:
    plt.figure(figsize=(8, 5))
    plt.hist(no_outliers[col], bins=30, color='skyblue', edgecolor='black', alpha=0.7)
    plt.axvline(no_outliers[col].mean(), color='red', linestyle='--', label='Mean')
    plt.axvline(no_outliers[col].median(), color='orange', linestyle='-', label='Median')
    plt.title(f"Distribution of {col} with Skewness: {skew(no_outliers[col]):.2f}", fontsize=14)
    plt.xlabel(col, fontsize=12)
    plt.ylabel("Frequency", fontsize=12)
    plt.legend()
    plt.grid(axis='y', linestyle='--', alpha=0.7)
    plt.show()

# Correlation matrix
correlation_matrix = csv_data[numerical_cols].corr()

plt.figure(figsize=(10, 8))
plt.imshow(correlation_matrix, cmap='coolwarm', interpolation='none')
plt.colorbar(label='Correlation Coefficient')

# Add labels to the axes
plt.xticks(range(len(numerical_cols)), numerical_cols, rotation=45, ha="right")
plt.yticks(range(len(numerical_cols)), numerical_cols)

# Add text to graph
for i in range(len(numerical_cols)):
    for j in range(len(numerical_cols)):
        plt.text(j, i, f"{correlation_matrix.iloc[i, j]:.2f}",
                 ha='center', va='center', color='black')

plt.title("Correlation Matrix of Numerical Features", fontsize=16)
plt.tight_layout()
plt.show()