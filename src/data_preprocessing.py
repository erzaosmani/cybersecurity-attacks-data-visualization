import pandas as pd
from sklearn.preprocessing import Binarizer, StandardScaler,MinMaxScaler

csv_data = pd.read_csv("cybersecurity_attacks.csv")

#Printing the data types
print("Data types for each field:")
print(csv_data.dtypes)

#Counting the number of fields
field_count = len(csv_data.columns)
print(f"Number of fields: {field_count}")

#count, mean, minimum, maximum values - aggregation functions
print("Summary statistics for numeric columns:")
print(csv_data.describe())

#Check for missing values
missing_values = csv_data.isnull().sum()
missing_values = missing_values[missing_values > 0]
print("Missing values in columns:")
print(missing_values)

#Check for duplicates
print("Duplicate values: ")
print(csv_data.duplicated().sum())

#Integration of field Packet Efficiency
csv_data['Payload Length'] = csv_data['Payload Data'].apply(len)
csv_data['Packet Efficiency'] = csv_data['Packet Length'] / csv_data['Payload Length']

#Aggregation of all attack types
aggregated_data = csv_data.groupby('Attack Type').size()
print("Aggregated data (count of each attack type):")
print(aggregated_data)

#Sampling random data
data_portion = csv_data.sample(frac=0.1)

#Filling missing values (String type)
malware = csv_data["Malware Indicators"].mode()[0]
csv_data["Malware Indicators"] = csv_data["Malware Indicators"].fillna(malware)

alerts_warnings = csv_data["Alerts/Warnings"].mode()[0]
csv_data["Alerts/Warnings"] = csv_data["Alerts/Warnings"].fillna(alerts_warnings)

proxy_information = csv_data["Proxy Information"].mode()[0]
csv_data["Proxy Information"] = csv_data["Proxy Information"].fillna(proxy_information)

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

# # Display the first rows of discretized columns
# print(csv_data[['Source Port', 'Source Port Binned', 
#             'Destination Port', 'Destination Port Binned', 
#             'Packet Length', 'Packet Length Binned', 
#             'Anomaly Scores', 'Anomaly Scores Binned']].head())



#2D array for binarized values
packet_type = csv_data['Packet Type'].values.reshape(-1, 1)
log_source = csv_data['Log Source'].values.reshape(-1, 1)

# # Display of the original values of binarizated columns
#print("\nOriginal Packet Type data values:\n", packet_type.flatten())
#print("\nOriginal Log Source data values:\n", log_source.flatten())

# Binarize 'Packet Type' field
csv_data['Packet Type Bin'] = csv_data['Packet Type'].apply(lambda x: 1 if x == "Control" else 0)

# Binarize 'Log Source' field
csv_data['Log Source Bin'] = csv_data['Log Source'].apply(lambda x: 1 if x == "Firewall" else 0)

#Displaying result of binarization
#print("\nBinarized Packet Type:\n", csv_data['Packet Type Bin'].values)
#print("\nBinarized Log Source:\n", csv_data['Log Source Bin'].values)


#Transformation
min_max_scaler = MinMaxScaler()
standard_scaler = StandardScaler()

# 1. Min-Max Scaling for Source Port and Destination Port (range 0-1)
csv_data['Source Port Scaled'] = min_max_scaler.fit_transform(csv_data[['Source Port']])
csv_data['Destination Port Scaled'] = min_max_scaler.fit_transform(csv_data[['Destination Port']])

# 3. Standardization (z-score normalization) for Anomaly Scores
csv_data['Anomaly Scores Standardized'] = standard_scaler.fit_transform(csv_data[['Anomaly Scores']])

# Display the first few rows to verify transformations
#print(csv_data[['Source Port', 'Source Port Scaled',
            #'Destination Port', 'Destination Port Scaled',
           # 'Anomaly Scores', 'Anomaly Scores Standardized']].head())

#Cleaned data csv file without missing values
csv_data.to_csv('cleaned_data.csv', index=False)