import pandas as pd
from sklearn.preprocessing import KBinsDiscretizer, Binarizer

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


#Discretization of fields
#Discretization of 'Packet Length'
discretizer = KBinsDiscretizer(n_bins=3, encode='ordinal', strategy='uniform')
csv_data['Packet Length Disc'] = discretizer.fit_transform(csv_data[['Packet Length']])

#Discretization of 'Anomaly Scores'
discretizer = KBinsDiscretizer(n_bins=3, encode='ordinal', strategy='uniform')
csv_data['Anomaly Scores Disc'] = discretizer.fit_transform(csv_data[['Anomaly Scores']])

#Binarization of fields
#Binarization of 'Packet Length'
binarizer = Binarizer(threshold=float(csv_data['Packet Length'].mean()))
csv_data['Packet Length Bin'] = binarizer.fit_transform(csv_data[['Packet Length']])

#Binarization of 'Anomaly Scores'
mean_value = csv_data['Anomaly Scores'].mean()
binarizer = Binarizer(threshold=float(mean_value))
csv_data['Anomaly Scores Bin'] = binarizer.fit_transform(csv_data[['Anomaly Scores']])

#Transformation
scaler = StandardScaler()
numerical_cols = csv_data.select_dtypes(include=['int64', 'float64']).columns
csv_data[numerical_cols] = scaler.fit_transform(csv_data[numerical_cols])

#Cleaned data csv file without missing values
csv_data.to_csv('cleaned_data.csv', index=False)
