
# Data Visualization: Cybersecurity Attacks

## Overview

The first part of the project involves preprocessing data related to cybersecurity attacks to prepare it for further analysis. 
The preprocessing steps include:

- Data collection
- Integration
- Aggregation
- Data cleaning
- Discretization
- Binarization
- Transformation
- Dimensionality reduction
- Feature subset selection

This README outlines the steps taken and their implementation in the provided Python code.

## Development Environment

- Editor: PyCharm
![PyCharm](https://img.shields.io/badge/-PyCharm-00B300?logo=pycharm&logoColor=white&style=for-the-badge)

- Instructions:
    - Download and install PyCharm Editor
    - Select Pure Python for the project type
    - If you don't have an interpreter set up, you can do it in the editor based on instructions.
    - Install the required packages

```bash
  pip install pandas numpy scikit-learn
```
 - Steps

   - Import required libraries:
      ```bash
       import numpy as np
       import pandas as pd
       from sklearn.decomposition import PCA
       from sklearn.preprocessing import StandardScaler,MinMaxScaler
       from sklearn.preprocessing import LabelEncoder
       from sklearn.feature_selection import chi2
      ```
    - Data Collection
      ```bash
      csv_data = pd.read_csv("cybersecurity_attacks.csv")

      ```
      - The dataset file `cybersecurity_attacks.csv` should be located in the directory: `cybersecurity-attacks-data-visualization/src`.

    - Load dataset 
      ```bash
      csv_data = pd.read_csv("cybersecurity_attacks.csv")
      ``` 
    - Printing Data Types
       ```bash
       print("Data types for each field:")
       print(csv_data.dtypes)
      ``` 
    - Aggregation Functions - mean, count, min, max
      ```bash
      print("Summary statistics for numeric columns:")
      print(csv_data.describe())
      ``` 
    - Missing values
      ```bash
      missing_values = csv_data.isnull().sum()
      missing_values = missing_values[missing_values > 0]
      ``` 
    - Duplicate values
      ```bash
      print(csv_data.duplicated().sum())
      ``` 

    - Integration of the field `Packet Efficiency`:
      ```bash
      csv_data['Payload Length'] = csv_data['Payload Data'].apply(len)
      csv_data['Packet Efficiency'] = csv_data['Packet Length']/csv_data['Payload Length']
      ``` 
    - Data cleaning - Filling missing values in the columns: `Malware Indicators`, `Alerts/Warnings`, `Proxy Information`, `Firewall Logs`, `IDS/IPS Alerts` with mode and "unknown" values.
      ```bash
      malware = csv_data["Malware Indicators"].mode()[0]
      csv_data["Malware Indicators"] = csv_data["Malware Indicators"].fillna(malware)

      alerts_warnings = csv_data["Alerts/Warnings"].mode()[0]
      csv_data["Alerts/Warnings"] = csv_data["Alerts/Warnings"].fillna(alerts_warnings)

      csv_data["Proxy Information"] = csv_data["Proxy Information"].fillna("No Proxy Information")

      firewall_logs = csv_data["Firewall Logs"].mode()[0]
      csv_data["Firewall Logs"] = csv_data["Firewall Logs"].fillna(firewall_logs)  

      ids_ips_alerts = csv_data["IDS/IPS Alerts"].mode()[0]
      csv_data["IDS/IPS Alerts"] = csv_data["IDS/IPS Alerts"].fillna(ids_ips_alerts)
      ``` 
    - Sampling - Random sampling of data
      ```bash
      data_portion = csv_data.sample(frac=0.1)
      ``` 
    - Discretization - The code applies binning to different numeric columns `Source Port`, `Destination Port`, `Packet Length`, `Anomaly Scores`, `Source IP Address`, `Destination IP Address`, using labels:
      ```bash
      csv_data['Source Port Binned'] = pd.cut(csv_data['Source Port'], 
                                    bins=[0, 1023, 49151, 65535], 
                                    labels=["System", "User", "Dynamic/Private"])

      csv_data['Destination Port Binned'] = pd.cut(csv_data['Destination Port'], 
                                    bins=[0, 1023, 49151, 65535], 
                                    labels=["System", "Registered", "Dynamic/Private"])      

      csv_data['Packet Length Binned'] = pd.cut(csv_data['Packet Length'], 
                                     bins=3, 
                                     labels=["Small", "Medium", "Large"]) 
      csv_data['Anomaly Scores Binned'] = pd.cut(csv_data['Anomaly Scores'], 
                                     bins=3, 
                                     labels=["Normal", "Suspicious", "Critical"])                                     
      csv_data['Source IP Class'] = csv_data['Source IP Address'].apply(classify_ip)

      csv_data['Destination IP Class'] = csv_data['Destination IP Address'].apply(classify_ip)
      ``` 

    - Binarization of the fields: `Packet Type` and `Log Source` using values 0 and 1.
      ```bash
      csv_data['Packet Type Bin'] = csv_data['Packet Type'].apply(lambda x: 1 if x == "Control" else 0)

      csv_data['Log Source Bin'] = csv_data['Log Source'].apply(lambda x: 1 if x == "Firewall" else 0)
      ```  

    - Dimensionality reduction - We applied Principal Component Analysis (PCA) to reduce the dataset to two principal components, capturing the most important features while simplifying the data structure. The numerical columns are also standardized.
      ```bash
      numerical_cols = ['Source Port', 'Destination Port', 'Packet Length',
                  'Payload Length', 'Packet Efficiency', 'Anomaly Scores']

      scaled_data = standard_scaler.fit_transform(csv_data[numerical_cols])
      pca = PCA(n_components=2)
      pca.fit(scaled_data)

      pca_components_df = pd.DataFrame(np.round(pca.components_, 4),
                                       columns=numerical_cols,
                                       index=[f'PC{i + 1}' for i in range(pca.n_components_)])
      print("Explained Variance Ratio:", pca.explained_variance_ratio_)  - the proportion of the dataset's total variance that is explained by each of the selected principal components in PCA.
      ```  
    - Feature selection using chi square - We performed feature selection using the Chi-Square test to assess the relationship between the categorical features and the target variable, "Attack Type." Each feature was encoded into numerical values using Label Encoding, and the Chi-Square statistics were calculated to determine the significance of each feature in predicting the target variable.
       ```bash
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
      ``` 
    - Cleaned dataset - After performing all these preprocessing tasks, new fields have been added to our dataset: `Payload Length`,`Packet Efficiency`, `Source Port Binned`, `Destination Port Binned`, `Packet Length Binned`, `Anomaly Scores Binned`, `Source IP Class`, `Destination IP Class`, `Packet Type Bin`, `Log Source Bin`. The dataset has been cleaned and has no missing and duplicate values.
    - The new cleaned dataset `cleaned_data.csv` should be located in the directory: `cybersecurity-attacks-data-visualization/src`.

### Authors

- [Albin Hashani](https://github.com/AlbinHashanii)
- [Arjana Tërnava](https://github.com/ArjanaaTernava)
- [Erza Osmani](https://github.com/erzaosmani)


### License

[Apache-2.0](http://www.apache.org/licenses/)

