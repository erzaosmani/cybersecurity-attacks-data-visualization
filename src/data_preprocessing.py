import pandas as pd

df = pd.read_csv("cybersecurity_attacks.csv")

#Printing the data types
print("Data types for each field:")
print(df.dtypes)

#Counting the number of fields
field_count = len(df.columns)
print(f"Number of fields: {field_count}")

#count, mean, minimum, maximum values
print("Summary statistics for numeric columns:")
print(df.describe())

#Check for missing values
missing_values = df.isnull().sum()
missing_values = missing_values[missing_values > 0]
print("Missing values in columns:")
print(missing_values)

#Check for duplicates
print("Duplicate values: ")
print(df.duplicated().sum())

#Integration of field Packet Efficiency
df['Payload Length'] = df['Payload Data'].apply(len)
df['Packet Efficiency'] = df['Packet Length'] / df['Payload Length']

#Aggregation of all attack types
aggregated_data = df.groupby('Attack Type').size()
print("Aggregated data (count of each attack type):")
print(aggregated_data)
