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

