
# Data Visualization: Cybersecurity Attacks

## Project Information
- Institution: University of Pristina "Hasan Prishtina"
- Program: Master's Degree, Computer and Software Engineering
- Subject: Preparation and Data Visualization       
- Professor: Dr. Sc. Mërgim H. HOTI
  

  <div align="center">
  <img src="images-readme/universiteti.jpg" alt="Project Logo" width="300">
</div>

## Authors

- [Albin Hashani](https://github.com/AlbinHashanii)
- [Arjana Tërnava](https://github.com/ArjanaaTernava)
- [Erza Osmani](https://github.com/erzaosmani)

## First Phase

The first phase of the project involves preprocessing data related to cybersecurity attacks to prepare it for further analysis. 
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

## Development Environment

- Editor: PyCharm
![PyCharm](https://img.shields.io/badge/-PyCharm-00B300?logo=pycharm&logoColor=white&style=for-the-badge)

- Instructions:
    - Download and install PyCharm Editor
    - Select Pure Python for the project type
    - If you don't have an interpreter set up, you can do it in the editor based on instructions.
    - Install the required packages

  - Results of the first phase: 

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
      
       ![Project Logo](images-readme/datatypes.jpg)
      
    - Summary statistics for numerical columns
      
      ![Project Logo](images-readme/desrcibe.png)

    - Aggregation Functions - mean, count, min, max
      
      ![Project Logo](images-readme/aggregation.png)
      
    - Missing values
      
      ![Project Logo](images-readme/missing.png)
      
    - Duplicate values
   
      ![Project Logo](images-readme/duplicate.png)
      
    - Discretization - The code applies binning to different numeric columns `Source Port`, `Destination Port`, `Packet Length`, `Anomaly Scores`, `Source IP Address`, `Destination IP Address`, using labels:
      
      ![Project Logo](images-readme/discretization.jpg) 

    - Binarization of the fields: `Packet Type` and `Log Source` using values 0 and 1.
      
      ![Project Logo](images-readme/binarization.png) 

    - Dimensionality reduction - We applied Principal Component Analysis (PCA) to reduce the dataset to two principal components, capturing the most important features while simplifying the data structure. The numerical columns are also standardized.
      
      ![Project Logo](images-readme/pca_before_outliers.png)
      
      ![Project Logo](images-readme/pca.png)
      
      ![Project Logo](images-readme/pca-top-features.png)
      
    - Chi Square Test Results - Target: Attack Type
      
      ![Project Logo](images-readme/chi-square.png)

      
## Second Phase

The second phase of the project focuses on identifying outliers and eliminating inaccurate findings within the dataset.
These steps include:
- Outlier detection
- Elimination of inaccurate discoveries
- Data exploration
- Results of the second phase:
  
  - Skewness data before removing outliers:
    
    ![Project Logo](images-readme/skewness.png)
    
    ![Project Logo](images-readme/destinationport_001.png)
    
    ![Project Logo](images-readme/packeteff1.76.png)
    
    ![Project Logo](images-readme/packetlenght-0.0.png)
    
    ![Project Logo](images-readme/payload-034.png)
    
    ![Project Logo](images-readme/sourceport_skewness_0.02.png)
    
  - Skewness data after removing outliers:
    
       ![Project Logo](images-readme/packeteffafter.png)
    
       ![Project Logo](images-readme/afterskewnesspayload.png)
    
       ![Project Logo](images-readme/skewness-no-outliers.png)
    
  - Correlation Matrix
    
      ![Project Logo](images-readme/matrix.png)
    

- The new cleaned dataset `cleaned_data.csv` should be located in the directory: `cybersecurity-attacks-data-visualization/src`.


### License

[Apache-2.0](http://www.apache.org/licenses/)


