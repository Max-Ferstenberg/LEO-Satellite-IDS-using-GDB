#**CIC-IDS2017 DATASET CLEANING** 

#(Merging this dataset was done later, during feature extraction)

#This script just adds labels, since they came separately for this dataset

import pandas as pd

MAIN_DATA_FILE = "CICIDSData.csv"
LABELS_FILE = "CICIDSLabel.csv"
BENIGN_OUTPUT_FILE = "CICIDS-Benign.csv"
MALICIOUS_OUTPUT_FILE = "CICIDS-Malicious.csv"

df_main = pd.read_csv(MAIN_DATA_FILE, low_memory=False)
df_labels = pd.read_csv(LABELS_FILE, low_memory=False)

#Combine the labels by concatenating along columns
df_combined = pd.concat([df_main, df_labels], axis=1)

#Convert the Label column to numeric
#a label of 0 is benign traffic; any non-zero value indicates an attack
df_combined["Label"] = pd.to_numeric(df_combined["Label"], errors='coerce')

#Split the combined DataFrame into benign and malicious subsets (This was done to make a separate calculation for frequency of each attack easier, which I didn't end up using in the end, so I just put them back into one file again later)
df_benign = df_combined[df_combined["Label"] == 0]
df_malicious = df_combined[df_combined["Label"] != 0]

#Save the benign and malicious subsets into separate CSV files
df_benign.to_csv(BENIGN_OUTPUT_FILE, index=False)
df_malicious.to_csv(MALICIOUS_OUTPUT_FILE, index=False)

print("Benign data written to:", BENIGN_OUTPUT_FILE)
print("Malicious data written to:", MALICIOUS_OUTPUT_FILE)