#**CREATES SMALLER DATASET SAMPLES**

import pandas as pd
import os, glob

input_file = "#UnfilteredCSV"
output_file = "#FilteredCSV"

df = pd.read_csv(input_file, low_memory=False)

#Standardise attack_cat
if " attack_cat" not in df.columns:
    raise Exception("Column 'attack_cat' not found in the dataset!")
df[" attack_cat"] = df[" attack_cat"].astype(str).str.strip().str.lower()

sample_size = 20000 #Set this to whatever

#Group by attack category for stratified sampling
grouped = df.groupby(" attack_cat")
sampled_dfs = []

print("Performing stratified sampling by attack_cat:")
for cat, group in grouped:
    n_cat = len(group)
    #Calculate number of samples for this category proportionally
    n_samples = int(round(n_cat / len(df) * sample_size))
    #Ensure that every non-empty group contributes at least one row (only applies to one category, which in the UNSW-NB15 dataset there is only one instance of)
    if n_samples < 1 and n_cat > 0:
        n_samples = 1
    #If the group is smaller than the number required, sample with replacement
    if n_samples > n_cat:
        sampled = group.sample(n=n_samples, replace=True, random_state=42)
    else:
        sampled = group.sample(n=n_samples, random_state=42)
    print(f"  Category '{cat}': total={n_cat}, sampling {n_samples} rows")
    sampled_dfs.append(sampled)

#Combine all the stratified samples
sample_df = pd.concat(sampled_dfs)

if len(sample_df) != sample_size:
    if len(sample_df) < sample_size:
        sample_df = sample_df.sample(n=sample_size, replace=True, random_state=42)
    else:
        sample_df = sample_df.sample(n=sample_size, random_state=42)

#Save the final stratified sample
sample_df.to_csv(output_file, index=False)
print(f"sample saved to: {output_file}")