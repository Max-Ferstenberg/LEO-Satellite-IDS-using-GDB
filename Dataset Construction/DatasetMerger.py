#FINAL DATASET MERGER

import os
import glob
import pandas as pd

INPUT_FOLDER = r"#Remaining Datasets that have not been merged"
OUTPUT_CSV = r"Full Dataset.csv"

#Retrieve all CSV files from the input folder
csv_file_paths = glob.glob(os.path.join(INPUT_FOLDER, "*.csv"))

#Initialise a list to collect DataFrames
dataframes = []

#Loop over each CSV file, load and clean data
for csv_path in csv_file_paths:
    #Read CSV file, automatically skipping blank lines
    df = pd.read_csv(csv_path, skip_blank_lines=True)
    #Remove rows where all values are missing
    df.dropna(how='all', inplace=True)
    dataframes.append(df)

#Merge all loaded DataFrames
if dataframes:
    merged_dataframe = pd.concat(dataframes, ignore_index=True)
    merged_dataframe.to_csv(OUTPUT_CSV, index=False)
    print(f"Merged {len(csv_file_paths)} CSV files into {OUTPUT_CSV} with {len(merged_dataframe)} rows.")