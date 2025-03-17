#Merges all separate packet CSVs into one large CSV - Ready for DNN training

import os
import glob
import pandas as pd

def concatenate(directory, output_file_path):
    #Concatenates all CSV files in the given directory into a single CSV file and assigns the correct request_id
    #Args: directory (str): Path to the directory containing the CSV files, output_file_path (str): Full path where the concatenated CSV file will be saved

    #Find all CSV files in the directory
    all_files = glob.glob(os.path.join(directory, "*.csv"))
    if not all_files:
        return

    list_of_dfs = []
    num_files = len(all_files)
    print(f"Found {num_files} CSV files to process.")

    #Read each CSV file, add a request_id column derived from the filename and collect the DataFrames in a list
    for i, filename in enumerate(all_files):
        try:
            df = pd.read_csv(filename)
            request_id = os.path.splitext(os.path.basename(filename))[0]
            df['request_id'] = request_id
            list_of_dfs.append(df)

        except pd.errors.EmptyDataError:
            print(f"Warning: Empty file skipped: {filename}")
        except Exception as e:
            print(f"Error reading file {filename}: {e}")

    if list_of_dfs:
        concatenated_df = pd.concat(list_of_dfs, ignore_index=True)
        try:
            concatenated_df.to_csv(output_file_path, index=False)
        except Exception as e:
            print(f"Error while saving concatenated CSV: {e}")

def main():
    directory = (r'#Separated Packet CSVs')
    output_file_path = (r"#Aggregated Packet CSV")
    concatenate(directory, output_file_path)

if __name__ == "__main__":
    main()