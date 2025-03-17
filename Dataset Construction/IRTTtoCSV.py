#**CONVERT IRTT TO CSV**

#This script flattens our JSON satellite data into CSV format, extracts packet info and high-level metrics from raw IRTT metrics, which provides us our baseline data




#!/usr/bin/env python3

import os
import csv
import ijson
import subprocess
import time
import math

def flatten(nested_dict, parent_key='', sep='_'):
    #Recursively flattens a nested dictionary
    #Inputs:
    #  nested_dict: the dictionary to flatten
    #  parent_key: base key to use for the current level
    #  sep: Separator used to concatenate keys
    #Returns: A flat dictionary with concatenated keys
    items = {}
    for k, v in nested_dict.items():
        new_key = f"{parent_key}{sep}{k}" if parent_key else k
        if isinstance(v, dict):
            items.update(flatten(v, new_key, sep=sep))
        else:
            items[new_key] = v
    return items

def get_dictionary(input_file):
    #Extracts and flattens the 'stats' object from a JSON file.
    #Inputs: input_file: Path to the JSON file.
    #Returns a flattened dictionary of statistics
    with open(input_file, "rb") as f:
        stats_obj = next(ijson.items(f, "stats"))
    return flatten(stats_obj)

def normalise_rt(trip):
    #Normalises an RTT entry from the JSON into a dictionary with a fixed set of keys
    #Inputs: trip: The dictionary for an RTT entry from the JSON
    #Returns a dictionary with normalised round-trip fields.
    normalised = {}

    normalised["seqno"] = trip.get("seqno", "")
    normalised["lost"]  = trip.get("lost", "")

    #delay metrics
    delay = trip.get("delay", {})
    if isinstance(delay, dict):
        normalised["delay_send"]    = delay.get("send", "")
        normalised["delay_receive"] = delay.get("receive", "")
        normalised["delay_rtt"]     = delay.get("rtt", "")
    else:
        normalised["delay_send"]    = delay
        normalised["delay_receive"] = ""
        normalised["delay_rtt"]     = ""

    #IPDV metrics
    ipdv = trip.get("ipdv", {})
    if isinstance(ipdv, dict):
        normalised["ipdv_send"]    = ipdv.get("send", "")
        normalised["ipdv_receive"] = ipdv.get("receive", "")
        normalised["ipdv_rtt"]     = ipdv.get("rtt", "")
    else:
        normalised["ipdv_send"]    = ipdv
        normalised["ipdv_receive"] = ""
        normalised["ipdv_rtt"]     = ""

    #timestamps
    timestamps = trip.get("timestamps", {})
    if isinstance(timestamps, dict):
        normalised["timestamps_Ecn"] = timestamps.get("Ecn", "")
        #client timestamps
        client = timestamps.get("client", {})
        if isinstance(client, dict):
            rec = client.get("receive", {})
            if isinstance(rec, dict):
                normalised["timestamps_client_receive_wall"] = rec.get("wall", "")
                normalised["timestamps_client_receive_monotonic"] = rec.get("monotonic", "")
            else:
                normalised["timestamps_client_receive_wall"] = rec
                normalised["timestamps_client_receive_monotonic"] = ""
            snd = client.get("send", {})
            if isinstance(snd, dict):
                normalised["timestamps_client_send_wall"] = snd.get("wall", "")
                normalised["timestamps_client_send_monotonic"] = snd.get("monotonic", "")
            else:
                normalised["timestamps_client_send_wall"] = snd
                normalised["timestamps_client_send_monotonic"] = ""
        else:
            normalised["timestamps_client_receive_wall"] = ""
            normalised["timestamps_client_receive_monotonic"] = ""
            normalised["timestamps_client_send_wall"] = ""
            normalised["timestamps_client_send_monotonic"] = ""
        #server timestamps
        server = timestamps.get("server", {})
        if isinstance(server, dict):
            rec = server.get("receive", {})
            if isinstance(rec, dict):
                normalised["timestamps_server_receive_wall"] = rec.get("wall", "")
                normalised["timestamps_server_receive_monotonic"] = rec.get("monotonic", "")
            else:
                normalised["timestamps_server_receive_wall"] = rec
                normalised["timestamps_server_receive_monotonic"] = ""
            snd = server.get("send", {})
            if isinstance(snd, dict):
                normalised["timestamps_server_send_wall"] = snd.get("wall", "")
                normalised["timestamps_server_send_monotonic"] = snd.get("monotonic", "")
            else:
                normalised["timestamps_server_send_wall"] = snd
                normalised["timestamps_server_send_monotonic"] = ""
        else:
            normalised["timestamps_server_receive_wall"] = ""
            normalised["timestamps_server_receive_monotonic"] = ""
            normalised["timestamps_server_send_wall"] = ""
            normalised["timestamps_server_send_monotonic"] = ""
    else:
        normalised["timestamps_Ecn"] = ""
        normalised["timestamps_client_receive_wall"] = ""
        normalised["timestamps_client_receive_monotonic"] = ""
        normalised["timestamps_client_send_wall"] = ""
        normalised["timestamps_client_send_monotonic"] = ""
        normalised["timestamps_server_receive_wall"] = ""
        normalised["timestamps_server_receive_monotonic"] = ""
        normalised["timestamps_server_send_wall"] = ""
        normalised["timestamps_server_send_monotonic"] = ""

    return normalised

def extract_rt(input_file, output_file):
    #Extracts RTT information from JSON, normalises it, and writes to CSV
    #Inputs: input_file: JSON file
    #Returns: output_file: CSV file
    fixed_fieldnames = [
        "seqno", "lost",
        "delay_send", "delay_receive", "delay_rtt",
        "ipdv_send", "ipdv_receive", "ipdv_rtt",
        "timestamps_Ecn",
        "timestamps_client_send_wall", "timestamps_client_send_monotonic",
        "timestamps_client_receive_wall", "timestamps_client_receive_monotonic",
        "timestamps_server_send_wall", "timestamps_server_send_monotonic",
        "timestamps_server_receive_wall", "timestamps_server_receive_monotonic",
    ]
    
    with open(input_file, "rb") as f, open(output_file, "w", newline="") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fixed_fieldnames)
        writer.writeheader()
        trips = ijson.items(f, "round_trips.item")
        for trip in trips:
            normalised = normalise_rt(trip)
            row = { key: normalised.get(key, "") for key in fixed_fieldnames }
            writer.writerow(row)
    print(f"RTT data written to {output_file}")

def process_folder(folder_path):
    #Processes all JSON files in a folder; same as above, just iterates through a directory
    #For each JSON file: Use the filename as request_id, Extract and flatten the 'stats' object, Writes RTT data to CSV
    #Returns: list of dictionaries containing flattened stats for all files
    master_stats = []
    json_files = sorted([f for f in os.listdir(folder_path) if f.endswith(".json")])
    
    for file in json_files:
        json_file = os.path.join(folder_path, file)
        request_id = os.path.splitext(file)[0]
        
        #Extract and flatten stats from JSON
        stats = get_dictionary(json_file)
        stats["request_id"] = request_id
        master_stats.append(stats)
        
        #Extract RTT data and write to CSV
        round_trips_csv = os.path.join(folder_path, f"round_trips_{request_id}.csv")
        extract_rt(json_file, round_trips_csv)
    
    #Write master stats for the folder (just an aggregated version of every time window that was in the folder)
    master_stats_csv = os.path.join(folder_path, "stats.csv")
    fieldnames = set()
    for stat in master_stats:
        fieldnames |= set(stat.keys())
    fieldnames = sorted(list(fieldnames))
    
    with open(master_stats_csv, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for stat in master_stats:
            writer.writerow({fn: stat.get(fn, "") for fn in fieldnames})
    print(f"Master stats written to {master_stats_csv}")
    return master_stats

def process_parent_folder(parent_folder):
    #Basically just a primary function that brings all previous functions together and calls them in the correct order
    #Inputs: parent_folder: The folder containing subfolders with JSON files
    #Returns: A list of aggregated stats dictionaries
    aggregated_stats = []
    subfolders = sorted([d for d in os.listdir(parent_folder) if os.path.isdir(os.path.join(parent_folder, d))])
    for subfolder in subfolders:
        folder_path = os.path.join(parent_folder, subfolder)
        print(f"Processing folder: {folder_path}")
        stats = process_folder(folder_path)
        aggregated_stats.extend(stats)
    
    master_stats_csv = os.path.join(parent_folder, "master_stats.csv")
    fieldnames = set()
    for stat in aggregated_stats:
        fieldnames |= set(stat.keys())
    fieldnames = sorted(list(fieldnames))
    
    with open(master_stats_csv, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for stat in aggregated_stats:
            writer.writerow({fn: stat.get(fn, "") for fn in fieldnames})
    print(f"Aggregated master stats written to {master_stats_csv}")

def main():
    parent_folder = "#PARENTDIR"
    process_parent_folder(parent_folder)

if __name__ == "__main__":
    main()