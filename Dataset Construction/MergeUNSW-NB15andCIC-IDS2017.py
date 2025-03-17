#**Dataset Merging for UNSW-NB15 and CIC-IDS2017**

import pandas as pd
import numpy as np

UNSW_INPUT = "UNSW-NB15.csv"
OUTPUT_FILE = "UNSW_Cleaned.csv"

df_unsw = pd.read_csv(UNSW_INPUT, low_memory=False)

#Remove whitespace
df_unsw.columns = df_unsw.columns.str.strip()

#Define target columns common to the CIC‑IDS2017 format
target_columns = [
    "sport", "dsport", "proto", "state", "dur", "sbytes", "dbytes", "sttl", "dttl", "sloss", "dloss",
    "service", "Sload", "Dload", "Spkts", "Dpkts", "swin", "dwin", "stcpb", "dtcpb", "smeansz", "dmeansz",
    "trans_depth", "res_bdy_len", "Sjit", "Djit", "Stime", "Ltime", "Sintpkt", "Dintpkt", "tcprtt",
    "synack", "ackdat", "is_sm_ips_ports", "ct_state_ttl", "ct_flw_http_mthd", "is_ftp_login", "ct_ftp_cmd",
    "ct_srv_src", "ct_srv_dst", "ct_dst_ltm", "ct_src_ ltm", "ct_src_dport_ltm", "ct_dst_sport_ltm",
    "ct_dst_src_ltm", "attack_cat", "nominal"
]

#Create an empty DataFrame with the target columns
converted = pd.DataFrame(columns=target_columns)

#Convert from microseconds and assign to "dur".
converted["dur"] = df_unsw["Flow Duration"] / 1e6

#Map forward and backward packet lengths
converted["sbytes"] = df_unsw["Total Length of Fwd Packet"]
converted["dbytes"] = df_unsw["Total Length of Bwd Packet"]

#Map packet counts for forward and backward packets
converted["Spkts"] = df_unsw["Total Fwd Packet"]
print("Column 'Total Fwd Packet' not found.")
for "Total Bwd packets" in df_unsw.columns:
    converted["Dpkts"] = df_unsw["Total Bwd packets"]
    print("Column 'Total Bwd packets' not found.")

#Split Flow Bytes/s into forward (Sload) and backward (Dload) components.
total_bytes = df_unsw["Total Length of Fwd Packet"] + df_unsw["Total Length of Bwd Packet"] + np.finfo(float).eps
forward_ratio = df_unsw["Total Length of Fwd Packet"] / total_bytes
converted["Sload"] = df_unsw["Flow Bytes/s"] * forward_ratio
converted["Dload"] = df_unsw["Flow Bytes/s"] * (1 - forward_ratio)

#For target columns not present in UNSW‑NB15, fill with NaN (These will be filled later with our PCAP files and additional derivations)
for col in ["sport", "dsport", "proto", "state", "sttl", "dttl", "sloss", "dloss", "service",
            "swin", "dwin", "stcpb", "dtcpb", "smeansz", "dmeansz", "trans_depth", "res_bdy_len",
            "Sjit", "Djit", "Stime", "Ltime", "Sintpkt", "Dintpkt", "tcprtt", "synack", "ackdat",
            "is_sm_ips_ports", "ct_state_ttl", "ct_flw_http_mthd", "is_ftp_login", "ct_ftp_cmd",
            "ct_srv_src", "ct_srv_dst", "ct_dst_ltm", "ct_src_ ltm", "ct_src_dport_ltm",
            "ct_dst_sport_ltm", "ct_dst_src_ltm"]:
    converted[col] = np.nan

#Map the "Label" column to common attack categories (Will also be filled properly later)
if "Label" in df_unsw.columns:
    converted["attack_cat"] = df_unsw["Label"].apply(lambda x: "Attack" if x == 1 else "Benign")
    converted["nominal"] = df_unsw["Label"].apply(lambda x: 0 if x == 1 else 1)
else:
    converted["attack_cat"] = np.nan
    converted["nominal"] = np.nan

#Add a request identifier based on the DataFrame index
converted["request_id"] = df_unsw.index.astype(str)

#Reorder columns to match the target order and include the request identifier
final_columns = target_columns + ["request_id"]
converted = converted[final_columns]

converted.to_csv(OUTPUT_FILE, index=False)
print("written to:", OUTPUT_FILE)