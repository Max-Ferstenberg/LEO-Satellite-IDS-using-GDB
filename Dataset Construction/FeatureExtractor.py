#FEATURE EXTRACTOR AND CALCULATOR FROM PCAP FILES (Also finishes off cleaning and merging for CIC-IDS2017)

import pandas as pd
import numpy as np
from scapy.all import rdpcap, IP, TCP, UDP
import os

def derive_and_merge(static_csv_path, metadata_csv_path, pcap_directory, output_merged_csv, output_metadata_csv):
    #Processes PCAP files and merges derived packet-level features with static metadata - This script does most of the heavy lifting in terms of dataset construction
    #Renames headers based on a predefined mapping and outputs two CSV files:
    #  - A merged CSV with derived features per request
    #  - A CSV with static metadata
    
    #Parameters:
    #  - static_csv_path: Path to the primary CSV file with static network data.
    #  - metadata_csv_path: Path to the CSV file with additional satellite metadata.
    #  - pcap_directory: Directory containing per-request PCAP files.
    #  - output_merged_csv: Output CSV file for the merged data.
    #  - output_metadata_csv: Output CSV file for the static metadata.
    
    #Mapping of original column names to target names; fields mapped to 'N/A' are ignored
    header_mapping = {
        'Flow ID': 'N/A',
        'Source IP': 'srcip',
        'Source Port': 'sport',
        'Destination IP': 'dstip',
        'Destination Port': 'dsport',
        'Protocol': 'proto',
        'Timestamp': 'Stime',
        'Flow Duration': 'dur',
        'Total Fwd Packets': 'Spkts',
        'Total Backward Packets': 'Dpkts',
        'Total Length of Fwd Packets': 'sbytes',
        'Total Length of Bwd Packets': 'dbytes',
        'Fwd Packet Length Max': 'N/A',
        'Fwd Packet Length Min': 'N/A',
        'Fwd Packet Length Mean': 'N/A',
        'Fwd Packet Length Std': 'N/A',
        'Bwd Packet Length Max': 'N/A',
        'Bwd Packet Length Min': 'N/A',
        'Bwd Packet Length Mean': 'N/A',
        'Bwd Packet Length Std': 'N/A',
        'Flow Bytes/s': 'N/A',
        'Flow Packets/s': 'N/A',
        'Flow IAT Mean': 'N/A',
        'Flow IAT Std': 'N/A',
        'Flow IAT Max': 'N/A',
        'Flow IAT Min': 'N/A',
        'Fwd IAT Total': 'N/A',
        'Fwd IAT Mean': 'N/A',
        'Fwd IAT Std': 'N/A',
        'Fwd IAT Max': 'N/A',
        'Fwd IAT Min': 'N/A',
        'Bwd IAT Total': 'N/A',
        'Bwd IAT Mean': 'N/A',
        'Bwd IAT Std': 'N/A',
        'Bwd IAT Max': 'N/A',
        'Bwd IAT Min': 'N/A',
        'Fwd PSH Flags': 'N/A',
        'Bwd PSH Flags': 'N/A',
        'Fwd URG Flags': 'N/A',
        'Bwd URG Flags': 'N/A',
        'Fwd Header Length': 'N/A',
        'Bwd Header Length': 'N/A',
        'Fwd Packets/s': 'N/A',
        'Bwd Packets/s': 'N/A',
        'Min Packet Length': 'N/A',
        'Max Packet Length': 'N/A',
        'Packet Length Mean': 'N/A',
        'Packet Length Std': 'N/A',
        'Packet Length Variance': 'N/A',
        'FIN Flag Count': 'N/A',
        'SYN Flag Count': 'N/A',
        'RST Flag Count': 'N/A',
        'PSH Flag Count': 'N/A',
        'ACK Flag Count': 'N/A',
        'URG Flag Count': 'N/A',
        'CWE Flag Count': 'N/A',
        'ECE Flag Count': 'N/A',
        'Down/Up Ratio': 'N/A',
        'Average Packet Size': 'N/A',
        'Avg Fwd Segment Size': 'N/A',
        'Avg Bwd Segment Size': 'N/A',
        'Fwd Header Length.1': 'N/A',
        'Fwd Avg Bytes/Bulk': 'N/A',
        'Fwd Avg Packets/Bulk': 'N/A',
        'Fwd Avg Bulk Rate': 'N/A',
        'Bwd Avg Bytes/Bulk': 'N/A',
        'Bwd Avg Packets/Bulk': 'N/A',
        'Bwd Avg Bulk Rate': 'N/A',
        'Subflow Fwd Packets': 'N/A',
        'Subflow Fwd Bytes': 'N/A',
        'Subflow Bwd Packets': 'N/A',
        'Subflow Bwd Bytes': 'N/A',
        'Init_Win_bytes_forward': 'swin',
        'Init_Win_bytes_backward': 'dwin',
        'act_data_pkt_fwd': 'N/A',
        'min_seg_size_forward': 'N/A',
        'Active Mean': 'N/A',
        'Active Std': 'N/A',
        'Active Max': 'N/A',
        'Active Min': 'N/A',
        'Idle Mean': 'N/A',
        'Idle Std': 'N/A',
        'Idle Max': 'N/A',
        'Idle Min': 'N/A',
        'Label': 'attack_cat',
        'Sintpkt': 'Sintpkt',
        'smeansz': 'smeansz',
        'dmeansz': 'dmeansz',
        'sloss': 'sloss',
        'dloss': 'dloss',
        'Sload': 'Sload',
        'Dload': 'Dload',
        'Sjit': 'Sjit',
        'Djit': 'Djit',
        'sttl': 'sttl',
        'dttl': 'dttl',
        'ct_state_ttl': 'ct_state_ttl',
        'ct_src_dport_ltm': 'ct_src_dport_ltm',
        'ct_dst_sport_ltm': 'ct_dst_sport_ltm',
        'ct_dst_src_ltm': 'ct_dst_src_ltm',
        'ct_srv_src': 'ct_srv_src',
        'ct_srv_dst': 'ct_srv_dst',
        'ct_dst_ltm': 'ct_dst_ltm',
        'ct_src_ltm': 'ct_src_ltm',
        'synack': 'synack',
        'ackdat': 'ackdat',
        'tcprtt': 'tcprtt',
        'Dintpkt': 'Dintpkt'
    }
    
    df_metadata = pd.read_csv(metadata_csv_path)
    
    #Open the output merged CSV file and write the header
    with open(output_merged_csv, 'w', encoding='utf-8') as outfile:
        #Construct header starting with 'request_id' then mapping values from header_mapping
        header = ['request_id'] + [new for orig, new in header_mapping.items() if new != 'N/A']
        outfile.write(','.join(header) + '\n')
    
    #Read the static CSV file with proper type inference
    try:
        df_static = pd.read_csv(static_csv_path, low_memory=False)
    except Exception:
        df_static = pd.read_csv(static_csv_path, dtype='object')
        for col in df_static.columns:
            try:
                df_static[col] = pd.to_numeric(df_static[col], errors='coerce')
            except Exception:
                try:
                    df_static[col] = pd.to_datetime(df_static[col], errors='coerce')
                except Exception:
                    pass
    
    #Convert the 'Timestamp' column to Unix time in seconds
    try:
        df_static['Timestamp'] = pd.to_datetime(df_static['Timestamp'], errors='coerce').astype('int64') // 10**9
    except ValueError:
        try:
            df_static['Timestamp'] = pd.to_datetime(df_static['Timestamp'], format="%m/%d/%Y %H:%M", errors='coerce').astype('int64') // 10**9
        except ValueError:
            pass

    #Iterate over each row in the static CSV
    for index, row in df_static.iterrows():
        request_id = row['request_id']
        pcap_file = os.path.join(pcap_directory, f"{request_id}.pcap")
        if not os.path.exists(pcap_file):
            pcap_file = os.path.join(pcap_directory, f"{request_id}.pcapng")
            if not os.path.exists(pcap_file):
                continue

        try:
            packets = rdpcap(pcap_file)
        except Exception:
            continue

        #Init lists for packet-level features
        timestamps, packet_lengths, directions = [], [], []
        src_ips, dst_ips, src_ports, dst_ports = [], [], [], []
        tcp_flags, ttls = [], []

        for packet in packets:
            if IP in packet:
                timestamps.append(packet.time)
                packet_lengths.append(len(packet))
                src_ips.append(packet[IP].src)
                dst_ips.append(packet[IP].dst)
                ttls.append(packet[IP].ttl)

                #Determine direction: 1 if packet from source to destination, 0 for reverse
                if packet[IP].src == row['Source IP'] and packet[IP].dst == row['Destination IP']:
                    direction = 1
                elif packet[IP].src == row['Destination IP'] and packet[IP].dst == row['Source IP']:
                    direction = 0
                else:
                    direction = -1
                directions.append(direction)

                #Extract port and TCP flag information
                if TCP in packet:
                    src_ports.append(packet[TCP].sport)
                    dst_ports.append(packet[TCP].dport)
                    tcp_flags.append(packet[TCP].flags)
                elif UDP in packet:
                    src_ports.append(packet[UDP].sport)
                    dst_ports.append(packet[UDP].dport)
                    tcp_flags.append(0)
                else:
                    src_ports.append(0)
                    dst_ports.append(0)
                    tcp_flags.append(0)
            else:
                #For non-IP packets, mark values accordingly
                timestamps.append(packet.time)
                packet_lengths.append(len(packet))
                directions.append(-1)
                src_ips.append(None)
                dst_ips.append(None)
                src_ports.append(0)
                dst_ports.append(0)
                ttls.append(0)
                tcp_flags.append(0)

        #Create a DataFrame from extracted packet data
        packet_df = pd.DataFrame({
            'Timestamp': timestamps,
            'Packet Length': packet_lengths,
            'Direction': directions,
            'srcip': src_ips,
            'dstip': dst_ips,
            'sport': src_ports,
            'dsport': dst_ports,
            'tcp_flags': tcp_flags,
            'ttl': ttls,
        })
        #Filter out packets with unknown direction
        packet_df = packet_df[packet_df['Direction'] != -1]

        #Derive features from the packet DataFrame
        derived = {}
        derived['request_id'] = request_id
        derived['Sintpkt'] = (packet_df['Timestamp'].diff().mean() * 1_000_000) if len(packet_df) > 1 else 0
        derived['smeansz'] = packet_df['Packet Length'].mean()
        derived['dmeansz'] = (packet_df.loc[packet_df['Direction'] == 0, 'Packet Length'].mean()
                              if len(packet_df[packet_df['Direction'] == 0]) > 0 else 0)
        derived['sloss'] = (packet_df['Direction'].diff() == 0).sum() if len(packet_df) > 1 else 0
        derived['dloss'] = ((packet_df['Direction'].diff() == 0) & (packet_df['Direction'] == 0)).sum() if len(packet_df) > 1 else 0

        flow_duration = float(row['Flow Duration'])
        derived['Sload'] = (packet_df['Packet Length'].sum() * 8) / (flow_duration * 1_000_000) if flow_duration > 0 else 0
        derived['Dload'] = (packet_df.loc[packet_df['Direction'] == 0, 'Packet Length'].sum() * 8) / (flow_duration * 1_000_000) if (flow_duration > 0 and len(packet_df[packet_df['Direction'] == 0]) > 0) else 0
        derived['Sjit'] = (packet_df['Timestamp'].diff().diff().abs().mean() * 1_000_000) if len(packet_df) > 2 else 0
        derived['Djit'] = (packet_df.loc[packet_df['Direction'] == 0, 'Timestamp'].diff().diff().abs().mean() * 1_000_000) if len(packet_df[packet_df['Direction'] == 0]) > 2 else 0
        derived['sttl'] = packet_df['ttl'].iloc[0] if not packet_df.empty else 0
        derived['dttl'] = (packet_df.loc[packet_df['Direction'] == 0, 'ttl'].iloc[0]
                           if not packet_df[packet_df['Direction'] == 0].empty else 0)

        ack_packets = packet_df[packet_df['tcp_flags'].astype(str).str.contains('A')]
        if not ack_packets.empty:
            first_a_timestamp = ack_packets['Timestamp'].iloc[0]
            row_timestamp = float(row['Timestamp'])
            derived['ackdat'] = (first_a_timestamp - row_timestamp) * 1_000_000
        else:
            derived['ackdat'] = 0

        derived['synack'] = ((packet_df[packet_df['tcp_flags'].astype(str).str.contains('S')]['Timestamp'].iloc[0] -
                              packet_df[packet_df['tcp_flags'].astype(str).str.contains('A')]['Timestamp'].iloc[0]) * 1_000_000
                             if (len(packet_df[packet_df['tcp_flags'].astype(str).str.contains('S')]) > 0 and
                                 len(packet_df[packet_df['tcp_flags'].astype(str).str.contains('A')]) > 0) else 0)
        derived['tcprtt'] = derived['synack'] + derived['ackdat'] if (derived['synack'] != 0 and derived['ackdat'] != 0) else 0
        derived['Dintpkt'] = (packet_df.loc[packet_df['Direction'] == 0, 'Timestamp'].diff().mean() * 1_000_000) if len(packet_df[packet_df['Direction'] == 0]) > 1 else 0
        
        #Set additional fields as placeholders
        derived['ct_state_ttl'] = 0
        derived['ct_src_dport_ltm'] = 0
        derived['ct_dst_sport_ltm'] = 0
        derived['ct_dst_src_ltm'] = 0
        derived['ct_srv_src'] = 0
        derived['ct_srv_dst'] = 0
        derived['ct_dst_ltm'] = 0
        derived['ct_src_ltm'] = 0

        #Create a DataFrame for the derived features
        derived_df = pd.DataFrame([derived])
        #Merge the static row with the derived features using request id
        merged_row = pd.merge(row.to_frame().T, derived_df, on='request_id', how='left')
        merged_row.fillna(0, inplace=True)

        #Build the output row based on the header mapping
        output_row = {'request_id': merged_row['request_id'].iloc[0]}
        for orig_col, new_col in header_mapping.items():
            if new_col != 'N/A':
                if orig_col in merged_row.columns:
                    output_row[new_col] = merged_row[orig_col].iloc[0]
                elif new_col in merged_row.columns:
                    output_row[new_col] = merged_row[new_col].iloc[0]
                else:
                    output_row[new_col] = 0

        #Filter the output row to include only the pre-determined header columns
        filtered_row = {col: output_row.get(col, 0) for col in header}
        
        #Append the processed row to the merged output CSV
        with open(output_merged_csv, 'a', encoding='utf-8') as outfile:
            outfile.write(','.join(str(value) for value in filtered_row.values()) + '\n')

    #Write the metadata DataFrame to the second output CSV
    df_metadata.to_csv(output_metadata_csv, index=False)
    print(f"Merged data written to {output_merged_csv}")
    print(f"Metadata written to {output_metadata_csv}")

#--- Usage ---
csv1_path = r'#DATASET1.csv'
csv2_path = r'#SATELLITEDATA.csv'
pcap_dir = r'#DATASET1PCAPs'
output1_path = 'dataset1_processed.csv'
output2_path = 'dataset2_processed.csv'

derive_and_merge(csv1_path, csv2_path, pcap_dir, output1_path, output2_path)