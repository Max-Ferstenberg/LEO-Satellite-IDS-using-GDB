#**FULL PCAP MAPPER**

#This script matches PCAP files to requests based on flows, groups packets together by request, and writes metrics to CSV format.


import os
import csv
import time
import glob
import pandas as pd
from scapy.all import PcapReader, wrpcap, TCP, UDP, IP, rdpcap

REQ_CSV = r"#REQUESTCSV.csv"
PCAP_DIR = r"#PCAPDIR"
OUTPUT_CSV_DIR = r"#Per-packet CSVs"
OUTPUT_PCAP_DIR = r"#Separated pcaps"

os.makedirs(OUTPUT_CSV_DIR, exist_ok=True)
os.makedirs(OUTPUT_PCAP_DIR, exist_ok=True)

#normalise column names
df_high = pd.read_csv(REQ_CSV, low_memory=False)
df_high.columns = df_high.columns.str.strip().str.lower()

output_cols = ["flow id", "source ip", "source port", "destination ip", "destination port", "protocol"]

#Convert protocol and port fields to numeric and then to integer to avoid data mismatches
df_high["protocol"] = pd.to_numeric(df_high["protocol"], errors="coerce").fillna(0).astype(int)
df_high["source port"] = pd.to_numeric(df_high["source port"], errors="coerce").fillna(0).astype(int)
df_high["destination port"] = pd.to_numeric(df_high["destination port"], errors="coerce").fillna(0).astype(int)

#Build a dictionary mapping a key tuple to a unique request identifier (flow id)
#The key is: (source ip, source port, destination ip, destination port, protocol) - We also construct this same key but with source and destination swapped, to indicate uplink/downlink
request_dict = {}
for idx, row in df_high.iterrows():
    proto_num = row["protocol"]
    if proto_num == 6:
        proto = "tcp"
    elif proto_num == 17:
        proto = "udp"
    else:
        continue 

    src_port = str(row["source port"])
    dst_port = str(row["destination port"])
    key = (
        str(row["source ip"]).strip().lower(),
        src_port,
        str(row["destination ip"]).strip().lower(),
        dst_port,
        proto
    )
    req_id = str(row["flow id"]).strip()
    request_dict[key] = req_id

#Prepare dictionaries to store packet records and raw Scapy packets per request
unique_req_ids = df_high["flow id"].astype(str).str.strip().unique()
request_csv_records = {req_id: [] for req_id in unique_req_ids}
request_raw_packets = {req_id: [] for req_id in unique_req_ids}

pcap_files = glob.glob(os.path.join(PCAP_DIR, "*.pcap")) + glob.glob(os.path.join(PCAP_DIR, "*.pcapng"))

packet_counter = 0
start_time = time.time()

#Main loop - processes PCAP into packets
for pcap_file in pcap_files:
    try:
        with PcapReader(pcap_file) as pcap_reader:
            for pkt in pcap_reader:
                packet_counter += 1

                if IP not in pkt or (TCP not in pkt and UDP not in pkt):
                    continue

                src_ip = pkt[IP].src.strip().lower()
                dst_ip = pkt[IP].dst.strip().lower()
                if TCP in pkt:
                    proto = "tcp"
                    sport = str(pkt[TCP].sport).strip()
                    dport = str(pkt[TCP].dport).strip()
                elif UDP in pkt:
                    proto = "udp"
                    sport = str(pkt[UDP].sport).strip()
                    dport = str(pkt[UDP].dport).strip()
                else:
                    continue

                #Construct both forward and reverse keys
                key = (src_ip, sport, dst_ip, dport, proto)
                rev_key = (dst_ip, dport, src_ip, sport, proto)

                req_id = request_dict.get(key) or request_dict.get(rev_key)
                if req_id is not None:
                    #Create a CSV record for the packet
                    record = {
                        "No.": packet_counter,
                        "Time": pkt.time,
                        "Source": pkt[IP].src if IP in pkt else "",
                        "Destination": pkt[IP].dst if IP in pkt else "",
                        "Protocol": proto,
                        "Length": len(pkt),
                        "Info": pkt.summary()
                    }
                    request_csv_records[req_id].append(record)
                    request_raw_packets[req_id].append(pkt)

                #Periodically log progress (this is just to prevent halting, keeps the process active since I was running this in google colab)
                if packet_counter % 10000 == 0:
                    print(f"Processed {packet_counter} packets")

    except Exception as e:
        print(f"Error processing {os.path.basename(pcap_file)}: {e}")

print(f"\nFinished! Total packets processed: {packet_counter}")

#Write per-request CSV and PCAP files
for req_id, records in request_csv_records.items():
    raw_pkts = request_raw_packets[req_id]
    if records:
        csv_out_path = os.path.join(OUTPUT_CSV_DIR, f"{req_id}.csv")
        fieldnames = ["No.", "Time", "Source", "Destination", "Protocol", "Length", "Info"]
        #Write or append CSV records for the request
        if os.path.exists(csv_out_path):
            try:
                with open(csv_out_path, 'a', newline='') as csvfile:
                    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                    writer.writerows(records)
            except Exception as e:
                print(f"Error appending CSV for {req_id}: {e}")
        else:
            try:
                with open(csv_out_path, 'w', newline='') as csvfile:
                    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                    writer.writeheader()
                    writer.writerows(records)
            except Exception as e:
                print(f"Error writing CSV for {req_id}: {e}")
                
        #Write or append PCAP files for the request
        pcap_out_path = os.path.join(OUTPUT_PCAP_DIR, f"{req_id}.pcap")
        if os.path.exists(pcap_out_path):
            try:
                existing_pkts = rdpcap(pcap_out_path)
                all_pkts = existing_pkts + raw_pkts
                wrpcap(pcap_out_path, all_pkts)
            except Exception as e:
                print(f"Error appending PCAP for {req_id}: {e}")
        else:
            try:
                wrpcap(pcap_out_path, raw_pkts)
            except Exception as e:
                print(f"Error writing PCAP for {req_id}: {e}")
    else:
        print(f"No packets matched for request {req_id}")

print("\nProcessing complete!")