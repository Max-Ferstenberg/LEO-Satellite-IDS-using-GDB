#**UNSW-NB15 PCAP Processing:**

#This was run inside my VM, since that's where the PCAP files were located at the time, hence why this one runs in command line.

#This one also only forms half of the packet derivation process, but is specific to the UNSW-NB15 dataset

#!/usr/bin/env python3

import pyshark
import csv
import statistics
import datetime
import sys

def extract_metrics_from_pcap(pcap_file):
    #Processes a PCAP file to compute various performance metrics.
    #Returns: A dictionary of computed metrics
    cap = pyshark.FileCapture(pcap_file, keep_packets=False)

    pkt_timestamps = []            #Capture times for all packets (in seconds)
    server_pkt_timestamps = []     #Capture times for packets received by the server
    tcp_seq_numbers = []           #List to track TCP sequence numbers
    duplicate_count = 0            #Counter for duplicate packets

    #Process each packet in the capture
    for pkt in cap:
        try:
            ts = float(pkt.sniff_timestamp)
        except Exception:
            continue
        pkt_timestamps.append(ts)

        #Identify packets received by the server using the destination IP field
        try:
            if hasattr(pkt, 'ip') and hasattr(pkt.ip, 'dst'):
                server_pkt_timestamps.append(ts)
        except Exception:
            pass

        #Detect duplicate packets using TCP sequence numbers
        try:
            seq = int(pkt.tcp.seq)
            if seq in tcp_seq_numbers:
                duplicate_count += 1
            else:
                tcp_seq_numbers.append(seq)
        except Exception:
            pass

    cap.close()

    if not pkt_timestamps:
        print("No packets captured.")
        return {}

    #Calculate overall flow duration
    flow_start_time = pkt_timestamps[0]
    flow_end_time = pkt_timestamps[-1]
    flow_duration = flow_end_time - flow_start_time

    metrics = {}
    metrics['server_packets_received'] = len(server_pkt_timestamps)

    #Compute server processing times as differences between consecutive server packet timestamps
    processing_times = [server_pkt_timestamps[i+1] - server_pkt_timestamps[i]
                        for i in range(len(server_pkt_timestamps)-1)]
    if processing_times:
        metrics['server_processing_time_max'] = max(processing_times)
        metrics['server_processing_time_min'] = min(processing_times)
        metrics['server_processing_time_mean'] = statistics.mean(processing_times)
        metrics['server_processing_time_stddev'] = statistics.stdev(processing_times) if len(processing_times) > 1 else 0.0
        metrics['server_processing_time_total'] = sum(processing_times)
        metrics['server_processing_time_n'] = len(processing_times)
        metrics['server_processing_time_variance'] = statistics.variance(processing_times) if len(processing_times) > 1 else 0.0
    else:
        for key in ['server_processing_time_max', 'server_processing_time_min', 'server_processing_time_mean',
                    'server_processing_time_stddev', 'server_processing_time_total', 'server_processing_time_n',
                    'server_processing_time_variance']:
            metrics[key] = None

    #Record the start time (wall clock and monotonic) for the flow
    metrics['start_time_wall'] = datetime.datetime.fromtimestamp(flow_start_time).isoformat()
    metrics['start_time_monotonic'] = flow_start_time

    #Compute timer errors: differences between actual inter-arrival times and an expected interval
    inter_arrivals = [pkt_timestamps[i+1] - pkt_timestamps[i] for i in range(len(pkt_timestamps)-1)]
    expected_interval = flow_duration / len(pkt_timestamps) if len(pkt_timestamps) > 0 else 0.0
    timer_errors = [ia - expected_interval for ia in inter_arrivals]
    if timer_errors:
        metrics['timer_error_max'] = max(timer_errors) * 1000   #Convert to milliseconds
        metrics['timer_error_min'] = min(timer_errors) * 1000
        metrics['timer_error_mean'] = statistics.mean(timer_errors) * 1000
        metrics['timer_error_stddev'] = (statistics.stdev(timer_errors) * 1000) if len(timer_errors) > 1 else 0.0
        metrics['timer_error_total'] = sum(timer_errors) * 1000
        metrics['timer_error_n'] = len(timer_errors)
        metrics['timer_error_variance'] = (statistics.variance(timer_errors) * 1e6) if len(timer_errors) > 1 else 0.0
        threshold = 2 * expected_interval
        errors_above_threshold = sum(1 for err in timer_errors if abs(err) > threshold)
        metrics['timer_err_percent'] = (errors_above_threshold / len(timer_errors)) * 100
    else:
        for key in ['timer_error_max', 'timer_error_min', 'timer_error_mean', 'timer_error_stddev',
                    'timer_error_total', 'timer_error_n', 'timer_error_variance', 'timer_err_percent']:
            metrics[key] = None

    #Compute upstream loss percentage
    total_packets = len(pkt_timestamps)
    metrics['upstream_loss_percent'] = ((total_packets - len(server_pkt_timestamps)) / total_packets) * 100 if total_packets > 0 else None

    #Calculate RTTs as differences between consecutive packet timestamps
    rtts = [pkt_timestamps[i+1] - pkt_timestamps[i] for i in range(len(pkt_timestamps)-1)]
    if rtts:
        metrics['rtt_max'] = max(rtts) * 1000  
        metrics['rtt_min'] = min(rtts) * 1000
        metrics['rtt_mean'] = statistics.mean(rtts) * 1000
        metrics['rtt_stddev'] = (statistics.stdev(rtts) * 1000) if len(rtts) > 1 else 0.0
        metrics['rtt_total'] = sum(rtts) * 1000
        metrics['rtt_n'] = len(rtts)
        metrics['rtt_variance'] = (statistics.variance(rtts) * 1e6) if len(rtts) > 1 else 0.0
        metrics['rtt_median'] = statistics.median(rtts) * 1000
    else:
        for key in ['rtt_max', 'rtt_min', 'rtt_mean', 'rtt_stddev', 'rtt_total', 'rtt_n', 'rtt_variance', 'rtt_median']:
            metrics[key] = None

    #Inter-Packet Delay Variation computed as differences between successive RTTs
    if rtts and len(rtts) > 1:
        ipdv_rtts = [abs(rtts[i+1] - rtts[i]) for i in range(len(rtts)-1)]
        metrics['ipdv_round_trip_max'] = max(ipdv_rtts) * 1000
        metrics['ipdv_round_trip_min'] = min(ipdv_rtts) * 1000
        metrics['ipdv_round_trip_mean'] = statistics.mean(ipdv_rtts) * 1000
        metrics['ipdv_round_trip_median'] = statistics.median(ipdv_rtts) * 1000
        metrics['ipdv_round_trip_stddev'] = (statistics.stdev(ipdv_rtts) * 1000) if len(ipdv_rtts) > 1 else 0.0
        metrics['ipdv_round_trip_total'] = sum(ipdv_rtts) * 1000
        metrics['ipdv_round_trip_n'] = len(ipdv_rtts)
        metrics['ipdv_round_trip_variance'] = (statistics.variance(ipdv_rtts) * 1e6) if len(ipdv_rtts) > 1 else 0.0
    else:
        for key in ['ipdv_round_trip_max', 'ipdv_round_trip_min', 'ipdv_round_trip_mean', 'ipdv_round_trip_median',
                    'ipdv_round_trip_stddev', 'ipdv_round_trip_total', 'ipdv_round_trip_n', 'ipdv_round_trip_variance']:
            metrics[key] = None

    #Record duplicate packet information based on TCP sequence numbers
    metrics['duplicates'] = duplicate_count
    metrics['duplicate_percent'] = (duplicate_count / total_packets * 100) if total_packets > 0 else None

    return metrics

def write_metrics_to_csv(metrics, output_csv):
    #Writes the computed metrics to a CSV file.
    #Input: metrics: A dictionary containing metric values.
    #Returns: output_csv
    fieldnames = sorted(metrics.keys())
    with open(output_csv, "w", newline="") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerow(metrics)
    print(f"Metrics written to {output_csv}")

if __name__ == "__main__":
    pcap_file = sys.argv[1]
    output_csv = sys.argv[2]
    metrics = extract_metrics_from_pcap(pcap_file)
    write_metrics_to_csv(metrics, output_csv)