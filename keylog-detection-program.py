import joblib
import pandas as pd
import numpy as np
from scapy.all import sniff, IP, TCP, UDP
from collections import defaultdict
import statistics

#ERROR: Everything works except "Flow Duration" which may be throwing off the ML model
detection_model = joblib.load('./keylogger-detection-model')

def process_packet(packet):
    # Initialize dictionary to store statistics for each process (IP, source port, destination port, and protocol)
    process_stats = defaultdict(lambda: defaultdict(list))

    # Extract relevant information from the packet
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        flow_duration = 0

        # Check if packet is TCP or UDP
        if TCP in packet:
            protocol = "TCP"
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
        elif UDP in packet:
            protocol = "UDP"
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
        else:
            protocol = "Unknown"
            src_port = -1
            dst_port = -1

        # Append packet info to process_stats for processing
        process_stats[(src_ip, src_port, dst_ip, dst_port, protocol)]["SourcePort"].append(src_port)
        process_stats[(src_ip, src_port, dst_ip, dst_port, protocol)]["DestinationPort"].append(dst_port)
        process_stats[(src_ip, src_port, dst_ip, dst_port, protocol)]["Protocol"].append(protocol)
        process_stats[(src_ip, src_port, dst_ip, dst_port, protocol)]["FlowDuration"].append(flow_duration)
        process_stats[(src_ip, src_port, dst_ip, dst_port, protocol)]["TotalFwdPackets"].append(1)
        process_stats[(src_ip, src_port, dst_ip, dst_port, protocol)]["TotalLengthofFwdPackets"].append(len(packet))
        process_stats[(src_ip, src_port, dst_ip, dst_port, protocol)]["FwdPacketLengthMax"].append(len(packet))
        process_stats[(src_ip, src_port, dst_ip, dst_port, protocol)]["FwdPacketLengthMin"].append(len(packet))
        process_stats[(src_ip, src_port, dst_ip, dst_port, protocol)]["FwdPacketLengthMean"].append(len(packet))
        process_stats[(src_ip, src_port, dst_ip, dst_port, protocol)]["FwdPacketLengthStd"].append(len(packet))
        process_stats[(src_ip, src_port, dst_ip, dst_port, protocol)]["FlowBytes/s"].append(len(packet))
        process_stats[(dst_ip, dst_port, src_ip, src_port, protocol)]["TotalBackwardPackets"].append(1)
        process_stats[(dst_ip, dst_port, src_ip, src_port, protocol)]["TotalLengthofBwdPackets"].append(len(packet))
        process_stats[(dst_ip, dst_port, src_ip, src_port, protocol)]["BwdPacketLengthMax"].append(len(packet))
        process_stats[(dst_ip, dst_port, src_ip, src_port, protocol)]["BwdPacketLengthMin"].append(len(packet))
        process_stats[(dst_ip, dst_port, src_ip, src_port, protocol)]["BwdPacketLengthMean"].append(len(packet))
        process_stats[(dst_ip, dst_port, src_ip, src_port, protocol)]["BwdPacketLengthStd"].append(len(packet))
        process_stats[(dst_ip, dst_port, src_ip, src_port, protocol)]["FlowBytes/s"].append(len(packet))

    return process_stats

def calculate_statistics(stats):
    calculated_stats = {}
    for key, value in stats.items():
        if value:
            #Calculate packet stats
            fwd_packet_length_max = max(value['FwdPacketLengthMax']) if value['FwdPacketLengthMax'] else 0
            fwd_packet_length_min = min(value['FwdPacketLengthMin']) if value['FwdPacketLengthMin'] else 0
            fwd_packet_length_mean = statistics.mean(value['FwdPacketLengthMean']) if value['FwdPacketLengthMean'] else 0
            fwd_packet_length_std = statistics.stdev(value['FwdPacketLengthStd']) if len(value['FwdPacketLengthStd']) > 1 else 0
            bwd_packet_length_max = max(value['BwdPacketLengthMax']) if value['BwdPacketLengthMax'] else 0
            bwd_packet_length_min = min(value['BwdPacketLengthMin']) if value['BwdPacketLengthMin'] else 0
            bwd_packet_length_mean = statistics.mean(value['BwdPacketLengthMean']) if value['BwdPacketLengthMean'] else 0
            bwd_packet_length_std = statistics.stdev(value['BwdPacketLengthStd']) if len(value['BwdPacketLengthStd']) > 1 else 0

            calculated_stats[key] = {
                'SourcePort': key[1],
                'DestinationPort': key[3],
                'Protocol': key[4],
                'FlowDuration': value['FlowDuration'],
                'TotalFwdPackets': sum(value['TotalFwdPackets']),
                'TotalBackwardPackets': sum(value['TotalBackwardPackets']),
                'TotalLengthofFwdPackets': sum(value['TotalLengthofFwdPackets']),
                'TotalLengthofBwdPackets': sum(value['TotalLengthofBwdPackets']),
                'FwdPacketLengthMax': fwd_packet_length_max,
                'FwdPacketLengthMin': fwd_packet_length_min,
                'FwdPacketLengthMean': fwd_packet_length_mean,
                'FwdPacketLengthStd': fwd_packet_length_std,
                'BwdPacketLengthMax': bwd_packet_length_max,
                'BwdPacketLengthMin': bwd_packet_length_min,
                'BwdPacketLengthMean': bwd_packet_length_mean,
                'BwdPacketLengthStd': bwd_packet_length_std,
                'FlowBytes/s': sum(value['FlowBytes/s']) / len(value['FlowBytes/s']),
                'FlowPackets/s': sum(value['TotalFwdPackets']) / len(value['FlowBytes/s'])
            }
    return calculated_stats

def preprocess_system_info(network_stats):
    df = pd.DataFrame.from_dict(network_stats, orient='index')

    # Extract numerical features from network_stats
    numerical_features = df[['TotalFwdPackets', 'TotalBackwardPackets', 'TotalLengthofFwdPackets', 'TotalLengthofBwdPackets', 'FwdPacketLengthMax', 'FwdPacketLengthMin', 'FwdPacketLengthMean', 'FwdPacketLengthStd', 'BwdPacketLengthMax', 'BwdPacketLengthMin', 'BwdPacketLengthMean', 'BwdPacketLengthStd', 'FlowBytes/s', 'FlowPackets/s']].values

    # Convert categorical variables to one-hot encoded representation
    categorical_features = pd.get_dummies(df[['SourcePort', 'DestinationPort', 'Protocol']]).values

    # Concatenate numerical and categorical features
    all_features = np.concatenate((numerical_features, categorical_features), axis=1)

    return all_features

def scan_network_traffic(duration=10):
    process_stats = defaultdict(lambda: defaultdict(list))

    # Sniff network packets for the specified duration
    sniff(filter="ip", prn=lambda pkt: process_stats.update(process_packet(pkt)), timeout=duration)

    return calculate_statistics(process_stats)

network_stats = scan_network_traffic(duration=30)

# Print the extracted network traffic statistics
for (src_ip, src_port, dst_ip, dst_port, protocol), stats in network_stats.items():
    print(f"Source IP: {src_ip}, Source Port: {src_port}, Destination IP: {dst_ip}, Destination Port: {dst_port}, Protocol: {protocol}")
    for key, value in stats.items():
        print(f"{key}: {value}")
    print()

preprocessed_system_info = preprocess_system_info(network_stats)

print(detection_model.predict(preprocessed_system_info))
