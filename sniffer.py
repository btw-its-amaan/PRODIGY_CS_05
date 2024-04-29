from scapy.all import *

# Define the file path
file_path = "/home/baymax/Downloads/captured_packets.txt"

def packet_handler(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = packet[IP].proto

        with open(file_path, "a") as f:
            f.write(f"Source IP: {src_ip} --> Destination IP: {dst_ip} Protocol: {protocol}\n")

        if TCP in packet:
            payload = packet[TCP].payload
            with open(file_path, "a") as f:
                f.write("TCP Payload:" + str(payload) + "\n")

        elif UDP in packet:
            payload = packet[UDP].payload
            with open(file_path, "a") as f:
                f.write("UDP Payload:" + str(payload) + "\n")

# Sniff packets
sniff(iface="eth0", prn=packet_handler, store=0)
