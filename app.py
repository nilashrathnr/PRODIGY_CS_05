from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.packet import Raw

# Function to process packets
def packet_callback(packet):
    # Check if the packet has an IP layer (most will)
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        proto = packet[IP].proto

        # Determine the protocol (TCP/UDP/ICMP)
        if proto == 6:  # TCP
            protocol = "TCP"
        elif proto == 17:  # UDP
            protocol = "UDP"
        elif proto == 1:  # ICMP
            protocol = "ICMP"
        else:
            protocol = "Other"

        # Display packet details
        print(f"Source IP: {ip_src}")
        print(f"Destination IP: {ip_dst}")
        print(f"Protocol: {protocol}")

        # If it's TCP or UDP, show port numbers
        if TCP in packet or UDP in packet:
            src_port = packet.sport
            dst_port = packet.dport
            print(f"Source Port: {src_port}")
            print(f"Destination Port: {dst_port}")

        # Show payload data
        if Raw in packet:
            print(f"Payload: {packet[Raw].load}")
        
        print("=" * 50)

# Sniff packets on the default interface
print("Starting packet sniffing...")
sniff(prn=packet_callback, store=0)
