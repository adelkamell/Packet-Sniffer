from scapy.all import IP, TCP, UDP

def analyze_packet(packet):
    if TCP in packet:
        flags = packet[TCP].flags
        print(f"    TCP Flags: {flags}")
    elif UDP in packet:
        print(f"    UDP Port: {packet[UDP].sport} -> {packet[UDP].dport}")