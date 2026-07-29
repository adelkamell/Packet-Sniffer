"""
Packet Sniffer V1 :
    - simple and prototype version - just read IP, TCP, UDP, and ICMP of packets
    
"""

from scapy.all import sniff, IP, TCP, UDP, ICMP

def packet_callback(packet):
    """Callback function called for each captured packet"""
    if IP in packet:
        ip_layer = packet[IP]
        print(f"\n[+] Packet captured:")
        print(f"    Source IP: {ip_layer.src}")
        print(f"    Destination IP: {ip_layer.dst}")
        print(f"    Protocol: {ip_layer.proto}")
        
        # Check for specific protocols
        if TCP in packet:
            print(f"    TCP Source Port: {packet[TCP].sport}")
            print(f"    TCP Dest Port: {packet[TCP].dport}")
        elif UDP in packet:
            print(f"    UDP Source Port: {packet[UDP].sport}")
            print(f"    UDP Dest Port: {packet[UDP].dport}")
        elif ICMP in packet:
            print(f"    ICMP Type: {packet[ICMP].type}")
            print(f"    ICMP Code: {packet[ICMP].code}")
        
        # Show first 50 bytes of payload
        if len(packet[IP].payload) > 0:
            print(f"    Payload (first 50 bytes): {bytes(packet[IP].payload)[:50]}")

def main():
    print("Starting packet sniffer... (Press Ctrl+C to stop)")
    print("Sniffing all interfaces...")
    
    # Sniff packets (requires root/admin privileges)
    sniff(prn=packet_callback, count=0, store=False)

if __name__ == "__main__":
    main()