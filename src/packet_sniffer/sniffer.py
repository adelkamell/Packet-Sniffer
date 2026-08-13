"""
Packet Sniffer - Advanced Network Packet Capture Tool
Author: Adel Kamel
GitHub: https://github.com/adelkamell
"""

from scapy.all import sniff, IP, TCP, UDP, ICMP
from colorama import Fore, Style, init
import sys

# Initialize colorama for cross-platform colored output
init(autoreset=True)


class PacketSniffer:
    """Main packet sniffer class with callback-based architecture"""
    
    def __init__(self, interface=None, count=0, verbose=False):
        """
        Initialize the packet sniffer.
        
        Args:
            interface (str): Network interface to sniff on (None = all)
            count (int): Number of packets to capture (0 = infinite)
            verbose (bool): Enable verbose output
        """
        self.interface = interface
        self.count = count
        self.verbose = verbose
        self.packets = []
        self.packet_count = 0
        
    def start(self):
        """Start capturing packets"""
        print(f"{Fore.GREEN}[*] Starting packet sniffer...")
        print(f"{Fore.YELLOW}[*] Interface: {self.interface or 'All interfaces'}")
        print(f"{Fore.YELLOW}[*] Press Ctrl+C to stop")
        print("-" * 60)
        
        try:
            # Sniff packets with callback
            sniff(
                iface=self.interface,
                count=self.count,
                prn=self._callback,
                store=False
            )
        except KeyboardInterrupt:
            print(f"\n{Fore.RED}[!] Sniffing stopped by user")
        except PermissionError:
            print(f"{Fore.RED}[!] Permission denied. Run with sudo/administrator privileges.")
            sys.exit(1)
        except Exception as e:
            print(f"{Fore.RED}[!] Error: {e}")
            sys.exit(1)
            
        print(f"\n{Fore.GREEN}[*] Total packets captured: {self.packet_count}")
        return self.packets
    
    def _callback(self, packet):
        """
        Callback function called for each captured packet.
        This is your original packet_callback function with enhancements.
        """
        self.packet_count += 1
        
        # Your original code starts here
        if IP in packet:
            ip_layer = packet[IP]
            
            # Colored output for better readability
            print(f"\n{Fore.CYAN}[+] Packet #{self.packet_count} captured:")
            print(f"    {Fore.WHITE}Source IP: {Fore.YELLOW}{ip_layer.src}")
            print(f"    {Fore.WHITE}Destination IP: {Fore.YELLOW}{ip_layer.dst}")
            print(f"    {Fore.WHITE}Protocol: {Fore.GREEN}{ip_layer.proto}")
            
            # Check for specific protocols
            if TCP in packet:
                print(f"    {Fore.WHITE}TCP Source Port: {Fore.MAGENTA}{packet[TCP].sport}")
                print(f"    {Fore.WHITE}TCP Dest Port: {Fore.MAGENTA}{packet[TCP].dport}")
                # TCP Flags (new feature)
                flags = packet[TCP].flags
                print(f"    {Fore.WHITE}TCP Flags: {Fore.BLUE}{flags}")
                
            elif UDP in packet:
                print(f"    {Fore.WHITE}UDP Source Port: {Fore.MAGENTA}{packet[UDP].sport}")
                print(f"    {Fore.WHITE}UDP Dest Port: {Fore.MAGENTA}{packet[UDP].dport}")
                
            elif ICMP in packet:
                print(f"    {Fore.WHITE}ICMP Type: {Fore.MAGENTA}{packet[ICMP].type}")
                print(f"    {Fore.WHITE}ICMP Code: {Fore.MAGENTA}{packet[ICMP].code}")
            
            # Show first 50 bytes of payload (your original code)
            if len(packet[IP].payload) > 0:
                payload = bytes(packet[IP].payload)[:50]
                print(f"    {Fore.WHITE}Payload (first 50 bytes): {Fore.CYAN}{payload}")
            
            # Verbose mode - show raw packet
            if self.verbose:
                print(f"    {Fore.WHITE}Raw Packet: {Fore.LIGHTBLACK_EX}{packet.summary()}")
        
        # Store packet for later analysis
        self.packets.append(packet)


def main():
    """Entry point for command-line usage"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Advanced Packet Sniffer for Network Security Analysis",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  packet-sniffer                    # Sniff on all interfaces
  packet-sniffer -i eth0            # Sniff on eth0 interface
  packet-sniffer -c 50              # Capture 50 packets
  packet-sniffer -i wlan0 -v        # Verbose output on wlan0
        """
    )
    parser.add_argument(
        '-i', '--interface',
        help='Network interface to sniff on (default: all)'
    )
    parser.add_argument(
        '-c', '--count',
        type=int,
        default=0,
        help='Number of packets to capture (0 = infinite)'
    )
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Enable verbose output'
    )
    
    args = parser.parse_args()
    
    # Create and start sniffer
    sniffer = PacketSniffer(
        interface=args.interface,
        count=args.count,
        verbose=args.verbose
    )
    sniffer.start()


if __name__ == "__main__":
    main()