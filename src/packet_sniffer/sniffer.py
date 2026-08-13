import sys
from scapy.all import sniff, IP, TCP, UDP
from colorama import Fore, Style, init
from .analyzer import analyze_packet

init(autoreset=True)

class PacketSniffer:
    def __init__(self, interface=None, count=10):
        self.interface = interface
        self.count = count
        self.packets = []

    def start(self):
        print(f"{Fore.GREEN}[*] Starting packet sniffer on {self.interface or 'all interfaces'}")
        self.packets = sniff(iface=self.interface, count=self.count, prn=self._callback)
        return self.packets

    def _callback(self, packet):
        if IP in packet:
            src = packet[IP].src
            dst = packet[IP].dst
            proto = "TCP" if TCP in packet else "UDP" if UDP in packet else "Other"
            print(f"{Fore.CYAN}[+] {src} -> {dst} ({proto})")
            analyze_packet(packet)

def main():
    sniffer = PacketSniffer(count=20)
    sniffer.start()

if __name__ == "__main__":
    main()