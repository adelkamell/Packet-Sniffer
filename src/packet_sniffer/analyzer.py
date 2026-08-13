"""
Packet Analyzer - Advanced packet analysis and statistics
"""

from collections import Counter
from scapy.all import IP, TCP, UDP, ICMP


class PacketAnalyzer:
    """Analyze captured packets and generate statistics"""
    
    def __init__(self, packets):
        self.packets = packets
        self.stats = {
            'total': len(packets),
            'protocols': Counter(),
            'src_ips': Counter(),
            'dst_ips': Counter(),
            'ports': Counter(),
        }
        self._analyze()
    
    def _analyze(self):
        """Analyze all packets and populate statistics"""
        for packet in self.packets:
            if IP in packet:
                ip = packet[IP]
                self.stats['protocols'][ip.proto] += 1
                self.stats['src_ips'][ip.src] += 1
                self.stats['dst_ips'][ip.dst] += 1
                
                if TCP in packet:
                    self.stats['ports'][packet[TCP].sport] += 1
                    self.stats['ports'][packet[TCP].dport] += 1
                elif UDP in packet:
                    self.stats['ports'][packet[UDP].sport] += 1
                    self.stats['ports'][packet[UDP].dport] += 1
    
    def get_summary(self):
        """Get a summary of packet statistics"""
        summary = f"""
📊 Packet Analysis Summary
{'='*50}
Total Packets:     {self.stats['total']}

Top Protocols:
"""
        for proto, count in self.stats['protocols'].most_common(5):
            summary += f"  - {proto}: {count} packets\n"
        
        summary += "\nTop Source IPs:\n"
        for ip, count in self.stats['src_ips'].most_common(5):
            summary += f"  - {ip}: {count} packets\n"
        
        summary += "\nTop Destination IPs:\n"
        for ip, count in self.stats['dst_ips'].most_common(5):
            summary += f"  - {ip}: {count} packets\n"
        
        return summary
    
    def get_protocol_breakdown(self):
        """Get protocol breakdown as dictionary"""
        return dict(self.stats['protocols'])
    
    def get_top_ports(self, n=10):
        """Get top n ports"""
        return self.stats['ports'].most_common(n)