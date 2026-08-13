"""
Packet Sniffer - A lightweight, real-time packet sniffer for network security analysis.
"""

from .sniffer import PacketSniffer, main
from .analyzer import PacketAnalyzer

__version__ = "0.1.0"
__author__ = "Adel Kamel"
__all__ = ['PacketSniffer', 'PacketAnalyzer', 'main']