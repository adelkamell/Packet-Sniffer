"""
Unit tests for Packet Sniffer
"""

import unittest
from packet_sniffer.sniffer import PacketSniffer


class TestPacketSniffer(unittest.TestCase):
    """Test cases for PacketSniffer class"""
    
    def test_initialization(self):
        """Test proper initialization"""
        sniffer = PacketSniffer(interface="eth0", count=10, verbose=True)
        self.assertEqual(sniffer.interface, "eth0")
        self.assertEqual(sniffer.count, 10)
        self.assertTrue(sniffer.verbose)
    
    def test_default_initialization(self):
        """Test default values"""
        sniffer = PacketSniffer()
        self.assertIsNone(sniffer.interface)
        self.assertEqual(sniffer.count, 0)
        self.assertFalse(sniffer.verbose)
    
    def test_packet_count(self):
        """Test packet counter starts at zero"""
        sniffer = PacketSniffer()
        self.assertEqual(sniffer.packet_count, 0)


if __name__ == "__main__":
    unittest.main()