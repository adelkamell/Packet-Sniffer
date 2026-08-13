import unittest
from packet_sniffer.sniffer import PacketSniffer

class TestPacketSniffer(unittest.TestCase):
    def test_initialization(self):
        sniffer = PacketSniffer(count=5)
        self.assertEqual(sniffer.count, 5)

if __name__ == "__main__":
    unittest.main()