"""
Test whether layer 2 parsing and generating works
"""
import unittest
from ipaddress import IPv6Address

from dhcpkit_vpp.protocols.layer2 import Ethernet
from dhcpkit_vpp.protocols.layer3 import IPv6
from dhcpkit_vpp.protocols.layer4 import UDP
from dhcpkit_vpp.tests.protocols import FrameTestCase


class Layer2FrameTestCase(FrameTestCase):
    def setUp(self):
        self.packet_class = Ethernet

        self.packet_fixture = bytes.fromhex(
            '0123456789abcdef0123456786dd'
            '6efbcdef001811fd200109e0000000000000000000032002200109e0000400320212004500320222'
            '123456780018a695') + b'Demo UDP packet!'

        self.message_fixture = Ethernet(
            destination=bytes.fromhex('0123456789ab'),
            source=bytes.fromhex('cdef01234567'),
            ethertype=int('86dd', 16),
            payload=IPv6(
                traffic_class=239,
                flow_label=773615,
                next_header=17,
                hop_limit=253,
                source=IPv6Address('2001:9e0::3:2002'),
                destination=IPv6Address('2001:9e0:4:32:212:45:32:0222'),
                payload=UDP(
                    source_port=4660,
                    destination_port=22136,
                    checksum=42645,
                    payload=b'Demo UDP packet!'
                )
            )
        )
        self.parse_packet()


if __name__ == '__main__':
    unittest.main()
