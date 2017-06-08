"""
Test whether layer 2 parsing and generating works
"""
import unittest
from ipaddress import IPv6Address

from dhcpkit_vpp.protocols.layer2 import Ethernet
from dhcpkit_vpp.protocols.layer3 import IPv6
from dhcpkit_vpp.protocols.layer4 import UDP


class Layer2FrameTestCase(unittest.TestCase):
    def setUp(self):
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

    def parse_packet(self):
        self.length, self.message = Ethernet.parse(self.packet_fixture)
        self.assertIsInstance(self.message, Ethernet)
        self.message_class = type(self.message)

    def test_length(self):
        self.assertEqual(self.length, len(self.packet_fixture))

    def test_parse(self):
        self.assertEqual(self.message, self.message_fixture)

    def test_save_parsed(self):
        self.assertEqual(self.packet_fixture, self.message.save())

    def test_save_fixture(self):
        self.assertEqual(self.packet_fixture, self.message_fixture.save())

    def test_validate(self):
        # This should be ok
        self.message.validate()

    def check_unsigned_integer_property(self, property_name: str, size: int = None):
        """
        Perform basic verification of validation of an unsigned integer

        :param property_name: The property under test
        :param size: The number of bits of this integer field
        """
        # Do the basic integer checks
        setattr(self.message, property_name, 0.1)
        with self.assertRaisesRegex(ValueError, 'integer'):
            self.message.validate()

        setattr(self.message, property_name, 0)
        self.message.validate()

        setattr(self.message, property_name, -1)
        with self.assertRaisesRegex(ValueError, 'unsigned .* integer'):
            self.message.validate()

        if not size:
            # We can't do any further tests without knowing the size
            return

        setattr(self.message, property_name, 2 ** size - 1)
        self.message.validate()

        setattr(self.message, property_name, 2 ** size)
        with self.assertRaisesRegex(ValueError, 'unsigned {} bit integer'.format(size)):
            self.message.validate()


if __name__ == '__main__':
    unittest.main()
