"""
Test whether layer 2 parsing and generating works
"""
import unittest
from ipaddress import IPv6Address

from dhcpkit.protocol_element import ElementDataRepresentation, UnknownProtocolElement

from dhcpkit_vpp.protocols.layer2 import Ethernet
from dhcpkit_vpp.protocols.layer3 import IPv6, UnknownLayer3Packet
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

    def test_display_source(self):
        display = self.message.display_source()
        self.assertIsInstance(display, ElementDataRepresentation)

    def test_display_destination(self):
        display = self.message.display_destination()
        self.assertIsInstance(display, ElementDataRepresentation)

    def test_display_ethertype(self):
        display = self.message.display_ethertype()
        self.assertIsInstance(display, ElementDataRepresentation)

    def test_validate_source(self):
        self.message.source = b'123456'
        self.message.validate()

        self.message.source = b'12345'
        with self.assertRaisesRegex(ValueError, 'Source .* 6 bytes'):
            self.message.validate()

        self.message.source = '123456'
        with self.assertRaisesRegex(ValueError, 'Source .* 6 bytes'):
            self.message.validate()

        self.message.source = '12345'
        with self.assertRaisesRegex(ValueError, 'Source .* 6 bytes'):
            self.message.validate()

    def test_validate_destination(self):
        self.message.destination = b'123456'
        self.message.validate()

        self.message.destination = b'12345'
        with self.assertRaisesRegex(ValueError, 'Destination .* 6 bytes'):
            self.message.validate()

        self.message.destination = '123456'
        with self.assertRaisesRegex(ValueError, 'Destination .* 6 bytes'):
            self.message.validate()

        self.message.destination = '12345'
        with self.assertRaisesRegex(ValueError, 'Destination .* 6 bytes'):
            self.message.validate()

    def test_validate_ethertype(self):
        self.check_unsigned_integer_property('ethertype', 16)

    def test_validate_payload(self):
        self.message.payload = b'Bad bad bad'
        with self.assertRaisesRegex(ValueError, 'Payload .* protocol element'):
            self.message.validate()

    def test_ethernet_length(self):
        with self.assertRaisesRegex(ValueError, '14 bytes'):
            Ethernet.parse(bytes.fromhex('000000000000'
                                         '000000000000'
                                         '00'))

        Ethernet.parse(bytes.fromhex('000000000000'
                                     '000000000000'
                                     '0000'))

    def test_l3_payload_type(self):
        message = Ethernet(
            payload=UnknownLayer3Packet(b'1234')
        )
        packet = bytes.fromhex('000000000000'
                               '000000000000'
                               '0000'
                               '31323334')
        parsed_len, parsed_message = Ethernet.parse(packet)
        self.assertEqual(parsed_len, len(packet))
        self.assertEqual(parsed_message, message)
        self.assertEqual(message.save(), packet)

    def test_unknown_payload_type(self):
        message = Ethernet(
            payload=UnknownProtocolElement(b'1234')
        )
        packet = bytes.fromhex('000000000000'
                               '000000000000'
                               '0000'
                               '31323334')
        self.assertEqual(message.save(), packet)


if __name__ == '__main__':
    unittest.main()
