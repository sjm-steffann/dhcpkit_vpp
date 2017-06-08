"""
Test whether layer 3 parsing and generating works
"""
import unittest
from ipaddress import IPv6Address

from dhcpkit.protocol_element import UnknownProtocolElement

from dhcpkit_vpp.protocols.layer3 import IPv6, UnknownLayer3Packet
from dhcpkit_vpp.protocols.layer4 import UDP, UnknownLayer4Protocol
from dhcpkit_vpp.tests.protocols import FrameTestCase


class UnknownLayer3PacketTestCase(FrameTestCase):
    def setUp(self):
        self.packet_class = UnknownLayer3Packet
        self.packet_fixture = b'Demo packet'
        self.message_fixture = UnknownLayer3Packet(
            data=b'Demo packet'
        )

        self.parse_packet()

    def test_pseudo_header(self):
        dummy_payload = UnknownLayer4Protocol(b'')
        self.assertEqual(self.message_fixture.get_pseudo_header(dummy_payload), b'')
        self.assertEqual(self.message.get_pseudo_header(dummy_payload), b'')


class IPv6TestCase(FrameTestCase):
    def setUp(self):
        self.packet_class = IPv6

        self.packet_fixture = bytes.fromhex(
            '6efbcdef001811fd200109e0000000000000000000032002200109e0000400320212004500320222'
            '123456780018a695') + b'Demo UDP packet!'

        self.message_fixture = IPv6(
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

        self.parse_packet()

    def test_validate_traffic_class(self):
        self.check_unsigned_integer_property('traffic_class', 8)

    def test_validate_flow_label(self):
        self.check_unsigned_integer_property('flow_label', 20)

    def test_validate_next_header(self):
        self.check_unsigned_integer_property('next_header', 8)

    def test_validate_hop_limit(self):
        self.check_unsigned_integer_property('hop_limit', 8)

    def test_validate_source(self):
        self.message.source = bytes.fromhex('20010db8000000000000000000000001')
        with self.assertRaisesRegex(ValueError, 'Source .* IPv6 address'):
            self.message.validate()

        self.message.source = IPv6Address('ff02::1')
        with self.assertRaisesRegex(ValueError, 'Source .* non-multicast IPv6 address'):
            self.message.validate()

    def test_validate_destination(self):
        self.message.destination = bytes.fromhex('20010db8000000000000000000000001')
        with self.assertRaisesRegex(ValueError, 'Destination .* IPv6 address'):
            self.message.validate()

    def test_validate_payload(self):
        self.message.payload = b'Bad bad bad'
        with self.assertRaisesRegex(ValueError, 'Payload .* protocol element'):
            self.message.validate()

    def test_protocol_version(self):
        with self.assertRaisesRegex(ValueError, 'does not contain an IPv6 packet'):
            IPv6.parse(bytes.fromhex('5000000000000000000000000000000000000000'
                                     '0000000000000000000000000000000000000000'))

        IPv6.parse(bytes.fromhex('6000000000000000000000000000000000000000'
                                 '0000000000000000000000000000000000000000'))

    def test_ipv6_length(self):
        with self.assertRaisesRegex(ValueError, '40 bytes'):
            IPv6.parse(bytes.fromhex('6000000000000000000000000000000000000000'
                                     '00000000000000000000000000000000000000'))

        IPv6.parse(bytes.fromhex('6000000000000000000000000000000000000000'
                                 '0000000000000000000000000000000000000000'))

        with self.assertRaisesRegex(ValueError, 'longer than available buffer'):
            IPv6.parse(bytes.fromhex('6000000000010000000000000000000000000000'
                                     '0000000000000000000000000000000000000000'))

        IPv6.parse(bytes.fromhex('6000000000010000000000000000000000000000'
                                 '0000000000000000000000000000000000000000'
                                 '01'))

    def test_trailing_data(self):
        packet = bytes.fromhex('6000000000040000000000000000000000000000'
                               '0000000000000000000000000000000000000000'
                               '3132333435')
        parsed_len, parsed_message = IPv6.parse(packet)
        self.assertEqual(parsed_len, len(packet) - 1)

    def test_l4_payload_type(self):
        message = IPv6(
            traffic_class=0,
            flow_label=0,
            next_header=0,
            hop_limit=0,
            source=IPv6Address('::'),
            destination=IPv6Address('::'),
            payload=UnknownLayer4Protocol(b'1234')
        )
        packet = bytes.fromhex('6000000000040000000000000000000000000000'
                               '0000000000000000000000000000000000000000'
                               '31323334')
        parsed_len, parsed_message = IPv6.parse(packet)
        self.assertEqual(parsed_len, len(packet))
        self.assertEqual(parsed_message, message)
        self.assertEqual(message.save(), packet)

    def test_unknown_payload_type(self):
        message = IPv6(
            traffic_class=0,
            flow_label=0,
            next_header=0,
            hop_limit=0,
            source=IPv6Address('::'),
            destination=IPv6Address('::'),
            payload=UnknownProtocolElement(b'1234')
        )
        packet = bytes.fromhex('6000000000040000000000000000000000000000'
                               '0000000000000000000000000000000000000000'
                               '31323334')
        self.assertEqual(message.save(), packet)


if __name__ == '__main__':
    unittest.main()
