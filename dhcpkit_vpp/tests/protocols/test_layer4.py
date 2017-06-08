"""
Test whether layer 4 parsing and generating works
"""
import unittest
from ipaddress import IPv6Address

from dhcpkit_vpp.protocols.layer3 import IPv6
from dhcpkit_vpp.protocols.layer4 import UDP, UnknownLayer4Protocol
from dhcpkit_vpp.tests.protocols import FrameTestCase


class UnknownLayer4ProtocolTestCase(FrameTestCase):
    def setUp(self):
        self.packet_class = UnknownLayer4Protocol
        self.packet_fixture = b'Demo packet'
        self.message_fixture = UnknownLayer4Protocol(
            data=b'Demo packet'
        )

        self.parse_packet()

    def test_length(self):
        self.assertEqual(self.message_fixture.length, len(self.packet_fixture))
        self.assertEqual(self.message.length, len(self.packet_fixture))
        self.assertEqual(self.message.length, len(self.packet_fixture))
        self.assertEqual(self.length, len(self.packet_fixture))


class UDPTestCase(FrameTestCase):
    def setUp(self):
        self.packet_class = UDP

        # Intentionally using odd number of bytes to test padding
        self.packet_fixture = bytes.fromhex('123456780017a6b8') + b'Demo UDP packet'
        self.message_fixture = UDP(
            source_port=4660,
            destination_port=22136,
            checksum=42680,
            payload=b'Demo UDP packet'
        )

        self.parse_packet()

    def test_checksum_calculation(self):
        dummy_ipv6 = IPv6(
            source=IPv6Address('2001:9e0::3:2002'),
            destination=IPv6Address('2001:9e0:4:32:212:45:32:0222'),
        )
        self.assertEqual(self.message_fixture.checksum, self.message.calculate_checksum(dummy_ipv6))

    def test_validate_source_port(self):
        self.check_unsigned_integer_property('source_port', 16)

    def test_validate_destination_port(self):
        self.check_unsigned_integer_property('destination_port', 16)

    def test_validate_checksum(self):
        self.check_unsigned_integer_property('checksum', 16)

    def test_validate_payload(self):
        setattr(self.message, 'payload', 0.1)
        with self.assertRaisesRegex(ValueError, 'bytes'):
            self.message.validate()

        setattr(self.message, 'payload', 0)
        with self.assertRaisesRegex(ValueError, 'bytes'):
            self.message.validate()

        setattr(self.message, 'payload', 'Not bytes')
        with self.assertRaisesRegex(ValueError, 'bytes'):
            self.message.validate()

        setattr(self.message, 'payload', b'Bytes!')
        self.message.validate()

    def test_udp_length(self):
        with self.assertRaisesRegex(ValueError, '8 bytes'):
            UDP.parse(bytes.fromhex('00010002000700'))

        with self.assertRaisesRegex(ValueError, '8 bytes'):
            UDP.parse(bytes.fromhex('0001000200070000'))

        UDP.parse(bytes.fromhex('0001000200080000'))

        with self.assertRaisesRegex(ValueError, 'longer than available buffer'):
            UDP.parse(bytes.fromhex('0001000200090000'))

    def test_save_zero_checksum(self):
        saved = self.message_fixture.save(zero_checksum=True)
        fixture = bytes.fromhex('1234567800170000') + b'Demo UDP packet'
        self.assertEqual(saved, fixture)

    def test_save_with_checksum_calculation(self):
        dummy_ipv6 = IPv6(
            source=IPv6Address('2001:9e0::3:2002'),
            destination=IPv6Address('2001:9e0:4:32:212:45:32:0222'),
        )
        self.message.checksum = -1
        saved = self.message.save(recalculate_checksum_for=dummy_ipv6)
        self.assertEqual(saved, self.packet_fixture)


if __name__ == '__main__':
    unittest.main()
