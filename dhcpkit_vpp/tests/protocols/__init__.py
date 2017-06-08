import unittest

from dhcpkit.protocol_element import UnknownProtocolElement


class FrameTestCase(unittest.TestCase):
    def setUp(self):
        self.packet_class = UnknownProtocolElement
        self.packet_fixture = b'Some data'
        self.message_fixture = UnknownProtocolElement(
            data=b'Some data'
        )

        self.parse_packet()

    def parse_packet(self):
        self.length, self.message = self.packet_class.parse(self.packet_fixture)
        self.assertIsInstance(self.message, self.packet_class)
        self.message_class = type(self.message)

    def test_length(self):
        self.assertEqual(self.length, len(self.packet_fixture))

    def test_class(self):
        self.assertEqual(self.message_class, self.packet_class)

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
