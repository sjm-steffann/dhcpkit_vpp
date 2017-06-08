import unittest

from dhcpkit_vpp.protocols import Layer4Protocol, Layer3Packet
from dhcpkit_vpp.protocols.layer4 import UnknownLayer4Protocol


class Layer3PacketTestCase(unittest.TestCase):
    def test_abstract_get_pseudo_header(self):
        obj = Layer3Packet()
        l4_obj = UnknownLayer4Protocol()

        with self.assertRaises(NotImplementedError):
            obj.get_pseudo_header(l4_obj)


class Layer4ProtocolTestCase(unittest.TestCase):
    def test_abstract_length(self):
        obj = Layer4Protocol()
        with self.assertRaises(NotImplementedError):
            self.assertIsNone(obj.length)

    def test_abstract_save(self):
        obj = Layer4Protocol()
        with self.assertRaises(NotImplementedError):
            obj.save()
