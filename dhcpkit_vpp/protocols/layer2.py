"""
Classes and constants for layer 2 frames
"""
import codecs
from struct import pack, unpack_from

from dhcpkit.protocol_element import ProtocolElement, UnknownProtocolElement, ElementDataRepresentation
from dhcpkit.utils import normalise_hex

from dhcpkit_vpp.protocols import Layer2Frame


class Ethernet(Layer2Frame):
    """
    The class for ethernet frames.
    """

    def __init__(self, destination: bytes = b'\x00\x00\x00\x00\x00\x00', source: bytes = b'\x00\x00\x00\x00\x00\x00',
                 ethertype: int = 0, payload: ProtocolElement = None):
        super().__init__()
        self.destination = destination
        self.source = source
        self.ethertype = ethertype
        self.payload = payload

    @classmethod
    def determine_class(cls, buffer: bytes, offset: int = 0) -> type:
        """
        Return the appropriate class to parse this element with.

        :param buffer: The buffer to read data from
        :param offset: The offset in the buffer where to start reading
        :return: The best known class for this data
        """
        return Ethernet

    def display_source(self) -> ElementDataRepresentation:
        """
        Nicer representation of source
        :return: Representation of source
        """
        return ElementDataRepresentation(normalise_hex(codecs.encode(self.source, 'hex').decode('ascii'),
                                                       include_colons=True))

    def display_destination(self) -> ElementDataRepresentation:
        """
        Nicer representation of destination
        :return: Representation of destination
        """
        return ElementDataRepresentation(normalise_hex(codecs.encode(self.destination, 'hex').decode('ascii'),
                                                       include_colons=True))

    def display_ethertype(self) -> ElementDataRepresentation:
        """
        Nicer representation of ethertype
        :return: Representation of ethertype
        """
        return ElementDataRepresentation("{:x} ({})".format(self.ethertype, self.ethertype))

    def validate(self):
        """
        Validate that the contents of this object conform to protocol specs.
        """
        # Check if the source and destination are 6 bytes
        if not isinstance(self.source, bytes) or len(self.source) != 6:
            raise ValueError("Source must be a sequence of 6 bytes")

        if not isinstance(self.destination, bytes) or len(self.destination) != 6:
            raise ValueError("Destination must be a sequence of 6 bytes")

        # Check if the ethertype is two bytes
        if not isinstance(self.ethertype, int) or not (0 <= self.ethertype < 2 ** 16):
            raise ValueError("Ethertype must be an unsigned 16 bit integer")

        # Check if the payload is a protocol element
        if not isinstance(self.payload, ProtocolElement):
            raise ValueError("Payload must be a protocol element")

        # Check if all options are allowed
        self.validate_contains([self.payload])
        self.payload.validate()

    def load_from(self, buffer: bytes, offset: int = 0, length: int = None) -> int:
        """
        Load the internal state of this object from the given buffer. The buffer may contain more data after the
        structured element is parsed. This data is ignored.

        :param buffer: The buffer to read data from
        :param offset: The offset in the buffer where to start reading
        :param length: The amount of data we are allowed to read from the buffer
        :return: The number of bytes used from the buffer
        """
        my_offset = 0
        max_length = length or (len(buffer) - offset)

        if max_length < 14:
            raise ValueError("Ethernet frames must be at least 14 bytes long")

        self.destination = buffer[offset + my_offset:offset + my_offset + 6]
        my_offset += 6

        self.source = buffer[offset + my_offset:offset + my_offset + 6]
        my_offset += 6

        self.ethertype = unpack_from('!H', buffer[offset + my_offset:offset + my_offset + 2])[0]
        my_offset += 2

        # Determine the layer 3 type based on the ethertype
        from dhcpkit_vpp.protocols.layer3 import UnknownLayer3Packet
        from dhcpkit_vpp.protocols.layer3_registry import protocol_layer3_registry
        layer3_class = protocol_layer3_registry.get(self.ethertype, UnknownLayer3Packet)

        max_payload_len = max_length - my_offset
        payload_len, self.payload = layer3_class.parse(buffer, offset=offset + my_offset, length=max_payload_len)
        my_offset += payload_len

        return my_offset

    def save(self) -> bytes:
        """
        Save the internal state of this object as a buffer.

        :return: The buffer with the data from this element
        """
        return self.destination + self.source + pack('!H', self.ethertype) + self.payload.save()


Layer2Frame.add_may_contain(UnknownProtocolElement)
