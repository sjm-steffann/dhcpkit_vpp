"""
Classes and constants for layer 4 protocols
"""
from struct import unpack_from, pack

from dhcpkit.protocol_element import ProtocolElement, UnknownProtocolElement
from dhcpkit_vpp.protocols.layer3 import Layer3Packet


class Layer4Protocol(ProtocolElement):
    """
    Base class for layer 4 protocols
    """


class UDP(Layer4Protocol):
    """
    The class for UDP packets.
    """

    def __init__(self, source_port: int = 0, destination_port: int = 0, checksum: int = 0,
                 payload: ProtocolElement = None):
        super().__init__()
        self.source_port = source_port
        self.destination_port = destination_port
        self.checksum = checksum
        self.payload = payload

    @classmethod
    def determine_class(cls, buffer: bytes, offset: int = 0) -> type:
        """
        Return the appropriate class to parse this element with.

        :param buffer: The buffer to read data from
        :param offset: The offset in the buffer where to start reading
        :return: The best known class for this data
        """
        return UDP

    def validate(self):
        """
        Validate that the contents of this object conform to protocol specs.
        """
        # Check if the ports fit in 16 bits
        if not isinstance(self.source_port, int) or not (0 <= self.source_port < 2 ** 16):
            raise ValueError("Source port must be an unsigned 16 bit integer")

        if not isinstance(self.destination_port, int) or not (0 <= self.destination_port < 2 ** 16):
            raise ValueError("Destination port must be an unsigned 16 bit integer")

        # Check if the checksum fits in 16 bits
        if not isinstance(self.checksum, int) or not (0 <= self.checksum < 2 ** 16):
            raise ValueError("Checksum must be an unsigned 16 bit integer")

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

        if max_length < 8:
            raise ValueError("UDP packets must be at least 8 bytes long")

        # Extract the fields
        self.source_port, self.destination_port, payload_len, self.checksum = unpack_from('!HHHH', buffer, offset)
        my_offset += 8

        # Determine the layer 5 type based on the destination port value
        from dhcpkit_vpp.protocols.layer5_registry import protocol_layer5_registry
        layer5_class = protocol_layer5_registry.get(self.destination_port, UnknownProtocolElement)

        max_payload_len = max_length - my_offset
        if payload_len - 8 > max_payload_len:
            raise ValueError("UDP payload is longer than available buffer")

        payload_len, self.payload = layer5_class.parse(buffer, offset=offset + my_offset, length=max_payload_len)
        my_offset += payload_len

        return my_offset

    def save(self) -> bytearray:
        """
        Save the internal state of this object as a buffer.

        :return: The buffer with the data from this element
        """
        payload = self.payload.save()

        buffer = bytearray()
        buffer.extend(pack('!HHHH', self.source_port, self.destination_port, len(payload) + 8, self.checksum))
        buffer.extend(payload)

        return buffer


Layer3Packet.add_may_contain(Layer4Protocol)
