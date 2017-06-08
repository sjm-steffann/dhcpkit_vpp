"""
Classes and constants for layer 3 protocols
"""
from ipaddress import IPv6Address
from struct import unpack_from, pack

from dhcpkit.protocol_element import ProtocolElement, UnknownProtocolElement

from dhcpkit_vpp.protocols import Layer2Frame, Layer3Packet, Layer4Protocol


class UnknownLayer3Packet(Layer3Packet, UnknownProtocolElement):
    """
    A layer 3 packet of unknown type
    """

    @classmethod
    def determine_class(cls, buffer: bytes, offset: int = 0) -> type:
        """
        Return the appropriate class to parse this element with.

        :param buffer: The buffer to read data from
        :param offset: The offset in the buffer where to start reading
        :return: The best known class for this data
        """
        return UnknownLayer3Packet

    def get_pseudo_header(self, for_payload: Layer4Protocol) -> bytes:
        """
        We don't have a pseudo header

        :param for_payload: Get the pseudo header for the given layer 4 protocol
        :return: The pseudo header
        """
        return b''


class IPv6(Layer3Packet):
    """
    The class for IPv6 packets.
    """

    def __init__(self, traffic_class: int = 0, flow_label: int = 0, next_header: int = 0, hop_limit: int = 0,
                 source: IPv6Address = None, destination: IPv6Address = None, payload: ProtocolElement = None):
        super().__init__()
        self.traffic_class = traffic_class
        self.flow_label = flow_label
        self.next_header = next_header
        self.hop_limit = hop_limit
        self.source = source
        self.destination = destination
        self.payload = payload

    @classmethod
    def determine_class(cls, buffer: bytes, offset: int = 0) -> type:
        """
        Return the appropriate class to parse this element with.

        :param buffer: The buffer to read data from
        :param offset: The offset in the buffer where to start reading
        :return: The best known class for this data
        """
        return IPv6

    def validate(self):
        """
        Validate that the contents of this object conform to protocol specs.
        """
        # Check if the traffic class fits in 8 bits
        if not isinstance(self.traffic_class, int) or not (0 <= self.traffic_class < 2 ** 8):
            raise ValueError("Traffic class must be an unsigned 8 bit integer")

        # Check if the flow label fits in 20 bits
        if not isinstance(self.flow_label, int) or not (0 <= self.flow_label < 2 ** 20):
            raise ValueError("Flow label must be an unsigned 20 bit integer")

        # Check if the next header fits in 8 bits
        if not isinstance(self.next_header, int) or not (0 <= self.next_header < 2 ** 8):
            raise ValueError("Next header type must be an unsigned 8 bit integer")

        # Check if the hop limit fits in 8 bits
        if not isinstance(self.hop_limit, int) or not (0 <= self.hop_limit < 2 ** 8):
            raise ValueError("Hop limit must be an unsigned 8 bit integer")

        # Check if the source and destination are IPv6 addresses
        if not isinstance(self.source, IPv6Address):
            raise ValueError("Source must be an IPv6 address")

        if self.source.is_multicast:
            raise ValueError("Source must be a non-multicast IPv6 address")

        if not isinstance(self.destination, IPv6Address):
            raise ValueError("Destination must be an IPv6 address")

        # Check if the payload is a protocol element
        if not isinstance(self.payload, ProtocolElement):
            raise ValueError("Payload must be a protocol element")

        # Check if all options are allowed
        self.validate_contains([self.payload])
        self.payload.validate()

    def get_pseudo_header(self, l4_payload: Layer4Protocol) -> bytes:
        """
        Return the pseudo header for this protocol

        :param l4_payload: The payload protocol to calculate the pseudo header for
        :return: The pseudo header bytes
        """
        # This should be changed when routing headers are implemented
        final_destination = self.destination.packed

        return self.source.packed + final_destination + pack("!I3xB", l4_payload.length,
                                                             l4_payload.protocol_number)

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

        if max_length < 40:
            raise ValueError("IPv6 packets must be at least 40 bytes long")

        # Check version
        version = buffer[offset] >> 4
        if version != 6:
            raise ValueError("The provided buffer does not contain an IPv6 packet")

        # Extract the traffic class
        self.traffic_class = unpack_from('!H', buffer, offset)[0] >> 4 & 0xff

        # Extract the flow label
        self.flow_label = unpack_from('!I', buffer, offset)[0] & 0x0fffff

        my_offset += 4

        # Extract the payload length
        payload_len, self.next_header, self.hop_limit = unpack_from('!HBB', buffer, offset + my_offset)
        my_offset += 4

        self.source = IPv6Address(buffer[my_offset + offset:my_offset + offset + 16])
        my_offset += 16

        self.destination = IPv6Address(buffer[my_offset + offset:my_offset + offset + 16])
        my_offset += 16

        # Determine the layer 4 type based on the next header value
        from dhcpkit_vpp.protocols.layer4 import UnknownLayer4Protocol
        from dhcpkit_vpp.protocols.layer4_registry import protocol_layer4_registry
        layer4_class = protocol_layer4_registry.get(self.next_header, UnknownLayer4Protocol)

        max_payload_len = max_length - my_offset
        if payload_len > max_payload_len:
            raise ValueError("IPv6 payload is longer than available buffer")

        payload_len, self.payload = layer4_class.parse(buffer, offset=offset + my_offset, length=payload_len)
        my_offset += payload_len

        return my_offset

    def save(self) -> bytearray:
        """
        Save the internal state of this object as a buffer.

        :return: The buffer with the data from this element
        """
        buffer = bytearray([
            6 << 4 | self.traffic_class >> 4,
            (self.traffic_class & 0x0f) << 4 | self.flow_label >> 16,
            (self.flow_label >> 8) & 0xff,
            self.flow_label & 0xff,
        ])

        if isinstance(self.payload, Layer4Protocol):
            payload = self.payload.save(recalculate_checksum_for=self)
        else:
            payload = self.payload.save()

        buffer.extend(pack('!HBB', len(payload), self.next_header, self.hop_limit))
        buffer.extend(self.source.packed)
        buffer.extend(self.destination.packed)
        buffer.extend(payload)

        return buffer


Layer2Frame.add_may_contain(Layer3Packet)
