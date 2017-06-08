"""
Classes and constants for protocol implementations
"""

from dhcpkit.protocol_element import ProtocolElement


class Layer4Protocol(ProtocolElement):
    """
    Base class for layer 4 protocols
    """
    protocol_number = 0

    @property
    def length(self):
        """
        Return the length of this protocol+payload

        :return: The length
        """
        raise NotImplementedError("Length not implemented for {}".format(self.__class__.__name__))

    def save(self, zero_checksum: bool = False, recalculate_checksum_for: 'Layer3Packet' = None) -> bytearray:
        """
        Save the internal state of this object as a buffer.

        :param zero_checksum: Save with zeroes where the checksum should be
        :param recalculate_checksum_for: Recalculate the checksum for the given layer 3 packet headers
        :return: The buffer with the data from this element
        """
        raise NotImplementedError("Save not implemented for {}".format(self.__class__.__name__))


class Layer3Packet(ProtocolElement):
    """
    Base class for layer 3 packets
    """

    def get_pseudo_header(self, for_payload: Layer4Protocol) -> bytes:
        """
        Return the pseudo header for this protocol

        :param for_payload: Get the pseudo header for the given layer 4 protocol
        :return: The pseudo header bytes
        """
        raise NotImplementedError("Pseudo header not implemented for {}".format(self.__class__.__name__))


class Layer2Frame(ProtocolElement):
    """
    Base class for layer 2 frames
    """
