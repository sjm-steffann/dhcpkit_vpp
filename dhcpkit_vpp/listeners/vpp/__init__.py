"""
Factory for the implementation of a listener on a VPP punt socket
"""
from dhcpkit.ipv6.server.listeners import IgnoreMessage


class UnwantedVPPMessage(IgnoreMessage):
    """
    This is a message that we don't want
    """


class UnknownVPPInterface(UnwantedVPPMessage):
    """
    Signal that this message is incomplete because it came from an unknown VPP interface.
    """


class UnknownVPPAction(UnwantedVPPMessage):
    """
    Signal that this message is incomplete because it contained an unknown VPP action value.
    """
