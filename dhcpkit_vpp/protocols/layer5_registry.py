"""
The protocol layer 5 registry
"""
from dhcpkit.registry import Registry


class ProtocolLayer5Registry(Registry):
    """
    Registry for Protocols
    """
    entry_point = 'dhcpkit_vpp.protocols.layer5'


# Instantiate the protocol registry
protocol_layer5_registry = ProtocolLayer5Registry()
