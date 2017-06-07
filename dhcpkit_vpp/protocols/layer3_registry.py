"""
The protocol layer 3 registry
"""
from dhcpkit.registry import Registry


class ProtocolLayer3Registry(Registry):
    """
    Registry for Protocols
    """
    entry_point = 'dhcpkit_vpp.protocols.layer3'


# Instantiate the protocol registry
protocol_layer3_registry = ProtocolLayer3Registry()
