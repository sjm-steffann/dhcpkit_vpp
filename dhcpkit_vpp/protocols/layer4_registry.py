"""
The protocol layer 4 registry
"""
from dhcpkit.registry import Registry


class ProtocolLayer4Registry(Registry):
    """
    Registry for Protocols
    """
    entry_point = 'dhcpkit_vpp.protocols.layer4'


# Instantiate the protocol registry
protocol_layer4_registry = ProtocolLayer4Registry()
