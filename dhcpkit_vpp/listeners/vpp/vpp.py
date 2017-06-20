"""
UDP implementations of listeners and repliers
"""

import logging
import socket
from ipaddress import IPv6Address
from struct import unpack_from, pack

from dhcpkit.common.server.logging import DEBUG_PACKETS
from dhcpkit.ipv6 import CLIENT_PORT, SERVER_PORT
from dhcpkit.ipv6.extensions.linklayer_id import LinkLayerIdOption
from dhcpkit.ipv6.messages import RelayReplyMessage
from dhcpkit.ipv6.options import InterfaceIdOption
from dhcpkit.ipv6.server.listeners import IncomingPacketBundle, Listener, ListeningSocketError, Replier, \
    increase_message_counter, IncompleteMessage
from typing import Iterable, Tuple

from dhcpkit_vpp.listeners.vpp import UnknownVPPInterface, UnknownVPPAction, UnwantedVPPMessage
from dhcpkit_vpp.listeners.vpp.vpp_interface import VPPInterface
from dhcpkit_vpp.protocols.layer2 import Ethernet
from dhcpkit_vpp.protocols.layer3 import IPv6
from dhcpkit_vpp.protocols.layer4 import UDP

logger = logging.getLogger(__name__)


class VPPListener(Listener):
    """
    A wrapper for a VPP socket that bundles a socket to listen on with a socket to send replies from.

    :type interfaces: Iterable[VPPInterface]
    :type listen_socket: socket.socket
    :type marks: Iterable[str]
    """

    def __init__(self, interfaces: Iterable[VPPInterface], listen_socket: socket.socket, marks: Iterable[str] = None):
        """
        Initialise VPP listener.

        :param interfaces: The interfaces we listen to and their information
        :param listen_socket: The socket we are listening on, may be a unicast or multicast socket
        :param marks: Marks attached to this listener
        """
        self.interfaces = interfaces
        self.listen_socket = listen_socket
        self.marks = list(marks or [])

        # Check that we have Unix Domain sockets
        if self.listen_socket.family != socket.AF_UNIX or self.listen_socket.type != socket.SOCK_DGRAM:
            raise ListeningSocketError("Listen socket has to be Unix domain datagram socket")

    def recv_request(self) -> Tuple[IncomingPacketBundle, Replier]:
        """
        Receive incoming messages

        :return: The incoming packet data and a replier object
        """
        data = self.listen_socket.recv(65536)

        # Check minimum length (8 bytes for the if-index and action, 14 for ethernet, 40 for IPv6, 8 for UDP)
        if len(data) < 70:
            logger.warning("Message from VPP is too short to contain an IPv6 UDP packet")
            raise IncompleteMessage

        # Get the interface-index and action
        if_index, action = unpack_from('ii', data)

        # Make sure this action is known
        if action != 0:
            logger.warning("Message from VPP contains unknown action {}".format(action))
            raise UnknownVPPAction

        # Check if we know this interface
        for possible_interface in self.interfaces:
            if if_index == possible_interface.index:
                interface = possible_interface
                break
        else:
            # VPP punts everything on the DHCPv6 port, so this is not uncommon
            logger.info("Received message from unknown VPP interface {}".format(if_index))
            raise UnknownVPPInterface

        # Parse the raw IPv6 packet
        try:
            frame_len, frame = Ethernet.parse(data, offset=8)
            if not (isinstance(frame, Ethernet)
                    and isinstance(frame.payload, IPv6)
                    and isinstance(frame.payload.payload, UDP)
                    and frame.payload.payload.destination_port == SERVER_PORT):
                raise ValueError
        except ValueError:
            logger.warning("Received message was not an IPv6 UDP DHCPv6 message")
            raise UnwantedVPPMessage

        # Extract basic information
        source_mac = frame.source
        source = frame.payload.source
        source_port = frame.payload.payload.source_port
        destination = frame.payload.destination
        dhcp_message = frame.payload.payload.payload

        # Check permissions
        if frame.payload.destination.is_multicast:
            if not interface.accept_multicast:
                logger.info("Not accepting multicast on {if_name}, ignoring message from {source}".format(
                    if_name=interface.name,
                    source=source
                ))
                raise UnwantedVPPMessage
        else:
            if not interface.accept_unicast:
                logger.info("Not accepting unicast on {if_name}, ignoring message from {source}".format(
                    if_name=interface.name,
                    source=source
                ))
                raise UnwantedVPPMessage

        # Create the message-ID
        message_counter = increase_message_counter()
        message_id = '#{:06X}'.format(message_counter)

        logger.log(DEBUG_PACKETS, "{message_id}: Received message from {client_addr} port {port} on {interface}".format(
            message_id=message_id, client_addr=source, port=source_port, interface=interface.name))

        interface_id_option = InterfaceIdOption(interface_id=interface.name.encode('utf-8'))
        linklayer_id_option = LinkLayerIdOption(link_layer_type=1, link_layer_address=frame.source)

        packet_bundle = IncomingPacketBundle(message_id=message_id,
                                             data=dhcp_message,
                                             source_address=source,
                                             link_address=interface.link_address,
                                             interface_index=interface.index,
                                             received_over_multicast=destination.is_multicast,
                                             received_over_tcp=False,
                                             marks=self.marks,
                                             relay_options=[interface_id_option,
                                                            linklayer_id_option])

        replier = VPPReplier(interface_index=interface.index,
                             interface_mac_address=interface.mac_address,
                             client_mac_address=source_mac,
                             reply_from=interface.reply_from,
                             reply_socket=self.listen_socket)

        return packet_bundle, replier

    def fileno(self) -> int:
        """
        The fileno of the listening socket, so this object can be used by select()

        :return: The file descriptor
        """
        return self.listen_socket.fileno()


class VPPReplier(Replier):
    """
    A class to send replies to the client
    """

    def __init__(self, interface_index: int,
                 interface_mac_address: bytes, client_mac_address: bytes,
                 reply_from: IPv6Address, reply_socket: socket.socket):
        self.interface_index = interface_index
        self.interface_mac_address = interface_mac_address
        self.client_mac_address = client_mac_address
        self.reply_from = reply_from
        self.reply_socket = reply_socket

    def send_reply(self, outgoing_message: RelayReplyMessage) -> bool:
        """
        Send a reply to the client

        :param outgoing_message: The message to send, including a wrapping RelayReplyMessage
        :return: Whether sending was successful
        """
        # Determine network addresses and bytes
        reply = outgoing_message.relayed_message
        port = isinstance(reply, RelayReplyMessage) and SERVER_PORT or CLIENT_PORT
        destination_address = outgoing_message.peer_address
        message_data = reply.save()

        # Try to determine the interface name from the outgoing relay options
        interface_name = 'unknown'
        interface_id_option = outgoing_message.get_option_of_type(InterfaceIdOption)
        if interface_id_option:
            try:
                interface_name = interface_id_option.interface_id.decode(encoding='utf-8', errors='replace')
            except OSError:
                pass

        # Build the outgoing ethernet frame
        frame = Ethernet(destination=self.client_mac_address,
                         source=self.interface_mac_address,
                         ethertype=0x86DD,
                         payload=IPv6(traffic_class=0xc0,
                                      next_header=17,
                                      hop_limit=63,
                                      source=self.reply_from,
                                      destination=destination_address,
                                      payload=UDP(source_port=SERVER_PORT,
                                                  destination_port=port,
                                                  payload=message_data)))
        data = pack('ii', self.interface_index, 0) + frame.save()

        sent_length = self.reply_socket.send(data)
        success = len(data) == sent_length

        if success:
            logger.log(DEBUG_PACKETS, "Sent {message_type} to {client_addr} port {port} on {interface}".format(
                message_type=outgoing_message.inner_message.__class__.__name__,
                client_addr=destination_address,
                port=port,
                interface=interface_name))
        else:
            logger.error("Could not send {message_type} to {client_addr} port {port} on {interface}".format(
                message_type=outgoing_message.inner_message.__class__.__name__,
                client_addr=destination_address,
                port=port,
                interface=interface_name))

        return success
