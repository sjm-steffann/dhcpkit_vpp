"""
Factory for the implementation of a listener on a unicast address of a local network interface
"""
import fnmatch
import logging
import os
import socket
import stat
from ipaddress import IPv6Address
from os.path import realpath

from ZConfig.matcher import SectionValue
from dhcpkit.common.server.config_elements import ConfigElementFactory
from dhcpkit.ipv6 import SERVER_PORT, All_DHCP_Relay_Agents_and_Servers
from dhcpkit.ipv6.server.listeners import Listener, ListeningSocketError
from dhcpkit.ipv6.server.listeners.factories import ListenerFactory
from dhcpkit.ipv6.utils import is_global_unicast
from typing import Iterable, Optional, List

from dhcpkit_vpp.listeners.vpp.vpp import VPPListener
from dhcpkit_vpp.listeners.vpp.vpp_interface import VPPInterface
from dhcpkit_vpp.vpp_papi import VPP

logger = logging.getLogger(__name__)


class VPPInterfaceSection(ConfigElementFactory):
    """
    Configuration section representing a VPP interface
    """

    # noinspection PyTypeChecker
    name_datatype = staticmethod(str)

    def validate_config_section(self):
        """
        Check whether the provided information makes sense
        """
        # Validate what the user supplied
        if self.section.reply_from and not self.section.reply_from.is_link_local:
            raise ValueError("The reply-from address must be a link-local address")

        if self.section.link_address and not is_global_unicast(self.section.link_address):
            raise ValueError("The link-address must be a global unicast address")


class VPPListenerFactory(ListenerFactory):
    """
    Factory for the implementation of a listener on a Unix domain socket to VPP
    """

    name_datatype = staticmethod(realpath)

    sock_type = socket.SOCK_DGRAM

    def __init__(self, section: SectionValue):
        self.vpp = None  # type: VPP
        self.found_interfaces = []  # type: List[VPPInterface]

        super().__init__(section)

    def __del__(self):
        """
        Clean up VPP connection
        """
        if not self.vpp or not self.vpp.connected:
            return

        # Set a timeout so we don't hang here
        self.vpp.read_timeout = 10

        logger.debug("Tell VPP we don't want punted packets anymore")
        self.vpp.api.punt_socket(is_add=0,
                                 ipv=6, l4_protocol=socket.IPPROTO_UDP, l4_port=self.listen_port,
                                 pathname=self.name.encode('utf-8'))
        logger.debug("Disconnect from VPP API")
        self.vpp.disconnect()

    def vpp_connect(self) -> VPP:
        """
        Connect to VPP based on this configuration

        :return: A connected VPP instance
        """
        # Don't connect again if we are already connected
        if self.vpp and self.vpp.connected:
            return self.vpp

        json_files = []
        if self.section.api_definitions:
            for root, dir_names, filenames in os.walk(self.section.api_definitions):
                for filename in fnmatch.filter(filenames, '*.api.json'):
                    json_files.append(os.path.join(root, filename))

        try:
            logger.debug("Loading VPP API")
            self.vpp = VPP(json_files)

            if self.section.namespace_prefix:
                logger.info("Connecting to VPP using namespace '{}'".format(self.section.namespace_prefix))
                self.vpp.connect('DHCPKit', chroot_prefix=self.section.namespace_prefix)
            else:
                logger.info("Connecting to VPP")
                self.vpp.connect('DHCPKit')
        except ValueError as e:
            if len(e.args) >= 2:
                raise ValueError("VPP error: {}".format(e.args[1]))
            raise
        except IOError:
            raise ValueError("VPP error: cannot connect")

        return self.vpp

    @staticmethod
    def find_reply_from(reply_from: Optional[IPv6Address], interface_name: str,
                        interface_addresses: Iterable[IPv6Address]) -> IPv6Address:
        """
        Find the appropriate reply-from address
        
        :param reply_from: The reply-from address specified in the configuration, if any
        :param interface_name: The name of the interface for logging purposes
        :param interface_addresses: The list of addresses on the interface
        :return: The reply-from address to use
        """
        if reply_from:
            # Check if this address exists
            if reply_from not in interface_addresses:
                raise ValueError("Reply-from address {addr} does not exist on {intf}".format(
                    addr=reply_from,
                    intf=interface_name
                ))
            return reply_from
        else:
            # Pick the first link-local address
            ll_addresses = [address for address in interface_addresses if address.is_link_local]
            if not ll_addresses:
                raise ValueError("No link-local address found on {intf}".format(
                    intf=interface_name
                ))
            return ll_addresses[0]

    @staticmethod
    def find_link_address(link_address: Optional[IPv6Address],
                          interface_addresses: Iterable[IPv6Address]) -> IPv6Address:
        """
        Find the appropriate reply-from address
        
        :param link_address: The link-address address specified in the configuration, if any
        :param interface_addresses: The list of addresses on the interface
        :return: The reply-from address to use
        """
        if link_address:
            return link_address
        else:
            # Pick the first global address
            global_addresses = [address for address in interface_addresses if is_global_unicast(address)]
            if global_addresses:
                return global_addresses[0]
            else:
                return IPv6Address('::')

    def validate_config_section(self):
        """
        Validate the listener information
        """
        # Make sure that no existing file is in the way
        if os.path.exists(self.name):
            st = os.stat(self.name)
            if not stat.S_ISSOCK(st.st_mode):
                raise ValueError("{} already exists and is not a socket".format(self.name))

        # Connect to VPP to check the interface names
        vpp = self.vpp_connect()
        interfaces = vpp.api.sw_interface_dump()
        if not interfaces:
            raise ValueError("Can't get interfaces from VPP")

        # Look for all the interfaces
        for vpp_interface_section in self.section.vpp_interfaces:
            for interface in interfaces:
                interface_name = interface.interface_name.decode('utf8').rstrip('\x00')

                if interface_name == vpp_interface_section.name:
                    interface_index = interface.sw_if_index
                    interface_mac = interface.l2_address[:interface.l2_address_length]

                    # Get all addresses on this interface
                    raw_addresses = vpp.api.ip_address_dump(sw_if_index=interface_index, is_ipv6=1)
                    addresses = [IPv6Address(details.ip) for details in raw_addresses]
                    addresses.sort()

                    # Find reply-from
                    reply_from = self.find_reply_from(reply_from=vpp_interface_section.reply_from,
                                                      interface_name=interface_name,
                                                      interface_addresses=addresses)

                    # Find link-address
                    link_address = self.find_link_address(link_address=vpp_interface_section.link_address,
                                                          interface_addresses=addresses)

                    vpp_interface = VPPInterface(
                        vpp=vpp,
                        name=interface_name,
                        index=interface_index,
                        mac_address=interface_mac,
                        accept_unicast=vpp_interface_section.accept_unicast,
                        accept_multicast=vpp_interface_section.accept_multicast,
                        reply_from=reply_from,
                        link_address=link_address
                    )

                    logger.debug("Found VPP interface {intf.index}: {intf.name} "
                                 "reply-from={intf.reply_from} "
                                 "link-address={intf.link_address}".format(intf=vpp_interface))

                    self.found_interfaces.append(vpp_interface)
                    break

            else:
                raise ValueError("Can't find VPP interface {}".format(vpp_interface_section.name))

    def create(self, old_listeners: Iterable[Listener] = None) -> VPPListener:
        """
        Create a listener of this class based on the configuration in the config section.

        :param old_listeners: A list of existing listeners in case we can recycle them
        :return: A listener object
        """
        # Let interfaces initialise themselves
        for vpp_interface in self.found_interfaces:
            vpp_interface.activate()

        if any([vpp_interface.accept_multicast for vpp_interface in self.found_interfaces]):
            mroute_result = self.vpp.api.ip_mroute_add_del(next_hop_sw_if_index=0xffffffff,
                                                           grp_address_length=128, is_add=1,
                                                           is_ipv6=1, is_local=1, itf_flags=4,
                                                           grp_address=All_DHCP_Relay_Agents_and_Servers.packed)
            if mroute_result.retval != 0:
                raise ListeningSocketError("Can't make VPP listen to the multicast address")

        # See if there is a listener that has the right socket
        old_listeners = list(old_listeners or [])
        for listener in old_listeners:
            if not isinstance(listener, VPPListener):
                continue

            if listener.listen_socket.getsockname() == self.name:
                # This is the one!
                sock = listener.listen_socket
                break
        else:
            # Make space for our socket
            try:
                os.unlink(self.name)
            except OSError:
                if os.path.exists(self.name):
                    raise ListeningSocketError("Can't unlink {} to make space for Unix domain socket".format(self.name))

            # Set up Unix domain socket for VPP to connect to
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
            sock.bind(self.name)

        # Register DHCP port for punt
        punt_result = self.vpp.api.punt_socket(is_add=1, ipv=6, l4_protocol=17, l4_port=SERVER_PORT,
                                               pathname=self.name.encode('utf-8'))
        if punt_result.retval != 0:
            raise ListeningSocketError("Can't make VPP punt DHCPv6 traffic to DHCPKit")

        # Connect our socket to the VPP instance
        sock.connect(punt_result.pathname)

        return VPPListener(self.found_interfaces, sock, marks=self.marks)
