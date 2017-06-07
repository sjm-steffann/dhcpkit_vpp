.. _listen-vpp:

Listen-vpp
==========

This listener sets up a two-way connection to a VPP instance using Unix domain sockets. It will learn the
server created by the VPP instance using the VPP Python API. The name of the socket endpoint it creates for
itself (so VPP can send messages to DHCPKit) is specified as the name of the section.

With this listener DHCPKit can become a DHCPv6 server for VPP. You must list all VPP interfaces that DHCPKit
should respond to.

VPP must be configured to create a punt socket::

    punt {
        socket /run/vpp/punt_socket
    }

This socket is used to send messages from DHCPKit back to VPP. You don't need to specify this socket in the
DHCPKit configuration, it will learn it through the VPP API.


Example
-------

.. code-block:: dhcpkitconf

    <listen-vpp /run/vpp/client_socket>
        namespace-prefix foo

        <vpp-interface tap-0 />

        <vpp-interface GigabitEthernet0/1/2>
            reply-from fe80::1
            link-address 2001:db8::1
        </vpp-interface>
    </listen-vpp>

.. _listen-vpp_parameters:

Section parameters
------------------

mark (multiple allowed)
    Every incoming request can be marked with different tags. That way you can handle messages differently
    based on i.e. which listener they came in on. Every listener can set one or more marks. Also see the
    :ref:`marked-with` filter.

    **Default**: "unmarked"

namespace-prefix
    Namespace prefix for the API. When specifying a prefix in the VPP startup configuration::

        api-segment {
            prefix foo
        }

    then specify `foo` here.

    **Example**: "namespace-prefix foo"

api-definitions
    Path to the JSON files that define the API. If left empty the default path for your system will be
    used.

    **Example**: "api-definitions /usr/share/vpp/api"

Possible sub-section types
--------------------------

:ref:`Vpp-interface <vpp-interface>` (required, multiple allowed)
    VPP Interface to listen on

