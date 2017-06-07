.. _vpp-interface:

Vpp-interface
=============

VPP Interface to listen on


Example
-------

.. code-block:: dhcpkitconf

    <vpp-interface GigabitEthernet0/1/2>
        reply-from fe80::1
        link-address 2001:db8::1
    </vpp-interface>

.. _vpp-interface_parameters:

Section parameters
------------------

accept-multicast
    Whether to process multicast messages received on this interface

    **Default**: "yes"

accept-unicast
    Whether to process unicast messages received on this interface

    **Default**: "yes"

reply-from
    The link-local address to send on-link replies from

    **Default**: The first link-local address found on the interface

link-address
    A global unicast address used to identify the link to filters and handlers.
    It doesn't even need to exist.

    **Default**: The first global unicast address found on the interface, or ``::`` otherwise

