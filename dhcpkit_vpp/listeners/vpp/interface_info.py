from ipaddress import IPv6Address


class VPPInterfaceInfo:
    """
    A simple container to keep information about VPP interfaces in
    """

    def __init__(self, name: str, index: int, accept_unicast: bool, accept_multicast: bool, reply_from: IPv6Address,
                 link_address: IPv6Address):
        self.name = name
        self.index = index
        self.accept_unicast = accept_unicast
        self.accept_multicast = accept_multicast
        self.reply_from = reply_from
        self.link_address = link_address

    def __repr__(self):
        return str(self.__dict__)
