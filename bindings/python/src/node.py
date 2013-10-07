from elliptics.core import Node
from socket import AF_INET
from elliptics.route import Address


class Node(Node):
    def add_remote(self, addr, port=None, family=AF_INET):
        if type(addr) is Address:
            super(Node, self).add_remote(addr=addr.host,
                                         port=addr.port,
                                         family=addr.family)
        elif not port and type(addr) is str:
            super(Node, self).add_remote(addr=addr)
        elif port and type(addr) is str:
            super(Node, self).add_remote(addr=addr,
                                         port=port,
                                         family=family)
