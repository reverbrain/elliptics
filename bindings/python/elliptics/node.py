from elliptics.core import Node
from socket import AF_INET
from elliptics.route import Address

class Node(Node):
    def add_remote(self, address, port=None, family=AF_INET):
        if type(address) is Address:
            super(Node, self).add_remote(addr=address.host, port=address.port, family=address.family)
        elif not port and type(address) is str:
            super(Node, self).add_remote(addr=address)
        elif port and type(address) is str:
            super(Node, self).add_remote(addr=address, port=port, family=family)