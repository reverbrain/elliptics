# =============================================================================
# 2013+ Copyright (c) Kirill Smorodinnikov <shaitkir@gmail.com>
# All rights reserved.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# =============================================================================

from elliptics.core import Node
from socket import AF_INET
from elliptics.route import Address
from elliptics.log import logged_class


@logged_class
class Node(Node):
    """
    Node represents a connection with Elliptics.
    """
    def add_remote(self, addr, port=None, family=AF_INET):
        """
           Adds connection to Elliptics node
           Keyword arguments:
           addr -- can be an Address instance or
                   string 'host' or 'host:port' or 'host:port:family'
           port -- destination port (default None, thus should be specified in addr)
           family -- network family (default AF_INET)\n
           node.add_remote(addr="host.com", port=1025, family=2)
           node.add_remote(addr="host.com:1025")
           node.add_remote(addr="host.com:1025:2")
           node.add_remote(Address.from_host_port("host.com:1025"))
        """
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
