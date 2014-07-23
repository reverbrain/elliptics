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
    def add_remote(self, address):
        """
           Adds connection to Elliptics node
           @address -- elliptics.Address of server node

           node.add_remote(Address.from_host_port("host.com:1025"))
        """
        super(Node, self).add_remote(host=address.host,
                                     port=address.port,
                                     family=address.family)
