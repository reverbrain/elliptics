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
from socket import AF_UNSPEC
from elliptics.route import Address
from elliptics.log import logged_class


@logged_class
class Node(Node):
    """
    Node represents a connection with Elliptics.
    """
    def add_remote(self, remotes, port=None, family=AF_UNSPEC):
        '''
            Adds connections to Elliptics node
            @remotes -- elliptics.Address's of server node

            node.add_remote("host.com:1025:2")
            node.add_remote("host.com", 1025, 2)
            node.add_remote("host.com", 1025)
            node.add_remote(Address.from_host_port("host.com:1025"))

            node.add_remote([
                Address.from_host_port("host.com:1025"),
                Address.from_host_port_family("host.com:1026:2"),
                "host.com:1027:2"
                ])
        '''

        if port is not None:
            remotes = Address(remotes, port, family)

        if type(remotes) in [str, Address]:
            super(Node, self).add_remote((str(remotes), ))
        elif hasattr(remotes, '__iter__'):
            super(Node, self).add_remote(map(str, remotes))
        else:
            raise ValueError("Couldn't convert {0} to [elliptics.Address]".format(repr(remotes)))
