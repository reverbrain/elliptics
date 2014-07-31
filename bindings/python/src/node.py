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
    def __init__(self, logger, config=None):
        '''Initializes node by the logger and custom configuration\n
        node = elliptics.Node(logger, config)"))
        node = elliptics.Node(logger)
        '''
        if config:
            super(Node, self).__init__(logger, config)
        else:
            super(Node, self).__init__(logger)
        self._logger = logger
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
