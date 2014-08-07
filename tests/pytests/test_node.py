#!/usr/bin/env python

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

import sys
sys.path.insert(0, "")  # for running from cmake
import pytest
import elliptics
from server import server

class TestNode:
    def test_add_remotes_by_one(self, server):
        elog = elliptics.Logger('client.log', 4)
        node = elliptics.Node(elog)
        remotes = server.remotes
        node.add_remote(remotes[0])
        node.add_remote(elliptics.Address.from_host_port_family(remotes[1]))
        host, port, family = remotes[2].split(':')
        node.add_remote(host, int(port), int(family))

    def test_add_several_remotes(self, server):
        elog = elliptics.Logger('client.log', 4)
        node = elliptics.Node(elog)
        remotes = []
        for num, remote in enumerate(server.remotes):
            if num % 2 == 0:
                remotes.append(remote)
            else:
                remotes.append(elliptics.Address.from_host_port_family(remote))
        node.add_remote(remotes)
