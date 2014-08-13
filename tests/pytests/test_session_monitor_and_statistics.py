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


from conftest import set_property, simple_node, raises
from server import server
import elliptics


class TestSession:
    def test_stat_log_count(self, server, simple_node):
        session = elliptics.Session(simple_node)
        stat_count = session.stat_log_count().get()
        assert len(stat_count) == len(session.routes.addresses_with_backends())
        for stat in stat_count:
            assert stat.error.code == 0
            assert stat.error.message == ''
            assert stat.group_id in session.routes.get_address_groups(stat.address)

    def test_stat_log(self, server, simple_node):
        session = elliptics.Session(simple_node)
        for addr in session.routes.addresses():
            addr_id = session.routes.get_address_unique_routes(addr)[0].id
            stat = session.stat_log(addr_id).get()[0]
            assert stat.error.code == 0
            assert stat.error.message == ''
            assert stat.group_id in session.routes.get_address_groups(stat.address)

    def test_monitor_stat(self, server, simple_node):
        session = elliptics.Session(simple_node)
        for addr in session.routes.addresses():
            stat = session.monitor_stat(addr).get()[0]
            assert stat.error.code == 0
            assert stat.error.message == ''
            assert type(stat.statistics) == dict
