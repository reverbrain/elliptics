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


from conftest import set_property, simple_node, raises, make_session
from server import server
import elliptics


class TestSession:
    def test_monitor_stat(self, server, simple_node):
        session = make_session(node=simple_node,
                               test_name='TestSession.test_monitor_stat')
        for addr in session.routes.addresses():
            stat = session.monitor_stat(addr).get()[0]
            assert stat.error.code == 0
            assert stat.error.message == ''
            assert type(stat.statistics) == dict
