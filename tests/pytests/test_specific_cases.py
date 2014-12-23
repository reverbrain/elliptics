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

import pytest
import elliptics
from server import Servers

@pytest.fixture(scope="module")
def servers(request):
    groups = [int(g) for g in request.config.option.groups.split(',')]

    servers = Servers(groups=groups,
                      without_cocaine=True,
                      nodes_count=2,
                      backends_count=1,
                      isolated=True,
                      path='special_servers')

    def fin():
        servers.stop()
    request.addfinalizer(fin)

    return servers

class TestSpecificCases:
    '''
    Test that covers specific bugs
    '''
    def test_2_backends_with_equal_ids_and_group(self, servers):
        '''
        These test case check correct handling situation when some backend from one nodes has the same group and ids
        like another backend from another node.
        For this test all nodes mustn't know about each other, their `remote` are empty.
        In this test creates 2 client nodes and both connects to 2 different nodes.
        At each node selects one backend from one group, equal to both backend.
        Updates ids for both backends to make it be equal.
        To the second client node adds remote to the first node. It raises route-list update error: -EEXIST and raises exception.
        After that makes read some noexistent key from all groups - it will raise an exception.
        With old bug thes test case caused `Segmentation fault` on read_data_from_groups.
        At the end reverts ids of both backends.
        '''
        address1, address2 = servers.remotes

        address1 = elliptics.Address.from_host_port_family(address1)
        session1 = elliptics.Session(elliptics.Node(elliptics.Logger("client.log", elliptics.log_level.debug)))
        session1._node.add_remotes(address1)
        routes = session1.routes.filter_by_address(address1)
        group = routes.groups()[-1]
        groups = routes.groups()
        routes = session1.routes.filter_by_group(group)
        ids = [session1.transform('somekey')]
        backend_id1 = routes.get_address_backends(address1)[0]
        old_ids1 = [r.id for r in routes.filter_by_address(address1).filter_by_backend(backend_id1)]
        session1.set_backend_ids(address1, backend_id1, ids).get()

        address2 = elliptics.Address.from_host_port_family(address2)
        session2 = elliptics.Session(elliptics.Node(elliptics.Logger("client.log", elliptics.log_level.debug)))
        session2._node.add_remotes(address2)
        routes = session2.routes.filter_by_group(group)
        backend_id2 = routes.get_address_backends(address2)[0]
        old_ids2 = [r.id for r in routes.filter_by_address(address2).filter_by_backend(backend_id2)]
        session2.set_backend_ids(address2, backend_id2, ids).get()

        with pytest.raises(elliptics.core.Error):
            session2._node.add_remotes(address1)
        assert session2.routes.addresses() == (address2, )
        for g in groups:
            with pytest.raises(elliptics.core.Error):
                session2.read_data_from_groups('unique key for test_2_backends_with_equal_ids_and_group', [g]).get()

        session1.set_backend_ids(address1, backend_id1, old_ids1).get()
        session2.set_backend_ids(address2, backend_id2, old_ids2).get()
