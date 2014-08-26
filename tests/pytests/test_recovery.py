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


from conftest import simple_node, make_session
from server import server
import elliptics

class RECOVERY:
    MERGE = 1
    DC = 2

def check_backend_status(result, backend_id, state, defrag_state=0, last_start_err=0):
    '''
    Checks one backends status
    '''
    assert len(result) == 1
    assert len(result[0].backends) == 1
    assert result[0].backends[0].backend_id == backend_id
    assert result[0].backends[0].state == state
    assert result[0].backends[0].defrag_state == defrag_state
    assert result[0].backends[0].last_start_err == last_start_err

def disable_backend(scope, session, group, address, backend_id):
    '''
    Disables backend @backend_id on node @address via session.
    Adds (@group, @address, @backend_id) to the list of disabled backends in scope.
    Checks results.
    '''
    scope.disabled_backends.append((group, address, backend_id))
    return session.disable_backend(address, backend_id)

def enable_backend(scope, session, group, address, backend_id):
    '''
    Enables @backend_id at @address in @group.
    Removes enabled backend from list of disabled ones from scope.
    Checks results.
    '''
    index = scope.disabled_backends.index((group, address, backend_id))
    del scope.disabled_backends[index]
    return session.enable_backend(address, backend_id)

def wait_backends_in_route(session, addresses_with_backends):
    from time import sleep
    while set(addresses_with_backends).difference(session.routes.addresses_with_backends()):
        print set(addresses_with_backends).difference(session.routes.addresses_with_backends()), addresses_with_backends, session.routes.addresses_with_backends()
        sleep(0.1)

def enable_group(scope, session, group):
    '''
    Enables all backends at all nodes from @group.
    '''
    from functools import partial
    to_enable = [(g, a, b) for g, a, b in scope.disabled_backends if g == group]
    res = []
    for g, a, b in to_enable:
        res.append((enable_backend(scope, session, g, a, b), b))

    for r, b in res:
        check_backend_status(r.get(), b, state=1)

    wait_backends_in_route(session, ((addr, back) for _, addr, back in to_enable))


def write_data(scope, session, keys, datas):
    '''
    Writes @key to the @session. Writes all keys async at once and waits/checks results at the end.
    '''
    res = map(lambda (i, x): session.write_data(x, datas[i]), enumerate(keys))
    for r in res:
        r.wait()

def check_data(scope, session, keys, datas):
    '''
    Reads @keys from the session. Reads all keys async at once and waits/checks results at the end.
    '''
    res = map(session.read_data, keys)
    res = map(lambda x: x.get()[0].data, res)
    assert res == datas

def recovery(one_node, remotes, backend_id, address, groups, session, rtype, log_file, tmp_dir):
    '''
    Imports dnet_recovery tools and executes merge recovery. Checks result of merge.
    '''
    from elliptics_recovery.ctx import Ctx
    from elliptics_recovery.route import RouteList
    from elliptics_recovery.monitor import Monitor
    from elliptics_recovery.etime import Time
    import os

    if rtype == RECOVERY.MERGE:
        from elliptics_recovery.types.merge import main
    elif rtype == RECOVERY.DC:
        from elliptics_recovery.types.dc import main
    else:
        assert 0

    ctx = Ctx()
    cur_dir = os.getcwd()
    ctx.tmp_dir = os.path.join(cur_dir, tmp_dir)
    try:
        os.makedirs(ctx.tmp_dir, 0755)
    except: pass
    ctx.log_file = os.path.join(ctx.tmp_dir, 'recovery.log')

    import logging
    import logging.handlers

    log = logging.getLogger()
    log.setLevel(logging.DEBUG)
    formatter = logging.Formatter(fmt='%(asctime)-15s %(thread)d/%(process)d %(processName)s %(levelname)s %(message)s',
                                  datefmt='%d %b %y %H:%M:%S')

    ch = logging.FileHandler(ctx.log_file)
    ch.setFormatter(formatter)
    ch.setLevel(logging.DEBUG)
    log.addHandler(ch)

    ctx.dry_run = False
    ctx.safe = False
    ctx.one_node = one_node
    ctx.custom_recover = ''
    ctx.dump_file = None
    ctx.chunk_size = 1024
    ctx.log_level = 4
    ctx.remotes = remotes
    ctx.backend_id = backend_id
    ctx.address = address
    ctx.groups = groups
    ctx.batch_size = 100
    ctx.nprocess = 3
    ctx.attempts = 1
    ctx.monitor_port = None
    ctx.wait_timeout = 36000
    ctx.elog = elliptics.Logger(ctx.log_file, int(ctx.log_level))
    ctx.routes = RouteList.from_session(session)
    ctx.monitor = Monitor(ctx, None)
    ctx.timestamp = Time.from_epoch(0)

    recovery_res = main(ctx)
    assert recovery_res

    ctx.monitor.shutdown()


@pytest.fixture(scope="module")
def scope():
    '''
    Scope fixture for sharing info between test cases.
    '''
    class Scope():
        def __repr__(self):
            return '{0}'.format(vars(self))
    return Scope()

@pytest.mark.incremental
class TestRecovery:
    '''
    Turns off all backends from all node except one.
    Makes few writes in the backend group. Checks writed data availability.
    Turns on one backend from the same node and the same group
    Runs dnet_recovery merge with --one-node and --backend-id.
    Checks writed data availability.
    Turns on all backends from the same group from all node.
    Runs dnet_recovery merge without --one-node and without --backend-id.
    Checks writed data availability.
    Turns on one backend from other node and from one second group.
    Runs dnet_recovery dc with --one-node and with --backend-id.
    Checks writed data availability in both groups.
    Turns on all nodes from on second group.
    Runs dnet_recovery dc without --one-node and without --backend-id.
    Checks writed data availability in both groups.
    Turns on third group nodes.
    Writes new data on the same keys.
    Runs dnet_recovery without --one-node and without --backend-id.
    Checks writed data availability in all groups.
    Runs defragmentation on all backends from all group.
    Checks writed data availability in all groups.
    '''
    namespace = "TestRecovery"
    count = 1024
    keys = map('{0}'.format, range(count))
    datas = keys
    datas2 = map('{0}.{0}'.format, keys)

    def test_disable_backends(self, scope, server, simple_node):
        '''
        Turns off all backends from all node except one.
        '''
        session = make_session(node=simple_node,
                               test_name='TestRecovery.test_disable_backends',
                               test_namespace=self.namespace)
        session.set_timeout(10)
        groups = session.routes.groups()
        scope.test_group = groups[0]
        scope.test_group2 = groups[1]
        scope.test_group3 = groups[2]
        scope.test_other_groups = groups[3:]
        scope.disabled_backends = []
        scope.init_routes = session.routes.filter_by_groups(groups)

        #disables backends from other than scope.test_group group from all node
        res = []
        for group in session.routes.groups()[1:]:
            addr_back = session.routes.filter_by_group(group).addresses_with_backends()
            for address, backend in addr_back:
                res.append((disable_backend(scope, session, group, address, backend), backend))

        routes = session.routes.filter_by_group(scope.test_group)

        #chooses one backend from one node to leave it enabled
        scope.test_address = routes[0].address
        scope.test_backend = routes[0].backend_id

        #disables all other backends from that groups.
        addr_back = routes.addresses_with_backends()
        for address, backend in addr_back:
            if (address, backend) != (scope.test_address, scope.test_backend):
                res.append((disable_backend(scope, session, scope.test_group, address, backend), backend))

        for r, backend in res:
            check_backend_status(r.get(), backend, state=0)

        #checks that routes contains only chosen backend address.
        assert session.routes.addresses_with_backends() == ((scope.test_address, scope.test_backend),)
        #checks that routes contains only chosen backend group
        assert session.routes.groups() == (scope.test_group, )

    def test_prepare_data(self, scope, server, simple_node):
        '''
        Writes self.keys to chosen group and checks their availability.
        '''
        session = make_session(node=simple_node,
                               test_name='TestRecovery.test_prepare_data',
                               test_namespace=self.namespace)
        session.groups = [scope.test_group]

        write_data(scope, session, self.keys, self.datas)
        check_data(scope, session, self.keys, self.datas)

    def test_enable_group_one_backend(self, scope, server, simple_node):
        '''
        Turns on one backend from the same group.
        '''
        assert scope.disabled_backends[-1][0] == scope.test_group
        session = make_session(node=simple_node,
                               test_name='TestRecovery.test_enable_group_one_backend',
                               test_namespace=self.namespace)
        group, address, backend = scope.disabled_backends[-1]
        r = enable_backend(scope, session, group, address, backend)
        check_backend_status(r.get(), backend, state=1)
        wait_backends_in_route(session, ((address, backend),))


    def test_merge_two_backends(self, scope, server, simple_node):
        '''
        Runs dnet_recovery merge with --one-node=scope.test_address and --backend-id==scope.test_backend.
        Checks self.keys availability after recovering.
        '''
        session = make_session(node=simple_node,
                               test_name='TestRecovery.test_merge_two_backends',
                               test_namespace=self.namespace)

        recovery(one_node=True,
                 remotes=map(elliptics.Address.from_host_port_family, server.remotes),
                 backend_id=scope.test_backend,
                 address=scope.test_address,
                 groups=(scope.test_group,),
                 session=session.clone(),
                 rtype=RECOVERY.MERGE,
                 log_file='merge_2_backends.log',
                 tmp_dir='merge_2_backends')

        session.groups = (scope.test_group,)
        check_data(scope, session, self.keys, self.datas)

    def test_enable_all_group_backends(self, scope, server, simple_node):
        '''
        Enables all backends from all nodes from first group
        '''
        session = make_session(node=simple_node,
                               test_name='TestRecovery.test_enable_all_group_backends',
                               test_namespace=self.namespace)
        enable_group(scope, session, scope.test_group)

    def test_merge_one_group(self, scope, server, simple_node):
        '''
        Runs dnet_recovery merge without --one-node and without --backend-id.
        Checks self.keys availability after recovering.
        '''
        session = make_session(node=simple_node,
                               test_name='TestRecovery.test_merge_one_group',
                               test_namespace=self.namespace)

        recovery(one_node=False,
                 remotes=map(elliptics.Address.from_host_port_family, server.remotes),
                 backend_id=None,
                 address=scope.test_address,
                 groups=(scope.test_group,),
                 session=session.clone(),
                 rtype=RECOVERY.MERGE,
                 log_file='merge_one_group.log',
                 tmp_dir='merge_one_group')

        session.groups = (scope.test_group,)
        check_data(scope, session, self.keys, self.datas)

    def test_enable_second_group_one_backend(self, scope, server, simple_node):
        '''
        Enables one backend from one node from second group.
        '''
        session = make_session(node=simple_node,
                               test_name='TestRecovery.test_enable_second_group_one_backend',
                               test_namespace=self.namespace)
        group, address, backend = next(((g, a, b) for g, a, b in scope.disabled_backends if g == scope.test_group2))
        scope.test_address2 = address
        scope.test_backend2 = backend

        r = enable_backend(scope, session, group, address, backend)
        check_backend_status(r.get(), backend, state=1)
        wait_backends_in_route(session, ((address, backend), ))

    def test_dc_one_backend_and_one_group(self, scope, server, simple_node):
        '''
        Runs dnet_recovery dc with --one-node=scope.test_address2, --backend-id=scope.test_backend2 and against both groups.
        Checks self.keys availability after recovering in both groups.
        '''
        session = make_session(node=simple_node,
                               test_name='TestRecovery.test_dc_one_backend_and_one_group',
                               test_namespace=self.namespace)

        recovery(one_node=True,
                 remotes=map(elliptics.Address.from_host_port_family, server.remotes),
                 backend_id=scope.test_backend2,
                 address=scope.test_address2,
                 groups=(scope.test_group, scope.test_group2,),
                 session=session.clone(),
                 rtype=RECOVERY.DC,
                 log_file='dc_one_backend.log',
                 tmp_dir='dc_one_backend')

        session.groups = (scope.test_group2,)
        check_data(scope, session, self.keys, self.datas)

    def test_enable_all_second_group_backends(self, scope, server, simple_node):
        '''
        Enables all backends from all node in second group.
        '''
        session = make_session(node=simple_node,
                               test_name='TestRecovery.test_enable_all_second_group_backends',
                               test_namespace=self.namespace)
        enable_group(scope, session, scope.test_group2)

    def test_dc_two_groups(self, scope, server, simple_node):
        '''
        Runs dnet_recovery dc without --one-node and without --backend-id against both groups.
        Checks self.keys availability after recovering in both groups.
        '''
        session = make_session(node=simple_node,
                               test_name='TestRecovery.test_dc_two_groups',
                               test_namespace=self.namespace)

        recovery(one_node=False,
                 remotes=map(elliptics.Address.from_host_port_family, server.remotes),
                 backend_id=None,
                 address=scope.test_address2,
                 groups=(scope.test_group, scope.test_group2,),
                 session=session.clone(),
                 rtype=RECOVERY.DC,
                 log_file='dc_two_groups.log',
                 tmp_dir='dc_two_groups')

        session.groups = (scope.test_group,)
        check_data(scope, session, self.keys, self.datas)

        session.groups = (scope.test_group2,)
        check_data(scope, session, self.keys, self.datas)

    def test_enable_all_third_group_backends(self, scope, server, simple_node):
        '''
        Enables all backends from all node from third group.
        '''
        session = make_session(node=simple_node,
                               test_name='TestRecovery.test_enable_all_third_group_backends',
                               test_namespace=self.namespace)
        enable_group(scope, session, scope.test_group3)

    def test_write_data_to_third_group(self, scope, server, simple_node):
        '''
        Writes different data by self.key in third group
        '''
        session = make_session(node=simple_node,
                               test_name='TestRecovery.test_write_data_to_third_group',
                               test_namespace=self.namespace)
        session.groups = [scope.test_group3]


        write_data(scope, session, self.keys, self.datas2)
        check_data(scope, session, self.keys, self.datas2)

    def test_dc_three_groups(self, scope, server, simple_node):
        '''
        Run dc recovery without --one-node and without --backend-id against all three groups.
        Checks that all three groups contain data from third group.
        '''
        session = make_session(node=simple_node,
                               test_name='TestRecovery.test_dc_three_groups',
                               test_namespace=self.namespace)

        recovery(one_node=False,
                 remotes=map(elliptics.Address.from_host_port_family, server.remotes),
                 backend_id=None,
                 address=scope.test_address2,
                 groups=(scope.test_group, scope.test_group2, scope.test_group3),
                 session=session.clone(),
                 rtype=RECOVERY.DC,
                 log_file='dc_three_groups.log',
                 tmp_dir='dc_three_groups')

        session.groups = (scope.test_group,)
        check_data(scope, session, self.keys, self.datas2)

        session.groups = (scope.test_group2,)
        check_data(scope, session, self.keys, self.datas2)

        session.groups = (scope.test_group3,)
        check_data(scope, session, self.keys, self.datas2)

    def test_defragmentation(self, scope, server, simple_node):
        '''
        Runs defragmentation on all backends from all nodes and groups.
        Waiting defragmentation stops and checks results.
        '''
        session = make_session(node=simple_node,
                               test_name='TestRecovery.test_defragmentation',
                               test_namespace=self.namespace)
        res = []
        for address, backend in session.routes.addresses_with_backends():
            res.append((session.start_defrag(address, backend), backend))
        cnt = 0
        for r, backend in res:
            assert len(r.get()) == 1
            assert len(r.get()[0].backends) == 1
            assert r.get()[0].backends[0].backend_id == backend
            assert r.get()[0].backends[0].state == 1
            assert r.get()[0].backends[0].defrag_state == 1
            assert r.get()[0].backends[0].last_start_err == 0
            cnt += r.get()[0].backends[0].defrag_state

        while cnt > 0:
            cnt = 0
            for address in session.routes.addresses():
                res = session.request_backends_status(address).get()
                backends = session.routes.get_address_backends(address)
                assert len(res) == 1
                assert len(res[0].backends) == len(backends)
                for r in res[0].backends:
                    assert r.backend_id in backends
                    assert r.state == 1
                    assert r.last_start_err == 0
                    cnt += r.defrag_state
            print "In defragmentation:", cnt

        session.groups = (scope.test_group,)
        check_data(scope, session, self.keys, self.datas2)

        session.groups = (scope.test_group2,)
        check_data(scope, session, self.keys, self.datas2)

        session.groups = (scope.test_group3,)
        check_data(scope, session, self.keys, self.datas2)

    def test_enable_rest_backends(self, scope, server, simple_node):
        '''
        Restore all groups with all nodes and all backends.
        '''
        session = make_session(node=simple_node,
                               test_name='TestRecovery.test_enable_rest_backends',
                               test_namespace=self.namespace)
        for g in scope.test_other_groups:
            enable_group(scope, session, g)

    def test_checks_all_enabled(self, scope, server, simple_node):
        '''
        Checks statuses of all backends from all nodes and groups
        '''
        session = make_session(node=simple_node,
                               test_name='TestRecovery.test_checks_all_enabled',
                               test_namespace=self.namespace)
        assert set(scope.init_routes.addresses()) == set(session.routes.addresses())
