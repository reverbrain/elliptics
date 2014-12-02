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
from conftest import make_session
import elliptics
import elliptics_recovery.types.dc
import elliptics_recovery.types.merge


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
    results = []
    for i, k in enumerate(keys):
        results.append(session.write_data(k, datas[i]))
    for r in results:
        r.wait()


def check_data(scope, session, keys, datas, timestamp):
    '''
    Reads @keys from the session. Reads all keys async at once and waits/checks results at the end.
    '''
    results = []
    for k in keys:
        results.append(session.read_data(k))
    results = map(lambda x: x.get()[0], results)
    assert [x.data for x in results] == datas
    timestamps = [x.timestamp for x in results]
    assert all(x == timestamp for x in timestamps)


def recovery(one_node, remotes, backend_id, address, groups,
             session, rtype, log_file, tmp_dir, dump_file=None, no_meta=False):
    '''
    Imports dnet_recovery tools and executes merge recovery. Checks result of merge.
    '''
    from elliptics_recovery.recovery import run
    import os

    cur_dir = os.getcwd()
    tmp_dir = os.path.join(cur_dir, tmp_dir)
    try:
        os.makedirs(tmp_dir, 0755)
    except:
        pass

    args = ['-D', tmp_dir,
            '-l', os.path.join(tmp_dir, 'recovery.log'),
            '-c', 1024,
            '-L', elliptics.log_level.debug,
            '-g', ','.join(map(str, groups)),
            '-b', 100,
            '-n', 3,
            '-a', 1
            ]
    for r in remotes:
        args += ['-r', str(r)]
    if one_node:
        args += ['-o', str(address)]
    if dump_file:
        args += ['-f', os.path.abspath(dump_file)]
    if backend_id is not None:
        args += ['-i', backend_id]
    if no_meta:
        args += ['-M']
    if rtype == RECOVERY.MERGE:
        args += ['merge']
    elif rtype == RECOVERY.DC:
        args += ['dc']

    assert run(args) == 0


@pytest.fixture(scope="module", autouse=True)
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
    Makes few writes in the backend group. Checks written data availability.
    Turns on one backend from the same node and the same group
    Runs dnet_recovery merge with --one-node and --backend-id.
    Checks written data availability.
    Enables another one backend from the same group.
    Runs dnet_recovery merge without --one-node and without --backend-id and with -f merge.dump.file.
    Checks written data availability.
    Turns on all backends from the same group from all node.
    Runs dnet_recovery merge without --one-node and without --backend-id.
    Checks written data availability.
    Turns on one backend from other node and from one second group.
    Runs dnet_recovery dc with --one-node and with --backend-id.
    Checks written data availability in both groups.
    Turns on all nodes from on second group.
    Runs dnet_recovery dc without --one-node and without --backend-id and with -f merge.dump.file.
    Checks written data availability in both groups.
    Turns on third group nodes.
    Writes new data on the same keys.
    Runs dnet_recovery without --one-node and without --backend-id.
    Checks written data availability in all groups.
    Writes one key with different data and incremental timestamp to 1,2,3 groups.
    Corrupts record at 3d group.
    Run dnet_recovery for all groups (1,2,3).
    Checks that all groups have the key with the same data and timestamp that was written to the second group.
    Runs defragmentation on all backends from all group.
    Checks written data availability in all groups.
    '''
    namespace = "TestRecovery"
    count = 1024
    # keys which will be written, readed, recovered and checked by recovery tests
    keys = map('{0}'.format, range(count))
    # at first steps datas of all keys written to first and second group would be equal to key
    datas = keys
    # to make it simplier all keys from first and second group will be have similar timestamp
    timestamp = elliptics.Time.now()
    # this data will be written to the third group
    datas2 = map('{0}.{0}'.format, keys)
    # this timestamp will be used for writing data to the third group
    timestamp2 = elliptics.Time(timestamp.tsec + 3600, timestamp.tnsec)
    corrupted_key = 'corrupted_test.key'
    corrupted_data = 'corrupted_test.data'
    # timestamp of corrupted_key from first group
    corrupted_timestamp = elliptics.Time.now()
    # timestamp of corrupted_key from second group which should be recovered to first and third group
    corrupted_timestamp2 = elliptics.Time(corrupted_timestamp.tsec + 3600, corrupted_timestamp.tnsec)

    def test_disable_backends(self, server, simple_node):
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

    def test_prepare_data(self, server, simple_node):
        '''
        Writes self.keys to chosen group and checks their availability.
        '''
        session = make_session(node=simple_node,
                               test_name='TestRecovery.test_prepare_data',
                               test_namespace=self.namespace)
        session.groups = [scope.test_group]
        session.timestamp = self.timestamp

        write_data(scope, session, self.keys, self.datas)
        check_data(scope, session, self.keys, self.datas, self.timestamp)

    def test_enable_group_one_backend(self, server, simple_node):
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

    def test_merge_two_backends(self, server, simple_node):
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
                 no_meta=True,
                 log_file='merge_2_backends.log',
                 tmp_dir='merge_2_backends')

        session.groups = (scope.test_group,)
        check_data(scope, session, self.keys, self.datas, self.timestamp)

    def test_enable_another_one_backend(self, server, simple_node):
        '''
        Enables another one backend from the same group.
        '''
        assert scope.disabled_backends[-2][0] == scope.test_group
        session = make_session(node=simple_node,
                               test_name='TestRecovery.test_enable_another_one_backend',
                               test_namespace=self.namespace)
        group, address, backend = scope.disabled_backends[-1]
        r = enable_backend(scope, session, group, address, backend)
        check_backend_status(r.get(), backend, state=1)
        wait_backends_in_route(session, ((address, backend),))

    def test_merge_from_dump_3_backends(self, server, simple_node):
        '''
        Writes all keys to dump file: 'merge.dump.file'.
        Runs dnet_recovery merge without --one-node and without --backend-id and with -f merge.dump.file.
        Checks that all keys are available and have correct data.
        '''
        session = make_session(node=simple_node,
                               test_name='TestRecovery.test_merge_from_dump_3_backends',
                               test_namespace=self.namespace)

        dump_filename = 'merge.dump.file'
        with open(dump_filename, 'w') as dump_file:
            for key in self.keys + ['unknown_key']:
                dump_file.write('{0}\n'.format(str(session.transform(key))))

        recovery(one_node=False,
                 remotes=map(elliptics.Address.from_host_port_family, server.remotes),
                 backend_id=None,
                 address=scope.test_address,
                 groups=(scope.test_group,),
                 session=session.clone(),
                 rtype=RECOVERY.MERGE,
                 log_file='merge_from_dump_3_backends.log',
                 tmp_dir='merge_from_dump_3_backends',
                 dump_file=dump_filename)

        session.groups = (scope.test_group,)
        check_data(scope, session, self.keys, self.datas, self.timestamp)

    def test_enable_all_group_backends(self, server, simple_node):
        '''
        Enables all backends from all nodes from first group
        '''
        session = make_session(node=simple_node,
                               test_name='TestRecovery.test_enable_all_group_backends',
                               test_namespace=self.namespace)
        enable_group(scope, session, scope.test_group)

    def test_merge_one_group(self, server, simple_node):
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
        check_data(scope, session, self.keys, self.datas, self.timestamp)

    def test_enable_second_group_one_backend(self, server, simple_node):
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

    def test_dc_one_backend_and_one_group(self, server, simple_node):
        '''
        Runs dnet_recovery dc with --one-node=scope.test_address2,
        --backend-id=scope.test_backend2 and against both groups.
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
                 tmp_dir='dc_one_backend',
                 no_meta=True)

        session.groups = (scope.test_group2,)
        check_data(scope, session, self.keys, self.datas, self.timestamp)

    def test_enable_all_second_group_backends(self, server, simple_node):
        '''
        Enables all backends from all node in second group.
        '''
        session = make_session(node=simple_node,
                               test_name='TestRecovery.test_enable_all_second_group_backends',
                               test_namespace=self.namespace)
        enable_group(scope, session, scope.test_group2)

    def test_dc_from_dump_two_groups(self, server, simple_node):
        '''
        Runs dnet_recovery dc without --one-node and
        without --backend-id against both groups and with -f merge.dump.file.
        Checks self.keys availability after recovering in both groups.
        '''
        session = make_session(node=simple_node,
                               test_name='TestRecovery.test_dc_from_dump_two_groups',
                               test_namespace=self.namespace)

        dump_filename = 'dc.dump.file'
        with open(dump_filename, 'w') as dump_file:
            for key in self.keys + ['unknown_key']:
                dump_file.write('{0}\n'.format(str(session.transform(key))))

        recovery(one_node=False,
                 remotes=map(elliptics.Address.from_host_port_family, server.remotes),
                 backend_id=None,
                 address=scope.test_address2,
                 groups=(scope.test_group, scope.test_group2,),
                 session=session.clone(),
                 rtype=RECOVERY.DC,
                 log_file='dc_from_dump_two_groups.log',
                 tmp_dir='dc_from_dump_two_groups',
                 dump_file=dump_filename)

        session.groups = (scope.test_group,)
        check_data(scope, session, self.keys, self.datas, self.timestamp)

        session.groups = (scope.test_group2,)
        check_data(scope, session, self.keys, self.datas, self.timestamp)

    def test_enable_all_third_group_backends(self, server, simple_node):
        '''
        Enables all backends from all node from third group.
        '''
        session = make_session(node=simple_node,
                               test_name='TestRecovery.test_enable_all_third_group_backends',
                               test_namespace=self.namespace)
        enable_group(scope, session, scope.test_group3)

    def test_write_data_to_third_group(self, server, simple_node):
        '''
        Writes different data by self.key in third group
        '''
        session = make_session(node=simple_node,
                               test_name='TestRecovery.test_write_data_to_third_group',
                               test_namespace=self.namespace)
        session.groups = [scope.test_group3]
        session.timestamp = self.timestamp2

        write_data(scope, session, self.keys, self.datas2)
        check_data(scope, session, self.keys, self.datas2, self.timestamp2)

    def test_dc_three_groups(self, server, simple_node):
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

        for group in (scope.test_group, scope.test_group2, scope.test_group3):
            session.groups = [group]
            check_data(scope, session, self.keys, self.datas2, self.timestamp2)

    def test_write_and_corrupt_data(self, server, simple_node):
        '''
        Writes one by one the key with different data and
        incremental timestamp to groups 1, 2, 3 and corrupts data in the group #3.
        '''
        session = make_session(node=simple_node,
                               test_name='TestRecovery.test_write_and_corrupt_data',
                               test_namespace=self.namespace)

        timestamp3 = elliptics.Time(self.corrupted_timestamp.tsec + 7200, self.corrupted_timestamp.tnsec)

        session.groups = [scope.test_group]
        session.timestamp = self.corrupted_timestamp
        write_data(scope, session, [self.corrupted_key], [self.corrupted_data + '.1'])
        check_data(scope, session, [self.corrupted_key], [self.corrupted_data + '.1'], self.corrupted_timestamp)

        session.groups = [scope.test_group2]
        session.timestamp = self.corrupted_timestamp2
        write_data(scope, session, [self.corrupted_key], [self.corrupted_data + '.2'])
        check_data(scope, session, [self.corrupted_key], [self.corrupted_data + '.2'], self.corrupted_timestamp2)

        session.groups = [scope.test_group3]
        session.timestamp = timestamp3
        write_data(scope, session, [self.corrupted_key], [self.corrupted_data + '.3'])
        check_data(scope, session, [self.corrupted_key], [self.corrupted_data + '.3'], timestamp3)

        res = session.lookup(self.corrupted_key).get()[0]

        with open(res.filepath, 'r+b') as f:
            f.seek(res.offset, 0)
            tmp = '123' + f.read()[3:]
            f.seek(res.offset, 0)
            f.write(tmp)
            f.flush()

    def test_dc_corrupted_data(self, server, simple_node):
        '''
        Runs dc recovery and checks that second version of data is recovered to all groups.
        This test checks that dc recovery correctly handles corrupted key on his way:
        Group #3 which key was corrupted has a newest timestamp and recovery tries to used it at first.
        But read fails and recovery switchs to the group #2 and recovers data from this group to groups #1 and #3.
        '''
        session = make_session(node=simple_node,
                               test_name='TestRecovery.test_dc_corrupted_data',
                               test_namespace=self.namespace)

        recovery(one_node=False,
                 remotes=map(elliptics.Address.from_host_port_family, server.remotes),
                 backend_id=None,
                 address=scope.test_address2,
                 groups=(scope.test_group, scope.test_group2, scope.test_group3),
                 session=session.clone(),
                 rtype=RECOVERY.DC,
                 log_file='dc_corrupted_data.log',
                 tmp_dir='dc_corrupted_data')

        for group in (scope.test_group, scope.test_group2, scope.test_group3):
            session.groups = [group]
            check_data(scope, session, [self.corrupted_key], [self.corrupted_data + '.2'], self.corrupted_timestamp2)

    def test_defragmentation(self, server, simple_node):
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

        for group in (scope.test_group, scope.test_group2, scope.test_group3):
            session.groups = [group]
            check_data(scope, session, self.keys, self.datas2, self.timestamp2)

    def test_enable_rest_backends(self, server, simple_node):
        '''
        Restore all groups with all nodes and all backends.
        '''
        session = make_session(node=simple_node,
                               test_name='TestRecovery.test_enable_rest_backends',
                               test_namespace=self.namespace)
        for g in scope.test_other_groups:
            enable_group(scope, session, g)

    def test_checks_all_enabled(self, server, simple_node):
        '''
        Checks statuses of all backends from all nodes and groups
        '''
        session = make_session(node=simple_node,
                               test_name='TestRecovery.test_checks_all_enabled',
                               test_namespace=self.namespace)
        assert set(scope.init_routes.addresses()) == set(session.routes.addresses())
