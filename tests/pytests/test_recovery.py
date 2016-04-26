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

import os
import sys
import errno
sys.path.insert(0, "")  # for running from cmake
import pytest
from conftest import make_session
import elliptics
import elliptics_recovery.types.dc
import elliptics_recovery.types.merge


class RECOVERY:
    MERGE = 1
    DC = 2


def cleanup_logger():
    from logging import getLogger
    log = getLogger()
    log.handlers = []


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


def check_keys_absence(scope, session, keys):
    '''
    Checks that merge recovery removes moved @keys from the source backend.
    '''
    session = session.clone()
    session.exceptions_policy = elliptics.core.exceptions_policy.no_exceptions
    session.set_filter(elliptics.filters.all)
    session.set_direct_id(scope.test_address, scope.test_backend)

    routes = session.routes.filter_by_group(scope.test_group)
    results = []
    for k in keys:
        addr, _, backend = routes.get_id_routes(session.transform(k))[0]
        if addr != scope.test_address or backend != scope.test_backend:
            results.append(session.lookup(k))

    assert len(results) > 0
    for r in results:
        assert r.get()[0].status == -errno.ENOENT


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
    assert all(x.user_flags == session.user_flags for x in results)


def recovery(one_node, remotes, backend_id, address, groups,
             rtype, log_file, tmp_dir, dump_file=None, no_meta=False, user_flags_set=()):
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
    for user_flags in user_flags_set:
        args += ['--user-flags', user_flags]

    assert run(args) == 0

    cleanup_logger()


@pytest.fixture(scope="class", autouse=True)
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

        # disables backends from other than scope.test_group group from all node
        res = []
        for group in session.routes.groups()[1:]:
            addr_back = session.routes.filter_by_group(group).addresses_with_backends()
            for address, backend in addr_back:
                res.append((disable_backend(scope, session, group, address, backend), backend))

        routes = session.routes.filter_by_group(scope.test_group)

        # chooses one backend from one node to leave it enabled
        scope.test_address = routes[0].address
        scope.test_backend = routes[0].backend_id

        # disables all other backends from that groups.
        addr_back = routes.addresses_with_backends()
        for address, backend in addr_back:
            if (address, backend) != (scope.test_address, scope.test_backend):
                res.append((disable_backend(scope, session, scope.test_group, address, backend), backend))

        for r, backend in res:
            check_backend_status(r.get(), backend, state=0)

        # checks that routes contains only chosen backend address.
        assert session.routes.addresses_with_backends() == ((scope.test_address, scope.test_backend),)
        # checks that routes contains only chosen backend group
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
                 rtype=RECOVERY.MERGE,
                 no_meta=True,
                 log_file='merge_2_backends.log',
                 tmp_dir='merge_2_backends')

        session.groups = (scope.test_group,)
        check_data(scope, session, self.keys, self.datas, self.timestamp)
        check_keys_absence(scope, session, self.keys)

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
                 rtype=RECOVERY.MERGE,
                 log_file='merge_from_dump_3_backends.log',
                 tmp_dir='merge_from_dump_3_backends',
                 dump_file=dump_filename)

        session.groups = (scope.test_group,)
        check_data(scope, session, self.keys, self.datas, self.timestamp)
        check_keys_absence(scope, session, self.keys)

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
                 rtype=RECOVERY.MERGE,
                 log_file='merge_one_group.log',
                 tmp_dir='merge_one_group')

        session.groups = (scope.test_group,)
        check_data(scope, session, self.keys, self.datas, self.timestamp)
        check_keys_absence(scope, session, self.keys)

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


def remove_files(pattern):
    '''
    Removes files by path pattern
    '''
    import glob
    for fl in glob.iglob(pattern):
        if os.path.isfile(fl):
            print 'Removing:', fl
            os.remove(fl)


def remove_all_blobs(session):
    '''
    requests monitor stats, gets blob's path pattern for each backends from all nodes and
    removes all blobs
    '''
    results = session.monitor_stat(categories=elliptics.monitor_stat_categories.backend).get()
    for result in results:
        backends = result.statistics['backends']
        for backend in backends:
            data_path = backends[backend]['backend']['config']['data']
            remove_files(data_path + '*')


def disable_backends(session, addresses_with_backends):
    '''
    Disables all enabled backends at all nodes
    '''
    res = []
    for address, backend in addresses_with_backends:
        res.append((session.disable_backend(address, backend), backend))

    for r, backend in res:
        check_backend_status(r.get(), backend, state=0)


def enable_backends(session, addresses_with_backends):
    '''
    Enables all specified backends at specified node
    '''
    res = []
    for address, backend in addresses_with_backends:
        res.append((session.enable_backend(address, backend), backend))

    for r, backend in res:
        check_backend_status(r.get(), backend, state=1)


class KeyShifter:
    '''
    Class that allows to generate incremental keys from base key
    '''
    def __init__(self, base_key):
        '''
        Saves int values of base_key
        '''
        self.__base_key__ = int(str(base_key), 16)

    def get(self, shift):
        '''
        Returns elliptics.Id got by shifting base_key
        '''
        return elliptics.Id('%x' % (self.__base_key__ + shift))


def make_test_data(timestamps, dest_count):
    '''
    Generates and returns list of cases. Each case is a list of Variant(action, timestamp)
    for each destination (backend or group) that will be done through the case.
    '''
    from collections import namedtuple
    from itertools import product
    Variant = namedtuple('Variant', ['action', 'timestamp'])

    actions = [elliptics.Session.write_prepare, elliptics.Session.write_data]

    variants = [None] + [Variant(action, ts) for action, ts in product(actions, timestamps)]
    return list(product(variants, repeat=dest_count))


@pytest.mark.incremental
class TestMerge:
    '''
        Description:
            checks that merge correctly recovers keys with different combination of replicas in both
            hidden and real backends.
        Steps:
        setup:
            disable all backends
            remove all blobs
            enable 2 backends from group 1
            prepare keys on both backend for recovery
        recover;
            run merge recovery
        check:
            check via reading all keys accessibility and data correctness
        teardown:
            disable enabled backends
            remove all blobs
            enable all backends
    '''
    data = os.urandom(1024)
    cur_ts = elliptics.Time.now()
    old_ts = elliptics.Time(cur_ts.tsec - 24 * 60 * 60, cur_ts.tnsec)
    new_ts = elliptics.Time(cur_ts.tsec + 24 * 60 * 60, cur_ts.tnsec)

    def get_result(self, case):
        '''
        Estimates result for the case
        '''
        assert len(case) == 2
        if case[0] is None or \
           case[0].action == elliptics.Session.write_prepare:
            if case[1] is None or \
               case[1].action == elliptics.Session.write_prepare:
                return None
            else:
                return case[1].timestamp
        else:
            assert case[0].action == elliptics.Session.write_data
            if case[1] is None or \
               case[1].action == elliptics.Session.write_prepare or \
               case[1].timestamp < case[0].timestamp:
                return case[0].timestamp
            else:
                return case[1].timestamp

    def make_action(self, key, session, (method, ts), backend):
        '''
        Makes action `method` against session for key, ts, self.data and backend.
        Returns AsyncResult with ts and backend that will be used for checking results
        '''
        args = {'data': self.data,
                'key': key}

        if method == elliptics.Session.write_prepare:
            args['remote_offset'] = 0
            args['psize'] = len(self.data)
        elif method == elliptics.Session.write_data:
            args['offset'] = 0

        session.timestamp = ts
        return (method(session, **args), ts, backend)

    def prepare_test_data(self):
        '''
        Make prepared actions from test_data list and checks that all actions was succeeded.
        '''
        results = []
        for i, actions in enumerate(self.scope.test_data):
            key = self.scope.keyshifter.get(i)
            for j, backend in enumerate(self.scope.backends):
                if actions[j]:
                    results.append(self.make_action(key,
                                                    self.test_sessions[j],
                                                    actions[j],
                                                    backend))

        for r, ts, backend in results:
            result = r.get()
            assert len(result) == 1
            assert result[0].timestamp == ts
            assert result[0].backend_id == backend

    def get_first_backend_key(self):
        '''
        Returns first key of the range that could be used in test.
        Test requires incremental keys that belong to second backend according to route-list.
        '''
        group_routes = self.scope.routes.filter_by_group(self.scope.group)
        address_routes = group_routes.filter_by_address(self.scope.address)
        backend_ranges = address_routes.get_address_backend_ranges(self.scope.address, self.scope.backends[1])
        assert len(backend_ranges) > 0
        first_range = backend_ranges[0]
        id2int = lambda id: int(str(id), 16)
        assert id2int(first_range[1]) - id2int(first_range[0]) > len(self.scope.test_data)
        return first_range[0]

    def test_setup(self, server, simple_node):
        '''
        Initial test cases that prepare test cluster before running recovery. It includes:
        1. preparing whole test class scope - making session, choosing node and backends etc.
        2. initial cleanup - disabling all backends at all nodes and removing all blobs
        3. enabling backends that will be used at test
        4. running initial actions from test_data - preparing keys on both backends
        '''
        self.scope = scope
        self.scope.session = make_session(node=simple_node,
                                          test_name='TestMerge')

        self.scope.routes = self.scope.session.routes
        self.scope.group = self.scope.routes.groups()[0]
        self.scope.session.groups = [self.scope.group]
        self.scope.address = self.scope.routes.addresses()[0]
        group_routes = self.scope.routes.filter_by_group(self.scope.group)
        self.scope.backends = group_routes.get_address_backends(self.scope.address)[:2]
        self.scope.timestamp = elliptics.Time.now()
        self.scope.test_data = make_test_data(timestamps=[self.old_ts, self.cur_ts, self.new_ts],
                                              dest_count=len(self.scope.backends))
        self.scope.keyshifter = KeyShifter(self.get_first_backend_key())

        self.test_sessions = []
        for backend in self.scope.backends:
            self.test_sessions.append(self.scope.session.clone())
            self.test_sessions[-1].set_direct_id(self.scope.address, backend)

        disable_backends(self.scope.session, self.scope.session.routes.addresses_with_backends())
        remove_all_blobs(self.scope.session)

        enable_backends(self.scope.session, [(self.scope.address, b) for b in self.scope.backends])

        self.prepare_test_data()

    def test_recovery(self, server, simple_node):
        '''
        Runs recovery and checks recovery result
        '''
        recovery(one_node=False,
                 remotes=map(elliptics.Address.from_host_port_family, server.remotes),
                 backend_id=None,
                 address=scope.address,
                 groups=(scope.group,),
                 rtype=RECOVERY.MERGE,
                 no_meta=False,
                 log_file='merge_with_uncommitted_keys.log',
                 tmp_dir='merge_with_uncommitted_keys')

    def test_check(self, server, simple_node):
        '''
        Checks that all keys from test_data are in correct state - have correct timestamp and availability.
        '''
        results = []
        for i, case in enumerate(scope.test_data):
            results.append((
                scope.session.read_data(scope.keyshifter.get(i)),
                i))

        for r, case_num in results:
            case = scope.test_data[case_num]
            check_ts = self.get_result(case)
            if check_ts is None:
                with pytest.raises(elliptics.NotFoundError):
                    r.get()
            else:
                check_key = scope.keyshifter.get(case_num)
                result = r.get()
                assert len(result) == 1
                result = result[0]
                assert result.id == check_key
                assert result.backend_id == scope.backends[1]
                assert result.timestamp == check_ts
                assert result.data == self.data

    def test_teardown(self, server, simple_node):
        '''
        Cleanup test that makes follow:
        1. disables all backends
        2. removes all blobs
        3. enables all backends on all nodes
        '''
        disable_backends(scope.session, scope.session.routes.addresses_with_backends())
        remove_all_blobs(scope.session)
        enable_backends(scope.session, scope.routes.addresses_with_backends())


@pytest.mark.incremental
class TestDC:
    '''
        Description:
            checks that dc correctly recovers keys with different combination of replicas in 3 groups
        Steps:
        setup:
            disable all backends
            remove all blobs
            enable all backends
            prepare keys in groups for recovery
        recover;
            run dc recovery
        check:
            check by reading all keys accessibility and data correctness
        teardown:
            disable enabled backends
            remove all blobs
            enable all backends
    '''
    data = os.urandom(1024)
    cur_ts = elliptics.Time.now()
    old_ts = elliptics.Time(cur_ts.tsec - 24 * 60 * 60, cur_ts.tnsec)
    new_ts = elliptics.Time(cur_ts.tsec + 24 * 60 * 60, cur_ts.tnsec)

    def get_result(self, case):
        '''
        Estimates result for the case
        '''
        timestamps = [c.timestamp for c in case if c]
        if len(timestamps) < 1:
            return [None] * len(case)
        max_ts = max(timestamps)
        if all(c.action == elliptics.Session.write_prepare for c in case if c and c.timestamp == max_ts):
            if max_ts == self.old_ts:
                return [None] * len(case)
            else:
                get_ts = lambda c: c.timestamp if c and c.action == elliptics.Session.write_data else None
                return map(get_ts, case)
        else:
            return [max_ts] * len(case)

    def make_action(self, key, session, (method, ts), group):
        '''
        Makes action `method` against session for key, ts, self.data and backend.
        Returns AsyncResult with ts and backend that will be used for checking results
        '''
        args = {'data': self.data,
                'key': key}

        if method == elliptics.Session.write_prepare:
            args['remote_offset'] = 0
            args['psize'] = len(self.data)
        elif method == elliptics.Session.write_data:
            args['offset'] = 0

        tmp_session = session.clone()
        tmp_session.groups = [group]
        tmp_session.timestamp = ts
        return (method(tmp_session, **args), ts, group)

    def prepare_test_data(self):
        '''
        Make prepared actions from test_data list and checks that all actions was succeeded.
        '''
        results = []
        for i, actions in enumerate(self.scope.test_data):
            key = self.scope.keyshifter.get(i)
            for j, group in enumerate(self.scope.groups):
                if actions[j]:
                    results.append(self.make_action(key,
                                                    self.scope.session,
                                                    actions[j],
                                                    group))

        for r, ts, group in results:
            result = r.get()
            assert len(result) == 1
            assert result[0].timestamp == ts
            assert result[0].group_id == group

    def test_setup(self, server, simple_node):
        '''
        Initial test cases that prepare test cluster before running recovery. It includes:
        1. preparing whole test class scope - making session, choosing node and backends etc.
        2. initial cleanup - disabling all backends at all nodes and removing all blobs
        3. enabling backends that will be used at test
        4. running initial actions from test_data - preparing keys on both backends
        '''
        self.scope = scope
        self.scope.session = make_session(node=simple_node,
                                          test_name='TestDC')
        self.scope.keyshifter = KeyShifter(elliptics.Id(0))
        self.scope.routes = self.scope.session.routes
        self.scope.groups = self.scope.routes.groups()[:3]
        self.scope.test_data = make_test_data(timestamps=[self.old_ts, self.cur_ts, self.new_ts],
                                              dest_count=len(self.scope.groups))

        disable_backends(self.scope.session, self.scope.session.routes.addresses_with_backends())
        remove_all_blobs(self.scope.session)

        enable_backends(self.scope.session, self.scope.routes.addresses_with_backends())

        self.prepare_test_data()

    def test_recovery(self, server, simple_node):
        '''
        Runs recovery and checks recovery result
        '''
        recovery(one_node=False,
                 remotes=scope.routes.addresses(),
                 backend_id=None,
                 address=scope.routes.addresses()[0],
                 groups=scope.groups,
                 rtype=RECOVERY.DC,
                 log_file='dc_with_uncommitted_keys.log',
                 tmp_dir='dc_with_uncommitted_keys')

    def test_check(self, server, simple_node):
        '''
        Checks that all keys from test_data are in correct state - have correct timestamp and availability.
        '''
        sessions = []
        for g in scope.groups:
            sessions.append(scope.session.clone())
            sessions[-1].groups = [g]

        results = []
        for i, case in enumerate(scope.test_data):
            key = scope.keyshifter.get(i)
            groups_results = []
            for g in scope.groups:
                session = scope.session.clone()
                session.groups = [g]
                groups_results.append(session.read_data(key))
            results.append((
                groups_results,
                i))

        for groups_results, case_num in results:
            case = scope.test_data[case_num]
            check_ts = self.get_result(case)
            check_key = scope.keyshifter.get(case_num)
            assert len(check_ts) == len(groups_results)
            for i in range(len(check_ts)):
                if check_ts[i] is None:
                    with pytest.raises(elliptics.NotFoundError):
                        groups_results[i].get()
                else:
                    result = groups_results[i].get()
                    assert len(result) == 1
                    result = result[0]
                    assert result.id == check_key
                    assert result.group_id == scope.groups[i]
                    assert result.timestamp == check_ts[i]
                    assert result.data == self.data

    def test_teardown(self, server, simple_node):
        '''
        Cleanup test that makes follow:
        1. disables all backends
        2. removes all blobs
        3. enables all backends on all nodes
        '''
        disable_backends(scope.session, scope.session.routes.addresses_with_backends())
        remove_all_blobs(scope.session)
        enable_backends(scope.session, scope.routes.addresses_with_backends())


@pytest.mark.incremental
class TestRecoveryUserFlags:
    '''
    Checks recovery with specified user_flags_set: recover key if at least one replica
    has user_flags from specified user_flags_set
    '''
    user_flags_set = [2]
    timestamp = elliptics.Time.now()
    timestamp_new = elliptics.Time(timestamp.tsec + 3600, timestamp.tnsec)
    test_key = 'skip_test.key'
    test_key2 = 'skip_test.key2'
    test_key3 = 'skip_test.key3'
    test_data = 'skip_test.data'
    namespace = 'TestRecoveryUserFlags'

    def prepare_test_data(self):
        '''
        Writes test keys with a specific user_flags and checks that operation was successfull:
        1. Write test_key to test_groups with different user_flags that are not in user_flags_set.
        2. Write test_key2 with different user_flags including ones from user_flags_set.
        3. Write test_key3 with different user_flags. Replicas with user_flags from user_flags_set
           are written with older timestamp.
        '''
        session = scope.session.clone()
        session.timestamp = self.timestamp

        for i, group_id in enumerate(scope.test_groups):
            session.groups = [group_id]
            session.user_flags = i
            assert i not in self.user_flags_set

            write_data(scope, session, [self.test_key], [self.test_data])
            check_data(scope, session, [self.test_key], [self.test_data], self.timestamp)

        for i, group_id in enumerate(scope.groups):
            session.groups = [group_id]
            session.user_flags = i

            write_data(scope, session, [self.test_key2], [self.test_data])
            check_data(scope, session, [self.test_key2], [self.test_data], self.timestamp)

        for i, group_id in enumerate(scope.groups):
            if i in self.user_flags_set:
                timestamp = self.timestamp
            else:
                timestamp = self.timestamp_new

            session.timestamp = timestamp
            session.groups = [group_id]
            session.user_flags = i

            write_data(scope, session, [self.test_key3], [self.test_data])
            check_data(scope, session, [self.test_key3], [self.test_data], timestamp)

    def cleanup_backends(self):
        '''
        Cleanup test that makes follow:
        1. disables all backends
        2. removes all blobs
        3. enables all backends on all nodes
        '''
        disable_backends(scope.session, scope.session.routes.addresses_with_backends())
        remove_all_blobs(scope.session)
        enable_backends(scope.session, scope.routes.addresses_with_backends())

    def test_setup(self, server, simple_node):
        '''
        Initial test cases that prepare test cluster before running recovery. It includes:
        1. preparing whole test class scope - making session, choosing node and backends etc.
        2. initial cleanup - disabling all backends at all nodes and removing all blobs
        3. enabling backends that will be used at test
        4. preparing test keys
        '''
        self.scope = scope
        self.scope.session = make_session(node=simple_node,
                                          test_name='TestRecoveryUserFlags')
        self.scope.routes = self.scope.session.routes
        self.scope.groups = self.scope.routes.groups()[:3]
        self.scope.test_groups = self.scope.groups[1:]

        self.cleanup_backends()
        self.prepare_test_data()

    def test_recovery(self, server, simple_node):
        '''
        Runs recovery with filtration of keys by specifying user_flags_set and checks that:
        1. test_key shouldn't be recovered
        2. test_key2 replicas shouldn't countain user_flags that are not in user_flags_set
        3. test_key3 replicas shouldn't countain user_flags that are in user_flags_set
        '''
        recovery(one_node=False,
                 remotes=scope.routes.addresses(),
                 backend_id=None,
                 address=scope.routes.addresses()[0],
                 groups=scope.groups,
                 rtype=RECOVERY.DC,
                 log_file='dc_recovery_user_flags.log',
                 tmp_dir='dc_recovery_user_flags',
                 user_flags_set=self.user_flags_set)

        session = scope.session.clone()
        session.exceptions_policy = elliptics.core.exceptions_policy.no_exceptions
        session.set_filter(elliptics.filters.all)

        for group_id in scope.groups:
            session.groups = [group_id]

            results = session.lookup(self.test_key).get()
            if group_id in scope.test_groups:
                assert all(r.status == 0 for r in results)
            else:
                assert all(r.status == -errno.ENOENT for r in results)

            results = session.read_data(self.test_key2).get()
            assert all(r.user_flags in self.user_flags_set for r in results)

            results = session.read_data(self.test_key3).get()
            assert all(r.user_flags not in self.user_flags_set for r in results)

    def test_teardown(self, server, simple_node):
        self.cleanup_backends()
