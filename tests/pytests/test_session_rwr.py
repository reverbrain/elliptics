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


def write_cas_converter(x):
    return '__' + x + '__'


def check_write_results(results, number, data, session):
    assert len(results) == number
    for r in results:
        assert type(r) == elliptics.core.LookupResultEntry
        assert r.size == 48 + len(data)  # 48 is the size of data header
        assert r.error.code == 0
        assert r.error.message == ''
        assert r.group_id in session.routes.get_address_groups(r.address)


def checked_write(session, key, data,):
    results = session.write_data(key, data).get()
    check_write_results(results, len(session.groups), data, session)


def checked_bulk_write(session, datas, data):
    results = session.bulk_write(datas).get()
    check_write_results(results, len(session.groups) * len(datas), data, session)


def check_read_results(results, number, data, session):
    assert len(results) == number
    assert type(results[0]) == elliptics.core.ReadResultEntry
    assert results[0].data == data
    assert results[0].group_id in session.routes.get_address_groups(results[0].address)
    return results


def checked_read(session, key, data):
    results = session.read_data(key).get()
    check_read_results(results, 1, data, session)


def checked_bulk_read(session, keys, data):
    results = session.bulk_read(keys).get()
    check_read_results(results, len(keys), data, session)


class TestSession:
    @pytest.mark.parametrize('key, data', [
                             ('', ''),
                             ('', 'data'),
                             ('without_group_key_1', ''),
                             ('without_group_key_2', 'data'),
                             ("without_group_key_3", '309u8ryeygwvfgadd0u9g8y0ahbg8')])
    def test_write_without_groups(self, server, simple_node, key, data):
        session = make_session(node=simple_node,
                               test_name='TestSession.test_write_without_groups')
        result = session.write_data(key, data)
        try:
            result.get()
        except elliptics.Error as e:
            assert e.message.message == 'insufficient results count due to'\
                ' checker: 0 of 1 (1): No such device or address: -6'
        else:
            pytest.fail('Failed: DID NOT RAISE')

    @pytest.mark.parametrize('key, data, exception', [
                             #('', '', elliptics.core.NotFoundError),
                             #('all_group_key_1', '', elliptics.core.NotFoundError),
                             ('', 'data', None),
                             ('all_group_key_2', 'data', None),
                             ("all_group_key_3", '309u8ryeygwvfgadd0u9g8y0ahbg8',
                              None)])
    def test_write_to_all_groups(self, server, simple_node,
                                 key, data, exception):
        session = make_session(node=simple_node,
                               test_name='TestSession.test_write_to_all_groups')
        groups = session.routes.groups()
        session.groups = groups

        if exception:
            with pytest.raises(exception):
                checked_write(session, key, data)
        else:
            checked_write(session, key, data)

    def test_write_to_one_group(self, server, simple_node):
        data = 'some data'
        session = make_session(node=simple_node,
                               test_name='TestSession.test_write_to_one_group')
        for group in session.routes.groups():
            tmp_key = 'one_groups_key_' + str(group)
            session.groups = [group]
            checked_write(session, tmp_key, data)

            other_groups = list(session.routes.groups())
            other_groups.remove(group)
            session.groups = other_groups
            with pytest.raises(elliptics.NotFoundError):
                results = session.read_data(tmp_key).get()
                assert results == []

    def test_write_namespace(self, server, simple_node):
        key = 'namespaced_key'
        ns1 = 'namesapce 1'
        ns2 = 'namespace 2'
        data1 = 'some data 1'
        data2 = 'unique data 2'
        session = make_session(node=simple_node,
                               test_name='TestSession.test_write_namespace')

        groups = session.routes.groups()
        session.groups = groups

        session.set_namespace(ns1)
        checked_write(session, key, data1)

        session.set_namespace(ns2)
        checked_write(session, key, data2)

        session.set_namespace(ns1)
        checked_read(session, key, data1)

        session.set_namespace(ns2)
        checked_read(session, key, data2)

    @pytest.mark.parametrize('key, data, offset, size', [
                             ('diff key 1', 'init data', 0, 4),
                             ('diff key 1', 'rewrite data', 2, 0)
                             ])
    def test_different_writes(self, server, simple_node,
                              key, data, offset, size):
        pass

    def test_write_append(self, server, simple_node):
        key1 = 'append_key_1'
        key2 = 'append_key_2'
        data1 = 'some data 1'
        data2 = 'some data 2'
        session = make_session(node=simple_node,
                               test_name='TestSession.test_write_append')
        groups = session.routes.groups()
        session.groups = groups

        session.ioflags = elliptics.io_flags.default
        checked_write(session, key1, data1)
        checked_read(session, key1, data1)

        session.ioflags |= elliptics.io_flags.append
        checked_write(session, key1, data2)
        checked_read(session, key1, data1 + data2)

        checked_write(session, key2, data1)
        checked_read(session, key2, data1)

        checked_write(session, key2, data2)
        checked_read(session, key2, data1 + data2)

    def test_bulk_write_read(self, server, simple_node):
        session = make_session(node=simple_node,
                               test_name='TestSession.test_bulk_write_read')
        groups = session.routes.groups()
        session.groups = groups

        data = 'data'

        keys = ['bulk key ' + str(i) for i in xrange(100)]

        checked_bulk_write(session, [(key, data) for key in keys], data)
        checked_bulk_read(session, keys, data)

        session.set_namespace('bulk additional namespace')
        checked_bulk_write(session, dict.fromkeys(keys, 'data'), data)
        checked_bulk_read(session, keys, data)

    def test_write_cas(self, server, simple_node):
        session = make_session(node=simple_node,
                               test_name='TestSession.test_write_cas')
        groups = session.routes.groups()
        session.groups = groups

        key = 'cas key'
        data1 = 'data 1'
        data2 = 'data 2'

        checked_write(session, key, data1)
        checked_read(session, key, data1)

        results = session.write_cas(key, data2, session.transform(data1)).get()
        check_write_results(results, len(session.groups), data2, session)
        checked_read(session, key, data2)

        ndata = write_cas_converter(data2)
        results = session.write_cas(key, write_cas_converter).get()
        check_write_results(results, len(session.groups), ndata, session)
        checked_read(session, key, ndata)

    def test_prepare_write_commit(self, server, simple_node):
        session = make_session(node=simple_node,
                               test_name='TestSession.test_prepare_write_commit')
        session.groups = [session.routes.groups()[0]]

        routes = session.routes.filter_by_groups(session.groups)
        pos, records, addr, back = (0, 0, None, 0)

        for id, address, backend in routes.get_unique_routes():
            ranges = routes.get_address_backend_ranges(address, backend)
            statistics = session.monitor_stat(address, elliptics.monitor_stat_categories.backend).get()[0].statistics
            session._node._logger.log(elliptics.log_level.debug, "monitor: stat: {0}".format(statistics))
            records_in_blob = statistics['backends']['{0}'.format(backend)]['backend']['config']['records_in_blob']

            for i, (begin, end) in enumerate(ranges):
                if int(str(end), 16) - int(str(begin), 16) > records_in_blob * 2:
                    pos = int(str(begin), 16)
                    records = records_in_blob * 2
                    addr, back = address, backend

        assert pos
        assert records

        for i in range(pos, pos + records):
            r = session.write_data(elliptics.Id(format(i, 'x')), 'data').get()
            assert len(r) == 1
            assert r[0].address == addr

        pos_id = elliptics.Id(format(i, 'x'))
        prepare_size = 1<<10
        data = 'a' + 'b' * (prepare_size - 2) + 'c'

        session.write_prepare(pos_id, data[0], 0, 1<<10).get()
        session.write_plain(pos_id, data[1:-1], 1).get()
        session.write_commit(pos_id, data[-1], prepare_size - 1, prepare_size).get()

        assert session.read_data(pos_id).get()[0].data == data
