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
from conftest import make_session
import pytest
import md5
import elliptics


def format_result(node, backend, result, counter):
    return "{0}, key: {1}, user_flags: {2}, timestamp: {3}, status: {4}, size: {5}, hashed_data: {6}, iterator_id: {7}".format(
        format_stat(node, backend, result, counter),
        result.response.key,
        result.response.user_flags,
        result.response.timestamp,
        result.response.status,
        result.response.size,
        md5.new(result.response_data).hexdigest(),
        result.id)


def format_stat(node, backend, result, counter):
    return "node: {0}/{1}: filtered_keys: {2} iterated_keys: {3}, total_keys: {4}".format(
        node,
        backend,
        counter,
        result.response.iterated_keys,
        result.response.total_keys)


def check_iterator_results(node, backend, iterator, session, node_id, no_meta=False):
    counter = 0
    for result in iterator:
        assert result.status == 0, "if iterator is ok status of result should be 0"
        if result.response.status != 0:
            #this is one of keepalive response, we should skip it because it contains iterator statistics only
            print format_stat(node, backend, result, counter)
            continue

        if no_meta:
            assert result.response.user_flags == 0
            assert result.response.timestamp == elliptics.Time(2 ** 64 - 1, 2 ** 64 - 1)

        # Test flow control on after result
        if counter == 0:
            print "Pause iterator"
            session.pause_iterator(node_id, result.id)
            print "Continue iterator"
            session.continue_iterator(node_id, result.id)

        counter += 1
        print format_result(node, backend, result, counter)


def convert_ranges(ranges):
    def make_range(begin, end):
        range = elliptics.IteratorRange()
        range.key_begin = begin
        range.key_end = end
        return range
    return (make_range(*r) for r in ranges)


def invert_ranges(ranges):
    inverted_ranges = []
    ID_MIN = elliptics.Id([0] * 64, 0)
    ID_MAX = elliptics.Id([255] * 64, 0)

    if ranges[0][0] != ID_MIN:
        inverted_ranges.append((ID_MIN, ranges[0][0]))
    for i in xrange(1, len(ranges)):
        inverted_ranges.append((ranges[i - 1][1], ranges[i][0]))
    if ranges[-1][1] != ID_MAX:
        inverted_ranges.append((ranges[-1], [1], ID_MAX))

    return convert_ranges(inverted_ranges)


@pytest.mark.trylast
class TestSession:
    def test_iterate_default(self, server, simple_node):
        '''
        Runs iterator on first node/backend from route-list without specified ranges and special flags
        '''
        session = make_session(node=simple_node,
                               test_name='TestSession.test_iterate_one_backend')
        session.groups = session.routes.groups()
        routes = session.routes
        addresses_with_backends = routes.addresses_with_backends()
        first_node, first_backend = addresses_with_backends[0]
        node_id = routes.get_address_backend_route_id(first_node, first_backend)

        iterator = session.start_iterator(
            id=node_id,
            ranges=[],
            type=elliptics.iterator_types.network,
            flags=elliptics.iterator_flags.default,
            time_begin=elliptics.Time(0, 0),
            time_end=elliptics.Time(2 ** 64 - 1, 2 ** 64 - 1))

        check_iterator_results(first_node, first_backend, iterator, session, node_id)

    def test_iterate_one_range(self, server, simple_node):
        '''
        Runs iterator on first node/backend from route-list with using only first range of it.
        '''
        session = make_session(node=simple_node,
                               test_name='TestSession.test_iterate_one_range')
        session.groups = session.routes.groups()
        node_id, node, backend = iter(session.routes.get_unique_routes()[0])
        ranges = convert_ranges((session.routes.get_address_backend_ranges(node, backend)[0],))

        iterator = session.start_iterator(
            id=node_id,
            ranges=ranges,
            type=elliptics.iterator_types.network,
            flags=elliptics.iterator_flags.key_range,
            time_begin=elliptics.Time(0, 0),
            time_end=elliptics.Time(2 ** 64 - 1, 2 ** 64 - 1))

        check_iterator_results(node, backend, iterator, session, node_id)

    def test_iterate_all_node_ranges(self, server, simple_node):
        '''
        Runs iterator on first node/backend from route-list with using all ranges covered by it.
        '''
        session = make_session(node=simple_node,
                               test_name='TestSession.test_iterate_all_node_ranges')
        session.groups = session.routes.groups()
        node_id, node, backend = iter(session.routes.get_unique_routes()[0])
        ranges = convert_ranges(session.routes.get_address_backend_ranges(node, backend))

        iterator = session.start_iterator(
            id=node_id,
            ranges=ranges,
            type=elliptics.iterator_types.network,
            flags=elliptics.iterator_flags.key_range,
            time_begin=elliptics.Time(0, 0),
            time_end=elliptics.Time(2 ** 64 - 1, 2 ** 64 - 1))

        check_iterator_results(node, backend, iterator, session, node_id)

    def test_iterate_all_node_ranges_with_timestamp(self, server, simple_node):
        '''
        Runs iterator on first node/backend from route-list with using all ranges covered by it
        and timetamps that specifies period from 30 second before now to now.
        '''
        session = make_session(node=simple_node,
                               test_name='TestSession.test_iterate_all_node_ranges_with_timestamp')
        session.groups = session.routes.groups()
        node_id, node, backend = iter(session.routes.get_unique_routes()[0])
        ranges = convert_ranges(session.routes.get_address_backend_ranges(node, backend))

        end_time = elliptics.Time.now()
        begin_time = end_time
        begin_time.tsec -= 30

        iterator = session.start_iterator(
            id=node_id,
            ranges=ranges,
            type=elliptics.iterator_types.network,
            flags=elliptics.iterator_flags.key_range | elliptics.iterator_flags.ts_range,
            time_begin=begin_time,
            time_end=end_time)

        check_iterator_results(node, backend, iterator, session, node_id)

    def test_iterate_inverted_node_ranges_with_data(self, server, simple_node):
        '''
        Runs iterator on first node/backend from route-list with using inverted ranges
        that aren't covered by this node/backend
        '''
        session = make_session(node=simple_node,
                               test_name='TestSession.test_iterate_inverted_node_ranges')
        session.groups = session.routes.groups()
        node_id, node, backend = iter(session.routes.get_unique_routes()[0])
        ranges = invert_ranges(session.routes.get_address_backend_ranges(node, backend))

        iterator = session.start_iterator(
            id=node_id,
            ranges=ranges,
            type=elliptics.iterator_types.network,
            flags=elliptics.iterator_flags.key_range | elliptics.iterator_flags.data,
            time_begin=elliptics.Time(0, 0),
            time_end=elliptics.Time(2 ** 64 - 1, 2 ** 64 - 1))

        check_iterator_results(node, backend, iterator, session, node_id)

    def test_iterate_all_node_ranges_no_meta(self, server, simple_node):
        '''
        Runs iterator with no_meta on first node/backend from route-list with using all ranges covered by it
        '''
        session = make_session(node=simple_node,
                               test_name='TestSession.test_iterate_all_node_ranges_no_meta')
        session.groups = session.routes.groups()
        node_id, node, backend = iter(session.routes.get_unique_routes()[0])
        ranges = convert_ranges(session.routes.get_address_backend_ranges(node, backend))

        end_time = elliptics.Time.now()
        begin_time = end_time
        begin_time.tsec -= 30

        iterator = session.start_iterator(
            id=node_id,
            ranges=ranges,
            type=elliptics.iterator_types.network,
            flags=elliptics.iterator_flags.key_range | elliptics.iterator_flags.no_meta,
            time_begin=begin_time,
            time_end=end_time)

        check_iterator_results(node, backend, iterator, session, node_id, True)
