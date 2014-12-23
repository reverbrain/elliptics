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
from conftest import set_property, raises, make_session
import elliptics

io_flags = set((elliptics.io_flags.default,
                elliptics.io_flags.append,
                elliptics.io_flags.prepare,
                elliptics.io_flags.commit,
                elliptics.io_flags.overwrite,
                elliptics.io_flags.nocsum,
                elliptics.io_flags.plain_write,
                elliptics.io_flags.nodata,
                elliptics.io_flags.cache,
                elliptics.io_flags.cache_only,
                elliptics.io_flags.cache_remove_from_disk))

command_flags = set((elliptics.command_flags.default,
                     elliptics.command_flags.direct,
                     elliptics.command_flags.nolock))

exceptions_policy = set((elliptics.exceptions_policy.no_exceptions,
                         elliptics.exceptions_policy.throw_at_start,
                         elliptics.exceptions_policy.throw_at_wait,
                         elliptics.exceptions_policy.throw_at_get,
                         elliptics.exceptions_policy.throw_at_iterator_end,
                         elliptics.exceptions_policy.default_exceptions))

filters = set((elliptics.filters.positive,
               elliptics.filters.positive,
               elliptics.filters.positive_with_ack,
               elliptics.filters.positive_final,
               elliptics.filters.negative,
               elliptics.filters.negative_with_ack,
               elliptics.filters.negative_final,
               elliptics.filters.all,
               elliptics.filters.all_with_ack,
               elliptics.filters.all_final))

checkers = set((elliptics.checkers.no_check,
                elliptics.checkers.at_least_one,
                elliptics.checkers.all,
                elliptics.checkers.quorum))


class TestSession:
    def test_flags(self):
        assert set(elliptics.io_flags.values.values()) == io_flags
        assert set(elliptics.command_flags.values.values()) == command_flags
        assert set(elliptics.exceptions_policy.values.values()) == exceptions_policy
        assert set(elliptics.filters.values.values()) == filters
        assert set(elliptics.checkers.values.values()) == checkers

    @pytest.mark.parametrize("prop, value", [
        ('timeout', 5),
        ('groups', []),
        ('exceptions_policy', elliptics.exceptions_policy.default_exceptions),
        ('cflags', 0),
        ('ioflags', 0),
        ('timestamp', elliptics.Time(2 ** 64 - 1, 2 ** 64 - 1)),
        ('trace_id', 0),
        ('user_flags', 0)])
    def test_properties_default(self, server, simple_node, prop, value):
        session = elliptics.Session(node=simple_node)
        assert getattr(session, prop) == value

    @pytest.mark.parametrize('prop, setter, getter, values', [
        ('groups', 'set_groups', 'get_groups', (
            [],
            range(1, 100),
            range(1, 100000),
            range(10, 10000))),
        ('cflags', 'set_cflags', 'get_cflags', command_flags),
        ('ioflags', 'set_ioflags', 'get_ioflags', io_flags),
        ('exceptions_policy', 'set_exceptions_policy',
         'get_exceptions_policy', tuple(exceptions_policy) + (
             elliptics.exceptions_policy.throw_at_start |
             elliptics.exceptions_policy.throw_at_wait,

             elliptics.exceptions_policy.throw_at_start |
             elliptics.exceptions_policy.throw_at_wait |
             elliptics.exceptions_policy.throw_at_get |
             elliptics.exceptions_policy.throw_at_iterator_end)),
        ('timeout', 'set_timeout', 'get_timeout', (
         28376487,
         2 ** 63 - 1)),
        ('timestamp', 'set_timestamp', 'get_timestamp', (
         elliptics.Time(0, 0),
         elliptics.Time(2 ** 64 - 1, 2 ** 64 - 1),
         elliptics.Time(238689126897, 1723861827))),
        ('trace_id', None, None, (
         0,
         32423946,
         2 ** 32 - 1)),
        ('user_flags', 'set_user_flags', 'get_user_flags', (
         0,
         438975345,
         2 ** 64 - 1))])
    def test_properties(self, server, simple_node,
                        prop, setter, getter, values):
        session = elliptics.Session(node=simple_node)
        assert type(session) == elliptics.Session
        for value in values:
            set_property(session, prop, value,
                         setter=setter,
                         getter=getter)

    def test_resetting_timeout(self, server, simple_node):
        session = make_session(node=simple_node,
                               test_name='TestSession.test_resetting_timeout')
        assert session.timeout == 5  # check default timeout value
        session.timeout = 1  # set different value
        assert session.timeout == 1  # check that the value has been set
        session.timeout = 0  # set timeout to 0 which should reset to default
        assert session.timeout == 5  # check default timeout value

    @pytest.mark.parametrize("prop, value", [
                             ('cflags', 2 ** 64),
                             ('ioflags', 2 ** 32),
                             ('exceptions_policy', 2 ** 32),
                             ('timeout', 2 ** 63),
                             ('trace_id', 2 ** 64),
                             ('user_flags', 2 ** 64)])
    def test_properties_out_of_limits(self, server, simple_node, prop, value):
        session = elliptics.Session(simple_node)
        pytest.raises(OverflowError,
                      "set_property(session, '{0}', {1})"
                      .format(prop, value))

    def test_clone(self, server, simple_node):
        orig_s = make_session(node=simple_node,
                              test_name='TestSession.test_clone')

        orig_s.groups = [1, 2, 3]
        orig_s.timeout = 13
        orig_s.exceptions_policy = elliptics.exceptions_policy.throw_at_wait
        orig_s.cflags = elliptics.command_flags.direct
        orig_s.ioflags = elliptics.io_flags.overwrite
        orig_s.timestamp = elliptics.Time(213, 415)
        orig_s.trace_id = 731
        orig_s.user_flags = 19731

        clone_s = orig_s.clone()

        assert clone_s.groups == orig_s.groups == [1, 2, 3]
        assert clone_s.timeout == orig_s.timeout == 13
        assert clone_s.exceptions_policy == orig_s.exceptions_policy == \
            elliptics.exceptions_policy.throw_at_wait
        assert clone_s.cflags == orig_s.cflags == elliptics.command_flags.direct
        assert clone_s.ioflags == orig_s.ioflags == elliptics.io_flags.overwrite
        assert clone_s.timestamp == orig_s.timestamp == elliptics.Time(213, 415)
        assert clone_s.trace_id == orig_s.trace_id == 731
        assert clone_s.user_flags == orig_s.user_flags == 19731
