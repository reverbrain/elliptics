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
from server import server, Server


import elliptics


class TestSession:
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
        session = elliptics.Session(simple_node)
        assert getattr(session, prop) == value

    @pytest.mark.parametrize('prop, setter, getter, values', [
        ('groups', 'set_groups', 'get_groups', (
            [],
            range(1, 100),
            range(1, 100000),
            range(10, 10000))),
        ('cflags', 'set_cflags', 'get_cflags', (
            elliptics.command_flags.default,
            elliptics.command_flags.direct,
            elliptics.command_flags.nolock)),
        ('ioflags', 'set_ioflags', 'get_ioflags', (
            elliptics.io_flags.default,
            elliptics.io_flags.append,
            elliptics.io_flags.prepare,
            elliptics.io_flags.commit,
            elliptics.io_flags.overwrite,
            elliptics.io_flags.nocsum,
            elliptics.io_flags.plain_write,
            elliptics.io_flags.nodata,
            elliptics.io_flags.cache,
            elliptics.io_flags.cache_only,
            elliptics.io_flags.cache_remove_from_disk)),
        ('exceptions_policy', 'set_exceptions_policy',
         'get_exceptions_policy', (
             elliptics.exceptions_policy.no_exceptions,
             elliptics.exceptions_policy.throw_at_start,
             elliptics.exceptions_policy.throw_at_wait,
             elliptics.exceptions_policy.throw_at_get,
             elliptics.exceptions_policy.throw_at_iterator_end,
             elliptics.exceptions_policy.default_exceptions,

             elliptics.exceptions_policy.throw_at_start |
             elliptics.exceptions_policy.throw_at_wait,

             elliptics.exceptions_policy.throw_at_start |
             elliptics.exceptions_policy.throw_at_wait |
             elliptics.exceptions_policy.throw_at_get |
             elliptics.exceptions_policy.throw_at_iterator_end)),
        ('timeout', 'set_timeout', 'get_timeout', (
         28376487,
         2 ** 32 - 1)),
        ('timestamp', 'set_timestamp', 'get_timestamp', (
         elliptics.Time(0, 0),
         elliptics.Time(2 ** 64 - 1, 2 ** 64 - 1),
         elliptics.Time(238689126897, 1723861827))),
        ('trace_id', None, None, (
         0,
         32423946,
         0 | elliptics.trace_bit,
         123121435 | elliptics.trace_bit,
         2 ** 32 - 1)),
        ('user_flags', 'set_user_flags', 'get_user_flags', (
         0,
         438975345,
         2 ** 64 - 1))])
    def test_properties(self, server, simple_node,
                        prop, setter, getter, values):
        session = elliptics.Session(simple_node)
        assert type(session) == elliptics.Session
        for value in values:
            set_property(session, prop, value,
                         setter=setter,
                         getter=getter)

    def test_trace_bit(self, server, simple_node):
        assert elliptics.trace_bit == 2 ** 31

    def test_resetting_timeout(self, server, simple_node):
        session = elliptics.Session(simple_node)
        assert session.timeout == 5  # check default timeout value
        session.timeout = 1  # set different value
        assert session.timeout == 1  # check that the value has been set
        session.timeout = 0  # set timeout to 0 which should reset to default
        assert session.timeout == 5  # check default timeout value

    @pytest.mark.parametrize("prop, value", [
                             ('cflags', 2 ** 64),
                             ('ioflags', 2 ** 32),
                             ('exceptions_policy', 2 ** 32),
                             ('timeout', 2 ** 32),
                             ('trace_id', 2 ** 32),
                             ('user_flags', 2 ** 64)])
    def test_properties_out_of_limits(self, server, simple_node, prop, value):
        session = elliptics.Session(simple_node)
        pytest.raises(OverflowError,
                      "set_property(session, '{0}', {1})"
                      .format(prop, value))

    @pytest.mark.parametrize('key, data', [
                             ('', ''),
                             ('', 'data'),
                             ('key', ''),
                             ('key', 'data'),
                             ("q839rhuij 0", '309u8ryeygwvfgadd0u9g8y0ahbg8')])
    def test_write_without_groups(self, server, simple_node, key, data):
        session = elliptics.Session(simple_node)
        result = session.write_data(key, data)
        try:
            result.get()
        except elliptics.Error as e:
            assert e.message.message == 'insufficient results count due to'\
                ' checker: 0 of 0 (0): No such device or address: -6'
        else:
            pytest.fail('Failed: DID NOT RAISE')

    @pytest.mark.parametrize('key, data, exception', [
                             ('', '', elliptics.core.NotFoundError),
                             ('key', '', elliptics.core.NotFoundError),
                             ('', 'data', None),
                             ('key', 'data', None),
                             ("q839rhuij0", '309u8ryeygwvfgadd0u9g8y0ahbg8',
                              None)])
    def test_write_to_all_groups(self, server, simple_node,
                                 key, data, exception):
        session = elliptics.Session(simple_node)
        session.groups = session.routes.groups()
        results = session.write_data(key, data)

        if exception:
            try:
                results.get()
            except exception:
                pass
            else:
                pytest.fail('Failed: DID NOT RAISE')
            return

        results = results.get()
        assert len(results) == len(session.routes.groups())
        for r in results:
            assert type(r) == elliptics.core.LookupResultEntry
            #assert r.size == len(data)
            assert r.error.code == 0
            assert r.error.message == ''
