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

import pytest
import sys

sys.path.insert(0, "")  # for running from cmake

from conftest import set_property


def pytest_generate_tests(metafunc):
    if 'properties' in metafunc.fixturenames:
        metafunc.parametrize('properties', [
            ('check_timeout', (
                -2 ** 63 + 1,
                -1,
                0,
                28376487,
                2 ** 63 - 1)),
            ('wait_timeout', (
                0,
                28376487,
                2 ** 32 - 1)),
            ('io_thread_num', (
                -2 ** 31 + 1,
                -1,
                0,
                28376487,
                2 ** 31 - 1)),
            ('net_thread_num', (
                -2 ** 31 + 1,
                -1,
                0,
                28376487,
                2 ** 31 - 1)),
            ('nonblocking_io_thread_num', (
                -2 ** 31 + 1,
                -1,
                0,
                28376487,
                2 ** 31 - 1)),
            ('flags', (
                -2 ** 31 + 1,
                -1,
                0,
                28376487,
                2 ** 31 - 1)),
            ('client_prio', (
                -2 ** 31 + 1,
                -1,
                0,
                28376487,
                2 ** 31 - 1)),
        ])


@pytest.fixture(scope='class')
def cfg():
    import elliptics
    return elliptics.Config()


class TestConfig:
    def test_default(self, cfg):
        assert cfg.check_timeout == 20
        assert cfg.wait_timeout == 5
        assert cfg.io_thread_num == 1
        assert cfg.net_thread_num == 1
        assert cfg.nonblocking_io_thread_num == 1
        assert cfg.flags == 0
        assert cfg.cookie == '\x00' * 32
        assert cfg.client_prio == 0
        assert cfg == cfg.config

    def test_properties(self, cfg, properties):
        prop, values = properties
        for value in values:
            set_property(cfg, prop, value)

    def test_cookie(self, cfg):
        set_property(
            cfg, 'cookie', '', '\x00' * 32)

        set_property(
            cfg, 'cookie', 'x', 'x' + '\x00' * 31)

        set_property(
            cfg, 'cookie', '435sdg453y2sd', '435sdg453y2sd' + '\x00' * 19)

        set_property(
            cfg, 'cookie', 'lsdjhfalkshjdflkjahsglkjhasdkjg',
            'lsdjhfalkshjdflkjahsglkjhasdkjg\x00')

        set_property(
            cfg, 'cookie', '093-4utpoijherg098dfh-98haspdngpapwg9yas',
            '093-4utpoijherg098dfh-98haspdng\x00')

    def test_out_of_limits(self, cfg):
        pytest.raises(OverflowError,
                      set_property, cfg, 'check_timeout', 2 ** 63)

        pytest.raises(OverflowError,
                      set_property, cfg, 'wait_timeout', 2 ** 63)

        pytest.raises(OverflowError,
                      set_property, cfg, 'io_thread_num', 2 ** 32)

        pytest.raises(OverflowError,
                      set_property, cfg, 'net_thread_num', 2 ** 32)

        pytest.raises(OverflowError,
                      set_property, cfg, 'nonblocking_io_thread_num', 2 ** 32)

        pytest.raises(OverflowError,
                      set_property, cfg, 'flags', 2 ** 32)

        pytest.raises(OverflowError,
                      set_property, cfg, 'client_prio', 2 ** 32)
