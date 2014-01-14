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

import elliptics


def pytest_addoption(parser):
    parser.addoption('--remote', action='append', default=[],
                     help='Elliptics node address')


def set_property(obj, prop, value, check_value=None,
                 getter=None, setter=None):
    check_value = check_value if check_value else value
    setattr(obj, prop, value)
    assert getattr(obj, prop) == check_value
    if setter:
        getattr(obj, setter)(value)
    assert getattr(obj, prop) == check_value
    if getter:
        assert getattr(obj, getter)() == check_value
    assert getattr(obj, prop) == check_value


def raises(type, message, func, *args, **kwargs):
    exception = pytest.raises(type, func, *args, **kwargs)
    assert exception.value.message == message


@pytest.fixture(scope='class')
def simple_node(request):
    simple_node = elliptics.Node(elliptics.Logger("/dev/null", 4))
    for r in request.config.option.remote:
        simple_node.add_remote(r)

    if len(request.config.option.remote) == 0:
        simple_node.add_remote('shaitan01h.dev.yandex.net:2025:2')

    def fin():
        print "Finilizing simple node"
    request.addfinalizer(fin)
    return simple_node
