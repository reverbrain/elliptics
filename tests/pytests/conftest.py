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
    parser.addoption('--remotes', action='append', default=[],
                     help='Elliptics node address')
    parser.addoption('--groups', action='store', help='elliptics groups', default='1,2,3')
    parser.addoption('--loglevel', type='choice', choices=xrange(5), default=1)

    parser.addoption('--without-cocaine', action='store_true', default=False,
                     help='Turns off exec tests that are connected with cocaine')


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
    simple_node = elliptics.Node(elliptics.Logger("/dev/stderr", 4))
    for r in request.config.option.remotes:
        simple_node.add_remote(elliptics.Address.from_host_port_family(r))

    def fin():
        print "Finilizing simple node"
    request.addfinalizer(fin)
    return simple_node


class PassthroughWrapper(object):
    ''' Wrapper to assure session/node destroy sequence: session first, node last '''
    def __init__(self, node, session):
        self.node = node
        self.session = session

    def __getattr__(self, name):
        return getattr(self.session, name)

    def __del__(self):
        del self.session
        del self.node


def connect(endpoints, groups, **kw):
    remotes = []
    for r in endpoints:
        remotes.append(elliptics.Address.from_host_port_family(r))

    def rename(kw, old, new):
        if old in kw:
            kw[new] = kw.pop(old)

    # drop impedeing attrs, just in case
    kw.pop('elog', None)
    kw.pop('cfg', None)
    kw.pop('remotes', None)
    # rename good names to required bad ones
    rename(kw, 'logfile', 'log_file')
    rename(kw, 'loglevel', 'log_level')

    n = elliptics.create_node(**kw)

    for r in remotes:
        try:
            n.add_remote(r)
        except Exception as e:
            import sys
            sys.stderr.write("{0}\n".format(repr(e)))
            pass

    s = elliptics.Session(n)
    s.add_groups(groups)

#    return PassthroughWrapper(n, s)
    return s


@pytest.fixture
def elliptics_remotes(request):
    return request.config.option.remotes


@pytest.fixture
def elliptics_groups(request):
    return [int(g) for g in request.config.option.groups.split(',')]


#@pytest.fixture(scope='module')
@pytest.fixture
def elliptics_client(request):
    ''' Initializes client connection to elliptics.
    Returns Session object.
    '''
    remote = request.config.option.remotes
    groups = [int(g) for g in request.config.option.groups.split(',')]
    loglevel = request.config.option.loglevel
    logfile = 'client.log'
    return connect(remote, groups, loglevel=loglevel, logfile=logfile)
    # client = connect([remote], groups, loglevel=loglevel)
    # client.set_filter(elliptics.filters.all_with_ack)
    # return client
