# =============================================================================
# 2015+ Copyright (c) Budnik Andrey <budnik27@gmail.com>
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
import elliptics
import zlib
import json
import hashlib
try:
    import urllib.request as urllib_req
except ImportError:
    import urllib2 as urllib_req


def get_top(remote, port):
    url = 'http://' + remote + ':' + port + '/top'
    data = urllib_req.urlopen(url).read()
    json_data = zlib.decompress(data)
    return json.loads(json_data)

def has_key(key, keys):
    for k in keys:
        if k['id'] == key:
            return True
    return False

def check_keys_fields(keys):
    for k in keys:
        assert k['group']
        assert k['id']
        assert k['size']
        assert k['frequency']

class TestMonitorTop:
    def test_single_write(self, server, simple_node):
        session = make_session(node=simple_node,
                               test_name='TestMonitorTop.test_single_write')
        groups = session.routes.groups()
        session.groups = groups

        test_key = 'one_key'
        session.write_data(test_key, 'some_data').get()
        session.read_latest(test_key).get()

        test_key = hashlib.sha512(test_key).hexdigest()
        keys = []
        for remote, port in zip(server.remotes, server.monitors):
            remote = remote.split(':')[0]
            response = get_top(remote, port)
            keys = response['top']['top_by_size']
            if has_key(test_key, keys):
                break
        assert has_key(test_key, keys)
        check_keys_fields(keys)
