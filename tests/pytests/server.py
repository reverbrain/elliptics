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
import os
import shutil
sys.path.insert(0, "")  # for running from cmake


class Servers:
    def __init__(self,
                 groups=[1],
                 without_cocaine=False):
        import json
        import subprocess
        self.path = 'servers'
        if os.path.exists(self.path):
            shutil.rmtree(self.path)
        os.mkdir(self.path)

        config = dict()
        config['srw'] = not without_cocaine
        config['fork'] = True
        config['monitor'] = True
        config['path'] = self.path
        servers = []
        for g in groups:
            for i in xrange(3):
                servers.append({'group': g})
        config['servers'] = servers
        js = json.dumps(config)

        print js
        self.p = subprocess.Popen(args=['../dnet_run_servers'],
                                  stdin=subprocess.PIPE,
                                  stdout=subprocess.PIPE)

        self.p.stdin.write(js + '\0')

        assert self.p.poll() is None

        while self.p.poll() is None:
            js = self.p.stdout.readline()
            if js:
                self.config = json.loads(js)
                break

        assert self.p.poll() is None

        self.remotes = [str(x['remote']) for x in self.config['servers']]
        self.monitors = [str(x['monitor']) for x in self.config['servers']]

    def stop(self):
        if self.p and self.p.poll() is None:
            self.p.terminate()
            self.p.wait()

        if os.path.exists(self.path):
            shutil.rmtree(self.path)


@pytest.fixture(scope='session')
def server(request):
    if request.config.option.remotes:
        return None

    groups = [int(g) for g in request.config.option.groups.split(',')]

    servers = Servers(groups=groups,
                      without_cocaine=request.config.option.without_cocaine,)

    request.config.option.remotes = servers.remotes
    request.config.option.monitors = servers.monitors

    def fin():
        print "Finilizing Servers"
        servers.stop()
    request.addfinalizer(fin)

    return servers
