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
import os
import shutil
sys.path.insert(0, "")  # for running from cmake


class Servers:
    def __init__(self,
                 groups=[1],
                 without_cocaine=False,
                 nodes_count=2,
                 backends_count=2,
                 isolated=False,
                 path='servers'):
        import json
        import subprocess
        self.path = path
        if os.path.exists(self.path):
            shutil.rmtree(self.path)
        os.mkdir(self.path)

        config = dict()
        config['srw'] = not without_cocaine
        config['fork'] = True
        config['monitor'] = True
        config['path'] = self.path
        config['isolated'] = isolated
        config['top_period'] = 5 * 60
        config['top_k'] = 50
        config['top_events_limit'] = 1000
        servers = []
        for node in xrange(nodes_count):
            backends = []
            for g in groups:
                for i in xrange(backends_count):
                    backends.append({'group': g, 'records_in_blob': 100})
            servers.append({'backends': backends})
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
