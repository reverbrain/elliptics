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
import random
import sys
import os
sys.path.insert(0, "")  # for running from cmake


class Server:
    def __init__(self,
                 log_level=4,
                 group=1, remotes=[],
                 port=2025,
                 wait_timeout=30, check_timeout=50,
                 cache_size=1024 * 1024 * 256, caches_number=16,
                 indexes_shard_count=2, locator_port=20053, plugin_path="", without_cocaine=False,
                 monitor_port=20000):
        from socket import gethostname
        self.name = 'server_{0}'.format(port)
        self.without_cocaine = without_cocaine
        self.log_path = '/dev/stderr'
        self.log_level = log_level
        self.group = group
        self.port = port
        self.wait_timeout = wait_timeout
        self.check_timeout = check_timeout
        self.cache_size = cache_size
        self.caches_number = caches_number
        self.indexes_shard_count = indexes_shard_count
        self.addr = gethostname()
        self.history = 'history'
        self.data_path = 'blob'
        self.cfg_path = 'elliptis.cfg'
        self.plugin_path = plugin_path
        self.runtime_path = 'run'
        self.locator_port = locator_port
        self.monitor_port = monitor_port
        self.remotes = remotes + [self.get_addr()]

    def start(self):
        import subprocess
        import time
        self.__create_config__()
        self.__create_cocaine_config()

        self.p = subprocess.Popen(['../dnet_ioserv', '-c', self.cfg_path],
                                  cwd=self.name)
        time.sleep(1)
        assert self.p.poll() is None
        self.upload_app()

    def __create_manifest__(self):
        manifest_path = os.path.join(self.name, 'dnet_cpp_srw_test_app.manifest')
        with open(manifest_path, 'w') as f:
            import json
            json.dump({
                'type': 'binary',
                'slave': 'dnet_cpp_srw_test_app'
            }, f)

    def __create_profile__(self):
        profile_path = os.path.join(self.name, 'dnet_cpp_srw_test_app.profile')
        with open(profile_path, 'w') as f:
            import json
            json.dump({
                "isolate": {
                    "type": "process",
                    "args": {
                        "spool": "/var/tmp/cocaine/spool"
                    }
                }
            }, f)

    def upload_app(self):
        if self.without_cocaine:
            return
        import subprocess
        self.__create_manifest__()
        self.__create_profile__()

        app = subprocess.Popen(['cocaine-tool', 'app', 'upload',
                                '--manifest', self.name + '/dnet_cpp_srw_test_app.manifest',
                                '--package', '../dnet_cpp_srw_test_app.tar',
                                '--name', 'dnet_cpp_srw_test_app',
                                '--host={0}'.format(self.addr),
                                '--port={0}'.format(self.locator_port)])
        app.wait()
        assert(app.returncode == 0)

        profile = subprocess.Popen(['cocaine-tool', 'profile', 'upload',
                                    '--profile', self.name + '/dnet_cpp_srw_test_app.profile',
                                    '--name', 'dnet_cpp_srw_test_app',
                                    '--host={0}'.format(self.addr),
                                    '--port={0}'.format(self.locator_port)])
        profile.wait()
        assert(profile.returncode == 0)

        import elliptics

        n = elliptics.create_node(remotes=[self.get_addr()], log_level=self.log_level)
        s = elliptics.Session(n)
        s.groups = [self.group]
        s.cflags = elliptics.command_flags.nolock
        s.set_filter(elliptics.filters.all_with_ack)
        s.exec_(id=None, event='dnet_cpp_srw_test_app@start-task').wait()

    def status(self):
        return 0

    def stop(self):
        self.p.terminate()
        self.p.wait()
        assert self.p.poll() == 0
        import shutil
        shutil.rmtree(self.name)

    def get_addr(self):
        return '{0}:{1}:2'.format(self.addr, self.port)

    def __create_config__(self):
        if not os.path.exists(self.name):
            os.mkdir(self.name)
        history_path = os.path.join(self.name, self.history)
        if not os.path.exists(history_path):
            os.mkdir(history_path)
        data_path = os.path.join(self.name, self.data_path)
        if not os.path.exists(data_path):
            os.mkdir(data_path)
        srw_line = 'srw_config = cocaine.cfg'
        if self.without_cocaine:
            srw_line = ''
        config = '''
        log = {0}
        log_level = {1}
        group = {2}
        history = {3}
        io_thread_num = 1
        net_thread_num = 1
        nonblocking_io_thread_num = 1
        join = 1
        remote = {4}
        addr = {5}:{6}:2
        wait_timeout = 5
        check_timeout = 20
        auth_cookie = unique_storage_cookie
        cache_size = 102400
        indexes_shard_count = 2
        monitor_port = {7}
        server_net_prio = 0x20
        client_net_prio = 6
        flags = 4
        {8}
        backend = blob
        blob_size = 10M
        records_in_blob = 10000000
        blob_flags = 6
        blob_cache_size = 0
        defrag_timeout = 3600
        defrag_percentage = 25
        sync = 5
        data = {9}
        iterate_thread_num = 1
        '''.format(self.log_path, int(self.log_level), self.group, self.history,
                   ' '.join(self.remotes), self.addr, self.port, self.monitor_port,
                   srw_line, self.data_path + '/data')
        config_path = os.path.join(self.name, self.cfg_path)
        with open(config_path, 'w') as f:
            f.write(config)

    def __create_cocaine_config(self):
        if self.without_cocaine:
            return
        if not os.path.exists(self.name):
            os.mkdir(self.name)
        runtime_path = os.path.join(self.name, self.runtime_path)
        if not os.path.exists(runtime_path):
            os.mkdir(runtime_path)
        config_path = os.path.join(self.name, 'cocaine.cfg')
        with open(config_path, 'w') as f:
            import json
            json.dump({
                'version': 2,
                'locator': {'port': self.locator_port},
                'paths': {
                    'plugins': self.plugin_path,
                    'runtime_path': self.runtime_path
                },
                'services': {
                    'logging': {'type': 'logging'},
                    'storage': {'type': 'storage'}
                },
                'storages': {
                    'core': {
                        'type': 'elliptics',
                        'args': {
                            'nodes': {self.addr: self.port},
                            'groups': [self.group],
                            'verbosity': self.log_level
                        },
                    }
                },
                'loggers': {'tools': {'type': 'stderr'}}
            }, f)


@pytest.fixture(scope='module')
def server(request):
    if request.config.option.remotes:
        return None

    import socket

    plugin_path = os.path.join(request.config.option.binary_dir, '../cocaine/plugins/')
    groups = [int(g) for g in request.config.option.groups.split(',')]

    servers = []

    ports = random.sample(xrange(2000, 3000), len(groups) * 2)
    locator_ports = random.sample(xrange(4000, 5000), len(groups) * 2)
    monitor_ports = random.sample(xrange(6000, 7000), len(groups) * 2)

    request.config.option.remotes = ['{0}:{1}:2'.format(socket.gethostname(), p) for p in ports]

    nodes_in_group = 2

    for i, g in enumerate(groups):
        for j in range(nodes_in_group):
            servers.append(Server(port=ports[i * nodes_in_group + j],
                                  locator_port=locator_ports[i * nodes_in_group + j],
                                  plugin_path=plugin_path,
                                  without_cocaine=request.config.option.without_cocaine,
                                  remotes=request.config.option.remotes,
                                  group=g,
                                  monitor_port=monitor_ports[i * nodes_in_group + j]))

    def fin():
        print "Finilizing Servers"
        for s in servers:
            s.stop()
    request.addfinalizer(fin)

    for s in servers:
        s.start()

    return servers
