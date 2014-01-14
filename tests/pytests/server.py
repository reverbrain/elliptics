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
sys.path.insert(0, "")  # for running from cmake


class Server:
    server_no = 0
    ports = []

    def __init__(self,
                 log_level=4,
                 group=1, remotes=[],
                 port=random.randint(2000, 8000),
                 wait_timeout=30, check_timeout=50,
                 cache_size=1024 * 1024 * 256, caches_number=16,
                 indexes_shard_count=2):
        self.name = 'server_{0}'.format(Server.server_no)
        Server.server_no += 1
        self.log_path = '/dev/null'
        self.log_level = log_level
        self.group = group
        self.remotes = remotes
        self.port = port
        self.wait_timeout = wait_timeout
        self.check_timeout = check_timeout
        self.cache_size = cache_size
        self.caches_number = caches_number
        self.indexes_shard_count = indexes_shard_count
        self.addr = 'shaitan01h.dev.yandex.net:{0}:2'.format(self.port)
        self.history = 'history'
        self.data_path = 'blob'
        self.cfg_path = 'cfg'

        while self.port in Server.ports:
            self.port = random.randint(2000, 8000)
        Server.ports.append(self.port)

    def start(self):
        import subprocess
        import time
        self.__create_config__()
        self.p = subprocess.Popen(['../dnet_ioserv', '-c', self.cfg_path],
                                  cwd=self.name)
        time.sleep(0.1)
        assert self.p.poll() is None

    def status(self):
        return 0

    def stop(self):
        self.p.terminate()
        self.p.wait()
        assert self.p.poll() == 0
        import shutil
        shutil.rmtree(self.name)

    def __create_config__(self):
        import os
        if not os.path.exists(self.name):
            os.mkdir(self.name)
        if not os.path.exists(self.name + '/' + self.history):
            os.mkdir(self.name + '/' + self.history)
        if not os.path.exists(self.name + '/' + self.data_path):
            os.mkdir(self.name + '/' + self.data_path)
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
        addr = {5}
        wait_timeout = 5
        check_timeout = 20
        auth_cookie = unique_storage_cookie
        cache_size = 102400
        indexes_shard_count = 2
        monitor_port = 20000
        server_net_prio = 0x20
        client_net_prio = 6
        flags = 4
        backend = blob
        blob_size = 10M
        records_in_blob = 10000000
        blob_flags = 6
        blob_cache_size = 0
        defrag_timeout = 3600
        defrag_percentage = 25
        sync = 5
        data = {6}
        iterate_thread_num = 1
        '''.format(self.log_path, int(self.log_level), self.group,
                   self.history, ' '.join(self.remotes), self.addr,
                   self.data_path)
        with open(self.name + '/' + self.cfg_path, 'w') as f:
            f.write(config)


@pytest.fixture(scope='module')
def server(request):
    if request.config.option.remote != []:
        return None
    server = Server(remotes=['shaitan01h.dev.yandex.net:2025:2'],
                    port=2025)

    def fin():
        print "Finilizing Servers"
        server.stop()
    request.addfinalizer(fin)

    server.start()
    return server
