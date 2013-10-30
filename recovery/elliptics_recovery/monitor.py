# =============================================================================
# 2013+ Copyright (c) Kirill Smorodinnikov <shaitkir@gmail.com>
# 2013+ Copyright (c) Alexey Ivanov <rbtz@ph34r.me>
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

"""
Wrapper for monitoring data and working with it in user code
"""

import os
import socket

from datetime import datetime
from threading import Thread
from multiprocessing import Manager

from .utils.misc import logged_class
from .stat import Stats

from BaseHTTPServer import HTTPServer
from SimpleHTTPServer import SimpleHTTPRequestHandler


@logged_class
class StatsProxy(object):
    """
    Very simple wrapper that forwards counter and timer methods to queue.
    Also it provides access to sub-stats via []
    """
    COUNTER = 1
    TIMER = 2

    def __init__(self, queue, prefix=''):
        self.queue = queue
        self.prefix = prefix

    def counter(self, name, value):
        try:
            self.queue.put_nowait((self.prefix, self.COUNTER, name, value))
        except Exception as e:
            self.log.error("Got an error during counter update: {0}".format(e))

    def timer(self, name, milestone):
        try:
            self.queue.put_nowait((self.prefix, self.TIMER, name, milestone, datetime.now()))
        except Exception as e:
            self.log.error("Got an error during timer update: {0}".format(e))

    def __getitem__(self, item):
        prefix = item
        if self.prefix:
            prefix = '\\'.join([self.prefix, prefix])
        return StatsProxy(self.queue, prefix=prefix)

@logged_class
class Monitor(object):
    """
    Contains monitoring data and provides interface for manipulating it from detached threads/processes
    """
    def __init__(self, ctx, port):
        self.ctx = ctx
        self.port = port
        self.manager = Manager()
        self.queue = self.manager.Queue()
        self.stats = StatsProxy(self.queue)
        self.__shutdown_request = False
        self.__stats = Stats('monitor')
        self.stats_file = 'stats'

        self.d_thread = Thread(target=self.data_thread, name="MonitorDataThread")
        self.d_thread.daemon = True

        if self.port:
            if socket.has_ipv6:
                HTTPServer.address_family = socket.AF_INET6
                address = '::'
            else:
                HTTPServer.address_family = socket.AF_INET
                address = '0.0.0.0'
            server_address = (address, self.port)
            self.httpd = HTTPServer(server_address, SimpleHTTPRequestHandler)
            self.l_thread = Thread(target=self.listen_thread, name="MonitorListenThread")
            self.l_thread.daemon = True

        self.u_thread = Thread(target=self.update_thread, name="MonitorUpdateThread")
        self.u_thread.daemon = True

        self.d_thread.start()
        if self.port:
            self.l_thread.start()
        self.u_thread.start()

    def update(self):
        """
        Writes to file current stats
        """
        stats_file_tmp = os.path.join(self.ctx.tmp_dir, self.stats_file + '.tmp')
        with open(stats_file_tmp, 'w') as f:
            f.write(str(self.__stats))
            f.write('\n')
        os.rename(stats_file_tmp, self.stats_file + '.txt')

    def data_thread(self):
        """
        TODO: Not very pythonish interface, but OK for now.
        """
        while not self.__shutdown_request:
            try:
                data = self.queue.get(block=True)
            except EOFError:
                break
            except Exception as e:
                self.log.error("Failed to wait on queue: {0}".format(e))
                continue

            try:
                prefix = data[0]
                stats = self.__stats

                # If prefix was set then use sub stat
                if prefix:
                    for sub in prefix.split('\\'):
                        stats = stats[sub]

                # Use different handling for different stat flavours
                flavour = data[1]
                if flavour == StatsProxy.COUNTER:
                    _, _, name, value = data
                    counter = getattr(stats.counter, name)
                    if value > 0:
                        counter += value
                    else:
                        counter -= -value
                elif flavour == StatsProxy.TIMER:
                    _, _, name, milestone, ts = data
                    timer = getattr(stats.timer, name, ts)
                    timer(milestone)
                else:
                    RuntimeError("Unknown flavour: {0}".format(data))
            except Exception as e:
                self.log.error("Failed to process: {0}: {1}".format(data, e))

    def listen_thread(self):
        sa = self.httpd.socket.getsockname()
        self.log.debug("Serving HTTP on {0}:{1} port...".format(sa[0], sa[1]))
        self.httpd.serve_forever()

    def update_thread(self, seconds=1):
        """
        Periodically saves stats to file
        """
        from time import sleep
        while not self.__shutdown_request:
            try:
                self.update()
            except Exception as e:
                self.log.error("Got an error during stats update: {0}".format(e))
            sleep(seconds)

    def shutdown(self):
        """
        FIXME: We also need a condition variable per thread to really check that thread is finished
        """
        self.__shutdown_request = True
        if self.port:
            self.httpd.shutdown()
