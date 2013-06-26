"""
Wrapper for monitoring data and working with it in user code
"""

import os

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
            '\\'.join([self.prefix, prefix])
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
        self.__stats = Stats('monitor')
        self.stats_file = 'stats'

        self.d_thread = Thread(target=self.data_thread, name="MonitorDataThread")
        self.d_thread.daemon = True

        if port:
            server_address = ('0.0.0.0', port)
            self.httpd = HTTPServer(server_address, SimpleHTTPRequestHandler)
            self.l_thread = Thread(target=self.listen_thread, name="MonitorListenThread")
            self.l_thread.daemon = True

        self.u_thread = Thread(target=self.update_thread, name="MonitorUpdateThread")
        self.u_thread.daemon = True

        self.d_thread.start()
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
        while True:
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

    def update_thread(self, period=1):
        """
        Periodically saves stats to file
        """
        from select import select
        while True:
            try:
                self.update()
            except Exception as e:
                self.log.error("Got an error during stats update: {0}".format(e))
            select([], [], [], period)
