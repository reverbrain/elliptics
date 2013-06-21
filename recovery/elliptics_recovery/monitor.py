"""
Wrapper for monitoring data and working with it in user code
"""

from threading import Thread
from multiprocessing import Queue
from datetime import datetime

from .utils.misc import logged_class
from elliptics_recovery.stat import format_kv


@logged_class
class EmptyMonitor(object):
    __doc__ = \
        """
        Empty Monitor implements interface of Monitor class but do nothing.
        """

    def __init__(self):
        pass

    def __str__(self):
        return ""

    def add_counter(self, name, value):
        pass

    def add_timer(self, stat_name, timer_name):
        pass


class Counters:
    EndTime,\
        Iterations,\
        TotalIterations,\
        IteratedKeys,\
        Diffs,\
        MergedDiffs,\
        ReadKeys,\
        SkippedReadKeys,\
        RecoveredKeys,\
        RecoveredBytes,\
        FailedIterations,\
        FailedKeys,\
        FailedBytes = range(13)


@logged_class
class Monitor(object):
    __doc__ = \
        """
        Contains monitoring data and provides interface for munipulating it from detached threads/processes
        """

    def __init__(self, port, recovery_type, ctx):
        self.port = port
        self.recovery_type = recovery_type
        self.ctx = ctx
        self.queue = Queue()
        self.d_thread = Thread(target=self.data_thread, args=(), name="MonitorDataThread")
        self.d_thread.daemon = True

        self.l_thread = Thread(target=self.listen_thread, args=(), name="MonitorListenThread")
        self.l_thread.daemon = True

        self.d_thread.start()
        self.l_thread.start()

        self.start_time = datetime.now()
        self.end_time = None
        self.iterations = 0
        self.total_iterations = 0
        self.iterated_keys = 0
        self.diffs = 0
        self.merged_diffs = None
        self.recovered_keys = 0
        self.recovered_bytes = 0
        self.read_keys = 0
        self.skipped_read_keys = 0

        self.failed_iterations = 0
        self.failed_keys = 0
        self.failed_bytes = 0

    def data_thread(self):
        while True:

            try:
                type, value = self.queue.get(block=True)
            except EOFError:
                return
            except ValueError:
                continue

            if type == Counters.EndTime:
                self.end_time = value
            elif type == Counters.TotalIterations:
                self.total_iterations = value
            elif type == Counters.Iterations:
                self.iterations += value
            elif type == Counters.IteratedKeys:
                self.iterated_keys += value
            elif type == Counters.Diffs:
                self.diffs += value
            elif type == Counters.MergedDiffs:
                if not self.merged_diffs:
                    self.merged_diffs = 0
                self.merged_diffs += value
            elif type == Counters.ReadKeys:
                self.read_keys += value
            elif type == Counters.SkippedReadKeys:
                self.skipped_read_keys += value
            elif type == Counters.RecoveredKeys:
                self.recovered_keys += value
            elif type == Counters.RecoveredBytes:
                self.recovered_bytes += value
            elif type == Counters.FailedKeys:
                self.failed_keys += value
            elif type == Counters.FailedBytes:
                self.failed_bytes += value

    def listen_thread(self):
        import socket
        backlog = 5
        size = 1
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind(('', self.port))
        s.listen(backlog)
        while True:
            client, address = s.accept()
            request = client.recv(size)
            response = None
            if request == 'i':
                response = str(self)
            #elif request == 'p':
            #    response = "Recover is paused\n"
            #elif request == 'c':
            #    response = "Recover is restored\n"
            #elif request == 's':
            #    response = "Recover is stopped\n"
            else:
                response = ""
                if request != 'h':
                    response += "Unkown requst: {0}\n".format(request)
                #response += "Request chars:\ni - info\np - pause\nc - continue\ns - stop\nh - this info\n"
                response += "Request chars:\ni - info\nh - this info\n"

            if response:
                client.send(response)
            client.close()

    def set_finished(self):
        self.queue.put_nowait((Counters.EndTime, datetime.now()))

    def add_counter(self, type, value):
        self.queue.put_nowait((type, value))

    def __str__(self):
        ret = "{0:=^100}".format(self.recovery_type + " Monitor Statistics")
        ret += "\ncontext{0}".format(self.ctx)
        ret += "\n{0}".format(format_kv("Started", self.start_time))
        if self.end_time:
            ret += "\n{0}".format(format_kv("Started", self.end_time - self.start_time))
            ret += "\n{0}".format(format_kv("Finished", self.end_time))

        ret += "\n{0}".format(format_kv("Iterations succ/fail/all", "{0}/{1}/{2}".format(self.iterations, self.failed_iterations, self.total_iterations)))
        ret += "\n{0}".format(format_kv("Iterated keys", self.iterated_keys))
        ret += "\n{0}".format(format_kv("Diffs", self.diffs))
        if self.merged_diffs:
            ret += "\n{0}".format(format_kv("Merged diffs", self.merged_diffs))

        total_keys = self.diffs
        if self.merged_diffs:
            total_keys = self.merged_diffs

        if total_keys:
            ret += "\n{0}".format(format_kv("Read keys succ/skipped", "{0}/{1}".format(self.read_keys, self.skipped_read_keys)))
            read_part = (self.read_keys + self.skipped_read_keys) * 100 / total_keys
            ret += "\n{0}[{1}%]".format("="*read_part + "-"*(100 - read_part), read_part)

        total_keys -= self.skipped_read_keys

        if self.read_keys:
            ret += "\n{0}".format(format_kv("Recovered keys succ/fail", "{0}/{1}".format(self.recovered_keys, self.failed_keys)))
            recovered_part = self.recovered_keys * 100 / self.read_keys
            failed_part = self.failed_keys * 100 / self.read_keys
            rest = 100 - recovered_part - failed_part
            if rest < 0:
                rest = 0
            ret += "\n{0}[{1}%]".format("="*recovered_part + "!"*failed_part + "-"*rest, recovered_part + failed_part)
            ret += "\n{0}".format(format_kv("Recovered bytes succ/fail", "{0}/{1}".format(self.recovered_bytes, self.failed_bytes)))
        return ret
