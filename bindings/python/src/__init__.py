from __future__ import absolute_import

from elliptics.core import *
import elliptics.route
import elliptics.session
from elliptics.route import *
from elliptics.session import *
from elliptics.node import *


@property
def storage_address(self):
    return Address.from_host_port(self.__storage_address__)


def wrap_address(classes):
    @property
    def address(self):
        return Address.from_host_port(self.__address__)
    for cls in classes:
        cls.__address__ = cls.address
        cls.address = address

LookupResultEntry.__storage_address__ = LookupResultEntry.storage_address
LookupResultEntry.storage_address = storage_address

wrap_address([IteratorResultEntry,
              ReadResultEntry,
              LookupResultEntry,
              ExecResultEntry,
              CallbackResultEntry,
              StatResultEntry,
              AddressStatistics,
              StatCountResultEntry
              ])


def create_node(elog=None, log_file='/dev/stderr', log_level=1,
                cfg=None, wait_timeout=3600, check_timeout=60,
                flags=0, io_thread_num=1, net_thread_num=1,
                nonblocking_io_thread_num=1, remotes=[]):
    if not elog:
        elog = Logger(log_file, log_level)
    if not cfg:
        cfg = elliptics.Config()
        cfg.config.wait_timeout = wait_timeout
        cfg.config.check_timeout = check_timeout
        cfg.config.flags = flags
        cfg.config.io_thread_num = io_thread_num
        cfg.config.nonblocking_io_thread_num = nonblocking_io_thread_num
        cfg.config.net_thread_num = net_thread_num
    n = Node(elog, cfg)
    for r in remotes:
        try:
            n.add_remote(r)
        except:
            pass
    return n

del elliptics.route
del elliptics.session
