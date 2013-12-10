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

from elliptics.core import *
from elliptics.route import Address


@property
def storage_address(self):
    """
    Node address as elliptics.Address
    """
    return Address.from_host_port(self.__storage_address__)


def wrap_address(classes):
    @property
    def address(self):
        """
        Node address as elliptics.Address
        """
        return Address.from_host_port(self.__address__, self.__group_id__)
    for cls in classes:
        cls.__address__ = cls.address
        cls.__group_id__ = cls.group_id
        del cls.group_id
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
        cfg = Config()
        cfg.wait_timeout = wait_timeout
        cfg.check_timeout = check_timeout
        cfg.flags = flags
        cfg.io_thread_num = io_thread_num
        cfg.nonblocking_io_thread_num = nonblocking_io_thread_num
        cfg.net_thread_num = net_thread_num
    n = Node(elog, cfg)
    for r in remotes:
        try:
            n.add_remote(r)
        except:
            pass
    return n


del storage_address
del wrap_address
