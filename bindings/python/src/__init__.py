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

from __future__ import absolute_import

from elliptics.core import *
from elliptics.route import Address, RouteList
from elliptics.session import Session
from elliptics.node import Node
from elliptics.log import log, init_logger

__author__ = "Kirill Smorodinnikov, Evgeniy Polyakov, Ruslan Nigmatullin, Alexey Ivanov"
__copyright__ = """2008+ Copyright (c) Evgeniy Polyakov <zbr@ioremap.net>
2012+ Copyright (c) Ruslan Nigmatullin <euroelessar@yandex.ru>
2013+ Copyright (c) Kirill Smorodinnikov <shaitkir@gmail.com>
All rights reserved.

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU General Public License for more details."""
__credits__ = ["Kirill Smorodinnikov", "Evgeniy Polyakov", "Ruslan Nigmatullin", "Alexey Ivanov"]
__license__ = "GPLv2"
__maintainer__ = "Kirill Smorodinnikov"


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


del init_logger
