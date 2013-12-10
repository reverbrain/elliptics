# =============================================================================
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
Misc. routines
"""

import logging as log
import sys
import hashlib

# XXX: change me before BETA
sys.path.insert(0, "bindings/python/")
import elliptics

def logged_class(klass):
    """
    This decorator adds 'log' method to passed class
    """
    klass.log = log.getLogger(klass.__name__)
    return klass

def id_to_int(key_id):
    """Returns numerical equivalent of key"""
    return int(''.join('%02x' % b for b in key_id.id[:64]), 16)

def mk_container_name(address, prefix="iterator_"):
    """
    Makes filename for iterators' results
    """
    return "{0}{1}".format(prefix, hashlib.sha256(str(address)).hexdigest())

def elliptics_create_node(address=None, elog=None, wait_timeout=3600, check_timeout=60, flags=0, io_thread_num=1, net_thread_num=1, nonblocking_io_thread_num=1):
    """
    Connects to elliptics cloud
    """
    log.info("Creating node using: {0}, wait_timeout: {1}".format(address, wait_timeout))
    cfg = elliptics.Config()
    cfg.config.wait_timeout = wait_timeout
    cfg.config.check_timeout = check_timeout
    cfg.config.flags = flags
    cfg.config.io_thread_num = io_thread_num
    cfg.config.nonblocking_io_thread_num = nonblocking_io_thread_num
    cfg.config.net_thread_num = net_thread_num
    node = elliptics.Node(elog, cfg)
    node.add_remote(addr=address.host, port=address.port, family=address.family)
    log.info("Created node: {0}".format(node))
    return node

def elliptics_create_session(node=None, group=None, cflags=elliptics.command_flags.default):
    log.debug("Creating session: {0}@{1}.{2}".format(node, group, cflags))
    session = elliptics.Session(node)
    session.groups = [group]
    session.cflags = cflags
    return session

def worker_init():
    """Do not catch Ctrl+C in worker"""
    from signal import signal, SIGINT, SIG_IGN
    signal(SIGINT, SIG_IGN)
