"""
Misc. routines
"""

import logging as log
import sys

# XXX: change me before BETA
sys.path.insert(0, "bindings/python/")
import elliptics

def logged_class(klass):
    """
    This decorator adds 'log' method to passed class
    """
    klass.log = log.getLogger(klass.__name__)
    return klass

def format_id(key_id, count=6):
    """
    Pretty format for key_ids
    """
    return ''.join('%02x' % b for b in key_id[:count])

def id_to_int(key_id):
    """Returns numerical equivalent of key"""
    return int(format_id(key_id, count=64), 16)


def mk_container_name(id_range, eid, prefix="iterator_"):
    """
    Makes filename for iterators' results
    """
    return "{0}{1}_@{2}".format(prefix, str(id_range), format_id(eid.id))

def elliptics_create_node(address=None, elog=None, wait_timeout=3600, check_timeout=60, flags=0, io_thread_num=1, net_thread_num=1, nonblocking_io_thread_num=1):
    """
    Connects to elliptics cloud
    """
    log.info("Creating node using: {0}".format(address))
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
    session.set_groups([group])
    session.set_cflags(cflags)
    return session

def worker_init():
    """Do not catch Ctrl+C in worker"""
    from signal import signal, SIGINT, SIG_IGN
    signal(SIGINT, SIG_IGN)
