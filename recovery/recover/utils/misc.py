import logging

__doc__ = \
"""
Misc. routines
"""

def logged_class(klass):
    """
    This decorator adds 'log' method to passed class
    """
    klass.log = logging.getLogger(klass.__name__)
    return klass

def format_id(key_id, count=6):
    """
    Pretty format for key_ids
    """
    return ''.join('%02x' % b for b in key_id[:count])

def split_host_port(string):
    """
    Return (host, port) tuple from string
    """
    host, port = string.split(':', 1)
    return host, int(port)

def mk_container_name(id_range, eid, prefix="iterator_"):
    """
    Makes filename for iterators' results
    """
    return "{0}{1}_@{2}".format(prefix, str(id_range), format_id(eid.id))
