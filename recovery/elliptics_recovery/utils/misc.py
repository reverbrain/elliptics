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
import hashlib
import errno
import traceback
import struct
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


def mk_container_name(address, backend_id, prefix="iterator_"):
    """
    Makes filename for iterators' results
    """
    return "{0}{1}.{2}".format(prefix, hashlib.sha256(str(address)).hexdigest(), backend_id)

INDEX_MAGIC_NUMBER = struct.pack('Q', 6747391680278904871)
INDEX_MAGIC_NUMBER_LENGTH = len(INDEX_MAGIC_NUMBER)


def validate_index(result):
    if result.size < INDEX_MAGIC_NUMBER_LENGTH:
        return False
    return result.data[:8] == INDEX_MAGIC_NUMBER


def elliptics_create_node(address=None, elog=None, wait_timeout=3600, check_timeout=60, flags=0, io_thread_num=1,
                          net_thread_num=1, nonblocking_io_thread_num=1, remotes=[]):
    """
    Connects to elliptics cloud
    """
    log.debug("Creating node using: {0}, wait_timeout: {1}, remotes: {2}".format(address, wait_timeout, remotes))
    cfg = elliptics.Config()
    cfg.config.wait_timeout = wait_timeout
    cfg.config.check_timeout = check_timeout
    cfg.config.flags = flags
    cfg.config.io_thread_num = io_thread_num
    cfg.config.nonblocking_io_thread_num = nonblocking_io_thread_num
    cfg.config.net_thread_num = net_thread_num
    node = elliptics.Node(elog, cfg)
    node.add_remotes([address] + remotes)
    log.debug("Created node: {0}".format(node))
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


# common class for collecting statistics of recovering one key
class RecoverStat(object):
    def __init__(self):
        self.skipped = 0
        self.lookup = 0
        self.lookup_failed = 0
        self.lookup_retries = 0
        self.read = 0
        self.read_failed = 0
        self.read_retries = 0
        self.read_bytes = 0
        self.write = 0
        self.write_failed = 0
        self.write_retries = 0
        self.written_bytes = 0
        self.remove = 0
        self.remove_failed = 0
        self.remove_retries = 0
        self.removed_bytes = 0
        self.remove_old = 0
        self.remove_old_failed = 0
        self.remove_old_bytes = 0
        self.merged_indexes = 0

    def apply(self, stats):
        if self.skipped:
            stats.counter("skipped_keys", self.skipped)
        if self.lookup:
            stats.counter("remote_lookups", self.lookup)
        if self.lookup_failed:
            stats.counter("remote_lookups", -self.lookup_failed)
        if self.lookup_retries:
            stats.counter("remote_lookup_retries", self.lookup_retries)
        if self.read:
            stats.counter("local_reads", self.read)
        if self.read_failed:
            stats.counter("local_reads", -self.read_failed)
        if self.read_retries:
            stats.counter("local_read_retries", self.read_retries)
        if self.read_bytes:
            stats.counter("local_read_bytes", self.read_bytes)
        if self.write:
            stats.counter("remote_writes", self.write)
        if self.write_failed:
            stats.counter("remote_writes", -self.write_failed)
        if self.write_retries:
            stats.counter("remote_write_retries", self.write_retries)
        if self.written_bytes:
            stats.counter("remote_written_bytes", self.written_bytes)
        if self.remove:
            stats.counter("local_removes", self.remove)
        if self.remove_failed:
            stats.counter("local_removes", -self.remove_failed)
        if self.remove_retries:
            stats.counter("local_remove_retries", self.remove_retries)
        if self.removed_bytes:
            stats.counter("local_removed_bytes", self.removed_bytes)
        if self.remove_old:
            stats.counter('local_removes_old', self.remove_old)
        if self.remove_old_failed:
            stats.counter('local_removes_old', -self.remove_old_failed)
        if self.remove_old_bytes:
            stats.counter('local_removes_old_bytes', self.remove_old_bytes)
        if self.merged_indexes:
            stats.counter("merged_indexes", self.merged_indexes)

    def __add__(self, b):
        ret = RecoverStat()
        ret.skipped = self.skipped + b.skipped
        ret.lookup = self.lookup + b.lookup
        ret.lookup_failed = self.lookup_failed + b.lookup_failed
        ret.lookup_retries = self.lookup_retries + b.lookup_retries
        ret.read = self.read + b.read
        ret.read_failed = self.read_failed + b.read_failed
        ret.read_retries = self.read_retries + b.read_retries
        ret.read_bytes = self.read_bytes + b.read_bytes
        ret.write = self.write + b.write
        ret.write_failed = self.write_failed + b.write_failed
        ret.write_retries = self.write_retries + b.write_retries
        ret.written_bytes = self.written_bytes + b.written_bytes
        ret.remove = self.remove + b.remove
        ret.remove_failed = self.remove_failed + b.remove_failed
        ret.remove_retries = self.remove_retries + b.remove_retries
        ret.removed_bytes = self.removed_bytes + b.removed_bytes
        ret.remove_old = self.remove_old + b.remove_old
        ret.remove_old_failed = self.remove_old_failed + b.remove_old_failed
        ret.remove_old_bytes = self.remove_old_bytes + b.remove_old_bytes
        ret.merged_indexes = self.merged_indexes + b.merged_indexes
        return ret


class DirectOperation(object):
    '''
    Base class for direct operations with id from address in group
    '''
    def __init__(self, address, backend_id, id, group, ctx, node, callback):
        # creates new session
        self.session = elliptics.Session(node)
        # turns off exceptions
        self.session.exceptions_policy = elliptics.core.exceptions_policy.no_exceptions
        # makes session direct to the address
        self.session.set_direct_id(address, backend_id)
        # sets groups
        self.session.groups = [group]
        self.id = id
        self.stats = RecoverStat()
        self.attempt = 0
        self.ctx = ctx
        self.callback = callback
        self.address = address
        self.backend_id = backend_id


# class for looking up id directly from address via reading 1 byte of it
class LookupDirect(DirectOperation):
    def run(self):
        # read one byt of id
        async_result = self.session.read_data(self.id, offset=0, size=1)
        async_result.connect(self.onread)

    def onread(self, results, error):
        try:
            if error.code == -errno.ETIMEDOUT:
                log.debug("Lookup key: {0} has been timed out: {1}"
                          .format(repr(self.id), error))
                # if read failed with timeout - retry it predetermined number of times
                if self.attempt < self.ctx.attempts:
                    old_timeout = self.session.timeout
                    self.session.timeout *= 2
                    self.attempt += 1
                    log.debug("Retry to lookup key: {0} attempt: {1}/{2} increased timeout: {3}/{4}"
                              .format(repr(self.id),
                                      self.attempt, self.ctx.attempts,
                                      self.session.timeout, old_timeout))
                    self.stats.lookup_retries += 1
                    self.run()

            if error.code:
                self.stats.lookup_failed += 1
                self.callback(None, self.stats)
            else:
                self.stats.lookup += 1
                self.callback(results[0], self.stats)
        except Exception as e:
            log.error("Onlookup exception: {0}, traceback: {1}"
                      .format(repr(e), traceback.format_exc()))
            self.callback(None, self.stats)


class RemoveDirect(DirectOperation):
    '''
    Class for removing id directly from address
    '''
    def run(self):
        async_result = self.session.remove(self.id)
        async_result.connect(self.onremove)

    def onremove(self, results, error):
        try:
            if error.code:
                log.debug("Remove key: {0} on node: {1}/{2} has been failed: {3}"
                          .format(self.id, self.address, self.backend_id, repr(error)))
                # if removing filed - retry it predetermined number of times
                if self.attempt < self.ctx.attempts:
                    old_timeout = self.session.timeout
                    self.session.timeout *= 2
                    self.attempt += 1
                    log.debug("Retry to remove key: {0} attempt: {1}/{2} "
                              "increased timeout: {3}/{4}"
                              .format(repr(self.id),
                                      self.attempt, self.ctx.attempts,
                                      self.session.timeout, old_timeout))
                    self.stats.remove_retries += 1
                    self.run()
                    return
                log.error("Key: {0} hasn't been removed from node: {1}/{2}: {3}"
                          .format(repr(self.id), self.address, self.backend_id, repr(error)))
                self.stats.remove_failed += 1
                self.callback(False, self.stats)
                return

            self.stats.remove += 1
            #self.stats.removed_bytes += self.total_size
            self.callback(True, self.stats)
        except Exception as e:
            log.error("Onremove exception: {0}, traceback: {1}"
                      .format(repr(e), traceback.format_exc()))
            self.result = False
            self.callback(False, self.stats)


class KeyInfo(object):
    def __init__(self, address, group_id, timestamp, size, user_flags):
        self.address = address
        self.group_id = group_id
        self.timestamp = timestamp
        self.size = size
        self.user_flags = user_flags

    def dump(self):
        return (
            (self.address.host, self.address.port, self.address.family),
            self.group_id,
            (self.timestamp.tsec, self.timestamp.tnsec),
            self.size,
            self.user_flags)

    @classmethod
    def load(cls, data):
        return cls(elliptics.Address(data[0][0], data[0][1], data[0][2]),
                   data[1],
                   elliptics.Time(data[2][0], data[2][1]),
                   data[3],
                   data[4])


def dump_key_data(key_data, file):
    import msgpack
    dump_data = (key_data[0].id, tuple(ki.dump() for ki in key_data[1]))
    msgpack.pack(dump_data, file)


def load_key_data(filepath):
    import msgpack
    with open(filepath, 'r') as input_file:
        unpacker = msgpack.Unpacker(input_file)
        for data in unpacker:
            yield (elliptics.Id(data[0], 0), tuple(KeyInfo.load(d) for d in data[1]))
