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

import pickle
import sys
import logging
import threading
import os
from itertools import groupby
import struct

from elliptics_recovery.utils.misc import elliptics_create_node

sys.path.insert(0, "bindings/python/")

import elliptics
from elliptics import Address

log = logging.getLogger()


class RecoverStat(object):
    def __init__(self):
        self.read = 0
        self.read_failed = 0
        self.read_bytes = 0
        self.merged_indexes = 0
        self.write = 0
        self.write_failed = 0
        self.written_bytes = 0

    def apply(self, stats):
        if self.read:
            stats.counter("reads", self.read)
        if self.read_failed:
            stats.counter("reads", -self.read_failed)
        if self.read_bytes:
            stats.counter("read_bytes", self.read_bytes)
        if self.merged_indexes:
            stats.counter("merged_indexes", self.merged_indexes)
        if self.write:
            stats.counter("writes", self.write)
        if self.write_failed:
            stats.counter("writes", -self.write_failed)
        if self.written_bytes:
            stats.counter("written_bytes", self.written_bytes)

    def __add__(a, b):
        ret = RecoverStat()
        ret.read = a.read + b.read
        ret.read_failed = a.read_failed + b.read_failed
        ret.read_bytes = a.read_bytes + b.read_bytes
        ret.write = a.write + b.write
        ret.write_failed = a.write_failed + b.write_failed
        ret.written_bytes = a.written_bytes + b.written_bytes
        return ret

magic_number = 6747391680278904871
magic_string = struct.pack('Q', magic_number)


def validate_index(result):
    if result.size < 8:
        return False

    return struct.unpack('Q', result.data[:8])[0] == magic_number


class IndexItem:
    def __init__(self, id, data, tsec=0, tnsec=0):
        self.id = struct.unpack('B' * 64, id)
        self.data = data
        self.tsec = tsec
        self.tnsec = tnsec

    def __cmp__(self, other):
        return cmp(
            (self.id, other.tsec, other.tnsec, len(self.data)),
            (other.id, self.tsec, self.tnsec, len(other.data)))

    def pack(self):
        ret = [struct.pack('B' * 64, *self.id),
               self.data]

        if self.tsec or self.tnsec:
            ret += [self.tsec, self.tnsec]

        return tuple(ret)


class Index:
    def __init__(self, items):
        self.items = iter(items)
        self.top = IndexItem(*next(self.items))

    def next(self):
        self.top = IndexItem(*next(self.items))

    def __cmp__(self, other):
        return cmp(self.top, other.top)


def merge_index_shards(results):
    import msgpack
    shards = []
    for r in results:
        if r and r.size > 8:
            try:
                log.debug("Unpacking index shard size: {0}".format(r.size))
                shard = msgpack.loads(r.data[8:])
                if shard[1]:
                    shards.append(shard)
            except Exception as e:
                log.error("Could not to load msgpack string: {0}".format(e))

    if not shards:
        return None
    elif len(shards) == 1:
        return magic_string + msgpack.dumps(shards[0])

    shard_info = (shards[0][0], shards[0][2], shards[0][3])

    assert all((s[0], s[2], s[3]) == shard_info for s in shards)

    import heapq
    heap = []

    for s in shards:
        heapq.heappush(heap, Index(s[1]))

    final = []

    while heap:
        smallest = heapq.heappop(heap)
        if final and final[-1].id == smallest.top.id:
            try:
                smallest.next()
                heapq.heappush(heap, smallest)
            except StopIteration:
                pass
            continue

        smallest_val = smallest.top
        final.append(smallest_val)

        try:
            smallest.next()
            heapq.heappush(heap, smallest)
        except StopIteration:
            pass

    final = tuple(f.pack() for f in final)
    merged_shard = (shard_info[0],
                    final,
                    shard_info[1],
                    shard_info[2])
    return magic_string + msgpack.dumps(merged_shard)


class KeyRecover(object):
    def __init__(self, key, origin_group, diff_groups, missed_groups, node):
        self.complete = threading.Event()
        self.stats = RecoverStat()
        self.key = key
        self.origin_group = origin_group
        self.diff_groups = set(diff_groups)
        self.missed_groups = set(missed_groups)

        self.origin_session = elliptics.Session(node)
        self.origin_session.groups = [origin_group]

        self.diff_sessions = []
        for g in self.diff_groups:
            self.diff_sessions.append(elliptics.Session(node))
            self.diff_sessions[-1].groups = [g]

        self.missed_sessions = []
        for g in self.missed_groups:
            self.missed_sessions.append(elliptics.Session(node))
            self.missed_sessions[-1].groups = [g]

        self.write_session = elliptics.Session(node)
        self.result = False

    def run(self):
        log.debug("Recovering key: {0}, origin group: {1}, "
                  "groups with diff: {2}, missed groups: {3}"
                  .format(repr(self.key), self.origin_group,
                          self.diff_groups,
                          self.missed_groups))

        self.origin_read = self.origin_session.read_data(self.key)
        self.origin_read.connect(self.on_read_origin)

    def on_read_origin(self, results, error):
        self.origin_read = None
        try:
            if error.code or len(results) < 1:
                log.error("Read key: {0} from group: {1} has failed: {2}".
                          format(repr(self.key), self.origin_group, error))
                self.stats.read_failed += 1
                self.complete.set()
                return

            self.stats.read += 1
            self.stats.read_bytes += results[0].size

            if validate_index(results[0]) and self.diff_groups:
                log.debug("Index has been found in key: {0}. "
                          "Trying to merge shards from other groups: {1}"
                          .format(repr(self.key), self.diff_groups))
                self.data_to_merge = [results[0]]
                self.diff_reads = []
                self.merge_lock = threading.Lock()
                for s in self.diff_sessions:
                    self.diff_reads.append(s.read_data(self.key))
                    self.diff_reads[-1].connect(self.on_read_merge)
            else:
                self.write_session.groups = self.diff_groups \
                    .union(self.missed_groups)
                log.debug("Regular object has been found in key: {0}. "
                          "Simply copy it from group: {1} to groups: {2}"
                          .format(repr(self.key), self.origin_group,
                                  self.write_session.groups))
                self.size_to_write = results[0].size
                self.write_result = self.write_session.write_data(
                    results[0].io_attribute,
                    results[0].data)
                self.write_result.connect(self.on_write)
        except Exception as e:
            log.error("Failed to handle origin key: {0}, exception: {1}"
                      .format(repr(self.key), e))
            self.complete.set()

    def on_read_merge(self, results, error):
        complete = False
        try:
            with self.merge_lock:
                if error.code or len(results) < 1:
                    log.error("Read key: {0} has failed: {2}".
                              format(repr(self.key),
                                     error))
                    self.stats.read_failed += 1
                    self.data_to_merge.append(None)
                else:
                    self.stats.read += 1
                    self.stats.read_bytes += results[0].size
                    self.data_to_merge.append(results[0])

                if len(self.data_to_merge) == len(self.diff_groups) + 1:
                    complete = True

            if complete:
                log.debug("Merging index shards from different groups")
                data = merge_index_shards(self.data_to_merge)
                self.stats.merged_indexes += 1
                self.size_to_write = len(data)
                if data:
                    io = elliptics.IoAttr()
                    io.id = self.key
                    io.timestamp = elliptics.Time.now()
                    self.write_session.groups = self.diff_groups \
                        .union(self.missed_groups) \
                        .union([self.origin_group])
                    log.debug("Writing merged")
                    self.write_result = self.write_session.write_data(io, data)
                    self.write_result.connect(self.on_write)
        except Exception as e:
            log.error("Failed to merge shards for key: {0} exception: {1}"
                      .format(repr(self.key), e))
            self.complete.set()

    def on_write(self, results, error):
        try:
            if error.code:
                self.stats.write_failed += 1
                log.error("Failed to write key: {0}: {1}"
                          .format(repr(self.key), error))
            else:
                log.debug("Writed key: {0}".format(repr(self.key)))
                self.result = True
                self.stats.write += 1
                self.stats.written_bytes += self.size_to_write
            self.complete.set()
        except Exception as e:
            log.error("Failed to handle write result key: {0}: {1}"
                      .format(repr(self.key), e))

    def wait(self):
        if not self.complete.is_set():
            self.complete.wait()

    def succeeded(self):
        self.wait()
        return self.result


def unpcikle(filepath):
    with open(filepath, 'r') as input_file:
        try:
            unpickler = pickle.Unpickler(input_file)
            while True:
                yield unpickler.load()
        except:
            pass


def filter(filepath, groups):
    # removes duplicates from groups
    groups = set(groups)
    # for each key with its infos
    for key, key_infos in unpcikle(filepath):
        origin = None
        diffs = []
        same = []

        # for each infos assosiated with key
        for key_info in key_infos:
            # Sets first key_info as origin
            if origin is None:
                origin = key_info
                continue

            cmp_time = cmp(key_info.timestamp, origin.timestamp)
            cmp_size = cmp(key_info.size, origin.size)

            # if timestamp of origin is younger then in key_info
            if cmp_time < 0:
                # adds key_info to diffs
                diffs.append(key_info)
            # if timestamp of origin is older or
            # size of origin is smaller then in key_info
            elif cmp_time > 0 or cmp_size > 0:
                same.append(origin)
                diffs += same
                origin = key_info
                same = []
            elif cmp_time == cmp_size == 0:
                same.append(key_info)
            else:
                diffs.append(key_info)

        same_groups = set((x.address.group_id for x in same))
        diff_groups = set((x.address.group_id for x in diffs))

        missed_groups = groups.difference(same_groups) \
                              .difference(diff_groups) \
                              .difference([origin.address.group_id])

        if not diff_groups and not missed_groups:
            continue

        yield (key, origin.address.group_id, diff_groups, missed_groups)


def recover(ctx):
    ret = True
    stats = ctx.monitor.stats['recover']

    filtered = filter(ctx.merged_filename, ctx.groups)

    node = elliptics_create_node(address=ctx.address,
                                 elog=ctx.elog,
                                 wait_timeout=ctx.wait_timeout,
                                 net_thread_num=4,
                                 io_thread_num=1)

    for batch_id, batch in groupby(enumerate(filtered),
                                   key=lambda x: x[0] / ctx.batch_size):
        recovers = []
        rs = RecoverStat()
        for _, val in batch:
            rec = KeyRecover(*val, node=node)
            recovers.append(rec)
            rec.run()
        for r in recovers:
            r.wait()
            ret &= r.succeeded()
            rs += r.stats
        rs.apply(stats)
    return ret


if __name__ == '__main__':
    from elliptics_recovery.ctx import Ctx
    from optparse import OptionParser
    parser = OptionParser()
    parser.usage = "%prog [options]"
    parser.description = __doc__
    parser.add_option("-i", "--merged-filename", dest="merged_filename",
                      default='merged_result', metavar="FILE",
                      help="Input file which contains information about keys "
                      "in groups [default: %default]")
    parser.add_option("-d", "--debug", action="store_true",
                      dest="debug", default=False,
                      help="Enable debug output [default: %default]")
    parser.add_option("-D", "--dir", dest="tmp_dir",
                      default='/var/tmp/dnet_recovery_%TYPE%', metavar="DIR",
                      help="Temporary directory for iterators' results "
                      "[default: %default]")
    parser.add_option("-l", "--log", dest="elliptics_log",
                      default='dnet_recovery.log', metavar="FILE",
                      help="Output log messages from library to file "
                      "[default: %default]")
    parser.add_option("-L", "--log-level", action="store",
                      dest="elliptics_log_level", default="1",
                      help="Elliptics client verbosity [default: %default]")
    parser.add_option("-w", "--wait-timeout", action="store",
                      dest="wait_timeout", default="3600",
                      help="[Wait timeout for elliptics operations "
                      "default: %default]")
    parser.add_option("-r", "--remote", action="store",
                      dest="elliptics_remote", default=None,
                      help="Elliptics node address [default: %default]")
    parser.add_option("-g", "--groups", action="store",
                      dest="elliptics_groups", default=None,
                      help="Comma separated list of groups [default: all]")
    parser.add_option("-b", "--batch-size", action="store",
                      dest="batch_size", default="1024",
                      help="Number of keys in read_bulk/write_bulk "
                      "batch [default: %default]")

    (options, args) = parser.parse_args()
    ctx = Ctx()

    log.setLevel(logging.DEBUG)
    formatter = logging.Formatter(
        fmt='%(asctime)-15s %(processName)s %(levelname)s %(message)s',
        datefmt='%d %b %y %H:%M:%S')

    ch = logging.StreamHandler(sys.stderr)
    ch.setFormatter(formatter)
    ch.setLevel(logging.INFO)
    log.addHandler(ch)

    if not os.path.exists(ctx.tmp_dir):
        try:
            os.makedirs(ctx.tmp_dir, 0755)
            log.warning("Created tmp directory: {0}".format(ctx.tmp_dir))
        except Exception as e:
            raise ValueError("Directory: {0} does not exist and "
                             "could not be created: {1}"
                             .format(ctx.tmp_dir, e))
    os.chdir(ctx.tmp_dir)

    try:
        ctx.log_file = os.path.join(ctx.tmp_dir, options.elliptics_log)
        ctx.log_level = int(options.elliptics_log_level)
        ctx.merged_filename = os.path.join(ctx.tmp_dir,
                                           options.merged_filename)

        ch.setLevel(logging.WARNING)
        if options.debug:
            ch.setLevel(logging.DEBUG)

        # FIXME: It may be inappropriate to use one log for both
        # elliptics library and python app, esp. in presence of auto-rotation
        fh = logging.FileHandler(ctx.log_file)
        fh.setFormatter(formatter)
        fh.setLevel(logging.DEBUG)
        log.addHandler(fh)
    except Exception as e:
        raise ValueError("Can't parse log_level: '{0}': {1}"
                         .format(options.elliptics_log_level, repr(e)))
    log.info("Using elliptics client log level: {0}".format(ctx.log_level))

    if options.elliptics_remote is None:
        raise ValueError("Recovery address should be given (-r option).")
    try:
        ctx.address = Address.from_host_port_family(options.elliptics_remote)
    except Exception as e:
        raise ValueError("Can't parse host:port:family: '{0}': {1}".format(
            options.elliptics_remote, repr(e)))
    log.info("Using host:port:family: {0}".format(ctx.address))

    try:
        if options.elliptics_groups:
            ctx.groups = map(int, options.elliptics_groups.split(','))
        else:
            ctx.groups = []
    except Exception as e:
        raise ValueError("Can't parse grouplist: '{0}': {1}".format(
            options.elliptics_groups, repr(e)))

    try:
        ctx.batch_size = int(options.batch_size)
        if ctx.batch_size <= 0:
            raise ValueError("Batch size should be positive: {0}"
                             .format(ctx.batch_size))
    except Exception as e:
        raise ValueError("Can't parse batchsize: '{0}': {1}".format(
            options.batch_size, repr(e)))
    log.info("Using batch_size: {0}".format(ctx.batch_size))

    try:
        ctx.wait_timeout = int(options.wait_timeout)
    except Exception as e:
        raise ValueError("Can't parse wait_timeout: '{0}': {1}"
                         .format(options.wait_timeout, repr(e)))

    log.debug("Creating logger")
    ctx.elog = elliptics.Logger(ctx.log_file, int(ctx.log_level))

    res = recover(ctx)

    exit(res)
