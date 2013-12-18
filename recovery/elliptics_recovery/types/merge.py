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

"""
Deep Merge recovery type - recovers keys in one hash ring (aka group)
by placing them to the node where they belong.

 * Iterate all node in the group for ranges which are not belong to it.
 * Get all keys which shouldn't be on the node:
 * Looks up keys meta info on the proper node
 * If the key on the proper node is missed or older
 * then moved it form the node to ther proper node
 * If the key is valid then just remove it from the node.
"""

import sys
import logging

from itertools import groupby
from multiprocessing import Pool

from ..etime import Time
from ..utils.misc import elliptics_create_node, worker_init
from ..route import RouteList
from ..iterator import Iterator
from ..range import IdRange

import errno

# XXX: change me before BETA
sys.path.insert(0, "bindings/python/")
import elliptics

log = logging.getLogger(__name__)


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

    def __add__(a, b):
        ret = RecoverStat()
        ret.skipped = a.skipped + b.skipped
        ret.lookup = a.lookup + b.lookup
        ret.lookup_failed = a.lookup_failed + b.lookup_failed
        ret.lookup_retries = a.lookup_retries + b.lookup_retries
        ret.read = a.read + b.read
        ret.read_failed = a.read_failed + b.read_failed
        ret.read_retries = a.read_retries + b.read_retries
        ret.read_bytes = a.read_bytes + b.read_bytes
        ret.write = a.write + b.write
        ret.write_failed = a.write_failed + b.write_failed
        ret.write_retries = a.write_retries + b.write_retries
        ret.written_bytes = a.written_bytes + b.written_bytes
        ret.remove = a.remove + b.remove
        ret.remove_failed = a.remove_failed + b.remove_failed
        ret.remove_retries = a.remove_retries + b.remove_retries
        ret.removed_bytes = a.removed_bytes + b.removed_bytes
        return ret


class Recovery(object):
    def __init__(self, ctx, it_response, address, group, node):
        self.it_response = it_response
        self.address = address
        self.group = group
        self.node = node
        self.direct_session = elliptics.Session(node)
        self.direct_session.set_direct_id(*self.address)
        self.direct_session.groups = [group]
        self.session = elliptics.Session(node)
        self.session.groups = [group]
        self.ctx = ctx
        self.stats = RecoverStat()
        self.result = True
        self.attempt = 0
        self.data_size = it_response.size
        log.debug("Created Recovery object for key: {0}, node: {1}"
                  .format(repr(it_response.key), address))

    def run(self):
        log.debug("Recovering key: {0}, node: {1}"
                  .format(repr(self.it_response.key), self.address))
        address = self.session.lookup_address(self.it_response.key, self.group)
        if address == self.address:
            log.warning("Key: {0} already on the right node: {1}"
                        .format(repr(self.it_response.key), self.address))
            self.stats.skipped += 1
            return
        else:
            log.debug("Key: {0} should be on node: {1}"
                      .format(repr(self.it_response.key), address))
        self.dest_address = address
        log.debug("Lookup key: {0} on node: {1}"
                  .format(repr(self.it_response.key), self.dest_address))
        self.lookup_result = self.session.lookup(self.it_response.key)
        self.lookup_result.connect(self.onlookup)

    def onlookup(self, results, error):
        self.lookup_result = None
        try:
            if error.code == -errno.ETIMEDOUT:
                log.debug("Lookup key: {0} has been timed out: {1}"
                          .format(repr(self.it_response.key), error))
                if self.attempt < self.ctx.attempts:
                    old_timeout = self.session.timeout
                    self.session.timeout *= 2
                    self.attempt += 1
                    log.debug("Retry to lookup key: {0} attempt: {1}/{2} "
                              "increased timeout: {3}/{4}"
                              .format(repr(self.it_response.key),
                                      self.attempt, self.ctx.attempts,
                                      self.session.timeout, old_timeout))
                    self.stats.lookup_retries += 1
                    self.lookup_result = self.session.lookup(self.it_response.key)
                    self.lookup_result.connect(self.onlookup)
                    return

            if error.code:
                self.stats.lookup_failed += 1
            else:
                self.stats.lookup += 1

            if error.code == 0 and self.it_response.timestamp < results[0].timestamp:
                log.debug("Key: {0} on node: {1} is newer. "
                            "Just removing it from node: {2}."
                            .format(repr(self.it_response.key),
                                    self.dest_address, self.address))
                if self.ctx.dry_run:
                    log.debug("Dry-run mode is turned on. Skipping removing stage.")
                    return
                self.attempt = 0
                if not self.ctx.safe:
                    self.remove_result = self.direct_session.remove(self.it_response.key)
                    self.remove_result.connect(self.onremove)
                return

            log.debug("Key: {0} on node: {1} is older or miss. "
                      "Reading it from node: {2}"
                      .format(repr(self.it_response.key),
                              self.dest_address, self.address))
            if self.ctx.dry_run:
                log.debug("Dry-run mode is turned on. "
                          "Skipping reading, writing and removing stages.")
                return
            self.attempt = 0
            log.debug("Reading key: {0} from node: {1}"
                      .format(repr(self.it_response.key),
                              self.address))
            self.read_result = self.direct_session.read_data(self.it_response.key)
            self.read_result.connect(self.onread)
        except Exception as e:
            log.error("Onlookup exception: {0}".format(e))
            self.result = False

    def onread(self, results, error):
        self.read_result = None
        try:
            if error.code or len(results) < 1:
                log.debug("Read key: {0} on node: {1} has been timed out: {2}"
                          .format(repr(self.it_response.key), self.address, error))
                if self.attempt < self.ctx.attempts:
                    old_timeout = self.session.timeout
                    self.session.timeout *= 2
                    self.attempt += 1
                    log.debug("Retry to read key: {0} attempt: {1}/{2} "
                              "increased timeout: {3}/{4}"
                              .format(repr(self.it_response.key), self.attempt,
                                      self.ctx.attempts,
                                      self.direct_session.timeout, old_timeout))
                    self.stats.read_retries += 1
                    self.read_result = self.direct_session.read_data(self.it_response.key)
                    self.read_result.connect(self.onread)
                    return
                log.error("Reading key: {0} on the node: {1} failed. "
                          "Skipping it: {2}"
                          .format(repr(self.it_response.key),
                                  self.address, error))
                self.result = False
                self.stats.read_failed += 1
                return

            self.stats.read += 1
            self.write_io = elliptics.IoAttr()
            self.write_io.id = results[0].id
            self.write_io.timestamp = results[0].timestamp
            self.write_io.user_flags = results[0].user_flags
            self.write_data = results[0].data
            log.debug("Writing key: {0} to node: {1}"
                      .format(repr(self.it_response.key),
                              self.dest_address))
            self.data_size = len(self.write_data)
            self.stats.read_bytes += self.data_size
            self.attempt = 0
            self.write_result = self.session.write_data(self.write_io,
                                                        self.write_data)
            self.write_result.connect(self.onwrite)
        except Exception as e:
            log.error("Onread exception: {0}".format(e))
            self.result = False

    def onwrite(self, results, error):
        self.write_result = None
        try:
            if error.code or len(results) < 1:
                log.debug("Write key: {0} on node: {1} has been timed out: {2}"
                          .format(repr(self.it_response.key),
                                  self.dest_address, error))
                if self.attempt < self.ctx.attempts:
                    old_timeout = self.session.timeout
                    self.session.timeout *= 2
                    self.attempt += 1
                    log.debug("Retry to write key: {0} attempt: {1}/{2} "
                              "increased timeout: {3}/{4}"
                              .format(repr(self.it_response.key),
                                      self.attempt, self.ctx.attempts,
                                      self.direct_session.timeout, old_timeout))
                    self.stats.write_retries += 1
                    self.write_result = self.session.write_data(self.write_io,
                                                                self.write_data)
                    self.write_result.connect(self.onwrite)
                    return
                log.error("Writing key: {0} to node: {1} failed. "
                          "Skipping it: {2}"
                          .format(repr(self.it_response.key),
                                  self.dest_address, error))
                self.result = False
                self.stats.write_failed += 1
                return

            self.stats.write += 1
            self.stats.written_bytes += self.data_size

            log.debug("Key: {0} has been copied to node: {1}. "
                      "So we can delete it from node: {2}"
                      .format(repr(self.it_response.key),
                              self.dest_address, self.address))
            self.attempt = 0
            if not self.ctx.safe:
                log.debug("Removing key: {0} from node: {1}"
                          .format(repr(self.it_response.key), self.address))
                self.remove_result = self.direct_session.remove(self.it_response.key)
                self.remove_result.connect(self.onremove)
        except Exception as e:
            log.error("Onwrite exception: {0}".format(e))
            self.result = False

    def onremove(self, results, error):
        self.remove_result = None
        try:
            if error.code:
                log.debug("Remove key: {0} on node: {1} has been timed out: {2}"
                          .format(repr(self.it_response.key),
                                  self.address, error))
                if self.attempt < self.ctx.attempts:
                    old_timeout = self.direct_session.timeout
                    self.direct_session.timeout *= 2
                    self.attempt += 1
                    log.debug("Retry to remove key: {0} attempt: {1}/{2} "
                              "increased timeout: {3}/{4}"
                              .format(repr(self.it_response.key),
                                      self.attempt, self.ctx.attempts,
                                      self.direct_session.timeout, old_timeout))
                    self.stats.remove_retries += 1
                    self.remove_result = self.direct_session.remove(self.it_response.key)
                    self.remove_result.connect(self.onremove)
                    return
                log.error("Key: {0} hasn't been removed from node: {1}: {2}"
                          .format(repr(self.it_response.key),
                                  self.address, error))
                self.result = False
                self.stats.remove_failed += 1
                return

            self.stats.remove += 1
            self.stats.removed_bytes += self.data_size
        except Exception as e:
            log.error("Onremove exception: {0}".format(e))
            self.result = False

    def wait(self):
        log.debug("Waiting lookup for key: {0}".format(repr(self.it_response.key)))
        while hasattr(self, 'lookup_result') and self.lookup_result is not None:
            try:
                self.lookup_result.wait()
            except:
                pass
        log.debug("Lookup completed for key: {0}".format(repr(self.it_response.key)))

        log.debug("Waiting read for key: {0}".format(repr(self.it_response.key)))
        while hasattr(self, 'read_result') and self.read_result is not None:
            try:
                self.read_result.wait()
            except:
                pass
        log.debug("Read completed for key: {0}".format(repr(self.it_response.key)))

        log.debug("Waiting write for key: {0}".format(repr(self.it_response.key)))
        while hasattr(self, 'write_result') and self.write_result is not None:
            try:
                self.write_result.wait()
            except:
                pass
        log.debug("Write completed for key: {0}".format(repr(self.it_response.key)))

        log.debug("Waiting remove for key: {0}".format(repr(self.it_response.key)))
        while hasattr(self, 'remove_result') and self.remove_result is not None:
            try:
                self.remove_result.wait()
            except:
                pass
        log.debug("Remove completed for key: {0}".format(repr(self.it_response.key)))

    def succeeded(self):
        self.wait()
        return self.result


def iterate_node(ctx, node, address, ranges, eid, stats):
    try:
        log.debug("Running iterator on node: {0}".format(address))
        timestamp_range = ctx.timestamp.to_etime(), Time.time_max().to_etime()
        result, result_len = Iterator.iterate_with_stats(node=node,
                                                         eid=eid,
                                                         timestamp_range=timestamp_range,
                                                         key_ranges=[IdRange(r[0], r[1]) for r in ranges],
                                                         tmp_dir=ctx.tmp_dir,
                                                         address=address,
                                                         batch_size=ctx.batch_size,
                                                         stats=stats,
                                                         counters=['iterated_keys'],
                                                         leave_file=False)
        if result is None:
            return None
        log.info("Iterator {0} obtained: {1} record(s)"
                 .format(result.address, result_len))
        stats.counter('iterations', 1)
        return result
    except Exception as e:
        log.error("Iteration failed for: {0}: {1}"
                  .format(address, e))
        stats.counter('iterations', -1)
        return None


def recover(ctx, address, group, node, results, stats):
    if results is None or len(results) < 1:
        log.warning("Recover skipped iterator results are empty for node: {0}"
                    .format(address))
        return True

    ret = True
    for batch_id, batch in groupby(enumerate(results), key=lambda x: x[0] / ctx.batch_size):
        recovers = []
        rs = RecoverStat()
        for _, response in batch:
            rec = Recovery(ctx, response, address, group, node)
            rec.run()
            recovers.append(rec)
        for r in recovers:
            ret &= r.succeeded()
            rs += r.stats
        rs.apply(stats)
    return ret


def process_node(address, group, ranges):
    log.debug("Processing node: {0} from group: {1} for ranges: {2}"
              .format(address, group, ranges))
    ctx = g_ctx
    stats = ctx.monitor.stats['node_{0}'.format(address)]
    stats.timer('process', 'started')

    node = elliptics_create_node(address=ctx.address,
                                 elog=ctx.elog,
                                 wait_timeout=ctx.wait_timeout)
    s = elliptics.Session(node)

    stats.timer('process', 'iterate')
    results = iterate_node(ctx=ctx,
                           node=node,
                           address=address,
                           ranges=ranges,
                           eid=s.routes.get_address_eid(address),
                           stats=stats)
    if results is None or len(results) == 0:
        log.warning('Iterator result is empty, skipping')
        return True

    stats.timer('process', 'recover')
    ret = recover(ctx, address, group, node, results, stats)
    stats.timer('process', 'finished')

    return ret


def get_ranges(ctx, group):
    ranges = dict()
    routes = RouteList(ctx.routes.filter_by_group_id(group))

    ID_MIN = elliptics.Id([0] * 64, group)
    ID_MAX = elliptics.Id([255] * 64, group)

    addresses = None
    if ctx.one_node:
        if ctx.address not in routes.addresses():
            return None
        addresses = [ctx.address]
    else:
        addresses = routes.addresses()

    for addr in addresses:
        addr_ranges = routes.get_address_ranges(addr)
        if len(addr_ranges) == 0:
            continue

        ranges[addr] = []
        if addr_ranges[0][0] != ID_MIN:
            ranges[addr].append((ID_MIN, addr_ranges[0][0]))

        for i in xrange(1, len(addr_ranges)):
            ranges[addr].append((addr_ranges[i - 1][1], addr_ranges[i][0]))

        if addr_ranges[-1][1] != ID_MAX:
            ranges[addr].append((addr_ranges[-1][1], ID_MAX))

    return ranges


def main(ctx):
    global g_ctx
    g_ctx = ctx
    g_ctx.monitor.stats.timer('main', 'started')
    processes = min(g_ctx.nprocess, len(g_ctx.routes.addresses()))
    log.info("Creating pool of processes: {0}".format(processes))
    pool = Pool(processes=processes, initializer=worker_init)
    ret = True
    for group in g_ctx.groups:
        log.warning("Processing group: {0}".format(group))
        group_stats = g_ctx.monitor.stats['group_{0}'.format(group)]
        group_stats.timer('group', 'started')

        ranges = get_ranges(ctx, group)

        if ranges is None:
            continue

        pool_results = []

        log.debug("Processing nodes ranges: {0}".format(ranges))

        for range in ranges:
            pool_results.append(pool.apply_async(process_node, (range, group, ranges[range])))

        try:
            log.info("Fetching results")
            # Use INT_MAX as timeout, so we can catch Ctrl+C
            timeout = 2147483647
            for p in pool_results:
                ret &= p.get(timeout)
        except KeyboardInterrupt:
            log.error("Caught Ctrl+C. Terminating.")
            pool.terminate()
            pool.join()
            group_stats.timer('group', 'finished')
            g_ctx.monitor.stats.timer('main', 'finished')
            return False
        else:
            log.info("Closing pool, joining threads.")
            pool.close()
            pool.join()
            group_stats.timer('group', 'finished')
            g_ctx.monitor.stats.timer('main', 'finished')
            return False

        group_stats.timer('group', 'finished')

    g_ctx.monitor.stats.timer('main', 'finished')
    return ret
