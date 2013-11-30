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

 * Find ranges that host is responsible for now.
 * Start metadata-only iterator for the found ranges on local and remote hosts.
 * Sort iterators' outputs.
 * Computes diff between local and remote iterator.
 * Recover keys provided by diff using bulk APIs.
 * If necessary removes recovered keys from remote hosts.
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

# XXX: change me before BETA
sys.path.insert(0, "bindings/python/")
import elliptics

log = logging.getLogger(__name__)


class Recovery(object):
    def __init__(self, ctx, it_response, address, group, node, stats):
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
        self.stats = stats
        self.result = True
        log.debug("Created Recovery object for key: {0}, node: {2}, group: {1}"
                  .format(it_response.key,
                          address,
                          group))

    def run(self):
        log.debug("Recovering key: {0}, node: {2}, group: {1}"
                  .format(repr(self.it_response.key),
                          self.address,
                          self.group))
        log.debug("Looking up address for key: {0} in group: {1}"
                  .format(repr(self.it_response.key),
                          self.group))
        address = self.session.lookup_address(self.it_response.key, self.group)
        if address == self.address:
            log.warning("Key: {0} already on the right node: {1} in group: {2}"
                        .format(repr(self.it_response.key),
                                self.address,
                                self.group))
            self.stats.counter('skipped_keys', 1)
            return
        log.debug("Lookup key: {0} in group: {1}"
                  .format(repr(self.it_response.key),
                          self.group))
        self.lookup_result = self.session.lookup(self.it_response.key)
        self.lookup_result.connect(self.onlookup)

    def onlookup(self, results, error):
        try:
            log.debug("Onlookup results: {0} error: {1}"
                      .format(results, error))
            self.stats.counter('lookup', 1)
            if error.code == 0 and self.it_response.timestamp < results[0].timestamp:
                log.warning("Key: {0} in group: {1} is newer. "
                            "Just removing it from node: {2}."
                            .format(repr(self.it_response.key),
                                    self.group,
                                    self.address))
                if g_ctx.dry_run:
                    log.debug("Dry-run mode is turned on. Skipping removing stage.")
                    return
                self.remove_result = self.direct_session.remove(self.it_response.key)
                self.remove_result.connect(self.onremove)
                return

            log.debug("Key: {0} in group: {1} is older or miss. "
                      "Reading it from node: {2}"
                      .format(repr(self.it_response.key),
                              self.group,
                              self.address))
            if g_ctx.dry_run:
                log.debug("Dry-run mode is turned on. "
                          "Skipping reading, writing and removing stages.")
                return
            self.read_result = self.direct_session.read_data(self.it_response.key)
            self.read_result.connect(self.onread)
        except Exception as e:
            log.debug("Onlookup exception: {0}".format(e))
            self.result = False

    def onread(self, results, error):
        try:
            if error.code != 0 or len(results) < 1:
                log.error("Reading key: {0} on the node: {1} failed. "
                          "Skipping it: {2}"
                          .format(repr(self.it_response.key),
                                  self.address,
                                  error))
                self.stats.counter('read_keys', -1)
                self.result = False
                return

            self.stats.counter('read_keys', 1)
            io = elliptics.IoAttr()
            io.id = results[0].id
            io.timestamp = results[0].timestamp
            io.user_flags = results[0].user_flags
            log.debug("Writing read key: {0} to group: {1}"
                      .format(self.it_response.key, self.group))
            self.data_size = len(results[0].data)
            self.stats.counter('read_bytes', self.data_size)
            self.write_result = self.session.write_data(io, results[0].data)
            self.write_result.connect(self.onwrite)
        except Exception as e:
            log.debug("Onread exception: {0}".format(e))
            self.result = False

    def onwrite(self, results, error):
        try:
            if error.code != 0 or len(results) < 1:
                log.error("Writing key: {0} to group: {1} failed."
                          "Skipping it: {2}"
                          .format(repr(self.it_response.key),
                                  self.group,
                                  error))
                self.stats.counter('written_key', -1)
                self.stats.counter('written_bytes', -self.data_size)
                self.result = False
                return

            self.stats.counter('written_key', 1)
            self.stats.counter('written_bytes', self.data_size)

            log.debug("Key: {0} has been successfully copied to the right node"
                      "in group: {1}. So we can delete it from node: {2}"
                      .format(repr(self.it_response.key),
                              self.group,
                              self.address))
            self.remove_result = self.direct_session.remove(self.it_response.key)
            self.remove_result.connect(self.onremove)
        except Exception as e:
            log.debug("Onwrite exception: {0}".format(e))
            self.result = False

    def onremove(self, results, error):
        try:
            if error.code != 0:
                log.debug("Key: {0} hasn't been removed from node: {1}: {2}"
                          .format(repr(self.it_response.key),
                                  self.address,
                                  error))
                self.stats.counter('removed_keys', -1)
                self.result = False
                return
            self.stats.counter('removed_keys', 1)
        except Exception as e:
            log.debug("Onremove exception: {0}".format(e))
            self.result = False

    def wait(self):
        try:
            log.debug("Waiting lookup complete")
            if hasattr(self, 'lookup_result'):
                self.lookup_result.wait()
        except Exception as e:
            log.debug("Got exception while waiting lookup: {0}"
                      .format(e))
            pass
        try:
            log.debug("Waiting read complete")
            if hasattr(self, 'read_result'):
                self.read_result.wait()
        except Exception as e:
            log.debug("Got exception  while waiting read: {0}"
                      .format(e))
            pass
        try:
            log.debug("Waiting write complete")
            if hasattr(self, 'write_result'):
                self.write_result.wait()
        except Exception as e:
            log.debug("Got exception  while waiting write: {0}"
                      .format(e))
            pass
        try:
            log.debug("Waiting remove complete")
            if hasattr(self, 'remove_result'):
                self.remove_result.wait()
        except Exception as e:
            log.debug("Got exception  while waiting remove: {0}"
                      .format(e))
            pass

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
        for _, response in batch:
            rec = Recovery(ctx, response, address, group, node, stats)
            rec.run()
            recovers.append(rec)
        for r in recovers:
            ret &= r.succeeded()
    return ret


def process_node(address, group, ranges):
    log.debug("Processing node: {0} from group: {1} for ranges: {2}"
              .format(address, group, ranges))
    ctx = g_ctx
    stats = ctx.monitor.stats['node_{0}'.format(address)]
    stats.timer('process', 'started')

    node = elliptics_create_node(address=address,
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

    stats.timer('process', 'recover')
    recover(ctx, address, group, node, results, stats)

    stats.timer('process', 'finished')


def main(ctx):
    global g_ctx
    g_ctx = ctx
    g_ctx.monitor.stats.timer('main', 'started')
    processes = min(g_ctx.nprocess, len(g_ctx.routes.addresses()))
    log.info("Creating pool of processes: {0}".format(processes))
    pool = Pool(processes=processes, initializer=worker_init)
    for group in g_ctx.groups:
        log.warning("Processing group: {0}".format(group))
        group_stats = g_ctx.monitor.stats['group_{0}'.format(group)]
        group_stats.timer('group', 'started')

        routes = RouteList(g_ctx.routes.filter_by_group_id(group))

        ranges = dict()

        prev = elliptics.Route(elliptics.Id([0] * 64, group), None)
        for route in routes:
            if route.address != prev.address and prev.key < route.key:
                if route.address in ranges:
                    ranges[route.address].append((prev.key, route.key))
                else:
                    ranges[route.address] = [(prev.key, route.key)]
            prev = route

        pool_results = []

        log.debug("Processing nodes ranges: {0}".format(ranges))

        for range in ranges:
            pool_results.append(pool.apply_async(process_node, (range, group, ranges[range])))

        for p in pool_results:
            print p.get()
