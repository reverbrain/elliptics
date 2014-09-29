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
import os

from itertools import groupby
from multiprocessing import Pool
import traceback

from ..etime import Time
from ..utils.misc import elliptics_create_node, worker_init, RecoverStat, LookupDirect, RemoveDirect
from ..route import RouteList
from ..iterator import Iterator
from ..range import IdRange

# XXX: change me before BETA
sys.path.insert(0, "bindings/python/")
import elliptics

log = logging.getLogger(__name__)

# class for recovering one key with (timestamp, size) from address to group with check or not
# if callback is specified then it will be called when all work is done
class Recovery(object):
    def __init__(self, key, timestamp, size, address, backend_id, group, ctx, node, check=True, callback=None):
        self.key = key
        self.key_timestamp = timestamp
        self.address = address
        self.backend_id = backend_id
        self.group = group
        self.node = node
        self.direct_session = elliptics.Session(node)
        self.direct_session.set_direct_id(self.address, self.backend_id)
        self.direct_session.groups = [group]
        self.session = elliptics.Session(node)
        self.session.groups = [group]
        self.ctx = ctx
        self.stats = RecoverStat()
        self.result = True
        self.attempt = 0
        self.total_size = size
        self.recovered_size = 0
        self.just_remove = False
        # if size of object more that size of one chunk than file should be read/written in chunks
        self.chunked = self.total_size > self.ctx.chunk_size
        self.check = check
        self.callback = callback
        log.debug("Created Recovery object for key: {0}, node: {1}/{2}".format(repr(key), address, backend_id))

    def run(self):
        log.debug("Recovering key: {0}, node: {1}/{2}"
                  .format(repr(self.key), self.address, self.backend_id))
        address, _, backend_id = self.session.routes.filter_by_group(self.group).get_id_routes(self.key)[0]
        if (address, backend_id) == (self.address, self.backend_id):
            log.warning("Key: {0} already on the right node: {1}/{2}"
                        .format(repr(self.key), self.address, self.backend_id))
            self.stats.skipped += 1
            return
        else:
            log.debug("Key: {0} should be on node: {1}/{2}"
                      .format(repr(self.key), address, backend_id))
        self.dest_address = address
        self.dest_backend_id = backend_id
        if self.check:
            log.debug("Lookup key: {0} on node: {1}/{2}".format(repr(self.key), self.dest_address, self.dest_backend_id))
            self.lookup_result = LookupDirect(self.dest_address,
                                              self.dest_backend_id,
                                              self.key,
                                              self.group,
                                              self.ctx,
                                              self.node,
                                              self.onlookup)
            self.lookup_result.run()
        elif self.ctx.dry_run:
            log.debug("Dry-run mode is turned on. Skipping reading, writing and removing stages.")
        else:
            self.attempt = 0
            self.read()

    def read(self):
        size = 0
        try:
            log.debug("Reading key: {0} from node: {1}/{2}, chunked: {3}"
                      .format(repr(self.key), self.address, self.backend_id, self.chunked))
            if self.chunked:
                # size of chunk that should be read/written next
                size = min(self.total_size - self.recovered_size, self.ctx.chunk_size)
            if self.recovered_size != 0:
                # if it is not first chunk then do not check checksum on read
                self.direct_session.ioflags |= elliptics.io_flags.nocsum
            self.read_result = self.direct_session.read_data(self.key,
                                                             offset=self.recovered_size,
                                                             size=size)
            self.read_result.connect(self.onread)
        except Exception, e:
            log.error("Read key: {0} by offset: {1} and size: {2} raised exception: {3}, traceback: {4}"
                      .format(self.key, self.recovered_size, size, repr(e), traceback.format_exc()))
            self.result = False

    def write(self):
        try:
            log.debug("Writing key: {0} to node: {1}/{2}".format(repr(self.key),
                                                                 self.dest_address,
                                                                 self.dest_backend_id))
            if self.chunked:
                if self.recovered_size == 0:
                    # if it is first chunk - write it via prepare
                    self.write_result = self.session.write_prepare(key=self.key,
                                                                   data=self.write_data,
                                                                   remote_offset=self.recovered_size,
                                                                   psize=self.total_size)
                elif self.recovered_size + len(self.write_data) < self.total_size:
                    # if it is not last chunk - write it via write_plain
                    self.write_result = self.session.write_plain(key=self.key,
                                                                 data=self.write_data,
                                                                 remote_offset=self.recovered_size)
                else:
                    # if it is the last chunk - write it via write_commit
                    self.write_result = self.session.write_commit(key=self.key,
                                                                  data=self.write_data,
                                                                  remote_offset=self.recovered_size,
                                                                  csize=self.total_size)
            else:
                # if object was not splitted by chunks then write it via write_data
                self.write_result = self.session.write_data(key=self.key,
                                                            data=self.write_data,
                                                            offset=self.recovered_size)
            self.write_result.connect(self.onwrite)
        except Exception, e:
            log.error("Write exception: {0}, traceback: {1}"
                      .format(repr(e), traceback.format_exc()))
            self.result = False
            raise e

    def remove(self):
        if not self.ctx.safe:
            log.debug("Removing key: {0} from node: {1}/{2}".format(repr(self.key), self.address, self.backend_id))
            # remove object directly from address by using RemoveDirect
            self.remove_result = RemoveDirect(self.address,
                                              self.backend_id,
                                              self.key,
                                              self.group,
                                              self.ctx,
                                              self.node,
                                              self.onremove)
            self.remove_result.run()
        elif self.callback:
            self.callback(self.result, self.stats)

    def onlookup(self, result, stats):
        self.lookup_result = None
        try:
            self.stats += stats
            if result and self.key_timestamp < result.timestamp:
                self.just_remove = True
                log.debug("Key: {0} on node: {1}/{2} is newer. Just removing it from node: {3}/{4}."
                          .format(repr(self.key), self.dest_address, self.dest_backend_id, self.address, self.backend_id))
                if self.ctx.dry_run:
                    log.debug("Dry-run mode is turned on. Skipping removing stage.")
                    return
                self.attempt = 0
                self.remove()
                return

            log.debug("Key: {0} on node: {1}/{2} is older or miss. Reading it from node: {3}/{4}"
                      .format(repr(self.key), self.dest_address, self.dest_backend_id, self.address, self.backend_id))
            if self.ctx.dry_run:
                log.debug("Dry-run mode is turned on. Skipping reading, writing and removing stages.")
                return
            self.attempt = 0
            self.read()
        except Exception as e:
            log.error("Onlookup exception: {0}, traceback: {1}"
                      .format(repr(e), traceback.format_exc()))
            self.result = False
            if self.callback:
                self.callback(self.result, self.stats)

    def onread(self, results, error):
        self.read_result = None
        try:
            if error.code or len(results) < 1:
                log.debug("Read key: {0} on node: {1}/{2} has been timed out: {3}"
                          .format(repr(self.key), self.address, self.backend_id, error))
                if self.attempt < self.ctx.attempts:
                    old_timeout = self.session.timeout
                    self.session.timeout *= 2
                    self.attempt += 1
                    log.debug("Retry to read key: {0} attempt: {1}/{2} "
                              "increased timeout: {3}/{4}"
                              .format(repr(self.key), self.attempt,
                                      self.ctx.attempts,
                                      self.direct_session.timeout, old_timeout))
                    self.read()
                    self.stats.read_retries += 1
                    return
                log.error("Reading key: {0} on the node: {1}/{2} failed. "
                          "Skipping it: {3}"
                          .format(repr(self.key),
                                  self.address,
                                  self.backend_id,
                                  error))
                self.result = False
                self.stats.read_failed += 1
                return

            if self.recovered_size == 0:
                self.session.user_flags = results[0].user_flags
                self.session.timestamp = results[0].timestamp
            self.stats.read += 1
            self.write_data = results[0].data
            self.total_size = results[0].io_attribute.total_size
            self.stats.read_bytes += results[0].size
            self.attempt = 0
            self.write()
        except Exception as e:
            log.error("Onread exception: {0}, traceback: {1}"
                      .format(repr(e), traceback.format_exc()))
            self.result = False
            if self.callback:
                self.callback(self.result, self.stats)

    def onwrite(self, results, error):
        self.write_result = None
        try:
            if error.code or len(results) < 1:
                log.debug("Write key: {0} on node: {1}/{2} has been timed out: {3}"
                          .format(repr(self.key),
                                  self.dest_address,
                                  self.dest_backend_id,
                                  error))
                if self.attempt < self.ctx.attempts:
                    old_timeout = self.session.timeout
                    self.session.timeout *= 2
                    self.attempt += 1
                    log.debug("Retry to write key: {0} attempt: {1}/{2} "
                              "increased timeout: {3}/{4}"
                              .format(repr(self.key),
                                      self.attempt, self.ctx.attempts,
                                      self.direct_session.timeout, old_timeout))
                    self.stats.write_retries += 1
                    self.write()
                    return
                log.error("Writing key: {0} to node: {1}/{2} failed. "
                          "Skipping it: {3}"
                          .format(repr(self.key),
                                  self.dest_address,
                                  self.dest_backend_id,
                                  error))
                self.result = False
                self.stats.write_failed += 1
                return

            self.stats.write += 1
            self.stats.written_bytes += len(self.write_data)
            self.recovered_size += len(self.write_data)
            self.attempt = 0

            if self.recovered_size < self.total_size:
                self.read()
            else:
                log.debug("Key: {0} has been copied to node: {1}/{2}. So we can delete it from node: {3}/{4}"
                          .format(repr(self.key), self.dest_address, self.dest_backend_id, self.address, self.backend_id))
                self.remove()
        except Exception as e:
            log.error("Onwrite exception: {0}, traceback: {1}"
                      .format(repr(e), traceback.format_exc()))
            self.result = False
            if self.callback:
                self.callback(self.result, self.stats)

    def onremove(self, removed, stats):
        self.remove_result = None
        self.result &= removed
        self.stats += stats
        if self.callback:
            self.callback(self.result, self.stats)

    def wait(self):
        log.debug("Waiting lookup for key: {0}".format(repr(self.key)))
        while hasattr(self, 'lookup_result') and self.lookup_result is not None:
            try:
                self.lookup_result.wait()
            except:
                pass
        log.debug("Lookup completed for key: {0}".format(repr(self.key)))

        log.debug("Waiting read for key: {0}".format(repr(self.key)))
        while hasattr(self, 'read_result') and self.read_result is not None:
            try:
                self.read_result.wait()
            except:
                pass
        log.debug("Read completed for key: {0}".format(repr(self.key)))

        log.debug("Waiting write for key: {0}".format(repr(self.key)))
        while hasattr(self, 'write_result') and self.write_result is not None:
            try:
                self.write_result.wait()
            except:
                pass
        log.debug("Write completed for key: {0}".format(repr(self.key)))

        log.debug("Waiting remove for key: {0}".format(repr(self.key)))
        while hasattr(self, 'remove_result') and self.remove_result is not None:
            try:
                self.remove_result.wait()
            except:
                pass
        log.debug("Remove completed for key: {0}".format(repr(self.key)))

    def succeeded(self):
        self.wait()
        return self.result


def iterate_node(ctx, node, address, backend_id, ranges, eid, stats):
    try:
        log.debug("Running iterator on node: {0}/{1}".format(address, backend_id))
        timestamp_range = ctx.timestamp.to_etime(), Time.time_max().to_etime()
        key_ranges = [IdRange(r[0], r[1]) for r in ranges]
        result, result_len = Iterator.iterate_with_stats(node=node,
                                                         eid=eid,
                                                         timestamp_range=timestamp_range,
                                                         key_ranges=key_ranges,
                                                         tmp_dir=ctx.tmp_dir,
                                                         address=address,
                                                         backend_id=backend_id,
                                                         group_id = eid.group_id,
                                                         batch_size=ctx.batch_size,
                                                         stats=stats,
                                                         leave_file=False)
        if result is None:
            return None
        log.info("Iterator {0}/{1} obtained: {2} record(s)"
                 .format(result.address, backend_id, result_len))
        stats.counter('iterations', 1)
        return result
    except Exception as e:
        log.error("Iteration failed for: {0}/{1}: {2}, traceback: {3}"
                  .format(address, backend_id, repr(e), traceback.format_exc()))
        stats.counter('iterations', -1)
        return None


def recover(ctx, address, backend_id, group, node, results, stats):
    if results is None or len(results) < 1:
        log.warning("Recover skipped iterator results are empty for node: {0}/{1}"
                    .format(address, backend_id))
        return True

    ret = True
    for batch_id, batch in groupby(enumerate(results), key=lambda x: x[0] / ctx.batch_size):
        recovers = []
        rs = RecoverStat()
        for _, response in batch:
            rec = Recovery(key=response.key,
                           timestamp=response.timestamp,
                           size=response.size,
                           address=address,
                           backend_id=backend_id,
                           group=group,
                           ctx=ctx,
                           node=node)
            rec.run()
            recovers.append(rec)
        for r in recovers:
            ret &= r.succeeded()
            rs += r.stats
        rs.apply(stats)
    return ret


def process_node_backend(address, backend_id, group, ranges):
    log.debug("Processing node: {0}/{1} from group: {2} for ranges: {3}"
              .format(address, backend_id, group, ranges))
    ctx = g_ctx
    stats = ctx.monitor.stats['node_{0}/{1}'.format(address, backend_id)]
    stats.timer('process', 'started')

    node = elliptics_create_node(address=ctx.address,
                                 elog=ctx.elog,
                                 wait_timeout=ctx.wait_timeout,
                                 remotes=ctx.remotes,
                                 io_thread_num=4)
    s = elliptics.Session(node)

    stats.timer('process', 'iterate')
    results = iterate_node(ctx=ctx,
                           node=node,
                           address=address,
                           backend_id=backend_id,
                           ranges=ranges,
                           eid=s.routes.get_address_backend_route_id(address, backend_id),
                           stats=stats)
    if results is None or len(results) == 0:
        log.warning('Iterator result is empty, skipping')
        return True

    stats.timer('process', 'dump_keys')
    dump_path = os.path.join(ctx.tmp_dir, 'dump_{0}'.format(address))
    log.debug("Dump iterated keys to file: {0}".format(dump_path))
    with open(dump_path, 'w') as dump_f:
        for r in results:
            dump_f.write('{0}\n'.format(r.key))

    stats.timer('process', 'recover')
    ret = recover(ctx, address, backend_id, group, node, results, stats)
    stats.timer('process', 'finished')

    return ret


def get_ranges(ctx, group):
    ranges = dict()
    routes = RouteList(ctx.routes.filter_by_group(group))

    ID_MIN = elliptics.Id([0] * 64, group)
    ID_MAX = elliptics.Id([255] * 64, group)

    addresses = None
    if ctx.one_node:
        if ctx.backend_id == None:
            if ctx.address not in routes.addresses():
                log.error("Address: {0} wasn't found at group: {1} route list".format(ctx.address, group))
                return None
            addresses = routes.filter_by_address(ctx.address).addresses_with_backends()
        else:
            if (ctx.address, ctx.backend_id) not in routes.addresses_with_backends():
                log.error("Address: {0}/{1} hasn't been found in group: {2}".format(ctx.address, ctx.backend_id, ctx.group))
                return None
            addresses = ((ctx.address, ctx.backend_id),)
    else:
        addresses = routes.addresses_with_backends()

    for addr, backend_id in addresses:
        addr_info = (addr, backend_id)
        addr_ranges = routes.get_address_backend_ranges(addr, backend_id)
        if addr_ranges is None or len(addr_ranges) == 0:
            log.warning("Address: {0}/{1} has no range in group: {2}".format(addr, backend_id, group))
            continue

        ranges[addr_info] = []
        if addr_ranges[0][0] != ID_MIN:
            ranges[addr_info].append((ID_MIN, addr_ranges[0][0]))

        for i in xrange(1, len(addr_ranges)):
            ranges[addr_info].append((addr_ranges[i - 1][1], addr_ranges[i][0]))

        if addr_ranges[-1][1] != ID_MAX:
            ranges[addr_info].append((addr_ranges[-1][1], ID_MAX))

    return ranges


def main(ctx):
    global g_ctx
    g_ctx = ctx
    g_ctx.monitor.stats.timer('main', 'started')
    processes = min(g_ctx.nprocess, len(g_ctx.routes.addresses_with_backends()))
    log.info("Creating pool of processes: {0}".format(processes))
    pool = Pool(processes=processes, initializer=worker_init)
    ret = True
    if ctx.one_node:
        if ctx.backend_id == None:
            ctx.groups = tuple(set(ctx.groups).intersection(ctx.routes.get_address_groups(ctx.address)))
        else:
            ctx.groups = tuple(set(ctx.groups).intersection((ctx.routes.get_address_backend_group(ctx.address, ctx.backend_id),)))
    for group in ctx.groups:
        log.warning("Processing group: {0}".format(group))
        group_stats = g_ctx.monitor.stats['group_{0}'.format(group)]
        group_stats.timer('group', 'started')

        group_routes = ctx.routes.filter_by_groups([group])
        if len(group_routes.addresses_with_backends()) < 2:
            log.warning("Group {0} hasn't enough nodes/backends for recovery: {1}".format(group, group_routes.addresses_with_backends()))
            group_stats.timer('group', 'finished')
            continue

        ranges = get_ranges(ctx, group)

        if ranges is None or not len(ranges):
            log.warning("There is no ranges in group: {0}, skipping this group".format(group))
            group_stats.timer('group', 'finished')
            continue

        pool_results = []

        log.debug("Processing nodes ranges: {0}".format(ranges))

        for range in ranges:
            pool_results.append(pool.apply_async(process_node_backend, (range[0], range[1], group, ranges[range])))

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
        except Exception as e:
            log.error("Caught unexpected exception: {0}, traceback: {1}"
                      .format(repr(e), traceback.format_exc()))
            log.info("Closing pool, joining threads.")
            pool.close()
            pool.join()
            group_stats.timer('group', 'finished')
            g_ctx.monitor.stats.timer('main', 'finished')
            return False

        group_stats.timer('group', 'finished')

    log.info("Closing pool, joining threads.")
    pool.close()
    pool.join()
    g_ctx.monitor.stats.timer('main', 'finished')
    return ret


# special recovery class that lookups id on all nodes in group
# finds out newest version and reads/writes it to node where it should live.
class DumpRecover(object):
    def __init__(self, routes, node, id, group, ctx):
        self.node = node
        self.id = id
        self.routes = routes.filter_by_group(group)
        self.group = group
        self.ctx = ctx
        simple_session = elliptics.Session(node)
        # determines node where the id lives
        self.address = simple_session.lookup_address(self.id, group)
        self.async_lookups = []
        self.async_removes = []
        self.recover_address = None
        self.stats = RecoverStat()
        self.result = True

    def run(self):
        self.lookup_results = []
        # looks up for id on each node in group
        for addr, backend_id in self.routes.addresses_with_backends():
            self.async_lookups.append(LookupDirect(addr, backend_id, self.id, self.group, self.ctx, self.node, self.onlookup))
            self.async_lookups[-1].run()

    def onlookup(self, result, stats):
        self.stats += stats
        self.lookup_results.append(result)
        if len(self.lookup_results) == len(self.async_lookups):
            self.check()
            self.async_lookups = None

    def check(self):
        # finds timestamp of newest object
        max_ts = max([r.timestamp for r in self.lookup_results if r])
        log.debug("Max timestamp of key: {0}: {1}".format(repr(self.id), max_ts))
        # filters objects with newest timestamp
        results = [r for r in self.lookup_results if r and r.timestamp == max_ts]
        # finds max size of newest object
        max_size = max([r.size for r in results])
        log.debug("Max size of latest replicas for key: {0}: {1}".format(repr(self.id), max_size))
        # filters newest objects with max size
        results = [r.address for r in results if r.size == max_size]
        if self.address in results:
            log.debug("Node: {0} already has the latest version of key: {1}."
                      .format(self.address, repr(self.id), self.group))
            # if destination node already has newest object then just remove key from unproper nodes
            self.remove()
        else:
            # if destination node has outdated object - recovery it from one of filtered nodes
            self.timestamp = max_ts
            self.size = max_size
            self.recover_address = results[0]
            log.debug("Node: {0} has the newer version of key: {1}. Recovering it on node: {2}"
                      .format(self.recover_address, repr(self.id), self.address))
            self.recover()

    def recover(self):
        self.recover_result = Recovery(key=self.id,
                                       timestamp=self.timestamp,
                                       size=self.size,
                                       address=self.recover_address,
                                       group=self.group,
                                       ctx=self.ctx,
                                       node=self.node,
                                       check=False,
                                       callback=self.onrecover)
        self.recover_result.run()

    def onrecover(self, result, stats):
        self.result &= result
        self.stats += stats;
        self.remove()

    def remove(self):
        # remove id from node with positive lookups but not from destination node and node that took a part in recovery
        addresses_with_backends = [(r.address, r.backend_id) for r in self.lookup_results if r and r.address not in [self.address, self.recover_address]]
        if addresses_with_backends and not self.ctx.safe:
            log.debug("Removing key: {0} from nodes: {1}".format(repr(self.id), addresses))
            for addr, backend_id in addresses:
                self.async_removes.append(RemoveDirect(addr, backend_id, self.id, self.group, self.ctx, self.node, self.onremove))
                self.async_removes[-1].run()

    def wait(self):
        log.debug("Waiting lookup for key: {0}".format(repr(self.id)))
        while hasattr(self, 'async_lookups') and self.async_lookups is not None:
            for r in self.async_lookups:
                try:
                    self.r.wait()
                except:
                    pass
        log.debug("Lookup completed for key: {0}".format(repr(self.id)))
        if hasattr(self, 'recover_result'):
            self.recover_result.wait()

        log.debug("Waiting remove for key: {0}".format(repr(self.id)))
        if hasattr(self, 'async_removes') and self.async_removes is not None:
            for r in self.async_removes:
                try:
                    r.wait()
                except:
                    pass
        log.debug("Remove completed for key: {0}".format(repr(self.id)))

    def onremove(self, removed, stats):
        self.result &= removed
        self.stats += stats

    def succeeded(self):
        self.wait()
        return self.result


def dump_process_group(group):
    log.debug("Processing group: {0}".format(group))
    ctx = g_ctx
    stats = ctx.monitor.stats['group_{0}'.format(group)]
    if group not in ctx.routes.groups():
        log.error("Group: {0} is not presented in route list".format(group))
        return False
    ctx.elog = elliptics.Logger(ctx.log_file, int(ctx.log_level))
    node = elliptics_create_node(address=ctx.address,
                                 elog=ctx.elog,
                                 wait_timeout=ctx.wait_timeout,
                                 net_thread_num=1,
                                 io_thread_num=1,
                                 remotes=ctx.remotes)
    ret = True
    with open(ctx.dump_file, 'r') as dump:
        #splits ids from dump file in batchs and recovers it
        for batch_id, batch in groupby(enumerate(dump), key=lambda x: x[0] / ctx.batch_size):
            recovers = []
            rs = RecoverStat()
            for _, val in batch:
                rec = DumpRecover(routes=ctx.routes, node=node, id=elliptics.Id(val), group=group, ctx=ctx)
                recovers.append(rec)
                rec.run()
            for r in recovers:
                r.wait()
                ret &= r.succeeded()
                rs += r.stats
            rs.apply(stats)
    return ret


def dump_main(ctx):
    global g_ctx
    g_ctx = ctx
    ctx.monitor.stats.timer('main', 'started')
    processes = min(g_ctx.nprocess, len(g_ctx.groups))
    log.info("Creating pool of processes: {0}".format(processes))
    pool = Pool(processes=processes, initializer=worker_init)
    ret = True

    try:
        # processes each group in separated process
        results = pool.map(dump_process_group, ctx.groups)
    except KeyboardInterrupt:
        log.error("Caught Ctrl+C. Terminating.")
        pool.terminate()
        pool.join()
        ctx.monitor.stats.timer('main', 'finished')
        return False

    ret = all(results)

    log.info("Closing pool, joining threads.")
    pool.close()
    pool.join()
    ctx.monitor.stats.timer('main', 'finished')
    return ret
