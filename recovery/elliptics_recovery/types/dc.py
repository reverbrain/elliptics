# =============================================================================
# 2013+ Copyright (c) Kirill Smorodinnikov <shaitkir@gmail.com>
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

import logging
from multiprocessing import Pool
from ..utils.misc import worker_init, elliptics_create_node
from ..range import IdRange
from ..etime import Time
from ..iterator import Iterator, MergeData, KeyInfo, IteratorResult

import os
import pickle

import elliptics

log = logging.getLogger(__name__)


def iterate_node(arg):
    address, ranges = arg
    ctx = g_ctx
    ctx.elog = elliptics.Logger(ctx.log_file, int(ctx.log_level))
    stats_name = 'iterate_{0}'.format(address)
    stats = ctx.monitor.stats[stats_name]
    stats.timer('process', 'started')
    log.info("Running iterator")
    log.debug("Ranges:")
    for range in ranges:
        log.debug(repr(range))
    stats.timer('process', 'iterate')

    node_id = ctx.routes.get_address_id(address)

    node = elliptics_create_node(address=address,
                                 elog=ctx.elog,
                                 wait_timeout=ctx.wait_timeout,
                                 net_thread_num=4,
                                 io_thread_num=1)

    try:
        timestamp_range = ctx.timestamp.to_etime(), Time.time_max().to_etime()

        log.debug("Running iterator on node: {0}".format(address))
        results, results_len = Iterator.iterate_with_stats(
            node=node,
            eid=node_id,
            timestamp_range=timestamp_range,
            key_ranges=ranges,
            tmp_dir=ctx.tmp_dir,
            address=address,
            batch_size=ctx.batch_size,
            stats=stats,
            leave_file=True,
            separately=True)

    except Exception as e:
        log.error("Iteration failed for: {0}: {1}".format(address, repr(e)))
        stats.counter('iterations', -1)
        return None

    log.debug("Iterator {0} obtained: {1} record(s)"
              .format(address, results_len))
    stats.counter('iterations', 1)

    stats.timer('process', 'sort')
    for range_id in results:
        results[range_id].sort()

    stats.timer('process', 'finished')
    return [(range_id, container.filename, container.address)
            for range_id, container in results.items()]


def transpose_results(results):
    result_tree = dict()

    # for each address iterator results
    for res_dict in results:
        # for each range
        for range_id, filepath, address in res_dict:
            # if it first time with this range
            if range_id not in result_tree:
                # initialize it
                result_tree[range_id] = []
            # add iterator result to tree
            result_tree[range_id].append((filepath, address))

    return result_tree


def merge_results(arg):
    import heapq
    ctx = g_ctx

    range_id, results = arg
    results = [IteratorResult.load_filename(
        filename=r[0],
        address=r[1],
        is_sorted=True,
        tmp_dir=ctx.tmp_dir)
        for r in results]
    filename = os.path.join(ctx.tmp_dir, 'merge_{0}'.format(range_id))
    with open(filename, 'w') as f:
        pickler = pickle.Pickler(f)

        heap = []

        for d in results:
            try:
                heapq.heappush(heap, MergeData(d, None))
            except StopIteration:
                pass

        while len(heap):
            min_data = heapq.heappop(heap)
            key_data = (min_data.value.key,
                        [KeyInfo(min_data.address,
                                 min_data.value.timestamp,
                                 min_data.value.size,
                                 min_data.value.user_flags)])
            same_datas = [min_data]
            while len(heap) and min_data.value.key == heap[0].value.key:
                key_data[1].append(KeyInfo(heap[0].address,
                                           heap[0].value.timestamp,
                                           heap[0].value.size,
                                           heap[0].value.user_flags))
                same_datas.append(heapq.heappop(heap))
            pickler.dump(key_data)
            for i in same_datas:
                try:
                    i.next()
                    heapq.heappush(heap, i)
                except StopIteration:
                    pass

    return filename


def get_ranges(ctx):
    routes = ctx.routes.filter_by_group_ids(ctx.groups)
    addresses = dict()
    groups_number = len(routes.groups())
    prev_key = None
    ranges = []
    for i in range(groups_number):
        route = routes[i]
        addresses[route.key.group_id] = route.address
        prev_key = route.key

    for i in range(groups_number, len(routes) - groups_number + 1):
        route = routes[i]
        ranges.append((prev_key, routes[i].key, addresses.values()))
        prev_key = route.key
        addresses[route.key.group_id] = route.address

    if ctx.one_node:
        ranges = [x for x in ranges if ctx.address in x[2]]

    address_range = dict()

    for i, rng in enumerate(ranges):
        for addr in rng[2]:
            val = IdRange(rng[0], rng[1])
            if addr not in address_range:
                address_range[addr] = []
            address_range[addr].append(val)

    return address_range


def main(ctx):
    global g_ctx
    g_ctx = ctx
    ctx.monitor.stats.timer('main', 'started')
    ret = True
    if len(ctx.routes.groups()) < 2:
        log.error("There is only one group in route list: {0}. "
                  "sdc recovery could not be made."
                  .format(ctx.routes.groups()))
        return False
    processes = min(g_ctx.nprocess, len(g_ctx.routes.addresses()))
    log.info("Creating pool of processes: {0}".format(processes))
    pool = Pool(processes=processes, initializer=worker_init)

    ranges = get_ranges(ctx)
    results = None

    try:
        results = pool.map(iterate_node,
                           ((addr, ranges[addr], ) for addr in ranges))
    except KeyboardInterrupt:
        log.error("Caught Ctrl+C. Terminating.")
        pool.terminate()
        pool.join()
        ctx.monitor.stats.timer('main', 'finished')
        return False

    ctx.monitor.stats.timer('main', 'transpose')
    results = transpose_results(results)
    ctx.monitor.stats.timer('main', 'merge')

    try:
        results = pool.map(merge_results, (x for x in results.items()))
    except KeyboardInterrupt:
        log.error("Caught Ctrl+C. Terminating.")
        pool.terminate()
        pool.join()
        ctx.monitor.stats.timer('main', 'finished')
        return False

    ctx.merged_filename = os.path.join(ctx.tmp_dir, 'merged_result')

    with open(ctx.merged_filename, 'w') as m_file:
        for res in results:
            if res:
                with open(res, 'r') as r_file:
                    m_file.write(r_file.read())

    ctx.monitor.stats.timer('main', 'filter')
    log.debug("Merged_filename: %s, address: %s, groups: %s, tmp_dir:%s",
              ctx.merged_filename, ctx.address, ctx.groups, ctx.tmp_dir)

    if ctx.dry_run:
        return ret

    if ctx.custom_recover == '':
        from ..dc_recovery import recover
        recover(ctx)
    else:
        import imp
        log.debug("Loading module: {0}".format(ctx.custom_recover))
        imp.acquire_lock()
        custom_recover = imp.load_source('custom_recover', ctx.custom_recover)
        imp.release_lock()
        custom_recover.recover(ctx)

    ctx.monitor.stats.timer('main', 'finished')
    return ret


def lookup_keys(ctx):
    log.info("Start looking up keys")
    stats = ctx.monitor.stats["lookup"]
    stats.timer('process', 'started')
    ctx.elog = elliptics.Logger(ctx.log_file, int(ctx.log_level))
    node = elliptics_create_node(address=ctx.address,
                                 elog=ctx.elog,
                                 wait_timeout=ctx.wait_timeout,
                                 net_thread_num=1,
                                 io_thread_num=1)
    session = elliptics.Session(node)
    filename = os.path.join(ctx.tmp_dir, 'merged_result')
    merged_f = open(filename, 'w')
    pickler = pickle.Pickler(merged_f)
    with open(ctx.dump_file, 'r') as dump:
        for str_id in dump:
            id = elliptics.Id(str_id)
            lookups = []
            for g in ctx.groups:
                session.groups = [g]
                lookups.append(session.read_data(id, size=1))
            key_infos = []

            for i, l in enumerate(lookups):
                try:
                    result = l.get()[0]
                    address = result.address
                    address.group_id = ctx.groups[i]
                    key_infos.append(KeyInfo(address,
                                             result.timestamp,
                                             result.size,
                                             result.user_flags))
                except Exception, e:
                    log.error("Failed to lookup key: {} in group: {}: {}".format(id,
                                                                                 ctx.groups[i],
                                                                                 e))
                    stats.counter("lookups", -1)
            if len(key_infos) > 0:
                key_data = (id, key_infos)
                pickler.dump(key_data)
                stats.counter("lookups", len(key_infos))
            else:
                log.error("Key: {} is missing in all specified groups: {}. It won't be recovered."
                          .format(id, ctx.groups))
    stats.timer('process', 'finished')
    return filename


def dump_main(ctx):
    global g_ctx
    g_ctx = ctx
    ctx.monitor.stats.timer('main', 'started')
    ret = True
    if len(ctx.routes.groups()) < 2:
        log.error("There is only one group in route list: {0}. "
                  "sdc recovery could not be made."
                  .format(ctx.routes.groups()))
        return False

    try:
        ctx.merged_filename = lookup_keys(ctx)
    except KeyboardInterrupt:
        log.error("Caught Ctrl+C. Terminating.")
        ctx.monitor.stats.timer('main', 'finished')
        return False

    log.debug("Merged_filename: %s, address: %s, groups: %s, tmp_dir:%s",
              ctx.merged_filename, ctx.address, ctx.groups, ctx.tmp_dir)

    if ctx.dry_run:
        return ret

    if ctx.custom_recover == '':
        from ..dc_recovery import recover
        recover(ctx)
    else:
        import imp
        log.debug("Loading module: {0}".format(ctx.custom_recover))
        imp.acquire_lock()
        custom_recover = imp.load_source('custom_recover', ctx.custom_recover)
        imp.release_lock()
        custom_recover.recover(ctx)

    ctx.monitor.stats.timer('main', 'finished')
    return ret
