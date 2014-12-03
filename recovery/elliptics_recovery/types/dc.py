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
from ..utils.misc import elliptics_create_node, dump_key_data, KeyInfo
from ..range import IdRange
from ..etime import Time
from ..iterator import Iterator, MergeData, IteratorResult
from ..dc_recovery import recover

import os
import traceback

import elliptics

log = logging.getLogger(__name__)


def iterate_node(arg):
    ctx, address, backend_id, ranges = arg
    elog = elliptics.Logger(ctx.log_file, int(ctx.log_level))
    stats = ctx.stats["iterate"][str(address)][str(backend_id)]
    stats.timer('process', 'started')
    log.info("Running iterator on node: {0}/{1}".format(address, backend_id))
    log.debug("Ranges:")
    for range in ranges:
        log.debug(repr(range))
    stats.timer('process', 'iterate')

    node_id = ctx.routes.get_address_backend_route_id(address, backend_id)

    node = elliptics_create_node(address=address,
                                 elog=elog,
                                 wait_timeout=ctx.wait_timeout,
                                 net_thread_num=4,
                                 io_thread_num=1)

    try:
        flags = elliptics.iterator_flags.key_range
        timestamp_range = ctx.timestamp.to_etime(), Time.time_max().to_etime()
        if ctx.no_meta:
            flags |= elliptics.iterator_flags.no_meta
        else:
            flags |= elliptics.iterator_flags.ts_range

        log.debug("Running iterator on node: {0}/{1}".format(address, backend_id))
        results, results_len = Iterator.iterate_with_stats(
            node=node,
            eid=node_id,
            timestamp_range=timestamp_range,
            key_ranges=ranges,
            tmp_dir=ctx.tmp_dir,
            address=address,
            backend_id=backend_id,
            group_id=node_id.group_id,
            batch_size=ctx.batch_size,
            stats=stats,
            flags=flags,
            leave_file=True,
            separately=True)
        if results is None or results_len == 0:
            return None

    except Exception as e:
        log.error("Iteration failed for node {0}/{1}: {2}, traceback: {3}"
                  .format(address, backend_id, repr(e), traceback.format_exc()))
        return None

    log.debug("Iterator for node {0}/{1} obtained: {2} record(s)"
              .format(address, backend_id, results_len))

    stats.timer('process', 'sort')
    for range_id in results:
        results[range_id].sort()

    stats.timer('process', 'finished')
    return [(range_id, container.filename, container.address, container.backend_id, container.group_id)
            for range_id, container in results.items()]


def transpose_results(results):
    log.debug("Transposing iteration results from all nodes")
    result_tree = dict()

    # for each address iterator results
    for res_dict in (r for r in results if r is not None):
        # for each range
        for range_id, filepath, address, backend_id, group_id in res_dict:
            # if it first time with this range
            if range_id not in result_tree:
                # initialize it
                result_tree[range_id] = []
            # add iterator result to tree
            result_tree[range_id].append((filepath, address, backend_id, group_id))

    return result_tree


def skip_key_data(ctx, key_data):
    '''
    Checks that all groups are presented in key_data and
    all key_datas have equal timestamp and user_flags
    '''
    count = len(key_data[1])
    if count < len(ctx.groups):
        return False
    assert count == len(ctx.groups)

    first = key_data[1][0]
    return all(((k.timestamp, k.user_flags) == (first.timestamp, first.user_flags) for k in key_data[1]))


def merge_results(arg):
    import heapq

    ctx, range_id, results = arg
    log.debug("Merging iteration results of range: {0}".format(range_id))
    results = [IteratorResult.load_filename(
        filename=r[0],
        address=r[1],
        backend_id=r[2],
        group_id=r[3],
        is_sorted=True,
        tmp_dir=ctx.tmp_dir)
        for r in results]
    filename = os.path.join(ctx.tmp_dir, 'merge_{0}'.format(range_id))
    dump_filename = os.path.join(ctx.tmp_dir, 'dump_{0}'.format(range_id))
    keys_counter = 0
    with open(filename, 'w') as f:
        with open(dump_filename, 'w') as df:
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
                                     min_data.group_id,
                                     min_data.value.timestamp,
                                     min_data.value.size,
                                     min_data.value.user_flags)])
                same_datas = [min_data]
                while len(heap) and min_data.value.key == heap[0].value.key:
                    key_data[1].append(KeyInfo(heap[0].address,
                                               heap[0].group_id,
                                               heap[0].value.timestamp,
                                               heap[0].value.size,
                                               heap[0].value.user_flags))
                    same_datas.append(heapq.heappop(heap))

                # skip keys that already exist and equal in all groups
                if not skip_key_data(ctx, key_data):
                    keys_counter += 1
                    dump_key_data(key_data, f)
                    if ctx.dump_keys:
                        df.write('{0}\n'.format(key_data[0]))
                for i in same_datas:
                    try:
                        i.next()
                        heapq.heappush(heap, i)
                    except StopIteration:
                        pass
    ctx.stats.counter("total_keys", keys_counter)
    return filename, dump_filename


def get_ranges(ctx):
    routes = ctx.routes.filter_by_groups(ctx.groups)
    addresses = dict()
    groups_number = len(routes.groups())
    prev_id = None
    ranges = []
    for i in range(groups_number):
        route = routes[i]
        addresses[route.id.group_id] = (route.address, route.backend_id)
        prev_id = route.id

    for i in range(groups_number, len(routes) - groups_number + 1):
        route = routes[i]
        ranges.append((prev_id, routes[i].id, addresses.values()))
        prev_id = route.id
        addresses[route.id.group_id] = (route.address, route.backend_id)

    def contains(addresses_with_backends, address, backend_id):
        for addr, bid in addresses_with_backends:
            if addr == address and (backend_id is None or backend_id == bid):
                return True
        return False

    if ctx.one_node:
        ranges = [x for x in ranges if contains(x[2], ctx.address, ctx.backend_id)]

    address_range = dict()

    for i, rng in enumerate(ranges):
        for addr in rng[2]:
            val = IdRange(rng[0], rng[1], range_id=i)
            if addr not in address_range:
                address_range[addr] = []
            address_range[addr].append(val)
    return address_range


def final_merge(ctx, results):
    import shutil
    ctx.stats.timer('main', 'final_merge')
    log.info("final merge")

    ctx.merged_filename = os.path.join(ctx.tmp_dir, 'merged_result')
    dump_filename = os.path.join(ctx.tmp_dir, 'dump')
    with open(ctx.merged_filename, 'wb') as mf:
        with open(dump_filename, 'wb') as df:
            for res in (r for r in results if r):
                shutil.copyfileobj(open(res[0], 'rb'), mf)
                os.remove(res[0])
                shutil.copyfileobj(open(res[1], 'rb'), df)
                os.remove(res[1])

    log.debug("Merged_filename: %s, address: %s, groups: %s, tmp_dir: %s",
              ctx.merged_filename, ctx.address, ctx.groups, ctx.tmp_dir)


def main(ctx):
    ctx.stats.timer('main', 'started')
    ret = True
    if len(ctx.routes.groups()) < 2:
        log.error("There is only one group in route list: {0}. "
                  "sdc recovery could not be made."
                  .format(ctx.routes.groups()))
        return False

    ranges = get_ranges(ctx)
    log.debug("Ranges: {0}".format(ranges))
    results = None

    try:
        ctx.stats.timer('main', 'iterating')
        log.info("Start iterating {0} nodes in the pool".format(len(ranges)))
        results = ctx.pool.map(iterate_node, ((ctx.portable(), addr[0], addr[1], ranges[addr]) for addr in ranges))
    except KeyboardInterrupt:
        log.error("Caught Ctrl+C. Terminating.")
        ctx.stats.timer('main', 'finished')
        return False

    ctx.stats.timer('main', 'transpose')
    log.info("Transposing iteration results")
    results = transpose_results(results)
    ctx.stats.timer('main', 'merge')

    try:
        log.info("Merging iteration results from different nodes")
        results = ctx.pool.map(merge_results, ((ctx.portable(), ) + x for x in results.items()))
    except KeyboardInterrupt:
        log.error("Caught Ctrl+C. Terminating.")
        ctx.stats.timer('main', 'finished')
        return False

    final_merge(ctx, results)

    if ctx.dry_run:
        ctx.stats.timer('main', 'finished')
        return ret

    ctx.stats.timer('main', 'recover')
    log.info("Start recovering")
    if ctx.custom_recover == '':
        ret &= recover(ctx)
    else:
        import imp
        log.debug("Loading module: {0}".format(ctx.custom_recover))
        imp.acquire_lock()
        custom_recover = imp.load_source('custom_recover', ctx.custom_recover)
        imp.release_lock()
        ret &= custom_recover.recover(ctx)

    ctx.stats.timer('main', 'finished')
    return ret


def lookup_keys(ctx):
    log.info("Start looking up keys")
    stats = ctx.stats["lookup"]
    stats.timer('process', 'started')
    elog = elliptics.Logger(ctx.log_file, int(ctx.log_level))
    node = elliptics_create_node(address=ctx.address,
                                 elog=elog,
                                 wait_timeout=ctx.wait_timeout,
                                 net_thread_num=1,
                                 io_thread_num=1,
                                 remotes=ctx.remotes)
    session = elliptics.Session(node)
    filename = os.path.join(ctx.tmp_dir, 'merged_result')
    with open(filename, 'w') as merged_f:
        with open(ctx.dump_file, 'r') as dump_f:
            for str_id in dump_f:
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
                        key_infos.append(KeyInfo(address,
                                                 ctx.groups[i],
                                                 result.timestamp,
                                                 result.total_size,
                                                 result.user_flags))
                    except Exception, e:
                        log.debug("Failed to lookup key: {0} in group: {1}: {2}, traceback: {3}"
                                  .format(id, ctx.groups[i], repr(e), traceback.format_exc()))
                        stats.counter("lookups", -1)
                if len(key_infos) > 0:
                    key_data = (id, key_infos)
                    dump_key_data(key_data, merged_f)
                    stats.counter("lookups", len(key_infos))
                else:
                    log.error("Key: {0} is missing in all specified groups: {1}. It won't be recovered."
                              .format(id, ctx.groups))
    stats.timer('process', 'finished')
    return filename


def dump_main(ctx):
    ctx.stats.timer('main', 'started')
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
        ctx.stats.timer('main', 'finished')
        return False

    log.debug("Merged_filename: %s, address: %s, groups: %s, tmp_dir:%s",
              ctx.merged_filename, ctx.address, ctx.groups, ctx.tmp_dir)

    if ctx.dry_run:
        return ret

    if ctx.custom_recover == '':
        recover(ctx)
    else:
        import imp
        log.debug("Loading module: {0}".format(ctx.custom_recover))
        imp.acquire_lock()
        custom_recover = imp.load_source('custom_recover', ctx.custom_recover)
        imp.release_lock()
        custom_recover.recover(ctx)

    ctx.stats.timer('main', 'finished')
    return ret
