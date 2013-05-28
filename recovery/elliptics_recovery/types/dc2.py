#!/usr/bin/env python

__doc__ = \
    """
    New recovery mechanism for elliptics that utilizes new iterators and metadata.
    NB! For now only "merge" mode is supported e.g. recovery within a group.

     * Find ranges that host stole from neighbours in routing table.
     * Start metadata-only iterator fo each range on local and remote hosts.
     * Sort iterators' outputs.
     * Computes diff between local and remote iterator.
     * Recover keys provided by diff using bulk APIs.
    """

import sys
import logging as log

from multiprocessing import Pool

from ..iterator import Iterator, IteratorResult
from ..time import Time
from ..utils.misc import format_id, mk_container_name, elliptics_create_node, elliptics_create_session

# XXX: change me before BETA
sys.path.insert(0, "bindings/python/")
import elliptics

log.getLogger()

def run_iterators(ctx, ranges=None):
    """
    Runs local and remote iterators for each range.
    TODO: We can group iterators by host and run them in parallel
    TODO: We can run only one iterator per host if we'll teach iterators to "batch" all key ranges in one request
    """
    local_group_id = ctx.group_id

    node = elliptics_create_node(address=ctx.address, elog=ctx.elog)

    records = 0
    it = 0

    try:
        timestamp_range = ctx.timestamp.to_etime(), Time.time_max().to_etime()
        eid = ranges[0].address[0]
        group_id = ranges[0].address[2]

        log.debug("Running iterator on: {0} address: {1}".format(', '.join(
                [mk_container_name(range.id_range, eid) for range in ranges])
            , ranges[0].address[1]))
        results = Iterator(node, group_id).start(
            eid = eid,
            timestamp_range = timestamp_range,
            key_ranges = [r.id_range for r in ranges],
            tmp_dir = ctx.tmp_dir,
            address = ranges[0].address[1],
            leave_file=True)
        for r in results:
            records += len(r)
            r.address = ranges[0].address[1]
            r.group_id = ranges[0].address[2]
        it += 1
        log.debug("{0} obtained: {1} record(s)".format(ranges[0].address[1], records))
    except Exception as e:
        log.error("Iteration failed for: {0}@{1}: {2}".format(
            range.id_range, range.address, repr(e)))

    return results, records, it

def sort(ctx, results):
    """
    Runs sort routine for all iterator result
    """
    sorted_results = []
    sort_skipped = 0
    sort_sort = 0
    for r in results:
        if not r.status:
            log.debug("Sort skipped because some iterator failed")
            sort_skipped += 1
            sorted_results.append(r)
            continue
        if len(r) == 0:
            log.debug("Sort skipped iterator results are empty")
            sorted_results.append(r)
            continue
        try:
            log.info("Processing sorting range: {0}".format(r.id_range))
            r.container.sort()
            sort_sort += 1

            sorted_results.append(r)
        except Exception as e:
            log.error("Sort of {0} failed: {1}".format(r.id_range, e))
            sort_sort -= 1
    return sorted_results, sort_skipped, sort_sort

def diff(local_results, remote_results):
    diff_results = dict()
    for remote in remote_results:
        try:
            if len(remote) == 0:
                log.info("Remote container is empty, skipping range: {0}".format(remote.id_range))
                continue

            local = [l for l in local_results if l.id_range == remote.id_range][0]

            if len(local) == 0 and len(remote) > 0:
                # If local container is empty and remote is not
                # then difference is whole remote container
                log.info("Local container is empty, recovering full range: {0}".format(local.id_range))
                result = remote;
            else:
                log.info("Computing differences for: {0}".format(local.id_range))
                result = local.diff(remote)
                result.address = remote.address
                result.group_id = remote.group_id
            if len(result) > 0:
                for res in result:
                    res.address = remote.address
                    res.group_id = remote.group_id
                    key = tuple(res.key)
                    if key in diff_results:
                        diff = diff_results[key]
                        if diff.timestamp.tsec > res.timestamp.tsec:
                            continue
                        elif diff.timestamp.tsec == res.timestamp.tsec and diff.timestamp.tnsec > res.timestamp.tnsec:
                            continue

                        diff_results[key] = res
                    else:
                        diff_results[format_id(res.key)] = res
            else:
                log.info("Resulting diff is empty, skipping range: {0}".format(local.id_range))
        except Exception as e:
            log.error("Diff of {0} failed: {1}".format(local.id_range, e))
    return diff_results

def recover(ctx, diffs):
    """
    Recovers difference between remote and local data.
    TODO: Group by diffs by host and process each group in parallel
    """
    result = True
    addresses = set([(r.address, r.group_id) for r in diffs.values()])
    successes = 0
    failures = 0
    for address, group_id in addresses:
        keys = [elliptics.Id(r.key, group_id, 0) for r in diffs.values() if r.address == address]
        succ, fail = recover_keys(ctx, address, group_id, keys)
        successes += succ
        failures += fail
        result &= (fail == 0)
    return result, successes, failures

def recover_keys(ctx, address, group, keys):
    """
    Bulk recovery of keys.
    """
    key_num = len(keys)

    log.debug("Reading {0} keys".format(key_num))
    try:
        node = elliptics_create_node(address=address, elog=ctx.elog, flags=2)
        log.debug("Creating direct session: {0}".format(address))
        direct_session = elliptics_create_session(node=node,
                                                  group=group,
                                                  cflags=elliptics.command_flags.direct,
        )
        batch = direct_session.bulk_read(keys)
    except Exception as e:
        log.debug("Bulk read failed: {0} keys: {1}".format(key_num, e))
        return 0, key_num

    size = sum(len(v[1]) for v in batch)
    log.debug("Writing {0} keys: {1} bytes".format(key_num, size))
    try:
        node = elliptics_create_node(address=ctx.address, elog=ctx.elog, flags=2)
        log.debug("Creating direct session: {0}".format(ctx.address))
        direct_session = elliptics_create_session(node=node,
                                                  group=ctx.group_id,
                                                  cflags=elliptics.command_flags.direct,
        )
        direct_session.bulk_write(batch)
    except Exception as e:
        log.debug("Bulk write failed: {0} keys: {1}".format(key_num, e))
        return 0, key_num
    return key_num, 0



def process_range(ranges):
    global g_ctx
    g_ctx.elog = elliptics.Logger(g_ctx.log_file, g_ctx.log_level)
    results, records, it = run_iterators(g_ctx, ranges)
    results, sort_skipped, sort_sort = sort(g_ctx, results)
    results = [(s.id_range, s.eid, s.address, s.group_id) for s in results]
    return results, records, it, sort_skipped, sort_sort
    #it_results, local_r, remote_r, local_it, remote_it = run_iterators(g_ctx, ranges=ranges)
    #sorted_results, sort_skipped, sort_local, sort_remote, sort_sort = sort(g_ctx, it_results)
    #diff_results = diff(g_ctx, sorted_results)
    #result, successes, failures = recover(g_ctx, diff_results)

    #return result, local_r, remote_r, local_it, remote_it, sort_skipped, sort_local, sort_remote, sort_sort, len(diff_results), successes, failures


def main(ctx):
    result = True
    global g_ctx
    g_ctx = ctx
    g_ctx.stats.timer.main('started')
    if len(g_ctx.groups) == 0:
        g_ctx.groups = g_ctx.routes.groups()
    log.debug("Groups: %s" % g_ctx.groups)

    g_ctx.group_id = g_ctx.routes.filter_by_address(g_ctx.address)[0].key.group_id

    log.warning("Searching for ranges that %s store" % g_ctx.address)
    ranges = g_ctx.routes.get_local_ranges_by_address(g_ctx.address)
    log.debug("Recovery ranges: %d" % len(ranges))
    if not ranges:
        log.warning("No ranges to recover for address %s" % g_ctx.address)
        g_ctx.stats.timer.main('finished')
        return result

    async_results = []
    g_ctx.pool = Pool(processes=g_ctx.nprocess)
    log.debug("Created pool of processes: %d" % g_ctx.nprocess)

    recover_stats = ctx.stats["recover"]
    recover_stats.timer.group('started')

    log.debug("Elliptics nodes: {0}".format(ranges.keys()))

    local_async_result = g_ctx.pool.apply_async(process_range, (ranges[str(g_ctx.address)], ))

    del ranges[str(g_ctx.address)] # removes local node ranges

    for r in ranges:
        async_results.append(g_ctx.pool.apply_async(process_range, (ranges[r],)))

    local_result, local_records, local_it, local_sort_skipped, local_sort_sort = local_async_result.get()
    recover_stats.counter.records += local_records
    recover_stats.counter.local_records += local_records
    recover_stats.counter.local_iterations += local_it
    recover_stats.counter.iterations += local_it
    recover_stats.counter.sort_skipped += local_sort_skipped
    recover_stats.counter.sorted_records += local_sort_sort

    local = []

    def init_it_result(i):
        id_range, eid, address, group_id = i
        filename = mk_container_name(id_range, eid)
        it_result = IteratorResult.load_filename(filename, address=address, eid=eid, sorted=True, id_range=id_range, tmp_dir=g_ctx.tmp_dir, leave_file=False)
        it_result.address = address
        it_result.group_id = group_id
        return it_result
        local.append(it_result)

    for i in local_result:
        local.append(init_it_result(i))

    remote = []

    for r in async_results:
        res, records, it, sort_skipped, sort_sort = r.get()
        recover_stats.counter.records += records
        recover_stats.counter.remote_records += records
        recover_stats.counter.remote_iterations += it
        recover_stats.counter.iterations += it
        recover_stats.counter.sort_skipped += sort_skipped
        recover_stats.counter.sorted_records += sort_sort
        for i in res:
            remote.append(init_it_result(i))

    diff_results = diff(local, remote)

    recover_stats.counter.diff += len(diff_results)

    if not g_ctx.test:
        result, successes, failures = recover(g_ctx, diff_results)
        recover_stats.counter.recover_key += successes
        recover_stats.counter.recover_key -= failures

    recover_stats.timer.group('finished')
    ctx.stats.timer.main('finished')
    log.debug("Result: %s" % result)

    return result
