"""
Merge recovery type - recovers keys in one hash ring (aka group)
by placing them to the node where they belong.

 * Find ranges that host stole from neighbours in routing table.
 * Start metadata-only iterator fo each range on local and remote hosts.
 * Sort iterators' outputs.
 * Computes diff between local and remote iterator.
 * Recover keys provided by diff using bulk APIs.
"""

import sys
import logging

from itertools import groupby
from multiprocessing import Pool

from ..range import IdRange, RecoveryRange
from ..route import RouteList
from ..iterator import Iterator
from ..etime import Time
from ..utils.misc import format_id, elliptics_create_node, elliptics_create_session, worker_init

# XXX: change me before BETA
sys.path.insert(0, "bindings/python/")
import elliptics

log = logging.getLogger(__name__)

def get_ranges(ctx, routes, group_id):
    """
    For each record in RouteList create 1 or 2 RecoveryRange(s)
    Returns list of RecoveryRange`s
    """
    ranges = []
    for i, route in enumerate(routes):
        ekey, address = routes[i]
        prev_address = routes[i - 1].address
        next_ekey = routes[i + 1].key
        # For matching address but only in case where there is no wraparound
        if address == ctx.address and address != prev_address:
            log.debug("Processing route: {0}, {1}".format(format_id(ekey.id), address))
            start = ekey.id
            stop = next_ekey.id
            # If we wrapped around hash ring circle - split route into two distinct ranges
            if (stop < start):
                log.debug("Splitting range: {0}:{1}".format(
                    format_id(start), format_id(stop)))
                ranges.append(RecoveryRange(IdRange(IdRange.ID_MIN, stop), prev_address))
                ranges.append(RecoveryRange(IdRange(start, IdRange.ID_MAX), prev_address))
                created = (1, 2)
            else:
                ranges.append(RecoveryRange(IdRange(start, stop), prev_address))
                created = (1,)
            for i in created:
                log.debug("Created range: {0}, {1}".format(*ranges[-i]))
    return ranges


def run_iterator(ctx, group=None, address=None, routes=None, ranges=None, stats=None):
    """
    Runs iterator for all ranges on node specified by address
    TODO: We can group iterators by address and run them in parallel
    """
    node = elliptics_create_node(address=address, elog=ctx.elog)
    try:
        timestamp_range = ctx.timestamp.to_etime(), Time.time_max().to_etime()
        eid = routes.filter_by_address(address)[0].key
        key_ranges = [r.id_range for r in ranges]
        log.debug("Running iterator on node: {0}".format(address))
        result, result_len = Iterator.iterate_with_stats(
            node=node,
            eid=eid,
            timestamp_range=timestamp_range,
            key_ranges=key_ranges,
            tmp_dir=ctx.tmp_dir,
            address=address,
            batch_size=ctx.batch_size,
            stats=stats,
            counters=['iterated_keys']
        )
        if result is None:
            raise RuntimeError("Iterator result is None")
        log.debug("Iterator {0} obtained: {1} record(s)".format(result.id_range, len(result)))
        stats.counter('iterations', 1)
        return result
    except Exception as e:
        log.error("Iteration failed for: {0}: {1}".format(address, repr(e)))
        stats.counter('iterations', -1)
        return None

def sort(ctx, result, stats):
    """
    Runs sort routine for all iterator results
    """
    if len(result) == 0:
        log.debug("Sort skipped iterator results are empty")
        return None
    try:
        log.info("Processing sorting range: {0}".format(result.id_range))
        result.container.sort()
        stats.counter('sort', 1)
        return result
    except Exception as e:
        log.error("Sort of {0} failed: {1}".format(result.id_range, e))
        stats.counter('sort', -1)
    return None


def diff(ctx, local, remote, stats):
    """
    Compute differences between local and remote results.
    TODO: We can compute up to CPU_NUM diffs at max in parallel
    """
    try:
        if remote is None or len(remote) == 0:
            log.info("Remote container is empty, skipping")
            return None
        elif (local is None or len(local) == 0) and len(remote) > 0:
            # If local container is empty and remote is not
            # then difference is whole remote container
            log.info("Local container is empty, recovering full range")
            result = remote
        else:
            log.info("Computing differences for: {0}".format(remote.address))
            result = local.diff(remote)
        if len(result) == 0:
            log.info("Resulting diff is empty, skipping: {0}".format(remote.address))
            return None
        stats.counter('diff', 1)
        return result
    except Exception as e:
        log.error("Diff for {0} failed: {1}".format(remote.address, e))
        stats.counter('diff', -1)
        return None

def recover(ctx, diff, group, stats):
    """
    Recovers difference between remote and local data.
    TODO: Group by diffs by address and process each group in parallel
    """
    result = True
    log.info("Recovering range: {0} for: {1}".format(diff.id_range, diff.address))

    log.debug("Creating remote node for: {0}".format(diff.address))
    remote_node = elliptics_create_node(address=diff.address, elog=g_ctx.elog)
    log.debug("Creating direct remote session: {0}".format(diff.address))
    remote_session = elliptics_create_session(node=remote_node,
                                              group=group,
                                             )
    remote_session.set_direct_id(*diff.address)

    log.debug("Creating local node for: {0}".format(g_ctx.address))
    local_node = elliptics_create_node(address=g_ctx.address, elog=g_ctx.elog)
    log.debug("Creating direct local session: {0}".format(g_ctx.address))
    local_session = elliptics_create_session(node=local_node,
                                             group=group,
                                            )
    local_session.set_direct_id(*g_ctx.address)

    # Here we cleverly splitting responses into ctx.batch_size batches
    total_size, total_records = (0, 0)
    for batch_id, batch in groupby(enumerate(diff),
                                    key=lambda x: x[0] / ctx.batch_size):
        keys = [elliptics.Id(r.key, group) for _, r in batch]
        results = recover_keys(ctx, diff.address, group, keys, local_session, remote_session, stats)
        if results is None:
            stats.counter('recovered_keys', -len(keys))
            continue

        successes, failures, successes_size, failures_size = (0, 0, 0, 0)
        for r, size in results:
            r.wait()
            if r.successful():
                successes_size += size
                successes += 1
            else:
                failures_size += size
                failures += 1
            total_records += 1
            total_size += size

        stats.counter('recovered_bytes', successes_size)
        stats.counter('recovered_bytes', -failures_size)
        stats.counter('recovered_keys', successes)
        stats.counter('recovered_keys', -failures)
        log.debug("Recovered batch: {0}/{1} of size: {2}/{3}".format(total_records, len(diff),
                                                                     failures_size + successes_size, total_size))
        result &= (failures == 0)
    return result

def recover_keys(ctx, address, group, keys, local_session, remote_session, stats):
    """
    Bulk recovery of keys.
    """
    keys_len = len(keys)
    async_write_results = []

    try:
        batch = remote_session.bulk_read_async(keys)
        for b in batch:
            async_write_results.append((local_session.write_data_async((b.id, b.timestamp, b.user_flags), b.data), len(b.data)))
        read_len = len(async_write_results)
        stats.counter('read_keys', read_len)
        stats.counter('skipped_keys', keys_len - read_len)
        return async_write_results
    except Exception as e:
        log.debug("Bulk read failed: {0} keys: {1}".format(keys_len, e))
        stats.counter('skipped_keys', keys_len)
        return None

def process_address(address, group, ranges):
    """
    Recover all ranges for an address.

    For each range we iterate, sort, diff with corresponding
    local iterator result, recover diff.
    """
    remote_stats_name = 'remote_{0}'.format(address)
    remote_stats = g_ctx.monitor.stats[remote_stats_name]
    result = False

    try:
        log.warning("Running remote iterators")
        remote_stats.timer('remote', 'iterator')
        # In merge mode we only using ranges that were stolen from `address`
        remote_ranges = [r for r in ranges if r.address == address]
        remote_result = run_iterator(
            g_ctx,
            group=group,
            address=address,
            routes=g_ctx.routes,
            ranges=remote_ranges,
            stats=remote_stats,
        )
        if remote_result is None or len(remote_result) == 0:
            log.warning("Remote iterator results are empty, skipping")
            return True

        log.warning("Sorting remote iterator results")
        remote_stats.timer('remote', 'sort')
        sorted_remote_result = sort(g_ctx, remote_result, remote_stats)
        assert len(remote_result) >= len(sorted_remote_result)
        log.warning("Sorted successfully: {0} remote result(s)".format(len(sorted_remote_result)))

        log.warning("Computing diff local vs remote")
        remote_stats.timer('remote', 'diff')
        diff_result = diff(g_ctx, g_sorted_local_results, sorted_remote_result, remote_stats)
        if diff_result is None or len(diff_result) == 0:
            log.warning("Diff results are empty, skipping")
            return True
        assert len(sorted_remote_result) >= len(diff_result)
        log.warning("Computed differences: {0} diff(s)".format(len(diff_result)))

        log.warning("Recovering diffs")
        remote_stats.timer('remote', 'recover')
        if not g_ctx.dry_run:
            result = recover(g_ctx, diff_result, group, remote_stats)
        else:
            result = True
            log.warning("Recovery skipped due to `dry-run`")
        log.warning("Recovery finished, setting result to: {0}".format(result))
        remote_stats.timer('remote', 'finished')
    except Exception as e:
        log.error("Recovery failed with exception: {0}".format(e))
    return result

def main(ctx):
    """
    Run local iterators, sort them. Then for each host in route
    table run recovery process.
    """
    global g_ctx
    global g_sorted_local_results
    result = True
    g_ctx = ctx
    g_ctx.monitor.stats.timer('main', 'started')

    for group in g_ctx.groups:
        log.warning("Processing group: {0}".format(group))
        group_stats = g_ctx.monitor.stats['group_{0}'.format(group)]
        group_stats.timer('group', 'started')
        local_stats = group_stats['local']
        local_stats.timer('local', 'started')

        routes = RouteList(g_ctx.routes.filter_by_group_id(group))
        ranges = get_ranges(g_ctx, routes, group)
        log.debug("Recovery ranges: {0}".format(len(ranges)))
        if not ranges:
            log.warning("No ranges to recover in group: {0}".format(group))
            group_stats.timer('group', 'finished')
            continue
        assert all(address != g_ctx.address for _, address in ranges)

        log.warning("Running local iterators against: {0} range(s)".format(len(ranges)))
        local_stats.timer('local', 'iterator')
        local_result = run_iterator(
            g_ctx,
            group=group,
            address=g_ctx.address,
            routes=g_ctx.routes,
            ranges=ranges,
            stats=local_stats,
        )
        log.warning("Finished local iteration of: {0} range(s)".format(len(ranges)))

        log.warning("Sorting local iterator results")
        local_stats.timer('local', 'sort')
        g_sorted_local_results = sort(g_ctx, local_result, local_stats)
        if g_sorted_local_results is not None:
            assert len(local_result) == len(g_sorted_local_results)
            log.warning("Sorted successfully: {0} local record(s)".format(len(g_sorted_local_results)))
        else:
            log.warning("Local results are empty")
        local_stats.timer('local', 'finished')

        # For each address in computed recovery ranges run iterator in subprocess
        group_stats.timer('group', 'remote')
        async_results = []
        addresses = set([r.address for r in ranges])
        processes = min(g_ctx.nprocess, len(addresses))
        log.info("Creating pool of processes: {0}".format(processes))
        pool = Pool(processes=processes, initializer=worker_init)
        for address in addresses:
            async_results.append(pool.apply_async(process_address, (address, group, ranges)))

        results = []
        try:
            log.info("Fetching results")
            # Use INT_MAX as timeout, so we can catch Ctrl+C
            timeout = 2147483647
            for result in (r.get(timeout) for r in async_results):
                results.append(result)
        except KeyboardInterrupt:
            log.error("Caught Ctrl+C. Terminating.")
            pool.terminate()
            pool.join()
        else:
            log.info("Closing pool, joining threads.")
            pool.close()
            pool.join()

        result = all(results)
        group_stats.timer('group', 'finished')
    g_ctx.monitor.stats.timer('main', 'finished')
    return result
