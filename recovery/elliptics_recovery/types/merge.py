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

from itertools import groupby

from ..range import IdRange, RecoveryRange
from ..iterator import Iterator
from ..time import Time
from ..utils.misc import format_id, mk_container_name, elliptics_create_node, elliptics_create_session

# XXX: change me before BETA
sys.path.insert(0, "bindings/python/")
import elliptics

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
        if address == ctx.address:
            log.debug("Processing route: {0}, {1}".format(format_id(ekey.id), address))
            if ekey.group_id != group_id:
                log.debug("Skipped route: {0}, it belongs to group_id: {1}".format(
                    route, ekey.group_id))
                continue
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

def run_iterators(ctx, group=None, routes=None, ranges=None, stats=None):
    """
    Runs local and remote iterators for each range.
    TODO: We can group iterators by address and run them in parallel
    TODO: We can run only one iterator per address if we'll teach iterators to "batch" all key ranges in one request
    """
    results = []
    local_eid = routes.filter_by_address(ctx.address)[0].key
    local_node = elliptics_create_node(address=ctx.address, elog=ctx.elog)
    for iteration_range in ranges:
        try:
            timestamp_range = ctx.timestamp.to_etime(), Time.time_max().to_etime()

            log.debug("Running local iterator on: {0}".format(mk_container_name(
                iteration_range.id_range, local_eid)))
            local_result = Iterator(local_node, group).start(
                eid=local_eid,
                timestamp_range=timestamp_range,
                key_range=[iteration_range.id_range],
                tmp_dir=ctx.tmp_dir,
                address=ctx.address,
            )
            log.debug("Local obtained: {0} record(s)".format(len(local_result)))
            stats.counter.local_records += len(local_result)
            stats.counter.local_iterations += 1
            stats.counter.iterations += 1

            remote_eid = routes.filter_by_address(iteration_range.address)[0].key
            log.debug("Running remote iterator on: {0}".format(mk_container_name(
                iteration_range.id_range, remote_eid)))
            remote_result = Iterator(local_node, group).start(
                eid=remote_eid,
                timestamp_range=timestamp_range,
                key_range=[iteration_range.id_range],
                tmp_dir=ctx.tmp_dir,
                address=iteration_range.address,
            )
            log.debug("Remote obtained: {0} record(s)".format(len(remote_result)))
            stats.counter.remote_records += len(remote_result)
            stats.counter.remote_iterations += 1
            stats.counter.iterations += 2
            results.append((local_result, remote_result))
        except Exception as e:
            log.error("Iteration failed for: {0}: {1}".format(
                iteration_range.id_range, repr(e)))
            stats.counter.iterations -= 1
    return results

def sort(ctx, results, stats):
    """
    Runs sort routine for all iterator result
    """
    sorted_results = []
    for local, remote in results:
        if not (local.status and remote.status):
            log.debug("Sort skipped because local or remote iterator failed")
            stats.counter.sort_skipped += 1
            continue
        if len(remote) == 0:
            log.debug("Sort skipped remote iterator results are empty")
            continue
        try:
            assert local.id_range == remote.id_range, \
                "Local range must equal remote range"

            log.info("Processing sorting local range: {0}".format(local.id_range))
            local.container.sort()
            stats.counter.sort_local += 1

            log.info("Processing sorting remote range: {0}".format(local.id_range))
            remote.container.sort()
            stats.counter.sort_remote += 1

            sorted_results.append((local, remote))
        except Exception as e:
            log.error("Sort of {0} failed: {1}".format(local.id_range, e))
            stats.counter.sort -= 1
    return sorted_results

def diff(ctx, results, stats):
    """
    Compute differences between local and remote results.
    TODO: We can compute up to CPU_NUM diffs at max in parallel
    """
    diff_results = []
    for local, remote in results:
        try:
            if len(local) >= 0 and len(remote) == 0:
                log.info("Remote container is empty, skipping range: {0}".format(local.id_range))
                continue
            elif len(local) == 0 and len(remote) > 0:
                # If local container is empty and remote is not
                # then difference is whole remote container
                log.info("Local container is empty, recovering full range: {0}".format(local.id_range))
                result = remote
            else:
                log.info("Computing differences for: {0}".format(local.id_range))
                result = local.diff(remote)
            if (len(result)):
                diff_results.append(result)
            else:
                log.info("Resulting diff is empty, skipping range: {0}".format(local.id_range))
            stats.counter.diff += 1
        except Exception as e:
            log.error("Diff of {0} failed: {1}".format(local.id_range, e))
            stats.counter.diff -= 1
    return diff_results

def recover(ctx, diffs, group, stats):
    """
    Recovers difference between remote and local data.
    TODO: Group by diffs by address and process each group in parallel
    """
    result = True
    for diff in diffs:
        log.info("Recovering range: {0} for: {1}".format(diff.id_range, diff.address))

        # Here we cleverly splitting responses into ctx.batch_size batches
        for batch_id, batch in groupby(enumerate(diff),
                                        key=lambda x: x[0] / ctx.batch_size):
            keys = [elliptics.Id(r.key, group, 0) for _, r in batch]
            successes, failures = recover_keys(ctx, diff.address, group, keys)
            stats.counter.recover_key += successes
            stats.counter.recover_key -= failures
            result &= (failures == 0)
            log.debug("Recovered batch: {0}/{1} of size: {2}/{3}".format(
                batch_id * ctx.batch_size, len(diff), successes, failures))
    return result

def recover_keys(ctx, address, group, keys):
    """
    Bulk recovery of keys.
    """
    key_num = len(keys)

    log.debug("Reading {0} keys".format(key_num))
    try:
        log.debug("Creating node for: {0}".format(address))
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
        log.debug("Creating node for: {0}".format(ctx.address))
        node = elliptics_create_node(address=ctx.address, elog=ctx.elog, flags=2)
        log.debug("Creating direct session: {0}".format(ctx.address))
        direct_session = elliptics_create_session(node=node,
                                                  group=group,
                                                  cflags=elliptics.command_flags.direct,
        )
        direct_session.bulk_write(batch)
    except Exception as e:
        log.debug("Bulk write failed: {0} keys: {1}".format(key_num, e))
        return 0, key_num
    return key_num, 0

def main(ctx):
    result = True
    ctx.stats.timer.main('started')

    for group in ctx.groups:
        log.warning("Processing group: {0}".format(group))
        group_stats = ctx.stats[group]
        group_stats.timer.group('started')

        ranges = get_ranges(ctx, ctx.routes, group)
        log.debug("Recovery ranges: {0}".format(len(ranges)))
        if not ranges:
            log.warning("No ranges to recover in group: {0}".format(group))
            group_stats.timer.group('finished')
            continue
        # We should not run iterators on ourselves
        assert all(address != ctx.address for _, address in ranges)

        log.warning("Running iterators against: {0} range(s)".format(len(ranges)))
        group_stats.timer.group('iterators')
        iterator_results = run_iterators(
            ctx,
            group=group,
            routes=ctx.routes,
            ranges=ranges,
            stats=group_stats,
        )
        assert len(ranges) >= len(iterator_results)
        log.warning("Finished iteration of: {0} range(s)".format(len(iterator_results)))

        log.warning("Sorting iterators' data")
        group_stats.timer.group('sort')
        sorted_results = sort(ctx, iterator_results, group_stats)
        assert len(iterator_results) >= len(sorted_results)
        log.warning("Sorted successfully: {0} result(s)".format(len(sorted_results)))

        log.warning("Computing diff local vs remote")
        group_stats.timer.group('diff')
        diff_results = diff(ctx, sorted_results, group_stats)
        assert len(sorted_results) >= len(diff_results)
        log.warning("Computed differences: {0} diff(s)".format(len(diff_results)))

        log.warning("Recovering diffs")
        group_stats.timer.group('recover')
        result &= recover(ctx, diff_results, group, group_stats)
        log.warning("Recovery finished, setting result to: {0}".format(result))
        group_stats.timer.group('finished')
    ctx.stats.timer.main('finished')
    return result
