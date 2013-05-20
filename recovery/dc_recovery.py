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
import os
import logging as log

from itertools import groupby

from recover.range import IdRange, RecoveryRange
from recover.iterator import Iterator
from recover.time import Time
from recover.utils.misc import format_id, mk_container_name, elliptics_create_node, elliptics_create_session

# XXX: change me before BETA
sys.path.insert(0, "bindings/python/")
import elliptics

log.getLogger()

def log_ranges(ranges):
    for range in ranges:
        log.debug("Range: %s" % (str(range.id_range) + " " + str(range.address)))

def run_iterators(ctx, ranges=None, stats=None):
    """
    Runs local and remote iterators for each range.
    TODO: We can group iterators by host and run them in parallel
    TODO: We can run only one iterator per host if we'll teach iterators to "batch" all key ranges in one request
    """
    log_ranges(ranges)
    results = []
    local_group_id = ctx.routes.filter_by_address(ctx.address)[0].key.group_id

    for iteration_range in ranges:
        try:
            timestamp_range = ctx.timestamp.to_etime(), Time.time_max().to_etime()
            local_eid = iteration_range.address[local_group_id][0]

            log.debug("Running local iterator on: {0} address: {1}".format(mk_container_name(
                iteration_range.id_range, local_eid), iteration_range.address[local_group_id][1]))
            local_result = Iterator(ctx.node, local_group_id).start(
                eid=local_eid,
                timestamp_range=timestamp_range,
                key_range=iteration_range.id_range,
                tmp_dir=ctx.tmp_dir,
            )
            log.debug("Local obtained: {0} record(s)".format(len(local_result)))
            stats.counter.local_records += len(local_result)
            stats.counter.local_iterations += 1
            stats.counter.iterations += 1
            remote_result = []

            for i in iteration_range.address:
                if i == local_group_id:
                    continue
                remote_eid = iteration_range.address[i][0]
                log.debug("Running remote iterator on: {0} host: {1}".format(mk_container_name(
                    iteration_range.id_range, remote_eid), iteration_range.address[i][1]))

                remote_result.append(Iterator(ctx.node, i).start(
                    eid=remote_eid,
                    timestamp_range=timestamp_range,
                    key_range=iteration_range.id_range,
                    tmp_dir=ctx.tmp_dir,
                ))
                remote_result[-1].address = iteration_range.address[i][1]
                remote_result[-1].group_id = i
                log.debug("Remote obtained: {0} record(s)".format(len(remote_result[-1])))
                stats.counter.remote_records += len(remote_result[-1])
                stats.counter.remote_iterations += 1

            results.append((local_result, remote_result))
            stats.counter.iterations += 2
        except Exception as e:
            log.error("Iteration failed for: {0}@{1}: {2}".format(
                iteration_range.id_range, iteration_range.address, repr(e)))
            stats.counter.iterations -= 1
    return results

def sort(ctx, results, stats):
    """
    Runs sort routine for all iterator result
    """
    sorted_results = []
    for local, remote in results:
        if not (local.status and all(r.status for r in remote)):
            log.debug("Sort skipped because local or remote iterator failed")
            stats.counter.sort_skipped += 1
            continue
        if len(remote) == 0:
            log.debug("Sort skipped remote iterator results are empty")
            continue
        try:
            assert all(local.id_range == r.id_range for r in remote), \
                "Local range must equal remote range"

            log.info("Processing sorting local range: {0}".format(local.id_range))
            local.container.sort()
            stats.counter.sort_local += 1

            for r in remote:
                log.info("Processing sorting remote range: {0}".format(r.id_range))
                r.container.sort()
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
        for r in remote:
            try:
                if len(local) >= 0 and len(r) == 0:
                    log.info("Remote container is empty, skipping range: {0}".format(local.id_range))
                    continue
                elif len(local) == 0 and len(r) > 0:
                    # If local container is empty and remote is not
                    # then difference is whole remote container
                    log.info("Local container is empty, recovering full range: {0}".format(local.id_range))
                    result = r;
                else:
                    log.info("Computing differences for: {0}".format(local.id_range))
                    result = local.diff(r)
                    result.address = r.address
                    result.group_id = r.group_id
                if len(result) > 0:
                    diff_results.append(result)
                else:
                    log.info("Resulting diff is empty, skipping range: {0}".format(local.id_range))
                stats.counter.diff += 1
            except Exception as e:
                log.error("Diff of {0} failed: {1}".format(local.id_range, e))
                stats.counter.diff -= 1
    return diff_results

def recover(ctx, diffs, stats):
    """
    Recovers difference between remote and local data.
    TODO: Group by diffs by host and process each group in parallel
    """
    result = True
    for diff in diffs:
        log.info("Recovering range: {0} for: {1}".format(diff.id_range, diff.address))

        # Here we cleverly splitting responses into ctx.batch_size batches
        for batch_id, batch in groupby(enumerate(diff),
                                        key=lambda x: x[0] / ctx.batch_size):
            keys = [elliptics.Id(r.key, diff.group_id, 0) for _, r in batch]
            successes, failures = recover_keys(ctx, diff.address, diff.group_id, keys)
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

def main(ctx):
    result = True
    ctx.stats.timer.main('started')
    if len(ctx.groups) == 0:
        ctx.groups = ctx.routes.groups()
    log.debug("Groups: %s" % ctx.groups)

    ctx.group_id = ctx.routes.filter_by_address(ctx.address)[0].key.group_id

    group_stats = ctx.stats["recovery"]
    group_stats.timer.group('started')

    log.warning("Searching for ranges that %s store" % ctx.address)
    ranges = ctx.routes.get_ranges_by_address(ctx.address)
    log.debug("Recovery ranges: %d" % len(ranges))
    if not ranges:
        log.warning("No ranges to recover for address %s" % ctx.address)
        group_stats.timer.group('finished')
        return result

    log.warning("Running iterators against: %d range(s)" % len(ranges))
    group_stats.timer.group('iterators')
    iterator_results = run_iterators(
        ctx,
        ranges=ranges,
        stats=group_stats
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
    result &= recover(ctx, diff_results, group_stats)
    log.warning("Recovery finished, setting result to: {0}".format(result))
    group_stats.timer.group('finished')

    ctx.stats.timer.main('finished')
    return result
