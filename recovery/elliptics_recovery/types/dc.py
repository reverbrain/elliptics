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

"""
Data Center recovery type - recovers keys at the expense of keys from other group.

 * Find ranges that host is responsible for now.
 * Start metadata-only iterator for the found ranges on local and remote hosts (from non-local groups).
 * Sort iterators' outputs.
 * Computes diff between local and remote iterator.
 * Recover keys provided by diff using bulk APIs.
"""

import sys
import os
import logging

from itertools import groupby
from multiprocessing import Pool

from ..iterator import Iterator, IteratorResult
from ..etime import Time
from ..utils.misc import elliptics_create_node, elliptics_create_session, worker_init, mk_container_name

# XXX: change me before BETA
sys.path.insert(0, "bindings/python/")
import elliptics

log = logging.getLogger(__name__)


def run_iterator(ctx, address, eid, ranges, stats):
    """
    Runs iterator for all ranges on node specified by address
    """
    node = elliptics_create_node(address=address, elog=ctx.elog, wait_timeout=ctx.wait_timeout)

    try:
        timestamp_range = ctx.timestamp.to_etime(), Time.time_max().to_etime()

        log.debug("Running iterator on node: {0}".format(address))
        result, result_len = Iterator.iterate_with_stats(node=node,
                                                         eid=eid,
                                                         timestamp_range=timestamp_range,
                                                         key_ranges=ranges,
                                                         tmp_dir=ctx.tmp_dir,
                                                         address=address,
                                                         batch_size=ctx.batch_size,
                                                         stats=stats,
                                                         leave_file=True
                                                         )

        if result is None:
            raise RuntimeError("Iterator result is None")
        log.debug("Iterator {0} obtained: {1} record(s)".format(result.address, result_len))
        stats.counter('iterations', 1)
        return result

    except Exception as e:
        log.error("Iteration failed for: {0}: {1}".format(address, repr(e)))
        stats.counter('iterations', -1)
        return None


def sort(ctx, result, stats):
    """
    Runs sort routine for all iterator result
    """
    if len(result) == 0:
        log.debug("Sort skipped iterator results are empty")
        return None
    try:
        log.info("Processing sorting ranges for: {0}".format(result.address))
        result.container.sort()
        stats.counter('sort', 1)
        return result
    except Exception as e:
        log.error("Sort of {0} failed: {1}".format(result.address, e))
        stats.counter('sort', -1)
    return None


def diff(ctx, local, remote, stats):
    """
    Compute differences between local and remote results.
    """
    try:
        if remote is None or len(remote) == 0:
            log.info("Remote container is empty, skipping")
            return None
        elif local is None or len(local) == 0:
            log.info("Local container is empty, recovering full range")
            result = remote
        else:
            log.info("Computing differences for: {0}".format(remote.address))
            result = local.diff(remote)
        result.leave_file = True
        diff_len = len(result)
        stats.counter('diff', diff_len)
        log.info("Found {0} differences".format(diff_len))
        return result
    except Exception as e:
        log.error("Diff for {0} failed: {1}".format(remote.address, e))
        stats.counter('diff', -1)
        return None


def recover((address, )):
    """
    Recovers difference between remote and local data.
    """

    ctx = g_ctx

    result = True
    stats_name = 'recover_{0}'.format(address)
    stats = ctx.monitor.stats[stats_name]
    log.info("Recovering ranges for: {0}".format(address))
    stats.timer('recover', 'started')

    filename = os.path.join(ctx.tmp_dir, mk_container_name(address, "merge_"))
    diff = IteratorResult.load_filename(filename,
                                        address=address,
                                        is_sorted=True,
                                        tmp_dir=ctx.tmp_dir,
                                        leave_file=False
                                        )
    ctx.elog = elliptics.Logger(ctx.log_file, int(ctx.log_level))

    local_node = elliptics_create_node(address=ctx.address,
                                       elog=ctx.elog,
                                       io_thread_num=10,
                                       net_thread_num=10,
                                       nonblocking_io_thread_num=10,
                                       wait_timeout=ctx.wait_timeout
                                       )
    log.debug("Creating direct session: {0}".format(ctx.address))
    local_session = elliptics_create_session(node=local_node,
                                             group=ctx.group_id,
                                             )
    local_session.set_direct_id(*ctx.address)

    remote_node = elliptics_create_node(address=diff.address,
                                        elog=ctx.elog,
                                        io_thread_num=10,
                                        net_thread_num=10,
                                        nonblocking_io_thread_num=10,
                                        wait_timeout=ctx.wait_timeout
                                        )
    log.debug("Creating direct session: {0}".format(diff.address))
    remote_session = elliptics_create_session(node=remote_node,
                                              group=diff.address.group_id,
                                              )
    remote_session.set_direct_id(*diff.address)

    for batch_id, batch in groupby(enumerate(diff), key=lambda x: x[0] / ctx.batch_size):
        result &= recover_keys(ctx=ctx,
                               address=diff.address,
                               group_id=diff.address.group_id,
                               keys=[r.key for _, r in batch],
                               local_session=local_session,
                               remote_session=remote_session,
                               stats=stats)

    stats.timer('recover', 'finished')
    return result


def recover_keys(ctx, address, group_id, keys, local_session, remote_session, stats):
    """
    Bulk recovery of keys.
    """
    keys_len = len(keys)

    log.debug("Copying {0} keys".format(keys_len))

    async_write_results = []
    batch = None

    try:
        batch = remote_session.bulk_read(keys)
        it = iter(batch)
    except Exception as e:
        log.error("Bulk read failed: {0} keys: {1}".format(keys_len, e))
        stats.counter('read_keys', -keys_len)
        stats.counter('recovered_keys', -keys_len)
        return False

    failed = 0

    while True:
        try:
            b = next(it)
            io = elliptics.IoAttr()
            io.id = b.id
            io.timestamp = b.timestamp
            io.user_flags = b.user_flags
            async_write_results.append((local_session.write_data(io, b.data),
                                        len(b.data)))
        except StopIteration:
            break
        except Exception as e:
            failed += 1
            log.error("Write failed: {0}".format(e))

    read_len = len(async_write_results)
    stats.counter('read_keys', read_len)
    stats.counter('read_keys', -failed)
    stats.counter('skipped_keys', keys_len - read_len - failed)

    successes, successes_size, failures_size = (0, 0, 0)
    for r, bsize in async_write_results:
        try:
            r.wait()
            if r.successful():
                successes_size += bsize
                successes += 1
            else:
                failures_size += bsize
                failed += 1
        except Exception as e:
            log.error("Write failed: {0}".format(e))
            failures_size += bsize
            failed += 1

    log.debug("Recovered batch: {0}/{1} of size: {2}/{3}".format(successes + failed, keys_len, successes_size, failures_size))

    stats.counter('recovered_keys', successes)
    stats.counter('recovered_keys', -failed)
    stats.counter('recovered_bytes', successes_size)
    stats.counter('recovered_bytes', -failures_size)

    return failed == 0


def iterate_node(address_ranges):
    """Iterates node range, sorts it and returns"""
    ctx = g_ctx
    ctx.elog = elliptics.Logger(ctx.log_file, int(ctx.log_level))

    stats_name = 'iterate_{0}'.format(address_ranges.address)
    if address_ranges.address == ctx.address:
        stats_name = 'iterate_local'
    stats = ctx.monitor.stats[stats_name]
    stats.timer('process', 'started')

    log.info("Running iterator")
    stats.timer('process', 'iterate')
    result = run_iterator(ctx=ctx,
                          address=address_ranges.address,
                          eid=address_ranges.eid,
                          ranges=address_ranges.id_ranges,
                          stats=stats
                          )
    if result is None or len(result) == 0:
        log.warning("Iterator result is empty, skipping")
        stats.timer('process', 'finished')
        return None

    stats.timer('process', 'sort')
    sorted_result = sort(ctx=ctx,
                         result=result,
                         stats=stats)
    assert len(result) >= len(sorted_result)

    log.info("Sorted successfully: {0} result(s)".format(len(sorted_result)))

    if sorted_result is None or len(sorted_result) == 0:
        log.warning("Sorted results are empty, skipping")
        stats.timer('process', 'finished')
        return None

    stats.timer('process', 'finished')
    return (sorted_result.address, sorted_result.filename)


def process_diff((local, remote)):
    log.debug('Looking for differences between local and remote nodes')
    if remote is None:
        log.debug('Remote container is empty, skipping')
        return None

    ctx = g_ctx
    remote_address, remote_filename = remote

    stats_name = 'diff_remote_{0}'.format(remote_address)
    stats = ctx.monitor.stats[stats_name]
    stats.timer('process', 'start')

    if local is None:
        log.info("Local container is empty, recovering full range")
        stats.timer('process', 'finished')
        return remote

    local_address, local_filename = local

    log.debug("Loading local result")
    local_result = None
    if local:
        local_result = IteratorResult.load_filename(local_filename,
                                                    address=ctx.address,
                                                    is_sorted=True,
                                                    tmp_dir=ctx.tmp_dir,
                                                    leave_file=True
                                                    )

    log.debug("Loading remote result")
    remote_result = None
    if remote:
        remote_result = IteratorResult.load_filename(remote_filename,
                                                     address=remote_address,
                                                     is_sorted=True,
                                                     tmp_dir=ctx.tmp_dir
                                                     )

    stats.timer('process', 'diff')
    diff_result = diff(ctx, local_result, remote_result, stats)

    if diff_result is None or len(diff_result) == 0:
        log.warning("Diff result is empty, skipping")
        stats.timer('process', 'finished')
        return None
    assert len(remote_result) >= len(diff_result)
    log.info("Computed differences: {0} diff(s)".format(len(diff_result)))

    stats.timer('process', 'finished')
    return (diff_result.address, diff_result.filename)


def main(ctx):
    global g_ctx
    g_ctx = ctx
    g_ctx.monitor.stats.timer('main', 'started')
    g_ctx.group_id = g_ctx.address.group_id
    result = True

    log.warning("Searching for ranges that %s store" % g_ctx.address)
    all_ranges = g_ctx.routes.get_local_ranges_by_address(g_ctx.address)
    log.debug("Recovery nodes: {0}".format(len(all_ranges)))
    if len(all_ranges) <= 1:
        log.warning("No ranges to recover for address %s" % g_ctx.address)
        g_ctx.monitor.stats.timer('main', 'finished')
        return result

    log.debug("Processing nodes: {0}".format([str(r.address) for r in all_ranges]))

    processes = min(g_ctx.nprocess, len(all_ranges))
    log.info("Creating pool of processes: {0}".format(processes))
    pool = Pool(processes=processes, initializer=worker_init)

    local_ranges = next((r for r in all_ranges if r.address == g_ctx.address), None)
    assert local_ranges, 'Local ranges is absent in route table'
    ctx.monitor.stats.counter('iterations', len(all_ranges))

    local_iter_result = pool.apply_async(iterate_node, (local_ranges, ))
    remote_ranges = (range for range in all_ranges
                     if range.address != g_ctx.address and
                        range.address.group_id in g_ctx.groups)
    iter_result = pool.imap_unordered(iterate_node, remote_ranges)

    try:
        timeout = 2147483647
        local_it_result = local_iter_result.get(timeout)
        diff_async_results = pool.imap_unordered(process_diff, ((local_it_result, result) for result in iter_result if result))

    except KeyboardInterrupt:
        log.error("Caught Ctrl+C. Terminating")
        pool.terminate()
        pool.join()
        g_ctx.monitor.stats.timer('main', 'finished')
        return False

    def unpack_diff_result(result):
        address, filename = result
        dres = IteratorResult.load_filename(filename,
                                            address=address,
                                            is_sorted=True,
                                            tmp_dir=g_ctx.tmp_dir
                                            )
        return dres

    try:
        diff_results = [unpack_diff_result(diff_r) for diff_r in diff_async_results if diff_r]
        diff_results = [diff_r for diff_r in diff_results if diff_r]
    except KeyboardInterrupt:
        log.error("Caught Ctrl+C. Terminating")
        pool.terminate()
        pool.join()
        g_ctx.monitor.stats.timer('main', 'finished')
        return False

    if len(diff_results) == 0:
        log.warning("Local node has up-to-date data")
        pool.terminate()
        pool.join()
        g_ctx.monitor.stats.timer('main', 'finished')
        return True

    diff_length = sum([len(diff) for diff in diff_results])

    log.warning('Computing merge and splitting by node all remote results')
    g_ctx.monitor.stats.timer('main', 'merge_and_split')
    splitted_results = IteratorResult.merge(diff_results, g_ctx.tmp_dir)
    g_ctx.monitor.stats.timer('main', 'finished')

    merged_diff_length = 0
    for spl in splitted_results:
        spl_len = len(spl)
        merged_diff_length += spl_len
        g_ctx.monitor.stats.counter('merged_diffs_{0}'.format(spl.address), spl_len)

    assert diff_length >= merged_diff_length
    g_ctx.monitor.stats.counter('merged_diffs', merged_diff_length)

    if not g_ctx.dry_run:
        try:
            results = pool.map(recover, ((r.address, ) for r in splitted_results if r))
        except KeyboardInterrupt:
            log.error("Caught Ctrl+C. Terminating.")
            pool.terminate()
            pool.join()
            g_ctx.monitor.stats.timer('main', 'merge_and_split')
            return False
        else:
            log.info("Closing pool, joining threads")
            pool.close()
            pool.join()
        result &= all(results)

    g_ctx.monitor.stats.timer('main', 'finished')
    log.debug("Result: %s" % result)

    return result
