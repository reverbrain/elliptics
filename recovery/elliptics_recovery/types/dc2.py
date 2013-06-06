"""
XXX:
"""

import sys
import os
import logging as log

from itertools import groupby
from multiprocessing import Pool

from ..iterator import Iterator, IteratorResult
from ..time import Time
from ..stat import Stats
from ..utils.misc import mk_container_name, elliptics_create_node, elliptics_create_session, worker_init

# XXX: change me before BETA
sys.path.insert(0, "bindings/python/")
import elliptics

log.getLogger()


def run_iterator(ctx, address, eid, ranges, stats):
    """
    Runs iterator for all ranges on node specified by address
    """
    node = elliptics_create_node(address=address, elog=ctx.elog)

    try:
        timestamp_range = ctx.timestamp.to_etime(), Time.time_max().to_etime()

        log.debug("Running iterator on node: {0}".format(address))
        result = Iterator(node, eid.group_id).start(eid=eid,
                                                    timestamp_range=timestamp_range,
                                                    key_ranges=ranges,
                                                    tmp_dir=ctx.tmp_dir,
                                                    address=address
                                                    )

        if result is None:
            raise RuntimeError("Iterator result is None")
        log.debug("Iterator {0} obtained: {1} record(s)".format(result.id_range, len(result)))
        stats.counter.iterated_keys += len(result)
        stats.counter.iterations += 1
        return result

    except Exception as e:
        log.error("Iteration failed for: {0}: {1}".format(address, repr(e)))
        stats.counter.iterations -= 1
        return None


def sort(ctx, result, stats):
    """
    Runs sort routine for all iterator result
    """
    if len(result) == 0:
        log.debug("Sort skipped iterator results are empty")
        return None
    try:
        log.info("Processing sorting range: {0}".format(result.id_range))
        result.container.sort()
        stats.counter.sort += 1
        return result
    except Exception as e:
        log.error("Sort of {0} failed: {1}".format(result.id_range, e))
        stats.counter.sort -= 1
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
        diff_len = len(result)
        stats.counter.diff += diff_len
        log.info("Found {0} differences".format(diff_len))
        return result
    except Exception as e:
        log.error("Diff for {0} failed: {1}".format(remote.address, e))
        stats.counter.diff -= 1
        return None


def recover(id_range, eid, address):
    """
    Recovers difference between remote and local data.
    """

    ctx = g_ctx

    result = True
    stats = Stats('recover_{0}'.format(address))
    log.info("Recovering range: {0} for: {1}".format(id_range, address))
    stats.timer.recover('started')

    filename = os.path.join(ctx.tmp_dir, "merge_" + mk_container_name(id_range, eid))
    diff = IteratorResult.load_filename(filename,
                                        address=address,
                                        id_range=id_range,
                                        eid=eid,
                                        is_sorted=True,
                                        tmp_dir=ctx.tmp_dir,
                                        leave_file=False
                                        )
    ctx.elog = elliptics.Logger(ctx.log_file, int(ctx.log_level))

    local_node = elliptics_create_node(address=ctx.address, elog=ctx.elog, flags=2)
    log.debug("Creating direct session: {0}".format(ctx.address))
    local_session = elliptics_create_session(node=local_node,
                                             group=ctx.group_id,
                                             cflags=elliptics.command_flags.direct,
                                             )

    remote_node = elliptics_create_node(address=diff.address, elog=ctx.elog, flags=2)
    log.debug("Creating direct session: {0}".format(diff.address))
    remote_session = elliptics_create_session(node=remote_node,
                                              group=diff.eid.group_id,
                                              cflags=elliptics.command_flags.direct,
                                              )

    for batch_id, batch in groupby(enumerate(diff), key=lambda x: x[0] / ctx.batch_size):
        keys = [elliptics.Id(r.key, diff.eid.group_id, 0) for _, r in batch]
        successes, failures = recover_keys(ctx, diff.address, diff.eid.group_id, keys, local_session, remote_session, stats)
        stats.counter.recovered_keys += successes
        stats.counter.recovered_keys -= failures
        result &= (failures == 0)
        log.debug("Recovered batch: {0}/{1} of size: {2}/{3}".format(
            batch_id * ctx.batch_size + len(keys), len(diff), successes, failures))

    stats.timer.recover('finished')

    return result, stats


def recover_keys(ctx, address, group_id, keys, local_session, remote_session, stats):
    """
    Bulk recovery of keys.
    """
    key_num = len(keys)

    log.debug("Reading {0} keys".format(key_num))
    try:
        batch = remote_session.bulk_read(keys)
    except Exception as e:
        log.debug("Bulk read failed: {0} keys: {1}".format(key_num, e))
        return 0, key_num

    size = sum(len(v[1]) for v in batch)
    log.debug("Writing {0} keys: {1} bytes".format(key_num, size))

    try:
        local_session.bulk_write(batch)
        stats.counter.recovered_bytes += size
        return key_num, 0
    except Exception as e:
        log.debug("Bulk write failed: {0} keys: {1}".format(key_num, e))
        stats.counter.recovered_bytes -= size
        return 0, key_num


def process_address_ranges(address_ranges, local=False):
    """XXX:"""
    stats_name = 'local'
    if not local:
        stats_name = 'remote_{0}'.format(address_ranges.address)
    stats = Stats(stats_name)
    stats.timer.process('started')

    ctx = g_ctx

    ctx.elog = elliptics.Logger(ctx.log_file, int(ctx.log_level))

    log.warning("Running remote iterator")
    stats.timer.process('iterator')
    result = run_iterator(ctx=ctx,
                          address=address_ranges.address,
                          eid=address_ranges.eid,
                          ranges=address_ranges.id_ranges,
                          stats=stats
                          )
    stats.timer.process('finished')
    if result is None or len(result) == 0:
        log.warning("Iterator results are empty, skipping")
        return True, stats, None

    stats.timer.process('sort')
    sorted_result = sort(ctx, result, stats)
    stats.timer.process('finished')
    assert len(result) >= len(sorted_result)
    log.warning("Sorted successfully: {0} result(s)".format(len(sorted_result)))

    if local:
        result.leave_file = True
        return True, stats, (result.id_range, result.eid, result.address)

    sorted_result.address = address_ranges.address
    sorted_result.eid = address_ranges.eid

    log.warning("Computing diff local vs remote")
    stats.timer.process('diff')

    if ctx.id_range is None or ctx.eid is None or ctx.id_range is None:
        local_result = None
    else:
        local_result = IteratorResult.load_filename(mk_container_name(ctx.id_range, ctx.eid),
                                                    address=ctx.address,
                                                    id_range=ctx.id_range,
                                                    eid=ctx.eid,
                                                    is_sorted=True,
                                                    tmp_dir=ctx.tmp_dir,
                                                    leave_file=True
                                                    )

    diff_result = diff(ctx, local_result, sorted_result, stats)
    stats.timer.process('finished')
    if diff_result is None or len(diff_result) == 0:
        log.warning("Diff results are empty, skipping")
        return True, stats, None
    assert len(sorted_result) >= len(diff_result)
    log.warning("Computed differences: {0} diff(s)".format(len(diff_result)))

    diff_result.leave_file = True

    return True, stats, (diff_result.id_range, diff_result.eid, diff_result.address, diff_result.filename)


def main(ctx):
    global g_ctx
    g_ctx = ctx
    result = True
    g_ctx.stats.timer.main('started')
    log.debug("Groups: %s" % g_ctx.groups)

    g_ctx.group_id = g_ctx.routes.get_address_group_id(g_ctx.address)

    log.warning("Searching for ranges that %s store" % g_ctx.address)
    all_ranges = g_ctx.routes.get_local_ranges_by_address(g_ctx.address)
    log.debug("Recovery nodes: {0}".format(len(all_ranges)))
    if len(all_ranges) <= 1:
        log.warning("No ranges to recover for address %s" % g_ctx.address)
        g_ctx.stats.timer.main('finished')
        return result

    log.debug("Processing nodes: {0}".format([str(r.address) for r in all_ranges]))

    local_ranges = [r for r in all_ranges if r.address == g_ctx.address][0]

    results = []

    try:
        local_result, local_stats, local_iter_result = process_address_ranges(local_ranges, True)
        g_ctx.stats[local_stats.name] = local_stats
    except KeyboardInterrupt:
        log.error("Caught Ctrl+C. Terminating")
        g_ctx.stats.timer.main('finished')
        return False

    results.append(local_result)

    if local_iter_result is None:
        g_ctx.id_range = None
        g_ctx.eid = None
    else:
        g_ctx.id_range = local_iter_result[0]
        g_ctx.eid = local_iter_result[1]

    result &= local_result

    processes = min(g_ctx.nprocess, len(all_ranges) - 1)
    log.info("Creating pool of processes: {0}".format(processes))
    pool = Pool(processes=processes, initializer=worker_init)

    async_results = [pool.apply_async(process_address_ranges, (r, False)) for r in all_ranges if r.address != g_ctx.address]

    try:
        remote_results = [r.get() for r in async_results]
    except KeyboardInterrupt:
        log.error("Caught Ctrl+C. Terminating.")
        pool.terminate()
        pool.join()
        g_ctx.stats.timer.main('finished')
        return False

    diff_results = []

    for result, stats, diff_result in remote_results:
        g_ctx.stats[stats.name] = stats
        if diff_result:
            id_range, eid, address, filename = diff_result
            dres = IteratorResult.load_filename(filename,
                                                address=address,
                                                eid=eid,
                                                is_sorted=True,
                                                id_range=id_range,
                                                tmp_dir=g_ctx.tmp_dir,
                                                )
            dres.address = address
            dres.group_id = eid.group_id
            diff_results.append(dres)
        results.append(result)

    result &= all(results)

    diff_length = sum([len(r) for r in diff_results])

    log.warning('Computing merge and splitting by node all remote results')
    stats.timer.main('merge & split')
    splitted_results = IteratorResult.merge(diff_results, g_ctx.tmp_dir)
    stats.timer.main('finished')

    assert diff_length == sum([len(r) for r in splitted_results])

    if not g_ctx.dry_run:
        try:
            async_results = [pool.apply_async(recover, (r.id_range, r.eid, r.address)) for r in splitted_results if r]

            # Use INT_MAX as timeout, so we can catch Ctrl+C
            timeout = 2147483647

            recover_results = [r.get(timeout) for r in async_results]
            results = []
            for result, stats in recover_results:
                results.append(result)
                g_ctx.stats[stats.name] = stats

        except KeyboardInterrupt:
            log.error("Caught Ctrl+C. Terminating.")
            pool.terminate()
            pool.join()
            g_ctx.stats.timer.main('finished')
            return False
        else:
            log.info("Closing pool, joining threads")
            pool.close()
            pool.join()
        result &= all(results)

    if not (g_ctx.id_range is None or g_ctx.eid is None or g_ctx.id_range is None):
        os.unlink(os.path.join(ctx.tmp_dir, mk_container_name(g_ctx.id_range, g_ctx.eid)))

    g_ctx.stats.timer.main('finished')
    log.debug("Result: %s" % result)

    return result
