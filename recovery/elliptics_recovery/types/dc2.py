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
                                                    address=address,
                                                    leave_file=True)

        if result is None:
            raise RuntimeError("Iterator result is None")
        log.debug("Iterator {0} obtained: {1} record(s)".format(result.id_range, len(result)))
        result_len = len(result)
        stats.counter.iterated_keys += result_len
        ctx.monitor.add_counter("iterated_keys", result_len)
        stats.counter.iterations += 1
        ctx.monitor.add_counter("iterations", 1)
        return result

    except Exception as e:
        log.error("Iteration failed for: {0}: {1}".format(address, repr(e)))
        ctx.monitor.add_counter("iterations", -1)
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
        ctx.monitor.add_counter("sort", 1)
        return result
    except Exception as e:
        log.error("Sort of {0} failed: {1}".format(result.id_range, e))
        stats.counter.sort -= 1
        ctx.monitor.add_counter("sort", -1)
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
        ctx.monitor.add_counter("diff", diff_len)
        log.info("Found {0} differences".format(diff_len))
        return result
    except Exception as e:
        log.error("Diff for {0} failed: {1}".format(remote.address, e))
        stats.counter.diff -= 1
        ctx.monitor.add_counter("diff", -1)
        return None


def recover((id_range, eid, address)):
    """
    Recovers difference between remote and local data.
    """

    ctx = g_ctx

    result = True
    stats_name = 'recover_{0}'.format(address)
    stats = Stats(stats_name)
    log.info("Recovering range: {0} for: {1}".format(id_range, address))
    ctx.monitor.add_timer(stats_name, 'started')
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

    local_node = elliptics_create_node(address=ctx.address, elog=ctx.elog)
    log.debug("Creating direct session: {0}".format(ctx.address))
    local_session = elliptics_create_session(node=local_node,
                                             group=ctx.group_id,
                                             )
    local_session.set_direct_id(*ctx.address)

    remote_node = elliptics_create_node(address=diff.address, elog=ctx.elog)
    log.debug("Creating direct session: {0}".format(diff.address))
    remote_session = elliptics_create_session(node=remote_node,
                                              group=diff.eid.group_id,
                                              )
    remote_session.set_direct_id(*diff.address)

    for batch_id, batch in groupby(enumerate(diff), key=lambda x: x[0] / ctx.batch_size):
        keys = [elliptics.Id(r.key, diff.eid.group_id) for _, r in batch]
        successes, failures = recover_keys(ctx, diff.address, diff.eid.group_id, keys, local_session, remote_session, stats)
        stats.counter.recovered_keys += successes
        ctx.monitor.add_counter("recovered_keys", successes)
        stats.counter.recovered_keys -= failures
        ctx.monitor.add_counter("recovered_keys", failures)
        result &= (failures == 0)
        log.debug("Recovered batch: {0}/{1} of size: {2}/{3}".format(
            batch_id * ctx.batch_size + len(keys), len(diff), successes, failures))

    stats.timer.recover('finished')
    ctx.monitor.add_timer(stats_name, 'finished')

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
        ctx.monitor.add_counter("recovered_bytes", size)
        return key_num, 0
    except Exception as e:
        log.debug("Bulk write failed: {0} keys: {1}".format(key_num, e))
        stats.counter.recovered_bytes -= size
        ctx.monitor.add_counter("recovered_bytes", -size)
        return 0, key_num


def iterate_node(address_ranges):
    """Iterates node range, sorts it and returns"""
    ctx = g_ctx

    stats_name = 'iterate_{0}'.format(address_ranges.address)
    if address_ranges.address == ctx.address:
        stats_name = 'iterate_local'

    stats = Stats(stats_name)
    ctx.monitor.add_timer(stats_name, 'started')
    stats.timer.process('started')
    ctx.elog = elliptics.Logger(ctx.log_file, int(ctx.log_level))

    log.info("Running iterator")
    ctx.monitor.add_timer(stats_name, 'iterate')
    stats.timer.process('iterate')
    result = run_iterator(ctx=ctx,
                          address=address_ranges.address,
                          eid=address_ranges.eid,
                          ranges=address_ranges.id_ranges,
                          stats=stats
                          )

    stats.timer.process('finished')
    ctx.monitor.add_timer(stats_name, 'finished')

    if result is None or len(result) == 0:
        log.warning("Iterator result is empty, skipping")
        return stats, None

    ctx.monitor.add_timer(stats_name, 'sort')
    stats.timer.process('sort')
    sorted_result = sort(ctx=ctx,
                         result=result,
                         stats=stats)
    stats.timer.process('finished')
    ctx.monitor.add_timer(stats_name, 'finished')
    assert len(result) >= len(sorted_result)

    log.info("Sorted successfully: {0} result(s)".format(len(sorted_result)))

    if sorted_result is None or len(sorted_result) == 0:
        log.warning("Sorted results are empty, skipping")
        return stats, None

    stats.timer.process('finished')
    ctx.monitor.add_timer(stats_name, 'finished')
    return stats, (sorted_result.id_range, sorted_result.eid, sorted_result.address, sorted_result.filename)


def process_diff((local, remote)):
    ctx = g_ctx

    stats_name = 'diff_remote_{0}'.format(remote[2])
    stats = Stats(stats_name)

    log.debug("Loading local result")
    ctx.monitor.add_timer(stats_name, 'start')
    stats.timer.process("start")
    local_result = None
    if local:
        local_result = IteratorResult.load_filename(local[3],
                                                    address=ctx.address,
                                                    id_range=local[0],
                                                    eid=local[1],
                                                    is_sorted=True,
                                                    tmp_dir=ctx.tmp_dir,
                                                    leave_file=True
                                                    )

    log.debug("Loading remote result")
    remote_result = None
    if remote:
        remote_result = IteratorResult.load_filename(remote[3],
                                                     address=remote[2],
                                                     id_range=remote[0],
                                                     eid=remote[1],
                                                     is_sorted=True,
                                                     tmp_dir=ctx.tmp_dir,
                                                     leave_file=True
                                                     )

    ctx.monitor.add_timer(stats_name, 'diff')
    stats.timer.process('diff')
    diff_result = diff(ctx, local_result, remote_result, stats)
    stats.timer.process('finished')
    ctx.monitor.add_timer(stats_name, 'finished')

    if diff_result is None or len(diff_result) == 0:
        log.warning("Diff result is empty, skipping")
        return stats, None

    assert len(remote_result) >= len(diff_result)

    log.info("Computed differences: {0} diff(s)".format(len(diff_result)))

    return stats, (diff_result.id_range, diff_result.eid, diff_result.address, diff_result.filename)


def main(ctx):
    global g_ctx
    g_ctx = ctx
    result = True
    g_ctx.monitor.add_timer("main", "started")
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

    processes = min(g_ctx.nprocess, len(all_ranges))
    log.info("Creating pool of processes: {0}".format(processes))
    pool = Pool(processes=processes, initializer=worker_init)

    local_ranges = next((r for r in all_ranges if r.address == g_ctx.address), None)
    assert local_ranges, 'Local ranges is absent in route table'

    local_iter_result = pool.apply_async(iterate_node, (local_ranges, ))

    iter_result = pool.imap_unordered(iterate_node, (range for range in all_ranges if range.address != g_ctx.address))

    diff_async_results = None

    def unpack_iter_result(stats, result):
        r_stats, r_result = result
        stats[r_stats.name] = r_stats
        return r_result

    try:
        timeout = 2147483647
        local_stats, local_it_result = local_iter_result.get(timeout)
        g_ctx.stats[local_stats.name] = local_stats

        diff_async_results = pool.imap_unordered(process_diff, ((local_it_result, unpack_iter_result(g_ctx.stats, result)) for result in iter_result if result[1]))

    except KeyboardInterrupt:
        log.error("Caught Ctrl+C. Terminating")
        pool.terminate()
        pool.join()
        g_ctx.stats.timer.main('finished')
        g_ctx.monitor.add_timer("main", "finished")
        return False

    diff_results = None

    def unpack_diff_result(stats, result):
        r_stats, r_diff_result = result
        stats[r_stats.name] = r_stats
        id_range, eid, address, filename = r_diff_result
        dres = IteratorResult.load_filename(filename,
                                            address=address,
                                            eid=eid,
                                            is_sorted=True,
                                            id_range=id_range,
                                            tmp_dir=g_ctx.tmp_dir,
                                            )
        dres.address = address
        dres.group_id = eid.group_id
        return dres

    try:
        diff_results = [unpack_diff_result(g_ctx.stats, diff_r) for diff_r in diff_async_results if diff_r[1]]
    except KeyboardInterrupt:
        log.error("Caught Ctrl+C. Terminating")
        pool.terminate()
        pool.join()
        g_ctx.stats.timer.main('finished')
        g_ctx.monitor.add_timer("main", "finished")
        return False

    if len(diff_results) == 0:
        log.warning("Local node has up-to-date data")
        pool.terminate()
        pool.join()
        g_ctx.stats.timer.main('finished')
        g_ctx.monitor.add_timer("main", "finished")
        return True

    diff_length = sum([len(diff) for diff in diff_results])

    log.warning('Computing merge and splitting by node all remote results')
    g_ctx.monitor.add_timer("main", "merge & split")
    g_ctx.stats.timer.main('merge & split')
    splitted_results = IteratorResult.merge(diff_results, g_ctx.tmp_dir)
    g_ctx.stats.timer.main('finished')
    g_ctx.monitor.add_timer("main", "finished")

    assert diff_length == sum([len(spl) for spl in splitted_results])

    if not g_ctx.dry_run:
        try:
            recover_results = pool.map(recover, ((r.id_range, r.eid, r.address) for r in splitted_results if r))

            results = []
            for result, stats in recover_results:
                results.append(result)
                g_ctx.stats[stats.name] = stats

        except KeyboardInterrupt:
            log.error("Caught Ctrl+C. Terminating.")
            pool.terminate()
            pool.join()
            g_ctx.stats.timer.main('finished')
            g_ctx.monitor.add_timer("main", "finished")
            return False
        else:
            log.info("Closing pool, joining threads")
            pool.close()
            pool.join()
        result &= all(results)

    g_ctx.stats.timer.main('finished')
    g_ctx.monitor.add_timer("main", "finished")
    log.debug("Result: %s" % result)

    return result
