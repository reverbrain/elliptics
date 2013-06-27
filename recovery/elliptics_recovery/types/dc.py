"""
XXX:
"""

import sys
import logging

from itertools import groupby
from multiprocessing import Pool

from ..iterator import Iterator, IteratorResult
from ..etime import Time
from ..utils.misc import elliptics_create_node, elliptics_create_session, worker_init

# XXX: change me before BETA
sys.path.insert(0, "bindings/python/")
import elliptics

log = logging.getLogger(__name__)


def run_iterators(ctx, range, stats):
    """
    Runs local and remote iterators for each range.
    TODO: We can group iterators by host and run them in parallel
    TODO: We can run only one iterator per host if we'll teach iterators to "batch" all key ranges in one request
    """
    node = elliptics_create_node(address=ctx.address, elog=ctx.elog)

    try:
        timestamp_range = ctx.timestamp.to_etime(), Time.time_max().to_etime()

        local_eid = range.address[ctx.group_id][0]

        log.debug("Running local iterator on: {0} on node: {1}".format(range.id_range, range.address[ctx.group_id][1]))
        local_result, local_result_len = Iterator.iterate_with_stats(node=node,
                                                                     eid=local_eid,
                                                                     timestamp_range=timestamp_range,
                                                                     key_ranges=[range.id_range],
                                                                     tmp_dir=ctx.tmp_dir,
                                                                     address=ctx.address,
                                                                     batch_size=ctx.batch_size,
                                                                     stats=stats,
                                                                     counters=['iterated_keys']
                                                                     )

        stats.counter('iterations', 1)
        log.debug("Local iterator obtained: {0} record(s)".format(local_result_len))
        remote_results = []

        for i in range.address:
            if i == ctx.group_id:
                continue
            remote_eid = range.address[i][0]

            log.debug("Running remote iterator on:{0} on node: {1}".format(range.id_range, range.address[i][1]))

            remote_result, remote_result_len = Iterator.iterate_with_stats(node=node,
                                                                           eid=remote_eid,
                                                                           timestamp_range=timestamp_range,
                                                                           key_ranges=[range.id_range],
                                                                           tmp_dir=ctx.tmp_dir,
                                                                           address=range.address[i][1],
                                                                           batch_size=ctx.batch_size,
                                                                           stats=stats,
                                                                           counters=['remote_records', 'iterated_keys']
                                                                           )

            stats.counter('iterations', 1)

            if remote_result is None or remote_result_len == 0:
                log.warning("Remote iterator result is empty, skipping")
                continue

            remote_results.append(remote_result)

            remote_results[-1].address = range.address[i][1]
            remote_results[-1].group_id = i
            log.debug("Remote obtained: {0} record(s)".format(remote_result_len))

        return local_result, remote_results

    except Exception as e:
        log.error("Iteration failed for: {0}@{1}: {2}".format(range.id_range, range.address, repr(e)))
        return None, None


def sort(ctx, local, remote, stats):
    """
    Runs sort routine for all iterator result
    """

    if remote is None or len(remote) == 0:
        log.debug("Sort skipped remote iterator results are empty")
        return local, remote

    try:
        assert all(local.id_range == r.id_range for r in remote), "Local range must equal remote range"

        log.info("Processing sorting local range: {0}".format(local.id_range))
        local.container.sort()
        stats.counter('sort', 1)

        for r in remote:
            log.info("Processing sorting remote range: {0}".format(r.id_range))
            r.container.sort()
            stats.counter('sort', 1)

        return local, remote
    except Exception as e:
        log.error("Sort of {0} failed: {1}".format(local.id_range, e))
        stats.counter('sort', -1)
        return None, None


def diff(ctx, local, remote, stats):
    """
    Compute differences between local and remote results.
    TODO: We can compute up to CPU_NUM diffs at max in parallel
    """
    diffs = []
    total_diffs = 0
    for r in remote:
        try:
            if r is None or len(r) == 0:
                log.info("Remote container is empty, skipping")
                continue
            elif local is None or len(local) == 0:
                log.info("Local container is empty, recovering full range: {0}".format(local.id_range))
                result = r
            else:
                log.info("Computing differences for: {0}".format(local.id_range))
                result = local.diff(r)
                result.address = r.address
                result.group_id = r.group_id
            if len(result) > 0:
                diffs.append(result)
                result_len = len(result)
                stats.counter('diffs', result_len)
                total_diffs += result_len
            else:
                log.info("Resulting diff is empty, skipping")
        except Exception as e:
            log.error("Diff of {0} failed: {1}".format(local.id_range, e))
    log.info("Found {0} differences with remote nodes.".format(total_diffs))
    return diffs


def recover(ctx, splitted_results, stats):
    """
    Recovers difference between remote and local data.
    TODO: Group by diffs by host and process each group in parallel
    """
    result = True

    log.info("Recovering {0} keys".format(sum(len(d) for d in splitted_results)))

    local_node = elliptics_create_node(address=ctx.address,
                                       elog=ctx.elog,
                                       io_thread_num=4,
                                       net_thread_num=4,
                                       nonblocking_io_thread_num=4
                                       )
    log.debug("Creating direct session: {0}".format(ctx.address))
    local_session = elliptics_create_session(node=local_node,
                                             group=ctx.group_id,
                                             )
    local_session.set_direct_id(*ctx.address)

    async_write_results = []
    successes, failures, successes_size, failures_size = (0, 0, 0, 0)

    for diff in splitted_results:
        remote_node = elliptics_create_node(address=diff.address,
                                            elog=ctx.elog,
                                            io_thread_num=4,
                                            net_thread_num=4,
                                            nonblocking_io_thread_num=4
                                            )
        log.debug("Creating direct session: {0}".format(diff.address))
        remote_session = elliptics_create_session(node=remote_node,
                                                  group=diff.eid.group_id,
                                                  )
        remote_session.set_direct_id(*diff.address)

        for batch_id, batch in groupby(enumerate(diff), key=lambda x: x[0] / ctx.batch_size):
            keys = [elliptics.Id(r.key, diff.eid.group_id) for _, r in batch]
            aresult = recover_keys(ctx, diff.address, diff.eid.group_id, keys, local_session, remote_session, stats)
            keys_len = len(keys)
            if not aresult:
                stats.counter('recovered_keys', -keys_len)
            else:
                async_write_results.extend(aresult)

    for batch_id, batch in groupby(enumerate(async_write_results), key=lambda x: x[0] / ctx.batch_size):
        successes, failures = (0, 0)
        for _, (r, bsize) in batch:
            r.wait()
            if r.successful():
                successes_size += bsize
                successes += 1
            else:
                failures_size += bsize
                failures += 1

        stats.counter('recovered_bytes', successes_size)
        stats.counter('recovered_bytes', -failures_size)
        stats.counter('recovered_keys', successes)
        stats.counter('recovered_keys', -failures)
        log.debug("Recovered batch: {0}/{1} of size: {2}/{3}".format(successes + failures, len(diff), successes, failures))
        result &= (failures == 0)

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
        batch = remote_session.bulk_read_async(keys)
    except Exception as e:
        log.debug("Bulk read failed: {0} keys: {1}".format(keys_len, e))
        stats.counter('recovered_keys', -keys_len)
        return None

    it = iter(batch)
    failed = 0

    while True:
        try:
            b = next(it)
            async_write_results.append((local_session.write_data_async((b.id, b.timestamp, b.user_flags), b.data), len(b.data)))
        except StopIteration:
            break
        except Exception as e:
            failed += 1
            log.debug("Write failed: {0}".format(e))

    read_len = len(async_write_results)
    stats.counter('read_keys', read_len)
    stats.counter('read_keys', -failed)
    stats.counter('recovered_keys', -failed)
    stats.counter('skipped_keys', keys_len - read_len - failed)
    return async_write_results


def process_range((range, dry_run)):
    ctx = g_ctx
    ctx.elog = elliptics.Logger(ctx.log_file, ctx.log_level)

    stats_name = 'range_{0}'.format(range.id_range)
    stats = ctx.monitor.stats[stats_name]

    log.info("Running iterators")
    stats.timer('process', 'iterator')
    it_local, it_remotes = run_iterators(ctx, range, stats)

    if it_remotes is None or len(it_remotes) == 0:
        log.warning("Iterator results are empty, skipping")
        stats.timer('process', 'finished')
        return True

    stats.timer('process', 'sort')
    sorted_local, sorted_remotes = sort(ctx, it_local, it_remotes, stats)
    assert len(sorted_remotes) >= len(it_remotes)

    log.info("Computing diff local vs remotes")
    stats.timer('process', 'diff')
    diff_results = diff(ctx, sorted_local, sorted_remotes, stats)
    if diff_results is None or len(diff_results) == 0:
        log.warning("Diff results are empty, skipping")
        stats.timer('process', 'finished')
        return True

    log.info('Computing merge and splitting by node all remote results')

    diff_length = sum([len(d) for d in diff_results])

    stats.timer('process', 'merge_and_split')
    splitted_results = IteratorResult.merge(diff_results, ctx.tmp_dir)

    merged_diff_length = 0
    for spl in splitted_results:
        spl_len = len(spl)
        merged_diff_length += spl_len
        stats.counter('merged_diffs_{0}'.format(spl.address), spl_len)

    assert diff_length >= merged_diff_length
    stats.counter('merged_diffs', merged_diff_length)

    result = True
    stats.timer('process', 'recover')
    if not dry_run:
        result = recover(ctx, splitted_results, stats)

    stats.timer('process', 'finished')
    return result


def main(ctx):
    global g_ctx
    g_ctx = ctx
    result = True
    g_ctx.monitor.stats.timer('main', 'started')

    log.debug("Groups: %s" % g_ctx.groups)

    g_ctx.group_id = g_ctx.routes.filter_by_address(g_ctx.address)[0].key.group_id

    log.info("Searching for ranges that %s store" % g_ctx.address)
    ranges = g_ctx.routes.get_ranges_by_address(g_ctx.address)
    log.debug("Recovery ranges: %d" % len(ranges))
    if not ranges:
        log.warning("No ranges to recover for address %s" % g_ctx.address)
        g_ctx.monitor.stats.timer('main', 'finished')
        return result

    processes = min(g_ctx.nprocess, len(ranges))
    pool = Pool(processes=processes, initializer=worker_init)
    log.debug("Created pool of processes: %d" % processes)

    g_ctx.monitor.stats.counter("iterations", len(ranges) * len(g_ctx.routes.groups()))
    try:
        for r in pool.imap_unordered(process_range, ((r, g_ctx.dry_run) for r in ranges)):
            result &= r
    except KeyboardInterrupt:
        log.error("Caught Ctrl+C. Terminating.")
        pool.terminate()
        pool.join()
        g_ctx.monitor.stats.timer('main', 'finished')
        return False
    else:
        log.info("Closing pool, joining threads.")
        pool.close()
        pool.join()

    g_ctx.monitor.stats.timer('main', 'finished')
    return result
