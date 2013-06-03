"""
XXX:
"""

import sys, os
import logging as log

from itertools import groupby
from multiprocessing import Pool

from ..iterator import Iterator, IteratorResult
from ..time import Time
from ..stat import Stats
from ..utils.misc import format_id, mk_container_name, elliptics_create_node, elliptics_create_session

# XXX: change me before BETA
sys.path.insert(0, "bindings/python/")
import elliptics

log.getLogger()

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
        local_result = Iterator(node, ctx.group_id).start(eid=local_eid,
                                                          timestamp_range=timestamp_range,
                                                          key_ranges=[range.id_range],
                                                          tmp_dir=ctx.tmp_dir,
                                                          address = ctx.address
                                                         )

        stats.counter.local_records += len(local_result)
        stats.counter.iterated_keys += len(local_result)
        stats.counter.iterations += 1
        log.debug("Local iterator obtained: {0} record(s)".format(len(local_result)))
        remote_result = []

        for i in range.address:
            if i == ctx.group_id:
                continue
            remote_eid = range.address[i][0]

            log.debug("Running remote iterator on:{0} on node: {1}".format(range.id_range, range.address[i][1]))

            it_result = Iterator(node, i).start(eid=remote_eid,
                                                timestamp_range=timestamp_range,
                                                key_ranges=[range.id_range],
                                                tmp_dir=ctx.tmp_dir,
                                                address = range.address[i][1]
                                               )

            if it_result is None or len(it_result) == 0:
                log.warning("Remote iterator result is empty, skipping")
                continue

            remote_result.append(it_result)

            remote_result[-1].address = range.address[i][1]
            remote_result[-1].group_id = i
            log.debug("Remote obtained: {0} record(s)".format(len(remote_result[-1])))
            stats.counter.remote_records += len(remote_result[-1])
            stats.counter.iterated_keys += len(remote_result[-1])
            stats.counter.iterations +=1

        return local_result, remote_result

    except Exception as e:
        log.error("Iteration failed for: {0}@{1}: {2}".format(range.id_range, range.address, repr(e)))
        return None, None

def sort(ctx, local, remote, stats):
    """
    Runs sort routine for all iterator result
    """
    sorted_results = []

    if remote is None or len(remote) == 0:
        log.debug("Sort skipped remote iterator results are empty")
        return local, remote

    try:
        assert all(local.id_range == r.id_range for r in remote), "Local range must equal remote range"

        log.info("Processing sorting local range: {0}".format(local.id_range))
        local.container.sort()
        stats.counter.sort += 1

        for r in remote:
            log.info("Processing sorting remote range: {0}".format(r.id_range))
            r.container.sort()
            stats.counter.sort += 1

        return local, remote
    except Exception as e:
        log.error("Sort of {0} failed: {1}".format(local.id_range, e))
        stats.counter.sort -= 1
        return None, None

def diff(ctx, local, remote, stats):
    """
    Compute differences between local and remote results.
    TODO: We can compute up to CPU_NUM diffs at max in parallel
    """
    diffs = []
    for r in remote:
        try:
            if r is None or len(r) == 0:
                log.info("Remote container is empty, skipping")
                continue
            elif local is None or len(local) == 0:
                log.info("Local container is empty, recovering full range: {0}".format(local.id_range))
                result = r;
            else:
                log.info("Computing differences for: {0}".format(local.id_range))
                result = local.diff(r)
                result.address = r.address
                result.group_id = r.group_id
            if len(result) > 0:
                diffs.append(result)
                stats.counter.diffs += len(result)
            else:
                log.info("Resulting diff is empty, skipping")
        except Exception as e:
            log.error("Diff of {0} failed: {1}".format(local.id_range, e))
    return diffs

def recover(ctx, splitted_results, stats):
    """
    Recovers difference between remote and local data.
    TODO: Group by diffs by host and process each group in parallel
    """
    result = True

    local_node = elliptics_create_node(address=ctx.address, elog=ctx.elog, flags=2)
    log.debug("Creating direct session: {0}".format(ctx.address))
    local_session = elliptics_create_session(node=local_node,
                                             group=ctx.group_id,
                                             cflags=elliptics.command_flags.direct,
                                            )

    for diff in splitted_results:

        remote_node = elliptics_create_node(address=diff.address, elog=g_ctx.elog, flags=2)
        log.debug("Creating direct session: {0}".format(diff.address))
        remote_session = elliptics_create_session(node=remote_node,
                                                  group=diff.eid.group_id,
                                                  cflags=elliptics.command_flags.direct,
                                                 )

        for batch_id, batch in groupby(enumerate(diff), key=lambda x: x[0] / g_ctx.batch_size):
            keys = [elliptics.Id(r.key, diff.eid.group_id, 0) for _, r in batch]
            successes, failures = recover_keys(ctx, diff.address, diff.eid.group_id, keys, local_session, remote_session, stats)
            stats.counter.recovered_keys += successes
            stats.counter.recovered_keys -= failures
            result &= (failures == 0)
            log.debug("Recovered batch: {0}/{1} of size: {2}/{3}".format(batch_id * g_ctx.batch_size + len(keys), len(diff), successes, failures))

    return result

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

def merge_and_split_diffs(ctx, diff_results, stats):
    log.warning('Computing merge and splittimg by node all remote results')
    stats.timer.main('merge & split')
    splitted_results = dict()

    if len(diff_results) == 1:
        import shutil
        diff = diff_results[0]
        filename = os.path.join(ctx.tmp_dir, "merge_" + mk_container_name(diff.id_range, diff.eid))
        shutil.copyfile(diff.filename, filename)
        splitted_results[diff.address] = IteratorResult.load_filename(filename,
                                                                      address=diff.address,
                                                                      id_range=diff.id_range,
                                                                      eid=diff.eid,
                                                                      sorted=True,
                                                                      tmp_dir=ctx.tmp_dir,
                                                                      leave_file=True
                                                                     )
    elif len(diff_results) != 0:
        its = []
        for d in diff_results:
            its.append(iter(d))
            filename = os.path.join(ctx.tmp_dir, "merge_" + mk_container_name(d.id_range, d.eid))
            splitted_results[d.address] = IteratorResult.from_filename(filename,
                                                                       address=d.address,
                                                                       id_range=d.id_range,
                                                                       eid=d.eid,
                                                                       tmp_dir=ctx.tmp_dir,
                                                                       leave_file=True
                                                                      )
        vals = [i.next() for i in its]
        while len(vals):
            i_min = 0
            k_min = IdRange.ID_MAX
            t_min = Time.time_max().to_etime()
            for i, v in enumerate(vals):
                key = v.key
                time = v.timestamp
                if key < k_min or (key == k_min and time > t_min):
                    k_min = key
                    t_min = time
                    i_min = i
            splitted_results[diff_results[i_min].address].append_rr(vals[i])
            for i, v in enumerate(vals):
                if v.key == k_min:
                    try:
                        vals[i] = its[i].next()
                    except:
                        del(vals[i])
                        del(its[i])
                        del(diff_results[i])

    stats.timer.main('finished')
    return splitted_results.values()

def process_range(range, dry_run):
    stats_name = 'range_{0}'.format(range.id_range)
    stats = Stats(stats_name)
    stats.timer.process('started')

    g_ctx.elog = elliptics.Logger(g_ctx.log_file, g_ctx.log_level)

    log.warning("Running iterators")
    stats.timer.process('iterator')
    it_local, it_remotes = run_iterators(g_ctx, range, stats)
    stats.timer.process('finished')

    if it_remotes is None or len(it_remotes) == 0:
        log.warning("Iterator results are empty, skipping")
        return True, stats

    stats.timer.process('sort')
    sorted_local, sorted_remotes = sort(g_ctx, it_local, it_remotes, stats)
    stats.timer.process('finished')
    assert len(sorted_remotes) >= len(it_remotes)

    log.warning("Computing diff local vs remotes")
    stats.timer.process('diff')
    diff_results = diff(g_ctx, sorted_local, sorted_remotes, stats)
    stats.timer.process('finished')

    if diff_results is None or len(diff_results) == 0:
        log.warning("Diff results are empty, skipping")
        return True, stats

    stats.timer.process('merge and split')
    splitted_results = merge_and_split_diffs(g_ctx, diff_results, stats)
    stats.timer.process('finished')

    result = True
    stats.timer.process('recover')
    if not dry_run:
        result = recover(g_ctx, splitted_results, stats)
    stats.timer.process('finished')

    return result, stats


def main(ctx):
    global g_ctx
    g_ctx = ctx
    result = True
    g_ctx.stats.timer.main('started')

    if len(g_ctx.groups) == 0:
        g_ctx.groups = g_ctx.routes.groups()
    log.debug("Groups: %s" % g_ctx.groups)

    g_ctx.group_id = g_ctx.routes.filter_by_address(g_ctx.address)[0].key.group_id

    log.warning("Searching for ranges that %s store" % g_ctx.address)
    ranges = g_ctx.routes.get_ranges_by_address(g_ctx.address)
    log.debug("Recovery ranges: %d" % len(ranges))
    if not ranges:
        log.warning("No ranges to recover for address %s" % g_ctx.address)
        g_ctx.stats.timer.main('finished')
        return result

    processes = min(g_ctx.nprocess, len(ranges) - 1)
    pool = Pool(processes=g_ctx.nprocess)
    log.debug("Created pool of processes: %d" % g_ctx.nprocess)

    recover_stats = g_ctx.stats["recover"]
    async_results = [ pool.apply_async(process_range, (r, g_ctx.dry_run)) for r in ranges ]

    log.info("Closing pool, joining threads")
    pool.close()
    pool.join()

    results = [ r.get() for r in async_results ]

    for r, stats in results:
        g_ctx.stats[stats.name] = stats
        result &= r

    g_ctx.stats.timer.main('finished')
    log.debug("Result: %s" % result)

    return result
