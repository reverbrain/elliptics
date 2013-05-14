#!/usr/bin/env python

"""
New recovery mechanism for elliptics that utilizes new iterators and metadata

 * Find ranges that host stole from neighbours in routing table.
 * Start metadata-only iterator fo each range on local and remote hosts.
 * Sort iterators' outputs.
 * Computes diff between local and remote iterator.
 * Recover keys provided by diff using bulk API.
"""

import sys
import os
import logging as log

from collections import defaultdict
from operator import itemgetter
from datetime import datetime
from itertools import groupby

from recover.range import IdRange, RecoveryRange
from recover.route import RouteList
from recover.iterator import Iterator
from recover.time import Time
from recover.utils.lru_cache import lru_cache
from recover.utils.misc import format_id, split_host_port, mk_container_name

# XXX: change me before BETA
sys.path.insert(0, "bindings/python/")
import elliptics

log.getLogger()

@lru_cache()
def elliptics_create_node(host=None, port=None, elog=None, cfg=None):
    """
    Connects to elliptics cloud
    """
    log.info("Creating node using: {0}:{1}".format(host, port))
    if not cfg:
        cfg = elliptics.Config()
    node = elliptics.Node(elog, cfg)
    node.add_remote(host, port)
    log.info("Created node: {0}".format(node))
    return node

@lru_cache()
def elliptics_create_session(node=None, group=None, cflags=None):
    log.debug("Creating session: {0}@{1}.{2}".format(node, group, cflags))
    session = elliptics.Session(node)
    session.set_groups([group])
    if cflags:
        session.set_cflags(cflags)
    return session

def get_ranges(ctx, routes, group_id):
    """
    For each record in RouteList create 1 or 2 RecoveryRange(s)
    Returns list of RecoveryRange`s
    """
    ranges = []
    for i, route in enumerate(routes):
        ekey, node = routes[i]
        prev_node = routes[i - 1].node
        next_ekey = routes[i + 1].key
        if ekey.group_id != group_id:
            log.debug("Skipped route: {0}, it belongs to group_id: {1}".format(
                route, ekey.group_id))
            continue
        if node == ctx.hostport:
            start = ekey.id
            stop = next_ekey.id
            # If we wrapped around hash ring circle - split route into two distinct ranges
            if (stop < start):
                log.debug("Splitting range: {0}:{1}".format(
                    format_id(start), format_id(stop)))
                ranges.append(RecoveryRange(IdRange(IdRange.ID_MIN, stop), prev_node))
                ranges.append(RecoveryRange(IdRange(start, IdRange.ID_MAX), prev_node))
            else:
                ranges.append(RecoveryRange(IdRange(start, stop), prev_node))
    return ranges

def run_iterators(ctx, group=None, routes=None, ranges=None, stats=None):
    """
    Runs local and remote iterators for each range.
    TODO: Can be parallel
    """
    results = []
    local_eid = routes.filter_by_host(ctx.hostport)[0].key

    for iteration_range in ranges:
        stats['iteration_total'] += 2
        try:
            timestamp_range = ctx.timestamp.to_etime(), Time.time_max().to_etime()

            log.debug("Running local iterator on: {0}".format(mk_container_name(
                iteration_range.id_range, local_eid)))
            local_result = Iterator(ctx.node, group).start(
                eid=local_eid,
                timestamp_range=timestamp_range,
                key_range=iteration_range.id_range,
                tmp_dir=ctx.tmp_dir,
            )
            log.debug("Local obtained: {0} record(s)".format(len(local_result)))
            stats['iteration_local_records'] += len(local_result)
            stats['iteration_local'] += 1

            remote_eid = routes.filter_by_host(iteration_range.host)[0].key
            log.debug("Running remote iterator on: {0}".format(mk_container_name(
                iteration_range.id_range, remote_eid)))
            remote_result = Iterator(ctx.node, group).start(
                eid=remote_eid,
                timestamp_range=timestamp_range,
                key_range=iteration_range.id_range,
                tmp_dir=ctx.tmp_dir,
            )
            remote_result.host = iteration_range.host
            log.debug("Remote obtained: {0} record(s)".format(len(remote_result)))
            stats['iteration_remote_records'] += len(remote_result)
            stats['iteration_remote'] += 1

            results.append((local_result, remote_result))
        except Exception as e:
            log.error("Iteration failed for: {0}@{1}: {2}".format(
                iteration_range.id_range, iteration_range.host, repr(e)))
            stats['iteration_failed'] += 1
    return results

def sort(ctx, results, stats):
    """
    Runs sort routine for all iterator result
    TODO: Can be parallel
    """
    sorted_results = []
    for local, remote in results:
        if not (local.status and remote.status):
            log.debug("Sort skipped because local or remote iterator failed")
            stats['sort_skipped'] += 1
            continue
        try:
            assert local.id_range == remote.id_range, \
                "Local range must equal remote range"

            log.info("Processing sorting local range: {0}".format(local.id_range))
            stats['sort_total'] += 1
            local.container.sort()
            stats['sort_local_finished'] += 1

            log.info("Processing sorting remote range: {0}".format(local.id_range))
            stats['sort_total'] += 1
            remote.container.sort()
            stats['sort_remote_finished'] += 1

            sorted_results.append((local, remote))
        except Exception as e:
            log.error("Sort of {0} failed: {1}".format(local.id_range, e))
            stats['sort_failed'] += 1
    return sorted_results

def diff(ctx, results, stats):
    """
    Compute differences between local and remote results.
    TODO: Can be parallel
    """
    diff_results = []
    for local, remote in results:
        stats['diff_total'] += 1
        log.info("Computing differences for {0}".format(local.id_range))
        try:
            diff_results.append(local.diff(remote))
        except Exception as e:
            stats['diff_failed'] += 1
            log.error("Diff of {0} failed: {1}".format(local.id_range, e))
    return diff_results

def recover(ctx, diffs, group, stats):
    """
    Recovers difference between remote and local data.
    TODO: Can be parallel
    """
    result = True
    for diff in diffs:
        log.info("Recovering range: {0} for: {1}".format(diff.id_range, diff.host))

        # Here we cleverly splitting responses into ctx.batch_size batches
        for group, batch in groupby(enumerate(diff),
                                        key=lambda x: x[0] / ctx.batch_size):
            keys = [elliptics.Id(r.key, group, 0) for _, r in batch]
            total, failures = recover_keys(ctx, diff.host, group, keys)
            stats['recover_keys_failed'] += failures
            stats['recover_keys_total'] += total
            result &= (failures == 0)
            log.debug("Recovered batch: {0} of size: {1}, failed: {2}".format(group, total, failures))
    return result

def recover_keys(ctx, hostport, group, keys):
    """
    Bulk recovery of keys.
    """
    key_num = len(keys)

    log.debug("Reading {0} keys".format(key_num))
    try:
        log.debug("Creating node for: {0}".format(hostport))
        host, port = split_host_port(hostport)
        node = elliptics_create_node(host=host, port=port, elog=ctx.elog)
        log.debug("Creating direct session: {0}".format(hostport))
        direct_session = elliptics_create_session(node=node,
                                                  group=group,
                                                  cflags=elliptics.command_flags.direct,
        )
        batch = direct_session.bulk_read_by_id(keys)
    except Exception as e:
        log.debug("Bulk read failed: {0} keys: {1}".format(key_num, e))
        return key_num, key_num

    log.debug("Writing {0} keys".format(key_num))
    try:
        session_normal = elliptics_create_session(node=ctx.node, group=group)
        session_normal.bulk_write_by_id(batch.iterkeys(), batch.itervalues())
    except Exception as e:
        log.debug("Bulk write failed: {0} keys: {1}".format(key_num, e))
        return key_num, key_num
    return key_num, 0

def print_stats(stats):
    """
    Output statistics about recovery process.
    TODO: Add different output formats
    """
    align = 80
    sep_equals = '=' * align
    sep_plus = '+' * align

    def format_kv(k,v):
        return '{0:<40}{1:>40}'.format(k + ':', str(v))

    def sort_dict_by_key(dictionary):
        return sorted(dictionary.iteritems(), key=itemgetter(0))

    print
    print sep_equals
    print "Statistics for groups: {0}".format(stats['groups'].keys())
    for k, v in sort_dict_by_key(stats['global']):
        print format_kv(k,v)
    print sep_equals
    for group in sorted(stats['groups']):
        print "Group {0} stats:".format(group)
        print sep_plus
        for k, v in sort_dict_by_key(stats['groups'][group]):
            print format_kv(k,v)
        print sep_plus
        print

def main(ctx):
    """
    XXX:
    """
    result = True
    ctx.stats['global'] = defaultdict(int)
    ctx.stats['global']['time_started'] = datetime.now()
    for group in ctx.groups:
        log.warning("Processing group: {0}".format(group))
        group_stats = ctx.stats['groups'][group] = defaultdict(int)

        log.debug("Creating session for: {0}".format(ctx.hostport))
        session = elliptics_create_session(node=ctx.node, group=group)

        log.warning("Searching for ranges that {0} stole".format(ctx.hostport))
        routes = RouteList(session.get_routes())
        log.debug("Total routes: {0}".format(len(routes)))

        ranges = get_ranges(ctx, routes, group)
        log.debug("Recovery ranges: {0}".format(len(ranges)))
        if not ranges:
            log.warning("No ranges to recover in group: {0}".format(group))
            continue
        # We should not run iterators on ourselves
        assert all(node != ctx.host for _, node in ranges)

        log.warning("Running iterators against: {0} range(s)".format(len(ranges)))
        iterator_results = run_iterators(
            ctx,
            group=group,
            routes=routes,
            ranges=ranges,
            stats=group_stats,
        )
        assert len(ranges) >= len(iterator_results)
        log.warning("Finished iteration of: {0} range(s)".format(len(iterator_results)))

        log.warning("Sorting iterators' data")
        sorted_results = sort(ctx, iterator_results, group_stats)
        assert len(iterator_results) >= len(sorted_results)
        log.warning("Sorted successfully: {0} result(s)".format(len(sorted_results)))

        log.warning("Computing diff local vs remote")
        diff_results = diff(ctx, sorted_results, group_stats)
        assert len(sorted_results) >= len(diff_results)
        log.warning("Computed differences: {0} diff(s)".format(len(diff_results)))

        log.warning("Recovering diffs")
        result &= recover(ctx, diff_results, group, group_stats)
        log.warning("Recovery finished, setting result to: {0}".format(result))

    ctx.stats['global']['time_stopped'] = datetime.now()
    ctx.stats['global']['time_taken'] = ctx.stats['global']['time_stopped']\
                                        - ctx.stats['global']['time_started']
    return result

if __name__ == '__main__':
    from recover.ctx import Ctx
    from optparse import OptionParser

    available_stats = ['none', 'text']

    parser = OptionParser()
    parser.add_option("-l", "--log", dest="elliptics_log", default='/dev/stderr', metavar="FILE",
                      help="Output log messages from library to file [default: %default]")
    parser.add_option("-L", "--log-level", action="store", dest="elliptics_log_level", default="1",
                      help="Elliptics client verbosity [default: %default]")
    parser.add_option("-r", "--remote", action="store", dest="elliptics_remote", default="127.0.0.1:1025",
                      help="Elliptics node address [default: %default]")
    parser.add_option("-g", "--groups", action="store_const", dest="elliptics_groups", default="2",
                      help="Comma separated list of groups [default: %default]")
    parser.add_option("-t", "--timestamp", action="store", dest="timestamp", default="0",
                      help="Recover keys created/modified since [default: %default]")
    parser.add_option("-b", "--batch-size", action="store", dest="batch_size", default="1024",
                      help="Number of keys in read_bulk/write_bulk batch [default: %default]")
    parser.add_option("-d", "--debug", action="store_true", dest="debug", default=False,
                      help="Enable debug output [default: %default]")
    parser.add_option("-s", "--stat", action="store", dest="stat", default="text",
                      help="Statistics output format: {0} [default: %default]".format("/".join(available_stats)))
    parser.add_option("-D", "--dir", dest="tmp_dir", default='/var/tmp/', metavar="DIR",
                      help="Temporary directory for iterators' results [default: %default]")

    (options, args) = parser.parse_args()

    if options.debug:
        log.getLogger().setLevel(log.DEBUG)

    if (args):
        raise RuntimeError("Passed garbage: '{0}'".format(args))

    log.info("Initializing context")
    ctx = Ctx()

    # XXX: Add proper stats API
    log.info("Initializing stats")
    ctx.stats = defaultdict(dict)

    try:
        ctx.hostport = options.elliptics_remote
        ctx.host, ctx.port = split_host_port(options.elliptics_remote)
    except Exception as e:
        raise ValueError("Can't parse host:port: '{0}': {1}".format(
            options.elliptics_remote, repr(e)))
    log.info("Using host:port: {0}:{1}".format(ctx.host, ctx.port))

    try:
        ctx.groups = map(int, options.elliptics_groups.split(','))
    except Exception as e:
        raise ValueError("Can't parse grouplist: '{0}': {1}".format(
            options.elliptics_groups, repr(e)))
    log.info("Using group list: {0}".format(ctx.groups))

    try:
        ctx.timestamp = Time.from_epoch(options.timestamp)
    except Exception as e:
        raise ValueError("Can't parse timestamp: '{0}': {1}".format(
            options.timestamp, repr(e)))
    log.info("Using timestamp: {0}".format(ctx.timestamp))

    try:
        ctx.batch_size = int(options.batch_size)
    except Exception as e:
        raise ValueError("Can't parse batchsize: '{0}': {1}".format(
            options.batch_size, repr(e)))
    log.info("Using batch_size: {0}".format(ctx.batch_size))

    try:
        ctx.log_file = options.elliptics_log
        ctx.log_level = int(options.elliptics_log_level)
    except Exception as e:
        raise ValueError("Can't parse log_level: '{0}': {1}".format(
            options.elliptics_log_level, repr(e)))
    log.info("Using elliptics client log level: {0}".format(ctx.log_level))

    ctx.tmp_dir = options.tmp_dir
    if not os.access(ctx.tmp_dir, os.W_OK):
        raise ValueError("Don't have write access to: {0}".format(options.tmp_dir))
    log.info("Using tmp directory: {0}".format(ctx.tmp_dir))

    if options.stat not in available_stats:
        raise ValueError("Unknown output format: '{0}'. Available formats are: {1}".format(
            options.stat, available_stats))

    log.debug("Using following context:\n{0}".format(ctx))

    log.info("Setting up elliptics client")
    log.debug("Creating logger")
    ctx.elog = elliptics.Logger(ctx.log_file, int(ctx.log_level))
    log.debug("Creating node")
    ctx.node = elliptics_create_node(host=ctx.host, port=ctx.port, elog=ctx.elog)

    result = main(ctx)

    if options.stat == 'text':
        print_stats(ctx.stats)

    exit(not result)
