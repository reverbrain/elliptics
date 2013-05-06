#!/usr/bin/env python

"""
New recovery mechanism for elliptics that utilizes new iterators and metadata

 * Find ranges that host stole from neighbours in routing table.
 * Start metadata-only iterator fo each range on remote hosts.
 * Start metadata-only local iterator.
 * Sort iterators' outputs.
 * Computes diff between local and remote iterator.
 * Recover keys provided by diff using bulk API.
"""

import sys
import logging as log

from itertools import chain, izip
from collections import defaultdict

from recover.range import IdRange, RecoveryRange
from recover.route import RouteList
from recover.misc import format_id, split_host_port
from recover.iterator import Iterator
from recover.time import Time

# TODO: change me before BETA
sys.path.insert(0, "bindings/python/")
import elliptics

log.getLogger()

def setup_elliptics(log_file, log_level):
    """
    Connects to elliptics cloud
    """
    log.info("Creating node using: log_file: {0}, log_level: {1}".format(log_file, log_level))

    log.debug('Creating config')
    cfg = elliptics.Config()
    cfg.config.wait_timeout = 60

    log.debug('Creating logger')
    elog = elliptics.Logger(log_file, int(log_level))

    log.debug('Creating node')
    node = elliptics.Node(elog, cfg)
    node.add_remote(host, port)

    log.debug("Creating session")
    session = elliptics.Session(node)
    session.add_groups(groups)
    return node, session

def get_ranges(routes, host, group_id):
    """
    For each record in RouteList create 1 or 2 RecoveryRange(s)
    Returns list of RecoveryRange`s
    TODO: Tests!

    :param routes: RouteList object
    :param group_id: integer that represents hash ring id
    """
    ranges = []
    for i, route in enumerate(routes):
        key, node = routes[i]
        prev_ekey, prev_node = routes[i - 1]
        if key.group_id != group_id:
            log.debug("Skipped route: {0}, it belongs to group_id: {1}".format(
                route, key.group_id))
            continue
        if node == host:
            start = prev_ekey.id
            stop = key.id
            # If we wrapped around hash ring circle - split route into two distinct ranges
            if (stop < start):
                log.debug("Splitting range: {0}:{1}".format(
                    format_id(start), format_id(stop)))
                ranges.append(RecoveryRange(IdRange(IdRange.ID_MIN, stop), prev_node))
                ranges.append(RecoveryRange(IdRange(start, IdRange.ID_MAX), prev_node))
            else:
                ranges.append(RecoveryRange(IdRange(start, stop), prev_node))
    return ranges

def run_iterators(node=None, group=None, routes=None, ranges=None, timestamp=None, host=None, stats=None):
    """
    Runs local and remote iterators for each range.
    TODO: Can be parallel
    """
    results = []
    for iteration_range in ranges:
        stats['iteration_total'] += 2
        try:
            timestamp_range = timestamp.to_etime(), Time.time_max().to_etime()

            local_key = iteration_range.id_range.start
            local_eid = elliptics.Id(local_key, 0, 0)
            local_result = Iterator(node, group).start(
                eid=local_eid,
                timestamp_range=timestamp_range,
                key_range=iteration_range.id_range,
            )
            stats['iteration_local'] += 1

            remote_eid = routes.filter_by_host(host)[0].key
            remote_result = Iterator(node, group).start(
                eid=remote_eid,
                timestamp_range=timestamp_range,
                key_range=iteration_range.id_range,
            )
            stats['iteration_remote'] += 1
            results.append((local_result, remote_result))
        except Exception as e:
            log.error("Iteration failed for: {0}@{1}: {2}".format(
                iteration_range.id_range, iteration_range.host, repr(e)))
            stats['iteration_failed'] += 1
    return results

def sort(results, stats):
    """
    Runs sort routine for all iterator result
    TODO: Can be parallel
    """
    sorted_results = []
    for local, remote in results:
        stats['sort_total'] += 2
        if not (local.status and remote.status):
            log.debug("Sort skipped because local or remote iterator failed")
            stats['sort_skipped'] += 1
            continue
        try:
            assert local.id_range == remote.id_range, "Local range must equal remote range"
            local.container.sort()
            remote.container.sort()
            sorted_results.append((local, remote))
        except Exception as e:
            log.error("Sort of {0} failed: {1}".format(local.id_range, e))
            stats['sort_failed'] += 1
    return sorted_results

def diff(results, stats):
    """
    Compute differences between local and remote results.
    TODO: Can be parallel
    """
    results = []
    # XXX:
    return results

def recover(diffs, stats):
    """
    Recovers difference between remote and local data.
    TODO: Can be parallel
    """
    for diff in diffs:
        for i, record in enumerate(diff):
            pass # XXX:
    return True

def print_stats(stats):
    """
    Output statistics about recovery process.
    TODO: Add different output formats
    """
    from pprint import pprint
    print
    print '=' * 80
    print "Statistics for groups: {0}".format(stats['groups'].keys())
    print '=' * 80
    for group in stats['groups']:
        print "Group {0} stats:".format(group)
        print '+' * 80
        for k, v in stats['groups'][group].iteritems():
            align = 80 - 2 - len(k)
            if align < 0:
                align = 0
            print '{0}: {1:>{2}}'.format(k, v, align)
        print '+' * 80
    print

def main(node, session, host, groups, timestamp):
    """
    XXX:
    """
    stats = defaultdict(dict)
    result = True
    for group in groups:
        log.warning("Processing group: {0}".format(group))
        group_stats = defaultdict(int)
        stats['groups'][group] = group_stats

        log.warning("Searching for ranges that '{0}' stole".format(host, group))
        routes = RouteList(session.get_routes())
        log.debug("Total routes: {0}".format(len(routes)))

        ranges = get_ranges(routes, host, group)
        log.debug("Recovery ranges: {0}".format(len(ranges)))
        if not ranges:
            log.warning("No ranges to recover in group: {0}".format(group))
            continue
        # We should not run iterators on ourselves
        assert all(node != host for _, node in ranges)

        log.warning("Running iterators against: {0} range(s)".format(len(ranges)))
        iterator_results = run_iterators(
            node=node,
            group=group,
            routes=routes,
            ranges=ranges,
            timestamp=timestamp,
            host=host,
            stats=group_stats,
        )
        assert len(ranges) >= len(iterator_results)
        log.warning("Finished iteration of: {0} range(s)".format(len(iterator_results)))

        log.warning("Sorting iterators' data")
        sorted_results = sort(iterator_results, group_stats)
        assert len(iterator_results) >= len(sorted_results)
        log.warning("Sorted successfully: {0} result(s)".format(len(sorted_results)))

        log.warning("Computing diff local vs remote")
        diff_results = diff(sorted_results, group_stats)
        log.warning("Computed differences: {0} diff(s)".format(len(diff_results)))

        log.warning("Recovering diffs")
        result &= recover(diff_results, group_stats)
        log.warning("Recovery finished, setting result to: {0}".format(result))
    return stats, result

if __name__ == '__main__':
    from optparse import OptionParser

    parser = OptionParser()
    parser.add_option("-l", "--log", dest="elliptics_log", default='/dev/stderr', metavar="FILE",
                      help="use file as log [default %default]")
    parser.add_option("-L", "--log-level", action="store", dest="elliptics_log_level", default="1",
                      help="Elliptics client verbosity [default: %default]")
    parser.add_option("-r", "--remote", action="store", dest="elliptics_remote", default="127.0.0.1:1025",
                      help="Elliptics node address [default: %default]")
    parser.add_option("-g", "--groups", action="store_const", dest="elliptics_groups", default="2",
                      help="Comma separated list of groups [default: %default]")
    parser.add_option("-t", "--timestamp", action="store", dest="timestamp", default="0",
                      help="Recover keys created/modified since [default: %default]")
    parser.add_option("-d", "--debug", action="store_true", dest="debug", default=False,
                      help="Enable debug output [default: %default]")
    # TODO: Add quiet option to not output statistics
    (options, args) = parser.parse_args()

    if options.debug:
        log.getLogger().setLevel(log.DEBUG)

    if (args):
        raise RuntimeError("Passed garbage: '{0}'".format(args))

    try:
        host, port = split_host_port(options.elliptics_remote)
    except Exception as e:
        raise ValueError("Can't parse host:port: '{0}': {1}".format(
            options.elliptics_remote, repr(e)))
    log.info("Using host:port: {0}:{1}".format(host, port))

    try:
        groups = map(int, options.elliptics_groups.split(','))
    except Exception as e:
        raise ValueError("Can't parse grouplist: '{0}': {1}".format(
            options.elliptics_groups, repr(e)))
    log.info("Using grouplist: {0}".format(groups))

    try:
        timestamp = Time.from_epoch(options.timestamp)
    except Exception as e:
        raise ValueError("Can't parse timestamp: '{0}': {1}".format(
            options.timestamp, repr(e)))
    log.info("Using timestamp: {0}".format(timestamp))

    try:
        log_level = int(options.elliptics_log_level)
    except Exception as e:
        raise ValueError("Can't parse log_level: '{0}': {1}".format(
            options.log_level, repr(e)))
    log.info("Using elliptics client log level: {0}".format(timestamp))

    node, session = setup_elliptics(options.elliptics_log, log_level)
    stats, result = main(node, session, options.elliptics_remote, groups, timestamp)
    print_stats(stats)

    exit(not result)
