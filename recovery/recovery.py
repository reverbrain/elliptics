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
from recover.routes import RouteList
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

def process_ranges(routes, host, group_id):
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

def run_remote_iterators(node, group, ranges, timestamp):
    """
    Runs remote iterator per recovery range
    TODO: Make it parallel
    """
    results = []
    for recovery_range in ranges:
        results.append(Iterator(node, group).start(
            timestamp_range=(timestamp.to_etime(), Time.time_max().to_etime()),
            key_range=(recovery_range.id_range.start, recovery_range.id_range.stop),
        ))
    return results

def run_local_iterators(node, group, ranges, timestamp, host, remote_results):
    """
    Runs local iterator for each remote result that succeeded.
    """
    local_results = []
    for recovery_range, result in zip(ranges, remote_results):
        if not result.status:
            log.warning("Skipped local iterator for range: {0}".format(recovery_range))
            continue
        try:
            # XXX: For local iterator we must use `disk' itype
            local_results.append(Iterator(node, group).start(
                timestamp_range=(timestamp.to_etime(), Time.time_max().to_etime()),
                key_range=recovery_range.id_range,
            ))
        except Exception as e:
            log.error("Iteration failed for: {0}: {1}".format(recovery_range, repr(e)))
    return local_results

def sort_results(it):
    """
    Runs sort routine for all iterator result
    TODO: Can be parallel
    """
    for result in it:
        if result.status == 0:
            result.container.sort() # XXX: return code

def recover(it):
    """
    Recovers difference between remote and local data.
    """
    for remote, local in it:
        for i, result in enumerate(remote):
            pass # XXX:

def print_stats(stats):
    """
    Output statistics about recovery process.
    """
    from pprint import pprint
    pprint(stats)

def main(node, session, host, groups, timestamp):
    """
    XXX:
    """
    stats = defaultdict(dict)
    for group in groups:
        log.warning("Processing group: {0}".format(group))
        stats['groups'][group] = {}

        log.warning("Searching for ranges that '{0}' stole".format(host, group))
        routes = RouteList(session.get_routes())
        log.debug("Total routes: {0}".format(len(routes)))

        ranges = process_ranges(routes, host, group)
        log.debug("Recovery ranges: {0}".format(len(ranges)))
        if not ranges:
            log.warning("No ranges to recover in group: {0}".format(group))
            continue
        # We should not run iterators on ourselves
        assert all(node != host for _, node in ranges)

        log.warning("Running remote iterators against: {0} range(s)".format(len(ranges)))
        remote_results = run_remote_iterators(node, group, ranges, timestamp)
        assert len(ranges) == len(remote_results)
        successful = sum(1 for res in remote_results if res.status)
        log.warning("Finished successfully: {0} range(s)".format(successful))

        log.warning("Running local iterators against: {0} range(s)".format(len(ranges)))
        local_results = run_local_iterators(node, group, ranges, timestamp, host, remote_results)

        log.warning("Sorting iterators' data")
        sort_results(chain(remote_results, local_results))

        log.warning("Computing diff remote vs local and recover")
        recover(izip(remote_results, local_results))
    return stats, 0

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
    stats, exit_code = main(node, session, options.elliptics_remote, groups, timestamp)
    print_stats(stats)

    exit(exit_code)
