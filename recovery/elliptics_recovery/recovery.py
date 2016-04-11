# =============================================================================
# 2013+ Copyright (c) Kirill Smorodinnikov <shaitkir@gmail.com>
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

import os
import sys
import logging
import logging.handlers
import traceback
from multiprocessing import Pool
# from memory_profiler import profile

from elliptics_recovery.route import RouteList
from elliptics_recovery.etime import Time
from elliptics_recovery.utils.misc import elliptics_create_node, elliptics_create_session, worker_init
from elliptics_recovery.monitor import Monitor, ALLOWED_STAT_FORMATS
from elliptics_recovery.ctx import Ctx
from elliptics.log import convert_elliptics_log_level

import elliptics
from elliptics.log import formatter

log = logging.getLogger()
log.setLevel(logging.DEBUG)

ch = logging.StreamHandler(sys.stderr)
ch.setFormatter(formatter)
ch.setLevel(logging.WARNING)
log.addHandler(ch)

TYPE_MERGE = 'merge'
TYPE_DC = 'dc'
ALLOWED_TYPES = (TYPE_MERGE, TYPE_DC)

TMP_FILE_PREFIXES = ['iterator_', 'diff_', 'merge', 'stat']


def cleanup(path):
    for file_name in os.listdir(path):
        if not os.path.isfile(file_name):
            continue
        for prefix in TMP_FILE_PREFIXES:
            if file_name.startswith(prefix):
                log.debug("Cleanup: removing stale file: {0}".format(file_name))
                os.unlink(file_name)


def get_routes(ctx):
    log.debug('Requesting routes')

    log.debug("Creating logger")
    elog = elliptics.Logger(ctx.log_file, int(ctx.log_level))

    log.debug("Creating node")
    node = elliptics_create_node(address=ctx.address,
                                 elog=elog,
                                 wait_timeout=ctx.wait_timeout,
                                 remotes=ctx.remotes)

    log.debug("Creating session for: {0}".format(ctx.address))
    session = elliptics_create_session(node=node, group=0, trace_id=ctx.trace_id)

    log.debug("Parsing routing table")
    return RouteList.from_session(session)


# @profile
def main(options, args):
    if len(args) > 1:
        raise ValueError("Too many arguments passed: {0}, expected: 1".format(len(args)))
    elif len(args) == 0:
        raise ValueError("Please specify one of following types: {0}".format(ALLOWED_TYPES))

    if args[0].lower() not in ALLOWED_TYPES:
        raise ValueError("Unknown type: '{0}', allowed: {1}".format(args[0], ALLOWED_TYPES))
    recovery_type = args[0].lower()

    log.info("Initializing context")
    ctx = Ctx()
    ctx.dry_run = options.dry_run
    ctx.safe = options.safe
    ctx.one_node = bool(options.one_node)
    ctx.custom_recover = options.custom_recover
    ctx.no_meta = options.no_meta and (options.timestamp is None)
    ctx.no_server_send = options.no_server_send
    ctx.user_flags_set = frozenset(options.user_flags_set)

    try:
        ctx.trace_id = int(options.trace_id, 16)
    except Exception as e:
        raise ValueError("Can't parse -T/--trace-id: '{0}': {1}, traceback: {2}"
                         .format(options.trace_id, repr(e), traceback.format_exc()))

    if ctx.custom_recover:
        ctx.custom_recover = os.path.abspath(ctx.custom_recover)

    if options.dump_file:
        ctx.dump_file = os.path.abspath(options.dump_file)
        if not os.path.exists(ctx.dump_file):
            raise ValueError('Dump file:`{}` does not exsists'.format(options.dump_file))
    else:
        ctx.dump_file = None

    try:
        ctx.chunk_size = int(options.chunk_size)
    except Exception, e:
        raise ValueError("Can't parse chunk_size: '{0}': {1}, traceback: {2}"
                         .format(options.chunk_size, repr(e), traceback.format_exc()))

    ctx.tmp_dir = options.tmp_dir.replace('%TYPE%', recovery_type)
    if not os.path.exists(ctx.tmp_dir):
        try:
            os.makedirs(ctx.tmp_dir, 0755)
            log.warning("Created tmp directory: {0}".format(ctx.tmp_dir))
        except Exception as e:
            raise ValueError("Directory: {0} does not exist and could not be created: {1}, traceback: {2}"
                             .format(ctx.tmp_dir, repr(e), traceback.format_exc()))
    init_dir = os.getcwd()
    os.chdir(ctx.tmp_dir)
    log.info("Using tmp directory: {0}".format(ctx.tmp_dir))

    try:
        ctx.log_file = os.path.join(ctx.tmp_dir, options.elliptics_log)
        try:
            ctx.log_level = int(options.elliptics_log_level)
        except:
            ctx.log_level = options.elliptics_log_level

        if isinstance(ctx.log_level, int):
            ctx.log_level = elliptics.log_level.values[ctx.log_level]
        else:
            ctx.log_level = elliptics.log_level.names[ctx.log_level]

        ctx.dump_keys = options.dump_keys

        # FIXME: It may be inappropriate to use one log for both
        # elliptics library and python app, esp. in presence of auto-rotation
        fh = logging.FileHandler(ctx.log_file)
        fh.setFormatter(formatter)
        fh.setLevel(convert_elliptics_log_level(ctx.log_level))
        log.addHandler(fh)
        log.setLevel(convert_elliptics_log_level(ctx.log_level))

        if options.debug:
            ch.setLevel(logging.DEBUG)
            log.setLevel(logging.DEBUG)
    except Exception as e:
        raise ValueError("Can't parse log_level: '{0}': {1}, traceback: {2}"
                         .format(options.elliptics_log_level, repr(e), traceback.format_exc()))
    log.info("Using elliptics client log level: {0}".format(ctx.log_level))

    try:
        if options.lock:
            import fcntl
            ctx.lockfd = os.open(os.path.join(ctx.tmp_dir, options.lock), os.O_TRUNC | os.O_CREAT | os.O_RDWR)
            fcntl.flock(ctx.lockfd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            log.info("Using lock file: {0}".format(options.lock))
        else:
            log.info("Not using lock file")
    except Exception as e:
        raise RuntimeError("Can't grab lock on: '{0}': {1}, traceback: {2}"
                           .format(options.lock, repr(e), traceback.format_exc()))

    if not options.remotes and not ctx.one_node:
        raise ValueError("At least one Elliptics node address should be given (-r option or -o).")

    ctx.remotes = []
    for remote in options.remotes:
        try:
            ctx.remotes.append(elliptics.Address.from_host_port_family(remote))
        except Exception as e:
            raise ValueError("Can't parse host:port:family: '{0}': {1}, traceback: {2}"
                             .format(remote, repr(e), traceback.format_exc()))

    ctx.backend_id = None
    # if one_node mode is on then use his address as a main otherwise use first from remotes
    if ctx.one_node:
        try:
            ctx.address = elliptics.Address.from_host_port_family(options.one_node)
        except Exception as e:
            raise ValueError("Can't parse host:port:family: '{0}': {1}, traceback: {2}"
                             .format(remote, repr(e), traceback.format_exc()))
        try:
            if options.backend_id is not None:
                ctx.backend_id = int(options.backend_id)
        except Exception as e:
            raise ValueError("Can't parse backend_id: '{0}': {1}, traceback: {2}"
                             .format(options.backend_id, repr(e), traceback.format_exc()))
    elif ctx.remotes:
        ctx.address = ctx.remotes[0]
    log.info("Using host:port:family: {0}".format(ctx.address))

    try:
        if options.elliptics_groups:
            ctx.groups = map(int, options.elliptics_groups.split(','))
        else:
            ctx.groups = None
    except Exception as e:
        raise ValueError("Can't parse grouplist: '{0}': {1}, traceback: {2}"
                         .format(options.elliptics_groups, repr(e), traceback.format_exc()))
    if not ctx.groups:
        raise ValueError("No group was specified")
    log.info("Using group list: {0}".format(ctx.groups))

    try:
        if options.timestamp is None:
            options.timestamp = 0
        ctx.timestamp = Time.from_epoch(options.timestamp)
    except Exception:
        try:
            ctx.timestamp = Time.from_string(options.timestamp)
        except Exception as e:
            raise ValueError("Can't parse timestamp: '{0}': {1}, traceback: {2}"
                             .format(options.timestamp, repr(e), traceback.format_exc()))
    log.info("Using timestamp: {0}".format(ctx.timestamp))

    try:
        ctx.batch_size = int(options.batch_size)
        if ctx.batch_size <= 0:
            raise ValueError("Batch size should be positive: {0}".format(ctx.batch_size))
    except Exception as e:
        raise ValueError("Can't parse batchsize: '{0}': {1}, traceback: {2}"
                         .format(options.batch_size, repr(e), traceback.format_exc()))
    log.info("Using batch_size: {0}".format(ctx.batch_size))

    try:
        ctx.nprocess = int(options.nprocess)
        if ctx.nprocess <= 0:
            raise ValueError("Number of processes should be positive: {0}".format(ctx.nprocess))
    except Exception as e:
        raise ValueError("Can't parse nprocess: '{0}': {1}, traceback: {2}"
                         .format(options.nprocess, repr(e), traceback.format_exc()))

    try:
        ctx.attempts = int(options.attempts)
        if ctx.attempts <= 0:
            raise ValueError("Number of attempts should be positive: {0}".format(ctx.attempts))
    except Exception as e:
        raise ValueError("Can't parse attempts: '{0}': {1}, traceback: {2}"
                         .format(options.attempts, repr(e), traceback.format_exc()))

    ctx.stat_format = options.stat
    if ctx.stat_format not in ALLOWED_STAT_FORMATS:
        raise ValueError("Unknown statistics output format: '{0}'. Available formats are: {1}"
                         .format(ctx.stat_format, ALLOWED_STAT_FORMATS))

    try:
        ctx.monitor_port = int(options.monitor_port)
        if ctx.monitor_port:
            try:
                from socket import getfqdn

                base_url = 'http://{0}:{1}'.format(getfqdn(), ctx.monitor_port)
                log.warning("Stats can be monitored via: {0}/{1}".format(base_url, "stats.txt"))
                log.warning("Log can be viewed via: {0}/{1}".format(base_url, options.elliptics_log))
            except Exception:
                pass
    except Exception as e:
        raise ValueError("Can't parse monitor_port: '{0}': {1}, traceback: {2}"
                         .format(options.monitor_port, repr(e), traceback.format_exc()))

    try:
        ctx.wait_timeout = int(options.wait_timeout)
    except Exception as e:
        raise ValueError("Can't parse wait_timeout: '{0}': {1}, traceback: {2}"
                         .format(options.wait_timeout, repr(e), traceback.format_exc()))

    try:
        ctx.prepare_timeout = Time.from_epoch(options.prepare_timeout)
    except Exception as e:
        try:
            ctx.prepare_timeout = Time.from_string(options.prepare_timeout).time
        except Exception as e:
            raise ValueError("Can't parse prepare_timeout: '{0}': {1}, traceback: {2}"
                             .format(options.wait_timeout, repr(e), traceback.format_exc()))
    log.info("Using timeout: {0} for uncommitted records".format(ctx.prepare_timeout))

    try:
        log.info("Starting cleanup...")
        cleanup(ctx.tmp_dir)
    except Exception as e:
        log.error("Cleanup failed: {0}, traceback: {1}"
                  .format(repr(e), traceback.format_exc()))

    log.info("Initializing monitor")
    monitor = Monitor(ctx, ctx.monitor_port)
    ctx.stats = monitor.stats

    log.debug("Using following context:\n{0}".format(ctx))

    ctx.routes = get_routes(ctx)
    log.debug("Parsed routing table:\n{0}".format(ctx.routes))
    if not ctx.routes:
        raise RuntimeError("No routes was parsed from session")
    log.debug("Total routes: {0}".format(len(ctx.routes)))

    if len(ctx.groups) == 0:
        ctx.groups = ctx.routes.groups()
        log.info("No groups specified: using all available groups: {0}".format(ctx.groups))

    try:
        log.info("Creating pool of processes: %d", ctx.nprocess)
        ctx.pool = Pool(processes=ctx.nprocess, initializer=worker_init)
        if recovery_type == TYPE_MERGE:
            if ctx.dump_file:
                from elliptics_recovery.types.merge import dump_main
                result = dump_main(ctx)
            else:
                from elliptics_recovery.types.merge import main
                result = main(ctx)
        elif recovery_type == TYPE_DC:
            if ctx.dump_file:
                from elliptics_recovery.types.dc import dump_main
                result = dump_main(ctx)
            else:
                from elliptics_recovery.types.dc import main
                result = main(ctx)
        ctx.pool.close()
        ctx.pool.terminate()
        ctx.pool.join()
    except Exception as e:
        log.error("Recovering failed: %s, traceback: %s", repr(e), traceback.format_exc())
        ctx.pool.terminate()
        ctx.pool.join()
        result = False

    rc = int(not result)
    log.info("Finished with rc: {0}".format(rc))
    ctx.stats.counter('result', rc)

    if options.no_exit:
        raw_input("Press Enter to exit!")

    monitor.shutdown()
    monitor.update()
    monitor.print_stat()
    os.chdir(init_dir)
    return rc


def run(args=None):
    from optparse import OptionParser

    parser = OptionParser()
    parser.usage = "%prog [options] TYPE"
    parser.description = __doc__
    parser.add_option("-b", "--batch-size", action="store", dest="batch_size", default="1024",
                      help="Number of keys in read_bulk/write_bulk batch [default: %default]")
    parser.add_option("-d", "--debug", action="store_true", dest="debug", default=False,
                      help="Enable debug output [default: %default]")
    parser.add_option("-D", "--dir", dest="tmp_dir", default='/var/tmp/dnet_recovery_%TYPE%', metavar="DIR",
                      help="Temporary directory for iterators' results [default: %default]")
    parser.add_option("-g", "--groups", action="store", dest="elliptics_groups", default=None,
                      help="Comma separated list of groups [default: all]")
    parser.add_option("-k", "--lock", dest="lock", default='dnet_recovery.lock', metavar="LOCKFILE",
                      help="Lock file used for recovery [default: %default]")
    parser.add_option("-l", "--log", dest="elliptics_log", default='dnet_recovery.log', metavar="FILE",
                      help="Output log messages from library to file [default: %default]")
    parser.add_option("-L", "--log-level", action="store", dest="elliptics_log_level",
                      default=elliptics.log_level.notice,
                      help="Elliptics client verbosity [default: %default]")
    parser.add_option("-n", "--nprocess", action="store", dest="nprocess", default="1",
                      help="Number of subprocesses [default: %default]")
    parser.add_option("-N", "--dry-run", action="store_true", dest="dry_run", default=False,
                      help="Enable test mode: only count diffs without recovering [default: %default]")
    parser.add_option("-r", "--remote", action="append", dest="remotes", default=[],
                      help="Elliptics node address")
    parser.add_option("-s", "--stat", action="store", dest="stat", default="text",
                      help="Statistics output format: {0} [default: %default]".format("/".join(ALLOWED_STAT_FORMATS)))
    parser.add_option("-S", "--safe", action="store_true", dest="safe", default=False,
                      help="Do not remove recovered keys after merge [default: %default]")
    parser.add_option("-t", "--time", action="store", dest="timestamp", default=None,
                      help="Recover keys modified since `time`. "
                           "Can be specified as timestamp or as time difference"
                           "e.g.: `1368940603`, `12h`, `1d`, or `4w` [default: %default]")
    parser.add_option("-e", "--no-exit", action="store_true", dest="no_exit", default=False,
                      help="Will be waiting for user input at the finish.")
    parser.add_option("-m", "--monitor-port", action="store", dest="monitor_port", default=0,
                      help="Enable remote monitoring on provided port [default: disabled]")
    parser.add_option("-w", "--wait-timeout", action="store", dest="wait_timeout", default="3600",
                      help="[Wait timeout for elliptics operations default: %default]")
    parser.add_option("-a", "--attemps", action="store", dest="attempts", default=1,
                      help="Number of attempts to recover one key")
    parser.add_option("-o", "--one-node", action="store", dest="one_node", default=None,
                      help="Elliptics node address that should be iterated/recovered [default: %default]")
    parser.add_option("-c", "--chunk-size", action='store', dest='chunk_size', default=1024 * 1024,
                      help="Size of chunk by which all object will be read and recovered [default: %default]")
    parser.add_option("-C", "--custom-recover", action="store", dest="custom_recover", default="",
                      help="Sets custom recover app which accepts file path and returns file path to filtered keys")
    parser.add_option("-f", '--dump-file', action='store', dest='dump_file', default='',
                      help='Sets dump file which contains hex ids of object that should be recovered')
    parser.add_option('-i', '--backend-id', action='store', dest='backend_id', default=None,
                      help='Specifies backend data on which should be recovered. IT WORKS ONLY WITH --one-node')
    parser.add_option("-u", "--dont-dump-keys", action="store_false", dest="dump_keys", default=True,
                      help="Disable dumping all iterated key [default: %default]")
    parser.add_option("-M", "--no-meta", action="store_true", dest="no_meta", default=False,
                      help="Recover data without meta. It is usefull only for services without data-rewriting because"
                      " with this option dnet_recovery will not check which replica of the key is newer"
                      " and will copy any replica of the key to missing groups.")
    parser.add_option('-p', '--prepare-timeout', action='store', dest='prepare_timeout', default='1d',
                      help='Timeout for uncommitted records (prepared, but not committed).'
                      'Records that exceeded this timeout will be removed. [default: %default]')
    parser.add_option('-T', '--trace-id', action='store', dest="trace_id", default='0',
                      help='Marks all recovery commands by trace_id at both recovery and server logs. This option accepts hex strings. [default: %default]')
    parser.add_option('-U', '--no-server-send', action="store", dest="no_server_send", default=False,
                      help='Do not use server-send for recovery. Disabling recovery via server-send useful if there is no network connection between groups')
    parser.add_option('--user-flags', action='append', dest='user_flags_set', default=[],
                      help='Recover key if at least one replica has user_flags from specified user_flags_set')
    return main(*parser.parse_args(args))
