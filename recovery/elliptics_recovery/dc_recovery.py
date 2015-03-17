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

import sys
import logging
import threading
import os
import traceback

from elliptics_recovery.utils.misc import elliptics_create_node, RecoverStat, validate_index, INDEX_MAGIC_NUMBER_LENGTH
from elliptics_recovery.utils.misc import load_key_data

import elliptics
from elliptics import Address

log = logging.getLogger()


class KeyRecover(object):
    def __init__(self, ctx, key, key_infos, missed_groups, node):
        self.ctx = ctx
        self.complete = threading.Event()
        self.stats = RecoverStat()
        self.key = key
        self.key_infos = key_infos
        self.diff_groups = []
        self.missed_groups = list(missed_groups)

        self.read_session = elliptics.Session(node)
        self.read_session.set_filter(elliptics.filters.all)
        self.write_session = elliptics.Session(node)
        self.write_session.set_checker(elliptics.checkers.all)
        self.result = False
        self.attempt = 0

        log.debug("Recovering key: {0} from nonempty groups: {1} and missed groups: {2}"
                  .format(repr(self.key), [k.group_id for k in self.key_infos], self.missed_groups))
        self.run()

    def run(self):
        self.total_size = self.key_infos[0].size
        self.chunked = self.total_size > self.ctx.chunk_size
        self.recovered_size = 0
        self.same_groups = [k.group_id for k in self.key_infos if (k.timestamp, k.size) == (self.key_infos[0].timestamp, self.key_infos[0].size)]
        self.key_infos = [k for k in self.key_infos if k.group_id not in self.same_groups]
        self.diff_groups += [k.group_id for k in self.key_infos]
        self.diff_groups = list(set(self.diff_groups).difference(self.same_groups))
        if not self.diff_groups and not self.missed_groups:
            log.debug("Key: {0} already up-to-date in all groups: {1}".format(self.key, self.same_groups))
            self.stop(False)
            return

        log.debug("Try to recover key: {0} from groups: {1} to groups: {2}: diff groups: {3}, missed groups: {4}"
                  .format(self.key, self.same_groups, self.diff_groups + self.missed_groups, self.diff_groups, self.missed_groups))

        self.read_session.groups = self.same_groups
        self.write_session.groups = self.diff_groups + self.missed_groups
        self.read()

    def stop(self, result):
        self.result = result
        log.debug("Finished recovering key: {0} with result: {1}".format(self.key, self.result))
        self.complete.set()

    def read(self):
        size = 0
        try:
            log.debug("Reading key: {0} from groups: {1}, chunked: {2}"
                      .format(self.key, self.read_session.groups, self.chunked))
            if self.chunked:
                size = min(self.total_size - self.recovered_size, self.ctx.chunk_size)
            if self.recovered_size != 0:
                self.read_session.ioflags != elliptics.io_flags.nocsum
            else:
                #first read should be at least INDEX_MAGIC_NUMBER_LENGTH bytes
                size = min(self.total_size, max(size, INDEX_MAGIC_NUMBER_LENGTH))
            log.debug("Reading key: {0} from groups: {1}, chunked: {2}, offset: {3}, size: {4}, total_size: {5}"
                      .format(self.key, self.read_session.groups, self.chunked, self.recovered_size, size, self.total_size))

            # do not check checksum for all but the first chunk
            if self.recovered_size != 0:
                self.read_session.ioflags = elliptics.io_flags.nocsum
            else:
                self.read_session.ioflags = 0
            read_result = self.read_session.read_data(self.key,
                                                      offset=self.recovered_size,
                                                      size=size)
            read_result.connect(self.onread)
        except Exception as e:
            log.error("Read key: {0} by offset: {1} and size: {2} raised exception: {3}, traceback: {4}"
                      .format(self.key, self.recovered_size, size, repr(e), traceback.format_exc()))
            self.stop(False)

    def write(self):
        try:
            if self.index_shard:
                merge_groups = self.diff_groups + self.same_groups
                write_groups = merge_groups + self.missed_groups
                log.debug("Merging index shard: {0} from groups: {1} and writting it to groups: {2}"
                          .format(repr(self.key), merge_groups, write_groups))
                write_result = self.write_session.merge_indexes(self.key, merge_groups, write_groups)
            else:
                log.debug("Writing key: {0} to groups: {1}"
                          .format(repr(self.key), self.diff_groups + self.missed_groups))
                params = {'key': self.key,
                          'data': self.write_data,
                          'remote_offset': self.recovered_size}
                if self.chunked:
                    if self.recovered_size == 0:
                        params['psize'] = self.total_size
                        log.debug("Write_prepare key: {0} to groups: {1}, remote_offset: {2}, write_size: {3}, prepare_size: {4}"
                                  .format(params['key'], self.write_session.groups, params['remote_offset'], len(params['data']), params['psize']))
                        write_result = self.write_session.write_prepare(**params)
                    elif self.recovered_size + len(params['data']) < self.total_size:
                        log.debug("Write_plain key: {0} to groups: {1}, remote_offset: {2}, write_size: {3}, total_size: {4}"
                                  .format(params['key'], self.write_session.groups, params['remote_offset'], len(params['data']), self.total_size))
                        write_result = self.write_session.write_plain(**params)
                    else:
                        params['csize'] = self.total_size
                        log.debug("Write_commit key: {0} to groups: {1}, remote_offset: {2}, write_size: {3}, commit_size: {4}"
                                  .format(params['key'], self.write_session.groups, params['remote_offset'], len(params['data']), params['csize']))
                        write_result = self.write_session.write_commit(**params)
                else:
                    params['offset'] = params.pop('remote_offset')
                    log.debug("Write_data key: {0} to groups: {1}, offset: {2}, write_size: {3}, total_size: {4}"
                              .format(params['key'], self.write_session.groups, params['offset'], len(params['data']), self.total_size))
                    write_result = self.write_session.write_data(**params)
            write_result.connect(self.onwrite)
        except Exception as e:
            log.error("Writing key: {0} raised exception: {1}, traceback: {2}"
                      .format(self.key, repr(e), traceback.format_exc()))
            self.stop(False)

    def onread(self, results, error):
        try:
            if error.code:
                log.error("Failed to read key: {0} from groups: {1}: {2}".format(self.key, self.same_groups, error))
                self.stats.read_failed += 1
                if error.code == 110 and self.attempt < self.ctx.attempts:
                    self.attempt += len(self.read_session.groups)
                    log.debug("Read has been timed out. Try to reread key: {0} from groups: {1}, attempt: {2}/{3}"
                              .format(self.key, self.same_groups, self.attempt, self.ctx.attempts))
                    self.read()
                elif len(self.key_infos) > 1:
                    self.stats.read_failed += len(self.read_session.groups)
                    self.diff_groups += self.read_session.groups
                    self.run()
                else:
                    log.error("Failed to read key: {0} from any available group. This key couldn't be recovered now.".format(self.key))
                    self.stop(False)
                return

            self.stats.read += 1
            self.stats.read_bytes += results[-1].size

            if self.recovered_size == 0:
                self.write_session.user_flags = results[-1].user_flags
                self.write_session.timestamp = results[-1].timestamp
                if self.total_size != results[-1].total_size:
                    self.total_size = results[-1].total_size
                    self.chunked = self.total_size > self.ctx.chunk_size
            self.attempt = 0

            if self.chunked and len(results) > 1:
                self.missed_groups += [r.group_id for r in results if r.error.code]

            if validate_index(results[-1]) and self.diff_groups:
                self.index_shard = True
                log.debug("Index has been found in key: {0}".format(repr(self.key)))
            else:
                log.debug("Regular object has been found in key: {0}. Copy it from groups: {1} to groups: {2}"
                          .format(repr(self.key), self.same_groups, self.write_session.groups))
                self.index_shard = False
                self.write_data = results[-1].data
            self.write()
        except Exception as e:
            log.error("Failed to handle origin key: {0}, exception: {1}, traceback: {2}"
                      .format(self.key, repr(e), traceback.format_exc()))
            self.stop(False)

    def onwrite(self, results, error):
        try:
            if error.code:
                self.stats.write_failed += 1
                log.error("Failed to write key: {0}: to groups: {1}: {2}"
                          .format(self.key, self.write_session.groups, error))
                if self.attempt < self.ctx.attempts:
                    old_timeout = self.write_session.timeout
                    self.write_session.timeout *= 2
                    self.attempt += 1
                    log.debug("Retry to write key: {0} attempts: {1}/{2} "
                              "increased timeout: {3}/{4}"
                              .format(repr(self.key),
                                      self.attempt, self.ctx.attempts,
                                      self.write_session.timeout,
                                      old_timeout))
                    self.stats.write_failed += 1
                    self.write()
                    return
                self.stats.write_failed += 1
                self.stop(False)
                return

            self.stats.write += len(results)
            self.stats.written_bytes += sum([r.size for r in results])
            if self.index_shard:
                log.debug("Recovered index shard at key: {0}".format(repr(self.key)))
                self.stop(True)
                return

            self.recovered_size += len(self.write_data)
            self.attempt = 0
            if self.recovered_size < self.total_size:
                self.read()
            else:
                log.debug("Key: {0} has been successfully copied to groups: {1}".format(repr(self.key), [r.group_id for r in results]))
                self.stop(True)
        except Exception as e:
            log.error("Failed to handle write result key: {0}: {1}, traceback: {2}"
                      .format(self.key, repr(e), traceback.format_exc()))
            self.stop(False)

    def wait(self):
        if not self.complete.is_set():
            self.complete.wait()

    def succeeded(self):
        self.wait()
        return self.result


def iterate_key(filepath, groups):
    '''
    Iterates key and sort each key key_infos by timestamp and size
    '''
    groups = set(groups)
    for key, key_infos in load_key_data(filepath):
        if len(key_infos) + len(groups) > 1:
            key_infos = sorted(key_infos, key=lambda x: (x.timestamp, x.size), reverse=True)
            missed_groups = tuple(groups.difference([k.group_id for k in key_infos]))

            #if all key_infos has the same timestamp and size and there is no missed groups - skip key, it is already up-to-date in all groups
            if (key_infos[0].timestamp, key_infos[0].size) == (key_infos[-1].timestamp, key_infos[-1].size) and not missed_groups:
                continue

            yield (key, key_infos, missed_groups)
        else:
            log.error("Invalid number of replicas for key: {0}: infos_count: {1}, groups_count: {2}".format(key, len(key_infos), len(groups)))


def recover(ctx):
    from itertools import islice
    import time
    ret = True
    stats = ctx.stats['recover']

    stats.timer('recover', 'started')

    it = iterate_key(ctx.merged_filename, ctx.groups)

    elog = elliptics.Logger(ctx.log_file, int(ctx.log_level))
    node = elliptics_create_node(address=ctx.address,
                                 elog=elog,
                                 wait_timeout=ctx.wait_timeout,
                                 net_thread_num=4,
                                 io_thread_num=1,
                                 remotes=ctx.remotes)
    processed_keys = 0
    start = time.time()
    while 1:
        batch = tuple(islice(it, ctx.batch_size))
        if not batch:
            break
        recovers = []
        rs = RecoverStat()
        for val in batch:
            rec = KeyRecover(ctx, *val, node=node)
            recovers.append(rec)
        successes, failures = 0, 0
        for r in recovers:
            r.wait()
            ret &= r.succeeded()
            rs += r.stats
            if r.succeeded():
                successes += 1
            else:
                failures += 1
        processed_keys += successes + failures
        rs.apply(stats)
        stats.counter('recovered_keys', successes)
        ctx.stats.counter('recovered_keys', successes)
        stats.counter('recovered_keys', -failures)
        ctx.stats.counter('recovered_keys', -failures)
        stats.set_counter('recovery_speed', processed_keys / (time.time() - start))
    stats.timer('recover', 'finished')
    return ret


if __name__ == '__main__':
    from elliptics_recovery.ctx import Ctx
    from optparse import OptionParser
    parser = OptionParser()
    parser.usage = "%prog [options]"
    parser.description = __doc__
    parser.add_option("-i", "--merged-filename", dest="merged_filename",
                      default='merged_result', metavar="FILE",
                      help="Input file which contains information about keys "
                      "in groups [default: %default]")
    parser.add_option("-d", "--debug", action="store_true",
                      dest="debug", default=False,
                      help="Enable debug output [default: %default]")
    parser.add_option("-D", "--dir", dest="tmp_dir",
                      default='/var/tmp/dnet_recovery_%TYPE%', metavar="DIR",
                      help="Temporary directory for iterators' results "
                      "[default: %default]")
    parser.add_option("-l", "--log", dest="elliptics_log",
                      default='dnet_recovery.log', metavar="FILE",
                      help="Output log messages from library to file "
                      "[default: %default]")
    parser.add_option("-L", "--log-level", action="store",
                      dest="elliptics_log_level", default="1",
                      help="Elliptics client verbosity [default: %default]")
    parser.add_option("-w", "--wait-timeout", action="store",
                      dest="wait_timeout", default="3600",
                      help="[Wait timeout for elliptics operations "
                      "default: %default]")
    parser.add_option("-r", "--remote", action="store",
                      dest="elliptics_remote", default=None,
                      help="Elliptics node address [default: %default]")
    parser.add_option("-g", "--groups", action="store",
                      dest="elliptics_groups", default=None,
                      help="Comma separated list of groups [default: all]")
    parser.add_option("-b", "--batch-size", action="store",
                      dest="batch_size", default="1024",
                      help="Number of keys in read_bulk/write_bulk "
                      "batch [default: %default]")

    (options, args) = parser.parse_args()
    ctx = Ctx()

    log.setLevel(logging.DEBUG)
    formatter = logging.Formatter(
        fmt='%(asctime)-15s %(processName)s %(levelname)s %(message)s',
        datefmt='%d %b %y %H:%M:%S')

    ch = logging.StreamHandler(sys.stderr)
    ch.setFormatter(formatter)
    ch.setLevel(logging.INFO)
    log.addHandler(ch)

    if not os.path.exists(ctx.tmp_dir):
        try:
            os.makedirs(ctx.tmp_dir, 0755)
            log.warning("Created tmp directory: {0}".format(ctx.tmp_dir))
        except Exception as e:
            raise ValueError("Directory: {0} does not exist and could not be created: {1}, traceback: {2}"
                             .format(ctx.tmp_dir, repr(e), traceback.format_exc()))
    os.chdir(ctx.tmp_dir)

    try:
        ctx.log_file = os.path.join(ctx.tmp_dir, options.elliptics_log)
        ctx.log_level = int(options.elliptics_log_level)
        ctx.merged_filename = os.path.join(ctx.tmp_dir,
                                           options.merged_filename)

        ch.setLevel(logging.WARNING)
        if options.debug:
            ch.setLevel(logging.DEBUG)

        # FIXME: It may be inappropriate to use one log for both
        # elliptics library and python app, esp. in presence of auto-rotation
        fh = logging.FileHandler(ctx.log_file)
        fh.setFormatter(formatter)
        fh.setLevel(logging.DEBUG)
        log.addHandler(fh)
    except Exception as e:
        raise ValueError("Can't parse log_level: '{0}': {1}, traceback: {2}"
                         .format(options.elliptics_log_level, repr(e), traceback.format_exc()))
    log.info("Using elliptics client log level: {0}".format(ctx.log_level))

    if options.elliptics_remote is None:
        raise ValueError("Recovery address should be given (-r option).")
    try:
        ctx.address = Address.from_host_port_family(options.elliptics_remote)
    except Exception as e:
        raise ValueError("Can't parse host:port:family: '{0}': {1}, traceback: {2}"
                         .format(options.elliptics_remote, repr(e), traceback.format_exc()))
    log.info("Using host:port:family: {0}".format(ctx.address))

    try:
        if options.elliptics_groups:
            ctx.groups = map(int, options.elliptics_groups.split(','))
        else:
            ctx.groups = []
    except Exception as e:
        raise ValueError("Can't parse grouplist: '{0}': {1}, traceback: {2}"
                         .format(options.elliptics_groups, repr(e), traceback.format_exc()))

    try:
        ctx.batch_size = int(options.batch_size)
        if ctx.batch_size <= 0:
            raise ValueError("Batch size should be positive: {0}"
                             .format(ctx.batch_size))
    except Exception as e:
        raise ValueError("Can't parse batchsize: '{0}': {1}, traceback: {2}"
                         .format(options.batch_size, repr(e), traceback.format_exc()))
    log.info("Using batch_size: {0}".format(ctx.batch_size))

    try:
        ctx.wait_timeout = int(options.wait_timeout)
    except Exception as e:
        raise ValueError("Can't parse wait_timeout: '{0}': {1}, traceback: {2}"
                         .format(options.wait_timeout, repr(e), traceback.format_exc()))

    log.debug("Creating logger")
    elog = elliptics.Logger(ctx.log_file, int(ctx.log_level))

    result = recover(ctx)

    rc = int(not result)
    exit(rc)
