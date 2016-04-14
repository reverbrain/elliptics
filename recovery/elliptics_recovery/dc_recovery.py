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
import errno

from elliptics_recovery.utils.misc import elliptics_create_node, RecoverStat, validate_index
from elliptics_recovery.utils.misc import INDEX_MAGIC_NUMBER_LENGTH, load_key_data, WindowedRecovery
from elliptics_recovery.dc_server_send import ServerSendRecovery

import elliptics
from elliptics import Address
from elliptics.log import formatter, convert_elliptics_log_level

log = logging.getLogger()


class KeyRecover(object):
    def __init__(self, ctx, key, key_infos, missed_groups, node, callback):
        self.ctx = ctx
        self.complete = threading.Event()
        self.callback = callback
        self.stats = RecoverStat()
        self.key = key
        self.key_flags = 0
        self.key_infos = key_infos
        self.diff_groups = []
        self.missed_groups = list(missed_groups)

        self.read_session = elliptics.Session(node)
        self.read_session.trace_id = ctx.trace_id
        self.read_session.set_filter(elliptics.filters.all)

        self.write_session = elliptics.Session(node)
        self.write_session.trace_id = ctx.trace_id
        self.write_session.set_checker(elliptics.checkers.all)

        self.remove_session = elliptics.Session(node)
        self.remove_session.trace_id = ctx.trace_id
        self.remove_session.set_checker(elliptics.checkers.all)

        self.result = False
        self.attempt = 0

        log.debug("Recovering key: {0} from nonempty groups: {1} and missed groups: {2}"
                  .format(repr(self.key), [k.group_id for k in self.key_infos], self.missed_groups))
        self.run()

    def run(self):
        self.total_size = self.key_infos[0].size
        self.chunked = self.total_size > self.ctx.chunk_size
        self.recovered_size = 0

        same_ts = lambda lhs, rhs: lhs.timestamp == rhs.timestamp
        same_infos = [info for info in self.key_infos if same_ts(info, self.key_infos[0])]

        same_uncommitted = [info for info in same_infos if info.flags & elliptics.record_flags.uncommitted]
        if same_uncommitted == same_infos:
            # if all such keys have exceeded prepare timeout - remove all replicas
            # else skip recovering because the key is under writing and can be committed in nearest future.
            same_groups = [info.group_id for info in same_infos]
            if same_infos[0].timestamp < self.ctx.prepare_timeout:
                self.remove_session.groups = [info.group_id for info in self.key_infos]
                log.info('Key: {0} replicas with newest timestamp: {1} from groups: {2} are uncommitted. '
                         'Prepare timeout: {3} was exceeded. Remove all replicas from groups: {4}'
                         .format(self.key, same_infos[0].timestamp, same_groups, self.ctx.prepare_timeout,
                                 self.remove_session.groups))
                self.remove()
            else:
                log.info('Key: {0} replicas with newest timestamp: {1} from groups: {2} are uncommitted. '
                         'Prepare timeout: {3} was not exceeded. The key is written now. Skip it.'
                         .format(self.key, same_infos[0].timestamp, same_groups, self.ctx.prepare_timeout))
                self.stats.skipped += 1
                self.stop(True)
            return
        elif same_uncommitted != []:
            # removed incomplete replicas meta from same_infos
            # they will be corresponding as different and will be overwritten
            same_infos = [info for info in same_infos if info not in same_uncommitted]
            incomplete_groups = [info.group_id for info in same_uncommitted]
            same_groups = [info.group_id for info in same_infos]
            log.info('Key: {0} has uncommitted replicas in groups: {1} and completed replicas in groups: {2}.'
                     'The key will be recovered at groups with uncommitted replicas too.'
                     .format(self.key, incomplete_groups, same_groups))

        same_meta = lambda lhs, rhs: (lhs.timestamp, lhs.size, lhs.user_flags) == (rhs.timestamp, rhs.size, rhs.user_flags)
        same_infos = [info for info in self.key_infos if same_meta(info, same_infos[0])]
        self.key_flags = same_infos[0].flags

        self.same_groups = [info.group_id for info in same_infos]
        self.key_infos = [info for info in self.key_infos if info.group_id not in self.same_groups]
        self.diff_groups += [info.group_id for info in self.key_infos]
        self.diff_groups = list(set(self.diff_groups).difference(self.same_groups))

        if not self.diff_groups and not self.missed_groups:
            log.debug("Key: {0} already up-to-date in all groups: {1}".format(self.key, self.same_groups))
            self.stop(False)
            return

        log.debug("Try to recover key: {0} from groups: {1} to groups: {2}: diff groups: {3}, missed groups: {4}"
                  .format(self.key, self.same_groups, self.diff_groups + self.missed_groups,
                          self.diff_groups, self.missed_groups))

        self.read_session.groups = self.same_groups
        self.write_session.groups = self.diff_groups + self.missed_groups
        self.read()

    def stop(self, result):
        self.result = result
        log.debug("Finished recovering key: {0} with result: {1}".format(self.key, self.result))
        self.complete.set()
        self.callback(self.result, self.stats)

    def read(self):
        try:
            size = self.total_size
            log.debug("Reading key: {0} from groups: {1}, chunked: {2}"
                      .format(self.key, self.read_session.groups, self.chunked))
            if self.chunked:
                size = min(self.total_size - self.recovered_size, self.ctx.chunk_size)
            # do not check checksum for all but the first chunk
            if self.recovered_size != 0:
                if self.key_flags & elliptics.record_flags.chunked_csum:
                    # if record was checksummed by chunks there is no need to disable checksum verification
                    self.read_session.ioflags &= ~elliptics.io_flags.nocsum
                else:
                    self.read_session.ioflags |= elliptics.io_flags.nocsum
            else:
                # first read should be at least INDEX_MAGIC_NUMBER_LENGTH bytes
                size = min(self.total_size, max(size, INDEX_MAGIC_NUMBER_LENGTH))
                self.read_session.ioflags = 0

            log.debug("Reading key: {0} from groups: {1}, chunked: {2}, offset: {3}, size: {4}, total_size: {5}"
                      .format(self.key, self.read_session.groups, self.chunked,
                              self.recovered_size, size, self.total_size))

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

    def remove(self):
        if self.ctx.safe or self.ctx.dry_run:
            if self.ctx.safe:
                log.info("Safe mode is turned on. Skip removing key: {0}".format(repr(self.key)))
            else:
                log.info("Dry-run mode is turned on. Skip removing key: {0}.".format(repr(self.key)))
            self.stop(True)
        else:
            try:
                log.info("Removing key: {0} from group: {1}".format(self.key, self.remove_session.groups))
                remove_result = self.remove_session.remove(self.key)
                remove_result.connect(self.onremove)
            except:
                log.exception("Failed to remove key: {0} from groups: {1}".format(self.key, self.remove_session.groups))
                self.stop(False)

    def onread(self, results, error):
        try:
            if error.code:
                log.error("Failed to read key: {0} from groups: {1}: {2}".format(self.key, self.same_groups, error))
                self.stats.read_failed += len(results)
                if error.code == errno.ETIMEDOUT:
                    if self.attempt < self.ctx.attempts:
                        self.attempt += 1
                        old_timeout = self.read_session.timeout
                        self.read_session.timeout *= 2
                        log.error("Read has been timed out. Try to reread key: {0} from groups: {1}, attempt: {2}/{3} "
                                  "with increased timeout: {4}/{5}"
                                  .format(self.key, self.same_groups, self.attempt, self.ctx.attempts,
                                          self.read_session.timeout, old_timeout))
                        self.read()
                    else:
                        log.error("Read has been timed out {0} times, all {1} attemps are used. "
                                  "The key: {1} can't be recovery now. Skip it"
                                  .format(self.attempt, self.key))
                        self.stats.skipped += 1
                        self.stop(False)
                elif len(self.key_infos) > 1:
                    log.error("Key: {0} has available replicas in other groups. Try to recover the key from them"
                              .format(self.key))
                    self.diff_groups += self.read_session.groups
                    self.run()
                else:
                    log.error("Failed to read key: {0} from any available group. "
                              "This key can't be recovered now. Skip it"
                              .format(self.key))
                    self.stats.skipped += 1
                    self.stop(False)
                return

            self.stats.read_failed += len(results) - 1
            self.stats.read += 1
            self.stats.read_bytes += results[-1].size

            if self.recovered_size == 0:
                self.write_session.user_flags = results[-1].user_flags
                self.write_session.timestamp = results[-1].timestamp
                self.read_session.ioflags |= elliptics.io_flags.nocsum
                self.read_session.groups = [results[-1].group_id]
                self.key_flags = results[-1].record_flags
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
                    log.info("Retry to write key: {0} attempts: {1}/{2} increased timeout: {3}/{4}"
                             .format(repr(self.key), self.attempt, self.ctx.attempts,
                                     self.write_session.timeout, old_timeout))
                    self.stats.write_retries += 1
                    self.write()
                    return
                self.stop(False)
                return

            self.stats.write += len(results)
            if self.index_shard:
                self.stats.written_bytes += sum([r.size for r in results])
                log.debug("Recovered index shard at key: {0}".format(repr(self.key)))
                self.stop(True)
                return

            self.recovered_size += len(self.write_data)
            self.stats.written_bytes += len(self.write_data) * len(results)
            self.attempt = 0
            if self.recovered_size < self.total_size:
                self.read()
            else:
                log.debug("Key: {0} has been successfully copied to groups: {1}"
                          .format(repr(self.key), [r.group_id for r in results]))
                self.stop(True)
        except Exception as e:
            log.error("Failed to handle write result key: {0}: {1}, traceback: {2}"
                      .format(self.key, repr(e), traceback.format_exc()))
            self.stop(False)

    def onremove(self, results, error):
        try:
            if error.code:
                self.stats.remove_failed += 1
                log.error("Failed to remove key: {0}: from groups: {1}: {2}"
                          .format(self.key, self.remove_session.groups, error))
                if self.attempt < self.ctx.attempts:
                    old_timeout = self.remove_session.timeout
                    self.remove_session.timeout *= 2
                    self.attempt += 1
                    log.info("Retry to remove key: {0} attempts: {1}/{2} "
                             "increased timeout: {3}/{4}"
                             .format(repr(self.key),
                                     self.attempt, self.ctx.attempts,
                                     self.remove_session.timeout,
                                     old_timeout))
                    self.stats.remove_retries += 1
                    self.remove()
                    return
                self.stop(False)
                return

            self.stats.remove += len(results)
            self.stop(True)
        except:
            log.exception("Failed to handle remove result key: {0} from groups: {1}"
                          .format(self.key, self.remove_session.groups))

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

            # if all key_infos has the same timestamp and size and there is no missed groups -
            # skip key, it is already up-to-date in all groups
            same_meta = lambda lhs, rhs: (lhs.timestamp, lhs.size, lhs.user_flags) == (rhs.timestamp, rhs.size, rhs.user_flags)
            if same_meta(key_infos[0], key_infos[-1]) and not missed_groups:
                continue

            yield (key, key_infos, missed_groups)
        else:
            log.error("Invalid number of replicas for key: {0}: infos_count: {1}, groups_count: {2}"
                      .format(key, len(key_infos), len(groups)))


class WindowedDC(WindowedRecovery):
    def __init__(self, ctx, node):
        super(WindowedDC, self).__init__(ctx, ctx.stats['recover'])
        self.node = node
        ctx.rest_file.flush()
        self.keys = iterate_key(self.ctx.rest_file.name, self.ctx.groups)

    def run_one(self):
        try:
            key = None
            with self.lock:
                key = next(self.keys)
                self.recovers_in_progress += 1
            KeyRecover(self.ctx, *key, node=self.node, callback=self.callback)
            return True
        except StopIteration:
            last = False
            with self.lock:
                last = self.recovers_in_progress == 0
            if last:
                self.complete.set()
        return False


def cleanup(ctx):
    for f in ctx.bucket_files.itervalues():
        os.remove(f.name)
    del ctx.bucket_files
    os.remove(ctx.rest_file.name)
    del ctx.rest_file


def recover(ctx):
    stats = ctx.stats['recover']

    stats.timer('recover', 'started')
    node = elliptics_create_node(address=ctx.address,
                                 elog=elliptics.Logger(ctx.log_file, int(ctx.log_level)),
                                 wait_timeout=ctx.wait_timeout,
                                 net_thread_num=4,
                                 io_thread_num=24,
                                 remotes=ctx.remotes)
    result = ServerSendRecovery(ctx, node).recover()
    result &= WindowedDC(ctx, node).run()
    cleanup(ctx)
    stats.timer('recover', 'finished')

    return result


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

    ch = logging.StreamHandler(sys.stderr)
    ch.setFormatter(formatter)
    ch.setLevel(logging.WARNING)
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

        # FIXME: It may be inappropriate to use one log for both
        # elliptics library and python app, esp. in presence of auto-rotation
        fh = logging.FileHandler(ctx.log_file)
        fh.setFormatter(formatter)
        fh.setLevel(convert_elliptics_log_level(ctx.log_level))
        log.addHandler(fh)
        log.setLevel(convert_elliptics_log_level(ctx.log_level))

        if options.debug:
            log.setLevel(logging.DEBUG)
            ch.setLevel(logging.DEBUG)
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
