import logging
import os
import errno
import time
from itertools import groupby

from elliptics_recovery.utils.misc import dump_key_data, load_key_data_from_file

import elliptics

log = logging.getLogger()


class BucketsManager(object):
    '''
    BucketsManager is a single repository of bucket files. It is used by ServerSendRecovery.
    '''
    def __init__(self, ctx):
        self.ctx = ctx
        self.bucket_index = -1
        self.buckets = dict()

    def get_next_bucket(self):
        '''
        Every call returns BucketKeys object in a round-robin manner.
        '''
        if not self.ctx.bucket_order:
            return None

        self.bucket_index = (self.bucket_index + 1) % len(self.ctx.bucket_order)
        group = self.ctx.bucket_order[self.bucket_index]
        log.info("Get next bucket: index: {0}, group: {1}, bucket_order: {2}".format(self.bucket_index, group, self.ctx.bucket_order))
        return self._get_bucket(group)

    def on_server_send_fail(self, key, key_infos, next_group):
        if next_group >= 0:
            b = self._get_bucket(next_group)
            b.add_key(key, key_infos)
        else:
            self.move_to_rest_bucket(key, key_infos)

    def move_to_rest_bucket(self, key, key_infos):
        '''
        Dumps key to 'rest_keys' bucket.
        '''
        log.info("Moving key to rest keys bucket: {0}".format(key))
        key_data = (key, key_infos)
        dump_key_data(key_data, self.ctx.rest_file)

    def _get_bucket(self, group):
        '''
        Returns BucketKeys object for group_id == @group
        '''
        if group not in self.buckets:
            if group not in self.ctx.bucket_files:
                filename = os.path.join(self.ctx.tmp_dir, 'bucket_%d' % (group))
                self.ctx.bucket_files[group] = open(filename, 'wb+')
                self.ctx.bucket_order.append(group)
            self.buckets[group] = BucketKeys(self.ctx.bucket_files[group], group)
        return self.buckets[group]


class BucketKeys(object):
    '''
    BucketKeys provides simple container-like interface to a bucket file.
    '''
    def __init__(self, bucket_file, group):
        log.debug("Create bucket: group: {0}, bucket: {1}".format(group, bucket_file.name))
        self.bucket_file = bucket_file
        self.group = group

    def get_keys(self, max_keys_num):
        '''
        Yields bunch of keys from the bucket file.
        @max_keys_num defines max number of keys in the bunch.
        '''
        self.bucket_file.seek(0)
        for _, batch in groupby(enumerate(load_key_data_from_file(self.bucket_file)),
                                key=lambda x: x[0] / max_keys_num):
            yield [item[1] for item in batch]

    def get_group(self):
        return self.group

    def clear(self):
        '''
        Truncates bucket file.
        '''
        log.debug("Clear bucket: group: {0}, bucket: {1}".format(self.group, self.bucket_file.name))
        self.bucket_file.seek(0)
        self.bucket_file.truncate()

    def add_key(self, key, key_infos):
        '''
        Dumps key to the bucket file.
        '''
        log.debug("Append key to bucket: group: {0}, bucket: {1}".format(self.group, self.bucket_file.name))
        key_data = (key, key_infos)
        dump_key_data(key_data, self.bucket_file)


class ServerSendRecovery(object):
    '''
    ServerSendRecovery uses server_send operation for efficient recovering of small/medium keys.
    '''
    def __init__(self, ctx, node):
        self.ctx = ctx
        self.stats = ctx.stats['recover']
        self.node = node
        self.buckets = BucketsManager(ctx)

        self.session = elliptics.Session(node)
        self.session.trace_id = ctx.trace_id
        self.session.exceptions_policy = elliptics.exceptions_policy.no_exceptions
        self.session.timeout = 60

        self.remove_session = self.session.clone()
        self.remove_session.set_filter(elliptics.filters.all_final)

        self.result = True

        # next vars are used just for optimization
        self.groups_set = frozenset(ctx.groups)

    def recover(self):
        progress = True
        while progress:
            bucket = self.buckets.get_next_bucket()
            if bucket is None:
                break
            #bucket.external_sort_by_physical_order()
            group = bucket.get_group()
            progress = False
            for keys in bucket.get_keys(self.ctx.batch_size):
                progress = True
                self._server_send(keys, group)
            bucket.clear()
        return self.result

    def _server_send(self, keys, group):
        '''
        Recovers bunch of newest @keys from replica with group_id == @group to other replicas via server-send.
        '''
        log.info("Server-send bucket: source group: {0}, num keys: {1}".format(group, len(keys)))
        keys_bunch = dict() # remote_groups -> [list of newest keys]
        for key, key_infos in keys:
            unprocessed_key_infos = self._get_unprocessed_key_infos(key_infos, group)

            is_first_attempt = len(unprocessed_key_infos) == len(key_infos)
            if is_first_attempt and self._process_uncommited_keys(key, key_infos):
                continue

            if not self._can_use_server_send(unprocessed_key_infos):
                self.buckets.move_to_rest_bucket(key, key_infos)
                continue

            dest_groups = self._get_dest_groups(unprocessed_key_infos)
            index = frozenset(dest_groups)
            if index not in keys_bunch:
                keys_bunch[index] = []
            keys_bunch[index].append((key, key_infos))

        self.session.set_groups([group])

        for b in keys_bunch.iteritems():
            remote_groups = b[0]
            newest_keys = list()
            key_infos_map = dict()
            for key, key_infos in b[1]:
                log.debug("Prepare server-send key: {0}, group: {1}".format(key, key.group_id))
                newest_keys.append(key)
                key_infos_map[str(key)] = key_infos

            timeouted_keys = None
            for i in range(self.ctx.attempts):
                #for k in newest_keys:
                #    result = self.session.lookup(k).get()[0]
                #    log.debug("LOOKUP2: key: {0}, group: {1}, status: {2}".format(k, result.group_id, result.status))
                if newest_keys:
                    log.info("Server-send: group: {0}, remote_groups: {1}, num_keys: {2}".format(group, remote_groups, len(newest_keys)))
                    iterator = self.session.server_send(newest_keys, 0, remote_groups)
                    timeouted_keys, corrupted_keys = self._check_server_send_results(iterator, key_infos_map, group)
                    newest_keys = timeouted_keys
                    if corrupted_keys:
                        self._remove_corrupted_keys(corrupted_keys, [group])

            if timeouted_keys:
                self._on_server_send_timeout(timeouted_keys, key_infos_map, group)

    def _check_server_send_results(self, iterator, key_infos_map, group):
        '''
        Check result of remote sending for every key.
        Returns list of timeouted keys.
        '''
        start_time = time.time()
        recovers_in_progress = len(key_infos_map)

        timeouted_keys = []
        corrupted_keys = []
        index = -1
        for index, result in enumerate(iterator, 1):
            status = result.response.status
            self._update_stats(start_time, index, recovers_in_progress, status)

            if status < 0:
                key = result.response.key
                key_infos = key_infos_map[str(key)]
                self._on_server_send_fail(status, key, key_infos, timeouted_keys, corrupted_keys, group)
                continue
            log.debug("Recovered key: {0}, status {1}".format(result.response.key, status))

        if index < 0:
            log.error("Server-send operation failed: group: {0}".format(group))
            timeouted_keys = [elliptics.Id(k) for k in key_infos_map.iterkeys()]

        return timeouted_keys, corrupted_keys

    def _on_server_send_timeout(self, keys, key_infos_map, group):
        '''
        Moves keys to next bucket, if appropriate bucket meta is identical to current meta.
        '''
        same_meta = lambda lhs, rhs: (lhs.timestamp, lhs.size) == (rhs.timestamp, rhs.size)
        for key in keys:
            key_infos = key_infos_map[str(key)]
            filtered_key_infos = self._get_unprocessed_key_infos(key_infos, group)
            if len(filtered_key_infos) > 1:
                current_meta = filtered_key_infos[0]
                next_meta = filtered_key_infos[1]
                if same_meta(current_meta, next_meta):
                    self.buckets.on_server_send_fail(key, key_infos, next_meta.group_id)
                    continue
            self.result = False

    def _on_server_send_fail(self, status, key, key_infos, timeouted_keys, corrupted_keys, group):
        log.error("Failed to server-send key: {0}, group: {1}, error: {2}".format(key, group, status))

        if status in (-errno.ETIMEDOUT, -errno.ENXIO):
            timeouted_keys.append(key)
        else:
            if status == -errno.EILSEQ:
                corrupted_keys.append(key)
            next_group = self._get_next_group(key_infos, group)
            self.buckets.on_server_send_fail(key, key_infos, next_group)

    def _remove_corrupted_keys(self, keys, groups):
        '''
        Removes invalid keys with invalid checksum.
        '''
        if self.ctx.safe:
            return

        for attempt in range(self.ctx.attempts):
            if not keys:
                break

            self.remove_session.set_groups(groups)

            results = []
            for k in keys:
                result = self.remove_session.remove(k)
                results.append(result)

            timeouted_keys = []
            timeouted_groups = set()
            is_last_attempt = (attempt == self.ctx.attempts - 1)
            for i, r in enumerate(results):
                status = r.get()[0].status
                log.info("Removing corrupted key: {0}, status: {1}, last attempt: {2}".format(keys[i], status, is_last_attempt))
                if status == -errno.ETIMEDOUT:
                    timeouted_keys.append(keys[i])
                    timeouted_groups.add(keys[i].group_id)
            keys, groups = timeouted_keys, list(timeouted_groups)

    def _process_uncommited_keys(self, key, key_infos):
        same_ts = lambda lhs, rhs: lhs.timestamp == rhs.timestamp
        same_infos = [info for info in key_infos if same_ts(info, key_infos[0])]

        same_uncommitted = [info for info in same_infos if info.flags & elliptics.record_flags.uncommitted]
        has_uncommitted = len(same_uncommitted) > 0
        if same_uncommitted == same_infos:
            # if all such keys have exceeded prepare timeout - remove all replicas
            # else skip recovering because the key is under writing and can be committed in nearest future.
            same_groups = [info.group_id for info in same_infos]
            if same_infos[0].timestamp < self.ctx.prepare_timeout:
                groups = [info.group_id for info in key_infos]
                log.info('Key: {0} replicas with newest timestamp: {1} from groups: {2} are uncommitted. '
                         'Prepare timeout: {3} was exceeded. Remove all replicas from groups: {4}'
                         .format(key, same_infos[0].timestamp, same_groups, self.ctx.prepare_timeout, groups))
                self._remove_corrupted_keys([key], groups)
            else:
                log.info('Key: {0} replicas with newest timestamp: {1} from groups: {2} are uncommitted. '
                         'Prepare timeout: {3} was not exceeded. The key is written now. Skip it.'
                         .format(key, same_infos[0].timestamp, same_groups, self.ctx.prepare_timeout))
            return True
        elif has_uncommitted:
            # removed incomplete replicas meta from same_infos
            # they will be corresponding as different and will be overwritten
            same_infos = [info for info in same_infos if info not in same_uncommitted]
            incomplete_groups = [info.group_id for info in same_uncommitted]
            same_groups = [info.group_id for info in same_infos]
            log.info('Key: {0} has uncommitted replicas in groups: {1} and completed replicas in groups: {2}.'
                     'The key will be recovered at groups with uncommitted replicas too.'
                     .format(key, incomplete_groups, same_groups))

            committed_infos = [info for info in key_infos if info not in same_uncommitted]
            if committed_infos:
                key_infos = same_uncommitted + committed_infos
                next_group = committed_infos[0].group_id
                self.buckets.on_server_send_fail(key, key_infos, next_group)

        return has_uncommitted

    def _get_dest_groups(self, key_infos):
        '''
        Returns list of destination/remote groups to which key must be recovered.
        '''
        missed_groups = list(self.groups_set.difference([k.group_id for k in key_infos]))

        same_meta = lambda lhs, rhs: (lhs.timestamp, lhs.size) == (rhs.timestamp, rhs.size)
        diff_groups = [info.group_id for info in key_infos if not same_meta(info, key_infos[0])]

        missed_groups.extend(diff_groups)
        return missed_groups

    def _get_unprocessed_key_infos(self, original_key_infos, group):
        '''
        Each element of @original_key_infos describes key's metadata for a particular group.
        Recovery process successively iterates over elements of @original_key_infos.
        This method returns elements from @original_key_infos that were not processed by
        previous recovery iterations.
        '''
        for i, k in enumerate(original_key_infos):
            if k.group_id == group:
                return original_key_infos[i:]
        return []

    def _can_use_server_send(self, key_infos):
        return key_infos[0].size < self.ctx.chunk_size

    def _get_next_group(self, key_infos, group):
        '''
        Returns group_id among groups that hasn't been used for recovery yet.
        '''
        key_infos = self._get_unprocessed_key_infos(key_infos, group)
        if len(key_infos) > 1:
            return key_infos[1].group_id
        return -1

    def _update_stats(self, start_time, processed_keys, recovers_in_progress, status):
        speed = processed_keys / (time.time() - start_time)
        recovers_in_progress -= processed_keys
        self.stats.set_counter('recovery_speed', round(speed, 2))
        self.stats.set_counter('recovers_in_progress', recovers_in_progress)
        self.stats.counter('recovered_keys', 1 if status == 0 else -1)
        self.ctx.stats.counter('recovered_keys', 1 if status == 0 else -1)
