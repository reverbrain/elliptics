/*
 * 2011+ Copyright (c) Evgeniy Polyakov <zbr@ioremap.net>
 * Copyright 2013+ Ruslan Nigmatullin <euroelessar@yandex.ru>
 *
 * This file is part of Elliptics.
 *
 * Elliptics is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Elliptics is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with Elliptics.  If not, see <http://www.gnu.org/licenses/>.
 */


#include <errno.h>

#include "../bindings/cpp/session_indexes.hpp"
#include "../library/elliptics.h"
#include "../bindings/cpp/functional_p.h"
#include "local_session.h"

#include "elliptics/debug.hpp"

#include <mutex>

namespace {

#ifdef debug
#	undef debug
#endif

using namespace ioremap::elliptics;

struct update_indexes_functor : public std::enable_shared_from_this<update_indexes_functor>
{
	ELLIPTICS_DISABLE_COPY(update_indexes_functor)

	typedef std::shared_ptr<update_indexes_functor> ptr;

	update_indexes_functor(dnet_net_state *state, const dnet_cmd *cmd, const dnet_indexes_request *request)
		: sess(state->n), state(dnet_state_get(state)), cmd(*cmd), requests_in_progress(1), flags(request->flags)
	{
		this->cmd.flags |= DNET_FLAGS_MORE;

		request_id = request->id;

		size_t data_offset = 0;
		const char *data_start = reinterpret_cast<const char *>(request->entries);
		for (uint64_t i = 0; i < request->entries_count; ++i) {
			const dnet_indexes_request_entry *request_entry = reinterpret_cast<const dnet_indexes_request_entry *>(data_start + data_offset);

			raw_index_entry entry;
			entry.index = request_entry->id;
			entry.data = raw_data_pointer::copy(request_entry->data, request_entry->size);

			indexes.indexes.push_back(entry);

			data_offset += sizeof(dnet_indexes_request_entry) + request_entry->size;
		}

		std::sort(indexes.indexes.begin(), indexes.indexes.end(), raw_dnet_raw_id_less_than<>());
		indexes.shard_id = dnet_indexes_get_shard_id(state->n, reinterpret_cast<const dnet_raw_id*>(&cmd->id));
		indexes.shard_count = state->n->indexes_shard_count;
		if (!(flags & (DNET_INDEXES_FLAGS_UPDATE_ONLY | DNET_INDEXES_FLAGS_REMOVE_ONLY))) {
			msgpack::pack(buffer, indexes);
		}
	}

	~update_indexes_functor()
	{
		dnet_opunlock(state->n, &cmd.id);
		dnet_state_put(state);
	}

	/*
	 * update_indexes_functor::request_id holds key ID to add/remove from stored indexes
	 * update_indexes_functor::id holds key which contains list of all indexes which contain request_id
	 */

	local_session sess;
	dnet_net_state *state;
	dnet_cmd cmd;
	dnet_id request_id;
	// indexes to update
	raw_dnet_indexes indexes;

	msgpack::sbuffer buffer;
	// already updated indexes - they are read from storage and changed
	raw_dnet_indexes remote_indexes;
	std::vector<raw_index_entry> inserted_ids;
	std::vector<raw_index_entry> removed_ids;
	std::vector<dnet_indexes_reply_entry> result;

	std::atomic_int requests_in_progress;
	uint32_t flags;
	std::mutex requests_order_guard;

	static bool index_entry_less_than(const raw_index_entry &first, const raw_index_entry &second)
	{
		return memcmp(first.index.id, second.index.id, DNET_ID_SIZE) < 0;
	}

	static bool index_entry_equal(const raw_index_entry &first, const raw_index_entry &second)
	{
		return memcmp(first.index.id, second.index.id, DNET_ID_SIZE) == 0;
	}

	/*!
	 * Replace object's index cache (list of indexes given object is present in) by new table.
	 * Store them into @remote_indexes
	 */
	data_pointer convert_object_indexes(dnet_id *id, const data_pointer &data)
	{
		if (data.empty()) {
			remote_indexes.indexes.clear();
		} else {
			indexes_unpack(state->n, id, data, &remote_indexes, "convert_object_indexes");
		}

		if (flags & (DNET_INDEXES_FLAGS_UPDATE_ONLY | DNET_INDEXES_FLAGS_REMOVE_ONLY)) {
			// Merge both lists of object to one array,
			// remove object from remote_indexes.indexes that exists in indexes.indexes
			// and give it to the storage

			raw_dnet_indexes result;
			result.shard_count = indexes.shard_count;
			result.shard_id = indexes.shard_id;

			if (flags & DNET_INDEXES_FLAGS_UPDATE_ONLY) {
				result.indexes.reserve(indexes.indexes.size() + remote_indexes.indexes.size());
				result.indexes.insert(result.indexes.end(), indexes.indexes.begin(), indexes.indexes.end());
				result.indexes.insert(result.indexes.end(), remote_indexes.indexes.begin(), remote_indexes.indexes.end());

				std::inplace_merge(result.indexes.begin(), result.indexes.begin() + indexes.indexes.size(),
					result.indexes.end(), raw_dnet_raw_id_less_than<skip_data>());
				auto it = std::unique(result.indexes.begin(), result.indexes.end(), index_entry_equal);
				result.indexes.erase(it, result.indexes.end());
			} else if (flags & DNET_INDEXES_FLAGS_REMOVE_ONLY) {
				result.indexes.reserve(remote_indexes.indexes.size());
				std::set_difference(remote_indexes.indexes.begin(), remote_indexes.indexes.end(),
					indexes.indexes.begin(), indexes.indexes.end(),
					std::back_inserter(result.indexes), raw_dnet_raw_id_less_than<skip_data>());
			}

			msgpack::pack(buffer, result);
		}

		data_buffer tmp_buffer(DNET_INDEX_TABLE_MAGIC_SIZE + buffer.size());
		tmp_buffer.write(dnet_bswap64(DNET_INDEX_TABLE_MAGIC));
		tmp_buffer.write(buffer.data(), buffer.size());

		return std::move(tmp_buffer);
	}

	int process(bool *finished)
	{
		struct timeval start, end, convert_time, send_remote_time, insert_time, remove_time;
		long convert_usecs = -1;

		gettimeofday(&start, NULL);

		convert_time = send_remote_time = insert_time = remove_time = start;

		*finished = false;

		std::vector<size_t> local_inserted_ids;
		std::vector<size_t> local_removed_ids;

		size_t remote_inserted = 0;
		size_t remote_removed = 0;

		dnet_session *new_sess = NULL;
		int group_id = request_id.group_id;
		dnet_id base_id = request_id;

		int err = 0;
		data_pointer data = sess.read(cmd.id, &err);

		data_pointer new_data = convert_object_indexes(&cmd.id, data);

		if (data == new_data) {
			dnet_log(state->n, DNET_LOG_DEBUG, "INDEXES_UPDATE: data is the same\n");
			return complete(0, finished);
		}
		dnet_log(state->n, DNET_LOG_DEBUG, "INDEXES_UPDATE: data is different\n");

		const int shard_id = indexes.shard_id;

		err = sess.write(cmd.id, new_data);
		if (err)
			goto err_out_complete;

		gettimeofday(&convert_time, NULL);

#define DIFF(s, e) ((e).tv_sec - (s).tv_sec) * 1000000 + ((e).tv_usec - (s).tv_usec)

		convert_usecs = DIFF(start, convert_time);

		if (flags & (DNET_INDEXES_FLAGS_UPDATE_ONLY | DNET_INDEXES_FLAGS_REMOVE_ONLY)) {
			dnet_log(state->n, DNET_LOG_INFO, "%s: %s only finished:, convert-time: %ld usecs, err: %d\n",
				dnet_dump_id(&request_id),
				(flags & DNET_INDEXES_FLAGS_UPDATE_ONLY) ? "update" : "remove",
				convert_usecs, err);
			return complete(0, finished);
		}

		// We "insert" items also to update their data
		std::set_difference(indexes.indexes.begin(), indexes.indexes.end(),
			remote_indexes.indexes.begin(), remote_indexes.indexes.end(),
			std::back_inserter(inserted_ids), raw_dnet_raw_id_less_than<>());
		// Remove index entries which are not present in the new list of indexes
		std::set_difference(remote_indexes.indexes.begin(), remote_indexes.indexes.end(),
			indexes.indexes.begin(), indexes.indexes.end(),
			std::back_inserter(removed_ids), raw_dnet_raw_id_less_than<skip_data>());

		if (inserted_ids.empty() && removed_ids.empty()) {
			return complete(0, finished);
		}

		dnet_indexes_reply_entry result_entry;
		memset(&result_entry, 0, sizeof(result_entry));

		new_sess = dnet_session_create(state->n);
		dnet_session_set_groups(new_sess, &group_id, 1);

		/*
		 * Some indexes are stored on other servers,
		 * so we should send the request through network
		 */
		dnet_raw_id tmp_entry_id;
		for (size_t i = 0; i < inserted_ids.size(); ++i) {
			const auto &entry = inserted_ids[i];

			dnet_indexes_transform_index_id(state->n, &entry.index, &tmp_entry_id, shard_id);

			memcpy(base_id.id, tmp_entry_id.id, sizeof(base_id.id));

			dnet_net_state *index_state = dnet_state_get_first(state->n, &base_id);

			if (index_state) {
				remote_inserted++;
				int err = send_remote(new_sess, tmp_entry_id, entry.data, DNET_INDEXES_FLAGS_INTERNAL_INSERT);
				if (err)
					goto err_out_complete;
			} else {
				local_inserted_ids.push_back(i);
			}
		}

		for (size_t i = 0; i < removed_ids.size(); ++i) {
			const auto &entry = removed_ids[i];

			dnet_indexes_transform_index_id(state->n, &entry.index, &tmp_entry_id, shard_id);

			memcpy(base_id.id, tmp_entry_id.id, sizeof(base_id.id));

			dnet_net_state *index_state = dnet_state_get_first(state->n, &base_id);

			if (index_state) {
				remote_removed++;
				int err = send_remote(new_sess, tmp_entry_id, entry.data, DNET_INDEXES_FLAGS_INTERNAL_REMOVE);
				if (err)
					goto err_out_complete;
			} else {
				local_removed_ids.push_back(i);
			}
		}

		gettimeofday(&send_remote_time, NULL);
		dnet_session_destroy(new_sess);

		/*
		 * Iterate over all indexes and update those which changed.
		 * 'Changed' here means we want to either put or remove
		 * update_indexes_functor::request_id to/from given index
		 */
		for (size_t i = 0; i < local_inserted_ids.size(); ++i) {
			const auto &entry = inserted_ids[local_inserted_ids[i]];

			dnet_indexes_transform_index_id(state->n, &entry.index, &tmp_entry_id, shard_id);

			err = sess.update_index_internal(request_id, tmp_entry_id, entry.data, DNET_INDEXES_FLAGS_INTERNAL_INSERT);

			result_entry.status = err;
			result_entry.id = tmp_entry_id;
			result.push_back(result_entry);

			if (err)
				goto err_out_complete;
		}
		gettimeofday(&insert_time, NULL);

		for (size_t i = 0; i < local_removed_ids.size(); ++i) {
			const auto &entry = removed_ids[local_removed_ids[i]];

			dnet_indexes_transform_index_id(state->n, &entry.index, &tmp_entry_id, shard_id);

			err = sess.update_index_internal(request_id, tmp_entry_id, entry.data, DNET_INDEXES_FLAGS_INTERNAL_REMOVE);

			result_entry.status = err;
			result_entry.id = tmp_entry_id;
			result.push_back(result_entry);

			if (err)
				goto err_out_complete;
		}
		gettimeofday(&remove_time, NULL);

err_out_complete:
		err = complete(err, finished);

		gettimeofday(&end, NULL);

		long total_usecs = DIFF(start, end);
		long send_remote_usecs = DIFF(convert_time, send_remote_time);
		long insert_usecs = DIFF(send_remote_time, insert_time);
		long remove_usecs = DIFF(insert_time, remove_time);

		dnet_log(state->n, DNET_LOG_INFO, "%s: updated indexes: local-inserted: %zd, local-removed: %zd, "
				"remote-inserted: %zd, remote-removed: %zd, "
				"convert-time: %ld, send-remote-time: %ld, insert-time: %ld, remove-time: %ld, total-time: %ld usecs, err: %d\n",
				dnet_dump_id(&request_id), local_inserted_ids.size(), local_removed_ids.size(),
				remote_inserted, remote_removed,
				convert_usecs, send_remote_usecs, insert_usecs, remove_usecs, total_usecs, err);

		return err;
	}

	struct scope_data
	{
		ELLIPTICS_DISABLE_COPY(scope_data)

		scope_data(const ptr &functor) : functor(functor)
		{
		}

		ptr functor;
	};

	int send_remote(dnet_session *sess, const dnet_raw_id &index, const raw_data_pointer &data, uint32_t action)
	{
		data_buffer buffer(sizeof(dnet_indexes_request) + sizeof(dnet_indexes_request_entry) + data.size);

		dnet_indexes_request request;
		memset(&request, 0, sizeof(request));

		request.id = request_id;
		request.entries_count = 1;
		request.shard_id = indexes.shard_id;
		request.shard_count = indexes.shard_count;

		buffer.write(request);

		dnet_indexes_request_entry entry;
		memset(&entry, 0, sizeof(entry));

		entry.id = index;
		entry.size = data.size;
		entry.flags = action;

		buffer.write(entry);

		if (data.size > 0) {
			buffer.write(static_cast<const char *>(data.data), data.size);
		}

		data_pointer datap = std::move(buffer);

		dnet_trans_control control;
		memset(&control, 0, sizeof(control));

		control.cflags = DNET_FLAGS_NEED_ACK;
		control.cmd = DNET_CMD_INDEXES_INTERNAL;
		memcpy(control.id.id, index.id, sizeof(control.id.id));
		control.id.group_id = request_id.group_id;
		control.size = datap.size();
		control.data = datap.data();
		control.priv = new scope_data(shared_from_this());
		control.complete = on_reply_received;

		++requests_in_progress;

		int err = dnet_trans_alloc_send(sess, &control);

		if (err) {
			--requests_in_progress;
		}

		return err;
	}

	static int on_reply_received(dnet_net_state *st, dnet_cmd *cmd, void *priv)
	{
		scope_data *scope = reinterpret_cast<scope_data *>(priv);

		if (is_trans_destroyed(st, cmd)) {
			std::lock_guard<std::mutex> lock(scope->functor->requests_order_guard);

			if (0 == --scope->functor->requests_in_progress) {
				dnet_send_ack(scope->functor->state, &scope->functor->cmd, cmd->status, 0);
			}

			delete scope;
		} else {
			if (cmd->status || cmd->size) {
				std::lock_guard<std::mutex> lock(scope->functor->requests_order_guard);

				scope->functor->cmd.status = 0;
				dnet_send_reply(scope->functor->state, &scope->functor->cmd, cmd->data, cmd->size, 1);
			}
		}

		return 0;
	}

	int complete(int err, bool *finished)
	{
		data_buffer buffer(sizeof(dnet_indexes_reply) + result.size() * sizeof(dnet_indexes_reply_entry));

		dnet_indexes_reply reply;
		memset(&reply, 0, sizeof(reply));

		reply.entries_count = result.size();

		buffer.write(reply);

		for (size_t i = 0; i < result.size(); ++i) {
			buffer.write(result[i]);
		}

		data_pointer data = std::move(buffer);

		{
			std::lock_guard<std::mutex> lock(requests_order_guard);

			*finished = (0 == --requests_in_progress);
			cmd.status = 0;

			bool more = *finished && !err;

			if (!more) {
				cmd.flags &= (DNET_FLAGS_NEED_ACK | DNET_FLAGS_MORE);
			}

			dnet_send_reply(state, &cmd, data.data(), data.size(), more);
		}

		return err;
	}
};

/*!
 * Update data-object table for certain secondary index.
 *
 * @index_data is what client provided
 * @data is what was downloaded from the storage
 */
data_pointer convert_index_table(dnet_node *node, dnet_id *cmd_id, const dnet_indexes_request *request,
	const data_pointer &index_data, const data_pointer &data, uint32_t action)
{
	elliptics_timer timer;

	raw_dnet_indexes indexes;
	if (!data.empty())
		indexes_unpack(node, cmd_id, data, &indexes, "convert_index_table");

	const int64_t timer_unpack = timer.restart();

	// Construct index entry
	raw_index_entry request_index;
	memcpy(request_index.index.id, request->id.id, sizeof(request_index.index.id));
	request_index.data.data = index_data.data();
	request_index.data.size = index_data.size();

	auto it = std::lower_bound(indexes.indexes.begin(), indexes.indexes.end(), request_index);

	const int64_t timer_lower_bound = timer.restart();

	if (it != indexes.indexes.end() && it->index == request_index.index) {
		// It's already there
		if (action == DNET_INDEXES_FLAGS_INTERNAL_INSERT) {
			if (it->data == request_index.data) {
				const int64_t timer_compare = timer.restart();
				DNET_DUMP_ID_LEN(id_str, cmd_id, DNET_DUMP_NUM);
				typedef long long int lld;
				dnet_log(node, DNET_LOG_INFO, "INDEXES_INTERNAL: convert: id: %s, data size: %zu, new data size: %zu,"
					 "unpack: %lld ms, lower_bound: %lld ms, compare: %lld ms\n",
					 id_str, data.size(), data.size(), lld(timer_unpack), lld(timer_lower_bound),
					 lld(timer_compare));
				// All's ok, keep it untouched
				return data;
			} else {
				// Data is not correct, replace it by new one
				it->data = request_index.data;
			}
		} else {
			// Anyway, destroy it
			indexes.indexes.erase(it);
		}
	} else {
		// Index is not created yet
		if (action == DNET_INDEXES_FLAGS_INTERNAL_INSERT) {
			// Just insert it
			indexes.indexes.insert(it, 1, request_index);
		} else {
			const int64_t timer_compare = timer.restart();
			DNET_DUMP_ID_LEN(id_str, cmd_id, DNET_DUMP_NUM);
			typedef long long int lld;
			dnet_log(node, DNET_LOG_INFO, "INDEXES_INTERNAL: convert: id: %s, data size: %zu, new data size: %zu,"
				 "unpack: %lld ms, lower_bound: %lld ms, compare: %lld ms\n",
				 id_str, data.size(), data.size(), lld(timer_unpack), lld(timer_lower_bound),
				 lld(timer_compare));
			// All's ok, keep it untouched
			return data;
		}
	}

	const int64_t timer_update = timer.restart();

	indexes.shard_id = request->shard_id;
	indexes.shard_count = request->shard_count;

	msgpack::sbuffer buffer;
	msgpack::pack(&buffer, indexes);

	const int64_t timer_pack = timer.restart();

	data_buffer new_buffer(DNET_INDEX_TABLE_MAGIC_SIZE + buffer.size());
	new_buffer.write(dnet_bswap64(DNET_INDEX_TABLE_MAGIC));
	new_buffer.write(buffer.data(), buffer.size());

	const int64_t timer_write = timer.restart();

	DNET_DUMP_ID_LEN(id_str, cmd_id, DNET_DUMP_NUM);
	typedef long long int lld;
	dnet_log(node, DNET_LOG_INFO, "INDEXES_INTERNAL: convert: id: %s, data size: %zu, new data size: %zu,"
		 "unpack: %lld ms, lower_bound: %lld ms, update: %lld ms, pack: %lld ms, write: %lld ms\n",
		 id_str, data.size(), new_buffer.size(), lld(timer_unpack), lld(timer_lower_bound),
		 lld(timer_update), lld(timer_pack), lld(timer_write));

	return std::move(new_buffer);
}

int process_internal_indexes_entry(dnet_node *node, const dnet_indexes_request &request, dnet_indexes_request_entry &entry)
{
	elliptics_timer timer;

	local_session sess(node);

	dnet_id id;
	memset(&id, 0, sizeof(id));
	memcpy(id.id, entry.id.id, DNET_ID_SIZE);

	const data_pointer entry_data = data_pointer::from_raw(entry.data, entry.size);

	if (node->log->log_level >= DNET_LOG_DEBUG) {
		char index_buffer[DNET_DUMP_NUM * 2 + 1];
		char object_buffer[DNET_DUMP_NUM * 2 + 1];

		dnet_log(node, DNET_LOG_DEBUG, "INDEXES_INTERNAL: index: %s, object: %s, flags: %u\n",
			dnet_dump_id_len_raw(entry.id.id, DNET_DUMP_NUM, index_buffer),
			dnet_dump_id_len_raw(request.id.id, DNET_DUMP_NUM, object_buffer),
			request.flags);
	}

	uint32_t action = entry.flags & (DNET_INDEXES_FLAGS_INTERNAL_INSERT
		| DNET_INDEXES_FLAGS_INTERNAL_REMOVE | DNET_INDEXES_FLAGS_INTERNAL_REMOVE_ALL);

	switch (action) {
		case DNET_INDEXES_FLAGS_INTERNAL_INSERT:
		case DNET_INDEXES_FLAGS_INTERNAL_REMOVE:
			break;
		case DNET_INDEXES_FLAGS_INTERNAL_REMOVE_ALL: {
			const int64_t timer_checks = timer.restart();
			int err = sess.remove(id);
			const int64_t timer_remove = timer.restart();

			DNET_DUMP_ID_LEN(id_str, &id, DNET_DUMP_NUM);
			typedef long long int lld;
			dnet_log(node, DNET_LOG_INFO, "INDEXES_INTERNAL: id: %s, checks: %lld ms, remove: %lld ms\n",
				 id_str, lld(timer_checks), lld(timer_remove));

			return err;
		}
		default: {
			dnet_log(node, DNET_LOG_ERROR, "INDEXES_INTERNAL: invalid flags: 0x%llx\n",
				static_cast<unsigned long long>(entry.flags));
			return -EINVAL;
		}
	}

	const int64_t timer_checks = timer.restart();

	int err = 0;
	data_pointer data = sess.read(id, &err);
	const int64_t timer_read = timer.restart();

	data_pointer new_data = convert_index_table(node, &id, &request, entry_data, data, action);
	const int64_t timer_convert = timer.restart();

	const bool data_equal = data == new_data;

	const int64_t timer_compare = timer.restart();

	int64_t timer_write = 0;

	if (data_equal) {
		dnet_log(node, DNET_LOG_DEBUG, "INDEXES_INTERNAL: data is the same\n");
		err = 0;
	} else {
		dnet_log(node, DNET_LOG_DEBUG, "INDEXES_INTERNAL: data is different\n");
		err = sess.write(id, new_data);
		timer_write = timer.restart();
	}

	DNET_DUMP_ID_LEN(id_str, &id, DNET_DUMP_NUM);
	typedef long long int lld;
	dnet_log(node, DNET_LOG_INFO, "INDEXES_INTERNAL: id: %s, data size: %zu, new data size: %zu, checks: %lld ms, "
		 "read: %lld ms, convert: %lld ms, compare: %lld ms, write: %lld ms\n",
		 id_str, data.size(), new_data.size(), lld(timer_checks), lld(timer_read),
		 lld(timer_convert), lld(timer_compare), lld(timer_write));

	return err;
}

int process_internal_indexes(dnet_net_state *state, dnet_cmd *cmd, dnet_indexes_request *request)
{
	if (request->entries_count == 0) {
		return -EINVAL;
	}

	data_buffer buffer(sizeof(dnet_indexes_reply) + request->entries_count * sizeof(dnet_indexes_reply_entry));

	dnet_indexes_reply reply;
	memset(&reply, 0, sizeof(reply));

	reply.entries_count = request->entries_count;

	buffer.write(reply);

	dnet_indexes_reply_entry reply_entry;
	memset(&reply_entry, 0, sizeof(reply_entry));

	int err = -1;

	for (uint64_t i = 0; i < request->entries_count; ++i) {
		dnet_indexes_request_entry &entry = request->entries[i];
		int ret = process_internal_indexes_entry(state->n, *request, entry);

		reply_entry.id = entry.id;
		reply_entry.status = ret;

		buffer.write(reply_entry);

		if (!ret) {
			err = 0;
		} else if (err == -1) {
			err = ret;
		}
	}

	if (!err) {
		data_pointer reply_data = std::move(buffer);

		cmd->flags &= (DNET_FLAGS_NEED_ACK | DNET_FLAGS_MORE);

		dnet_send_reply(state, cmd, reply_data.data(), reply_data.size(), 0);
		return 0;
	}

	return err;
}

int process_find_indexes(dnet_net_state *state, dnet_cmd *cmd, const dnet_id &request_id, dnet_indexes_request *request, bool more)
{
	local_session sess(state->n);

	const bool intersection = request->flags & DNET_INDEXES_FLAGS_INTERSECT;
	const bool unite = request->flags & DNET_INDEXES_FLAGS_UNITE;

	dnet_log(state->n, DNET_LOG_DEBUG, "INDEXES_FIND: indexes count: %u, flags: %llu\n",
		 (unsigned) request->entries_count, (unsigned long long) request->flags);

	if ((intersection && unite) || !(intersection || unite)) {
		return -EINVAL;
	}

	std::vector<raw_find_indexes_result_entry> result;
	std::vector<data_pointer> data_cache;

	std::map<dnet_raw_id, size_t, raw_dnet_raw_id_less_than<> > result_map;

	raw_dnet_indexes tmp;

	int err = -1;
	dnet_id id = request_id;

	size_t data_offset = 0;
	char *data_start = reinterpret_cast<char *>(request->entries);
	for (uint64_t i = 0; i < request->entries_count; ++i) {
		dnet_indexes_request_entry &request_entry = *reinterpret_cast<dnet_indexes_request_entry *>(data_start + data_offset);
		data_offset += sizeof(dnet_indexes_request_entry) + request_entry.size;

		memcpy(id.id, request_entry.id.id, sizeof(id.id));

		int ret = 0;
		data_pointer data = sess.read(id, &ret);
		data_cache.push_back(data);

		if (ret) {
			dnet_log(state->n, DNET_LOG_DEBUG, "%s: INDEXES_FIND, err: %d\n",
				 dnet_dump_id(&id), ret);
		}

		if (ret && unite) {
			if (err == -1)
				err = ret;
			continue;
		} else if (ret && intersection) {
			return ret;
		}
		err = 0;

		tmp.indexes.clear();
		indexes_unpack(state->n, &id, data, &tmp, "process_find_indexes");

		if (unite) {
			for (size_t j = 0; j < tmp.indexes.size(); ++j) {
				const auto &entry = tmp.indexes[j];

				auto it = result_map.find(entry.index);
				if (it == result_map.end()) {
					it = result_map.insert(std::make_pair(entry.index, result.size())).first;
					result.resize(result.size() + 1);
					result.back().id = entry.index;
				}

				raw_index_entry result_entry = { request_entry.id, entry.data };
				result[it->second].indexes.push_back(result_entry);
			}
		} else if (intersection && i == 0) {
			result.resize(tmp.indexes.size());
			for (size_t j = 0; j < tmp.indexes.size(); ++j) {
				auto &entry = result[j];
				entry.id = tmp.indexes[j].index;
				raw_index_entry result_entry = { request_entry.id, tmp.indexes[j].data };
				entry.indexes.push_back(result_entry);
			}
		} else if (intersection) {
			// Remove all objects from result, which are not presented for this index
			auto it = std::set_intersection(result.begin(), result.end(),
				tmp.indexes.begin(), tmp.indexes.end(),
				result.begin(),
				raw_dnet_raw_id_less_than<skip_data>());
			result.resize(it - result.begin());

			// Remove all objects from this index, which are not presented in result
			std::set_intersection(tmp.indexes.begin(), tmp.indexes.end(),
				result.begin(), result.end(),
				tmp.indexes.begin(),
				raw_dnet_raw_id_less_than<skip_data>());

			// As lists contain othe same objects - it's possible to add index data by one cycle
			auto jt = tmp.indexes.begin();
			for (auto kt = result.begin(); kt != result.end(); ++kt, ++jt) {
				raw_index_entry result_entry = { request_entry.id, jt->data };
				kt->indexes.push_back(result_entry);
			}
		}
	}

	if (err != 0)
		return err;

	dnet_log(state->n, DNET_LOG_DEBUG, "%s: INDEXES_FIND: result of find: %zu objects\n",
		dnet_dump_id(&id), result.size());

	msgpack::sbuffer buffer;
	msgpack::pack(&buffer, result);

	if (!more) {
		/*
		 * Unset NEED_ACK flag if and only if it is the last reply.
		 * We have to send positive reply in such case, also we don't want to send
		 * useless acknowledge packet.
		 */
		cmd->flags &= ~DNET_FLAGS_NEED_ACK;
	}
	dnet_cmd cmd_copy = *cmd;
	dnet_setup_id(&cmd_copy.id, cmd->id.group_id, request_id.id);
	dnet_send_reply(state, &cmd_copy, buffer.data(), buffer.size(), more);

	return err;
}

}

int dnet_indexes_init(struct dnet_node *, struct dnet_config *)
{
	return 0;
}

void dnet_indexes_cleanup(struct dnet_node *)
{
}

int dnet_process_indexes(dnet_net_state *st, dnet_cmd *cmd, void *data)
{
	dnet_indexes_request *request = static_cast<dnet_indexes_request*>(data);
	int err = -ENOTSUP;

	switch (cmd->cmd) {
		case DNET_CMD_INDEXES_UPDATE: {
			// We are able only update, set or remove in one shot
			if ((request->flags & DNET_INDEXES_FLAGS_UPDATE_ONLY) && (request->flags & DNET_INDEXES_FLAGS_REMOVE_ONLY)) {
				err = -EINVAL;
				break;
			}

			auto functor = std::make_shared<update_indexes_functor>(st, cmd, request);

			bool finished = false;

			err = functor->process(&finished);

			if (!(finished && !err)) {
				// Do not send final ACK, it will be sent when all indexes are fully updated

				// Mark command as no-lock, so that lock will not be released in dnet_process_cmd_raw()
				// Lock will be releaseed when indexes are fully updated
				cmd->flags |= DNET_FLAGS_NOLOCK;

				cmd->flags &= ~DNET_FLAGS_NEED_ACK;
			}
		}
			break;
		case DNET_CMD_INDEXES_INTERNAL:
			err = process_internal_indexes(st, cmd, request);
			break;
		case DNET_CMD_INDEXES_FIND: {
			bool first = true;

			err = -1;

			while (request) {
				bool more = (request->flags & DNET_INDEXES_FLAGS_MORE);
				int ret = process_find_indexes(st, cmd, first ? cmd->id : request->id, request, more);
				first = false;

				if (err == -1)
					err = ret;
				else if (!ret)
					err = ret;

				if (!more) {
					break;
				}

				char *raw_data = reinterpret_cast<char *>(request + 1);
				for (size_t i = 0; i < request->entries_count; ++i) {
					auto entry = reinterpret_cast<dnet_indexes_request_entry *>(raw_data);
					raw_data += sizeof(*entry) + entry->size;
				}
				request = reinterpret_cast<dnet_indexes_request *>(raw_data);
			}
			break;
		}
		default:
			break;
	}


	return err;
}
