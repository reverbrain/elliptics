/*
 * 2011+ Copyright (c) Evgeniy Polyakov <zbr@ioremap.net>
 * All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include <errno.h>

#include "../library/elliptics.h"
#include "../bindings/cpp/functional_p.h"
#include "../bindings/cpp/session_indexes.hpp"

#include "elliptics/debug.hpp"

#include <mutex>

namespace {

#ifdef debug
#	undef debug
#endif
#define debug() if (1) {} else std::cerr

enum update_index_action {
	insert_data = 1,
	remove_data = 2
};

using namespace ioremap::elliptics;

#undef list_entry
#define list_entry(ptr, type, member) ({			\
	const list_head *__mptr = (ptr);	\
	(dnet_io_req *)( (char *)__mptr - offsetof(dnet_io_req, member) );})

#undef list_for_each_entry_safe
#define list_for_each_entry_safe(pos, n, head, member)			\
	for (pos = list_entry((head)->next, decltype(*pos), member),	\
		n = list_entry(pos->member.next, decltype(*pos), member);	\
	     &pos->member != (head); 					\
	     pos = n, n = list_entry(n->member.next, decltype(*n), member))

class local_session
{
	ELLIPTICS_DISABLE_COPY(local_session)

	public:
		local_session(dnet_node *node)
		{
			m_state = reinterpret_cast<dnet_net_state *>(malloc(sizeof(dnet_net_state)));
			if (!m_state)
				throw std::bad_alloc();

			dnet_addr addr;
			memset(&addr, 0, sizeof(addr));

			memset(m_state, 0, sizeof(dnet_net_state));

			m_state->need_exit = 1;
			m_state->write_s = -1;
			m_state->read_s = -1;

			dnet_state_micro_init(m_state, node, &addr, 0, noop_process);
			dnet_state_get(m_state);
		}

		~local_session()
		{
//			debug() << "refcnt: " << atomic_read(&m_state->refcnt) << std::endl;
			dnet_state_put(m_state);
			dnet_state_put(m_state);
		}

		data_pointer read(const dnet_id &id, int *errp)
		{
			dnet_io_attr io;
			memset(&io, 0, sizeof(io));

			memcpy(io.id, id.id, DNET_ID_SIZE);
			memcpy(io.parent, id.id, DNET_ID_SIZE);

			dnet_cmd cmd;
			memset(&cmd, 0, sizeof(cmd));

			cmd.id = id;
			cmd.cmd = DNET_CMD_READ;
			cmd.flags |= DNET_FLAGS_NOLOCK;
			cmd.size = sizeof(io);

			int err = dnet_process_cmd_raw(m_state, &cmd, &io);
			if (err) {
				debug() << __LINE__ << std::endl;
				clear_queue();
				*errp = err;
				return data_pointer();
			}

			struct dnet_io_req *r, *tmp;

			std::map<uint64_t, data_pointer> data_map;

			size_t total_size = 0;

			list_for_each_entry_safe(r, tmp, &m_state->send_list, req_entry) {
				debug() << "hsize: " << r->hsize << ", dsize: " << r->dsize << std::endl;

				dnet_cmd *req_cmd = reinterpret_cast<dnet_cmd *>(r->header ? r->header : r->data);

				debug() << "entry in list, status: " << req_cmd->status << std::endl;

				if (req_cmd->status) {
					*errp = req_cmd->status;
					clear_queue();
					return data_pointer();
				} else if (req_cmd->size) {
					dnet_io_attr *req_io = reinterpret_cast<dnet_io_attr *>(req_cmd + 1);

					data_pointer &data = data_map[req_io->offset];

					total_size -= data.size();

					if (r->data) {
						data = data_pointer::copy(r->data, r->dsize);
					} else {
						data = data_pointer::allocate(req_io->size);
						ssize_t read_res = pread(r->fd, data.data(), data.size(), r->local_offset);
						if (read_res == -1) {
							*errp = errno;
							clear_queue();
							return data_pointer();
						}
					}

					total_size += data.size();

					debug() << "entry in list, size: " << req_io->size << std::endl;
				}

//				list_del(&r->req_entry);
//				dnet_io_req_free(r);
			}

			clear_queue();

			data_buffer buffer(total_size);

			for (auto it = data_map.begin(); it != data_map.end(); ++it) {
				buffer.write(it->second.data<char>(), it->second.size());
			}

			return std::move(buffer);
		}

		int write(const dnet_id &id, const data_pointer &data)
		{
			return write(id, data.data<char>(), data.size());
		}

		int write(const dnet_id &id, const char *data, size_t size)
		{
			dnet_io_attr io;
			memset(&io, 0, sizeof(io));

			memcpy(io.id, id.id, DNET_ID_SIZE);
			memcpy(io.parent, id.id, DNET_ID_SIZE);
			io.flags |= DNET_IO_FLAGS_COMMIT;
			io.size = size;
			io.num = size;

			data_buffer buffer(sizeof(dnet_io_attr) + size);
			buffer.write(io);
			buffer.write(data, size);

			debug() << "going to write size: " << size << std::endl;

			data_pointer datap = std::move(buffer);

			dnet_cmd cmd;
			memset(&cmd, 0, sizeof(cmd));

			cmd.id = id;
			cmd.cmd = DNET_CMD_WRITE;
			cmd.flags |= DNET_FLAGS_NOLOCK;
			cmd.size = datap.size();

			int err = dnet_process_cmd_raw(m_state, &cmd, datap.data());

			clear_queue(&err);

			return err;
		}

		int update_index_internal(const dnet_id &id, const dnet_raw_id &index, const data_pointer &data, update_index_action action)
		{
			data_buffer buffer(sizeof(dnet_indexes_request) + sizeof(dnet_indexes_request_entry) + data.size());

			dnet_indexes_request request;
			dnet_indexes_request_entry entry;
			memset(&request, 0, sizeof(request));
			memset(&entry, 0, sizeof(entry));

			request.id = id;
			request.entries_count = 1;

			buffer.write(request);

			entry.id = index;
			entry.size = data.size();
			entry.flags |= action;

			buffer.write(entry);
			if (!data.empty()) {
				buffer.write(data.data<char>(), data.size());
			}

			data_pointer datap = std::move(buffer);

			dnet_cmd cmd;
			memset(&cmd, 0, sizeof(cmd));
			memcpy(cmd.id.id, index.id, sizeof(cmd.id.id));

			cmd.cmd = DNET_CMD_INDEXES_INTERNAL;
			cmd.size = datap.size();

			int err = dnet_process_cmd_raw(m_state, &cmd, datap.data());

			clear_queue(&err);

			return err;
		}

	private:
		struct io_req_deleter
		{
			void operator() (dnet_io_req *io)
			{
				dnet_io_req_free(io);
			}
		};

		typedef std::unique_ptr<dnet_io_req, io_req_deleter> dnet_io_req_ptr;

		void clear_queue(int *errp = NULL)
		{
			struct dnet_io_req *r, *tmp;

			list_for_each_entry_safe(r, tmp, &m_state->send_list, req_entry) {
				dnet_cmd *cmd = reinterpret_cast<dnet_cmd *>(r->header ? r->header : r->data);

				if (errp && cmd->status)
					*errp = cmd->status;

				list_del(&r->req_entry);
				dnet_io_req_free(r);
			}
		}

		static int noop_process(struct dnet_net_state *, struct epoll_event *) { return 0; }

		dnet_net_state *m_state;
};

struct update_indexes_functor : public std::enable_shared_from_this<update_indexes_functor>
{
	ELLIPTICS_DISABLE_COPY(update_indexes_functor)

	typedef std::shared_ptr<update_indexes_functor> ptr;

	update_indexes_functor(dnet_net_state *state, dnet_cmd *cmd, dnet_indexes_request *request)
		: sess(state->n), state(dnet_state_get(state)), cmd(*cmd), requests_in_progress(1)
	{
		this->cmd.flags |= DNET_FLAGS_MORE;

		debug() << "cmd->size: " << cmd->size
			<< ", request: " << sizeof(dnet_indexes_request)
			<< ", entry: " << sizeof(dnet_indexes_request_entry) << std::endl;

		request_id = request->id;

		size_t data_offset = 0;
		char *data_start = reinterpret_cast<char *>(request->entries);
		for (uint64_t i = 0; i < request->entries_count; ++i) {
			dnet_indexes_request_entry &request_entry = *reinterpret_cast<dnet_indexes_request_entry *>(data_start + data_offset);

			index_entry entry;
			entry.index = request_entry.id;
			entry.data = data_pointer::copy(request_entry.data, request_entry.size);

			indexes.indexes.push_back(entry);

			data_offset += sizeof(dnet_indexes_request_entry) + request_entry.size;
		}

		std::sort(indexes.indexes.begin(), indexes.indexes.end(), dnet_raw_id_less_than<>());
		msgpack::pack(buffer, indexes);

		debug() << __PRETTY_FUNCTION__ << std::endl;
	}

	~update_indexes_functor()
	{
		dnet_opunlock(state->n, &cmd.id);
		debug() << __PRETTY_FUNCTION__ << std::endl;
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
	dnet_indexes indexes;

	msgpack::sbuffer buffer;
	// already updated indexes - they are read from storage and changed
	dnet_indexes remote_indexes;
	std::vector<index_entry> inserted_ids;
	std::vector<index_entry> removed_ids;
	std::vector<dnet_indexes_reply_entry> result;

	std::atomic_int requests_in_progress;
	std::mutex requests_order_guard;

	/*!
	 * Replace object's index cache (list of indexes given object is present in) by new table.
	 * Store them into @remote_indexes
	 */
	data_pointer convert_object_indexes(const data_pointer &data)
	{
		debug() << std::endl;
		if (data.empty()) {
			remote_indexes.indexes.clear();
		} else {
			indexes_unpack(data, &remote_indexes, "convert_object_indexes");
		}

		return data_pointer::from_raw(const_cast<char *>(buffer.data()), buffer.size());
	}

	int process(bool *finished)
	{
		*finished = false;
		debug() << "process: " << indexes.indexes << std::endl;

		int err = 0;
		data_pointer data = sess.read(cmd.id, &err);

		data_pointer new_data = convert_object_indexes(data);

		if (data == new_data) {
			debug() << "update: data the same" << std::endl;
			return complete(0, finished);
		}
		debug() << "update: data is different" << std::endl;

		err = sess.write(cmd.id, new_data);
		if (err) {
			return complete(err, finished);
		}

		// We "insert" items also to update their data
		std::set_difference(indexes.indexes.begin(), indexes.indexes.end(),
			remote_indexes.indexes.begin(), remote_indexes.indexes.end(),
			std::back_inserter(inserted_ids), dnet_raw_id_less_than<>());
		// Remove index entries which are not present in the new list of indexes
		std::set_difference(remote_indexes.indexes.begin(), remote_indexes.indexes.end(),
			indexes.indexes.begin(), indexes.indexes.end(),
			std::back_inserter(removed_ids), dnet_raw_id_less_than<skip_data>());

		debug() << "insert: " << inserted_ids << ", remove: " << removed_ids << std::endl;
		if (inserted_ids.empty() && removed_ids.empty()) {
			return complete(0, finished);
		}
		debug() << std::endl;

		dnet_indexes_reply_entry result_entry;
		memset(&result_entry, 0, sizeof(result_entry));

		dnet_id base_id = request_id;

		std::vector<size_t> local_inserted_ids;
		std::vector<size_t> local_removed_ids;

		dnet_session *new_sess = dnet_session_create(state->n);
		int group_id = request_id.group_id;
		dnet_session_set_groups(new_sess, &group_id, 1);

		/*
		 * Some indexes are stored on other servers,
		 * so we should send the request through network
		 */
		for (size_t i = 0; i < inserted_ids.size(); ++i) {
			const index_entry &entry = inserted_ids[i];

			memcpy(base_id.id, entry.index.id, sizeof(base_id.id));

			dnet_net_state *index_state = dnet_state_get_first(state->n, &base_id);

			if (index_state) {
				int err = send_remote(new_sess, entry.index, entry.data, insert_data);
				if (err) {
					return complete(err, finished);
				}
			} else {
				local_inserted_ids.push_back(i);
			}
		}

		for (size_t i = 0; i < removed_ids.size(); ++i) {
			const index_entry &entry = removed_ids[i];

			memcpy(base_id.id, entry.index.id, sizeof(base_id.id));

			dnet_net_state *index_state = dnet_state_get_first(state->n, &base_id);

			if (index_state) {
				int err = send_remote(new_sess, entry.index, entry.data, remove_data);
				if (err) {
					return complete(err, finished);
				}
			} else {
				local_removed_ids.push_back(i);
			}
		}

		dnet_session_destroy(new_sess);

		/*
		 * Iterate over all indexes and update those which changed.
		 * 'Changed' here means we want to either put or remove
		 * update_indexes_functor::request_id to/from given index
		 */
		for (size_t i = 0; i < local_inserted_ids.size(); ++i) {
			const index_entry &entry = inserted_ids[local_inserted_ids[i]];

			err = sess.update_index_internal(request_id, entry.index, entry.data, insert_data);

			result_entry.status = err;
			result_entry.id = entry.index;
			result.push_back(result_entry);

			if (err) {
				return complete(err, finished);
			}
		}
		debug() << std::endl;

		for (size_t i = 0; i < local_removed_ids.size(); ++i) {
			const index_entry &entry = removed_ids[local_removed_ids[i]];

			err = sess.update_index_internal(request_id, entry.index, entry.data, remove_data);

			result_entry.status = err;
			result_entry.id = entry.index;
			result.push_back(result_entry);

			if (err) {
				return complete(err, finished);
			}
		}

		return complete(0, finished);
	}

	struct scope_data
	{
		ELLIPTICS_DISABLE_COPY(scope_data)

		scope_data(const ptr &functor) : functor(functor)
		{
		}

		ptr functor;
	};

	int send_remote(dnet_session *sess, const dnet_raw_id &index, const data_pointer &data, update_index_action action)
	{
		data_buffer buffer(sizeof(dnet_indexes_request) + sizeof(dnet_indexes_request_entry) + data.size());

		dnet_indexes_request request;
		memset(&request, 0, sizeof(request));

		request.id = request_id;
		request.entries_count = 1;

		buffer.write(request);

		dnet_indexes_request_entry entry;
		memset(&entry, 0, sizeof(entry));

		entry.id = index;
		entry.size = data.size();
		entry.flags = action;

		buffer.write(entry);

		if (!data.empty()) {
			buffer.write(data.data<char>(), data.size());
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

		debug() << "send_remote: " << err << ", group: " << control.id.group_id << std::endl;

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
				dnet_send_ack(scope->functor->state, &scope->functor->cmd, cmd->status);
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
			dnet_send_reply(state, &cmd, data.data(), data.size(), *finished ? 0 : 1);
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
data_pointer convert_index_table(const dnet_id &request_id, const data_pointer &index_data, const data_pointer &data, update_index_action action)
{
	debug() << std::endl;
	dnet_indexes indexes;
	if (!data.empty())
		indexes_unpack(data, &indexes, "convert_index_table");

	// Construct index entry
	index_entry request_index;
	memcpy(request_index.index.id, request_id.id, sizeof(request_index.index.id));
	request_index.data = index_data;

	debug() << "request_id: " << request_index.index << std::endl;

	auto it = std::lower_bound(indexes.indexes.begin(), indexes.indexes.end(),
		request_index, dnet_raw_id_less_than<skip_data>());
	if (it != indexes.indexes.end() && it->index == request_index.index) {
		// It's already there
		if (action == insert_data) {
			if (it->data == request_index.data) {
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
		if (action == insert_data) {
			// Just insert it
			indexes.indexes.insert(it, 1, request_index);
		} else {
			// All's ok, keep it untouched
			return data;
		}
	}

	msgpack::sbuffer buffer;
	msgpack::pack(&buffer, indexes);

	return data_pointer::copy(buffer.data(), buffer.size());
}

int process_internal_indexes(dnet_net_state *state, dnet_cmd *cmd, dnet_indexes_request *request)
{
	local_session sess(state->n);

	if (request->entries_count != 1) {
		return -EINVAL;
	}

	dnet_indexes_request_entry &entry = request->entries[0];
	const data_pointer entry_data = data_pointer::from_raw(entry.data, entry.size);

	debug() << "internal index: " << entry.id << ", object: " << reinterpret_cast<dnet_raw_id&>(request->id) << std::endl;

	update_index_action action;
	if (entry.flags & insert_data) {
		action = insert_data;
	} else if (entry.flags & remove_data) {
		action = remove_data;
	} else {
		debug() << "internal: invalid flags" << std::endl;
		return -EINVAL;
	}

	int err = 0;
	data_pointer data = sess.read(cmd->id, &err);
	data_pointer new_data = convert_index_table(request->id, entry_data, data, action);

	if (data == new_data) {
		debug() << "internal: data the same" << std::endl;
		return 0;
	}
	debug() << "internal: data is different" << std::endl;

	return sess.write(cmd->id, new_data);
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

	debug() << "process: " << dnet_cmd_string(cmd->cmd) << std::endl;

	switch (cmd->cmd) {
		case DNET_CMD_INDEXES_UPDATE: {
			auto functor = std::make_shared<update_indexes_functor>(st, cmd, request);

			bool finished = false;

			int result = functor->process(&finished);

			cmd->flags |= DNET_FLAGS_NOLOCK;

			if (!finished) {
				// Keep a lock until the request is finally processed
				cmd->flags &= ~DNET_FLAGS_NEED_ACK;
			}

			debug() << "done" << std::endl;
			return result;
		}
		case DNET_CMD_INDEXES_INTERNAL: {
			return process_internal_indexes(st, cmd, request);
		}
		default:
			return -ENOTSUP;
	}
}
