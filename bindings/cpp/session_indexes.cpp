/*
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

#include "elliptics/utils.hpp"
#include "elliptics/debug.hpp"

#include "session_indexes.hpp"
#include "callback_p.h"
#include "functional_p.h"
#include "node_p.hpp"

#include "../../library/elliptics.h"

namespace ioremap { namespace elliptics {

typedef async_result_handler<callback_result_entry> async_update_indexes_handler;

#define DNET_INDEXES_FLAGS_CAPPED_COLLECTION (1<<28)
#define DNET_INDEXES_FLAGS_NOINTERNAL (1 << 29)
#define DNET_INDEXES_FLAGS_NOUPDATE (1 << 30)

static void on_update_index_entry(async_update_indexes_handler handler, const callback_result_entry &entry)
{
	handler.process(entry);

	if (!entry.data().empty()) {
		dnet_indexes_reply *reply = entry.data<dnet_indexes_reply>();

		for (size_t i = 0; i < reply->entries_count; ++i) {
			dnet_indexes_reply_entry &index_entry = reply->entries[i];
			dnet_addr addr = *entry.address();
			dnet_cmd cmd = *entry.command();

			memcpy(cmd.id.id, index_entry.id.id, sizeof(cmd.id.id));
			cmd.status = index_entry.status;
			cmd.size = 0;

			auto data = std::make_shared<callback_result_data>(&addr, &cmd);
			handler.process(callback_result_entry(data));
		}
	}
}

static void on_update_index_finished(async_update_indexes_handler handler, const error_info &error)
{
	handler.complete(error);
}

/*!
 * There are several modifying index methods with similiar behaviour.
 * Some of them send requests to 'object's list of indexes', other to
 * 'index's list of objects', some to both of them.
 *
 * This method should suit all of them and it's behaviour depends on
 * flags passed as an argument.
 */
static async_set_indexes_result session_set_indexes(session &orig_sess, const key &request_id,
		const std::vector<index_entry> &indexes, uint32_t flags, uint64_t limit = 0)
{
	orig_sess.transform(request_id);

	std::vector<int> groups(1, 0);

	const std::vector<int> known_groups = orig_sess.get_groups();

	if (known_groups.empty()) {
		async_set_indexes_result result(orig_sess);
		async_result_handler<callback_result_entry> handler(result);
		handler.complete(create_error(-ENXIO, "session_set_indexes: groups list is empty"));
		return result;
	}

	session sess = orig_sess.clean_clone();

	size_t data_size = 0;
	size_t max_data_size = 0;
	for (size_t i = 0; i < indexes.size(); ++i) {
		data_size += indexes[i].data.size();
		max_data_size = std::max(max_data_size, indexes[i].data.size());
	}

	dnet_node *node = sess.get_native_node();
	std::list<async_generic_result> results;

	dnet_id indexes_id;
	memset(&indexes_id, 0, sizeof(indexes_id));
	dnet_indexes_transform_object_id(node, &request_id.id(), &indexes_id);

	const bool capped = (flags & DNET_INDEXES_FLAGS_CAPPED_COLLECTION);
	const bool noupdate = (flags & DNET_INDEXES_FLAGS_NOUPDATE);
	const bool nointernal = (flags & DNET_INDEXES_FLAGS_NOINTERNAL);
	flags &= ~(DNET_INDEXES_FLAGS_CAPPED_COLLECTION | DNET_INDEXES_FLAGS_NOUPDATE | DNET_INDEXES_FLAGS_NOINTERNAL);

	if (!noupdate) {
		data_buffer buffer(sizeof(dnet_indexes_request) +
				indexes.size() * sizeof(dnet_indexes_request_entry) + data_size);


		dnet_indexes_request request;
		dnet_indexes_request_entry entry;
		memset(&request, 0, sizeof(request));
		memset(&entry, 0, sizeof(entry));

		request.flags = flags;
		request.id = request_id.id();

		request.entries_count = indexes.size();

		buffer.write(request);

		for (size_t i = 0; i < indexes.size(); ++i) {
			const index_entry &index = indexes[i];
			entry.id = index.index;
			entry.limit = limit;
			entry.size = index.data.size();

			buffer.write(entry);
			if (entry.size > 0) {
				buffer.write(index.data.data<char>(), index.data.size());
			}
		}

		data_pointer data(std::move(buffer));

		dnet_id &id = data.data<dnet_indexes_request>()->id;

		transport_control control;
		control.set_command(DNET_CMD_INDEXES_UPDATE);
		control.set_data(data.data(), data.size());
		control.set_cflags(DNET_FLAGS_NEED_ACK);

		for (size_t i = 0; i < known_groups.size(); ++i) {
			id.group_id = known_groups[i];
			indexes_id.group_id = id.group_id;

			groups[0] = id.group_id;
			sess.set_groups(groups);

			control.set_key(indexes_id);

			results.emplace_back(send_to_single_state(sess, control));
		}
	}

	if (!nointernal && (flags & (DNET_INDEXES_FLAGS_UPDATE_ONLY | DNET_INDEXES_FLAGS_REMOVE_ONLY))) {
		transport_control control;
		control.set_command(DNET_CMD_INDEXES_INTERNAL);
		control.set_cflags(DNET_FLAGS_NEED_ACK);

		data_pointer data = data_pointer::allocate(sizeof(dnet_indexes_request) +
				sizeof(dnet_indexes_request_entry) + max_data_size);
		memset(data.data(), 0, data.size());

		dnet_indexes_request *request = data.data<dnet_indexes_request>();
		dnet_indexes_request_entry *entry =
			data.skip<dnet_indexes_request>().data<dnet_indexes_request_entry>();
		void *entry_data = data.skip<dnet_indexes_request>().skip<dnet_indexes_request_entry>().data();

		request->id = request_id.id();
		request->entries_count = 1;
		dnet_raw_id &tmp_entry_id = entry->id;

		dnet_id id;
		memset(&id, 0, sizeof(id));

		const auto shard_id = dnet_indexes_get_shard_id(node, &key(indexes_id).raw_id());
		const auto shard_count = dnet_node_get_indexes_shard_count(node);

		request->shard_id = shard_id;
		request->shard_count = shard_count;

		entry->shard_id = shard_id;
		entry->shard_count = shard_count;

		for (size_t i = 0; i < indexes.size(); ++i) {
			const index_entry &index = indexes[i];

			dnet_indexes_transform_index_id(node, &index.index, &tmp_entry_id, shard_id);
			memcpy(id.id, tmp_entry_id.id, DNET_ID_SIZE);

			entry->limit = limit;
			entry->size = index.data.size();
			entry->flags = (flags & DNET_INDEXES_FLAGS_UPDATE_ONLY) ? DNET_INDEXES_FLAGS_INTERNAL_INSERT : DNET_INDEXES_FLAGS_INTERNAL_REMOVE;
			if (capped)
				entry->flags |= DNET_INDEXES_FLAGS_INTERNAL_CAPPED_COLLECTION;

			control.set_data(data.data(), sizeof(dnet_indexes_request) +
					sizeof(dnet_indexes_request_entry) + index.data.size());
			memcpy(entry_data, index.data.data(), index.data.size());

			for (size_t j = 0; j < known_groups.size(); ++j) {
				id.group_id = known_groups[j];

				groups[0] = id.group_id;
				sess.set_groups(groups);

				control.set_key(id);

				results.emplace_back(send_to_single_state(sess, control));
			}
		}
	}

	auto result = aggregated(sess, results.begin(), results.end());

	async_update_indexes_result final_result(orig_sess);

	async_update_indexes_handler handler(final_result);
	handler.set_total(result.total());

	result.connect(std::bind(on_update_index_entry, handler, std::placeholders::_1),
		std::bind(on_update_index_finished, handler, std::placeholders::_1));

	dnet_log(orig_sess.get_native_node(), DNET_LOG_INFO, "%s: key: %s, indexes: %zd",
			dnet_dump_id(&request_id.id()), request_id.to_string().c_str(), indexes.size());

	return final_result;
}

static void session_convert_indexes(session &sess, std::vector<index_entry> &raw_indexes,
	const std::vector<std::string> &indexes, const std::vector<data_pointer> &datas)
{
	dnet_id tmp;
	raw_indexes.resize(indexes.size());

	for (size_t i = 0; i < indexes.size(); ++i) {
		sess.transform(indexes[i], tmp);
		memcpy(raw_indexes[i].index.id, tmp.id, sizeof(tmp.id));
		raw_indexes[i].data = datas[i];
	}
}

static std::vector<dnet_raw_id> session_convert_indexes(session &sess, const std::vector<std::string> &indexes)
{
	std::vector<dnet_raw_id> raw_indexes;
	raw_indexes.resize(indexes.size());

	for (size_t i = 0; i < indexes.size(); ++i) {
		sess.transform(indexes[i], raw_indexes[i]);
	}

	return std::move(raw_indexes);
}

// Update \a indexes for \a request_id
// Result is pushed to \a handler
async_set_indexes_result session::set_indexes(const key &request_id, const std::vector<index_entry> &indexes)
{
	return session_set_indexes(*this, request_id, indexes, 0);
}

async_set_indexes_result session::set_indexes(const key &id, const std::vector<std::string> &indexes,
		const std::vector<data_pointer> &datas)
{
	if (datas.size() != indexes.size())
		throw_error(-EINVAL, id, "session::set_indexes: indexes and datas sizes mismtach");

	std::vector<index_entry> raw_indexes;
	session_convert_indexes(*this, raw_indexes, indexes, datas);

	return set_indexes(id, raw_indexes);
}

async_set_indexes_result session::update_indexes_internal(const key &request_id,
		const std::vector<ioremap::elliptics::index_entry> &indexes)
{
	return session_set_indexes(*this, request_id, indexes,
			DNET_INDEXES_FLAGS_NOUPDATE | DNET_INDEXES_FLAGS_UPDATE_ONLY);
}

async_set_indexes_result session::update_indexes_internal(const key &id,
		const std::vector<std::string> &indexes, const std::vector<data_pointer> &datas)
{
	if (datas.size() != indexes.size())
		throw_error(-EINVAL, id, "session::update_indexes_internal: indexes and datas sizes mismtach");

	std::vector<index_entry> raw_indexes;
	session_convert_indexes(*this, raw_indexes, indexes, datas);

	return update_indexes_internal(id, raw_indexes);
}

struct state_container
{
	state_container() : entries_count(0), failed(false)
	{
	}

	state_container(const state_container &other) = delete;
	state_container(state_container &&other) = delete;

	state_container &operator =(const state_container &other) = delete;
	state_container &operator =(state_container &&other) = delete;

	net_state_id cur;
	data_buffer buffer;
	size_t entries_count;
	bool failed;
};

async_generic_result session::remove_index_internal(const key &original_id)
{
	transform(original_id);

	dnet_id id = original_id.id();
	DNET_SESSION_GET_GROUPS(async_generic_result);

	dnet_raw_id index = original_id.raw_id();

	std::vector<async_generic_result> results;

	dnet_node *node = get_native_node();
	const int shard_count = dnet_node_get_indexes_shard_count(node);

	dnet_trans_control control;
	memset(&control, 0, sizeof(control));

	control.cmd = DNET_CMD_INDEXES_INTERNAL;
	control.cflags = DNET_FLAGS_NEED_ACK;

	dnet_indexes_request request;
	memset(&request, 0, sizeof(request));

	dnet_indexes_request_entry entry;
	memset(&entry, 0, sizeof(entry));

	entry.flags |= DNET_INDEXES_FLAGS_INTERNAL_REMOVE_ALL;
	entry.shard_count = shard_count;

	std::unique_ptr<state_container[]> states(new state_container[groups.size()]);

	session sess = clean_clone();

	/*
	 * To totally remove the index we have to send remove request to every shard and to every group.
	 * Sending 4k different requests is not optimal, so requests to the single elliptics node
	 * are joined to the single request.
	 *
	 * To do this we have to iterate through all shards. It's needed for every (shard, group) pair
	 * to compare dnet_net_state with (shard - 1, group) one if it exists.
	 */

	for (int shard_id = 0; shard_id <= shard_count; ++shard_id) {
		const bool after_last_entry = (shard_id == shard_count);
		entry.shard_id = shard_id;

		if (!after_last_entry) {
			dnet_indexes_transform_index_id(node, &index, &entry.id, shard_id);
			memcpy(id.id, entry.id.id, DNET_ID_SIZE);
		}

		/*
		 * Iterate for all groups, each group stores it's state it states[group_index] field.
		 * It's needed to decrease number of index transformations above.
		 */
		for (size_t group_index = 0; group_index < groups.size(); ++group_index) {
			state_container &state = states[group_index];

			// We failed to get this group's network state sometime ago so skip it
			if (state.failed) {
				continue;
			}

			id.group_id = groups[group_index];
			net_state_id next;

			if (shard_id == 0) {
				state.cur.reset(node, &id);
				// Error during state getting, don't touch this group more
				if (!state.cur) {
					state.failed = true;
					continue;
				}
			}

			if (!after_last_entry) {
				next.reset(node, &id);
				// Error during state getting, don't touch this group more
				if (!next) {
					state.failed = true;
					continue;
				}
			}

			// This is a first entry, prepend the request to the buffer
			if (state.entries_count == 0) {
				if (after_last_entry) {
					// Oh, this was not the first entry, but we already finished this group
					continue;
				}
				request.id = id;
				state.buffer.write(request);
			}

			if (state.cur == next) {
				// Append entry to the request list as they are to the same node
				state.buffer.write(entry);
				state.entries_count++;
				continue;
			} else {
				state.cur = std::move(next);
			}

			data_pointer data = std::move(state.buffer);

			// Set the actual entries_count value as it is unknown at the beginning
			dnet_indexes_request *request_ptr = data.data<dnet_indexes_request>();
			request_ptr->entries_count = state.entries_count;
			dnet_setup_id(&request_ptr->id, id.group_id, request_ptr->entries[0].id.id);
			state.entries_count = 0;

			control.id = request_ptr->id;
			control.data = data.data();
			control.size = data.size();
			control.id.group_id = groups[group_index];

			// Send exactly one request to exactly one elliptics node
			results.emplace_back(send_to_single_state(sess, control));

			if (!after_last_entry) {
				state.buffer.write(request);
				state.buffer.write(entry);
				state.entries_count++;
			}
		}
	}

	return aggregated(*this, results.begin(), results.end());
}

struct on_remove_index : std::enable_shared_from_this<on_remove_index>
{
	typedef std::shared_ptr<on_remove_index> ptr;

	on_remove_index(session &sess, async_generic_result &result) : sess(sess), handler(result), counter(1)
	{
	}

	void on_find_entry(const find_indexes_result_entry &entry)
	{
		using namespace std::placeholders;
		++counter;
		session remove_sess = sess.clone();
		session_set_indexes(remove_sess, entry.id, index_entry_list,
			DNET_INDEXES_FLAGS_NOINTERNAL | DNET_INDEXES_FLAGS_REMOVE_ONLY).connect(
			std::bind(&on_remove_index::on_remove_index_entry, shared_from_this(), _1),
			std::bind(&on_remove_index::on_request_finished, shared_from_this(), _1));

		{
			logger &log = sess.get_logger();
			char index_name[2 * DNET_ID_SIZE + 1];
			char object_name[2 * DNET_ID_SIZE + 1];
			BH_LOG(log, DNET_LOG_DEBUG, "on_remove_index: Removed index %s from object %s",
				dnet_dump_id_len_raw(index_id.id, DNET_DUMP_NUM, index_name),
				dnet_dump_id_len_raw(entry.id.id, DNET_DUMP_NUM, object_name));
		}

		if (remove_data) {
			++counter;
			sess.clone().remove(entry.id).connect(
				std::bind(&on_remove_index::on_remove_entry, shared_from_this(), _1),
				std::bind(&on_remove_index::on_request_finished, shared_from_this(), _1));
		}
	}

	void on_find_finished(const error_info &error)
	{
		(void) error;
		using namespace std::placeholders;
		sess.clone().remove_index_internal(index_id).connect(
			std::bind(&async_result_handler<callback_result_entry>::process, &handler, _1),
			std::bind(&on_remove_index::on_request_finished, shared_from_this(), _1));
	}

	void on_remove_entry(const remove_result_entry &)
	{
	}

	void on_remove_index_entry(const callback_result_entry &)
	{
	}

	void on_request_finished(const error_info &)
	{
		if (--counter == 0)
			handler.complete(error);
	}

	void on_remove_index_internal_finished(const error_info &error)
	{
		this->error = error;
		on_request_finished(error);
	}

	session sess;
	async_result_handler<callback_result_entry> handler;
	dnet_raw_id index_id;
	std::vector<dnet_raw_id> index_id_list;
	std::vector<index_entry> index_entry_list;
	bool remove_data;
	std::atomic_size_t counter;
	error_info error;
};

async_generic_result session::remove_index(const key &id, bool remove_data)
{
	using namespace std::placeholders;
	transform(id);
	async_generic_result result(*this);

	session sess = clone();
	sess.set_exceptions_policy(no_exceptions);
	sess.set_filter(filters::all_with_ack);

	auto functor = std::make_shared<on_remove_index>(sess, result);
	functor->index_id = id.raw_id();
	functor->index_id_list.assign(1, id.raw_id());
	functor->index_entry_list.assign(1, index_entry(id.raw_id(), data_pointer()));
	functor->remove_data = remove_data;
	find_all_indexes(functor->index_id_list).connect(
		std::bind(&on_remove_index::on_find_entry, functor, _1),
		std::bind(&on_remove_index::on_find_finished, functor, _1));

	return result;
}

async_set_indexes_result session::remove_indexes_internal(const key &id, const std::vector<dnet_raw_id> &indexes)
{
	std::vector<index_entry> index_entries;
	index_entries.reserve(indexes.size());
	for (auto it = indexes.begin(); it != indexes.end(); ++it) {
		index_entries.emplace_back(*it, data_pointer());
	}

	return session_set_indexes(*this, id, index_entries,
			DNET_INDEXES_FLAGS_NOUPDATE | DNET_INDEXES_FLAGS_REMOVE_ONLY);
}

async_set_indexes_result session::remove_indexes_internal(const key &id, const std::vector<std::string> &indexes)
{
	return remove_indexes_internal(id, session_convert_indexes(*this, indexes));
}

async_set_indexes_result session::update_indexes(const key &request_id,
		const std::vector<ioremap::elliptics::index_entry> &indexes)
{
	return session_set_indexes(*this, request_id, indexes, DNET_INDEXES_FLAGS_UPDATE_ONLY);
}

async_set_indexes_result session::update_indexes(const key &id,
		const std::vector<std::string> &indexes, const std::vector<data_pointer> &datas)
{
	if (datas.size() != indexes.size())
		throw_error(-EINVAL, id, "session::update_indexes: indexes and datas sizes mismtach");

	std::vector<index_entry> raw_indexes;
	session_convert_indexes(*this, raw_indexes, indexes, datas);

	return update_indexes(id, raw_indexes);
}

struct add_to_capped_collection_handler : public std::enable_shared_from_this<add_to_capped_collection_handler>
{
	add_to_capped_collection_handler(const session &sess, const async_generic_result &result)
		: sess(sess), handler(result), counter(1)
	{
	}

	void on_entry(const callback_result_entry &entry)
	{
		if (!entry.error() && entry.size() >= sizeof(dnet_indexes_reply)) {
			const dnet_indexes_reply *reply = entry.data<dnet_indexes_reply>();
			for (uint64_t index = 0; index < reply->entries_count; ++index) {
				const dnet_indexes_reply_entry &entry = reply->entries[index];
				if (entry.status == DNET_INDEXES_CAPPED_REMOVED) {
					using std::placeholders::_1;

					++counter;

					sess.remove(entry.id).connect(
						std::bind(&add_to_capped_collection_handler::on_removed_entry, shared_from_this(), _1),
						std::bind(&add_to_capped_collection_handler::on_finished, shared_from_this(), _1));
				}
			}
		}

		handler.process(entry);
	}

	void on_removed_entry(const callback_result_entry &entry)
	{
		handler.process(entry);
	}

	void on_finished(const error_info &error)
	{
		if (error) {
			std::lock_guard<std::mutex> lock(total_error_mutex);
			total_error = error;
		}

		if (0 == --counter)
			handler.complete(total_error);
	}

	session sess;
	async_result_handler<callback_result_entry> handler;
	std::atomic_size_t counter;
	std::mutex total_error_mutex;
	error_info total_error;
};

async_generic_result session::add_to_capped_collection(const key &id, const index_entry &index, int limit, bool remove_data)
{
	transform(id);

	session sess = *this;

	if (remove_data) {
		sess = clone();
		sess.set_filter(filters::all_with_ack);
		sess.set_checker(checkers::no_check);
		sess.set_exceptions_policy(no_exceptions);
	}

	async_generic_result indexes_result = session_set_indexes(sess, id, std::vector<index_entry>(1, index),
		DNET_INDEXES_FLAGS_CAPPED_COLLECTION | DNET_INDEXES_FLAGS_UPDATE_ONLY, limit);

	if (!remove_data) {
		return indexes_result;
	}

	session remove_sess = clone();
	remove_sess.set_filter(filters::all_with_ack);
	remove_sess.set_checker(checkers::no_check);
	remove_sess.set_exceptions_policy(no_exceptions);

	async_generic_result result(*this);

	auto handler = std::make_shared<add_to_capped_collection_handler>(remove_sess, result);

	using std::placeholders::_1;

	indexes_result.connect(std::bind(&add_to_capped_collection_handler::on_entry, handler, _1),
		std::bind(&add_to_capped_collection_handler::on_finished, handler, _1));

	return result;
}

async_set_indexes_result session::remove_indexes(const key &id, const std::vector<dnet_raw_id> &indexes)
{
	std::vector<index_entry> index_entries;
	index_entries.reserve(indexes.size());
	for (auto it = indexes.begin(); it != indexes.end(); ++it) {
		index_entries.emplace_back(*it, data_pointer());
	}

	return session_set_indexes(*this, id, index_entries, DNET_INDEXES_FLAGS_REMOVE_ONLY);
}

async_set_indexes_result session::remove_indexes(const key &id, const std::vector<std::string> &indexes)
{
	return remove_indexes(id, session_convert_indexes(*this, indexes));
}

class find_indexes_handler : public multigroup_handler<find_indexes_handler, callback_result_entry>
{
public:
	typedef std::map<dnet_raw_id, dnet_raw_id, dnet_raw_id_less_than<> > id_map;

	struct index_id
	{
		index_id(const dnet_raw_id &id, int shard_id) :
			id(id), shard_id(shard_id)
		{
		}

		bool operator <(const index_id &other) const
		{
			return dnet_id_cmp_str(id.id, other.id.id) < 0;
		}

		dnet_raw_id id;
		int shard_id;
	};

	find_indexes_handler(const session &sess, const async_generic_result &result, std::vector<int> &&groups,
		const std::vector<dnet_raw_id> &indexes, bool intersect) :
		parent_type(sess, result, std::move(groups)),
		m_logger(m_sess.get_logger()),
		m_intersect(intersect),
		m_shard_count(dnet_node_get_indexes_shard_count(sess.get_native_node())),
		m_indexes(indexes)
	{
		m_sess.set_checker(checkers::no_check);

		dnet_node *node = m_sess.get_native_node();

		m_id_precalc.resize(m_shard_count * m_indexes.size());

		/*
		 * index_requests_set contains all requests we have to send for this bulk-request.
		 * All indexes a splitted for shards, so we have to send separate logical request
		 * to certain shard for all indexes. This logical requests may be joined to one
		 * transaction if some of shards are situated on one elliptics node.
		 */
		dnet_raw_id tmp;

		for (size_t index = 0; index < m_indexes.size(); ++index) {
			dnet_indexes_transform_index_prepare(node, &m_indexes[index], &tmp);

			for (int shard_id = 0; shard_id < m_shard_count; ++shard_id) {
				dnet_raw_id &id = m_id_precalc[shard_id * m_indexes.size() + index];

				memcpy(&id, &tmp, sizeof(dnet_raw_id));
				dnet_indexes_transform_index_id_raw(node, &id, shard_id);

				m_convert_map[id] = m_indexes[index];
			}
		}

		for (int shard_id = 0; shard_id < m_shard_count; ++shard_id) {
			m_index_requests_set.insert(index_id(m_id_precalc[shard_id * m_indexes.size()], shard_id));
		}

		debug("INDEXES_FIND, callback: %p, shard_count: %d, indexes_count: %llu", this, m_shard_count, m_indexes.size());
	}

	id_map &&take_convert_map()
	{
		return std::move(m_convert_map);
	}

	async_generic_result send_to_next_group()
	{
		size_t count = 0;

		std::vector<async_generic_result> results;

		unsigned long long index_requests_count = 0;
		const int group_id = current_group();

		dnet_node *node = m_sess.get_native_node();

		dnet_id id;
		memset(&id, 0, sizeof(id));
		dnet_setup_id(&id, group_id, m_index_requests_set.begin()->id.id);

		net_state_id cur(node, &id);
		net_state_id next;
		dnet_id next_id = id;

		debug("INDEXES_FIND, callback: %p, group: %d, next", this, group_id);

		if (!cur) {
			debug("INDEXES_FIND, callback: %p, group: %d, id: %s, state: failed",
				this, group_id, dnet_dump_id(&id));
			return aggregated(m_sess, results.begin(), results.end());
		}
		debug("INDEXES_FIND, callback: %p, id: %s, state: %s, backend: %d",
			this, dnet_dump_id(&id), dnet_state_dump_addr(cur.state()), cur.backend());

		dnet_trans_control control;
		memset(&control, 0, sizeof(control));
		control.cmd = DNET_CMD_INDEXES_FIND;
		control.cflags = DNET_FLAGS_NEED_ACK;

		data_buffer buffer;

		dnet_indexes_request request;
		memset(&request, 0, sizeof(request));
		request.entries_count = m_indexes.size();
		request.id = id;
		if (m_intersect)
			request.flags |= DNET_INDEXES_FLAGS_INTERSECT;
		else
			request.flags |= DNET_INDEXES_FLAGS_UNITE;

		dnet_indexes_request_entry entry;
		memset(&entry, 0, sizeof(entry));

		std::vector<index_id> index_requests(m_index_requests_set.begin(), m_index_requests_set.end());

		/*
		 * Iterate through all requests uniting to single transaction all for the same host.
		 */
		for (auto it = index_requests.begin(); it != index_requests.end(); ++it) {
			bool more = false;
			/*
			 * Check for the state of the next request if current is not the last one.
			 * If next state is the same we should unite requests to single one.
			 */
			auto jt = it;
			if (++jt != index_requests.end()) {
				dnet_setup_id(&next_id, group_id, jt->id.id);

				next.reset(node, &next_id);
				if (!next) {
					debug("INDEXES_FIND, callback: %p, group: %d, id: %s, state: failed",
						this, group_id, dnet_dump_id(&next_id));
					return aggregated(m_sess, results.begin(), results.end());
				}
				debug("INDEXES_FIND, callback: %p, id: %s, state: %s, backend: %d",
					this, dnet_dump_id(&next_id), dnet_state_dump_addr(next.state()), next.backend());

				/* Send command only if state changes or it's a last id */
				more = (cur == next);
			}

			if (more) {
				request.flags |= DNET_INDEXES_FLAGS_MORE;
			} else {
				request.flags &= ~DNET_INDEXES_FLAGS_MORE;
			}
			dnet_setup_id(&request.id, group_id, m_id_precalc[it->shard_id * m_indexes.size()].id);

			buffer.write(request);
			++index_requests_count;

			for (size_t i = 0; i < m_indexes.size(); ++i) {
				entry.id = m_id_precalc[it->shard_id * m_indexes.size() + i];
				buffer.write(entry);
			}

			if (more) {
				continue;
			}

			data_pointer data = std::move(buffer);

			control.size = data.size();
			control.data = data.data();

			memcpy(&control.id, &id, sizeof(id));

			notice("INDEXES_FIND: callback: %p, count: %llu, state: %s, backend: %d",
				this,
				index_requests_count,
				dnet_state_dump_addr(cur.state()), cur.backend());

			++count;
			index_requests_count = 0;

			results.emplace_back(send_to_single_state(m_sess, control));

			debug("INDEXES_FIND, callback: %p, group: %d", this, group_id);

			cur.reset();
			std::swap(next, cur);
			memcpy(&id, &next_id, sizeof(struct dnet_id));
		}

		debug("INDEXES_FIND, callback: %p, group: %d, count: %d", this, group_id, count);

		return aggregated(m_sess, results.begin(), results.end());
	}

	bool need_next_group(const error_info &error)
	{
		(void) error;

		debug("INDEXES_FIND, callback: %p, index_requests_set.size: %llu, group_index: %llu, group_count: %llu",
			  this, m_index_requests_set.size(), m_group_index, m_groups.size());

		// all results are found or all groups are iterated
		return !m_index_requests_set.empty();
	}

	void process_entry(const callback_result_entry &entry)
	{
		if (filters::positive(entry)) {
			const auto &id = reinterpret_cast<dnet_raw_id&>(entry.command()->id);
			m_index_requests_set.erase(index_id(id, 0));
		}
	}

private:
	const dnet_logger &m_logger;
	const bool m_intersect;
	const int m_shard_count;
	std::set<index_id> m_index_requests_set;
	id_map m_convert_map;
	std::vector<dnet_raw_id> m_id_precalc;
	std::vector<dnet_raw_id> m_indexes;
};

static void on_find_indexes_process(session sess, std::shared_ptr<find_indexes_handler::id_map> convert_map,
	async_result_handler<find_indexes_result_entry> handler, const callback_result_entry &entry)
{
	if (!filters::positive(entry))
		return;

	dnet_node *node = sess.get_native_node();
	data_pointer data = entry.data();

	sync_find_indexes_result tmp;
	find_result_unpack(node, &entry.command()->id, data, &tmp, "on_find_indexes_process");

	for (auto it = tmp.begin(); it != tmp.end(); ++it) {
		find_indexes_result_entry &entry = *it;

		for (auto jt = entry.indexes.begin(); jt != entry.indexes.end(); ++jt) {
			dnet_raw_id &id = jt->index;

			auto converted = convert_map->find(id);
			if (converted == convert_map->end()) {
				BH_LOG(sess.get_logger(), DNET_LOG_ERROR, "%s: on_find_indexes_process, unknown id", dnet_dump_id_str(id.id));
				continue;
			}

			id = converted->second;
		}

		handler.process(entry);
	}
}

static void on_find_indexes_complete(async_result_handler<find_indexes_result_entry> handler, const error_info &error)
{
	handler.complete(error);
}

async_find_indexes_result session::find_indexes_internal(const std::vector<dnet_raw_id> &indexes, bool intersect)
{
	async_find_indexes_result result(*this);
	async_result_handler<find_indexes_result_entry> handler(result);

	if (indexes.size() == 0) {
		handler.complete(error_info());
		return result;
	}

	auto &id = indexes[0];

	DNET_SESSION_GET_GROUPS(async_find_indexes_result);

	session sess = clean_clone();
	async_generic_result raw_result(sess);
	auto raw_handler = std::make_shared<find_indexes_handler>(*this, raw_result, std::move(groups), indexes, intersect);
	auto convert_map = std::make_shared<find_indexes_handler::id_map>(std::move(raw_handler->take_convert_map()));
	raw_handler->start();

	using namespace std::placeholders;

	raw_result.connect(std::bind(on_find_indexes_process, sess, convert_map, handler, _1),
		std::bind(on_find_indexes_complete, handler, _1));

	return result;
}

async_find_indexes_result session::find_all_indexes(const std::vector<dnet_raw_id> &indexes)
{
	return find_indexes_internal(indexes, true);
}

async_find_indexes_result session::find_all_indexes(const std::vector<std::string> &indexes)
{
	return find_all_indexes(session_convert_indexes(*this, indexes));
}

async_find_indexes_result session::find_any_indexes(const std::vector<dnet_raw_id> &indexes)
{
	return find_indexes_internal(indexes, false);
}

async_find_indexes_result session::find_any_indexes(const std::vector<std::string> &indexes)
{
	return find_any_indexes(session_convert_indexes(*this, indexes));
}

struct check_indexes_handler
{
	session sess;
	key request_id;
	async_result_handler<index_entry> handler;

	void operator() (const sync_read_result &read_result, const error_info &err)
	{
		if (err) {
			handler.complete(err);
			return;
		}

		dnet_indexes result;
		try {
			indexes_unpack(sess.get_native_node(), &read_result[0].command()->id,
					read_result[0].file(), &result, "check_indexes_handler");
		} catch (std::exception &e) {
			handler.complete(create_error(-EINVAL, request_id, "%s", e.what()));
			return;
		}

		for (auto it = result.indexes.begin(); it != result.indexes.end(); ++it) {
			handler.process(*it);
		}
		handler.complete(error_info());
	}
};

async_list_indexes_result session::list_indexes(const key &request_id)
{
	transform(request_id);

	async_list_indexes_result result(*this);

	dnet_id id;
	memset(&id, 0, sizeof(id));
	dnet_indexes_transform_object_id(get_native_node(), &request_id.id(), &id);

	check_indexes_handler functor = { *this, request_id, result };
	read_latest(id, 0, 0).connect(functor);

	return result;
}

/*!
 * Auxiliary function to parse char* buffer with c-msgpack library
 */
static bool buffer_reader(cmp_ctx_t *ctx, void *data, size_t limit)
{
	char *start_ptr = static_cast<char *>(ctx->buf);
	char *ptr = start_ptr;
	while (ptr && limit) {
		++ptr;
		--limit;
	}
	if (limit != 0) {
		return false;
	}
	memcpy(data, start_ptr, ptr - start_ptr);
	ctx->buf = ptr;
	return true;
}

/*!
 * Structure of secondary index msgpack is following
 * Array of 4 elements
 * Version number
 * Array of indexes
 *
 * We need to get size of indexes array, that's why we
 * skip first two fields in msgpack and return size
 * of array in third position of msgpack
 */
static uint32_t get_index_size(const std::string &index_metadata, int &err)
{
	err = 0;
	cmp_ctx_t cmp;

	char *buffer = new char[index_metadata.length() + 1];
	memcpy(buffer, index_metadata.data(), index_metadata.length() + 1);

	cmp_init(&cmp, buffer, buffer_reader, NULL);

	uint32_t array_size;
	if (!cmp_read_array(&cmp, &array_size)) {
		err = -EBADMSG;
		return 0;
	}

	int32_t version;
	if (!cmp_read_int(&cmp, &version)) {
		err = -EBADMSG;
		return 0;
	}

	if (!cmp_read_array(&cmp, &array_size)) {
		err = -EBADMSG;
		return 0;
	}

	delete[] buffer;
	return array_size;
}

typedef std::map<dnet_raw_id, int, dnet_raw_id_less_than<> > id_to_shard_map;

/*!
 * \brief Callback that handles bulk_read responses
 *
 * Each response corresponds to some shard
 * We extract metadata from each shard index
 * and put it into vector of answers
 */
struct get_index_metadata_callback
{
	session sess;
	async_result_handler<get_index_metadata_result_entry> handler;
	id_to_shard_map id_to_shard;

	void operator() (const read_result_entry &result)
	{
		get_index_metadata_result_entry metadata;

		dnet_raw_id raw_id;
		memcpy(raw_id.id, result.command()->id.id, DNET_ID_SIZE);
		metadata.shard_id = id_to_shard[raw_id];

		std::string content =  result.file().to_string().substr(DNET_INDEX_TABLE_MAGIC_SIZE);
		int err = 0;
		metadata.index_size = get_index_size(content, err);
		if (err) {
			metadata.is_valid = false;
			BH_LOG(sess.get_logger(), DNET_LOG_ERROR, "get_index_metadata: Incorrect msgpack format: err: %d", err);
		} else {
			metadata.is_valid = true;
		}
		handler.process(metadata);
	}

	void operator() (const error_info &error)
	{
		handler.complete(error);
	}
};

/*!
 * \brief Returns metadata for each shard for secondary index \a index
 */
async_get_index_metadata_result session::get_index_metadata(const dnet_raw_id &index)
{
	session sess = clone();
	sess.set_exceptions_policy(session::no_exceptions);
	sess.set_filter(filters::positive);
	sess.set_checker(checkers::no_check);

	dnet_node *node = sess.get_native_node();
	int shard_count = node->indexes_shard_count;

	/*
	 * Prepare indexes ids for bulk_read request
	 */
	std::vector<dnet_io_attr> request_io_attrs;
	request_io_attrs.resize(shard_count);

	id_to_shard_map id_to_shard;

	/*
	 * index_requests_set contains all requests we have to send for this bulk-request.
	 * All indexes a splitted for shards, so we have to send separate logical request
	 * to certain shard for all indexes. This logical requests may be joined to one
	 * transaction if some of shards are situated on one elliptics node.
	 */
	dnet_raw_id tmp;

	dnet_indexes_transform_index_prepare(node, &index, &tmp);

	for (int shard_id = 0; shard_id < shard_count; ++shard_id) {
		dnet_raw_id id;

		memcpy(&id, &tmp, sizeof(dnet_raw_id));
		dnet_indexes_transform_index_id_raw(node, &id, shard_id);
		id_to_shard[id] = shard_id;

		dnet_io_attr &io = request_io_attrs[shard_id];
		memset(&io, 0, sizeof(io));

		io.size   = 100;
		io.offset = 0;
		io.flags  = get_ioflags() | DNET_IO_FLAGS_CACHE;
		memcpy(io.id, id.id, DNET_ID_SIZE);
		memcpy(io.parent, id.id, DNET_ID_SIZE);
	}

	async_get_index_metadata_result result(*this);
	get_index_metadata_callback callback = { sess, result, id_to_shard };
	sess.bulk_read(request_io_attrs).connect(callback, callback);

	return result;
}

async_get_index_metadata_result session::get_index_metadata(const std::string &index)
{
	dnet_raw_id raw_index;
	transform(index, raw_index);
	return get_index_metadata(raw_index);
}

struct merge_indexes_callback
{
	key id;
	session write_session;
	async_result_handler<write_result_entry> handler;

	/*!
	 * Comparator for tuples which sorts dnet_index_entry's by following properties:
	 * \li index id
	 * \li update time in seconds
	 * \li update time in nanoseconds
	 * \li size of index's data
	 *
	 * So more appropriate copy of index is the newest or with the biggest data
	 * in case if the time is equal.
	 */
	struct index_entry_comparator
	{
		bool operator ()(const std::tuple<size_t, dnet_index_entry> &first_tuple,
			const std::tuple<size_t, dnet_index_entry> &second_tuple) const
		{
			const auto &first = std::get<1>(first_tuple);
			const auto &second = std::get<1>(second_tuple);

			const int cmp = memcmp(first.index.id, second.index.id, DNET_ID_SIZE);
			if (cmp != 0)
				return cmp < 0;

			return std::make_tuple(first.time.tsec, first.time.tnsec, first.data.size())
				< std::make_tuple(second.time.tsec, second.time.tnsec, second.data.size());
		}
	};

	/*!
	 * This class returnes result of merged indexes one-by-one.
	 *
	 * It stores in the heap the biggest not-processed-yet from every group.
	 * If any element is poped from the heap it is replaced by the next element
	 * from the same group.
	 *
	 * When user asks for next element the following logic is applied:
	 * \li take the biggest element from the heap
	 * \li remove all elements from heap with the same id
	 *
	 * This is effective (O(n log k)) way to merge indexes.
	 */
	class index_entry_heap
	{
	public:
		index_entry_heap(std::vector<dnet_indexes> &&indexes) : m_indexes(std::move(indexes))
		{
			for (size_t i = 0; i < m_indexes.size(); ++i) {
				repopulate(i);
			}
		}

		bool has_next() const
		{
			return !m_heap.empty();
		}

		dnet_index_entry next()
		{
			dnet_index_entry result;
			std::tie(std::ignore, result) = m_heap.front();

			pop();

			while (!m_heap.empty() && memcmp(result.index.id, std::get<1>(m_heap.front()).index.id, DNET_ID_SIZE) == 0) {
				pop();
			}

			return result;
		}

	private:
		void pop()
		{
			index_entry_comparator comparator;

			size_t vector_id;
			std::tie(vector_id, std::ignore) = m_heap.front();

			std::pop_heap(m_heap.begin(), m_heap.end(), comparator);
			m_heap.pop_back();

			repopulate(vector_id);
		}

		void repopulate(size_t vector_id)
		{
			index_entry_comparator comparator;

			auto &vector = m_indexes[vector_id].indexes;

			if (!vector.empty()) {
				m_heap.emplace_back(vector_id, vector.back());
				vector.pop_back();
				std::push_heap(m_heap.begin(), m_heap.end(), comparator);
			}
		}

		std::vector<dnet_indexes> m_indexes;
		std::vector<std::tuple<size_t, dnet_index_entry>> m_heap;
	};

	void operator() (const sync_read_result &raw_indexes, const error_info &error)
	{
		logger &log = write_session.get_logger();

		if (error) {
			BH_LOG(log, DNET_LOG_ERROR, "%s: failed to read indexes: %s", dnet_dump_id(&id.id()), error.message());

			handler.complete(error);
			return;
		}

		std::vector<dnet_indexes> indexes;
		data_pointer valid_index_data;

		// Unpack all retrieved results if possible
		for (auto it = raw_indexes.begin(); it != raw_indexes.end(); ++it) {
			try {
				BH_LOG(log, DNET_LOG_DEBUG, "%s: unpacking indexes, size: %llu",
					dnet_dump_id(&id.id()), static_cast<unsigned long long>(it->file().size()));

				dnet_indexes tmp;
				indexes_unpack_raw(it->file(), &tmp);

				indexes.emplace_back(std::move(tmp));
				valid_index_data = it->file();
			} catch (std::bad_alloc &) {
				handler.complete(error_info(-ENOMEM, std::string()));
				return;
			} catch (std::exception &e) {
				BH_LOG(log, DNET_LOG_ERROR, "%s: failed to unpack indexes: %s", dnet_dump_id(&id.id()), e.what());
			}
		}

		if (indexes.empty()) {
			handler.complete(error_info());
			return;
		} else if (indexes.size() == 1) {
			indexes.front();

			write_session.write_data(id, valid_index_data, 0).connect(handler);
			return;
		}

		auto shard_id = indexes.front().shard_id;
		auto shard_count = indexes.front().shard_count;

		// Check if metadata of all indexes are the same
		for (auto it = indexes.begin(); it != indexes.end(); ++it) {
			/* skip checking unfilled indexes (believes that they are correct) */
			if (it->shard_id == 0 && it->shard_count == 0)
				continue;
			/* if first index was unfilled, use first filled index id and count for future checks */
			if (shard_id == 0 && shard_count == 0) {
				shard_id = it->shard_id;
				shard_count = it->shard_count;
				continue;
			}
			if (it->shard_id != shard_id || it->shard_count != shard_count) {
				BH_LOG(log, DNET_LOG_ERROR, "%s: mismatched indexes metadata: (%d, %d) vs (%d, %d)",
					dnet_dump_id(&id.id()), shard_id, shard_count, it->shard_id, it->shard_count);
				handler.complete(create_error(-EINVAL, id, "mismatched indexes metadata"));
				return;
			}
		}

		dnet_indexes result;
		result.shard_id = shard_id;
		result.shard_count = shard_count;

		// Merge all indexes
		index_entry_heap heap(std::move(indexes));
		while (heap.has_next())
			result.indexes.push_back(heap.next());

		// Head of the heap is the buggest element, so final list must be reversed
		std::reverse(result.indexes.begin(), result.indexes.end());

		// Pack indexes and write serialized data to server
		try {
			msgpack::sbuffer buffer;
			msgpack::pack(buffer, result);

			data_buffer tmp_buffer(DNET_INDEX_TABLE_MAGIC_SIZE + buffer.size());
			tmp_buffer.write(dnet_bswap64(DNET_INDEX_TABLE_MAGIC));
			tmp_buffer.write(buffer.data(), buffer.size());

			data_pointer data = std::move(tmp_buffer);

			write_session.write_data(id, data, 0).connect(handler);
		} catch (std::bad_alloc &) {
			handler.complete(error_info(-ENOMEM, std::string()));
		} catch (elliptics::error &e) {
			handler.complete(error_info(e.error_code(), e.error_message()));
		}
	}
};

async_write_result session::merge_indexes(const key &id, const std::vector<int> &from, const std::vector<int> &to)
{
	transform(id);

	async_write_result result(*this);

	session read_session = clone();
	read_session.set_checker(checkers::at_least_one);
	read_session.set_filter(filters::positive);
	read_session.set_exceptions_policy(session::no_exceptions);

	session write_session = clone();
	write_session.set_groups(to);
	write_session.set_filter(filters::all_with_ack);
	write_session.set_exceptions_policy(session::no_exceptions);

	merge_indexes_callback callback = {
		id,
		write_session,
		result
	};

	callback.handler.set_total(to.size());

	std::vector<async_read_result> read_results;

	// Read this index from every provided group
	for (auto it = from.begin(); it != from.end(); ++it) {
		session sess = read_session.clone();
		sess.set_checker(checkers::no_check);
		read_results.emplace_back(sess.read_data(id, std::vector<int>(1, *it), 0, 0));
	}

	aggregated(read_session, read_results.begin(), read_results.end()).connect(callback);

	return result;
}

/*!
 * \internal
 *
 * Logic of this recovery method is following:
 * \li run session::merge_indexes for every single shard of this index for every known group
 * \li run find_indexes to find every single object in this index
 * \li add this index to the list of indexes for every received object
 * \li ...
 * \li PROFIT
 *
 * Process is finished when any step fails or every step is succesfully completed.
 */
struct recover_index_callback : public std::enable_shared_from_this<recover_index_callback>
{
	key index;
	session sess;
	logger &log;
	async_result_handler<callback_result_entry> handler;
	std::atomic_size_t counter;
	std::mutex error_mutex;
	error_info total_error;

	recover_index_callback(const session &sess, const async_generic_result &result) :
		sess(sess), log(sess.get_logger()), handler(result), counter(0)
	{
	}

	void on_merge_finished(const error_info &error)
	{
		if (error) {
			handler.complete(error);
			return;
		}

		// Increment counter so we will know when last reply is received
		++counter;

		sess.clone().find_any_indexes(std::vector<dnet_raw_id>(1, index.raw_id())).connect(
			std::bind(&recover_index_callback::on_find_indexes_process, shared_from_this(), std::placeholders::_1),
			std::bind(&recover_index_callback::on_find_indexes_complete, shared_from_this(), std::placeholders::_1));
	}

	void on_find_indexes_process(const find_indexes_result_entry &entry)
	{
		for (auto it = entry.indexes.begin(); it != entry.indexes.end(); ++it) {
			BH_LOG(log, DNET_LOG_DEBUG, "recovery, index: %s, object: %s, data: %s",
				index.to_string().c_str(), dnet_dump_id_str(entry.id.id), it->data.to_string().c_str());
		}

		if (!entry.indexes.empty()) {
			// Increment counter so we will know when last reply is received
			++counter;

			// Add index to object's list of indexes
			session_set_indexes(sess, entry.id, entry.indexes,
				DNET_INDEXES_FLAGS_UPDATE_ONLY | DNET_INDEXES_FLAGS_NOINTERNAL).connect(
					std::bind(&recover_index_callback::on_update_indexes_process, shared_from_this(), std::placeholders::_1),
					std::bind(&recover_index_callback::on_update_indexes_complete, shared_from_this(), std::placeholders::_1));
		}
	}

	void on_find_indexes_complete(const error_info &error)
	{
		if (error) {
			// Something bad is happened, there were no successfull
			// find if this happened, so we are free to exit
			handler.complete(error);
		} else {
			decrement_counter();
		}
	}

	void on_update_indexes_process(const callback_result_entry &entry)
	{
		handler.process(entry);
	}

	void on_update_indexes_complete(const error_info &error)
	{
		if (error) {
			std::lock_guard<std::mutex> guard(error_mutex);
			if (!total_error)
				total_error = error;
		}

		decrement_counter();
	}

	void decrement_counter()
	{
		if (--counter == 0) {
			handler.complete(total_error);
		}
	}
};

async_generic_result session::recover_index(const key &index)
{
	transform(index);

	dnet_node *node = get_native_node();
	const int shard_count = dnet_node_get_indexes_shard_count(node);
	const std::vector<int> groups = get_groups();

	dnet_raw_id index_id;
	dnet_indexes_transform_index_prepare(node, &index.raw_id(), &index_id);

	std::vector<async_write_result> results;

	// Run merge_indexes for every single shard of this index
	for (int shard_id = 0; shard_id < shard_count; ++shard_id) {
		dnet_indexes_transform_index_id_raw(node, &index_id, shard_id);

		results.emplace_back(merge_indexes(index_id, groups, groups));
	}

	session sess = clone();
	sess.set_checker(checkers::no_check);
	sess.set_filter(filters::all_with_ack);
	sess.set_exceptions_policy(session::no_exceptions);

	async_generic_result result(sess);

	auto callback = std::make_shared<recover_index_callback>(sess, result);
	callback->index = index;

	aggregated(sess, results.begin(), results.end()).connect(
		std::bind(&async_result_handler<callback_result_entry>::process, callback->handler, std::placeholders::_1),
		std::bind(&recover_index_callback::on_merge_finished, callback, std::placeholders::_1));

	return result;
}

} } // ioremap::elliptics
