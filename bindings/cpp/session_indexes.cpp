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

/*
 * There are several modifying index methods with similiar behaviour.
 * Some of them send requests to 'object's list of indexes', other to
 * 'index's list of objects', some to both of them.
 *
 * This method should suit all of them and it's behaviour depends on
 * flags passed as an argument.
 */
static async_set_indexes_result session_set_indexes(session &orig_sess, const key &request_id,
		const std::vector<index_entry> &indexes, uint32_t flags)
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

	session sess = orig_sess.clone();
	sess.set_filter(filters::all_with_ack);
	sess.set_checker(checkers::no_check);
	sess.set_exceptions_policy(session::no_exceptions);

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

	const bool noupdate = (flags & DNET_INDEXES_FLAGS_NOUPDATE);
	const bool nointernal = (flags & DNET_INDEXES_FLAGS_NOINTERNAL);
	flags &= ~(DNET_INDEXES_FLAGS_NOUPDATE | DNET_INDEXES_FLAGS_NOINTERNAL);

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
			id.trace_id = sess.get_trace_id();
			indexes_id.group_id = id.group_id;
			indexes_id.trace_id = id.trace_id;

			groups[0] = id.group_id;
			sess.set_groups(groups);

			control.set_key(indexes_id);

			async_generic_result result(sess);
			auto cb = createCallback<single_cmd_callback>(sess, result, control);

			startCallback(cb);

			results.emplace_back(std::move(result));
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

		const int shard_id = dnet_indexes_get_shard_id(node, &key(indexes_id).raw_id());

		for (size_t i = 0; i < indexes.size(); ++i) {
			const index_entry &index = indexes[i];

			dnet_indexes_transform_index_id(node, &index.index, &tmp_entry_id, shard_id);
			memcpy(id.id, tmp_entry_id.id, DNET_ID_SIZE);

			entry->size = index.data.size();
			entry->flags = (flags & DNET_INDEXES_FLAGS_UPDATE_ONLY) ? DNET_INDEXES_FLAGS_INTERNAL_INSERT : DNET_INDEXES_FLAGS_INTERNAL_REMOVE;
			control.set_data(data.data(), sizeof(dnet_indexes_request) +
					sizeof(dnet_indexes_request_entry) + index.data.size());
			memcpy(entry_data, index.data.data(), index.data.size());

			for (size_t j = 0; j < known_groups.size(); ++j) {
				id.group_id = known_groups[j];

				groups[0] = id.group_id;
				sess.set_groups(groups);

				control.set_key(id);

				async_generic_result result(sess);
				auto cb = createCallback<single_cmd_callback>(sess, result, control);

				startCallback(cb);

				results.emplace_back(std::move(result));
			}
		}
	}

	auto result = aggregated(sess, results.begin(), results.end());

	async_update_indexes_result final_result(orig_sess);

	async_update_indexes_handler handler(final_result);

	result.connect(std::bind(on_update_index_entry, handler, std::placeholders::_1),
		std::bind(on_update_index_finished, handler, std::placeholders::_1));

	dnet_log(orig_sess.get_native_node(), DNET_LOG_INFO, "%s: key: %s, indexes: %zd\n",
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

async_generic_result session::remove_index_internal(const dnet_raw_id &id)
{
	async_generic_result result(*this);
	auto cb = createCallback<remove_index_callback>(*this, result, id);
	mix_states(cb->groups);

	startCallback(cb);
	return result;
}

async_generic_result session::remove_index_internal(const std::string &id)
{
	key kid(id);
	kid.transform(*this);
	return remove_index_internal(kid.raw_id());
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

		logger log = sess.get_logger();
		if (log.get_log_level() >= DNET_LOG_DEBUG) {
			char index_name[2 * DNET_ID_SIZE + 1];
			char object_name[2 * DNET_ID_SIZE + 1];
			dnet_dump_id_len_raw(index_id.id, DNET_DUMP_NUM, index_name);
			dnet_dump_id_len_raw(entry.id.id, DNET_DUMP_NUM, object_name);

			sess.get_logger().print(DNET_LOG_DEBUG, "on_remove_index: Removed index %s from object %s", index_name, object_name);
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

async_generic_result session::remove_index(const dnet_raw_id &id, bool remove_data)
{
	using namespace std::placeholders;
	async_generic_result result(*this);

	session sess = clone();
	sess.set_exceptions_policy(no_exceptions);
	sess.set_filter(filters::all_with_ack);

	auto functor = std::make_shared<on_remove_index>(sess, result);
	functor->index_id = id;
	functor->index_id_list.assign(1, id);
	functor->index_entry_list.assign(1, index_entry(id, data_pointer()));
	functor->remove_data = remove_data;
	find_all_indexes(functor->index_id_list).connect(
		std::bind(&on_remove_index::on_find_entry, functor, _1),
		std::bind(&on_remove_index::on_find_finished, functor, _1));

	return result;
}

async_generic_result session::remove_index(const std::string &id, bool remove_data)
{
	key kid(id);
	kid.transform(*this);
	return remove_index(kid.raw_id(), remove_data);
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

static void on_find_indexes_process(session sess, std::shared_ptr<find_indexes_callback::id_map> convert_map,
	async_result_handler<find_indexes_result_entry> handler, const callback_result_entry &entry)
{
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
				sess.get_logger().print(DNET_LOG_ERROR, "%s: on_find_indexes_process, unknown id", dnet_dump_id_str(id.id));
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

	session sess = clone();
	sess.set_filter(filters::positive);
	sess.set_checker(checkers::no_check);
	sess.set_exceptions_policy(session::no_exceptions);

	async_generic_result raw_result(sess);

	auto cb = createCallback<find_indexes_callback>(sess, indexes, intersect, raw_result);
	auto convert_map = std::make_shared<find_indexes_callback::id_map>(/*std::move(*/cb->convert_map/*)*/);
	mix_states(indexes[0], cb->groups);
	startCallback(cb);

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

		for (auto it = result.indexes.begin(); it != result.indexes.end(); ++it)
			handler.process(*it);
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

} } // ioremap::elliptics
