#include "session_indexes.hpp"
#include "callback_p.h"
#include "functional_p.h"
#include "../../include/elliptics/utils.hpp"

namespace ioremap { namespace elliptics {

static dnet_id indexes_generate_id(session &sess, const dnet_id &data_id)
{
	// TODO: Better id for storing the tree?
	std::string key;
	key.reserve(sizeof(data_id.id) + 5);
	key.resize(sizeof(data_id.id));
	memcpy(&key[0], data_id.id, sizeof(data_id.id));
	key += "index";

	dnet_id id;
	sess.transform(key, id);
	id.group_id = 0;
	id.type = 0;

	return id;
}

struct update_indexes_functor : public std::enable_shared_from_this<update_indexes_functor>
{
	ELLIPTICS_DISABLE_COPY(update_indexes_functor)

	enum update_index_action {
		insert_data,
		remove_data
	};

	update_indexes_functor(session &sess, const async_update_indexes_result &result, const key &request_id,
		const std::vector<index_entry> &input_indexes, const dnet_id &id)
		: sess(sess), handler(result), request_id(request_id), id(id), finished(0)
#ifdef SMAP_DEBUG
		, smap_failed(0)
#endif
	{
		indexes.indexes = input_indexes;
		std::sort(indexes.indexes.begin(), indexes.indexes.end(), dnet_raw_id_less_than<>());
		msgpack::pack(buffer, indexes);
#ifdef SMAP_DEBUG
		dnet_current_time(&smap_time);
#endif
	}

	/*
	 * update_indexes_functor::request_id holds key ID to add/remove from stored indexes
	 * update_indexes_functor::id holds key which contains list of all indexes which contain request_id
	 */

	session sess;
	async_result_handler<callback_result_entry> handler;
	key request_id;
	data_pointer request_data;
	// indexes to update
	dnet_indexes indexes;
	dnet_id id;

	msgpack::sbuffer buffer;
	// already updated indexes - they are read from storage and changed
	dnet_indexes remote_indexes;
	std::mutex previous_data_mutex;
	std::map<dnet_raw_id, data_pointer, dnet_raw_id_less_than<>> previous_data;
	std::vector<index_entry> inserted_ids;
	std::vector<index_entry> removed_ids;
	std::vector<dnet_raw_id> success_inserted_ids;
	std::vector<dnet_raw_id> success_removed_ids;
	std::mutex mutex;
	size_t finished;
	error_info exception;

#ifdef SMAP_DEBUG
	std::mutex smap_lock;
	std::map<void *, int> smap;
	int smap_failed;
	dnet_time smap_time;
#endif
	/*!
	 * Update data-object table for certain secondary index.
	 * This function is called when write-cas() has downloaded index data,
	 * it updates and returns it
	 *
	 * @index_data is what client provided
	 * @data is what was downloaded from the storage
	 */
	template <update_index_action action>
	data_pointer convert_index_table(const data_pointer &index_data, const data_pointer &data)
	{
		dnet_indexes indexes;
		if (!data.empty())
			indexes_unpack(data, &indexes, "convert_index_table");

		// Construct index entry
		index_entry request_index;
		request_index.index = request_id.raw_id();
		request_index.data = index_data;

		auto it = std::lower_bound(indexes.indexes.begin(), indexes.indexes.end(),
			request_index, dnet_raw_id_less_than<skip_data>());
		if (it != indexes.indexes.end() && it->index == request_index.index) {
			// It's already there
			if (action == insert_data) {
				if (it->data == request_index.data) {
					// All's ok, keep it untouched
					return data;
				} else {
					// Data is not correct, remember current value due to possible rollback
					std::lock_guard<std::mutex> lock(previous_data_mutex);
					previous_data[it->index] = it->data;
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

#ifdef SMAP_DEBUG
		{
			std::lock_guard<std::mutex> guard(smap_lock);
			auto it = smap.find((void *)&index_data);
			if (it == smap.end())
				smap[(void *)&index_data] = buffer.size();
			else
				smap_failed++;
		}
#endif

		return data_pointer::copy(buffer.data(), buffer.size());
	}

	/*!
	 * All changes were reverted - succesfully or not.
	 * Anyway, notify the user.
	 */
	void on_index_table_revert_finished()
	{
		if (finished != success_inserted_ids.size() + success_removed_ids.size())
			return;

		handler.complete(exception);
	}

	/*!
	 * Reverting of certain index was finished with error \a err.
	 */
	void on_index_table_reverted(const error_info &err)
	{
		std::lock_guard<std::mutex> lock(mutex);
		++finished;

		if (err) {
			exception = err;
		}

		on_index_table_revert_finished();
	}

	/*!
	 * Called for every index being updated.
	 * When all indexes are updated, check if any update failed, in this case all successfull changes must be reverted.
	 */
	void on_index_table_update_finished()
	{
		if (finished != inserted_ids.size() + removed_ids.size())
			return;

		finished = 0;

#ifdef SMAP_DEBUG
		long total_size = 0;
		for (auto sz : smap)
			total_size += sz.second;

		dnet_time tmp;
		dnet_current_time(&tmp);

		tmp.tsec -= smap_time.tsec;
		if (tmp.tnsec < smap_time.tnsec) {
			tmp.tsec--;
			tmp.tnsec += 1000000000;
		}

		tmp.tnsec -= smap_time.tnsec;

		std::cout.unsetf(std::ios::floatfield); 
		std::cout.precision(6);
		std::cout << "id: " << request_id.to_string() <<
			", indexes: " << smap.size() <<
			", total-size: " << total_size <<
			", failed: " << smap_failed <<
			", time: " << tmp.tsec << "." << tmp.tnsec / 1000 <<
			std::endl;
#endif
		dnet_id tmp_id;
		memset(&tmp_id, 0, sizeof(tmp_id));

		if (success_inserted_ids.size() != inserted_ids.size()
			|| success_removed_ids.size() != removed_ids.size()) {

			if (success_inserted_ids.empty() && success_removed_ids.empty()) {
				handler.complete(exception);
				return;
			}

			/*
			 * Revert all successfully made changes, since something went wrong
			 */
			for (size_t i = 0; i < success_inserted_ids.size(); ++i) {
				const auto &remote_id = success_inserted_ids[i];
				memcpy(tmp_id.id, remote_id.id, sizeof(tmp_id.id));
				sess.write_cas(tmp_id,
					std::bind(&update_indexes_functor::convert_index_table<remove_data>,
						shared_from_this(),
						data_pointer(),
						std::placeholders::_1),
				0).connect(std::bind(&update_indexes_functor::on_index_table_reverted,
					shared_from_this(),
					std::placeholders::_2));
			}

			for (size_t i = 0; i < success_removed_ids.size(); ++i) {
				const auto &remote_id = success_removed_ids[i];
				memcpy(tmp_id.id, remote_id.id, sizeof(tmp_id.id));
				sess.write_cas(tmp_id,
					std::bind(&update_indexes_functor::convert_index_table<insert_data>,
						shared_from_this(),
						previous_data[remote_id],
						std::placeholders::_1),
				0).connect(std::bind(&update_indexes_functor::on_index_table_reverted,
					shared_from_this(),
					std::placeholders::_2));
			}
		} else {
			handler.complete(error_info());
			return;
		}
	}

	/*!
	 * Function is called after we updated index table (secondary index) for given id.
	 * Update status is stored in error_info
	 */
	template <update_index_action action>
	void on_index_table_updated(const dnet_raw_id &id, const error_info &err)
	{
		std::lock_guard<std::mutex> lock(mutex);
		++finished;

		if (err) {
			exception = err;
		} else {
			if (action == insert_data) {
				success_inserted_ids.push_back(id);
			} else {
				success_removed_ids.push_back(id);
			}
		}

		on_index_table_update_finished();
	}

	/*!
	 * Replace object's index cache (list of indexes given object is present in) by new table.
	 * Store them into @remote_indexes
	 */
	data_pointer convert_object_indexes(const data_pointer &data)
	{
		if (data.empty()) {
			remote_indexes.indexes.clear();
		} else {
			indexes_unpack(data, &remote_indexes, "convert_object_indexes");
		}

		return data_pointer::from_raw(const_cast<char *>(buffer.data()), buffer.size());
	}

	/*!
	 * Handle result of object indexes' table update
	 * This method is called when list of indexes for given object has been downloaded
	 */
	void on_object_indexes_updated(const sync_write_result &result, const error_info &err)
	{
		for (auto it = result.begin(); it != result.end(); ++it)
			handler.process(*it);
		// If there was an error - notify user about this.
		// At this state there were no changes at the storage yet.
		if (err) {
			handler.complete(err);
			return;
		}

		try {
			// We "insert" items also to update their data
			std::set_difference(indexes.indexes.begin(), indexes.indexes.end(),
				remote_indexes.indexes.begin(), remote_indexes.indexes.end(),
				std::back_inserter(inserted_ids), dnet_raw_id_less_than<>());
			// Remove index entries which are not present in the new list of indexes
			std::set_difference(remote_indexes.indexes.begin(), remote_indexes.indexes.end(),
				indexes.indexes.begin(), indexes.indexes.end(),
				std::back_inserter(removed_ids), dnet_raw_id_less_than<skip_data>());

			if (inserted_ids.empty() && removed_ids.empty()) {
				handler.complete(error_info());
				return;
			}

			dnet_id tmp_id;
			tmp_id.group_id = 0;
			tmp_id.type = 0;

			/*
			 * Iterate over all indexes and update those which changed.
			 * 'Changed' here means we want to either put or remove
			 * update_indexes_functor::request_id to/from given index
			 */
			for (size_t i = 0; i < inserted_ids.size(); ++i) {
				memcpy(tmp_id.id, inserted_ids[i].index.id, sizeof(tmp_id.id));
				sess.write_cas(tmp_id,
					std::bind(&update_indexes_functor::convert_index_table<insert_data>,
						shared_from_this(),
						inserted_ids[i].data,
						std::placeholders::_1),
					0).connect(std::bind(&update_indexes_functor::on_index_table_updated<insert_data>,
						shared_from_this(),
						inserted_ids[i].index,
						std::placeholders::_2));
			}

			for (size_t i = 0; i < removed_ids.size(); ++i) {
				memcpy(tmp_id.id, removed_ids[i].index.id, sizeof(tmp_id.id));
				sess.write_cas(tmp_id,
					std::bind(&update_indexes_functor::convert_index_table<remove_data>,
						shared_from_this(),
						removed_ids[i].data,
						std::placeholders::_1),
					0).connect(std::bind(&update_indexes_functor::on_index_table_updated<remove_data>,
						shared_from_this(),
						removed_ids[i].index,
						std::placeholders::_2));
			}
		} catch (...) {
			handler.complete(error_info());
			return;
		}
	}

	void start()
	{
		session_scope scope(sess);
		sess.set_filter(filters::all_with_ack);
		sess.set_exceptions_policy(session::no_exceptions);
		sess.write_cas(id, bind_method(shared_from_this(), &update_indexes_functor::convert_object_indexes), 0)
			.connect(bind_method(shared_from_this(), &update_indexes_functor::on_object_indexes_updated));
	}
};

// Update \a indexes for \a request_id
// Result is pushed to \a handler
async_update_indexes_result session::update_indexes(const key &request_id, const std::vector<index_entry> &indexes)
{
	transform(request_id);
	async_update_indexes_result result(*this);

	auto functor = std::make_shared<update_indexes_functor>(
		*this, result, request_id, indexes, indexes_generate_id(*this, request_id.id()));
	functor->start();

	return result;
}

async_update_indexes_result session::update_indexes(const key &id, const std::vector<std::string> &indexes, const std::vector<data_pointer> &datas)
{
	if (datas.size() != indexes.size())
		throw_error(-EINVAL, id, "session::update_indexes: indexes and datas sizes mismtach");

	dnet_id tmp;
	std::vector<index_entry> raw_indexes;
	raw_indexes.resize(indexes.size());

	for (size_t i = 0; i < indexes.size(); ++i) {
		transform(indexes[i], tmp);
		memcpy(raw_indexes[i].index.id, tmp.id, sizeof(tmp.id));
		raw_indexes[i].data = datas[i];
	}

	return update_indexes(id, raw_indexes);
}

struct find_indexes_handler
{
	async_result_handler<find_indexes_result_entry> handler;
	size_t ios_size;

	void operator() (const sync_read_result &bulk_result, const error_info &err)
	{
		std::vector<find_indexes_result_entry> result;

		if (err == -ENOENT) {
			handler.complete(error_info());
			return;
		} else if (err) {
			handler.complete(err);
			return;
		}

		if (bulk_result.size() != ios_size) {
			handler.complete(error_info());
			return;
		}

		try {
			dnet_indexes tmp;
			indexes_unpack(bulk_result[0].file(), &tmp, "find_indexes_handler1");
			result.resize(tmp.indexes.size());
			for (size_t i = 0; i < tmp.indexes.size(); ++i) {
				find_indexes_result_entry &entry = result[i];
				entry.id = tmp.indexes[i].index;
				entry.indexes.push_back(std::make_pair(
					reinterpret_cast<dnet_raw_id&>(bulk_result[0].command()->id),
					tmp.indexes[i].data));
			}

			for (size_t i = 1; i < bulk_result.size() && !result.empty(); ++i) {
				auto raw = reinterpret_cast<dnet_raw_id&>(bulk_result[i].command()->id);
				tmp.indexes.resize(0);
				indexes_unpack(bulk_result[i].file(), &tmp, "find_indexes_handler2");
				auto it = std::set_intersection(result.begin(), result.end(),
					tmp.indexes.begin(), tmp.indexes.end(),
					result.begin(), dnet_raw_id_less_than<skip_data>());
				result.resize(it - result.begin());
				std::set_intersection(tmp.indexes.begin(), tmp.indexes.end(),
					result.begin(), result.end(),
					tmp.indexes.begin(), dnet_raw_id_less_than<skip_data>());
				auto jt = tmp.indexes.begin();
				for (auto kt = result.begin(); kt != result.end(); ++kt, ++jt) {
					kt->indexes.push_back(std::make_pair(raw, jt->data));
				}
			}
		} catch (std::exception &e) {
			handler.complete(create_error(-EINVAL, "%s", e.what()));
			return;
		}

		for (auto it = result.begin(); it != result.end(); ++it)
			handler.process(*it);
		handler.complete(error_info());
	}
};

async_find_indexes_result session::find_indexes(const std::vector<dnet_raw_id> &indexes)
{
	async_find_indexes_result result(*this);
	async_result_handler<find_indexes_result_entry> handler(result);

	if (indexes.size() == 0) {
		handler.complete(error_info());
		return result;
	}

	std::vector<dnet_io_attr> ios;
	struct dnet_io_attr io;
	memset(&io, 0, sizeof(io));

	for (size_t i = 0; i < indexes.size(); ++i) {
		memcpy(io.id, indexes[i].id, sizeof(dnet_raw_id));
		ios.push_back(io);
	}

	find_indexes_handler functor = { handler, ios.size() };
	bulk_read(ios).connect(functor);

	return result;
}

async_find_indexes_result session::find_indexes(const std::vector<std::string> &indexes)
{
	dnet_id tmp;
	std::vector<dnet_raw_id> raw_indexes;
	raw_indexes.resize(indexes.size());

	for (size_t i = 0; i < indexes.size(); ++i) {
		transform(indexes[i], tmp);
		memcpy(raw_indexes[i].id, tmp.id, sizeof(tmp.id));
	}

	return find_indexes(raw_indexes);
}

struct check_indexes_handler
{
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
			indexes_unpack(read_result[0].file(), &result, "check_indexes_handler");
		} catch (std::exception &e) {
			handler.complete(create_error(-EINVAL, request_id, "%s", e.what()));
			return;
		}

		for (auto it = result.indexes.begin(); it != result.indexes.end(); ++it)
			handler.process(*it);
		handler.complete(error_info());
	}
};

async_check_indexes_result session::check_indexes(const key &request_id)
{
	async_check_indexes_result result(*this);
	dnet_id id = indexes_generate_id(*this, request_id.id());

	check_indexes_handler functor = { request_id, result };
	read_latest(id, 0, 0).connect(functor);

	return result;
}

} } // ioremap::elliptics
