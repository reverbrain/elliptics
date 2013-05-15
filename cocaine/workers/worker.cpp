#include "worker.hpp"
#include "../../bindings/cpp/session_indexes.hpp"
#include "../../bindings/cpp/functional_p.h"
#include <elliptics/debug.hpp>
#include <cocaine/json.hpp>
#include <fstream>

namespace ioremap { namespace elliptics {

#ifdef debug
#	undef debug
#endif
#define debug() if (1) {} else std::cerr
//#define debug() std::cerr << __PRETTY_FUNCTION__ << ": " << __LINE__ << " "

struct update_indexes_functor : public std::enable_shared_from_this<update_indexes_functor>
{
	ELLIPTICS_DISABLE_COPY(update_indexes_functor)

	update_indexes_functor(session &sess, const std::shared_ptr<cocaine::framework::upstream_t> &response,
		const exec_context &context, const key &request_id,
		const std::vector<index_entry> &input_indexes, const dnet_id &id)
		: sess(sess), response(response), context(context), request_id(request_id), id(id), finished(0)
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
	std::shared_ptr<cocaine::framework::upstream_t> response;
	exec_context context;
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
	update_result result;
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
	 * All changes were reverted - successfully or not.
	 * Anyway, notify the user.
	 */
	void on_index_table_revert_finished()
	{
		if (finished != success_inserted_ids.size() + success_removed_ids.size())
			return;

		complete(exception);
	}

	/*!
	 * Reverting of certain index was finished with error \a err.
	 */
	void on_index_table_reverted(const error_info &err)
	{
		debug() << err.message() << std::endl;
		std::lock_guard<std::mutex> lock(mutex);
		++finished;

		if (err) {
			exception = err;
		}

		on_index_table_revert_finished();
	}

	/*!
	 * Called for every index being updated.
	 * When all indexes are updated, check if any update failed, in this case all successful changes must be reverted.
	 */
	void on_index_table_update_finished()
	{
		if (finished != inserted_ids.size() + removed_ids.size())
			return;
		debug() << std::endl;

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
		index_entry entry;

		if (success_inserted_ids.size() != inserted_ids.size()
			|| success_removed_ids.size() != removed_ids.size()) {
			complete(exception);

//			if (success_inserted_ids.empty() && success_removed_ids.empty()) {
//				complete(exception);
//				return;
//			}

//			/*
//			 * Revert all successfully made changes, since something went wrong
//			 */
//			for (size_t i = 0; i < success_inserted_ids.size(); ++i) {
//				const auto &remote_id = success_inserted_ids[i];
//				entry.index = remote_id;
//				update_index_table(request_id.id(), entry, application::remove_data)
//					.connect(std::bind(&update_indexes_functor::on_index_table_reverted,
//						shared_from_this(),
//						std::placeholders::_2));
//			}

//			for (size_t i = 0; i < success_removed_ids.size(); ++i) {
//				const auto &remote_id = success_removed_ids[i];
//				entry.index = remote_id;
//				entry.data = previous_data[remote_id];
//				update_index_table(request_id.id(), entry, application::insert_data)
//					.connect(std::bind(&update_indexes_functor::on_index_table_reverted,
//						shared_from_this(),
//						std::placeholders::_2));
//			}
		} else {
			complete(error_info());
			return;
		}
	}

	/*!
	 * Function is called after we updated index table (secondary index) for given id.
	 * Update status is stored in error_info
	 */
	template <application::update_index_action action>
	void on_index_table_updated(const dnet_raw_id &id, const error_info &err)
	{
		debug() << std::endl;
		std::lock_guard<std::mutex> lock(mutex);
		++finished;

		update_result_entry entry;
		entry.id = id;
		entry.error = err.code();
		result.indexes.push_back(entry);

		if (err) {
			exception = err;
		} else {
			if (action == application::insert_data) {
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
		debug() << std::endl;
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
	void on_object_indexes_updated(const sync_write_result &, const error_info &err)
	{
		debug() << std::endl;

		// If there was an error - notify user about this.
		// At this state there were no changes at the storage yet.
		debug() << std::endl << ('"' + err.message() + '"');
		if (err) {
			debug() << std::endl;
			complete(err);
			return;
		}
		debug() << std::endl;

		try {
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
				complete(error_info());
				return;
			}
			debug() << std::endl;

			dnet_raw_id tmp_id;

			/*
			 * Iterate over all indexes and update those which changed.
			 * 'Changed' here means we want to either put or remove
			 * update_indexes_functor::request_id to/from given index
			 */
			for (size_t i = 0; i < inserted_ids.size(); ++i) {
				memcpy(tmp_id.id, inserted_ids[i].index.id, sizeof(tmp_id.id));
				update_index_table(request_id.id(), inserted_ids[i], application::insert_data)
					.connect(std::bind(&update_indexes_functor::on_index_table_updated<application::insert_data>,
						shared_from_this(),
						inserted_ids[i].index,
						std::placeholders::_2));
			}
			debug() << std::endl;

			for (size_t i = 0; i < removed_ids.size(); ++i) {
				memcpy(tmp_id.id, removed_ids[i].index.id, sizeof(tmp_id.id));
				update_index_table(request_id.id(), removed_ids[i], application::remove_data)
					.connect(std::bind(&update_indexes_functor::on_index_table_updated<application::remove_data>,
						shared_from_this(),
						removed_ids[i].index,
						std::placeholders::_2));
			}
			debug() << std::endl;
		} catch (...) {
			debug() << std::endl;
			complete(error_info());
			return;
		}
		debug() << std::endl;
	}

	async_exec_result update_index_table(const dnet_id &object, const index_entry &index, application::update_index_action action)
	{
		dnet_id index_id;
		memcpy(index_id.id, index.index.id, sizeof(index_id.id));
		index_id.group_id = object.group_id;
		index_id.type = 0;

		debug() << std::endl;
		update_index_request request;
		request.id = object;
		request.index = index;
		request.remove = (action == application::remove_data);

		msgpack::sbuffer buffer;
		msgpack::pack(&buffer, request);
		debug() << std::endl;

		return sess.exec(&index_id, "indexes@update_final", data_pointer::copy(buffer.data(), buffer.size()));
	}

	void complete(const error_info &error)
	{
		debug() << error.message() << std::endl;

		msgpack::sbuffer buffer;
		msgpack::pack(&buffer, result);

//		if (error) {
//			response->error(cocaine::invocation_error, error.message());
//		} else {
//			response->close();
//		}
		sess.reply(context, data_pointer::from_raw(buffer.data(), buffer.size()), exec_context::final);
	}

	void start()
	{
		debug() << std::endl;
		session sess_copy = sess.clone();
		sess_copy.set_filter(filters::all_with_ack);
		sess_copy.set_exceptions_policy(session::no_exceptions);
		sess_copy.set_cflags(DNET_FLAGS_NOLOCK);
		sess_copy.write_cas(id, bind_method(shared_from_this(), &update_indexes_functor::convert_object_indexes), 0)
			.connect(bind_method(shared_from_this(), &update_indexes_functor::on_object_indexes_updated));
	}
};

application::application(std::shared_ptr<cocaine::framework::service_manager_t> service_manager)
	: cocaine::framework::application<application>(service_manager)
{
}

void application::initialize()
{
	debug() << std::endl;
	std::ifstream config;
	config.open("config.json");
	if (!config)
	    throw cocaine::configuration_error_t("can not open file \"config.json\"");

	debug() << std::endl;
	Json::Value args;
	Json::Reader reader;
	if (!reader.parse(config, args, false))
	    throw cocaine::configuration_error_t("can not parse \"config.json\"");

	debug() << std::endl;
	try {
	    m_logger.reset(new file_logger(args.get("node-log", "/dev/stderr").asCString(), DNET_LOG_DATA));
	    m_node.reset(new node(*m_logger));
	} catch (std::exception &e) {
	    throw cocaine::configuration_error_t(e.what());
	}

	debug() << std::endl;
	Json::Value remotes = args.get("remotes", Json::arrayValue);
	if (remotes.size() == 0) {
	    throw cocaine::configuration_error_t("no remotes have been specified");
	}
	int remotes_added = 0;
	for (Json::ArrayIndex index = 0; index < remotes.size(); ++index) {
	    try {
		m_node->add_remote(remotes[index].asCString());
		++remotes_added;
	    } catch (...) {
		// We don't care, really
	    }
	}
	if (remotes_added == 0) {
	    throw cocaine::configuration_error_t("no remotes were added successfully");
	}
	debug() << std::endl;

//	Json::Value groups = args.get("groups", Json::arrayValue);
//	if (groups.size() == 0) {
//	    throw cocaine::configuration_error_t("no groups have been specified");
//	}
//	std::transform(groups.begin(), groups.end(), std::back_inserter(m_groups),
//		std::bind(&Json::Value::asInt, std::placeholders::_1));
	debug() << std::endl;

	on<on_update_base>("indexes@update_base");
	on<on_update_final>("indexes@update_final");
}

session application::create_session()
{
	session sess(*m_node);
//	sess.set_groups(m_groups);
	return sess;
}

void application::on_update_base::on_chunk(const char *chunk, size_t size)
{
	exec_context context(data_pointer::copy(chunk, size));

	debug() << context.event() << std::endl;

	update_request request;
	debug() << std::endl;

	data_pointer data = context.data();
	debug() << std::endl;
	msgpack::unpacked msg;
	msgpack::unpack(&msg, data.data<char>(), data.size());
	debug() << std::endl;
	msg.get().convert(&request);
	debug() << std::endl;

	debug() << std::endl;

	COCAINE_LOG_DEBUG(app()->service_manager()->get_system_logger(),
		"Update request: %s", dnet_dump_id_str(request.id.id));

	debug() << std::endl;
	update_indexes(context, request.id, request.indexes);
}

void application::on_update_base::on_error(int code, const std::string &message)
{
	debug() << "code: " << code << ", message: " << message << std::endl;
}

void application::on_update_base::on_close()
{
	debug() << std::endl;
}

void application::on_update_base::update_indexes(const exec_context &context, const dnet_id &request_id, const std::vector<index_entry> &indexes)
{
	debug() << "group_id: " << request_id.group_id << std::endl;

	auto session = app()->create_session();
	session.set_groups(std::vector<int>(1, request_id.group_id));

	debug() << std::endl;
	auto functor = std::make_shared<update_indexes_functor>(
		session, response(), context, request_id,
		indexes, indexes_generate_id(session, request_id));
	functor->start();
}

void application::on_update_final::on_chunk(const char *chunk, size_t size)
{
	exec_context context(data_pointer::copy(chunk, size));

	update_index_request request;

	data_pointer data = context.data();
	debug() << std::endl;
	msgpack::unpacked msg;
	msgpack::unpack(&msg, data.data<char>(), data.size());
	debug() << std::endl;
	msg.get().convert(&request);
	debug() << std::endl;

	update_index(context, request.id, request.index, request.remove ? remove_data : insert_data);
}

void application::on_update_final::on_error(int code, const std::string &message)
{
	debug() << "code: " << code << ", message: " << message << std::endl;
}

void application::on_update_final::on_close()
{
}

void application::on_update_final::update_index(const exec_context &context, const dnet_id &request_id, const index_entry &index, update_index_action action)
{
	dnet_id tmp_id;
	tmp_id.group_id = 0;
	tmp_id.type = 0;
	memcpy(tmp_id.id, index.index.id, sizeof(tmp_id.id));

	session sess = app()->create_session();
	sess.set_groups(std::vector<int>(1, request_id.group_id));
	sess.set_cflags(DNET_FLAGS_NOLOCK);

	static char request_id_str[2 * DNET_ID_SIZE + 1];
	static char index_str[2 * DNET_ID_SIZE + 1];

	debug() << "object: " << dnet_dump_id_len_raw(request_id.id, DNET_DUMP_NUM, request_id_str)
		<< ", index: " << dnet_dump_id_len_raw(index.index.id, DNET_DUMP_NUM, index_str)
		<< std::endl;

	typedef data_pointer (on_update_final::*func_type)(const dnet_id &, const data_pointer            &, const data_pointer &);

	sess.write_cas(tmp_id,
		std::bind(action == insert_data
				? static_cast<func_type>(&on_update_final::convert_index_table<insert_data>)
				: static_cast<func_type>(&on_update_final::convert_index_table<remove_data>),
			shared_from_this(),
			request_id,
			index.data,
			std::placeholders::_1),
	0).connect(std::bind(&on_update_final::on_write_finished,
		shared_from_this(),
		sess,
		context,
		std::placeholders::_2));
}

void application::on_update_final::on_write_finished(session sess, const exec_context &context, const error_info &error)
{
	debug() << ('"' + error.message() + '"') << std::endl;
//	if (error) {
//		response()->error(cocaine::invocation_error, error.message());
//	} else {
//		response()->close();
//	}
	sess.reply(context, error.message(), exec_context::final);
}

/*!
 * Update data-object table for certain secondary index.
 * This function is called when write-cas() has downloaded index data,
 * it updates and returns it
 *
 * @index_data is what client provided
 * @data is what was downloaded from the storage
 */
template <application::update_index_action action>
data_pointer application::on_update_final::convert_index_table(const dnet_id &request_id, const data_pointer &index_data, const data_pointer &data)
{
	debug() << std::endl;
	dnet_indexes indexes;
	if (!data.empty())
		indexes_unpack(data, &indexes, "convert_index_table");

	// Construct index entry
	index_entry request_index;
	memcpy(request_index.index.id, request_id.id, sizeof(request_index.index.id));
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
				m_previous_data = it->data;
//				std::lock_guard<std::mutex> lock(previous_data_mutex);
//				previous_data[it->index] = it->data;
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

} } // namespace ioremap::elliptics

int main(int argc, char **argv)
{
	debug() << std::endl;
	return cocaine::framework::worker_t::run<ioremap::elliptics::application>(argc, argv);
}
