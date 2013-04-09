#include "session_indexes.hpp"
#include "callback_p.h"

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

struct update_indexes_data
{
	typedef std::shared_ptr<update_indexes_data> ptr;

	update_indexes_data(session &sess) : sess(sess) {}

	session sess;
	std::function<void (const std::exception_ptr &)> handler;
	key request_id;
	data_pointer request_data;
	// indexes to set
	dnet_indexes indexes;
	dnet_id id;

	msgpack::sbuffer buffer;
	// currently set indexes
	dnet_indexes remote_indexes;
	std::mutex previous_data_mutex;
	std::map<dnet_raw_id, data_pointer, dnet_raw_id_less_than<>> previous_data;
	std::vector<index_entry> inserted_ids;
	std::vector<index_entry> removed_ids;
	std::vector<dnet_raw_id> success_inserted_ids;
	std::vector<dnet_raw_id> success_removed_ids;
	std::mutex mutex;
	size_t finished;
	std::exception_ptr exception;

	// basic functor which is able to update secondary index for object
	struct update_functor
	{
		ptr scope;
		bool insert;
		dnet_raw_id id;
		data_pointer index_data;

		data_pointer operator() (const data_pointer &data)
		{
			dnet_indexes indexes;
			if (!data.empty())
				indexes_unpack(data, &indexes, "update_functor");

			// Construct index entry
			index_entry request_id;
			request_id.index = scope->request_id.raw_id();
			request_id.data = index_data;

			auto it = std::lower_bound(indexes.indexes.begin(), indexes.indexes.end(),
				request_id, dnet_raw_id_less_than<skip_data>());
			if (it != indexes.indexes.end() && it->index == request_id.index) {
				// It's already there
				if (insert) {
					if (it->data == request_id.data) {
						// All's ok, keep it untouched
						return data;
					} else {
						// Data is not correct, remember current value due to possible rollback
						std::lock_guard<std::mutex> lock(scope->previous_data_mutex);
						scope->previous_data[it->index] = it->data;
						it->data = request_id.data;
					}
				} else {
					// Anyway, destroy it
					indexes.indexes.erase(it);
				}
			} else {
				// Index is not created yet
				if (insert) {
					// Just insert it
					indexes.indexes.insert(it, 1, request_id);
				} else {
					// All's ok, keep it untouched
					return data;
				}
			}

			msgpack::sbuffer buffer;
			msgpack::pack(&buffer, indexes);
			return data_pointer::copy(buffer.data(), buffer.size());
		}
	};

	struct revert_functor : public update_functor
	{
		void on_fail(const std::exception_ptr &exception)
		{
			scope->exception = exception;
			check_finish();
		}

		void check_finish()
		{
			if (scope->finished != scope->success_inserted_ids.size() + scope->success_removed_ids.size())
				return;

			scope->handler(scope->exception);
		}

		using update_functor::operator();

		void operator() (const sync_write_result &, const error_info &err)
		{
			std::lock_guard<std::mutex> lock(scope->mutex);
			++scope->finished;

			if (err) {
				try {
					err.throw_error();
				} catch (...) {
					on_fail(std::current_exception());
				}
				return;
			}

			check_finish();
		}
	};

	struct try_functor : public update_functor
	{
		void on_fail(const std::exception_ptr &exception)
		{
			scope->exception = exception;
			check_finish();
		}

		void check_finish()
		{
			if (scope->finished != scope->inserted_ids.size() + scope->removed_ids.size())
				return;

			scope->finished = 0;

			dnet_id id;
			memset(&id, 0, sizeof(id));

			if (scope->success_inserted_ids.size() != scope->inserted_ids.size()
				|| scope->success_removed_ids.size() != scope->removed_ids.size()) {

				if (scope->success_inserted_ids.empty() && scope->success_removed_ids.empty()) {
					scope->handler(scope->exception);
					return;
				}

				revert_functor functor;
				functor.scope = scope;
				functor.insert = false;

				for (size_t i = 0; i < scope->success_inserted_ids.size(); ++i) {
					memcpy(id.id, scope->success_inserted_ids[i].id, sizeof(id.id));
					functor.id = scope->success_inserted_ids[i];
					scope->sess.write_cas(id, functor, 0).connect(functor);
				}

				functor.insert = true;

				for (size_t i = 0; i < scope->success_removed_ids.size(); ++i) {
					memcpy(id.id, scope->success_removed_ids[i].id, sizeof(id.id));
					functor.id = scope->success_removed_ids[i];
					functor.index_data = scope->previous_data[functor.id];
					scope->sess.write_cas(id, functor, 0).connect(functor);
				}
			} else {
				scope->handler(std::exception_ptr());
				return;
			}
		}

		using update_functor::operator();

		void operator() (const sync_write_result &, const error_info &err)
		{
			std::lock_guard<std::mutex> lock(scope->mutex);
			++scope->finished;

			if (err) {
				try {
					err.throw_error();
				} catch (...) {
					on_fail(std::current_exception());
				}
				return;
			}

			(insert ? scope->success_inserted_ids : scope->success_removed_ids).push_back(id);
			check_finish();
		}
	};

	struct main_functor
	{
		ptr scope;

		void operator() (const sync_write_result &, const error_info &err)
		{
			if (err) {
				try {
					err.throw_error();
				} catch (...) {
					scope->handler(std::current_exception());
				}
				return;
			}

			try {
				// We "insert" items also to update their data
				std::set_difference(scope->indexes.indexes.begin(), scope->indexes.indexes.end(),
					scope->remote_indexes.indexes.begin(), scope->remote_indexes.indexes.end(),
					std::back_inserter(scope->inserted_ids), dnet_raw_id_less_than<>());
				// Remove only absolutly another items
				std::set_difference(scope->remote_indexes.indexes.begin(), scope->remote_indexes.indexes.end(),
					scope->indexes.indexes.begin(), scope->indexes.indexes.end(),
					std::back_inserter(scope->removed_ids), dnet_raw_id_less_than<skip_data>());

				if (scope->inserted_ids.empty() && scope->removed_ids.empty()) {
					scope->handler(std::exception_ptr());
					return;
				}

				try_functor functor;
				functor.scope = scope;
				functor.insert = true;

				dnet_id id;
				id.group_id = 0;
				id.type = 0;

				for (size_t i = 0; i < scope->inserted_ids.size(); ++i) {
					memcpy(id.id, scope->inserted_ids[i].index.id, sizeof(id.id));
					functor.id = scope->inserted_ids[i].index;
					functor.index_data = scope->inserted_ids[i].data;
					scope->sess.write_cas(id, functor, 0).connect(functor);
				}

				functor.insert = false;

				for (size_t i = 0; i < scope->removed_ids.size(); ++i) {
					memcpy(id.id, scope->removed_ids[i].index.id, sizeof(id.id));
					functor.id = scope->removed_ids[i].index;
					scope->sess.write_cas(id, functor, 0).connect(functor);
				}
			} catch (...) {
				scope->handler(std::current_exception());
				return;
			}
		}

		data_pointer operator() (const data_pointer &data)
		{
			if (data.empty())
				scope->remote_indexes.indexes.clear();
			else
				indexes_unpack(data, &scope->remote_indexes, "main_functor");

			return data_pointer::from_raw(const_cast<char *>(scope->buffer.data()),
				scope->buffer.size());
		}
	};
};

// Update \a indexes for \a request_id
// Result is pushed to \a handler
void session::update_indexes(const std::function<void (const update_indexes_result &)> &handler,
	const key &request_id, const std::vector<index_entry> &indexes)
{
	transform(request_id);

	update_indexes_data::ptr scope = std::make_shared<update_indexes_data>(*this);
	scope->handler = handler;
	scope->request_id = request_id;
	scope->indexes.indexes = indexes;
	std::sort(scope->indexes.indexes.begin(), scope->indexes.indexes.end(), dnet_raw_id_less_than<>());
	// Generate id for storing the entire indexes
	scope->id = indexes_generate_id(*this, request_id.id());
	scope->finished = 0;

	msgpack::pack(scope->buffer, scope->indexes);
	update_indexes_data::main_functor functor = { scope };
	write_cas(scope->id, functor, 0).connect(functor);
}

void session::update_indexes(const key &request_id, const std::vector<index_entry> &indexes)
{
	transform(request_id);

	waiter<std::exception_ptr> w;
	update_indexes(w.handler(), request_id, indexes);
	w.result();
}

void session::update_indexes(const key &id, const std::vector<std::string> &indexes, const std::vector<data_pointer> &datas)
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

	update_indexes(id, raw_indexes);
}

struct find_indexes_handler
{
	std::function<void (const find_indexes_result &)> handler;
	size_t ios_size;

	void operator() (const sync_read_result &bulk_result, const error_info &err)
	{
		if (err) {
			try {
				err.throw_error();
			} catch (...) {
				handler(std::current_exception());
			}
			return;
		}

		if (bulk_result.size() != ios_size) {
			try {
				throw_error(-ENOENT, "Received not all results");
			} catch (...) {
				handler(std::current_exception());
				return;
			}
		}

		try {
			std::vector<find_indexes_result_entry> result;
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

			try {
				handler(result);
			} catch (...) {
			}
		} catch (...) {
			handler(std::current_exception());
			return;
		}
	}
};

void session::find_indexes(const std::function<void (const find_indexes_result &)> &handler, const std::vector<dnet_raw_id> &indexes)
{
	if (indexes.size() == 0) {
		std::vector<find_indexes_result_entry> results;
		handler(results);
		return;
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
}

find_indexes_result session::find_indexes(const std::vector<dnet_raw_id> &indexes)
{
	waiter<find_indexes_result> w;
	find_indexes(w.handler(), indexes);
	return w.result();
}

find_indexes_result session::find_indexes(const std::vector<std::string> &indexes)
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
	std::function<void (const check_indexes_result &)> handler;

	void operator() (const sync_read_result &read_result, const error_info &err)
	{
		if (err) {
			try {
				err.throw_error();
			} catch (...) {
				handler(std::current_exception());
			}
			return;
		}

		try {
			dnet_indexes result;
			indexes_unpack(read_result[0].file(), &result, "check_indexes_handler");

			try {
				handler(result.indexes);
			} catch (...) {
			}
		} catch (...) {
			handler(std::current_exception());
			return;
		}
	}
};

void session::check_indexes(const std::function<void (const check_indexes_result &)> &handler, const key &request_id)
{
	dnet_id id = indexes_generate_id(*this, request_id.id());

	check_indexes_handler functor = { handler };
	read_latest(id, 0, 0).connect(functor);
}

check_indexes_result session::check_indexes(const key &id)
{
	waiter<check_indexes_result> w;
	check_indexes(w.handler(), id);
	return w.result();
}

} } // ioremap::elliptics
