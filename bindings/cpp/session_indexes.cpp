#include "callback_p.h"
#include <msgpack.hpp>

static inline bool operator <(const dnet_raw_id &a, const dnet_raw_id &b)
{
	return memcmp(a.id, b.id, sizeof(a.id)) < 0;
}

static inline bool operator ==(const dnet_raw_id &a, const dnet_raw_id &b)
{
	return memcmp(a.id, b.id, sizeof(a.id)) == 0;
}

static inline bool operator ==(const dnet_raw_id &a, const ioremap::elliptics::index_entry &b)
{
	return memcmp(a.id, b.index.id, sizeof(a.id)) == 0;
}

static inline bool operator ==(const ioremap::elliptics::index_entry &a, const dnet_raw_id &b)
{
	return memcmp(b.id, a.index.id, sizeof(b.id)) == 0;
}

static inline bool operator ==(const ioremap::elliptics::data_pointer &a, const ioremap::elliptics::data_pointer &b)
{
	return a.size() == b.size() && memcmp(a.data(), b.data(), a.size()) == 0;
}

static inline bool operator ==(const ioremap::elliptics::index_entry &a, const ioremap::elliptics::index_entry &b)
{
	return a.data.size() == b.data.size()
		&& memcmp(b.index.id, a.index.id, sizeof(b.index.id)) == 0
		&& memcmp(a.data.data(), b.data.data(), a.data.size()) == 0;
}

namespace ioremap { namespace elliptics {

enum { skip_data = 0, compare_data = 1 };

template <int CompareData = compare_data>
struct dnet_raw_id_less_than
{
	inline bool operator() (const dnet_raw_id &a, const dnet_raw_id &b) const
	{
		return memcmp(a.id, b.id, sizeof(a.id)) < 0;
	}
	inline bool operator() (const index_entry &a, const dnet_raw_id &b) const
	{
		return operator() (a.index, b);
	}
	inline bool operator() (const dnet_raw_id &a, const index_entry &b) const
	{
		return operator() (a, b.index);
	}
	inline bool operator() (const index_entry &a, const index_entry &b) const
	{
		ssize_t cmp = memcmp(a.index.id, b.index.id, sizeof(b.index.id));
		if (CompareData && cmp == 0) {
			cmp = a.data.size() - b.data.size();
			if (cmp == 0) {
				cmp = memcmp(a.data.data(), b.data.data(), a.data.size());
			}
		}
		return cmp < 0;
	}
	inline bool operator() (const index_entry &a, const find_indexes_result_entry &b) const
	{
		return operator() (a.index, b.id);
	}
	inline bool operator() (const find_indexes_result_entry &a, const index_entry &b) const
	{
		return operator() (a.id, b.index);
	}
};

struct dnet_indexes
{
	std::vector<index_entry> indexes;
	std::vector<dnet_raw_id> friends;
};

static void indexes_unpack(const data_pointer &file, dnet_indexes *data)
{
	msgpack::unpacked msg;
	msgpack::unpack(&msg, file.data<char>(), file.size());
	msg.get().convert(data);
}

}}

namespace msgpack
{
using namespace ioremap::elliptics;

inline dnet_raw_id &operator >>(msgpack::object o, dnet_raw_id &v)
{
	if (o.type != msgpack::type::RAW || o.via.raw.size != sizeof(v.id))
		throw msgpack::type_error();
	memcpy(v.id, o.via.raw.ptr, sizeof(v.id));
	return v;
}

template <typename Stream>
inline msgpack::packer<Stream> &operator <<(msgpack::packer<Stream> &o, const dnet_raw_id &v)
{
	o.pack_raw(sizeof(v.id));
	o.pack_raw_body(reinterpret_cast<const char *>(v.id), sizeof(v.id));
	return o;
}

inline data_pointer &operator >>(msgpack::object o, data_pointer &v)
{
	if (o.type != msgpack::type::RAW)
		throw msgpack::type_error();
	if (o.via.raw.size)
		v = data_pointer::copy(o.via.raw.ptr, o.via.raw.size);
	else
		v = data_pointer();
	return v;
}

template <typename Stream>
inline msgpack::packer<Stream> &operator <<(msgpack::packer<Stream> &o, const data_pointer &v)
{
	o.pack_raw(v.size());
	o.pack_raw_body(reinterpret_cast<char *>(v.data()), v.size());
	return o;
}

inline index_entry &operator >>(msgpack::object o, index_entry &v)
{
	if (o.type != msgpack::type::ARRAY || o.via.array.size != 2)
		throw msgpack::type_error();
	object *p = o.via.array.ptr;
	p[0].convert(&v.index);
	p[1].convert(&v.data);
	return v;
}

template <typename Stream>
inline msgpack::packer<Stream> &operator <<(msgpack::packer<Stream> &o, const index_entry &v)
{
	o.pack_array(2);
	o.pack(v.index);
	o.pack(v.data);
	return o;
}

inline dnet_indexes &operator >>(msgpack::object o, dnet_indexes &v)
{
	if (o.type != msgpack::type::ARRAY || o.via.array.size < 1)
		throw msgpack::type_error();

	object *p = o.via.array.ptr;
	const uint32_t size = o.via.array.size;
	uint16_t version = 0;
	p[0].convert(&version);
	switch (version) {
	case 1: {
		if (size != 3)
			throw msgpack::type_error();

		p[1].convert(&v.indexes);
		p[2].convert(&v.friends);
		break;
	}
	default:
		throw msgpack::type_error();
	}

	return v;
}

template <typename Stream>
inline msgpack::packer<Stream> &operator <<(msgpack::packer<Stream> &o, const dnet_indexes &v)
{
	o.pack_array(3);
	o.pack(1);
	o.pack(v.indexes);
	o.pack(v.friends);
	return o;
}
}



std::ostream &operator <<(std::ostream &out, const dnet_raw_id &v)
{
	out << dnet_dump_id_str(v.id);
	return out;
}

std::ostream &operator <<(std::ostream &out, const ioremap::elliptics::index_entry &v)
{
	out << "(" << v.index << ",\"" << v.data.to_string() << "\")";
	return out;
}

std::ostream &operator <<(std::ostream &out, const ioremap::elliptics::data_pointer &v)
{
	out << v.to_string();
	return out;
}

template <typename T>
std::ostream &operator <<(std::ostream &out, const std::vector<T> &v)
{
	out << "{";
	for (size_t i = 0; i < v.size(); ++i) {
		if (i)
			out << ",";
		out << v[i];
	}
	out << "}";
	return out;
}

template <typename K, typename V>
std::ostream &operator <<(std::ostream &out, const std::map<K, V> &v)
{
	out << "{";
	for (auto it = v.begin(); it != v.end(); ++it) {
		if (it != v.begin())
			out << ",";
		out << *it;
	}
	out << "}";
	return out;
}

template <typename K, typename V>
std::ostream &operator <<(std::ostream &out, const std::pair<K, V> &v)
{
	out << "(" << v.first << "," << v.second << ")";
	return out;
}

std::ostream &operator <<(std::ostream &out, const ioremap::elliptics::find_indexes_result_entry &v)
{
	out << "(" << v.id << "," << v.indexes << ")";
	return out;
}



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
				indexes_unpack(data, &indexes);

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

		void operator() (const write_result &result)
		{
			std::lock_guard<std::mutex> lock(scope->mutex);
			++scope->finished;

			if (result.exception() != std::exception_ptr()) {
				on_fail(result.exception());
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
					scope->sess.write_cas(functor, id, functor, 0);
				}

				functor.insert = true;

				for (size_t i = 0; i < scope->success_removed_ids.size(); ++i) {
					memcpy(id.id, scope->success_removed_ids[i].id, sizeof(id.id));
					functor.id = scope->success_removed_ids[i];
					functor.index_data = scope->previous_data[functor.id];
					scope->sess.write_cas(functor, id, functor, 0);
				}
			} else {
				scope->handler(std::exception_ptr());
				return;
			}
		}

		using update_functor::operator();

		void operator() (const write_result &result)
		{
			std::lock_guard<std::mutex> lock(scope->mutex);
			++scope->finished;

			if (result.exception() != std::exception_ptr()) {
				on_fail(result.exception());
				return;
			}

			try {
				(insert ? scope->success_inserted_ids : scope->success_removed_ids).push_back(id);
				check_finish();
			} catch (...) {
				on_fail(result.exception());
				return;
			}
		}
	};

	struct main_functor
	{
		ptr scope;

		void operator() (const write_result &result)
		{
			if (result.exception() != std::exception_ptr()) {
				scope->handler(result.exception());
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
					scope->sess.write_cas(functor, id, functor, 0);
				}

				functor.insert = false;

				for (size_t i = 0; i < scope->removed_ids.size(); ++i) {
					memcpy(id.id, scope->removed_ids[i].index.id, sizeof(id.id));
					functor.id = scope->removed_ids[i].index;
					scope->sess.write_cas(functor, id, functor, 0);
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
				indexes_unpack(data, &scope->remote_indexes);

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
	write_cas(functor, scope->id, functor, 0);
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

	void operator() (const bulk_read_result &bulk_result)
	{
		if (bulk_result.exception() != std::exception_ptr()) {
			handler(bulk_result.exception());
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
			indexes_unpack(bulk_result[0].file(), &tmp);
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
				indexes_unpack(bulk_result[i].file(), &tmp);
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
	bulk_read(functor, ios);
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

	void operator() (const read_result &read_result)
	{
		if (read_result.exception() != std::exception_ptr()) {
			handler(read_result.exception());
			return;
		}

		try {
			dnet_indexes result;
			indexes_unpack(read_result->file(), &result);

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
	read_latest(functor, id, 0, 0);
}

check_indexes_result session::check_indexes(const key &id)
{
	waiter<check_indexes_result> w;
	check_indexes(w.handler(), id);
	return w.result();
}

} } // ioremap::elliptics
