/*
 * 2008+ Copyright (c) Evgeniy Polyakov <zbr@ioremap.net>
 * 2013+ Copyright (c) Kirill Smorodinnikov <shaitkir@gmail.com>
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

#include <netdb.h>
#include <boost/python.hpp>
#include <boost/python/object.hpp>
#include <boost/python/list.hpp>
#include <boost/python/dict.hpp>
#include <boost/python/stl_iterator.hpp>

#include <elliptics/cppdef.h>

#include <map>
#include <queue>
#include <mutex>
#include <condition_variable>

namespace bp = boost::python;

namespace ioremap { namespace elliptics {
enum elliptics_iterator_types {
	itype_disk = DNET_ITYPE_DISK,
	itype_network = DNET_ITYPE_NETWORK,
};

enum elliptics_iterator_flags {
	iflag_default = 0,
	iflag_data = DNET_IFLAGS_DATA,
	iflag_key_range = DNET_IFLAGS_KEY_RANGE,
	iflag_ts_range = DNET_IFLAGS_TS_RANGE,
};

enum elliptics_cflags {
	cflags_default = 0,
	cflags_direct = DNET_FLAGS_DIRECT,
	cflags_nolock = DNET_FLAGS_NOLOCK,
};

enum elliptics_ioflags {
	ioflags_default = 0,
	ioflags_append = DNET_IO_FLAGS_APPEND,
	ioflags_compress = DNET_IO_FLAGS_COMPRESS,
	ioflags_prepare = DNET_IO_FLAGS_PREPARE,
	ioflags_commit = DNET_IO_FLAGS_COMMIT,
	ioflags_overwrite = DNET_IO_FLAGS_OVERWRITE,
	ioflags_nocsum = DNET_IO_FLAGS_NOCSUM,
	ioflags_plain_write = DNET_IO_FLAGS_PLAIN_WRITE,
	ioflags_cache = DNET_IO_FLAGS_CACHE,
	ioflags_cache_only = DNET_IO_FLAGS_CACHE_ONLY,
	ioflags_cache_remove_from_disk = DNET_IO_FLAGS_CACHE_REMOVE_FROM_DISK,
};

enum elliptics_log_level {
	log_level_data = DNET_LOG_DATA,
	log_level_error = DNET_LOG_ERROR,
	log_level_info = DNET_LOG_INFO,
	log_level_notice = DNET_LOG_NOTICE,
	log_level_debug = DNET_LOG_DEBUG,
};

static void convert_from_list(const bp::list &l, unsigned char *dst, int dlen)
{
	memset(dst, 0, dlen);
	int i = 0;
	for (bp::stl_input_iterator<unsigned char> it(l), end; (it != end) && (i < dlen); ++it) {
		dst[i] = *it;
		++i;
	}
}

static bp::list convert_to_list(const unsigned char *src, unsigned int size)
{
	bp::list result;
	for (unsigned int i = 0; i < size; ++i)
		result.append(src[i]);
	return result;
}

class elliptics_id : public key {
public:
	elliptics_id() : key() {}
	elliptics_id(const std::string &remote) : key(remote) {}
	elliptics_id(const dnet_id &id) : key(id) {}
	elliptics_id(const dnet_raw_id &id) : key(id) {}
	elliptics_id(const key &other) : key(other) {}
	elliptics_id(const elliptics_id &other) : key(other) {}

	elliptics_id(const bp::list &id, const uint32_t &group_id) : key() {
		set_id(id);
		set_group_id(group_id);
	}

	bp::list get_id() const {
		return convert_to_list(id().id, sizeof(id().id));
	}

	void set_id(const bp::list &id) {
		dnet_id _id;
		convert_from_list(id, _id.id, sizeof(_id.id));
		key::set_id(_id);
	}

	uint32_t group_id() const {
		return id().group_id;
	}

	void set_group_id(const uint32_t &group_id) {
		key::set_group_id(group_id);
	}

	int cmp(const elliptics_id &other) const {
		return dnet_id_cmp_str(id().id, other.id().id);
	}

	static elliptics_id convert(const bp::api::object &id) {
		bp::extract<elliptics_id> get_id(id);
		if (get_id.check())
			return get_id();

		bp::extract<std::string> get_string(id);
		if (get_string.check())
			return elliptics_id(get_string());

		PyErr_SetString(PyExc_ValueError, "Coudn't convert id to elliptics id");
		bp::throw_error_already_set();

		return elliptics_id();
	}
	// Implements __str__ method.
	// Always returns printable hex representation of all id bytes
	std::string to_str() const {
		char buffer[2*DNET_ID_SIZE + 1] = {0};
		return std::string(dnet_dump_id_len_raw(id().id, DNET_ID_SIZE, buffer));
	}

	// Implements __repr__ method.
	// Returns group, hex id prefix, and original key string
	// (depending on key's previous history, any of those could be zero or empty).
	std::string to_repr() const {
		std::string result("<id: ");
		result += dnet_dump_id_len(&id(), DNET_DUMP_NUM);
		result += ", '";
		result += remote();
		result += "'>";
		return result;
	}
};

struct elliptics_time : public dnet_time {
	elliptics_time(uint64_t tsec = 0, uint64_t tnsec = 0) {
		this->tsec = tsec;
		this->tnsec = tnsec;
	}

	elliptics_time(const dnet_time &timestamp) {
		tsec = timestamp.tsec;
		tnsec = timestamp.tnsec;
	}

	int cmp_raw(const dnet_time &other) const {
		return dnet_time_cmp(this, &other);
	}

	int cmp(const elliptics_time &other) const {
		return dnet_time_cmp(this, &other);
	}
};

struct elliptics_range {
	elliptics_range() : offset(0), size(0),
		limit_start(0), limit_num(0), ioflags(0), group_id(0) {}

	elliptics_id	start, end;
	uint64_t	offset, size;
	uint64_t	limit_start, limit_num;
	uint32_t	ioflags;
	int		group_id;
};

static void elliptics_extract_range(const struct elliptics_range &r, struct dnet_io_attr &io)
{
	memcpy(io.id, r.start.id().id, sizeof(io.id));
	memcpy(io.parent, r.end.id().id, sizeof(io.parent));

	io.flags = r.ioflags;
	io.size = r.size;
	io.offset = r.offset;
	io.start = r.limit_start;
	io.num = r.limit_num;
}

class elliptics_config {
	public:
		elliptics_config() {
			memset(&config, 0, sizeof(struct dnet_config));
		}

		std::string cookie_get(void) const {
			std::string ret;
			ret.assign(config.cookie, sizeof(config.cookie));
			return ret;
		}

		void cookie_set(const std::string &cookie) {
			size_t sz = sizeof(config.cookie);
			if (cookie.size() + 1 < sz)
				sz = cookie.size() + 1;
			memset(config.cookie, 0, sizeof(config.cookie));
			snprintf(config.cookie, sz, "%s", (char *)cookie.data());
		}

		struct dnet_config		config;
};

class elliptics_status : public dnet_node_status
{
	public:
		elliptics_status() {
			nflags = 0;
			status_flags = 0;
			log_level = 0;
		}

		elliptics_status(const dnet_node_status &other) : dnet_node_status(other) {
		}

		elliptics_status &operator =(const dnet_node_status &other) {
			dnet_node_status::operator =(other);
			return *this;
		}
};

class elliptics_node_python : public node, public bp::wrapper<node> {
	public:
		elliptics_node_python(const logger &l)
			: node(l) {}

		elliptics_node_python(const logger &l, elliptics_config &cfg)
			: node(l, cfg.config) {}

		elliptics_node_python(const node &n): node(n) {}
};

template <typename T>
static std::vector<T> convert_to_vector(const bp::api::object &list)
{
	bp::stl_input_iterator<T> begin(list), end;
	return std::vector<T>(begin, end);
}

template <typename T>
struct python_async_result
{
	typedef typename async_result<T>::iterator iterator;

	std::shared_ptr<async_result<T>> scope;

	iterator begin() {
		return scope->begin();
	}

	iterator end() {
		return scope->end();
	}

	bp::list get() {
		bp::list ret;

		auto res = scope->get();
		for (auto it = res.begin(), end = res.end(); it != end; ++it) {
			ret.append(*it);
		}

		return ret;
	}

	void wait() {
		scope->wait();
	}

	bool successful() {
		if (!scope->ready()) {
			PyErr_SetString(PyExc_ValueError, "Async write operation hasn't yet been completed");
			bp::throw_error_already_set();
		}

		return !scope->error();
	}

	bool ready() {
		return scope->ready();
	}

	dnet_time elapsed_time() {
		return scope->elapsed_time();
	}
};

template <typename T>
python_async_result<T> create_result(async_result<T> &&result)
{
	python_async_result<T> pyresult = { std::make_shared<async_result<T>>(std::move(result)) };
	return pyresult;
}

template <typename... Args>
struct def_async_result;

template <typename T>
struct def_async_result<T>
{
	static void init() {
		bp::class_<python_async_result<T>>("AsyncResult", bp::no_init)
			.def("__iter__", bp::iterator<python_async_result<T>>())
			.def("get", &python_async_result<T>::get)
			.def("wait", &python_async_result<T>::wait)
			.def("successful", &python_async_result<T>::successful)
			.def("ready", &python_async_result<T>::ready)
			.def("elapsed_time", &python_async_result<T>::elapsed_time)
		;
	}
};

template <>
struct def_async_result<>
{
	static void init() {}
};

template <typename T, typename... Args>
struct def_async_result<T, Args...>
{
	static void init() {
		def_async_result<T>::init();
		def_async_result<Args...>::init();
	}
};

typedef python_async_result<iterator_result_entry>		python_iterator_result;
typedef python_async_result<read_result_entry> 			python_read_result;
typedef python_async_result<lookup_result_entry>		python_lookup_result;
typedef python_async_result<write_result_entry>			python_write_result;
typedef python_async_result<remove_result_entry>		python_remove_result;
typedef python_async_result<exec_result_entry>			python_exec_result;

typedef python_async_result<callback_result_entry>		python_async_set_indexes_result;
typedef python_async_result<find_indexes_result_entry>	python_find_indexes_result;
typedef python_async_result<index_entry>				python_check_indexes_result;

typedef python_async_result<stat_count_result_entry>	python_stat_count_result;

class elliptics_session: public session, public bp::wrapper<session> {
	public:
		elliptics_session(const node &n) : session(n) {}

		void set_groups(const bp::api::object &groups) {
			session::set_groups(convert_to_vector<int>(groups));
		}

		void set_direct_id(std::string saddr, int port, int family) {
			session::set_direct_id(saddr.c_str(), port, family);
		}

		struct elliptics_id get_direct_id() {
			dnet_id id = session::get_direct_id();
			return id;
		}

		bp::list get_groups() {
			std::vector<int> groups = session::get_groups();
			bp::list res;
			for (size_t i=0; i<groups.size(); i++) {
				res.append(groups[i]);
			}

			return res;
		}

		void read_file(const bp::api::object &id, const std::string &file, uint64_t offset, uint64_t size) {
			return session::read_file(elliptics_id::convert(id), file, offset, size);
		}

		void write_file(const bp::api::object &id, const std::string &file, uint64_t local_offset, uint64_t offset, uint64_t size) {
			return session::write_file(elliptics_id::convert(id), file, local_offset, offset, size);
		}

		python_read_result read_data(const bp::api::object &id, uint64_t offset, uint64_t size) {
			return create_result(std::move(session::read_data(elliptics_id::convert(id), offset, size)));
		}

		python_read_result read_latest(const bp::api::object &id, uint64_t offset, uint64_t size) {
			return create_result(std::move(session::read_latest(elliptics_id::convert(id), offset, size)));
		}

		python_write_result write_data(const bp::api::object &id, const std::string &data, uint64_t offset, uint64_t chunk_size) {
			return create_result(std::move(session::write_data(elliptics_id::convert(id), data, offset, chunk_size)));
		}

		python_write_result write_cache(const bp::api::object &id, const std::string &data, long timeout) {
			return create_result(std::move(session::write_cache(elliptics_id::convert(id), data, timeout)));
		}

		std::string lookup_address(const bp::api::object &id, const int group_id) {
			return session::lookup_address(elliptics_id::convert(id), group_id);
		}

		python_lookup_result lookup(const bp::api::object &id) {
			return create_result(std::move(session::lookup(elliptics_id::convert(id))));
		}

		python_lookup_result prepare_latest(const bp::api::object &id, const bp::api::object &gl) {
			std::vector<int> groups = convert_to_vector<int>(gl);

			return create_result(std::move(session::prepare_latest(elliptics_id::convert(id), groups)));
		}

		bp::tuple parse_lookup(const lookup_result_entry &lookup) {
			struct dnet_addr *addr = lookup.address();
			struct dnet_file_info *info = lookup.file_info();

			std::string address(dnet_server_convert_dnet_addr(addr));
			int port = dnet_server_convert_port((struct sockaddr *)addr->addr, addr->addr_len);

			return bp::make_tuple(address, port, info->size);
		}

		elliptics_status update_status(const bp::api::object &id, elliptics_status &status) {
			session::update_status(elliptics_id::convert(id), &status);
			return status;
		}

		elliptics_status update_status(const std::string &saddr, const int port,
		                               const int family, elliptics_status &status) {
			session::update_status(saddr.c_str(), port, family, &status);
			return status;
		}

		python_read_result read_data_range(const struct elliptics_range &r) {
			dnet_io_attr io;
			elliptics_extract_range(r, io);
			return create_result(std::move(session::read_data_range(io, r.group_id)));
		}

		bp::list get_routes() {
			bp::list res;

			auto routes = session::get_routes();

			for (auto it = routes.begin(), end = routes.end(); it != end; ++it) {
				std::string(dnet_server_convert_dnet_addr(&(it->second)));

				res.append(bp::make_tuple(elliptics_id(it->first),
				                          std::string(dnet_server_convert_dnet_addr(&(it->second)))
				                          ));
			}

			return res;
		}

		python_iterator_result start_iterator(const bp::api::object &id, const bp::api::object &ranges,
		                                      uint32_t type, uint64_t flags,
		                                      const elliptics_time& time_begin = elliptics_time(0, 0),
		                                      const elliptics_time& time_end = elliptics_time(-1, -1)) {
			std::vector<dnet_iterator_range> std_ranges = convert_to_vector<dnet_iterator_range>(ranges);
			return create_result(std::move(session::start_iterator(elliptics_id::convert(id), std_ranges, type, flags,
							time_begin, time_end)));
		}

		python_iterator_result pause_iterator(const bp::api::object &id, const uint64_t &iterator_id) {
			return create_result(std::move(session::pause_iterator(elliptics_id::convert(id), iterator_id)));
		}

		python_iterator_result continue_iterator(const bp::api::object &id, const uint64_t &iterator_id) {
			return create_result(std::move(session::continue_iterator(elliptics_id::convert(id), iterator_id)));
		}

		python_iterator_result cancel_iterator(const bp::api::object &id, const uint64_t &iterator_id) {
			return create_result(std::move(session::cancel_iterator(elliptics_id::convert(id), iterator_id)));
		}

		python_exec_result exec(const bp::api::object &id, const int src_key, const std::string &event, const std::string &data) {
			auto eid = elliptics_id::convert(id);
			transform(eid);
			return create_result(std::move(session::exec(const_cast<dnet_id*>(&eid.id()), src_key, event, data)));
		}

		python_exec_result exec(const bp::api::object &id, const std::string &event, const std::string &data) {
			auto eid = elliptics_id::convert(id);
			transform(eid);
			return create_result(std::move(session::exec(const_cast<dnet_id*>(&eid.id()), event, data)));
		}

		python_remove_result remove(const bp::api::object &id) {
			return create_result(std::move(session::remove(elliptics_id::convert(id))));
		}

		struct dnet_id_comparator {
			bool operator() (const struct dnet_id &first, const struct dnet_id &second) const
			{
				return memcmp(first.id, second.id, sizeof(first.id)) < 0;
			}
		};

		python_read_result bulk_read(const bp::list &keys) {
			std::vector<dnet_io_attr> ios;
			dnet_io_attr io;
			memset(&io, 0, sizeof(io));
			ios.reserve(bp::len(keys));

			for (bp::stl_input_iterator<bp::api::object> it(keys), end; it != end; ++it) {
				auto e_id = elliptics_id::convert(*it);
				transform(e_id);
				memcpy(io.id, e_id.id().id, sizeof(io.id));
				ios.push_back(io);
			}

			return create_result(std::move(session::bulk_read(ios)));
		}

		python_write_result bulk_write(const bp::list &datas) {
			std::vector<dnet_io_attr> ios;
			std::vector<std::string> wdatas;

			auto datas_len = bp::len(datas);
			ios.reserve(datas_len);
			wdatas.resize(datas_len);

			dnet_io_attr io;
			memset(&io, 0, sizeof(io));

			for (bp::stl_input_iterator<bp::tuple> it(datas), end; it != end; ++it) {
				auto e_id = elliptics_id::convert((*it)[0]);
				transform(e_id);

				std::string &data = bp::extract<std::string&>((*it)[1]);

				auto it_len = bp::len(*it);
				if (it_len > 2)
					io.timestamp = bp::extract<dnet_time>((*it)[2]);
				else
					dnet_empty_time(&io.timestamp);
				if(it_len > 3)
					io.user_flags = bp::extract<uint64_t>((*it)[3]);
				else
					io.user_flags = 0;

				memcpy(io.id, e_id.id().id, sizeof(io.id));
				io.size = data.size();
				wdatas.push_back(data);
				ios.push_back(io);
			}

			return create_result(std::move(session::bulk_write(ios, wdatas)));
		}

		python_async_set_indexes_result set_indexes(const bp::api::object &id, const bp::api::object &indexes, const bp::api::object &datas) {
			auto std_indexes = convert_to_vector<std::string>(indexes);
			auto string_datas = convert_to_vector<std::string>(datas);
			std::vector<data_pointer> std_datas(string_datas.begin(), string_datas.end());

			return create_result(std::move(session::set_indexes(elliptics_id::convert(id), std_indexes, std_datas)));
		}

		python_async_set_indexes_result set_indexes_raw(const bp::api::object &id, const bp::api::object &indexes) {
			auto std_indexes = convert_to_vector<index_entry>(indexes);

			return create_result(std::move(session::set_indexes(elliptics_id::convert(id), std_indexes)));
		}

		python_async_set_indexes_result update_indexes(const bp::api::object &id, const bp::api::object &indexes, const bp::api::object &datas) {
			auto std_indexes = convert_to_vector<std::string>(indexes);
			auto string_datas = convert_to_vector<std::string>(datas);
			std::vector<data_pointer> std_datas(string_datas.begin(), string_datas.end());

			return create_result(std::move(session::update_indexes(elliptics_id::convert(id), std_indexes, std_datas)));
		}

		python_async_set_indexes_result update_indexes_raw(const bp::api::object &id, const bp::api::object &indexes) {
			auto std_indexes = convert_to_vector<index_entry>(indexes);

			return create_result(std::move(session::update_indexes(elliptics_id::convert(id), std_indexes)));
		}

		python_async_set_indexes_result update_indexes_internal(const bp::api::object &id, const bp::api::object &indexes, const bp::api::object &datas) {
			auto std_indexes = convert_to_vector<std::string>(indexes);
			auto string_datas = convert_to_vector<std::string>(datas);
			std::vector<data_pointer> std_datas(string_datas.begin(), string_datas.end());

			return create_result(std::move(session::update_indexes_internal(elliptics_id::convert(id), std_indexes, std_datas)));
		}

		python_async_set_indexes_result update_indexes_internal_raw(const bp::api::object &id, const bp::api::object &indexes) {
			auto std_indexes = convert_to_vector<index_entry>(indexes);

			return create_result(std::move(session::update_indexes_internal(elliptics_id::convert(id), std_indexes)));
		}

		python_find_indexes_result find_all_indexes(const bp::list &indexes) {
			auto std_indexes = convert_to_vector<std::string>(indexes);

			return create_result(std::move(session::find_all_indexes(std_indexes)));
		}

		python_find_indexes_result find_all_indexes_raw(const bp::list &indexes) {
			std::vector<dnet_raw_id> std_indexes;
			std_indexes.reserve(bp::len(indexes));

			for (bp::stl_input_iterator<bp::api::object> it(indexes), end; it != end; ++it) {
				auto e_id = elliptics_id::convert(*it);
				transform(e_id);
				std_indexes.push_back(e_id.raw_id());
			}

			return create_result(std::move(session::find_all_indexes(std_indexes)));
		}

		python_find_indexes_result find_any_indexes(const bp::list &indexes) {
			auto std_indexes = convert_to_vector<std::string>(indexes);

			return create_result(std::move(session::find_any_indexes(std_indexes)));
		}

		python_find_indexes_result find_any_indexes_raw(const bp::list &indexes) {
			std::vector<dnet_raw_id> std_indexes;
			std_indexes.reserve(bp::len(indexes));

			for (bp::stl_input_iterator<bp::api::object> it(indexes), end; it != end; ++it) {
				auto e_id = elliptics_id::convert(*it);
				transform(e_id);
				std_indexes.push_back(e_id.raw_id());
			}

			return create_result(std::move(session::find_any_indexes(std_indexes)));
		}

		python_check_indexes_result list_indexes(const bp::api::object &id) {
			return create_result(std::move(session::list_indexes(elliptics_id::convert(id))));
		}

		python_stat_count_result stat_log_count() {
			return create_result(std::move(session::stat_log_count()));
		}
};

class elliptics_error_translator
{
	public:
		elliptics_error_translator()
		{}

		void operator() (const error &err) const {
			bp::api::object exception(err);
			bp::api::object type = m_type;
			for (size_t i = 0; i < m_types.size(); ++i) {
				if (m_types[i].first == err.error_code()) {
					type = m_types[i].second;
					break;
				}
			}
			PyErr_SetObject(type.ptr(), exception.ptr());
		}

		void initialize() {
			m_type = new_exception("Error");
			register_type(-ENOENT, "NotFoundError");
			register_type(-ETIMEDOUT, "TimeoutError");
		}

		void register_type(int code, const char *name) {
			register_type(code, new_exception(name, m_type.ptr()));
		}

		void register_type(int code, const bp::api::object &type) {
			m_types.push_back(std::make_pair(code, type));
		}

	private:
		bp::api::object new_exception(const char *name, PyObject *parent = NULL) {
			std::string scopeName = bp::extract<std::string>(bp::scope().attr("__name__"));
			std::string qualifiedName = scopeName + "." + name;

			PyObject *type = PyErr_NewException(&qualifiedName[0], parent, 0);
			if (!type)
				bp::throw_error_already_set();
			bp::api::object type_object = bp::api::object(bp::handle<>(type));
			bp::scope().attr(name) = type_object;
			return type_object;
		}

		bp::api::object m_type;
		std::vector<std::pair<int, bp::api::object> > m_types;
};

void ios_base_failure_translator(const std::ios_base::failure &exc)
{
	PyErr_SetString(PyExc_IOError, exc.what());
}

BOOST_PYTHON_MEMBER_FUNCTION_OVERLOADS(add_remote_overloads, add_remote, 2, 3);

std::string dnet_node_status_repr(const dnet_node_status &status)
{
	char buffer[128];
	const size_t buffer_size = sizeof(buffer);
	snprintf(buffer, buffer_size,
		"<SessionStatus nflags:%x, status_flags:%x, log_mask:%x>",
		status.nflags, status.status_flags, status.log_level);
	buffer[buffer_size - 1] = '\0';
	return buffer;
}

void logger_log(logger &log, const char *msg, int level)
{
	log.log(level, msg);
}

void next_impl(bp::api::object &value, const bp::api::object &next)
{
	value = next();
}

elliptics_id dnet_iterator_range_get_key_begin(const dnet_iterator_range *range)
{
	return elliptics_id(range->key_begin);
}

void dnet_iterator_range_set_key_begin(dnet_iterator_range *range, const elliptics_id &id)
{
	range->key_begin = id.raw_id();
}

elliptics_id dnet_iterator_range_get_key_end(const dnet_iterator_range *range)
{
	return elliptics_id(range->key_end);
}

void dnet_iterator_range_set_key_end(dnet_iterator_range *range, const elliptics_id &id)
{
	range->key_end = id.raw_id();
}

dnet_iterator_response iterator_result_response(iterator_result_entry result)
{
	return *result.reply();
}

std::string iterator_result_response_data(iterator_result_entry result)
{
	return result.reply_data().to_string();
}

elliptics_id iterator_response_get_key(dnet_iterator_response *response)
{
	return elliptics_id(response->key);
}

elliptics_time iterator_response_get_timestamp(dnet_iterator_response *response)
{
	return elliptics_time(response->timestamp);
}

uint64_t iterator_response_get_user_flags(dnet_iterator_response *response)
{
	return response->user_flags;
}

void iterator_container_append_rr(iterator_result_container &container,
		dnet_iterator_response &response)
{
	container.append(&response);
}

void iterator_container_append(iterator_result_container &container,
		iterator_result_entry &result)
{
	container.append(result);
}

void iterator_container_sort(iterator_result_container &container)
{
	container.sort();
}

uint64_t iterator_container_get_count(const iterator_result_container &container)
{
	return container.m_count;
}

dnet_iterator_response iterator_container_getitem(const iterator_result_container &container,
                                                  uint64_t n)
{
	if (n >= container.m_count) {
		PyErr_SetString(PyExc_IndexError, "Index out of range");
		bp::throw_error_already_set();
	}
	return container[n];
}

void iterator_container_diff(iterator_result_container &left,
                             iterator_result_container &right,
                             iterator_result_container &diff)
{
	left.diff(right, diff);
}

void iterator_container_merge(const bp::list& /*results*/, bp::dict& /*splitted_dict*/)
{}

std::string read_result_get_data(read_result_entry &result)
{
	return result.file().to_string();
}

elliptics_id read_result_get_id(read_result_entry &result)
{
	dnet_raw_id id;
	memcpy(id.id, result.io_attribute()->id, sizeof(id.id));
	return elliptics_id(id);
}

elliptics_time read_result_get_timestamp(read_result_entry &result)
{
	return elliptics_time(result.io_attribute()->timestamp);
}

uint64_t read_result_get_user_flags(read_result_entry &result)
{
	return result.io_attribute()->user_flags;
}

std::string exec_result_get_event(exec_result_entry &result)
{
	return result.context().event();
}

std::string exec_result_get_data(exec_result_entry &result)
{
	return result.context().data().to_string();
}

int exec_result_get_src_key(exec_result_entry &result)
{
	return result.context().src_key();
}

elliptics_id exec_result_get_src_id(exec_result_entry &result)
{
	const dnet_raw_id *raw = result.context().src_id();
	return elliptics_id(convert_to_list(raw->id, sizeof(raw->id)), 0);
}

std::string exec_result_get_address(exec_result_entry &result)
{
	struct dnet_addr *addr = result.context().address();
	return dnet_server_convert_dnet_addr(addr);
}

elliptics_id index_entry_get_index(index_entry &result)
{
	return elliptics_id(result.index);
}

void index_entry_set_index(index_entry &result, const elliptics_id &id)
{
	result.index = id.raw_id();
}

std::string index_entry_get_data(index_entry &result)
{
	return result.data.to_string();
}

void index_entry_set_data(index_entry &result, const std::string& data)
{
	result.data = data_pointer(data);
}

elliptics_id find_indexes_result_get_id(find_indexes_result_entry &result)
{
	return elliptics_id(result.id);
}

bp::list find_indexes_result_get_indexes(find_indexes_result_entry &result)
{
	bp::list ret;

	for (auto it = result.indexes.begin(), end = result.indexes.end(); it != end; ++it) {
		ret.append(*it);
	}

	return ret;
}

struct id_pickle : bp::pickle_suite
{
	static bp::tuple getinitargs(const elliptics_id& id) {
		return getstate(id);
	}

	static bp::tuple getstate(const elliptics_id& id) {
		return bp::make_tuple(id.get_id(), id.group_id());
	}

	static void setstate(elliptics_id& id, bp::tuple state) {
		if (len(state) != 2) {
			PyErr_SetObject(PyExc_ValueError,
				("expected 2-item tuple in call to __setstate__; got %s"
					% state).ptr()
				);
			bp::throw_error_already_set();
		}

		id.set_id(bp::extract<bp::list>(state[0]));
		id.set_group_id(bp::extract<uint32_t>(state[1]));
	}
};

struct time_pickle : bp::pickle_suite
{
	static bp::tuple getinitargs(const elliptics_time& time) {
		return getstate(time);
	}

	static bp::tuple getstate(const elliptics_time& time) {
		return bp::make_tuple(time.tsec, time.tnsec);
	}

	static void setstate(elliptics_time& time, bp::tuple state) {
		if (len(state) != 2) {
			PyErr_SetObject(PyExc_ValueError,
				("expected 2-item tuple in call to __setstate__; got %s"
					% state).ptr()
				);
			bp::throw_error_already_set();
		}

		time.tsec = bp::extract<uint64_t>(state[0]);
		time.tnsec = bp::extract<uint64_t>(state[1]);
	}
};

BOOST_PYTHON_MODULE(elliptics)
{
	bp::class_<error> error_class("ErrorInfo", bp::init<int, std::string>());
	error_class.def("__str__", &error::error_message);
	error_class.add_property("message", &error::error_message);
	error_class.add_property("code", &error::error_code);
	elliptics_error_translator error_translator;
	error_translator.initialize();


	bp::register_exception_translator<timeout_error>(error_translator);
	bp::register_exception_translator<not_found_error>(error_translator);
	bp::register_exception_translator<error>(error_translator);
	bp::register_exception_translator<std::ios_base::failure>(ios_base_failure_translator);

	bp::class_<elliptics_id>("Id", bp::no_init)
		.def(bp::init<bp::list, uint32_t>(bp::args("key", "group_id")))
		.def(bp::init<std::string>(bp::args("remote")))
		.add_property("id", &elliptics_id::get_id, &elliptics_id::set_id)
		.add_property("group_id", &elliptics_id::group_id, &elliptics_id::set_group_id)
		.def("__cmp__", &elliptics_id::cmp)
		.def("__str__", &elliptics_id::to_str)
		.def_pickle(id_pickle())
		.def("__repr__", &elliptics_id::to_repr)
	;

	bp::class_<elliptics_time>("Time",
			bp::init<uint64_t, uint64_t>(bp::args("tsec", "tnsec")))
		.def_readwrite("tsec", &elliptics_time::tsec)
		.def_readwrite("tnsec", &elliptics_time::tnsec)
		.def("__cmp__", &elliptics_time::cmp_raw)
		.def("__cmp__", &elliptics_time::cmp)
		.def_pickle(time_pickle())
	;

	bp::class_<dnet_iterator_range>("IteratorRange")
		.add_property("key_begin", dnet_iterator_range_get_key_begin,
				dnet_iterator_range_set_key_begin)
		.add_property("key_end", dnet_iterator_range_get_key_end,
				dnet_iterator_range_set_key_end)
	;

	def_async_result<	callback_result_entry,
						lookup_result_entry,
						read_result_entry,
						stat_result_entry,
						stat_count_result_entry,
						iterator_result_entry,
						exec_result_entry,
						find_indexes_result_entry,
						index_entry
					>::init();

	bp::class_<iterator_result_entry>("IteratorResultEntry")
		.add_property("id", &iterator_result_entry::id)
		.add_property("status", &iterator_result_entry::status)
		.add_property("response", iterator_result_response)
		.add_property("response_data", iterator_result_response_data)
	;

	bp::class_<dnet_iterator_response>("IteratorResultResponse",
			bp::no_init)
		.add_property("key", iterator_response_get_key)
		.add_property("timestamp", iterator_response_get_timestamp)
		.add_property("user_flags", iterator_response_get_user_flags)
	;

	bp::class_<iterator_result_container>("IteratorResultContainer",
			bp::init<int>(bp::args("fd")))
		.add_property("fd", &iterator_result_container::m_fd)
		.def(bp::init<int, bool, uint64_t>(bp::args("fd", "sorted", "write_position")))
		.def("append", iterator_container_append)
		.def("append_rr", iterator_container_append_rr)
		.def("sort", iterator_container_sort)
		.def("diff", iterator_container_diff)
		.def("__len__", iterator_container_get_count)
		.def("__getitem__", iterator_container_getitem)
		.def("merge", &iterator_container_merge)
		.staticmethod("merge")
	;

	bp::class_<read_result_entry>("ReadResultEntry")
		.add_property("data", read_result_get_data)
		.add_property("id", read_result_get_id)
		.add_property("timestamp", read_result_get_timestamp)
		.add_property("user_flags", read_result_get_user_flags)
	;

	bp::class_<lookup_result_entry>("LookupResultEntry")
	;

	bp::class_<exec_result_entry>("ExecResultEntry")
		.add_property("event", exec_result_get_event)
		.add_property("data", exec_result_get_data)
		.add_property("src_key", exec_result_get_src_key)
		.add_property("src_id", exec_result_get_src_id)
		.add_property("address", exec_result_get_address)
	;

	bp::class_<index_entry>("IndexEntry")
		.add_property("index",
		              index_entry_get_index,
		              index_entry_set_index)
		.add_property("data",
		              index_entry_get_data,
		              index_entry_set_data)
	;

	bp::class_<find_indexes_result_entry>("FindIndexesResultEntry")
		.add_property("id", find_indexes_result_get_id)
		.add_property("indexes", find_indexes_result_get_indexes)
	;

	bp::class_<callback_result_entry>("CallbackResultEntry")
	;

	bp::class_<stat_count_result_entry>("StatCountResultEntry")
	;

	bp::class_<elliptics_range>("Range")
		.def_readwrite("start", &elliptics_range::start)
		.def_readwrite("end", &elliptics_range::end)
		.def_readwrite("offset", &elliptics_range::offset)
		.def_readwrite("size", &elliptics_range::size)
		.def_readwrite("ioflags", &elliptics_range::ioflags)
		.def_readwrite("group_id", &elliptics_range::group_id)
		.def_readwrite("limit_start", &elliptics_range::limit_start)
		.def_readwrite("limit_num", &elliptics_range::limit_num)
	;

	bp::class_<logger, boost::noncopyable>("AbstractLogger", bp::no_init)
		.def("log", &logger::log)
	;

	bp::class_<file_logger, bp::bases<logger> > file_logger_class(
		"Logger", bp::init<const char *, const uint32_t>());

	bp::class_<elliptics_status>("SessionStatus", bp::init<>())
		.def_readwrite("nflags", &dnet_node_status::nflags)
		.def_readwrite("status_flags", &dnet_node_status::status_flags)
		.def_readwrite("log_level", &dnet_node_status::log_level)
		.def("__repr__", dnet_node_status_repr)
	;

	bp::class_<dnet_config>("dnet_config", bp::no_init)
		.def_readwrite("wait_timeout", &dnet_config::wait_timeout)
		.def_readwrite("flags", &dnet_config::flags)
		.def_readwrite("check_timeout", &dnet_config::check_timeout)
		.def_readwrite("io_thread_num", &dnet_config::io_thread_num)
		.def_readwrite("nonblocking_io_thread_num", &dnet_config::nonblocking_io_thread_num)
		.def_readwrite("net_thread_num", &dnet_config::net_thread_num)
		.def_readwrite("client_prio", &dnet_config::client_prio)
	;

	bp::class_<dnet_time>("dnet_time", bp::no_init)
		.def_readwrite("tsec", &dnet_time::tsec)
		.def_readwrite("tnsec", &dnet_time::tnsec)
	;

	bp::class_<elliptics_config>("Config", bp::init<>())
		.def_readwrite("config", &elliptics_config::config)
		.add_property("cookie", &elliptics_config::cookie_get, &elliptics_config::cookie_set)
	;

	bp::class_<elliptics_node_python>("Node", bp::init<logger>())
		.def(bp::init<logger, elliptics_config &>())
		.def("add_remote", static_cast<void (node::*)(const char*, int, int)>(&node::add_remote),
			(bp::arg("addr"), bp::arg("port"), bp::arg("family") = AF_INET))
	;

	bp::class_<elliptics_session, boost::noncopyable>("Session", bp::init<node &>())
		.add_property("groups", &elliptics_session::get_groups, &elliptics_session::set_groups)
		.def("add_groups", &elliptics_session::set_groups)
		.def("set_groups", &elliptics_session::set_groups)
		.def("get_groups", &elliptics_session::get_groups)

		.add_property("cflags", &elliptics_session::get_cflags, &elliptics_session::set_cflags)
		.def("set_cflags", &elliptics_session::set_cflags)
		.def("get_cflags", &elliptics_session::get_cflags)

		.add_property("ioflags", &elliptics_session::get_ioflags, &elliptics_session::set_ioflags)
		.def("set_ioflags", &elliptics_session::set_ioflags)
		.def("get_ioflags", &elliptics_session::get_ioflags)

		.def("set_direct_id", &elliptics_session::set_direct_id)
		.def("get_direct_id", &elliptics_session::get_direct_id)

		.def("read_file", &elliptics_session::read_file,
			(bp::arg("key"), bp::arg("filename"), bp::arg("offset") = 0, bp::arg("size") = 0))
		.def("write_file", &elliptics_session::write_file,
			(bp::arg("key"), bp::arg("filename"), bp::arg("offset") = 0, bp::arg("local_offset") = 0, bp::arg("size") = 0))

		.def("read_data", &elliptics_session::read_data,
			(bp::arg("key"), bp::arg("offset") = 0, bp::arg("size") = 0))

		.def("prepare_latest", &elliptics_session::prepare_latest)

		.def("read_latest", &elliptics_session::read_latest,
			(bp::arg("key"), bp::arg("offset") = 0, bp::arg("size") = 0))

		.def("write_data", &elliptics_session::write_data,
			(bp::arg("key"), bp::arg("data"), bp::arg("offset") = 0))

		.def("write_cache", &elliptics_session::write_cache)

		.def("lookup_addr", &elliptics_session::lookup_address)

		.def("lookup", &elliptics_session::lookup)

		.def("update_status", (elliptics_status (elliptics_session::*)(const bp::api::object&, elliptics_status&))&elliptics_session::update_status,
		     (bp::arg("id"), bp::arg("status")))
		.def("update_status", (elliptics_status (elliptics_session::*)(const std::string&, const int, const int, elliptics_status&))&elliptics_session::update_status,
		     (bp::arg("saddr"), bp::arg("port"), bp::arg("family"), bp::arg("status")))

		.def("read_data_range", &elliptics_session::read_data_range)

		.def("get_routes", &elliptics_session::get_routes)
		.def("stat_log", &elliptics_session::stat_log_count)

		.def("start_iterator", &elliptics_session::start_iterator)
		.def("pause_iterator", &elliptics_session::pause_iterator)
		.def("continue_iterator", &elliptics_session::continue_iterator)
		.def("cancel_iterator", &elliptics_session::cancel_iterator)

		// Couldn't use "exec" as a method name because it's a reserved keyword in python

		.def("exec_event", (python_exec_result (elliptics_session::*)
		     (const bp::api::object&,
		      const int, const std::string&,
		      const std::string&))&elliptics_session::exec,
			(bp::arg("id"), bp::arg("event"), bp::arg("data") = ""))
		.def("exec_event", (python_exec_result (elliptics_session::*)
		     (const bp::api::object&,
		      const std::string&,
		      const std::string&))&elliptics_session::exec,
			(bp::arg("id"), bp::arg("src_key"), bp::arg("event"), bp::arg("data") = ""))

		.def("remove", &elliptics_session::remove)

		.def("bulk_read", &elliptics_session::bulk_read,
			(bp::arg("keys")))

		.def("bulk_write", &elliptics_session::bulk_write,
			(bp::arg("datas")))

		.def("set_indexes", &elliptics_session::set_indexes,
		     (bp::arg("id"), bp::arg("indexes"), bp::arg("datas")))
		.def("set_indexes_raw", &elliptics_session::set_indexes_raw,
		     (bp::arg("id"), bp::arg("indexes")))

		.def("update_indexes", &elliptics_session::update_indexes,
		     (bp::arg("id"), bp::arg("indexes"), bp::arg("datas")))
		.def("update_indexes_raw", &elliptics_session::update_indexes_raw,
		     (bp::arg("id"), bp::arg("indexes")))

		.def("update_indexes_internal", &elliptics_session::update_indexes_internal,
		     (bp::arg("id"), bp::arg("indexes"), bp::arg("datas")))
		.def("update_indexes_internal_raw", &elliptics_session::update_indexes_internal_raw,
		     (bp::arg("id"), bp::arg("indexes")))

		.def("find_all_indexes", &elliptics_session::find_all_indexes,
		     (bp::arg("indexes")))
		.def("find_all_indexes_raw", &elliptics_session::find_all_indexes_raw,
		     (bp::arg("indexes")))

		.def("find_any_indexes", &elliptics_session::find_any_indexes,
		     (bp::arg("indexes")))
		.def("find_any_indexes_raw", &elliptics_session::find_any_indexes_raw,
		     (bp::arg("indexes")))

		.def("list_indexes", &elliptics_session::list_indexes,
		     (bp::arg("id")))
	;

	bp::enum_<elliptics_iterator_flags>("iterator_flags")
		.value("default", iflag_default)
		.value("data", iflag_data)
		.value("key_range", iflag_key_range)
		.value("ts_range", iflag_ts_range)
	;

	bp::enum_<elliptics_iterator_types>("iterator_types")
		.value("disk", itype_disk)
		.value("network", itype_network)
	;

	bp::enum_<elliptics_cflags>("command_flags")
		.value("default", cflags_default)
		.value("direct", cflags_direct)
		.value("nolock", cflags_nolock)
	;

	bp::enum_<elliptics_ioflags>("io_flags")
		.value("default", ioflags_default)
		.value("append", ioflags_append)
		.value("compress", ioflags_compress)
		.value("prepare", ioflags_prepare)
		.value("commit", ioflags_commit)
		.value("overwrite", ioflags_overwrite)
		.value("nocsum", ioflags_nocsum)
		.value("plain_write", ioflags_plain_write)
		.value("nodata", ioflags_plain_write)
		.value("cache", ioflags_cache)
		.value("cache_only", ioflags_cache_only)
		.value("cache_remove_from_disk", ioflags_cache_remove_from_disk)
	;

	bp::enum_<elliptics_log_level>("log_level")
		.value("data", log_level_data)
		.value("error", log_level_error)
		.value("info", log_level_info)
		.value("notice", log_level_notice)
		.value("debug", log_level_debug)
	;
};

} } // namespace ioremap::elliptics
