#include "elliptics_session.h"

#include <boost/python.hpp>
#include <boost/python/object.hpp>
#include <boost/python/list.hpp>
#include <boost/python/dict.hpp>
#include <boost/python/stl_iterator.hpp>

#include <elliptics/session.hpp>

#include "elliptics_id.h"
#include "async_result.h"
#include "result_entry.h"
#include "elliptics_time.h"

namespace bp = boost::python;

namespace ioremap { namespace elliptics { namespace python {

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

	std::string dnet_node_status_repr() const {
		char buffer[128];
		const size_t buffer_size = sizeof(buffer);
		snprintf(buffer, buffer_size,
			"<SessionStatus nflags:%x, status_flags:%x, log_mask:%x>",
			nflags, status_flags, log_level);
		buffer[buffer_size - 1] = '\0';
		return buffer;
	}
};

template <typename T>
static std::vector<T> convert_to_vector(const bp::api::object &list)
{
	bp::stl_input_iterator<T> begin(list), end;
	return std::vector<T>(begin, end);
}

struct elliptics_range {
	elliptics_range() : offset(0), size(0),
		limit_start(0), limit_num(0), ioflags(0), group_id(0) {}

	dnet_io_attr io_attr() const {
		dnet_io_attr io;

		memcpy(io.id, start.id().id, sizeof(io.id));
		memcpy(io.parent, end.id().id, sizeof(io.parent));

		io.flags = ioflags;
		io.size = size;
		io.offset = offset;
		io.start = limit_start;
		io.num = limit_num;

		return io;
	}

	elliptics_id	start, end;
	uint64_t		offset, size;
	uint64_t		limit_start, limit_num;
	uint32_t		ioflags;
	int				group_id;
};

class elliptics_session: public session, public bp::wrapper<session> {
	public:
		elliptics_session(const node &n) : session(n) {}

		elliptics_id transform(const std::string &data) {
			dnet_id id;
			session::transform(data, id);
			return elliptics_id(id);
		}

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

		void set_exceptions_policy(uint32_t policy) {
			session::set_exceptions_policy(policy);
		}

		uint32_t get_exceptions_policy() const {
			return session::get_exceptions_policy();
		}

		void set_namespace(const std::string& ns) {
			session::set_namespace(ns.c_str(), ns.size());
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
			return create_result(std::move(session::read_data_range(r.io_attr(), r.group_id)));
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
			return create_result(std::move(session::start_iterator(elliptics_id::convert(id), std_ranges, type, flags, time_begin.m_time, time_end.m_time)));
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
			session::transform(eid);
			return create_result(std::move(session::exec(const_cast<dnet_id*>(&eid.id()), src_key, event, data)));
		}

		python_exec_result exec(const bp::api::object &id, const std::string &event, const std::string &data) {
			auto eid = elliptics_id::convert(id);
			session::transform(eid);
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
				session::transform(e_id);
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
				session::transform(e_id);

				std::string &data = bp::extract<std::string&>((*it)[1]);

				auto it_len = bp::len(*it);
				if (it_len > 2) {
					elliptics_time e_time = bp::extract<elliptics_time>((*it)[2]);
					io.timestamp = e_time.m_time;
				}
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
				session::transform(e_id);
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
				session::transform(e_id);
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

void init_elliptcs_session() {

	bp::class_<elliptics_status>("SessionStatus", bp::init<>())
		.def_readwrite("nflags", &dnet_node_status::nflags)
		.def_readwrite("status_flags", &dnet_node_status::status_flags)
		.def_readwrite("log_level", &dnet_node_status::log_level)
		.def("__repr__", &elliptics_status::dnet_node_status_repr)
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

	bp::class_<elliptics_session, boost::noncopyable>("Session", bp::init<node &>())
		.def("transform", &elliptics_session::transform, (bp::args("data")))

		.add_property("groups", &elliptics_session::get_groups,
		                        &elliptics_session::set_groups)
		.def("add_groups", &elliptics_session::set_groups)
		.def("set_groups", &elliptics_session::set_groups)
		.def("get_groups", &elliptics_session::get_groups)

		.add_property("cflags", &elliptics_session::get_cflags,
		                        &elliptics_session::set_cflags)
		.def("set_cflags", &elliptics_session::set_cflags)
		.def("get_cflags", &elliptics_session::get_cflags)

		.add_property("ioflags", &elliptics_session::get_ioflags,
		                         &elliptics_session::set_ioflags)
		.def("set_ioflags", &elliptics_session::set_ioflags)
		.def("get_ioflags", &elliptics_session::get_ioflags)

		.def("set_direct_id", &elliptics_session::set_direct_id)
		.def("get_direct_id", &elliptics_session::get_direct_id)

		.add_property("exceptions_policy", &elliptics_session::get_exceptions_policy,
		                                   &elliptics_session::set_exceptions_policy)
		.def("set_exceptions_policy", &elliptics_session::set_exceptions_policy)
		.def("get_exceptions_policy", &elliptics_session::get_exceptions_policy)

		.def("set_namespace", &elliptics_session::set_namespace)

		.add_property("user_flags", &elliptics_session::get_user_flags,
		                                   &elliptics_session::set_user_flags)
		.def("set_user_flags", &elliptics_session::set_user_flags)
		.def("get_user_flags", &elliptics_session::get_user_flags)

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
}

} } } // namespace ioremap::elliptics::python