/*
* 2013+ Copyright (c) Kirill Smorodinnikov <shaitkir@gmail.com>
* All rights reserved.
*
* This program is free software; you can redistribute it and/or modify
* it under the terms of the GNU Lesser General Public License as published by
* the Free Software Foundation; either version 2 of the License, or
* (at your option) any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
* GNU Lesser General Public License for more details.
*/

#include "elliptics_session.h"

#include <boost/python.hpp>
#include <boost/python/object.hpp>
#include <boost/python/list.hpp>
#include <boost/python/dict.hpp>
#include <boost/python/stl_iterator.hpp>
#include <boost/python/manage_new_object.hpp>
#include <boost/python/return_value_policy.hpp>


#include <boost/make_shared.hpp>

#include <elliptics/session.hpp>

#include "elliptics_id.h"
#include "async_result.h"
#include "result_entry.h"
#include "elliptics_time.h"
#include "gil_guard.h"
#include "py_converters.h"
#include "elliptics_io_attr.h"

namespace bp = boost::python;

namespace ioremap { namespace elliptics { namespace python {

enum elliptics_filters {
	elliptics_filters_positive = 0,
	elliptics_filters_positive_with_ack,
	elliptics_filters_positive_final,
	elliptics_filters_negative,
	elliptics_filters_negative_with_ack,
	elliptics_filters_negative_final,
	elliptics_filters_all,
	elliptics_filters_all_with_ack,
	elliptics_filters_all_final,
};

enum elliptics_checkers {
	elliptics_checkers_no_check = 0,
	elliptics_checkers_at_least_one,
	elliptics_checkers_all,
	elliptics_checkers_quorum,
};

enum elliptics_monitor_categories {
	elliptics_monitor_categories_cache = DNET_MONITOR_CACHE,
	elliptics_monitor_categories_io = DNET_MONITOR_IO,
	elliptics_monitor_categories_commands = DNET_MONITOR_COMMANDS,
	elliptics_monitor_categories_backend = DNET_MONITOR_BACKEND,
	elliptics_monitor_categories_stats = DNET_MONITOR_STATS,
	elliptics_monitor_categories_procfs = DNET_MONITOR_PROCFS,
	elliptics_monitor_categories_top = DNET_MONITOR_TOP,
	elliptics_monitor_categories_all = DNET_MONITOR_CACHE |
	                                   DNET_MONITOR_IO |
	                                   DNET_MONITOR_COMMANDS |
	                                   DNET_MONITOR_BACKEND |
	                                   DNET_MONITOR_STATS |
	                                   DNET_MONITOR_PROCFS |
	                                   DNET_MONITOR_TOP
};

struct write_cas_converter {
	write_cas_converter(PyObject *converter): py_converter(converter) {}

	data_pointer convert(const data_pointer &data) {
		gil_guard gstate;
		std::string ret = bp::call<std::string>(py_converter, data.to_string());
		return data_pointer::copy(ret);
	}

	PyObject *py_converter;
};

class elliptics_status : public dnet_node_status {
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

struct elliptics_range {
	elliptics_range()
	: offset(0), size(0)
	, limit_start(0), limit_num(0)
	, ioflags(0), group_id(0) {}

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

elliptics_id dnet_iterator_range_get_key_begin(const dnet_iterator_range *range)
{
	return elliptics_id(range->key_begin);
}

void dnet_iterator_range_set_key_begin(dnet_iterator_range *range, const elliptics_id &id)
{
	memcpy(range->key_begin.id, id.id().id, DNET_ID_SIZE);
}

elliptics_id dnet_iterator_range_get_key_end(const dnet_iterator_range *range)
{
	return elliptics_id(range->key_end);
}

void dnet_iterator_range_set_key_end(dnet_iterator_range *range, const elliptics_id &id)
{
	memcpy(range->key_end.id, id.id().id, DNET_ID_SIZE);
}

class elliptics_session: public session, public bp::wrapper<session> {
public:
	elliptics_session(const node &n) : session(n) {}
	elliptics_session(const session &s) : session(s) {}

	elliptics_session* clone() const {
		return new elliptics_session(session::clone());
	}

	elliptics_id transform(const bp::api::object &data) {
		bp::extract<elliptics_id> get_id(data);
		bp::extract<std::string> get_string(data);

		if (get_id.check())
			return get_id();

		if (get_string.check()) {
			dnet_id id;
			memset(&id, 0, sizeof(dnet_id));
			session::transform(get_string(), id);
			return elliptics_id(id);
		}

		PyErr_SetString(PyExc_ValueError, "Couldn't transform value to elliptics.Id");
		bp::throw_error_already_set();

		return elliptics_id();
	}

	void set_groups(const bp::api::object &groups) {
		session::set_groups(convert_to_vector<int>(groups));
	}

	void set_direct_id(std::string host, int port, int family, const bp::api::object &backend_id) {
		if (backend_id.ptr() != Py_None) {
			bp::extract<uint32_t> get_backend(backend_id);
			session::set_direct_id(address(host, port, family), get_backend());
		} else {
			session::set_direct_id(address(host, port, family));
		}
	}

	struct elliptics_id get_direct_id() {
		return session::get_direct_id();
	}

	bp::list get_groups() {
		return convert_to_list(session::get_groups());
	}

	void set_trace_id(trace_id_t trace_id) {
		session::set_trace_id(trace_id);
	}

	trace_id_t get_trace_id() {
		return session::get_trace_id();
	}

	void set_namespace(const std::string& ns) {
		session::set_namespace(ns.c_str(), ns.size());
	}

	void set_timestamp(const bp::api::object &time_obj) {
		if (time_obj.ptr() == Py_None) {
			dnet_time ts;
			dnet_empty_time(&ts);
			session::set_timestamp(&ts);
		}
		else {
			elliptics_time &ts = bp::extract<elliptics_time&>(time_obj);
			session::set_timestamp(&ts.m_time);
		}
	}

	elliptics_time get_timestamp() {
		dnet_time ts;
		session::get_timestamp(&ts);
		return elliptics_time(ts);
	}

	void set_filter(elliptics_filters filter) {
		auto res = filters::positive;
		switch (filter) {
			default:
			case elliptics_filters_positive:
					res = filters::positive;
					break;
			case elliptics_filters_positive_with_ack:
					res = filters::positive_with_ack;
					break;
			case elliptics_filters_positive_final:
					res = filters::positive_final;
					break;
			case elliptics_filters_negative:
					res = filters::negative;
					break;
			case elliptics_filters_negative_with_ack:
					res = filters::negative_with_ack;
					break;
			case elliptics_filters_negative_final:
					res = filters::negative_final;
					break;
			case elliptics_filters_all:
					res = filters::all;
					break;
			case elliptics_filters_all_with_ack:
					res = filters::all_with_ack;
					break;
			case elliptics_filters_all_final:
					res = filters::all_final;
					break;
		}

		session::set_filter(res);
	}

	void set_checker(elliptics_checkers checker) {
		auto res = checkers::at_least_one;
		switch (checker) {
			case elliptics_checkers_no_check:
				res = checkers::no_check;
				break;
			case elliptics_checkers_all:
				res = checkers::all;
				break;
			case elliptics_checkers_quorum:
				res = checkers::quorum;
				break;
			default:
				break;
		}

		session::set_checker(res);
	}

	void read_file(const bp::api::object &id, const std::string &file, uint64_t offset, uint64_t size) {
		py_allow_threads_scoped pythr;

		bp::extract<elliptics_io_attr&> get_io_attr(id);
		if (!get_io_attr.check())
			return session::read_file(transform(id).id(), file, offset, size);

		elliptics_io_attr &io_attr = get_io_attr;
		transform_io_attr(io_attr);

		return session::read_file(io_attr.id.id(), file, io_attr.offset, io_attr.size);
	}

	void write_file(const bp::api::object &id, const std::string &file, uint64_t local_offset, uint64_t offset, uint64_t size) {
		py_allow_threads_scoped pythr;

		bp::extract<elliptics_io_attr&> get_io_attr(id);
		if (!get_io_attr.check())
			return session::write_file(transform(id).id(), file, local_offset, offset, size);

		elliptics_io_attr &io_attr = get_io_attr;
		transform_io_attr(io_attr);

		return session::write_file(io_attr.id.id(), file, local_offset, io_attr.offset, io_attr.size);
	}

	python_read_result read_data(const bp::api::object &id, uint64_t offset, uint64_t size) {
		bp::extract<elliptics_io_attr&> get_io_attr(id);
		if (!get_io_attr.check())
			return create_result(std::move(session::read_data(transform(id).id(), offset, size)));

		elliptics_io_attr &io_attr = get_io_attr;
		transform_io_attr(io_attr);

		return create_result(std::move(session::read_data(io_attr.id.id(), io_attr.offset, io_attr.size)));
	}

	python_read_result read_data_from_groups(const bp::api::object &id, const bp::api::object &groups, uint64_t offset, uint64_t size) {
		auto std_groups = convert_to_vector<int>(groups);

		bp::extract<elliptics_io_attr&> get_io_attr(id);
		if (!get_io_attr.check())
			return create_result(std::move(session::read_data(transform(id).id(), std_groups, offset, size)));

		elliptics_io_attr &io_attr = get_io_attr;
		transform_io_attr(io_attr);

		return create_result(std::move(session::read_data(io_attr.id.id(), std_groups, io_attr.offset, io_attr.size)));
	}

	python_lookup_result prepare_latest(const bp::api::object &id, const bp::api::object &gl) {
		std::vector<int> groups = convert_to_vector<int>(gl);
		bp::extract<elliptics_io_attr&> get_io_attr(id);
		if (!get_io_attr.check())
			return create_result(std::move(session::prepare_latest(transform(id).id(), groups)));

		elliptics_io_attr &io_attr = get_io_attr;
		transform_io_attr(io_attr);

		return create_result(std::move(session::prepare_latest(io_attr.id.id(), groups)));
	}

	python_read_result read_latest(const bp::api::object &id, uint64_t offset, uint64_t size) {
		bp::extract<elliptics_io_attr&> get_io_attr(id);
		if (!get_io_attr.check())
			return create_result(std::move(session::read_latest(transform(id).id(), offset, size)));

		elliptics_io_attr &io_attr = get_io_attr;
		transform_io_attr(io_attr);

		return create_result(std::move(session::read_latest(io_attr.id.id(), io_attr.offset, io_attr.size)));
	}

	python_write_result write_data(const bp::api::object &id, const std::string &data, uint64_t offset) {
		bp::extract<elliptics_io_attr&> get_io_attr(id);
		if (!get_io_attr.check())
			return create_result(std::move(session::write_data(transform(id).id(), data_pointer::copy(data), offset)));

		elliptics_io_attr &io_attr = get_io_attr;
		transform_io_attr(io_attr);

		return create_result(std::move(session::write_data(io_attr, data_pointer::copy(data))));
	}

	python_write_result write_data_by_chunks(const bp::api::object &id, const std::string &data, uint64_t offset, uint64_t chunk_size) {
		if (chunk_size == 0)
			return write_data(id, data, offset);

		bp::extract<elliptics_io_attr&> get_io_attr(id);
		if (!get_io_attr.check())
			return create_result(std::move(session::write_data(transform(id).id(), data_pointer::copy(data), offset, chunk_size)));

		elliptics_io_attr &io_attr = get_io_attr;
		transform_io_attr(io_attr);

		return create_result(std::move(session::write_data(io_attr.id.id(), data_pointer::copy(data), io_attr.offset, chunk_size)));
	}

	python_write_result write_cas(const bp::api::object &id, const std::string &data, const elliptics_id &old_csum, uint64_t remote_offset) {
		return create_result(std::move(session::write_cas(transform(id).id(), data_pointer::copy(data), old_csum.id(), remote_offset)));
	}

	python_write_result write_cas_callback(const bp::api::object &id, bp::api::object &converter, uint64_t remote_offset, int count) {
		auto wc_converter = boost::make_shared<write_cas_converter>(converter.ptr());
		return create_result(std::move(session::write_cas(transform(id).id(),
		                     boost::bind(&write_cas_converter::convert, wc_converter, _1),
		                     remote_offset,
		                     count)));
	}

	python_write_result write_prepare(const bp::api::object &id, const std::string &data, uint64_t remote_offset, uint64_t psize) {
		return create_result(std::move(session::write_prepare(transform(id).id(), data_pointer::copy(data), remote_offset, psize)));
	}

	python_write_result write_plain(const bp::api::object &id, const std::string &data, uint64_t remote_offset) {
		return create_result(std::move(session::write_plain(transform(id).id(), data_pointer::copy(data), remote_offset)));
	}

	python_write_result write_commit(const bp::api::object &id, const std::string &data, uint64_t remote_offset, uint64_t csize) {
		return create_result(std::move(session::write_commit(transform(id).id(), data_pointer::copy(data), remote_offset, csize)));
	}

	python_write_result write_cache(const bp::api::object &id, const std::string &data, long timeout) {
		return create_result(std::move(session::write_cache(transform(id).id(), data_pointer::copy(data), timeout)));
	}

	std::string lookup_address(const bp::api::object &id, const int group_id) {
		return session::lookup_address(transform(id).id(), group_id);
	}

	python_lookup_result lookup(const bp::api::object &id) {
		return create_result(std::move(session::lookup(transform(id).id())));
	}

	elliptics_status update_status(const std::string &host, const int port,
	                               const int family, elliptics_status &status) {
		session::update_status(address(host, port, family), &status);
		return status;
	}

	python_backend_status_result enable_backend(const std::string &host, int port, int family, uint32_t backend_id) {
		return create_result(std::move(session::enable_backend(address(host, port, family), backend_id)));
	}

	python_backend_status_result disable_backend(const std::string &host, int port, int family, uint32_t backend_id) {
		return create_result(std::move(session::disable_backend(address(host, port, family), backend_id)));
	}

	python_backend_status_result start_defrag(const std::string &host, int port, int family, uint32_t backend_id) {
		return create_result(std::move(session::start_defrag(address(host, port, family), backend_id)));
	}

	python_backend_status_result set_backend_ids(const std::string &host, int port, int family, uint32_t backend_id, const bp::api::object &ids) {
		std::vector<dnet_raw_id> std_ids;
		std_ids.reserve(bp::len(ids));

		for (bp::stl_input_iterator<bp::api::object> it(ids), end; it != end; ++it) {
			std_ids.push_back(transform(*it).raw_id());
		}
		return create_result(std::move(session::set_backend_ids(address(host, port, family), backend_id, std_ids)));
	}

	python_backend_status_result request_backends_status(const std::string &host, int port, int family) {
		return create_result(std::move(session::request_backends_status(address(host, port, family))));
	}

	python_backend_status_result make_readonly(const std::string &host, int port, int family, uint32_t backend_id) {
		return create_result(std::move(session::make_readonly(address(host, port, family), backend_id)));
	}

	python_backend_status_result make_writable(const std::string &host, int port, int family, uint32_t backend_id) {
		return create_result(std::move(session::make_writable(address(host, port, family), backend_id)));
	}


	python_read_result read_data_range(const elliptics_range &r) {
		return create_result(std::move(session::read_data_range(r.io_attr(), r.group_id)));
	}

	python_read_result remove_data_range(const elliptics_range &r) {
		return create_result(std::move(session::remove_data_range(r.io_attr(), r.group_id)));
	}

	bp::list get_routes() {
		auto routes = session::get_routes();
		return convert_to_list(routes);
	}

	python_iterator_result start_iterator(const bp::api::object &id, const bp::api::object &ranges,
	                                      uint32_t type, uint64_t flags,
	                                      const elliptics_time& time_begin = elliptics_time(0, 0),
	                                      const elliptics_time& time_end = elliptics_time(-1, -1)) {
		std::vector<dnet_iterator_range> std_ranges = convert_to_vector<dnet_iterator_range>(ranges);

		return create_result(std::move(session::start_iterator(transform(id).id(), std_ranges, type, flags, time_begin.m_time, time_end.m_time)));
	}

	python_iterator_result pause_iterator(const bp::api::object &id, const uint64_t &iterator_id) {
		return create_result(std::move(session::pause_iterator(transform(id).id(), iterator_id)));
	}

	python_iterator_result continue_iterator(const bp::api::object &id, const uint64_t &iterator_id) {
		return create_result(std::move(session::continue_iterator(transform(id).id(), iterator_id)));
	}

	python_iterator_result cancel_iterator(const bp::api::object &id, const uint64_t &iterator_id) {
		return create_result(std::move(session::cancel_iterator(transform(id).id(), iterator_id)));
	}

	python_exec_result exec(const bp::api::object &id_or_context, const std::string &event, const bp::api::object &data, const int src_key) {
		dnet_id* raw_id = NULL;
		dnet_id conv_id;

		std::string str_data;
		if (data.ptr() != Py_None) {
			bp::extract<std::string> get_data(data);
			str_data = get_data();
		}

		if (id_or_context.ptr() != Py_None) {
			bp::extract<exec_context> get_context(id_or_context);
			if (get_context.check()) {
				return create_result(std::move(session::exec(get_context(), event, data_pointer::copy(str_data))));
			} else {
				conv_id = transform(id_or_context).id();
				raw_id = &conv_id;
			}
		}

		return create_result(std::move(session::exec(raw_id, src_key, event, data_pointer::copy(str_data))));
	}

	python_exec_result push(const bp::api::object &id, const exec_context &context, const std::string &event, const bp::api::object &data) {
		dnet_id* raw_id = NULL;
		dnet_id conv_id;

		std::string str_data;
		if (data.ptr() != Py_None) {
			bp::extract<std::string> get_data(data);
			str_data = get_data();
		}

		if (id.ptr() != Py_None) {
			conv_id = transform(id).id();
			raw_id = &conv_id;
		}

		return create_result(std::move(session::push(raw_id, context, event, data_pointer::copy(str_data))));
	}

	python_exec_result reply(const exec_context &context, const bp::api::object &data, exec_context::final_state final_state) {
		std::string str_data;
		if (data.ptr() != Py_None) {
			bp::extract<std::string> get_data(data);
			str_data = get_data();
		}

		return create_result(std::move(session::reply(context, data_pointer::copy(str_data), final_state)));
	}

	python_remove_result remove(const bp::api::object &id) {
		return create_result(std::move(session::remove(transform(id).id())));
	}

	struct dnet_id_comparator {
		bool operator() (const struct dnet_id &first, const struct dnet_id &second) const
		{
			return memcmp(first.id, second.id, sizeof(first.id)) < 0;
		}
	};

	python_read_result bulk_read(const bp::api::object &keys) {
		std::vector<dnet_io_attr> ios;
		ios.reserve(bp::len(keys));

		for (bp::stl_input_iterator<bp::api::object> it(keys), end; it != end; ++it) {
			elliptics_io_attr io_attr = convert_io_attr(*it);
			transform_io_attr(io_attr);
			ios.push_back(io_attr);
		}

		return create_result(std::move(session::bulk_read(ios)));
	}

	python_write_result bulk_write(const bp::api::object &datas) {
		std::vector<dnet_io_attr> ios;
		std::vector<std::string> wdatas;

		auto datas_len = bp::len(datas);
		ios.reserve(datas_len);
		wdatas.reserve(datas_len);

		for (bp::stl_input_iterator<bp::tuple> it(datas), end; it != end; ++it) {
			elliptics_io_attr io_attr = convert_io_attr((*it)[0]);
			transform_io_attr(io_attr);

			bp::extract<std::string> get_data((*it)[1]);

			wdatas.push_back(get_data());
			ios.push_back(io_attr);
		}

		return create_result(std::move(session::bulk_write(ios, wdatas)));
	}

	python_callback_result set_indexes(const bp::api::object &id, const bp::api::object &indexes, const bp::api::object &datas) {
		auto std_indexes = convert_to_vector<std::string>(indexes);
		auto std_datas = convert_to_vector<data_pointer>(datas);

		return create_result(std::move(session::set_indexes(transform(id).raw_id(), std_indexes, std_datas)));
	}

	python_callback_result set_indexes_raw(const bp::api::object &id, const bp::api::object &indexes) {
		auto std_indexes = convert_to_vector<index_entry>(indexes);

		return create_result(std::move(session::set_indexes(transform(id).raw_id(), std_indexes)));
	}

	python_callback_result update_indexes(const bp::api::object &id, const bp::api::object &indexes, const bp::api::object &datas) {
		auto std_indexes = convert_to_vector<std::string>(indexes);
		auto std_datas = convert_to_vector<data_pointer>(datas);

		return create_result(std::move(session::update_indexes(transform(id).raw_id(), std_indexes, std_datas)));
	}

	python_callback_result update_indexes_raw(const bp::api::object &id, const bp::api::object &indexes) {
		auto std_indexes = convert_to_vector<index_entry>(indexes);

		return create_result(std::move(session::update_indexes(transform(id).raw_id(), std_indexes)));
	}

	python_callback_result update_indexes_internal(const bp::api::object &id, const bp::api::object &indexes, const bp::api::object &datas) {
		auto std_indexes = convert_to_vector<std::string>(indexes);
		auto std_datas = convert_to_vector<data_pointer>(datas);

		return create_result(std::move(session::update_indexes_internal(transform(id).raw_id(), std_indexes, std_datas)));
	}

	python_callback_result update_indexes_internal_raw(const bp::api::object &id, const bp::api::object &indexes) {
		auto std_indexes = convert_to_vector<index_entry>(indexes);

		return create_result(std::move(session::update_indexes_internal(transform(id).raw_id(), std_indexes)));
	}

	python_callback_result add_to_capped_collection(const bp::api::object &id, const index_entry &index, int limit, bool remove_data) {
		return create_result(std::move(session::add_to_capped_collection(transform(id).raw_id(), index, limit, remove_data)));
	}

	python_find_indexes_result find_all_indexes(const bp::api::object &indexes) {
		auto std_indexes = convert_to_vector<std::string>(indexes);

		return create_result(std::move(session::find_all_indexes(std_indexes)));
	}

	python_find_indexes_result find_all_indexes_raw(const bp::api::object &indexes) {
		std::vector<dnet_raw_id> std_indexes;
		std_indexes.reserve(bp::len(indexes));

		for (bp::stl_input_iterator<bp::api::object> it(indexes), end; it != end; ++it) {
			std_indexes.push_back(transform(*it).raw_id());
		}

		return create_result(std::move(session::find_all_indexes(std_indexes)));
	}

	python_find_indexes_result find_any_indexes(const bp::api::object &indexes) {
		auto std_indexes = convert_to_vector<std::string>(indexes);

		return create_result(std::move(session::find_any_indexes(std_indexes)));
	}

	python_find_indexes_result find_any_indexes_raw(const bp::api::object &indexes) {
		std::vector<dnet_raw_id> std_indexes;
		std_indexes.reserve(bp::len(indexes));

		for (bp::stl_input_iterator<bp::api::object> it(indexes), end; it != end; ++it) {
			std_indexes.push_back(transform(*it).raw_id());
		}

		return create_result(std::move(session::find_any_indexes(std_indexes)));
	}

	python_check_indexes_result list_indexes(const bp::api::object &id) {
		return create_result(std::move(session::list_indexes(transform(id).raw_id())));
	}

	python_write_result merge_indexes(const bp::api::object &id, const bp::api::object &from, const bp::api::object &to) {
		auto std_from = convert_to_vector<int>(from);
		auto std_to = convert_to_vector<int>(to);
		return create_result(std::move(session::merge_indexes(transform(id).raw_id(), std_from, std_to)));
	}

	python_callback_result recover_index(const bp::api::object &index) {
		return create_result(std::move(session::recover_index(transform(index).raw_id())));
	}

	python_callback_result remove_indexes(const bp::api::object &id, const bp::api::object &indexes) {
		auto std_indexes = convert_to_vector<std::string>(indexes);

		return create_result(std::move(session::remove_indexes(transform(id).raw_id(), std_indexes)));
	}

	python_callback_result remove_indexes_internal(const bp::api::object &id, const bp::api::object &indexes) {
		auto std_indexes = convert_to_vector<std::string>(indexes);

		return create_result(std::move(session::remove_indexes_internal(transform(id).raw_id(), std_indexes)));
	}

	python_remove_result remove_index(const bp::api::object &id, bool remove_data) {
		return create_result(std::move(session::remove_index(transform(id).raw_id(), remove_data)));
	}

	python_remove_result remove_index_internal(const bp::api::object &id) {
		return create_result(std::move(session::remove_index_internal(transform(id).raw_id())));
	}

	python_monitor_stat_result monitor_stat(const bp::tuple &addr, uint64_t categories) {
		if (bp::len(addr) == 0)
			return create_result(std::move(session::monitor_stat(categories)));

		bp::extract<std::string> get_host(addr[0]);
		bp::extract<int> get_port(addr[1]);
		bp::extract<int> get_family(addr[2]);

		return create_result(std::move(session::monitor_stat(address(get_host(),
		                                                             get_port(),
		                                                             get_family()),
		                                                     categories)));
	}

private:
	void transform_io_attr(elliptics_io_attr &io_attr) {
		auto& io = static_cast<dnet_io_attr&>(io_attr);

		memcpy(io.parent, io_attr.parent.id().id, sizeof(io.parent));
		memcpy(io.id, io_attr.id.id().id, sizeof(io.id));
		io.timestamp = io_attr.time.m_time;
	}

	elliptics_io_attr convert_io_attr(const bp::api::object &obj) {
		bp::extract<elliptics_io_attr&> get_io_attr(obj);
		if (get_io_attr.check()) {
			elliptics_io_attr &io_attr = get_io_attr;
			return io_attr;
		}
		else {
			elliptics_io_attr io_attr;
			io_attr.id = transform(obj);
			return io_attr;
		}
	}
};

void init_elliptics_session() {

	bp::enum_<elliptics_filters>("filters",
	    "Built-in replies filters. It is used at session.set_filter:\n\n"
	    "positive\n    Filters only positive replies\n"
	    "negative\n    Filters only negative replies\n"
	    "all\n    Doesn't apply any filter on replies\n"
	    "all_with_ack\n    Filters replies with ack")
		.value("positive", elliptics_filters_positive)
		.value("positive_with_ack", elliptics_filters_positive_with_ack)
		.value("positive_final", elliptics_filters_positive_final)
		.value("negative", elliptics_filters_negative)
		.value("negative_with_ack", elliptics_filters_negative_with_ack)
		.value("negative_final", elliptics_filters_negative_final)
		.value("all", elliptics_filters_all)
		.value("all_with_ack", elliptics_filters_all_with_ack)
		.value("all_final", elliptics_filters_all_final)
	;

	bp::enum_<elliptics_checkers>("checkers",
	    "Different strategies to determine the success of the operation. It is used at session.set_checkers:\n\n"
	    "no_check\n    The operation is always successful\n"
	    "at_least_one\n    The operation is successful if at least one group returns positive result\n"
	    "all\n    The operation is successful if all groups return positive result\n"
	    "quorum\n    The operation is successful if more than half of groups returns positive result")
		.value("no_check", elliptics_checkers_no_check)
		.value("at_least_one", elliptics_checkers_at_least_one)
		.value("all", elliptics_checkers_all)
		.value("quorum", elliptics_checkers_quorum)
	;

	bp::enum_<elliptics_monitor_categories>("monitor_stat_categories",
	    "Different categories of monitor statistics that can be requested:\n\n"
		"all\n    Category for requesting all available statistics\n"
		"cache\n    Category for cache statistics\n"
		"io\n    Category for IO queue statistics\n"
		"commands\n    Category for commands statistics\n"
		"backend\n    Category for backend statistics\n"
		"stats\n    Category for in-process runtime statistics\n"
		"procfs\n    Category for system statistics about process\n"
		"top\n    Category for statistics of top keys ordered by generated traffic\n")
		.value("all", elliptics_monitor_categories_all)
		.value("cache", elliptics_monitor_categories_cache)
		.value("io", elliptics_monitor_categories_io)
		.value("commands", elliptics_monitor_categories_commands)
		.value("backend", elliptics_monitor_categories_backend)
		.value("stats", elliptics_monitor_categories_stats)
		.value("procfs", elliptics_monitor_categories_procfs)
		.value("top", elliptics_monitor_categories_top)
	;

	bp::enum_<exec_context::final_state>("exec_context_final_states",
	    "Final states of exec context\n")
		.value("progressive", exec_context::final_state::progressive)
		.value("final", exec_context::final_state::final)
	;

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

	bp::class_<dnet_iterator_range>("IteratorRange",
	    "Used in iteration for specifying elliptics.Id ranges for filtering results")
		.add_property("key_begin", dnet_iterator_range_get_key_begin,
		                           dnet_iterator_range_set_key_begin,
		              "Start of elliptics.Id range\n\n"
		              "range.key_begin = elliptics.Id([0] * 64, 1)")
		.add_property("key_end", dnet_iterator_range_get_key_end,
		                         dnet_iterator_range_set_key_end,
		              "End of elliptics.Id range\n\n"
		              "range.key_end = elliptics.Id([255] * 64, 1)")
	;

	bp::class_<elliptics_session, boost::noncopyable>(
	        "Session",
	        "The main class which is used for executing operations with elliptics",
	        bp::init<node &>(bp::arg("node"),
	            "__init__(node)\n"
	            "    Initializes session by the node\n\n"
	            "    session = elliptics.Session(node)"))
		.def("clone", &elliptics_session::clone,
		     bp::return_value_policy<bp::manage_new_object>(),
		     "clone()\n"
		     "    Creates and returns session which is equal to current\n"
		     "    but complitely independent from it.\n\n"
		     "    cloned_session = session.clone()\n")
		.def("transform", &elliptics_session::transform, (bp::args("data")),
		     "transform(data)\n"
		     "    Transforms string data to elliptics.Id\n\n"
		     "    id = session.transform('some data')\n")

		.add_property("groups",
		              &elliptics_session::get_groups,
		              &elliptics_session::set_groups,
		    "Elliptics groups with which session will work\n\n"
		    "print session.groups #outputs current groups\n"
		    "session.groups = [1, 2, 3]")
		.def("add_groups", &elliptics_session::set_groups)
		.def("set_groups", &elliptics_session::set_groups)
		.def("get_groups", &elliptics_session::get_groups)

		.add_property("trace_id",
		              &elliptics_session::get_trace_id,
		              &elliptics_session::set_trace_id,
		    "Sets debug trace_id which will be printed in all logs\n"
		    "connected with operations executed by the sesssion.\n"
		    "All logs connected with operations executed by the session\n"
		    "will be printed with ignoring current log level\n\n"
		    "session.trace_id = 123456")

		.add_property("cflags",
		              &elliptics_session::get_cflags,
		              &elliptics_session::set_cflags,
		    "elliptics.command_flags which would be applied to\n"
		    "all operations executed by the session.\n\n"
		    "session.cflags = elliptics.command_flags.default")
		.def("set_cflags", &elliptics_session::set_cflags)
		.def("get_cflags", &elliptics_session::get_cflags)

		.add_property("ioflags",
		              &elliptics_session::get_ioflags,
		              &elliptics_session::set_ioflags,
		    "Bit sets of elliptics.io_flags which would be applied to\n"
		    "all operations executed by the session.\n\n"
		    "session.ioflags = elliptics.io_flags.append | elliptics.io_flags.cache")
		.def("set_ioflags", &elliptics_session::set_ioflags)
		.def("get_ioflags", &elliptics_session::get_ioflags)

		.def("set_direct_id", &elliptics_session::set_direct_id,
		     (bp::arg("host"), bp::arg("port"), bp::arg("family") = 2, bp::arg("backend_id")=bp::api::object()),
		    "set_direct_id(host, port, family=2, backend_id=None)\n"
		    "    Makes elliptics.Session works with only specified backend directly\n\n"
		    "    session.set_direct_id(host='host.com', port = 1025, family=2, backend_id=5)")

		.def("get_direct_id", &elliptics_session::get_direct_id,
		    "get_direct_id()\n"
		    "    Rerurns elliptics.Id of current direct node\n\n"
		    "    id = session.get_direct_id()")

		.add_property("exceptions_policy",
		              &elliptics_session::get_exceptions_policy,
		              &elliptics_session::set_exceptions_policy,
		    "Exceptions policy for the session\n\n"
		    "session.exceptions_policy = elliptics.exceptions_policy.no_exceptions")
		.def("set_exceptions_policy", &elliptics_session::set_exceptions_policy)
		.def("get_exceptions_policy", &elliptics_session::get_exceptions_policy)

		.def("set_namespace", &elliptics_session::set_namespace, (bp::arg("namespace")),
		    "set_namespace(namespace)\n"
		    "    Sets namespace for session\n\n"
		    "    session.set_namespace('Hello, World! Application Namespace')")

		.add_property("user_flags",
		              &elliptics_session::get_user_flags,
		              &elliptics_session::set_user_flags,
		    "Custom user-defined flags which would be applied to\n"
		    "all operations executed by the session\n\n"
		    "session.user_flags = 12345")
		.def("set_user_flags", &elliptics_session::set_user_flags)
		.def("get_user_flags", &elliptics_session::get_user_flags)

		.add_property("timestamp",
		              &elliptics_session::get_timestamp,
		              &elliptics_session::set_timestamp,
		    "Timestamp which would be applied to\n"
		    "all operations executed by the session\n\n"
		    "session.timestamp = elliptics.Time.now()")
		.def("set_timestamp", &elliptics_session::set_timestamp)
		.def("get_timestamp", &elliptics_session::get_timestamp)

		.add_property("timeout",
		              &elliptics_session::get_timeout,
		              &elliptics_session::set_timeout,
		    "Timeout in secods for operations which will be executed by the session\n"
		    "Overwrites values of node.wait_timeout for the session\n\n"
		    "session.timeout = 10")
		.def("set_timeout", &elliptics_session::set_timeout)
		.def("get_timeout", &elliptics_session::get_timeout)

		.add_property("routes", &elliptics_session::get_routes,
		     "routes\n"
		     "    Returns current routes table\n\n"
		     "    routes = session.routes")

		.def("set_filter", &elliptics_session::set_filter,
		     bp::args("filter"),
		    "set_filter(filter)\n"
		    "    Sets replies filter to the session\n\n"
		    "    session.set_filter(elliptics.filters.positive)  #filters only positive replies")

		.def("set_checker", &elliptics_session::set_checker,
		     bp::args("checker"),
		    "set_checker(checker)\n"
		    "    Sets to session how it should determines whether operation successful or not\n\n"
		    "    session.set_checker(elliptics.checkers.quorum)")

//Lookup operations

		.def("lookup", &elliptics_session::lookup,
		     bp::args("key"),
		    "lookup(key)\n"
		    "    Looks up meta information about the key. Returns elliptics.AsyncResult\n"
		    "    -- key - string or elliptics.Id\n\n"
		    "    result = session.lookup('looking up key')\n"
		    "    lookups = []\n"
		    "    try:\n"
		    "        lookups = result.get()\n"
		    "    except Exception as e:\n"
		    "        print 'Lookup is failed: ', e\n"
		    "    for lookup in lookups:\n"
		    "        print 'The \\'looking up key\\' exists on node:', lookup.address, '. It has:'\n"
		    "        print 'size:', lookup.size\n"
		    "        print 'offset', lookup.offset\n"
		    "        print 'timestamp:', lookup.timestamp\n"
		    "        print 'filepath:', lookup.filepath\n"
		    "        print 'checksum:', lookup.checksum\n"
		    "        print 'error:', lookup.error\n")

		.def("lookup_address", &elliptics_session::lookup_address,
		    "lookup_address(key, group_id)\n"
		    "    Returns address of node from specified group_id which is responsible for the key\n\n"
		    "    address = session.lookup_address('looking up key')\n"
		    "    print '\\'looking up key\\' should lives on node:', address")

// Read operations

		.def("read_file", &elliptics_session::read_file,
		     (bp::arg("key"), bp::arg("filename"),
		      bp::arg("offset") = 0, bp::arg("size") = 0),
		    "read_file(key, filename, offset=0, size=0)\n"
		    "    Reads object by the key and writes it to the specified file.\n"
		    "    The operation is asynchronous with nothing returns\n"
		    "    -- key - string or elliptics.Id, or elliptics.IoAttr\n"
		    "    -- filename - file path where read object will be written\n"
		    "    -- offset - offset from which object data should be read\n"
		    "    -- size - number of bytes to be read. If size equal ot 0 then the full object will be read\n\n"
		    "    session.read_file('key', '/path/to/file', 0, 0)\n"
		    "    session.read_file('key1', '/path/to/file1', 10, 100)\n")

		.def("read_data", &elliptics_session::read_data,
		     (bp::arg("key"), bp::arg("offset") = 0, bp::arg("size") = 0),
		    "read_data(keym offset=0, size=0)\n"
		    "    Reads data by the key. Returns elliptics.AsyncResult.\n"
		    "    -- key - string or elliptics.Id, or elliptics.IoAttr\n"
		    "    -- offset - offset from which object data should be read\n"
		    "    -- size - number of bytes to be read. If size equal ot 0 then the full object will be read\n\n"
		    "    read_result = None\n"
		    "    try:\n"
		    "        result = session.read_data('key', 0, 0)\n"
		    "        read_result = result.get()[0]\n"
		    "    except Exception as e:\n"
		    "        print 'Read has been failed:', e\n\n"
		    "    if read_result:\n"
		    "        print 'Read key: \\'key\\':'\n"
		    "        print 'data:', read_result.data\n"
		    "        print 'timestamp:', read_result.timestamp\n"
		    "        print 'size:', read_result.size\n"
		    "        print 'offset:', read_result.offset\n"
		    "        print 'user_flags:', read_result.user_flags\n"
		    "        print 'flags:', read_result.flags\n")

		.def("read_data_from_groups", &elliptics_session::read_data_from_groups,
		     (bp::arg("key"), bp::arg("groups"),
		      bp::arg("offset") = 0, bp::arg("size") = 0),
		    "read_data_from_groups(key, groups, offset=0, size=0)\n"
		    "    Reads data by the key from specified groups. Returns elliptics.AsyncResult.\n"
		    "    -- key - string or elliptics.Id, or elliptics.IoAttr\n"
		    "    -- groups - iterable object which specifies group ids from which data should be read\n"
		    "    -- offset - offset from which object data should be read\n"
		    "    -- size - number of bytes to be read. If size equal ot 0 then the full object will be read\n\n"
		    "    read_result = None\n"
		    "    try:\n"
		    "        result = session.read_data_from_groups('key', [1,2,3], 0, 0)\n"
		    "        read_result = result.get()[0]\n"
		    "    except Exception as e:\n"
		    "        print 'Read has been failed:', e\n\n"
		    "    if read_result:\n"
		    "        print 'Read key: \\'key\\':'\n"
		    "        print 'data:', read_result.data\n"
		    "        print 'timestamp:', read_result.timestamp\n"
		    "        print 'size:', read_result.size\n"
		    "        print 'offset:', read_result.offset\n"
		    "        print 'user_flags:', read_result.user_flags\n"
		    "        print 'flags:', read_result.flags\n")

		.def("read_latest", &elliptics_session::read_latest,
		     (bp::arg("key"), bp::arg("offset") = 0, bp::arg("size") = 0),
		    "read_latest(key, offset=0, size=0)\n"
		    "    Looks up to each group for the key and reads one which is newer then other. Returns elliptics.AsyncResult\n"
		    "    -- key - string or elliptics.Id, or elliptics.IoAttr\n"
		    "    -- offset - offset from which object data should be read\n"
		    "    -- size - number of bytes to be read. If size equal ot 0 then the full object will be read\n\n"
		    "    read_result = None\n"
		    "    try:\n"
		    "        result = session.read_latest('key', 0, 0)\n"
		    "        read_result = result.get()[0]\n"
		    "    except Exception as e:\n"
		    "        print 'Read has been failed:', e\n\n"
		    "    if read_result:\n"
		    "        print 'Read key: \\'key\\':'\n"
		    "        print 'data:', read_result.data\n"
		    "        print 'timestamp:', read_result.timestamp\n"
		    "        print 'size:', read_result.size\n"
		    "        print 'offset:', read_result.offset\n"
		    "        print 'user_flags:', read_result.user_flags\n"
		    "        print 'flags:', read_result.flags\n")

		.def("read_data_range", &elliptics_session::read_data_range,
		     (bp::arg("range")),
		    "read_data_range(range)\n"
		    "    Reads all keys from specified area. Returns elliptics.AsyncResult.\n"
		    "    -- range - elliptics.Range which specifies key area and io attributes\n\n"
		    "    range = elliptics.Range()\n"
		    "    range.group_id = 1\n"
		    "    range.start = elliptics.Id([0] * 64, 1)\n"
		    "    range.end = elliptics.Id([255]*64, 1)\n\n"
		    "    result = session.read_data_range(range)\n"
		    "    for read_result in result:\n"
		    "        print 'Read key:\\'',  read_result.id, '\\'\n"
		    "        print 'data:', read_result.data\n"
		    "        print 'timestamp:', read_result.timestamp\n"
		    "        print 'size:', read_result.size\n"
		    "        print 'offset:', read_result.offset\n"
		    "        print 'user_flags:', read_result.user_flags\n"
		    "        print 'flags:', read_result.flags\n")

		.def("bulk_read", &elliptics_session::bulk_read,
		     (bp::arg("keys")),
		    "bulk_read(keys)\n"
		    "    Reads all specified keys. Returns elliptics.AsyncResult\n"
		    "    -- keys - string or elliptics.Id, or elliptics.IoAttr\n\n"
		    "    keys = []\n"
		    "    keys.append('key')\n"
		    "    keys.append(elliptics.Id('key1'))\n\n"
		    "    io = elliptics.IoAttr()\n"
		    "    io.id = elliptics.Id('key3')\n"
		    "    io.offset = 10\n"
		    "    keys.append(io)\n\n"
		    "    result = session.bulk_read(keys)\n"
		    "    for read_result in result:\n"
		    "        print 'Read key:\\'',  read_result.id, '\\'\n"
		    "        print 'data:', read_result.data\n"
		    "        print 'timestamp:', read_result.timestamp\n"
		    "        print 'size:', read_result.size\n"
		    "        print 'offset:', read_result.offset\n"
		    "        print 'user_flags:', read_result.user_flags\n"
		    "        print 'flags:', read_result.flags\n")

// Write operations

		.def("write_file", &elliptics_session::write_file,
		     (bp::arg("key"), bp::arg("filename"), bp::arg("offset") = 0,
		      bp::arg("local_offset") = 0, bp::arg("size") = 0),
		    "write_file(key, filename, offset=0, local_offset=0, size=0)\n"
		    "    Writes data from file @filename by the key, offsets and size\n"
		    "    -- key - string or elliptics.Id, or elliptics.IoAttr\n"
		    "    -- filename - path to data which should be written to the key\n"
		    "    -- offset - offset with which data should be written\n"
		    "    -- local_offset - offset with which data should be read from @filename\n"
		    "    -- size - number of bytes to be read from @filename and to be written to @key.\n"
		    "        If it equal to 0 then full size will be read and written.\n\n"
		    "    session.write_file('key', '/path/to/file')")

		.def("write_data", &elliptics_session::write_data,
		     (bp::arg("key"), bp::arg("data"), bp::arg("offset") = 0),
		    "write_data(key, data, offset=0)\n"
		    "    Writes @data to @key with @offset. Returns elliptics.AsyncResult\n"
		    "    -- key - string or elliptics.Id, or elliptics.IoAttr\n"
		    "    -- data - string data\n"
		    "    -- offset - offset with which data should be written\n\n"
		    "    write_results = []\n"
		    "    try:\n"
		    "        result = session.write_data('key', 'key_data')\n"
		    "        write_results = result.get()\n"
		    "    except Exception as e:\n"
		    "        print 'Write data is failed:', e\n\n"
		    "    for write_result in write_results:\n"
		    "        print 'The key:\\'key\\' has been written:'\n"
		    "        print 'node:', write_result.address\n"
		    "        print 'checksum:', write_result.checksum\n"
		    "        print 'offset:', write_result.offset\n"
		    "        print 'size:', write_result.size\n"
		    "        print 'timestamp:', write_result.tiemstamp\n"
		    "        print 'filepath:', write_result.filepath\n")

		.def("write_data", &elliptics_session::write_data_by_chunks,
		     (bp::arg("key"), bp::arg("data"),
		      bp::arg("offset")=0, bp::arg("chunk_size")=0),
		    "write_data(key, data, offset=0, chunk_size=0)\n"
		    "    Writes @data splitted to pieces of @chunk_size to @key with @offset. Returns elliptics.AsyncResult\n"
		    "    -- key - string or elliptics.Id, or elliptics.IoAttr\n"
		    "    -- data - string data\n"
		    "    -- offset - offset with which data should be written\n"
		    "    -- chunk_size - maximum size of one chunk\n\n"
		    "    write_results = []\n"
		    "    try:\n"
		    "        result = session.write_data('key', 'key_data', 0, 3)\n"
		    "        write_results = result.get()\n"
		    "    except Exception as e:\n"
		    "        print 'Write data is failed:', e\n\n"
		    "    for write_result in write_results:\n"
		    "        print 'The key:\\'key\\' has been written:'\n"
		    "        print 'node:', write_result.address\n"
		    "        print 'checksum:', write_result.checksum\n"
		    "        print 'offset:', write_result.offset\n"
		    "        print 'size:', write_result.size\n"
		    "        print 'timestamp:', write_result.tiemstamp\n"
		    "        print 'filepath:', write_result.filepath\n")

		.def("write_cas", &elliptics_session::write_cas,
		     (bp::arg("key"), bp::arg("data"),
		      bp::arg("old_csum"), bp::arg("remote_offset") = 0),
		    "write_cas(key, data, old_csum, remote_offset=0)\n"
		    "    Writes @data to @key with @remote_offset only if\n"
		    "    csum of current object by @key is eqaul to old_csum. Returns elliptics.AsyncResult\n"
		    "    -- key - string or elliptics.Id, or elliptics.IoAttr\n"
		    "    -- data - string data\n"
		    "    -- old_csum - hash sum as the elliptics.Id\n"
		    "    -- remote_offset - offset with which data should be written\n\n"
		    "    write_results = []\n"
		    "    csum = elliptics.Id()\n"
		    "    try:\n"
		    "        result = session.write_cas('key', 'key_data', csum, 0)\n"
		    "        write_results = result.get()\n"
		    "    except Exception as e:\n"
		    "        print 'Write data is failed:', e\n\n"
		    "    for write_result in write_results:\n"
		    "        print 'The key:\\'key\\' has been written:'\n"
		    "        print 'node:', write_result.address\n"
		    "        print 'checksum:', write_result.checksum\n"
		    "        print 'offset:', write_result.offset\n"
		    "        print 'size:', write_result.size\n"
		    "        print 'timestamp:', write_result.tiemstamp\n"
		    "        print 'filepath:', write_result.filepath\n")

		.def("write_cas", &elliptics_session::write_cas_callback,
		     (bp::arg("key"), bp::arg("converter"),
		      bp::arg("remote_offset") = 0, bp::arg("count") = 10),
		    "write_cas(key, converter, remote_offset=0, count=10)\n"
		    "    Reads latest data for @key, calls converter on the data and\n"
		    "    tries to overwrite @key data vi write_cas. Returns elliptics.AsyncResult.\n"
		    "    -- key - string or elliptics.Id, or elliptics.IoAttr\n"
		    "    -- converter - callable object which receives string data and returns new string data which should be written\n"
		    "    -- remote_offset - offset with which data should be written\n"
		    "    -- count - number of retries before fail\n\n"
		    "    write_results = []\n"
		    "    csum = elliptics.Id()\n"
		    "    try:\n"
		    "        result = session.write_cas('key', lambda x: '___' + x + '___')\n"
		    "        write_results = result.get()\n"
		    "    except Exception as e:\n"
		    "        print 'Write data is failed:', e\n\n"
		    "    for write_result in write_results:\n"
		    "        print 'The key:\\'key\\' has been written:'\n"
		    "        print 'node:', write_result.address\n"
		    "        print 'checksum:', write_result.checksum\n"
		    "        print 'offset:', write_result.offset\n"
		    "        print 'size:', write_result.size\n"
		    "        print 'timestamp:', write_result.tiemstamp\n"
		    "        print 'filepath:', write_result.filepath\n")

		.def("write_prepare", &elliptics_session::write_prepare,
		     (bp::arg("key"), bp::arg("data"),
		      bp::arg("remote_offset"), bp::arg("psize")),
		    "write_prepare(key, data, remote_offset, psize)\n"
		    "    Tells Elliptics to allocate space of psize for future object by @key\n"
		    "    and writes part of object data by @data and @remote_offset.\n"
		    "    Returns elliptics.AsyncResult.\n"
		    "    -- key - string or elliptics.Id, or elliptics.IoAttr\n"
		    "    -- data - data which should be written at @remote_offset\n"
		    "    -- remote_offset - offset with which @data should be written\n"
		    "    -- psize - number of bytes to be reserved for future object\n\n"
		    "    write_results = []\n"
		    "    try:\n"
		    "        result = session.write_prepare('key', 'first_part', 0, 1024)\n"
		    "        write_results = result.get()\n"
		    "    except Exception as e:\n"
		    "        print 'Write data is failed:', e\n\n"
		    "    for write_result in write_results:\n"
		    "        print 'The key:\\'key\\' has been written:'\n"
		    "        print 'node:', write_result.address\n"
		    "        print 'checksum:', write_result.checksum\n"
		    "        print 'offset:', write_result.offset\n"
		    "        print 'size:', write_result.size\n"
		    "        print 'timestamp:', write_result.tiemstamp\n"
		    "        print 'filepath:', write_result.filepath\n")

		.def("write_plain", &elliptics_session::write_plain,
		     (bp::arg("key"), bp::arg("data"), bp::arg("remote_offset")),
		    "write_plain(key, data, remote_offset)\n"
		    "    Writes data to the space allocated earlier by write_prepare.\n"
		    "    Return elliptics.AsyncResult.\n"
		    "    -- key - string or elliptics.Id, or elliptics.IoAttr\n"
		    "    -- data - string data which should be written at @remote_offset\n"
		    "    -- remote_offset - offset with which @data should be written\n\n"
		    "    write_results = []\n"
		    "    try:\n"
		    "        offset = len('first_part')\n"
		    "        result = session.write_plain('key', 'second_part', offset)\n"
		    "        write_results += result.get()\n\n"
		    "        offset += len('second_part')\n"
		    "        result = session.write_plain('key', 'third_part', offset)\n"
		    "        write_results += result.get()\n\n"
		    "        offset += len('third_part')\n"
		    "        result = session.write_plain('key', 'fourth_part', offset)\n"
		    "        write_results += result.get()\n"
		    "    except Exception as e:\n"
		    "        print 'Write data is failed:', e\n\n"
		    "    for write_result in write_results:\n"
		    "        print 'The key:\\'key\\' has been written:'\n"
		    "        print 'node:', write_result.address\n"
		    "        print 'checksum:', write_result.checksum\n"
		    "        print 'offset:', write_result.offset\n"
		    "        print 'size:', write_result.size\n"
		    "        print 'timestamp:', write_result.tiemstamp\n"
		    "        print 'filepath:', write_result.filepath\n")

		.def("write_commit", &elliptics_session::write_commit,
		     (bp::arg("key"), bp::arg("data"),
		      bp::arg("remote_offset"), bp::arg("csize")),
		    "write_commit(key, data, remote_offset, csize)\n"
		    "    Makes final write to space allocated earlier by write_prepare\n"
		    "    and finalizes the object by truncating it by @csize.\n"
		    "    Return elliptics.AsyncResult\n"
		    "    -- key - string or elliptics.Id, or elliptics.IoAttr\n"
		    "    -- data - string data which should be written at @remote_offset\n"
		    "    -- remote_offset - offset with which @data should be written\n"
		    "    -- psize - total size of the data by which the object should be truncated\n\n"
		    "    write_results = []\n"
		    "    try:\n"
		    "        offset += len('first_part' + 'second_part' + 'third_part' + 'fourth_part')\n"
		    "        csize = len('first_part' + ... + 'last_part')\n"
		    "        result = session.write_commit('key', 'last_part', offset, csize)\n"
		    "        write_results += result.get()\n"
		    "    except Exception as e:\n"
		    "        print 'Write data is failed:', e\n\n"
		    "    for write_result in write_results:\n"
		    "        print 'The key:\\'key\\' has been written:'\n"
		    "        print 'node:', write_result.address\n"
		    "        print 'checksum:', write_result.checksum\n"
		    "        print 'offset:', write_result.offset\n"
		    "        print 'size:', write_result.size\n"
		    "        print 'timestamp:', write_result.tiemstamp\n"
		    "        print 'filepath:', write_result.filepath\n")

		.def("write_cache", &elliptics_session::write_cache,
		     (bp::arg("key"), bp::arg("data"), bp::arg("timeout")),
		    "write_cache(key, data, timeout)\n"
		    "    Writes @data to @key into Elliptics cache and sets the object's lifetime to timeout.\n"
		    "    Return elliptics.AsyncResult.\n"
		    "    -- key - string or elliptics.Id, or elliptics.IoAttr\n"
		    "    -- data - string data which should be written\n"
		    "    -- timeout - timeout in seconds after which unused object should be removed\n\n"
		    "    write_results = []\n"
		    "    try:\n"
		    "        result = session.write_cache('key', 'key_data', 60)\n"
		    "        write_results = result.get()\n"
		    "    except Exception as e:\n"
		    "        print 'Write data is failed:', e\n\n"
		    "    for write_result in write_results:\n"
		    "        print 'The key:\\'key\\' has been written:'\n"
		    "        print 'node:', write_result.address\n"
		    "        print 'checksum:', write_result.checksum\n"
		    "        print 'offset:', write_result.offset\n"
		    "        print 'size:', write_result.size\n"
		    "        print 'timestamp:', write_result.tiemstamp\n"
		    "        print 'filepath:', write_result.filepath\n")

		.def("bulk_write", &elliptics_session::bulk_write,
		     (bp::arg("datas")),
		    "bulk_write(data)\n"
		    "    Simultaneously writes several objects. Returns elliptics.AsyncResult.\n"
		    "    -- datas - iterable object which contains a tuple of key and data:\n"
		    "        -- key - string or elliptics.Id, or elliptics.IoAttr\n"
		    "        -- data - string data which should be written\n\n"
		    "    data = []\n"
		    "    datas.append(('key', 'key_data'))\n"
		    "    datas.append((elliptics.Id('key1'), 'key1_data'))\n\n"
		    "    io = elliptics.IoAttr()\n"
		    "    io.id = elliptics.Id('key3')\n"
		    "    io.offset = 10\n"
		    "    datas.append(io, 'key3_data')\n\n"
		    "    write_results = []\n"
		    "    try:\n"
		    "        result = session.bulk_write(datas)\n"
		    "        write_results = result.get()\n"
		    "    except Exception as e:\n"
		    "        print 'Write data is failed:', e\n\n"
		    "    for write_result in write_results:\n"
		    "        print 'The data has been written:'\n"
		    "        print 'node:', write_result.address\n"
		    "        print 'checksum:', write_result.checksum\n"
		    "        print 'offset:', write_result.offset\n"
		    "        print 'size:', write_result.size\n"
		    "        print 'timestamp:', write_result.tiemstamp\n"
		    "        print 'filepath:', write_result.filepath\n")

		.def("update_status", &elliptics_session::update_status,
		     (bp::arg("host"), bp::arg("port"),
		      bp::arg("family"), bp::arg("status")),
		    "update_status(addr, port, family, status)\n"
		    "    Updates status of node specified by address to status.\n\n"
		    "    new_status = elliptics.SessionStatus()\n"
		    "    new_status.nflags = elliptics.status_flags.change\n"
		    "    new_status.log_level = elliptics.log_level.error\n"
		    "    session.update_status(host='host.com', port=1025, family=AF_INET, new_status)")

		.def("enable_backend", &elliptics_session::enable_backend,
		     (bp::arg("host"), bp::arg("port"), bp::arg("family"), bp::arg("backend_id")),
		     "enable_backend(host, port, family, backend_id)\n"
		     "    Enables backend @backend_id at node addressed by @host, @port, @family\n"
		     "    Returns AsyncResult which provides new status of the backend\n\n"
		     "    new_status = session.enable_backend(elliptics.Address.from_host_port_family(host='host.com', port=1025, family=AF_INET), 0).get()[0].backends[0]")

		.def("disable_backend", &elliptics_session::disable_backend,
		     (bp::arg("host"), bp::arg("port"), bp::arg("family"), bp::arg("backend_id")),
		     "disable_backend(host, port, family, backend_id)\n"
		     "    Disables backend @backend_id at node addressed by @host, @port, @family\n"
		     "    Returns AsyncResult which provides new status of the backend\n\n"
		     "    new_status = session.disable_backend(elliptics.Address.from_host_port_family(host='host.com', port=1025, family=AF_INET), 0).get()[0].backends[0]")

		.def("start_defrag", &elliptics_session::start_defrag,
		     (bp::arg("host"), bp::arg("port"), bp::arg("family"), bp::arg("backend_id")),
		     "start_defrag(host, port, family, backend_id)\n"
		     "    Start defragmentation of backend @backend_id at node addressed by @host, @port, @family\n"
		     "    Returns AsyncResult which provides new status of the backend\n\n"
		     "    new_status = session.start_defrag(elliptics.Address.from_host_port_family(host='host.com', port=1025, family=AF_INET), 0).get()[0].backends[0]\n"
		     "    defrag_state = new_state.defrag_state")

		.def("set_backend_ids", &elliptics_session::set_backend_ids,
		     (bp::arg("host"), bp::arg("port"), bp::arg("family"), bp::arg("backend_id"), bp::arg("ids")),
		     "set_backend_ids(hot, port, family, backend_id, ids)\n"
		     "    Sets new ids to backend with @backend_id at node addressed by @host, @port, @family.\n"
		     "    Returns AsyncResult which provides status of the backend\n\n"
		     "    backend_status = session.set_backend_ids(elliptics.Address.from_host_port_family(host='host', port=1025, family=AF_INET, 0, []).get[0].backends[0]\n")

		.def("request_backends_status", &elliptics_session::request_backends_status,
		     (bp::arg("host"), bp::arg("port"), bp::arg("family")),
		     "request_backends_status(host, port, family)\n"
		     "    Request all backends status from node addressed by @host, @port, @family\n"
		     "    Returns AsyncResult which provides backends statuses\n\n"
		     "    backends_statuses = session.request_backends_status(elliptics.Address.from_host_port_family(host='host.com', port=1025, family=AF_INET)).get()[0].backends")

		.def("make_readonly", &elliptics_session::make_readonly,
		     (bp::arg("host"), bp::arg("port"), bp::arg("family"), bp::arg("backend_id")),
		     "make_readonly(host, port, family, backend_id)\n"
		     "    Makes backend with @backend_id read-only at node addressed by @host, @port, @family\n"
		     "    Returns AsyncResult which provides new status of the backend\n\n"
		     "    backends_statuses = session.make_readonly(elliptics.Address.from_host_port_family(host='host.com', port=1025, family=AF_INET), 0).get()[0].backends")

		.def("make_writable", &elliptics_session::make_writable,
		     (bp::arg("host"), bp::arg("port"), bp::arg("family"), bp::arg("backend_id")),
		     "make_writable(host, port, family, backend_id)\n"
		     "    Makes backend with @backend_id read-write-able at node addressed by @host, @port, @family\n"
		     "    Returns AsyncResult which provides new status of the backend\n\n"
		     "    backends_statuses = session.make_writable(elliptics.Address.from_host_port_family(host='host.com', port=1025, family=AF_INET), 0).get()[0].backends")

// Remove operations

		.def("remove", &elliptics_session::remove,
		     bp::args("key"),
		    "remove(key)\n"
		    "    Removes object by the key. Returns elliptics.AsyncResult.\n"
		    "    -- key - string or elliptics.Id, or elliptics.IoAttr\n\n"
		    "    try:\n"
		    "        result = session.remove('key')\n"
		    "        remove_results = result.get()\n"
		    "        for remove_result in remove_results:\n"
		    "            print 'The key: \\'key\\' has been removed:'\n"
		    "            print 'node:', remove_result.address\n"
		    "            print 'status:', remove_result.status\n"
		    "            print 'size:', remove_result.size\n"
		    "            print 'data:', remove_result.data\n")

		.def("remove_data_range", &elliptics_session::remove_data_range,
		     bp::args("range"),
		    "remove_data_range(range)\n"
		    "    Removes area of keys. It returns elliptics.AsyncResult.\n"
		    "    -- range - elliptics.Range which specifies area of key\n\n"
		    "    try:\n"
		    "        range = elliptics.Range()\n"
		    "        range.start = elliptics.Id([0] * 64, 1)\n"
		    "        range.end = elliptics.Id([255] * 64, 1)\n\n"
		    "        result = session.remove_data_range(range)\n"
		    "        remove_results = result.get()\n"
		    "        for remove_result in remove_results:\n"
		    "            print 'The key has been removed:'\n"
		    "            print 'node:', remove_result.address\n"
		    "            print 'status:', remove_result.status\n"
		    "            print 'size:', remove_result.size\n"
		    "            print 'data:', remove_result.data\n")

// Node iteration

		.def("start_iterator", &elliptics_session::start_iterator,
		     bp::args("id", "ranges", "type", "flags", "time_begin", "time_end"),
		    "start_iterator(id, ranges, type, flags, time_begin, time_end)\n"
		    "    Start iterator on the Elliptics node specified by @id. Return elliptics.AsyncResult.\n"
		    "    -- id - elliptics.Id of the node where iteration should be executed\n"
		    "    -- ranges - list of elliptics.IteratorRange by which keys on the node should be filtered\n"
		    "    -- type - elliptics.iterator_types\n"
		    "    -- flags - bits set of elliptics.iterator_flags\n"
		    "    -- time_begin - start of time range by which keys on the node should be filtered\n"
		    "    -- time_end - end of time range by which keys on the node should be filtered\n\n"
		    "    flags = elliptics.iterator_flags.key_range\n"
		    "    type = elliptics.iterator_types.network\n"
		    "    id = session.routes.get_address_id(Address.from_host_port('host.com:1025'))\n"
		    "    range = elliptics.IteratorRange()\n"
		    "    range.key_begin = elliptics.Id([0] * 64, 1)\n"
		    "    range.key_end = elliptics.Id([255] * 64, 1)\n"
		    "    iterator = session.start_iterator(id,\n"
		    "                                      [range],\n"
		    "                                      type,\n"
		    "                                      flags,\n"
		    "                                      elliptics.Time(0,0),\n"
		    "                                      elliptics.Time(0,0))\n\n"
		    "    for result in iterator:\n"
		    "        if result.status != 0:\n"
		    "            raise AssertionError('Wrong status: {0}'.format(result.status))\n\n"
		    "        iterator_id = result.id\n"
		    "        print ('node: {0}, key: {1}, flags: {2}, ts: {3}/{4}, data: {5}'\n"
		    "               .format(node,\n"
		    "                       result.response.key,\n"
		    "                       result.response.user_flags,\n"
		    "                       result.response.timestamp.tsec,\n"
		    "                       result.response.timestamp.tnsec,\n"
		    "                       result.response_data))\n")

		.def("pause_iterator", &elliptics_session::pause_iterator,
		     bp::args("id", "iterator_id"),
		    "pause_iterator(id, iterator_id)\n"
		    "    Pauses @iterator_id iterator on the node specified by @id\n"
		    "    -- id - elliptics.Id of the node where iteration should be paused\n"
		    "    -- iterator_id - integer ID of the iterator which should be paused\n\n"
		    "    id = session.routes.get_address_id(Address.from_host_port('host.com:1025'))\n"
		    "    iterator = session.pause_iterator(id, iterator_id)\n"
		    "    iterator.wait()\n")

		.def("continue_iterator", &elliptics_session::continue_iterator,
		     bp::args("id", "iterator_id"),
		    "continue_iterator(id, iterator_id)\n"
		    "    Continues @iterator_id iterator on the node specified by @id\n"
		    "    -- id - elliptics.Id of the node where iteration should be paused\n"
		    "    -- iterator_id - integer ID of the iterator which should be paused\n\n"
		    "    id = session.routes.get_address_id(Address.from_host_port('host.com:1025'))\n"
		    "    iterator = session.continue_iterator(id, iterator_id)\n"
		    "    for result in iterator:\n"
		    "        if result.status != 0:\n"
		    "            raise AssertionError('Wrong status: {0}'.format(result.status))\n\n"
		    "        iterator_id = result.id"
		    "        print ('node: {0}, key: {1}, flags: {2}, ts: {3}/{4}, data: {5}'\n"
		    "               .format(node,\n"
		    "                       result.response.key,\n"
		    "                       result.response.user_flags,\n"
		    "                       result.response.timestamp.tsec,\n"
		    "                       result.response.timestamp.tnsec,\n"
		    "                       result.response_data))\n")

		.def("cancel_iterator", &elliptics_session::cancel_iterator,
		     bp::args("id", "iterator_id"),
		    "cancel_iterator(id, iterator_id)\n"
		    "    Stops @iterator_id iterator on the node specified by @id\n"
		    "    -- id - elliptics.Id of the node where iteration should be paused\n"
		    "    -- iterator_id - integer ID of the iterator which should be paused\n\n"
		    "    id = session.routes.get_address_id(Address.from_host_port('host.com:1025'))\n"
		    "    iterator = session.cancel_iterator(id, iterator_id)\n"
		    "    iterator.wait()\n")

// Index operations

		.def("set_indexes", &elliptics_session::set_indexes,
		     (bp::arg("id"), bp::arg("indexes"), bp::arg("datas")),
		    "set_indexes(id, indexes, datas)\n"
		    "    Resets id indexes. The id will be removed from previous indexes.\n"
		    "    Also it updates list of indexes where id is.\n"
		    "    Returns elliptics.AsyncResult.\n"
		    "    -- id - string or elliptics.Id\n"
		    "    -- indexes - iterable object which provides set of indexes\n"
		    "    -- datas - iterable object which provides data which will be associated with the id in the index.\n\n"
		    "    indexes_result = []\n"
		    "    try:\n"
		    "        result = session.set_indexes('key', ['index1', 'index2'], ['index1_key_data', 'index2_key_data'])\n"
		    "        indexes_result = result.get()\n"
		    "    except Exception as e:\n"
		    "        print 'Set indexes has been failed:', e\n")

		.def("set_indexes_raw", &elliptics_session::set_indexes_raw,
		     (bp::arg("id"), bp::arg("indexes")),
		    "set_indexes_raw(id, indexes)\n"
		    "    Resets id indexes. The id will be removed from previous indexes. Return elliptics.AsyncResult.\n"
		    "    -- id - string or elliptics.Id\n"
		    "    -- indexes - iterable object which provides set of elliptics.IndexEntry\n\n"
		    "    indexes = []\n"
		    "    indexes.append(elliptics.IndexEntry())\n"
		    "    indexes[-1].index = elliptics.Id('index1')\n"
		    "    indexes[-1].data = 'index1_key_data'\n\n"
		    "    indexes.append(elliptics.IndexEntry())\n"
		    "    indexes[-1].index = elliptics.Id('index2')\n"
		    "    indexes[-1].data = 'index2_key_data'\n\n"
		    "    indexes_result = []\n"
		    "    try:\n"
		    "        result = session.set_indexes_raw('key', indexes)\n"
		    "        indexes_result = result.get()\n"
		    "    except Exception as e:\n"
		    "        print 'Set indexes raw has been failed:', e\n")

		.def("update_indexes", &elliptics_session::update_indexes,
		     (bp::arg("id"), bp::arg("indexes"), bp::arg("datas")),
		    "update_indexes(id, indexes, datas)\n"
		    "    Adds id to additional indees and or updates data for the id in specified indexes.\n"
		    "    Also it updates list of indexes where id is.\n"
		    "    Return elliptics.AsyncResult.\n"
		    "    -- id - string or elliptics.Id\n"
		    "    -- indexes - iterable object which provides set of indexes\n"
		    "    -- datas - iterable object which provides data which will be associated with the id in the index.\n\n"
		    "    indexes_result = []\n"
		    "    try:\n"
		    "        result = session.update_indexes('key', ['index1', 'index2'], ['index1_key_data', 'index2_key_data'])\n"
		    "        indexes_result = result.get()\n"
		    "    except Exception as e:\n"
		    "        print 'Set indexes has been failed:', e\n")

		.def("update_indexes_raw", &elliptics_session::update_indexes_raw,
		     (bp::arg("id"), bp::arg("indexes")),
		    "update_indexes_raw(id, indexes)\n"
		    "    Adds id to additional indees and or updates data for the id in specified indexes.\n"
		    "    Also it updates list of indexes where id is.\n"
		    "    Return elliptics.AsyncResult.\n"
		    "    -- id - string or elliptics.Id\n"
		    "    -- indexes - iterable object which provides set of elliptics.IndexEntry\n\n"
		    "    indexes = []\n"
		    "    indexes.append(elliptics.IndexEntry())\n"
		    "    indexes[-1].index = elliptics.Id('index1')\n"
		    "    indexes[-1].data = 'index1_key_data'\n\n"
		    "    indexes.append(elliptics.IndexEntry())\n"
		    "    indexes[-1].index = elliptics.Id('index2')\n"
		    "    indexes[-1].data = 'index2_key_data'\n\n"
		    "    indexes_result = []\n"
		    "    try:\n"
		    "        result = session.update_indexes_raw('key', indexes)\n"
		    "        indexes_result = result.get()\n"
		    "    except Exception as e:\n"
		    "        print 'Set indexes raw has been failed:', e\n")

		.def("update_indexes_internal", &elliptics_session::update_indexes_internal,
		     (bp::arg("id"), bp::arg("indexes"), bp::arg("datas")),
		    "update_indexes_internal(id, indexes, datas)\n"
		    "    Adds id to additional indees and or updates data for the id in specified indexes.\n"
		    "    It doesn't update list of indexes where id is.\n"
		    "    Return elliptics.AsyncResult.\n"
		    "    -- id - string or elliptics.Id\n"
		    "    -- indexes - iterable object which provides set of indexes\n"
		    "    -- datas - iterable object which provides data which will be associated with the id in the index.\n\n"
		    "    indexes_result = []\n"
		    "    try:\n"
		    "        result = session.update_indexes_internal('key', ['index1', 'index2'], ['index1_key_data', 'index2_key_data'])\n"
		    "        indexes_result = result.get()\n"
		    "    except Exception as e:\n"
		    "        print 'Set indexes has been failed:', e\n")

		.def("update_indexes_internal_raw", &elliptics_session::update_indexes_internal_raw,
		     (bp::arg("id"), bp::arg("indexes")),
		    "update_indexes_internal_raw(id, indexes)\n"
		    "    Adds id to additional indexes and or updates data for the id in specified indexes.\n"
		    "    It doesn't update list of indexes where id is.\n"
		    "    Return elliptics.AsyncResult.\n"
		    "    -- id - string or elliptics.Id\n"
		    "    -- indexes - iterable object which provides set of elliptics.IndexEntry\n\n"
		    "    indexes = []\n"
		    "    indexes.append(elliptics.IndexEntry())\n"
		    "    indexes[-1].index = elliptics.Id('index1')\n"
		    "    indexes[-1].data = 'index1_key_data'\n\n"
		    "    indexes.append(elliptics.IndexEntry())\n"
		    "    indexes[-1].index = elliptics.Id('index2')\n"
		    "    indexes[-1].data = 'index2_key_data'\n\n"
		    "    indexes_result = []\n"
		    "    try:\n"
		    "        result = session.update_indexes_internal_raw('key', indexes)\n"
		    "        indexes_result = result.get()\n"
		    "    except Exception as e:\n"
		    "        print 'Set indexes raw has been failed:', e\n")

		.def("add_to_capped_collection", &elliptics_session::add_to_capped_collection,
		     (bp::arg("id"), bp::arg("index"), bp::arg("limit"), bp::arg("remove_data")),
		     "add_to_capped_collection(id, index, limit, remove_data)\n"
		     "    Adds object @id to capped collection @index.\n"
		     "    As object is added to capped collection it displaces the oldest object from it in case if\n"
		     "    the @limit is reached.\n"
		     "    If @remove_data is true in addition to displacing of the object it's data is also removed from the storage.\n"
		     "    NOTE: The @limit is satisfied for each shard and not for whole collection.\n"
		     "    Return elliptics.AsyncResult.\n")

		.def("find_all_indexes", &elliptics_session::find_all_indexes,
		     (bp::arg("indexes")),
		    "find_all_indexes(indexes)\n"
		    "    Finds intersection of indexes. Returns elliptics.AsyncResult.\n"
		    "    -- indexes - iterable object which provides string indexes which ids should be intersected\n\n"
		    "    try:\n"
		    "        result = session.find_all_indexes(['index1', 'index2'])\n"
		    "        id_results = result.get()\n"
		    "        for id_result in id_result:\n"
		    "            print 'Find id:', id_result.id\n"
		    "            for index in id_result.indexes:\n"
		    "                print 'index:', index.index\n"
		    "                print 'data:', index.data\n"
		    "    except Exception as e:\n"
		    "        print 'Find all indexes has been failed:', e\n")

		.def("find_all_indexes_raw", &elliptics_session::find_all_indexes_raw,
		     (bp::arg("indexes")),
		    "find_all_indexes(indexes)\n"
		    "    Finds intersection of indexes. Returns elliptics.AsyncResult.\n"
		    "    -- indexes - iterable object which provides indexes as elliptics.Id which ids should be intersected\n\n"
		    "    try:\n"
		    "        result = session.find_all_indexes_raw([elliptics.Id('index1'), elliptics.Id('index2')])\n"
		    "        id_results = result.get()\n"
		    "        for id_result in id_result:\n"
		    "            print 'Find id:', id_result.id\n"
		    "            for index in id_result.indexes:\n"
		    "                print 'index:', index.index\n"
		    "                print 'data:', index.data\n"
		    "    except Exception as e:\n"
		    "        print 'Find all indexes has been failed:', e\n")

		.def("find_any_indexes", &elliptics_session::find_any_indexes,
		     (bp::arg("indexes")),
		    "find_any_indexes(indexes)\n"
		    "    Finds keys unioun from indexes. Returns elliptics.AsyncResult.\n"
		    "    -- indexes - iterable object which provides string indexes which ids should be united\n\n"
		    "    try:\n"
		    "        result = session.find_any_indexes(['index1', 'index2'])\n"
		    "        id_results = result.get()\n"
		    "        for id_result in id_result:\n"
		    "            print 'Find id:', id_result.id\n"
		    "            for index in id_result.indexes:\n"
		    "                print 'index:', index.index\n"
		    "                print 'data:', index.data\n"
		    "    except Exception as e:\n"
		    "        print 'Find all indexes has been failed:', e\n")

		.def("find_any_indexes_raw", &elliptics_session::find_any_indexes_raw,
		     (bp::arg("indexes")),
		    "find_any_indexes_raw(indexes)\n"
		    "    Finds keys uninoun from indexes. Returns elliptics.AsyncResult.\n"
		    "    -- indexes - iterable object which provides indexes as elliptics.Id which ids should be united\n\n"
		    "    try:\n"
		    "        result = session.find_any_indexes_raw([elliptics.Id('index1'), elliptics.Id('index2')])\n"
		    "        id_results = result.get()\n"
		    "        for id_result in id_result:\n"
		    "            print 'Find id:', id_result.id\n"
		    "            for index in id_result.indexes:\n"
		    "                print 'index:', index.index\n"
		    "                print 'data:', index.data\n"
		    "    except Exception as e:\n"
		    "        print 'Find all indexes has been failed:', e\n")

		.def("list_indexes", &elliptics_session::list_indexes,
		     (bp::arg("id")),
		     "list_indexes(id)\n"
		     "    Finds all indexes where @id is presented\n"
		     "    -- id - string or elliptics.Id\n\n"
		     "    try:\n"
		     "        result = session.list_indexes('key')\n"
		     "        indexes = results.get()\n"
		     "        for index in indexes:\n"
		     "            print 'Index:', index.index\n"
		     "            print 'Data:', index.data\n"
		     "    excep Exception as e:\n"
		     "        print 'List indexes failed:', e\n")

		.def("merge_indexes", &elliptics_session::merge_indexes,
		     (bp::args("id", "from", "to")),
		     "merge_indexes(id, from, to)\n"
		     "    Merges index tables stored at @id.\n"
		     "    Reads index tables from groups @from, merges them and writes result to @to.\n\n"
		     "    This is low-level function which merges not index @id, but merges\n"
		     "    data which is stored at key @id\n")

		.def("recover_index", &elliptics_session::recover_index,
		     (bp::args("index")),
		     "recover_index(index)\n"
		     "    Recover @index consistency in all groups.\n"
		     "    This method recovers not only list of objects in index but\n"
		     "    also list of indexes of all objects at this indexes.\n")

		.def("remove_indexes", &elliptics_session::remove_indexes,
		     (bp::args("id", "indexes")),
		     "remove_indexes(id, indexes)\n"
		     "    Removes @id from all @indexes and remove @indexes from indexes list of @id")

		.def("remove_indexes_internal", &elliptics_session::remove_indexes_internal,
		     (bp::args("id", "indexes")),
		     "remove_indexes_internal(id, indexes)\n"
		     "    Removes @id from all @indexes and doesn't change indexes list of @id\n")

		.def("remove_index", &elliptics_session::remove_index,
		     (bp::args("id", "remove_data")),
		     "remove_index(id, remove_data)\n"
		     "    Removes @id from all @indexes and doesn't change indexes list of @id\n")

		.def("remove_index_internal", &elliptics_session::remove_index_internal,
		     (bp::arg("id")),
		     "remove_index_internal(id)\n"
		     "    Removes @id from all indexes which are connected with @id\n"
		     "    Doesn't change indexes list of @id\n")

// Statistics

		.def("monitor_stat", &elliptics_session::monitor_stat,
		     (bp::arg("address"), bp::arg("categories")=elliptics_monitor_categories_all),
		    "monitor_stat(key=None, categories=elliptics.monitor_stat_categories.all)\n"
		    "    Gather monitor statistics of specified categories.\n"
		    "    -- address - elliptics.Address of node\n\n"
		    "    result = session.monitor_stat(elliptics.Address.from_host_port('host.com:1025'))\n"
		    "    stats = result.get()\n")

		.def("state_num", &session::state_num)

		// Couldn't use "exec" as a method name because it's a reserved keyword in python

		.def("exec_", &elliptics_session::exec,
		    (bp::arg("id_or_context")=bp::api::object(), bp::arg("event"), bp::arg("data") = "", bp::arg("src_key") = -1),
		    "exec_(id_or_context=None, event, data="", src_key=-1)\n"
		    "    Sends execution request of the given @event and @data\n"
		    "     to the party specified by a given @id_or_context.\n"
		    "     If @id_or_context is None then request will be sended to all nodes.\n"
		    "     Returns async_exec_result.\n"
		    "     Result contains all replies sent by nodes processing this event.\n")
		.def("push", &elliptics_session::push,
		    (bp::arg("id")=bp::api::object(), bp::arg("context"), bp::arg("event"), bp::arg("data") = ""),
		    "push(id=None, context, event, data="")\n"
		    "    Send an @event with @data to @id continuing the process specified by @context.\n"
		    "    If @id is null event is sent to all groups specified in the session.\n"
		    "    Returns async_exec_result.\n"
		    "    Result contains only the information about starting of event procession, so there is no\n"
		    "    information if it was finally processed successfully.\n")
		.def("reply", &elliptics_session::reply,
		    (bp::arg("context"), bp::arg("data"), bp::arg("final_state")),
		    "reply(context, data, final_state)\n"
		    "    Reply @data to initial starter of the process specified by @context.\n"
		    "    If @final_state is equal to elliptics.exec_context_final_states.final it is the last reply, otherwise there will be more.\n"
		    "    Returns async_reply_result.\n"
		    "    Result contains information if starter received the reply.\n")

		.def("prepare_latest", &elliptics_session::prepare_latest)
	;
}

} } } // namespace ioremap::elliptics::python
