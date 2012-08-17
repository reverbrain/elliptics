/*
 * 2008+ Copyright (c) Evgeniy Polyakov <zbr@ioremap.net>
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
#include <boost/python/list.hpp>
#include <boost/python/dict.hpp>

#if 0

using namespace boost::python;

#include <iostream>
#include <fstream>

class test_class_base {
	public:
		test_class_base(int mask = 0xff) : mask(mask) {};
		virtual ~test_class_base() {};
		
		virtual void log(const char *msg) = 0;

		int get_mask(void) {return mask;};
	private:
		int mask;
};

class test_class : public test_class_base {
	public:
		test_class(const char *path);
		virtual ~test_class();

		virtual void log(const char *msg);
		unsigned char test(unsigned long lptr) { unsigned char *ptr = (unsigned char *)lptr; return ptr[0]; };
	private:
		std::ofstream *stream;
};

test_class::test_class(const char *path)
{
	stream = new std::ofstream(path);
}

test_class::~test_class()
{
	delete stream;
}

void test_class::log(const char *msg)
{
	(*stream) << std::hex << get_mask() << ": " << msg;
	//(*stream) << msg;
	stream->flush();
}

class test_class_base_wrap : public test_class_base, public wrapper<test_class_base> {
	public:
		test_class_base_wrap(int mask) : test_class_base(mask) {};
		virtual ~test_class_base_wrap() {};

		void log(const char *msg) {
			this->get_override("log")(msg);
		}
};

class test_class_wrap : public test_class, public wrapper<test_class> {
	public:
		test_class_wrap(const char *msg) : test_class(msg) {};
		virtual ~test_class_wrap() {} ;

		void log(const char *msg) {
			if (override log = this->get_override("log")) {
				log(msg); // *note*
				return;
			}

			test_class::log(msg);
		}

		void default_log(const char *msg) { this->test_class::log(msg); }
};


BOOST_PYTHON_MODULE(libelliptics_python) {
	class_<test_class_base_wrap, boost::noncopyable>("test_class_base", init<int>())
		.def("get_mask", &test_class_base::get_mask)
		.def("log", pure_virtual(&test_class_base::log))
	;

	class_<test_class_wrap, boost::noncopyable, bases<test_class_base> >("test_class", init<const char *>())
		.def("log", &test_class::log, &test_class_wrap::default_log)
		.def("test", &test_class::test)
	;
};

#else

#include <elliptics/cppdef.h>

using namespace boost::python;
using namespace ioremap::elliptics;

static void elliptics_extract_arr(const list &l, unsigned char *dst, int *dlen)
{
	int length = len(l);

	if (length > *dlen)
		length = *dlen;

	memset(dst, 0, *dlen);
	for (int i = 0; i < length; ++i)
		dst[i] = extract<unsigned char>(l[i]);
}

struct elliptics_id {
	elliptics_id() : group_id(0), type(0) {}
	elliptics_id(list id_, int group_, int type_) : id(id_), group_id(group_), type(type_) {}

	elliptics_id(struct dnet_id &dnet) {
		for (unsigned int i = 0; i < sizeof(dnet.id); ++i)
			id.append(dnet.id[i]);

		group_id = dnet.group_id;
		type = dnet.type;
	}

	struct dnet_id to_dnet() const {
		struct dnet_id dnet;
		int len = sizeof(dnet.id);

 		elliptics_extract_arr(id, dnet.id, &len);

		dnet.group_id = group_id;
		dnet.type = type;

		return dnet;
	}

	list		id;
	uint32_t	group_id;
	int		type;
};

struct elliptics_range {
	elliptics_range() : offset(0), size(0),
		limit_start(0), limit_num(0), cflags(0), ioflags(0), group_id(0), type(0) {}

	list		start, end;
	uint64_t	offset, size;
	uint64_t	limit_start, limit_num;
	uint64_t	cflags;
	uint32_t	ioflags;
	int		group_id;
	int		type;
};

static void elliptics_extract_range(const struct elliptics_range &r, struct dnet_io_attr &io)
{
	int len = sizeof(io.id);

	elliptics_extract_arr(r.start, io.id, &len);
	elliptics_extract_arr(r.end, io.parent, &len);

	io.flags = r.ioflags;
	io.size = r.size;
	io.offset = r.offset;
	io.start = r.limit_start;
	io.num = r.limit_num;
	io.type = r.type;
}

class elliptics_log_wrap : public logger, public wrapper<logger> {
	public:
		elliptics_log_wrap(const uint32_t mask = DNET_LOG_ERROR | DNET_LOG_INFO) : logger(mask) {};

		void log(const uint32_t mask, const char *msg) {
			this->get_override("log")(mask, msg);
		}

		unsigned long clone(void) {
			return this->get_override("clone")();
		}
};

class elliptics_log_file_wrap : public log_file, public wrapper<log_file> {
	public:
		elliptics_log_file_wrap(const char *file, const uint32_t mask = DNET_LOG_ERROR | DNET_LOG_INFO) :
			log_file(file, mask) {};

		void log(const uint32_t mask, const char *msg) {
			if (override log = this->get_override("log")) {
				log_file::log(mask, msg);
				return;
			}

			log_file::log(mask, msg);
		}

		void default_log(uint32_t mask, const char *msg) { this->log(mask, msg); }

		unsigned long clone(void) {
			if (override clone = this->get_override("clone"))
				return log_file::clone();

			return log_file::clone();
		}

		unsigned long default_clone(void) { return this->clone(); }
};

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

class elliptics_node_python : public node {
	public:
		elliptics_node_python(logger &l) : node(l) {}

		elliptics_node_python(logger &l, elliptics_config &cfg) : node(l, cfg.config) {}

		void add_groups(const list &pgroups) {
			std::vector<int> groups;

			for (int i=0; i<len(pgroups); ++i)
				groups.push_back(extract<int>(pgroups[i]));

			node::add_groups(groups);
		}

		void write_metadata_by_id(const struct elliptics_id &id, const std::string &remote, const list &pgroups, uint64_t cflags) {
			struct timespec ts;
			memset(&ts, 0, sizeof(ts));

			struct dnet_id raw = id.to_dnet();

			std::vector<int> groups;

			for (int i=0; i<len(pgroups); ++i)
				groups.push_back(extract<int>(pgroups[i]));

			write_metadata((const dnet_id&)raw, remote, groups, ts, cflags);
		}

		void write_metadata_by_data_transform(const std::string &remote, uint64_t cflags) {
			struct timespec ts;
			memset(&ts, 0, sizeof(ts));

			struct dnet_id raw;

			transform(remote, raw);

			write_metadata((const dnet_id&)raw, remote, groups, ts, cflags);
		}


		void read_file_by_id(struct elliptics_id &id, const std::string &file, uint64_t offset, uint64_t size) {
			struct dnet_id raw = id.to_dnet();
			read_file(raw, file, offset, size);
		}

		void read_file_by_data_transform(const std::string &remote, const std::string &file,
				uint64_t offset, uint64_t size,	int type) {
			read_file(remote, file, offset, size, type);
		}

		void write_file_by_id(struct elliptics_id &id, const std::string &file,
				uint64_t local_offset, uint64_t offset, uint64_t size,
				uint64_t cflags, unsigned int ioflags) {
			struct dnet_id raw = id.to_dnet();
			write_file(raw, file, local_offset, offset, size, cflags, ioflags);
		}

		void write_file_by_data_transform(const std::string &remote, const std::string &file,
				uint64_t local_offset, uint64_t offset, uint64_t size,
				uint64_t cflags, unsigned int ioflags, int type) {
			write_file(remote, file, local_offset, offset, size, cflags, ioflags, type);
		}

		std::string read_data_by_id(const struct elliptics_id &id, uint64_t offset, uint64_t size,
				uint64_t cflags, unsigned int ioflags) {
			struct dnet_id raw = id.to_dnet();
			return read_data_wait(raw, offset, size, cflags, ioflags);
		}

		std::string read_data_by_data_transform(const std::string &remote, uint64_t offset, uint64_t size,
				uint64_t cflags, unsigned int ioflags, int type) {
			return read_data_wait(remote, offset, size, cflags, ioflags, type);
		}

		list prepare_latest_by_id(const struct elliptics_id &id, uint64_t cflags, list gl) {
			struct dnet_id raw = id.to_dnet();

			std::vector<int> groups;
			for (int i = 0; i < len(gl); ++i)
				groups.push_back(extract<int>(gl[i]));

			prepare_latest(raw, cflags, groups);

			list l;
			for (unsigned i = 0; i < groups.size(); ++i)
				l.append(groups[i]);

			return l;
		}

		std::string prepare_latest_by_id_str(const struct elliptics_id &id, uint64_t cflags, list gl) {
			struct dnet_id raw = id.to_dnet();

			std::vector<int> groups;
			for (int i = 0; i < len(gl); ++i)
				groups.push_back(extract<int>(gl[i]));

			prepare_latest(raw, cflags, groups);

			std::string ret;
			ret.assign((char *)groups.data(), groups.size() * 4);

			return ret;
		}

		std::string read_latest_by_id(const struct elliptics_id &id, uint64_t offset, uint64_t size,
				uint64_t cflags, unsigned int ioflags) {
			struct dnet_id raw = id.to_dnet();
			return read_latest(raw, offset, size, cflags, ioflags);
		}

		std::string read_latest_by_data_transform(const std::string &remote, uint64_t offset, uint64_t size,
				uint64_t cflags, unsigned int ioflags, int type) {
			return read_latest(remote, offset, size, cflags, ioflags, type);
		}

		std::string write_data_by_id(const struct elliptics_id &id, const std::string &data, uint64_t remote_offset,
				uint64_t cflags, unsigned int ioflags) {
			struct dnet_id raw = id.to_dnet();
			return write_data_wait(raw, data, remote_offset, cflags, ioflags);
		}

		std::string write_data_by_data_transform(const std::string &remote, const std::string &data, uint64_t remote_offset,
				uint64_t cflags, unsigned int ioflags, int type) {
			return write_data_wait(remote, data, remote_offset, cflags, ioflags, type);
		}

		std::string lookup_addr_by_data_transform(const std::string &remote, const int group_id) {
			return lookup_addr(remote, group_id);
		}

		std::string lookup_addr_by_id(const struct elliptics_id &id) {
			struct dnet_id raw = id.to_dnet();

			return lookup_addr(raw);
		}

		boost::python::tuple parse_lookup(const std::string &lookup) {
			const void *data = lookup.data();

			struct dnet_addr *addr = (struct dnet_addr *)data;
			struct dnet_cmd *cmd = (struct dnet_cmd *)(addr + 1);
			struct dnet_addr_attr *a = (struct dnet_addr_attr *)(cmd + 1);
			struct dnet_file_info *info = (struct dnet_file_info *)(a + 1);
			dnet_convert_file_info(info);

			std::string address(dnet_server_convert_dnet_addr(addr));
			int port = dnet_server_convert_port((struct sockaddr *)a->addr.addr, a->addr.addr_len);

			return make_tuple(address, port, info->size);
		}

		boost::python::tuple lookup_by_data_transform(const std::string &remote) {
			return parse_lookup(lookup(remote));
		}

		boost::python::tuple lookup_by_id(const struct elliptics_id &id) {
			struct dnet_id raw = id.to_dnet();

			return parse_lookup(lookup(raw));
		}

		struct dnet_node_status update_status_by_id(const struct elliptics_id &id, struct dnet_node_status &status) {
			struct dnet_id raw = id.to_dnet();

			update_status(raw, &status);
			return status;
		}
		
		struct dnet_node_status update_status_by_string(const std::string &saddr, const int port, const int family,
									struct dnet_node_status &status) {
			update_status(saddr.c_str(), port, family, &status);
			return status;
		}

		boost::python::list read_data_range(const struct elliptics_range &r) {
			struct dnet_io_attr io;
			elliptics_extract_range(r, io);

			std::vector<std::string> ret;
			ret = node::read_data_range(io, r.group_id, r.cflags);

			boost::python::list l;

			for (size_t i = 0; i < ret.size(); ++i) {
				l.append(ret[i]);
			}

			return l;
		}

		boost::python::list get_routes() {

			std::vector<std::pair<struct dnet_id, struct dnet_addr> > routes;
			std::vector<std::pair<struct dnet_id, struct dnet_addr> >::iterator it;

			boost::python::list res;

			routes = node::get_routes();

			for (it = routes.begin(); it != routes.end(); it++) {
				struct elliptics_id id(it->first);
				std::string address(dnet_server_convert_dnet_addr(&(it->second)));

				res.append(make_tuple(id, address));
			}

			return res;
		}

		std::string exec_name(const struct elliptics_id &id, const std::string &event,
				const std::string &data, const std::string &binary) {
			struct dnet_id raw = id.to_dnet();

			return exec(&raw, event, data, binary);
		}

		std::string exec_name_by_name(const std::string &remote, const std::string &event,
				const std::string &data, const std::string &binary) {
			struct dnet_id raw;
			transform(remote, raw);
			raw.type = 0;
			raw.group_id = 0;

			return exec(&raw, event, data, binary);
		}

		std::string exec_name_all(const std::string &event, const std::string &data, const std::string &binary) {
			return exec(NULL, event, data, binary);
		}

		void remove_by_id(const struct elliptics_id &id, uint64_t cflags, uint64_t ioflags) {
			struct dnet_id raw = id.to_dnet();

			remove_raw(raw, cflags, ioflags);
		}

		void remove_by_name(const std::string &remote, int type, uint64_t cflags, uint64_t ioflags) {
			remove_raw(remote, type, cflags, ioflags);
		}

		list bulk_read_by_name(const list &keys, uint64_t cflags = 0) {
			unsigned int length = len(keys);

			std::vector<std::string> k;
			k.resize(length);

			for (unsigned int i = 0; i < length; ++i)
				k[i] = extract<std::string>(keys[i]);

			std::vector<std::string> ret =  bulk_read(k, cflags);

			list py_ret;
			for (size_t i = 0; i < ret.size(); ++i) {
				py_ret.append(ret[i]);
			}

			return py_ret;
		}

		list stat_log() {
			list statistics;
			callback c;
			std::string ret;
			int err;
			int i;

			err = dnet_request_stat(m_node, NULL, DNET_CMD_STAT_COUNT, DNET_ATTR_CNTR_GLOBAL,
				callback::complete_callback, (void *)&c);
			if (err < 0) {
				std::ostringstream str;
				str << "Failed to request statistics: " << err;
				throw std::runtime_error(str.str());
			}

			ret = c.wait(err);

			const void *data = ret.data();
			int size = ret.size();

			while (size > 0) {
				dict node_stat, storage_commands, proxy_commands, counters;
				struct dnet_addr *addr = (struct dnet_addr *)data;
				struct dnet_cmd *cmd = (struct dnet_cmd *)(addr + 1);
				if (cmd->size <= sizeof(struct dnet_addr_stat)) {
					size -= cmd->size + sizeof(struct dnet_addr) + sizeof(struct dnet_cmd);
					data = (char *)data + cmd->size + sizeof(struct dnet_addr) + sizeof(struct dnet_cmd);
					continue;
				}

				struct dnet_addr_stat *as = (struct dnet_addr_stat *)(cmd + 1);

				dnet_convert_addr_stat(as, 0);
				std::string address(dnet_server_convert_dnet_addr(addr));
				node_stat[std::string("addr")] = address;
				node_stat[std::string("group_id")] = cmd->id.group_id;

				for (i = 0; i < as->num; ++i) {
					if (i < as->cmd_num) {
						storage_commands[std::string(dnet_counter_string(i, as->cmd_num))] = 
							make_tuple((unsigned long long)as->count[i].count, (unsigned long long)as->count[i].err);
					} else if (i < (as->cmd_num * 2)) {
						proxy_commands[std::string(dnet_counter_string(i, as->cmd_num))] = 
							make_tuple((unsigned long long)as->count[i].count, (unsigned long long)as->count[i].err);
					} else {
						counters[std::string(dnet_counter_string(i, as->cmd_num))] = 
							make_tuple((unsigned long long)as->count[i].count, (unsigned long long)as->count[i].err);
					}
				}

				node_stat["storage_commands"] = storage_commands;
				node_stat["proxy_commands"] = proxy_commands;
				node_stat["counters"] = counters;

				statistics.append(node_stat);

				int sz = sizeof(struct dnet_addr) + sizeof(struct dnet_cmd) + cmd->size;
				size -= sz;
				data = (char *)data + sz;
			}

			return statistics;
		}

};

BOOST_PYTHON_MEMBER_FUNCTION_OVERLOADS(add_remote_overloads, add_remote, 2, 3);

BOOST_PYTHON_MODULE(libelliptics_python) {
	class_<elliptics_id>("elliptics_id", init<>())
		.def(init<list, int, int>())
		.def_readwrite("id", &elliptics_id::id)
		.def_readwrite("group_id", &elliptics_id::group_id)
		.def_readwrite("type", &elliptics_id::type)
	;

	class_<elliptics_range>("elliptics_range", init<>())
		.def_readwrite("start", &elliptics_range::start)
		.def_readwrite("end", &elliptics_range::end)
		.def_readwrite("offset", &elliptics_range::offset)
		.def_readwrite("size", &elliptics_range::size)
		.def_readwrite("ioflags", &elliptics_range::ioflags)
		.def_readwrite("cflags", &elliptics_range::cflags)
		.def_readwrite("group_id", &elliptics_range::group_id)
		.def_readwrite("type", &elliptics_range::type)
		.def_readwrite("limit_start", &elliptics_range::limit_start)
		.def_readwrite("limit_num", &elliptics_range::limit_num)
	;

	class_<elliptics_log_wrap, boost::noncopyable>("elliptics_log", init<const uint32_t>())
		.def("log", pure_virtual(&logger::log))
		.def("clone", pure_virtual(&logger::clone))
	;

	class_<elliptics_log_file_wrap, boost::noncopyable, bases<logger> >("elliptics_log_file", init<const char *, const uint32_t>())
		.def("log", &log_file::log, &elliptics_log_file_wrap::default_log)
		.def("clone", &log_file::clone, &elliptics_log_file_wrap::default_clone)
	;

	class_<dnet_node_status>("dnet_node_status", init<>())
		.def_readwrite("nflags", &dnet_node_status::nflags)
		.def_readwrite("status_flags", &dnet_node_status::status_flags)
		.def_readwrite("log_mask", &dnet_node_status::log_mask)
	;

	class_<node>("elliptics_node", init<logger &>())
		.def("add_remote", &node::add_remote, add_remote_overloads())
	;

	class_<dnet_config>("dnet_config", init<>())
		.def_readwrite("wait_timeout", &dnet_config::wait_timeout)
		.def_readwrite("flags", &dnet_config::flags)
		.def_readwrite("check_timeout", &dnet_config::check_timeout)
		.def_readwrite("io_thread_num", &dnet_config::io_thread_num)
		.def_readwrite("nonblocking_io_thread_num", &dnet_config::nonblocking_io_thread_num)
		.def_readwrite("net_thread_num", &dnet_config::net_thread_num)
		.def_readwrite("client_prio", &dnet_config::client_prio)
	;
	
	class_<elliptics_config>("elliptics_config", init<>())
		.def_readwrite("config", &elliptics_config::config)
		.add_property("cookie", &elliptics_config::cookie_get, &elliptics_config::cookie_set)
	;

	class_<elliptics_node_python, bases<node> >("elliptics_node_python", init<logger &>())
		.def(init<logger &, elliptics_config &>())
		.def("add_remote", &node::add_remote, add_remote_overloads())

		.def("add_groups", &elliptics_node_python::add_groups)

		.def("read_file", &elliptics_node_python::read_file_by_id)
		.def("read_file", &elliptics_node_python::read_file_by_data_transform)
		.def("write_file", &elliptics_node_python::write_file_by_id)
		.def("write_file", &elliptics_node_python::write_file_by_data_transform)

		.def("read_data", &elliptics_node_python::read_data_by_id)
		.def("read_data", &elliptics_node_python::read_data_by_data_transform)

		.def("prepare_latest", &elliptics_node_python::prepare_latest_by_id)
		.def("prepare_latest_str", &elliptics_node_python::prepare_latest_by_id_str)

		.def("read_latest", &elliptics_node_python::read_latest_by_id)
		.def("read_latest", &elliptics_node_python::read_latest_by_data_transform)

		.def("write_data", &elliptics_node_python::write_data_by_id)
		.def("write_data", &elliptics_node_python::write_data_by_data_transform)

		.def("lookup_addr", &elliptics_node_python::lookup_addr_by_data_transform)
		.def("lookup_addr", &elliptics_node_python::lookup_addr_by_id)

		.def("lookup", &elliptics_node_python::lookup_by_data_transform)
		.def("lookup", &elliptics_node_python::lookup_by_id)

		.def("write_metadata", &elliptics_node_python::write_metadata_by_id)
		.def("write_metadata", &elliptics_node_python::write_metadata_by_data_transform)

		.def("update_status", &elliptics_node_python::update_status_by_id)
		.def("update_status", &elliptics_node_python::update_status_by_string)

		.def("read_data_range", &elliptics_node_python::read_data_range)

		.def("get_routes", &elliptics_node_python::get_routes)
		.def("stat_log", &elliptics_node_python::stat_log)

		.def("exec_event", &elliptics_node_python::exec_name)
		.def("exec_event", &elliptics_node_python::exec_name_by_name)
		.def("exec_event", &elliptics_node_python::exec_name_all)

		.def("remove", &elliptics_node_python::remove_by_id)
		.def("remove", &elliptics_node_python::remove_by_name)

		.def("bulk_read", &elliptics_node_python::bulk_read_by_name)
	;
};
#endif
