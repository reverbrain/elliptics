/*
 * 2008+ Copyright (c) Evgeniy Polyakov <zbr@ioremap.net>
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
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
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

#include "elliptics_id.h"
#include "async_result.h"
#include "result_entry.h"
#include "elliptics_time.h"
#include "elliptics_io_attr.h"
#include "elliptics_session.h"

namespace bp = boost::python;

namespace ioremap { namespace elliptics { namespace python {
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

enum elliptics_exceptions_policy {
	policy_no_exceptions			= ioremap::elliptics::session::no_exceptions,
	policy_throw_at_start			= ioremap::elliptics::session::throw_at_start,
	policy_throw_at_wait			= ioremap::elliptics::session::throw_at_wait,
	policy_throw_at_get				= ioremap::elliptics::session::throw_at_get,
	policy_throw_at_iterator_end	= ioremap::elliptics::session::throw_at_iterator_end,
	policy_default_exceptions		= ioremap::elliptics::session::throw_at_wait |
									  ioremap::elliptics::session::throw_at_get |
									  ioremap::elliptics::session::throw_at_iterator_end
};

enum elliptics_config_flags {
	config_flags_join_network		= DNET_CFG_JOIN_NETWORK,
	config_flags_no_route_list		= DNET_CFG_NO_ROUTE_LIST,
	config_flags_mix_stats			= DNET_CFG_MIX_STATES,
	config_flags_no_csum			= DNET_CFG_NO_CSUM,
	config_flags_randomize_states	= DNET_CFG_RANDOMIZE_STATES,
};

enum elliptics_node_status_flags {
	node_status_flags_change		= DNET_ATTR_STATUS_CHANGE,
	node_status_flags_exit			= DNET_STATUS_EXIT,
	node_status_flags_ro			= DNET_STATUS_RO,
};

dnet_config* dnet_config_init() {
	auto config = new dnet_config();
	memset(config, 0, sizeof(dnet_config));
	config->wait_timeout = 5;
	config->check_timeout = 20;
	config->io_thread_num = 1;
	config->net_thread_num = 1;
	config->nonblocking_io_thread_num = 1;
	return config;
}

void dnet_config_set_cookie(dnet_config &config, const std::string &cookie) {
	size_t sz = sizeof(config.cookie);
	if (cookie.size() + 1 < sz)
		sz = cookie.size() + 1;
	memset(config.cookie, 0, sizeof(config.cookie));
	snprintf(config.cookie, sz, "%s", (char *)cookie.data());
}

std::string dnet_config_get_cookie(const dnet_config &config) {
	return std::string(config.cookie, sizeof(config.cookie));
}

dnet_config& dnet_config_config(dnet_config &config) {
	return config;
}

class elliptics_node_python : public node, public bp::wrapper<node> {
	public:
		elliptics_node_python(const logger &l)
			: node(l) {}

		elliptics_node_python(const logger &l, dnet_config &cfg)
			: node(l, cfg) {}

		elliptics_node_python(const node &n): node(n) {}
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

void logger_log(logger &log, const char *msg, int level)
{
	log.log(level, msg);
}

void next_impl(bp::api::object &value, const bp::api::object &next)
{
	value = next();
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

std::string get_cmd_string(int cmd) {
	return std::string(dnet_cmd_string(cmd));
}

BOOST_PYTHON_MODULE(core)
{
	bp::docstring_options local_docstring_options(true, false, false);
	bp::class_<error>(
	    "ErrorInfo", "Basic error for Elliptics",
	    bp::init<int, std::string>())
		.def("__str__", &error::error_message,
		    "__str__()\n"
		    "    x.__str__() <==> str(x)")
		.def("__repr__", &error::error_message,
		     "__repr__()\n"
		     "    x.__repr__() <==> repr(x)")
		.add_property("message", &error::error_message,
		    "message()\n"
		    "    Returns description of the message\n\n"
		    "    print error.message()")
		.add_property("code", &error::error_code,
		    "code()\n"
		    "    Returns code of the error\n\n"
		    "    print error.code()")
	;
	elliptics_error_translator error_translator;
	error_translator.initialize();

	bp::scope().attr("trace_bit") = uint32_t(DNET_TRACE_BIT);

	bp::register_exception_translator<timeout_error>(error_translator);
	bp::register_exception_translator<not_found_error>(error_translator);
	bp::register_exception_translator<error>(error_translator);
	bp::register_exception_translator<std::ios_base::failure>(ios_base_failure_translator);

	bp::class_<logger, boost::noncopyable>("AbstractLogger")
		.def("log", &logger::log, bp::args("log_level", "log_message"),
		    "log(self, level, message)\n"
		    "   logs a message with level\n\n"
		    "   logger.log(elliptics.log_level.debug, \"We've got a problem\"")
	;

	bp::class_<file_logger, bp::bases<logger> > file_logger_class(
		"Logger", "File logger for using inside Elliptics client library",
		bp::init<const char *, const uint32_t>(bp::args("log_file", "log_level"),
		    "__init__(self, filename, log_level)\n"
		    "    Initializes file logger by the specified file and level of verbosity\n\n"
		    "    logger = elliptics.Logger(\"/dev/stderr\", elliptics.log_level.debug)"));

	bp::class_<dnet_config>(
	    "Config", "Config allows override default configuration for client node")
		.def("__init__", boost::python::make_constructor(&dnet_config_init))
		.add_property("cookie", &dnet_config_get_cookie, &dnet_config_set_cookie,
		              "authentication cookie")
		.def_readwrite("wait_timeout", &dnet_config::wait_timeout,
		               "Time to wait for an operation complete")
		.def_readwrite("check_timeout", &dnet_config::check_timeout,
		               "Timeout for pinging node")
		.def_readwrite("io_thread_num", &dnet_config::io_thread_num,
		               "Number of IO threads in processing pool")
		.def_readwrite("nonblocking_io_thread_num", &dnet_config::nonblocking_io_thread_num,
		               "Number of IO threads in processing pool dedicated to nonblocking operations")
		.def_readwrite("net_thread_num", &dnet_config::net_thread_num,
		               "Number of threads in network processing pool")
		.def_readwrite("flags", &dnet_config::flags,
		               "Bit set of elliptics.config_flags")
		.def_readwrite("client_prio", &dnet_config::client_prio,
		               "IP priority")
	;

	bp::class_<elliptics_node_python>(
	    "Node", "Node represents a connection with Elliptics.",
	    bp::init<logger>(bp::arg("logger"),
	        "__init__(self, logger)\n"
	        "    Initializes node by the logger and dafault configuration\n\n"
	        "    node = elliptics.Node(logger)"))
		.def(bp::init<logger, dnet_config &>(bp::args("logger", "config"),
		     "__init__(self, logger, config)\n"
		     "    Initializes node by the logger and custom configuration\n\n"
		     "node = elliptics.Node(logger, config)"))
		.def("add_remote", static_cast<void (node::*)(const char*, int, int)>(&node::add_remote),
		     (bp::arg("addr"), bp::arg("port"), bp::arg("family") = AF_INET),
		     "add_remote(addr, port, family=AF_INET)\n"
		     "    Adds connection to Elliptics node\n"
		     "    which located on address, port, family.\n"
		     "    Throws exception if connection hasn't been established\n\n"
		     "    node.add_remote(addr='host.com', port=1025, family=2)")
		.def("add_remote", static_cast<void (node::*)(const char*)>(&node::add_remote),
		     (bp::arg("addr")),
		     "add_remote(addr)\n"
		     "    Adds connection to Elliptics node which located on address.\n"
		     "    addr is string in format 'host:port:family'.\n"
		     "    Throws exception if connection hasn't been established\n\n"
		     "    node.add_remote('host.com:1025:2')")
		.def("set_timeouts", static_cast<void (node::*)(const int, const int)>(&node::set_timeouts),
		     (bp::arg("wait_timeout"), bp::arg("check_timeout")),
		     "set_timeouts(wait_timeout, check_timeout)\n"
		     "    Changes timeouts values\n\n"
		     "    node.set_timeouts(wait_timeout=5, check_timeout=50)")
	;

	bp::enum_<elliptics_iterator_flags>("iterator_flags",
	    "Flags which specifies how iteration should be performed:\n\n"
	    "default\n    There no filtering should be while iteration. All keys will be presented\n"
	    "data\n    Iteration results should also includes objects datas\n"
	    "key_range\n    elliptics.Id ranges should be used for filtering keys on the node while iteration\n"
	    "ts_range\n    Time range should be used for filtering keys on the node while iteration")
		.value("default", iflag_default)
		.value("data", iflag_data)
		.value("key_range", iflag_key_range)
		.value("ts_range", iflag_ts_range)
	;

	bp::enum_<elliptics_iterator_types>("iterator_types",
	    "Flags which specifies how iteration results should be transmitted:\n\n"
	    "disk\n    Iterator saves data chunks (index/metadata + (optionally) data)\n"
	          "    locally on server to $root/iter/$id instead of sending chunks to client\n"
	    "network\n    Iterator sends data chunks to client")
		.value("disk", itype_disk)
		.value("network", itype_network)
	;

	bp::enum_<elliptics_cflags>("command_flags",
	    "Flags which specifies how operation should be done\n\n"
	    "default\n    The key is locked before performing an operation and unlocked when an operation will done\n"
	    "direct\n    Request is sent to the specified Node bypassing the DHT ring\n"
	    "nolock\n    Server will not check the key is locked and will not lock it during this transaction.\n"
	            "    The operation will be handled in separated io thread pool")
		.value("default", cflags_default)
		.value("direct", cflags_direct)
		.value("nolock", cflags_nolock)
	;

	bp::enum_<elliptics_ioflags>("io_flags",
		"Bit flags which specifies how operation should be executed:\n\n"
		"default\n    The default value overwrites the data by specified offset and size\n"
		"append\n    Append given data at the end of the object\n"
		"prepare\n    eblob prepare/commit phase \n"
		"commit\n    eblob prepare/commit phase \n"
		"overwrite\n    Overwrite data \n"
		"nocsum\n    Do not checksum data \n"
		"plain_write\n    This flag is used when we want backend not to perform any additional actions\n"
		             "    except than write data at given offset\n"
		"nodata\n    Do not really send data in range request.\n"
		        "    Send only statistics instead.\n"
		"cache\n    Says we should first check cache: read/write or delete\n"
		"cache_only\n    Means we do not want to sink to disk,\n"
		            "    just return whatever cache processing returned (even error)\n"
		"cache_remove_from_disk\n    is set and object is being removed from cache,\n"
		                        "    then remove object from disk too")
		.value("default", ioflags_default)
		.value("append", ioflags_append)
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

	bp::enum_<elliptics_log_level>("log_level",
	    "Different levels of verbosity elliptics logs:\n\n"
	     "data\n    The level has very important data, practically nothing is written\n"
	     "error\n    The level contains reports of the previous level and critical errors that materially affect the work\n"
	     "info\n    The level contains reports of the previous level and messages about the time of the various operations\n"
	     "notice\n    The level is considered to be the first level of debugging\n"
	     "debug\n    The level includes all sort of information about errors and work")
		.value("data", log_level_data)
		.value("error", log_level_error)
		.value("info", log_level_info)
		.value("notice", log_level_notice)
		.value("debug", log_level_debug)
	;

	bp::enum_<elliptics_exceptions_policy>("exceptions_policy",
	    "Bit flags for specifying exception policy of elliptics.Session:\n\n"
	    "no_exceptions\n    No excetion will be thrown\n"
	    "throw_at_start\n    An exception will be thrown when the operation is started\n"
	    "throw_at_wait\n    An exception will be thrown when all results of the operation is available\n"
	    "throw_at_get\n    An exception will be thrown when the next result of the operation is available\n"
	    "throw_at_iterator_end\n    An exception will be thrown after the iterator has reached last result\n"
	    "default_exceptions\n    It is the union of follow flags: throw_at_wait, throw_at_get, throw_at_iterator_end")
		.value("no_exceptions", policy_no_exceptions)
		.value("throw_at_start", policy_throw_at_start)
		.value("throw_at_wait", policy_throw_at_wait)
		.value("throw_at_get", policy_throw_at_get)
		.value("throw_at_iterator_end", policy_throw_at_iterator_end)
		.value("default_exceptions", policy_default_exceptions)
	;

	bp::enum_<elliptics_config_flags>("config_flags",
	    "Bit flags which could be used at elliptics.Config.flags:\n\n"
	    "no_route_list\n    Do not request route table from remote nodes\n"
	    "mix_stats\n    Mix states according to their weights before reading data\n"
	    "no_csum\n    Globally disable checksum verification and update\n"
	    "randomize_states\n    Randomize states for read requests\n\n"
	    "config.flags = elliptics.config_flags.mix_stats | elliptics.config_flags.randomize_states\n"
	    )
		.value("no_route_list", config_flags_no_route_list)
		.value("mix_stats", config_flags_mix_stats)
		.value("no_csum", config_flags_no_csum)
		.value("randomize_states", config_flags_randomize_states)
	;

	bp::enum_<elliptics_node_status_flags>("status_flags",
	    "Bit flags which used for changing node status:\n\n"
	    "change\n    Elliptics node status - if set, status will be changed\n"
	    "exit\n    Elliptics node should exit\n"
	    "ro\n    Ellipitcs node goes ro/rw")
		.value("change", node_status_flags_change)
		.value("exit", node_status_flags_exit)
		.value("ro", node_status_flags_ro)
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

	init_elliptics_id();
	init_async_results();
	init_result_entry();
	init_elliptics_time();
	init_elliptics_io_attr();
	init_elliptics_session();
};

} } } // namespace ioremap::elliptics::python
