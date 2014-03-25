/*
 * Copyright 2008+ Evgeniy Polyakov <zbr@ioremap.net>
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

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/syscall.h>

#include <ctype.h>
#include <fcntl.h>
#include <errno.h>
#include <malloc.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#include <algorithm>

#include "elliptics/packet.h"
#include "elliptics/interface.h"
#include "elliptics/backends.h"

#include "../library/elliptics.h"
#include "../monitor/monitor.h"

#include <boost/lexical_cast.hpp>

#include <rapidjson/document.h>
#include <rapidjson/filestream.h>

#include <blackhole/log.hpp>
#include <blackhole/repository.hpp>
#include <blackhole/repository/config/parser/rapidjson.hpp>

#include "common.h"

#ifndef __unused
#define __unused	__attribute__ ((unused))
#endif

/*
 * Config parser is single-threaded.
 * No locks and simultaneous access from different threads.
 */

#define DNET_CONF_COMMENT	'#'
#define DNET_CONF_DELIMITER	'='

extern __thread uint32_t trace_id;

namespace ioremap { namespace elliptics { namespace config {
class config_error : public std::runtime_error
{
public:
	explicit config_error(const std::string &arg) : std::runtime_error(arg)
	{
	}
};

struct backend_info
{
	dnet_config_backend config;
	dnet_log *log;
	std::vector<char> data;
};

struct config_data : public dnet_config_data
{
	std::vector<backend_info> backends;
	std::string logger_value;
	dnet_log logger_impl;
};

extern "C" dnet_config_data *dnet_config_data_create()
{
	config_data *data = new config_data;

	memset(static_cast<dnet_config_data *>(data), 0, sizeof(dnet_config_data));
	memset(&data->logger_impl, 0, sizeof(data->logger_impl));

	data->logger_impl.log_level = DNET_LOG_DEBUG;
	data->logger_impl.log = dnet_common_log;
	data->cfg_state.log = &data->logger_impl;

	data->cfg_state.caches_number = DNET_DEFAULT_CACHES_NUMBER;
	data->cfg_state.cache_pages_number = DNET_DEFAULT_CACHE_PAGES_NUMBER;
	data->cfg_state.cache_pages_proportions = reinterpret_cast<unsigned *>(malloc(DNET_DEFAULT_CACHE_PAGES_NUMBER * sizeof(unsigned)));

	for (unsigned i = 0; i < DNET_DEFAULT_CACHE_PAGES_NUMBER; ++i)
		data->cfg_state.cache_pages_proportions[i] = 1;

	return data;
}

extern "C" void dnet_config_data_destroy(dnet_config_data *public_data)
{
	config_data *data = static_cast<config_data *>(public_data);

	free(data->cfg_addrs);
	free(data->cfg_remotes);

	delete data;
}

static int dnet_simple_set(config_data *data, const char *key, unsigned long long value)
{
	if (!strcmp(key, "wait_timeout"))
		data->cfg_state.wait_timeout = value;
	else if (!strcmp(key, "check_timeout"))
		data->cfg_state.check_timeout = value;
	else if (!strcmp(key, "cache_sync_timeout"))
		data->cfg_state.cache_sync_timeout = value;
	else if (!strcmp(key, "stall_count"))
		data->cfg_state.stall_count = value;
	else if (!strcmp(key, "join"))
		data->cfg_state.flags |= value ? DNET_CFG_JOIN_NETWORK : 0;
	else if (!strcmp(key, "flags"))
		data->cfg_state.flags |= (value & ~DNET_CFG_JOIN_NETWORK);
	else if (!strcmp(key, "daemon"))
		data->daemon_mode = value;
	else if (!strcmp(key, "io_thread_num"))
		data->cfg_state.io_thread_num = value;
	else if (!strcmp(key, "nonblocking_io_thread_num"))
		data->cfg_state.nonblocking_io_thread_num = value;
	else if (!strcmp(key, "net_thread_num"))
		data->cfg_state.net_thread_num = value;
	else if (!strcmp(key, "bg_ionice_class"))
		data->cfg_state.bg_ionice_class = value;
	else if (!strcmp(key, "bg_ionice_prio"))
		data->cfg_state.bg_ionice_prio = value;
	else if (!strcmp(key, "removal_delay"))
		data->cfg_state.removal_delay = value;
	else if (!strcmp(key, "server_net_prio"))
		data->cfg_state.server_prio = value;
	else if (!strcmp(key, "client_net_prio"))
		data->cfg_state.client_prio = value;
	else if (!strcmp(key, "indexes_shard_count"))
		data->cfg_state.indexes_shard_count = value;
	else if (!strcmp(key, "monitor_port"))
		data->cfg_state.monitor_port = value;
	else
		return -1;

	return 0;
}

static int dnet_set_group(config_data *data, const char *key __unused, unsigned long long value)
{
	data->cfg_state.group_id = value;
	return 0;
}

struct dnet_addr_wrap {
	struct dnet_addr	addr;
	int			addr_group;
};

static bool dnet_addr_wrap_less_than(const dnet_addr_wrap &w1, const dnet_addr_wrap &w2)
{
	return w1.addr_group < w2.addr_group;
}

static int dnet_set_addr(config_data *data, const char *key __unused, const std::vector<std::string> &addresses)
{
	std::vector<dnet_addr_wrap> wraps;

	for (auto it = addresses.begin(); it != addresses.end(); ++it) {
		try {
			std::string address = *it;
			int group = -1;

			size_t delim_index = address.find_first_of(DNET_CONF_ADDR_DELIM);
			if (delim_index == std::string::npos)
				throw config_error("port and address delimiter is missed");

			size_t group_index = address.find_first_of('-', delim_index);

			if (group_index != std::string::npos) {
				std::string group_str = address.substr(group_index + 1);
				try {
					group = boost::lexical_cast<int>(group_str);
				} catch (std::exception &exc) {
					throw config_error(std::string("address group parse error: ") + exc.what());
				}

				address.resize(group_index);
			}

			std::vector<char> address_copy(address.begin(), address.end());
			address_copy.push_back('\0');

			int port;
			int family;
			int err = dnet_parse_addr(address_copy.data(), &port, &family);

			if (err) {
				throw config_error(*it + ": failed to parse address: " + strerror(-err)
					+ ", " + boost::lexical_cast<std::string>(err));
			}

			data->cfg_state.port = port;
			data->cfg_state.family = family;

			dnet_addr_wrap wrap;
			wrap.addr.addr_len = sizeof(wrap.addr.addr);
			wrap.addr.family = data->cfg_state.family;
			wrap.addr_group = group;
			err = dnet_fill_addr(&wrap.addr, address_copy.data(), port, SOCK_STREAM, IPPROTO_TCP);

			if (err) {
				throw config_error(*it + ": failed to parse address: " + strerror(-err)
					+ ", " + boost::lexical_cast<std::string>(err));
			}

			wraps.push_back(wrap);
		} catch (std::exception &exc) {
			std::stringstream out;
			out << "'options.address[" << std::distance(addresses.begin(), it)
				<< "]', " << exc.what();
			throw config_error(out.str());
		}
	}

	if (!wraps.empty()) {
		std::sort(wraps.begin(), wraps.end(), dnet_addr_wrap_less_than);

		data->cfg_addrs = reinterpret_cast<dnet_addr *>(malloc(sizeof(struct dnet_addr) * wraps.size()));
		if (!data->cfg_addrs)
			throw std::bad_alloc();

		for (size_t i = 0; i < wraps.size(); ++i)
			data->cfg_addrs[i] = wraps[i].addr;
		data->cfg_addr_num = wraps.size();
	}

	return 0;
}

static int dnet_set_remote_addrs(config_data *data, const char *key __unused, const std::vector<std::string> &remotes)
{
	std::string tmp;
	for (size_t i = 0; i < remotes.size(); ++i) {
		tmp.append(remotes[i]);
		tmp.append(1, ' ');
	}

	if (tmp.size() > 0)
		tmp.resize(tmp.size() - 1);

	data->cfg_remotes = strdup(tmp.c_str());
	if (!data->cfg_remotes)
		return -ENOMEM;

	return 0;
}

static int dnet_set_srw(config_data *data, const char *key, const char *value)
{
	char **ptr = NULL;

	if (!strcmp(key, "srw_config"))
		ptr = &data->cfg_state.srw.config;

	if (ptr) {
		free(*ptr);
		*ptr = strdup(value);
		if (!*ptr)
			return -ENOMEM;
	}

	return 0;
}

static int dnet_set_malloc_options(config_data *data __unused, const char *key __unused, unsigned long long value)
{
	int err, thr = value;

	err = mallopt(M_MMAP_THRESHOLD, thr);
	if (err < 0) {
		dnet_backend_log(data->cfg_state.log, DNET_LOG_ERROR, "Failed to set mmap threshold to %d: %s\n", thr, strerror(errno));
		return err;
	}

	dnet_backend_log(data->cfg_state.log, DNET_LOG_INFO, "Set mmap threshold to %d.\n", thr);
	return 0;
}

static int dnet_set_auth_cookie(config_data *data, const char *key __unused, const char *value)
{
	snprintf(data->cfg_state.cookie, DNET_AUTH_COOKIE_SIZE, "%s", value);
	return 0;
}

extern "C" int dnet_node_reset_log(struct dnet_node *n)
{
	(void) n;
	return 0;
//	return dnet_node_set_log_impl(n->config_data, n->config_data->logger_value);
}

static int dnet_set_history_env(config_data *data, const char *key __unused, const char *value)
{
	snprintf(data->cfg_state.history_env, sizeof(data->cfg_state.history_env), "%s", value);
	return 0;
}

static int dnet_set_cache_size(config_data *data, const char *key __unused, unsigned long long value)
{
	data->cfg_state.cache_size = value;
	return 0;
}

static int dnet_set_caches_number(config_data *data, const char *key __unused, unsigned long long value)
{
	data->cfg_state.caches_number = value;
	return 0;
}

static int dnet_set_cache_pages_proportions(config_data *data, const char *key __unused, const std::vector<unsigned> &values)
{
	free(data->cfg_state.cache_pages_proportions);
	data->cfg_state.cache_pages_number = 0;

	data->cfg_state.cache_pages_proportions = reinterpret_cast<unsigned *>(malloc(values.size() * sizeof(unsigned)));
	if (!data->cfg_state.cache_pages_proportions)
		throw std::bad_alloc();

	memcpy(data->cfg_state.cache_pages_proportions, values.data(), values.size() * sizeof(unsigned));

	data->cfg_state.cache_pages_number = values.size();
	return 0;
}

template <typename T>
struct handler_type;

template <>
struct handler_type<unsigned long long>
{
	void operator()(config_data *data, const char *key, const rapidjson::Value &value) const
	{
		if (!value.IsUint64())
			throw config_error("'options." + std::string(key) + "' is not unsigned int");
		int err = handler(data, key, value.GetUint64());
		if (err)
			throw config_error("'options." + std::string(key) + "': " + strerror(-err));
	}

	int (*handler)(config_data *, const char *, unsigned long long);
};

template <>
struct handler_type<const char *>
{
	void operator()(config_data *data, const char *key, const rapidjson::Value &value) const
	{
		if (!value.IsString())
			throw config_error("'options." + std::string(key) + "' is not string");
		int err = handler(data, key, value.GetString());
		if (err)
			throw config_error("'options." + std::string(key) + "': " + strerror(-err));
	}

	int (*handler)(config_data *, const char *, const char *);
};

template <>
struct handler_type<const std::vector<std::string> &>
{
	void operator()(config_data *data, const char *key, const rapidjson::Value &value) const
	{
		if (!value.IsArray())
			throw config_error("'options." + std::string(key) + "' is not array");

		std::vector<std::string> entries;
		entries.reserve(value.Size());

		for (size_t i = 0; i < value.Size(); ++i) {
			const rapidjson::Value &entry = value[i];
			if (!entry.IsString())
				throw config_error("'options." + std::string(key) + "[" + boost::lexical_cast<std::string>(i) + "]' is not string");

			entries.emplace_back(entry.GetString(), entry.GetStringLength());
		}

		int err = handler(data, key, entries);
		if (err)
			throw config_error("'options." + std::string(key) + "': " + strerror(-err));
	}

	int (*handler)(config_data *, const char *, const std::vector<std::string> &);
};

template <>
struct handler_type<const std::vector<unsigned> &>
{
	void operator()(config_data *data, const char *key, const rapidjson::Value &value) const
	{
		if (!value.IsArray())
			throw config_error("'options." + std::string(key) + "' is not array");

		std::vector<unsigned> entries;
		entries.reserve(value.Size());

		for (size_t i = 0; i < value.Size(); ++i) {
			const rapidjson::Value &entry = value[i];
			if (!entry.IsUint())
				throw config_error("'options." + std::string(key) + "[" + boost::lexical_cast<std::string>(i) + "]' is not unisnged int");

			entries.emplace_back(entry.GetUint());
		}

		int err = handler(data, key, entries);
		if (err)
			throw config_error("'options." + std::string(key) + "': " + strerror(-err));
	}

	int (*handler)(config_data *, const char *, const std::vector<unsigned> &);
};

struct config_entry_function
{
public:
	template <typename T>
	config_entry_function(int (*handler)(config_data *, const char *, T))
	{
		handler_type<T> result = { handler };
		m_handler = result;
	}
	config_entry_function(int (*handler)(config_data *, const char *, const rapidjson::Value &))
	{
		m_handler = handler;
	}

	void operator()(config_data *data, const char *key, const rapidjson::Value &value) const
	{
		m_handler(data, key, value);
	}
private:
	std::function<void (config_data *data, const char *key, const rapidjson::Value &value)> m_handler;
};

enum class level {
	debug,
	notice,
	info,
	warning,
	error
};

const rapidjson::Value &json_get(const rapidjson::Value &value, const char *name, const std::string &field,
				 bool (rapidjson::Value::*method)() const, const char *type)
{
	if (!value.HasMember(name))
		throw config_error("field " + field + " is missed");

	const rapidjson::Value &result = value[name];
	if (!(result.*method)())
		throw config_error("field " + field + " is not " + type);

	return result;
}

const rapidjson::Value &json_get_string(const rapidjson::Value &value, const char *name, const std::string &field)
{
	return json_get(value, name, field, &rapidjson::Value::IsString, "string");
}

const rapidjson::Value &json_get_uint(const rapidjson::Value &value, const char *name, const std::string &field)
{
	return json_get(value, name, field, &rapidjson::Value::IsUint, "unsigned integer");
}

const rapidjson::Value &json_get_object(const rapidjson::Value &value, const char *name, const std::string &field)
{
	return json_get(value, name, field, &rapidjson::Value::IsObject, "object");
}

const rapidjson::Value &json_get_array(const rapidjson::Value &value, const char *name, const std::string &field)
{
	return json_get(value, name, field, &rapidjson::Value::IsArray, "array");
}

static void parse_logger(config_data *data, const rapidjson::Value &logger)
{
	const rapidjson::Value &type = json_get_string(logger, "type", "'loggers.type'");
	const rapidjson::Value &level = json_get_uint(logger, "level", "'loggers.level'");

	data->logger_value = std::string(type.GetString(), type.GetStringLength());
	data->logger_impl.log_level = level.GetInt();

	if (data->logger_value == "syslog") {
		openlog("elliptics", 0, LOG_USER);

		data->logger_impl.log_private = NULL;
		data->logger_impl.log = dnet_syslog;
	} else {
		FILE *old = reinterpret_cast<FILE *>(data->logger_impl.log_private);

		FILE *log = fopen(data->logger_value.c_str(), "a");
		if (!log) {
			throw config_error("failed to open log file '" + data->logger_value + "': " + strerror(errno));
			return;
		}

		data->logger_impl.log_private = log;
		data->logger_impl.log = dnet_common_log;

		dnet_common_log(log, -1, "Reopened log file\n");

		if (old) {
			dnet_common_log(old, -1, "Reopened log file\n");
			fclose(old);
		}
	}

	data->cfg_state.log = &data->logger_impl;
}

#if 0
void parse_logger(config_data *data, const rapidjson::Value &logger)
{
	using namespace blackhole;
	const std::vector<log_config_t> &configs = repository::config::parser_t<std::vector<log_config_t>>::parse(logger);

	repository_t<level> &repository = repository_t<level>::instance();
	for (auto it = configs.begin(); it != configs.end(); ++it) {
		repository.add_config(*it);
	}
}
#endif

void parse_options(config_data *data, const rapidjson::Value &options)
{
	const std::map<std::string, config_entry_function> entries = {
		{"mallopt_mmap_threshold", dnet_set_malloc_options},
		{"log_level", dnet_simple_set},
		{"wait_timeout", dnet_simple_set},
		{"check_timeout", dnet_simple_set},
		{"cache_sync_timeout", dnet_simple_set},
		{"stall_count", dnet_simple_set},
		{"group", dnet_set_group},
		{"address", dnet_set_addr},
		{"remote", dnet_set_remote_addrs},
		{"join", dnet_simple_set},
		{"flags", dnet_simple_set},
		{"daemon", dnet_simple_set},
		{"history", dnet_set_history_env},
		{"io_thread_num", dnet_simple_set},
		{"nonblocking_io_thread_num", dnet_simple_set},
		{"net_thread_num", dnet_simple_set},
		{"bg_ionice_class", dnet_simple_set},
		{"bg_ionice_prio", dnet_simple_set},
		{"removal_delay", dnet_simple_set},
		{"auth_cookie", dnet_set_auth_cookie},
		{"server_net_prio", dnet_simple_set},
		{"client_net_prio", dnet_simple_set},
		{"srw_config", dnet_set_srw},
		{"cache_size", dnet_set_cache_size},
		{"caches_number", dnet_set_caches_number},
		{"cache_pages_proportions", dnet_set_cache_pages_proportions},
		{"indexes_shard_count", dnet_simple_set},
		{"monitor_port", dnet_simple_set}
	};

	for (auto it = options.MemberBegin(); it != options.MemberEnd(); ++it) {
		const char *key = it->name.GetString();

		auto jt = entries.find(key);
		if (jt == entries.end()) {
			throw config_error("unknown field 'options." + std::string(key) + "'");
			continue;
		}

		jt->second(data, key, it->value);
	}
}

static std::string get_backend_field(size_t index, const char *name)
{
	return "'backends[" + boost::lexical_cast<std::string>(index) + "]." + name + "'";
}

void parse_backends(config_data *data, const rapidjson::Value &backends)
{
	if (backends.Size() != 1)
		throw config_error("size of field 'backends' must be equal to 1");

	data->backends.resize(backends.Size());

	for (size_t index = 0; index < backends.Size(); ++index) {
		const rapidjson::Value &backend = backends[index];

		const rapidjson::Value &history = json_get_string(backend, "history", get_backend_field(index, "history"));
		const rapidjson::Value &type = json_get_string(backend, "type", get_backend_field(index, "type"));

		dnet_set_history_env(data, "history", history.GetString());

		dnet_config_backend *backends_info[] = {
			dnet_eblob_backend_info(),
			dnet_file_backend_info(),
#ifdef HAVE_MODULE_BACKEND_SUPPORT
			dnet_module_backend_info(),
#endif
		};

		backend_info *info = NULL;

		for (size_t i = 0; i < sizeof(backends_info) / sizeof(backends_info[0]); ++i) {
			dnet_config_backend *current_backend = backends_info[i];
			if (strcmp(current_backend->name, type.GetString()) == 0) {
				info = &data->backends[index];

				info->config = *current_backend;
				info->data.resize(info->config.size, '\0');
				info->config.data = info->data.data();
				info->config.log = data->cfg_state.log;
				break;
			}
		}

		if (!info)
			throw config_error("field " + get_backend_field(index, "type") + ": backend '" + type.GetString() + "' is unknown");

		info->log = data->cfg_state.log;

		std::map<std::string, dnet_config_entry> entries;
		for (int i = 0; i < info->config.num; ++i) {
			entries.emplace(info->config.ent[i].key, info->config.ent[i]);
		}

		for (auto it = backend.MemberBegin(); it != backend.MemberEnd(); ++it) {
			const char *key = it->name.GetString();

			if (strcmp(key, "type") == 0 || strcmp(key, "history") == 0)
				continue;

			auto jt = entries.find(key);
			if (jt == entries.end()) {
				throw config_error("unknown field " + get_backend_field(index, key));
				continue;
			}

			std::string value_str;
			if (it->value.IsUint64())
				value_str = boost::lexical_cast<std::string>(it->value.GetUint64());
			else if (it->value.IsInt64())
				value_str = boost::lexical_cast<std::string>(it->value.GetInt64());
			else if (it->value.IsString())
				value_str.assign(it->value.GetString(), it->value.GetString() + it->value.GetStringLength());
			else
				throw config_error("field " + get_backend_field(index, key) + ", unknown type");

			std::vector<char> name(it->name.GetString(), it->name.GetString() + it->name.GetStringLength());
			name.push_back('\0');
			std::vector<char> value(value_str.begin(), value_str.end());
			value.push_back('\0');

			jt->second.callback(&info->config, name.data(), value.data());
		}
	}

	data->cfg_current_backend = &data->backends.front().config;
	data->cfg_state.cb = &data->cfg_current_backend->cb;
}

extern "C" struct dnet_node *dnet_parse_config(const char *file, int mon)
{
	FILE *f = fopen(file, "r");
	if (!f) {
		int err = -errno;
		fprintf(stderr, "cnf: failed to open config file '%s': %s.\n", file, strerror(-err));
		return NULL;
	}

	rapidjson::FileStream stream(f);
	rapidjson::Document doc;
	doc.ParseStream<0>(stream);

	fclose(f);

	dnet_node *node = NULL;

	config_data *data = static_cast<config_data *>(dnet_config_data_create());

	try {
		if (!data)
			throw std::bad_alloc();

		if (doc.HasParseError())
			throw config_error(doc.GetParseError());

		const rapidjson::Value &loggers = json_get_object(doc, "loggers", "'loggers'");
		const rapidjson::Value &options = json_get_object(doc, "options", "'options'");
		const rapidjson::Value &backends = json_get_array(doc, "backends", "'options'");

		parse_logger(data, loggers);
		parse_options(data, options);
		parse_backends(data, backends);

		if (data->daemon_mode && !mon)
			dnet_background();

		int err = data->cfg_current_backend->init(data->cfg_current_backend, &data->cfg_state);
		if (err) {
			throw config_error("failed to initialize backend: "
				+ std::string(strerror(-err)) + ": "
				+ boost::lexical_cast<std::string>(err));
		}

		if (!data->cfg_addr_num)
			throw config_error("no local address specified, exiting");

		node = dnet_server_node_create(data);
		if (!node)
			throw config_error("failed to create node");

		err = dnet_common_add_remote_addr(node, data->cfg_remotes);
		if (err)
			throw config_error("failed to connect to remotes");
	} catch (std::exception &exc) {
		dnet_backend_log(data->cfg_state.log, DNET_LOG_ERROR, "cnf: failed to read config file '%s': %s.\n", file, exc.what());

		if (node)
			dnet_server_node_destroy(node);

		return NULL;
	}

	return node;

//	FILE *f;
//	int buf_size = 1024 * 1024;
//	char *buf, *ptr, *value, *key;
//	int err, i, len;
//	int line_num = 0;
//	struct dnet_node *n;

//	sigset_t sig;
//	sigfillset(&sig);
//	pthread_sigmask(SIG_BLOCK, &sig, NULL);
//	sigprocmask(SIG_BLOCK, &sig, NULL);

//	dnet_cur_cfg_data = reinterpret_cast<dnet_config_data *>(malloc(sizeof(struct dnet_config_data)));
//	if (!dnet_cur_cfg_data) {
//		err = -ENOMEM;
//		goto err_out_exit;
//	}

//	memset(dnet_cur_cfg_data, 0, sizeof(struct dnet_config_data));
//	dnet_cur_cfg_data->cfg_entries = dnet_cfg_entries;
//	dnet_cur_cfg_data->cfg_size = ARRAY_SIZE(dnet_cfg_entries);

//	f = fopen(file, "r");
//	if (!f) {
//		err = -errno;
//		fprintf(stderr, "cnf: failed to open config file '%s': %s.\n", file, strerror(errno));
//		goto err_out_free_data;
//	}

//	buf = reinterpret_cast<char *>(malloc(buf_size));
//	if (!buf) {
//		err = -ENOMEM;
//		goto err_out_close;
//	}

//	dnet_cur_cfg_data->backend_logger.log_level = DNET_LOG_DEBUG;
//	dnet_cur_cfg_data->backend_logger.log = dnet_common_log;
//	dnet_cur_cfg_data->cfg_state.log = &dnet_cur_cfg_data->backend_logger;
//	dnet_cur_cfg_data->cfg_state.caches_number = DNET_DEFAULT_CACHES_NUMBER;
//	dnet_cur_cfg_data->cfg_state.cache_pages_number = DNET_DEFAULT_CACHE_PAGES_NUMBER;
//	dnet_cur_cfg_data->cfg_state.cache_pages_proportions = (unsigned int*) calloc(DNET_DEFAULT_CACHE_PAGES_NUMBER, sizeof(unsigned int));

//	if (!dnet_cur_cfg_data->cfg_state.cache_pages_proportions) {
//		err = -ENOMEM;
//		goto err_out_free_buf;
//	}

//	for (i = 0; i < DNET_DEFAULT_CACHE_PAGES_NUMBER; ++i) {
//		dnet_cur_cfg_data->cfg_state.cache_pages_proportions[i] = 1;
//	}

//	err = dnet_file_backend_init();
//	if (err)
//		goto err_out_free_proportions;

//#ifdef HAVE_MODULE_BACKEND_SUPPORT
//	err = dnet_module_backend_init();
//#endif
//	if (err)
//		goto err_out_file_exit;

//	err = dnet_eblob_backend_init();
//	if (err)
//		goto err_out_module_exit;

//	while (1) {
//		ptr = fgets(buf, buf_size, f);
//		if (!ptr) {
//			if (feof(f))
//				break;

//			err = -errno;
//			dnet_backend_log(DNET_LOG_ERROR, "cnf: failed to read config file '%s': %s.\n", file, strerror(errno));
//			goto err_out_free;
//		}

//		line_num++;

//		ptr = dnet_skip_line(ptr);
//		if (!ptr)
//			continue;

//		len = strlen(ptr);

//		if (len > 1) {
//			if (ptr[len - 1] == '\r' || ptr[len - 1] == '\n') {
//				ptr[len - 1] = '\0';
//				len--;
//			}
//		}

//		if (len > 2) {
//			if (ptr[len - 2] == '\r' || ptr[len - 2] == '\n') {
//				ptr[len - 2] = '\0';
//				len--;
//			}
//		}

//		key = value = NULL;
//		err = 0;
//		for (i=0; i<len; ++i) {
//			if (isspace(ptr[i])) {
//				if (key)
//					ptr[i] = '\0';
//				continue;
//			}

//			if (!key) {
//				key = ptr + i;
//				continue;
//			}

//			if (!value) {
//				if (ptr[i] == DNET_CONF_DELIMITER) {
//					value = ptr;
//					ptr[i] = '\0';
//					continue;
//				}

//				if (ptr[i] ==  DNET_CONF_COMMENT) {
//					key = value = NULL;
//					break;
//				}

//				continue;
//			} else {
//				value = ptr + i;
//				break;
//			}

//			key = value = NULL;
//			err = -EINVAL;
//			fprintf(stderr, "cnf: error in line %d: %s.\n", line_num, ptr);
//			goto err_out_free;
//		}

//		if (err)
//			goto err_out_free;
//		if (!key || !value)
//			continue;

//		for (i=0; i<dnet_cur_cfg_data->cfg_size; ++i) {
//			if (!strcmp(key, dnet_cur_cfg_data->cfg_entries[i].key)) {
//				err = dnet_cur_cfg_data->cfg_entries[i].callback(dnet_cur_cfg_data->cfg_current_backend, key, value);
//				dnet_backend_log(DNET_LOG_INFO, "backend: %s, key: %s, value: %s, err: %d\n",
//						(dnet_cur_cfg_data->cfg_current_backend) ? dnet_cur_cfg_data->cfg_current_backend->name : "root level",
//						ptr, value, err);
//				if (err)
//					goto err_out_free;

//				break;
//			}
//		}
//	}

//	if (!dnet_cur_cfg_data->cfg_current_backend) {
//		err = -EINVAL;
//		goto err_out_free;
//	}

//	if (dnet_cur_cfg_data->daemon_mode && !mon)
//		dnet_background();

//	err = dnet_cur_cfg_data->cfg_current_backend->init(dnet_cur_cfg_data->cfg_current_backend, &dnet_cur_cfg_data->cfg_state);
//	if (err)
//		goto err_out_free;

//	fclose(f);
//	f = NULL;

//	if (!dnet_cur_cfg_data->cfg_addr_num) {
//		dnet_backend_log(DNET_LOG_ERROR, "No local address specified, exiting.\n");
//		goto err_out_free;
//	}

//	n = dnet_server_node_create(dnet_cur_cfg_data);
//	if (!n) {
//		/* backend cleanup is already called */
//		goto err_out_free;
//	}

//	err = dnet_common_add_remote_addr(n, dnet_cur_cfg_data->cfg_remotes);
//	if (err)
//		goto err_out_node_destroy;

//	free(buf);

//	return n;

//err_out_node_destroy:
//	// dnet_cur_cfg_data will be destroyed by dnet_server_node_destroy
//	dnet_cur_cfg_data = NULL;
//	dnet_server_node_destroy(n);
//err_out_free:
//	if (dnet_cur_cfg_data)
//		free(dnet_cur_cfg_data->cfg_remotes);

////err_out_eblob_exit:
//	dnet_eblob_backend_exit();
//err_out_module_exit:
//#ifdef HAVE_MODULE_BACKEND_SUPPORT
//	dnet_module_backend_exit();
//#endif
//err_out_file_exit:
//	dnet_file_backend_exit();
//err_out_free_proportions:
//	if (dnet_cur_cfg_data)
//		free(dnet_cur_cfg_data->cfg_state.cache_pages_proportions);
//err_out_free_buf:
//	free(buf);
//err_out_close:
//	if (f)
//		fclose(f);
//err_out_free_data:
//	free(dnet_cur_cfg_data);
//err_out_exit:
//	dnet_cur_cfg_data = NULL;
//	return NULL;
}

extern "C" int dnet_backend_check_log_level(dnet_log *l, int level)
{
	return (l->log && ((l->log_level >= level) || (trace_id & DNET_TRACE_BIT)));
}

extern "C" void dnet_backend_log_raw(dnet_log *l, int level, const char *format, ...)
{
	va_list args;
	char buf[1024];
	int buflen = sizeof(buf);

	if (!dnet_backend_check_log_level(l, level))
		return;

	va_start(args, format);
	vsnprintf(buf, buflen, format, args);
	buf[buflen-1] = '\0';
	l->log(l->log_private, level, buf);
	va_end(args);
}

} } } // namespace ioremap::elliptics::config
