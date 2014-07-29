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
#include <fstream>

#include "elliptics/packet.h"
#include "elliptics/interface.h"
#include "elliptics/backends.h"
#include "elliptics/error.hpp"
#include "elliptics/session.hpp"

#include "../library/elliptics.h"
#include "../monitor/monitor.h"

#include <boost/lexical_cast.hpp>

#include <type_traits>

#include <rapidjson/document.h>
#include <rapidjson/filestream.h>

#define BLACKHOLE_HEADER_ONLY
#include <blackhole/repository.hpp>
#include <blackhole/repository/config/parser/rapidjson.hpp>
#include <blackhole/frontend/syslog.hpp>
#include <blackhole/frontend/files.hpp>

#include "common.h"

#ifndef __unused
#define __unused	__attribute__ ((unused))
#endif

extern __thread trace_id_t trace_id;

// To be able to properly map user-defined severity enumeration to the syslog's one
// we should implement special mapping trait that is called by library each time when
// mapping is required.
namespace blackhole {

namespace sink {

template<>
struct priority_traits<dnet_log_level> {
	static priority_t map(dnet_log_level lvl) {
		switch (lvl) {
		case DNET_LOG_ERROR:
			return priority_t::err;
		case DNET_LOG_INFO:
			return priority_t::info;
		default:
			break;
		}

		return priority_t::debug;
	}
};

} // namespace sink

} // namespace blackhole

namespace ioremap { namespace elliptics { namespace config {

class config_error : public std::exception
{
public:
	explicit config_error()
	{
	}

	config_error(const config_error &other) :
		m_message(other.m_message)
	{
		m_stream << m_message;
	}

	config_error &operator =(const config_error &other)
	{
		m_message = other.m_message;
		m_stream << m_message;
		return *this;
	}

	explicit config_error(const std::string &message)
	{
		m_stream << message;
		m_message = message;
	}

	const char *what() const ELLIPTICS_NOEXCEPT
	{
		return m_message.c_str();
	}

	template <typename T>
	config_error &operator <<(const T &value)
	{
		m_stream << value;
		m_message = m_stream.str();
		return *this;
	}

	config_error &operator <<(std::ostream &(*handler)(std::ostream &))
	{
		m_stream << handler;
		m_message = m_stream.str();
		return *this;
	}

	virtual ~config_error() throw()
	{}

private:
	std::stringstream m_stream;
	std::string m_message;
};

struct config_data : public dnet_config_data
{
	config_data() : logger(logger_base, blackhole::log::attributes_t())
	{
	}

	dnet_backend_info_list backends_guard;
	std::string logger_value;
	ioremap::elliptics::logger_base logger_base;
	ioremap::elliptics::logger logger;
};

extern "C" dnet_config_data *dnet_config_data_create()
{
	config_data *data = new config_data;

	memset(static_cast<dnet_config_data *>(data), 0, sizeof(dnet_config_data));

	data->backends = &data->backends_guard;
	data->destroy_config_data = dnet_config_data_destroy;

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

namespace detail
{

enum {
	boolean_type = 1,
	integral_type = 2,
	floating_point_type = 4,
	string_type = 8,
	vector_type = 16
};

template <typename T, int specific>
struct config_value_caster_specific_helper;

template <typename T>
struct is_vector : public std::false_type { };

template <typename T>
struct is_vector<std::vector<T>> : public std::true_type { };


template <typename T>
struct config_value_caster_helper
{
	enum {
		boolean = std::is_same<T, bool>::value ? boolean_type : 0,
		integral = std::is_integral<T>::value && !boolean ? integral_type : 0,
		floating_point = std::is_floating_point<T>::value ? floating_point_type : 0,
		string = std::is_same<T, std::string>::value ? string_type : 0,
		vector = is_vector<T>::value ? vector_type : 0,
		type = integral | floating_point | string | boolean | vector
	};

	static_assert(integral || floating_point || string || boolean || vector, "Unsupported type");
	static_assert((type == integral) || (type == floating_point) || (type == string) || (type == boolean) || (type == vector), "Internal type check error");

	static T cast(const std::string &path, const rapidjson::Value &value)
	{
		return config_value_caster_specific_helper<T, type>::cast(path, value);
	}
};

template <typename T>
struct config_value_caster : public config_value_caster_helper<typename std::remove_all_extents<T>::type>
{
};

template <typename T>
struct config_value_caster_specific_helper<T, boolean_type>
{
	static T cast(const std::string &path, const rapidjson::Value &value)
	{
		if (!value.IsBool())
			throw config_error() << path << " must be a bool";

		return value.GetBool();
	}
};

template <typename T>
struct config_value_caster_specific_helper<T, integral_type>
{
	static T cast(const std::string &path, const rapidjson::Value &value)
	{
		if (value.IsInt64()) {
			const auto tmp = value.GetInt64();
			assert_limits(path, tmp);
			return tmp;
		} else if (value.IsUint64()) {
			const auto tmp = value.GetUint64();
			assert_limits(path, tmp);
			return tmp;
		} else {
			throw_limits_error(path);
			return T();
		}
	}

	template <typename Y>
	static void assert_limits(const std::string &path, Y value)
	{
		if (value > std::numeric_limits<T>::max() || value < std::numeric_limits<T>::min())
			throw_limits_error(path);
	}

	static void throw_limits_error(const std::string &path)
	{
		throw config_error() << path << " must be an integer between "
			<< std::numeric_limits<T>::min() << " and " << std::numeric_limits<T>::max();
	}
};

template <typename T>
struct config_value_caster_specific_helper<T, floating_point_type>
{
	static T cast(const std::string &path, const rapidjson::Value &value)
	{
		if (!value.IsDouble())
			throw config_error() << path << " must be a floating point number";

		return value.GetDouble();
	}
};

template <typename T>
struct config_value_caster_specific_helper<T, string_type>
{
	static T cast(const std::string &path, const rapidjson::Value &value)
	{
		if (!value.IsString())
			throw config_error() << path << " must be a string";

		return T(value.GetString(), value.GetStringLength());
	}
};

template <typename T>
struct config_value_caster_specific_helper<T, vector_type>
{
	static T cast(const std::string &path, const rapidjson::Value &value)
	{
		typedef config_value_caster<typename T::value_type> caster;

		if (!value.IsArray())
			throw config_error() << path << " must be an array";

		T result;
		for (size_t i = 0; i < value.Size(); ++i)
			result.emplace_back(caster::cast(path + "[" + boost::lexical_cast<std::string>(i) + "]", value[i]));
		return result;
	}
};

}

class config
{
public:
	config(const std::string &path, const rapidjson::Value *value) :
		m_path(path), m_value(value)
	{
	}

	bool has(const std::string &name) const
	{
		assert_object();
		const rapidjson::Value &result = (*m_value)[name.c_str()];
		return !result.IsNull();
	}

	config at(const std::string &name) const
	{
		assert_object();
		const rapidjson::Value &result = (*m_value)[name.c_str()];
		std::string path = m_path + "." + name;

		if (result.IsNull())
			throw config_error() << path << " is missed";

		return config(path, &result);
	}

	template <typename T>
	T at(const std::string &name, const T &default_value) const
	{
		if (!has(name))
			return default_value;

		return at(name).as<T>();
	}

	template <typename T>
	T at(const std::string &name) const
	{
		return at(name).as<T>();
	}

	size_t size() const
	{
		assert_array();
		return m_value->Size();
	}

	bool has(size_t index) const
	{
		assert_array();
		const rapidjson::Value &result = (*m_value)[index];
		return !result.IsNull();
	}

	config at(size_t index) const
	{
		assert_array();
		const rapidjson::Value &result = (*m_value)[index];
		std::string path = m_path + "[" + boost::lexical_cast<std::string>(index) + "]";

		if (result.IsNull())
			throw config_error() << path << " is missed";

		return config(path, &result);
	}

	template <typename T>
	T at(size_t index, const T &default_value) const
	{
		if (!has(index))
			return default_value;

		return at(index).as<T>();
	}

	template <typename T>
	T at(size_t index) const
	{
		return at(index).as<T>();
	}

	template <typename T>
	T as() const
	{
		assert_valid();
		return detail::config_value_caster<T>::cast(m_path, *m_value);
	}

	const std::string &path() const
	{
		return m_path;
	}

	std::string to_string() const
	{
		assert_valid();

		std::string value_str;

		if (m_value->IsUint64())
			value_str = boost::lexical_cast<std::string>(m_value->GetUint64());
		else if (m_value->IsInt64())
			value_str = boost::lexical_cast<std::string>(m_value->GetInt64());
		else if (m_value->IsDouble())
			value_str = boost::lexical_cast<std::string>(m_value->GetDouble());
		else if (m_value->IsString())
			value_str.assign(m_value->GetString(), m_value->GetString() + m_value->GetStringLength());
		else
			throw config_error() << m_path << " has unknown type";

		return value_str;
	}

	void assert_valid() const
	{
		if (!m_value || m_value->IsNull())
			throw config_error() << m_path << " is missed";
	}

	void assert_array() const
	{
		assert_valid();
		if (!m_value->IsArray())
			throw config_error() << m_path << " must be an array";
	}

	void assert_object() const
	{
		assert_valid();
		if (!m_value->IsObject())
			throw config_error() << m_path << " must be an object";
	}

	const rapidjson::Value *raw() const
	{
		return m_value;
	}

protected:
	std::string m_path;
	const rapidjson::Value *m_value;
};

class config_parser
{
public:
	config_parser()
	{
	}

	void open(const std::string &path)
	{
		FILE *f = fopen(path.c_str(), "r");
		if (!f) {
			int err = -errno;
			throw config_error() << "failed to open config file'" << path << "': " << strerror(-err);
		}

		rapidjson::FileStream stream(f);
		m_doc.ParseStream<0>(stream);

		fclose(f);

		if (m_doc.HasParseError()) {
			std::ifstream in(path.c_str());
			if (in) {
				size_t offset = m_doc.GetErrorOffset();
				std::vector<char> buffer(offset);
				in.read(buffer.data(), offset);

				std::string data(buffer.begin(), buffer.end());
				std::string line;

				if (std::getline(in, line))
					data += line;

				/*
				 * Produce a pretty output about the error
				 * including the line and certain place where
				 * the error occured.
				 */

				size_t line_offset = data.find_last_of('\n');
				if (line_offset == std::string::npos)
					line_offset = 0;

				for (size_t i = line_offset; i < data.size(); ++i) {
					if (data[i] == '\t') {
						data.replace(i, 1, std::string(4, ' '));

						if (offset > i)
							offset += 3;
					}
				}

				const size_t line_number = std::count(data.begin(), data.end(), '\n') + 1;
				const size_t dash_count = line_offset < offset ? offset - line_offset - 1 : 0;

				throw config_error()
					<< "parser error at line " << line_number << ": " << m_doc.GetParseError() << std::endl
					<< data.substr(line_offset + 1) << std::endl
					<< std::string(dash_count, ' ') << '^' << std::endl
					<< std::string(dash_count, '~') << '+' << std::endl;
			}

			throw config_error() << "parser error: at unknown line: " << m_doc.GetParseError();
		}

		if (!m_doc.IsObject())
			throw config_error() << "root must be an object";
	}

	config root()
	{
		return config("path", &m_doc);
	}

private:
	rapidjson::Document m_doc;
};

extern "C" int dnet_node_reset_log(struct dnet_node *n __unused)
{
	return 0;
}

static void parse_logger(config_data *data, const config &logger)
{
	using namespace blackhole;

	repository_t::instance().configure<
		sink::syslog_t<dnet_log_level>,
		formatter::string_t
	>();
	repository_t::instance().configure<
		sink::files_t<
			sink::files::boost_backend_t,
			sink::rotator_t<
				sink::files::boost_backend_t,
				sink::rotation::watcher::size_t
			>
		>,
		formatter::string_t
	>();
	repository_t::instance().configure<
		sink::files_t<>,
		formatter::string_t
	>();

	config frontends = logger.at("frontends");
	frontends.assert_array();

	const dynamic_t &dynamic = repository::config::transformer_t<rapidjson::Value>::transform(*frontends.raw());
	const log_config_t &log_config = repository::config::parser_t<log_config_t>::parse("root", dynamic);
	repository_t::instance().add_config(log_config);

	data->logger_base = repository_t::instance().root<dnet_log_level>();
	data->logger_base.verbosity(dnet_log_level(logger.at<int>("level")));
	data->logger_base.add_attribute(blackhole::keyword::request_id() = 0);

	data->cfg_state.log = &data->logger;
}

struct dnet_addr_wrap {
	struct dnet_addr	addr;
	int			addr_group;
};

static bool dnet_addr_wrap_less_than(const dnet_addr_wrap &w1, const dnet_addr_wrap &w2)
{
	return w1.addr_group < w2.addr_group;
}

static void dnet_set_addr(config_data *data, const std::vector<std::string> &addresses)
{
	if (addresses.empty())
		return;

	std::vector<dnet_addr_wrap> wraps;

	for (auto it = addresses.begin(); it != addresses.end(); ++it) {
		try {
			std::string address = *it;
			int group = -1;

			size_t delim_index = address.find_first_of(DNET_CONF_ADDR_DELIM);
			if (delim_index == std::string::npos)
				throw config_error() << "port and address delimiter is missed";

			size_t group_index = address.find_first_of('-', delim_index);

			if (group_index != std::string::npos) {
				std::string group_str = address.substr(group_index + 1);
				try {
					group = boost::lexical_cast<int>(group_str);
				} catch (std::exception &exc) {
					throw config_error() << "address group parse error: " << exc.what();
				}

				address.resize(group_index);
			}

			std::vector<char> address_copy(address.begin(), address.end());
			address_copy.push_back('\0');

			int port;
			int family;
			int err = dnet_parse_addr(address_copy.data(), &port, &family);

			if (err) {
				throw config_error() << *it << ": failed to parse address: " << strerror(-err)
					<< ", " << boost::lexical_cast<std::string>(err);
			}

			data->cfg_state.port = port;
			data->cfg_state.family = family;

			dnet_addr_wrap wrap;
			memset(&wrap, 0, sizeof(wrap));

			wrap.addr.addr_len = sizeof(wrap.addr.addr);
			wrap.addr.family = data->cfg_state.family;
			wrap.addr_group = group;
			err = dnet_fill_addr(&wrap.addr, address_copy.data(), port, SOCK_STREAM, IPPROTO_TCP);

			if (err) {
				throw config_error() << *it << ": failed to parse address: " << strerror(-err)
					<< ", " << boost::lexical_cast<std::string>(err);
			}

			wraps.push_back(wrap);
		} catch (std::exception &exc) {
			throw config_error() << "'options.address[" << std::distance(addresses.begin(), it)
				<< "]', " << exc.what();
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
}

static void dnet_set_remote_addrs(config_data *data, const std::vector<std::string> &remotes)
{
	if (remotes.empty())
		return;

	std::string tmp;
	for (size_t i = 0; i < remotes.size(); ++i) {
		tmp.append(remotes[i]);
		tmp.append(1, ' ');
	}

	if (tmp.size() > 0)
		tmp.resize(tmp.size() - 1);

	data->cfg_remotes = strdup(tmp.c_str());
	if (!data->cfg_remotes)
		throw std::bad_alloc();
}

static int dnet_set_malloc_options(config_data *data, unsigned long long value)
{
	int err, thr = value;

	err = mallopt(M_MMAP_THRESHOLD, thr);
	if (err < 0) {
		dnet_backend_log(data->cfg_state.log, DNET_LOG_ERROR, "Failed to set mmap threshold to %d: %s", thr, strerror(errno));
		return err;
	}

	dnet_backend_log(data->cfg_state.log, DNET_LOG_INFO, "Set mmap threshold to %d.", thr);
	return 0;
}

static void dnet_set_cache_pages_proportions(config_data *data, const std::vector<unsigned> &values)
{
	if (values.empty())
		return;

	free(data->cfg_state.cache_pages_proportions);
	data->cfg_state.cache_pages_number = 0;

	data->cfg_state.cache_pages_proportions = reinterpret_cast<unsigned *>(malloc(values.size() * sizeof(unsigned)));
	if (!data->cfg_state.cache_pages_proportions)
		throw std::bad_alloc();

	memcpy(data->cfg_state.cache_pages_proportions, values.data(), values.size() * sizeof(unsigned));

	data->cfg_state.cache_pages_number = values.size();
}

void parse_options(config_data *data, const config &options)
{
	if (options.has("mallopt_mmap_threshold")) {
		dnet_set_malloc_options(data, options.at<int>("mallopt_mmap_threshold"));
	}

	data->cfg_state.wait_timeout = options.at("wait_timeout", 0u);
	data->cfg_state.check_timeout = options.at("check_timeout", 0l);
	data->cfg_state.stall_count = options.at("stall_count", 0l);
	data->cfg_state.flags |= (options.at("join", false) ? DNET_CFG_JOIN_NETWORK : 0);
	data->cfg_state.flags |= (options.at("flags", 0) & ~DNET_CFG_JOIN_NETWORK);
	data->cfg_state.io_thread_num = options.at("io_thread_num", 0);
	data->cfg_state.nonblocking_io_thread_num = options.at("nonblocking_io_thread_num", 0);
	data->cfg_state.net_thread_num = options.at("net_thread_num", 0);
	data->cfg_state.bg_ionice_class = options.at("bg_ionice_class", 0);
	data->cfg_state.bg_ionice_prio = options.at("bg_ionice_prio", 0);
	data->cfg_state.removal_delay = options.at("removal_delay", 0);
	data->cfg_state.server_prio = options.at("server_net_prio", 0);
	data->cfg_state.client_prio = options.at("client_net_prio", 0);
	data->cfg_state.indexes_shard_count = options.at("indexes_shard_count", 0);
	data->cfg_state.monitor_port = options.at("monitor_port", 0);
	data->daemon_mode = options.at("daemon", false);
	snprintf(data->cfg_state.cookie, DNET_AUTH_COOKIE_SIZE, "%s", options.at<std::string>("auth_cookie").c_str());

	if (options.has("srw_config")) {
		data->cfg_state.srw.config = strdup(options.at<std::string>("srw_config").c_str());
		if (!data->cfg_state.srw.config)
			throw std::bad_alloc();
	}

	dnet_set_addr(data, options.at("address", std::vector<std::string>()));
	dnet_set_remote_addrs(data, options.at("remote", std::vector<std::string>()));

	if (options.has("cache")) {
		const config cache = options.at("cache");
		data->cfg_state.cache_size = cache.at("size", 0ull);
		data->cfg_state.cache_sync_timeout = cache.at("sync_timeout", 0);
		data->cfg_state.caches_number = cache.at("shards", data->cfg_state.caches_number);
		dnet_set_cache_pages_proportions(data, cache.at("pages_proportions", std::vector<unsigned>()));
	}
}

void parse_backends(config_data *data, const config &backends)
{
	data->backends->backends.resize(backends.size());

	for (size_t index = 0; index < backends.size(); ++index) {
		const config backend = backends.at(index);
		std::string type = backend.at<std::string>("type");

		dnet_config_backend *backends_info[] = {
			dnet_eblob_backend_info(),
			dnet_file_backend_info(),
#ifdef HAVE_MODULE_BACKEND_SUPPORT
			dnet_module_backend_info(),
#endif
		};

		dnet_backend_info *info = NULL;

		for (size_t i = 0; i < sizeof(backends_info) / sizeof(backends_info[0]); ++i) {
			dnet_config_backend *current_backend = backends_info[i];
			if (type == current_backend->name) {
				info = &data->backends->backends[index];

				info->config_template = *current_backend;
				info->config = *current_backend;
				info->data.resize(info->config.size, '\0');
				info->log = data->cfg_state.log;
				break;
			}
		}

		if (!info)
			throw config_error() << backend.at("type").path() << " is unknown backend";

		info->group = backend.at<int>("group");
		info->history = backend.at<std::string>("history");
		info->enable_at_start = backend.at<bool>("enable", true);
		info->cache = NULL;

		for (int i = 0; i < info->config.num; ++i) {
			dnet_config_entry &entry = info->config.ent[i];
			if (backend.has(entry.key)) {
				std::string key_str = entry.key;
				std::vector<char> key(key_str.begin(), key_str.end());
				key.push_back('\0');

				std::string value_str = backend.at(entry.key).to_string();
				std::vector<char> value(value_str.begin(), value_str.end());
				value.push_back('\0');

				dnet_backend_config_entry option = {
					&entry,
					value,
					value
				};

				info->options.emplace_back(std::move(option));
			}
		}
	}
}

extern "C" struct dnet_node *dnet_parse_config(const char *file, int mon)
{
	dnet_node *node = NULL;
	config_data *data = NULL;

	try {
		data = static_cast<config_data *>(dnet_config_data_create());
		if (!data)
			throw std::bad_alloc();

		config_parser parser;
		parser.open(file);

		const config root = parser.root();
		const config logger = root.at("logger");
		const config options = root.at("options");
		const config backends = root.at("backends");

		parse_logger(data, logger);
		parse_options(data, options);
		parse_backends(data, backends);

		if (data->daemon_mode && !mon)
			dnet_background();

		if (!data->cfg_addr_num)
			throw config_error("no local address specified, exiting");

		node = dnet_server_node_create(data);
		if (!node)
			throw config_error("failed to create node");

		int err = dnet_common_add_remote_addr(node, data->cfg_remotes);
		if (err)
			throw config_error("failed to connect to remotes");

	} catch (std::exception &exc) {
		if (data && data->cfg_state.log) {
			dnet_backend_log(data->cfg_state.log, DNET_LOG_ERROR,
				"cnf: failed to read config file '%s': %s", file, exc.what());
		} else {
			fprintf(stderr, "cnf: %s\n", exc.what());
			fflush(stderr);
		}

		if (node)
			dnet_server_node_destroy(node);
		else if (data)
			dnet_config_data_destroy(data);

		return NULL;
	}

	return node;
}

extern "C" int dnet_backend_check_log_level(dnet_logger *l, int level)
{
	return dnet_log_enabled(l, dnet_log_level(level));
}

extern "C" void dnet_backend_log_raw(dnet_logger *l, int level, const char *format, ...)
{
	va_list args;

	va_start(args, format);
	DNET_LOG_BEGIN_ONLY_LOG(l, dnet_log_level(level));
	DNET_LOG_VPRINT(format, args);
	DNET_LOG_END();
	va_end(args);
}

} } } // namespace ioremap::elliptics::config
