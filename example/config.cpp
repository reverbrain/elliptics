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


#include "config.hpp"

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
#include "../cache/cache.hpp"

#include <boost/lexical_cast.hpp>

#include <type_traits>

#define BLACKHOLE_HEADER_ONLY
#include <blackhole/repository.hpp>
#include <blackhole/repository/config/parser/rapidjson.hpp>
#include <blackhole/frontend/syslog.hpp>
#include <blackhole/frontend/files.hpp>
#include <blackhole/sink/socket.hpp>
//#include <blackhole/formatter/json.hpp>

#include "common.h"

#ifndef __unused
#define __unused	__attribute__ ((unused))
#endif

namespace ioremap { namespace elliptics { namespace config {

extern "C" dnet_config_data *dnet_config_data_create()
{
	config_data *data = new config_data;

	memset(static_cast<dnet_config_data *>(data), 0, sizeof(dnet_config_data));

	data->backends = &data->backends_guard;
	data->destroy_config_data = dnet_config_data_destroy;

	return data;
}

extern "C" void dnet_config_data_destroy(dnet_config_data *public_data)
{
	config_data *data = static_cast<config_data *>(public_data);

	free(data->cfg_addrs);

	delete data;
}

extern "C" int dnet_node_reset_log(struct dnet_node *n __unused)
{
	return 0;
}

static void parse_logger(config_data *data, const config &logger)
{
	using namespace blackhole;

	// Available logging sinks.
	typedef boost::mpl::vector<
	    blackhole::sink::files_t<
	        blackhole::sink::files::boost_backend_t,
	        blackhole::sink::rotator_t<
	            blackhole::sink::files::boost_backend_t,
	            blackhole::sink::rotation::watcher::move_t
	        >
	    >,
	    blackhole::sink::syslog_t<dnet_log_level>,
	    blackhole::sink::socket_t<boost::asio::ip::tcp>,
	    blackhole::sink::socket_t<boost::asio::ip::udp>
	> sinks_t;

	// Available logging formatters.
	typedef boost::mpl::vector<
	    blackhole::formatter::string_t
//	    blackhole::formatter::json_t
	> formatters_t;

	auto &repository = blackhole::repository_t::instance();
	repository.configure<sinks_t, formatters_t>();

	config frontends = logger.at("frontends");
	frontends.assert_array();

	const dynamic_t &dynamic = frontends.raw();
	log_config_t log_config = repository::config::parser_t<log_config_t>::parse("root", dynamic);

	const auto mapper = file_logger::mapping();
	for(auto it = log_config.frontends.begin(); it != log_config.frontends.end(); ++it) {
		it->formatter.mapper = mapper;
	}

	repository.add_config(log_config);

	data->logger_base = repository.root<dnet_log_level>();
	data->logger_base.add_attribute(keyword::request_id() = 0);

	const config &level_config = logger.at("level");
	const std::string &level = level_config.as<std::string>();
	try {
		data->logger_base.verbosity(file_logger::parse_level(level));
	} catch (error &exc) {
		throw config_error() << level_config.path() << " " << exc.what();
	}

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
				throw config_error() << *it << ": could not resolve address: " << strerror(-err)
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
	data->cfg_state.io_thread_num = options.at<unsigned>("io_thread_num");
	data->cfg_state.nonblocking_io_thread_num = options.at<unsigned>("nonblocking_io_thread_num");
	data->cfg_state.net_thread_num = options.at<unsigned>("net_thread_num");
	data->cfg_state.bg_ionice_class = options.at("bg_ionice_class", 0);
	data->cfg_state.bg_ionice_prio = options.at("bg_ionice_prio", 0);
	data->cfg_state.removal_delay = options.at("removal_delay", 0);
	data->cfg_state.server_prio = options.at("server_net_prio", 0);
	data->cfg_state.client_prio = options.at("client_net_prio", 0);
	data->cfg_state.indexes_shard_count = options.at("indexes_shard_count", 0);
	data->daemon_mode = options.at("daemon", false);
	data->parallel_start = options.at("parallel", true);
	snprintf(data->cfg_state.cookie, DNET_AUTH_COOKIE_SIZE, "%s", options.at<std::string>("auth_cookie").c_str());

	if (options.has("srw_config")) {
		data->cfg_state.srw.config = strdup(options.at<std::string>("srw_config").c_str());
		if (!data->cfg_state.srw.config)
			throw std::bad_alloc();
	}

	dnet_set_addr(data, options.at("address", std::vector<std::string>()));

	const std::vector<std::string> remotes = options.at("remote", std::vector<std::string>());
	for (auto it = remotes.begin(); it != remotes.end(); ++it) {
		data->remotes.emplace_back(*it);
	}

	if (options.has("monitor")) {
		const config monitor = options.at("monitor");
		data->monitor_config = ioremap::monitor::monitor_config::parse(monitor);
	}

	if (options.has("handystats_config")) {
		data->cfg_state.handystats_config = strdup(options.at<std::string>("handystats_config").c_str());
		if (!data->cfg_state.handystats_config)
			throw std::bad_alloc();
	}

	if (options.has("cache")) {
		const config cache = options.at("cache");
		data->cache_config = ioremap::cache::cache_config::parse(cache);
	}
}

void parse_backends(config_data *data, const config &backends)
{
	std::set<uint32_t> backends_ids;
	auto &backends_info = data->backends->backends;

	for (size_t index = 0; index < backends.size(); ++index) {
		const config backend = backends.at(index);
		const uint32_t backend_id = backend.at<uint32_t>("backend_id");

		// Check if this is first backend with such backend_id
		if (!backends_ids.insert(backend_id).second) {
			throw ioremap::elliptics::config::config_error()
				<< backend.at("backend_id").path()
				<< " duplicates one of previous backend_id";
		}

		while (backend_id + 1 > backends_info.size())
			backends_info.emplace_back(data->logger, backends_info.size());

		dnet_backend_info &info = backends_info[backend_id];
		info.enable_at_start = backend.at<bool>("enable", true);
		info.state = DNET_BACKEND_DISABLED;
		info.history = backend.at("history", std::string());

		if (info.enable_at_start) {
			// It's parsed to check configuration at start
			// It will be reparsed again at backend's initialization anyway
			info.parse(data, backend);
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

		data->config_path = file;

		auto parser = data->parse_config();
		const config root = parser->root();
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

		static_assert(sizeof(dnet_addr) == sizeof(address), "Size of dnet_addr and size of address must be equal");
		if (data->remotes.size() != 0) {
			int err = dnet_add_state(node, reinterpret_cast<const dnet_addr *>(data->remotes.data()), data->remotes.size(), 0);
			if (err < 0)
				BH_LOG(*node->log, DNET_LOG_WARNING, "Failed to connect to remote nodes: %d", err);
		}

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
