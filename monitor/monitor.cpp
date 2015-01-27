/*
 * Copyright 2013+ Kirill Smorodinnikov <shaitkir@gmail.com>
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
 * You should have received a copy of the GNU General Public License
 * along with Elliptics.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "monitor.h"
#include "monitor.hpp"
#include "compress.hpp"

#include <exception>

#include "library/elliptics.h"
#include "io_stat_provider.hpp"
#include "backends_stat_provider.hpp"
#include "procfs_provider.hpp"
#include "top_provider.hpp"

#include "../example/config.hpp"

static ioremap::monitor::monitor* get_monitor(struct dnet_node *n) {
	return n->monitor ? static_cast<ioremap::monitor::monitor*>(n->monitor) : NULL;
}

#ifdef HAVE_HANDYSTATS
#include <handystats/core.hpp>
#endif

namespace ioremap { namespace monitor {

std::unique_ptr<monitor_config> monitor_config::parse(const elliptics::config::config &monitor)
{
	monitor_config config;
	config.top_k = monitor.at<size_t>("top_k", DNET_DEFAULT_MONITOR_TOP_K);
	config.events_limit = monitor.at<size_t>("events_limit", DNET_DEFAULT_MONITOR_TOP_EVENTS_LIMIT);
	config.period_in_seconds = monitor.at<int>("period_in_seconds", DNET_DEFAULT_MONITOR_TOP_PERIOD);
	return blackhole::utils::make_unique<monitor_config>(config);
}

monitor::monitor(struct dnet_node *n, struct dnet_config *cfg)
: m_node(n)
, m_server(*this, cfg->monitor_port, cfg->family)
, m_statistics(*this, cfg)
{
#if defined(HAVE_HANDYSTATS) && !defined(HANDYSTATS_DISABLE)
	if (cfg->handystats_config != nullptr) {
		//TODO: add parse/configuration errors logging when handystats will allow to get them
		if (HANDY_CONFIG_FILE(cfg->handystats_config)) {
			BH_LOG(*cfg->log, DNET_LOG_INFO, "monitor: initializing stats subsystem, config file '%s'", cfg->handystats_config);
		} else {
			BH_LOG(*cfg->log, DNET_LOG_ERROR, "monitor: initializing stats subsystem, error parsing config file '%s', using defaults", cfg->handystats_config);
		}
	} else {
		BH_LOG(*cfg->log, DNET_LOG_INFO, "monitor: initializing stats subsystem, no config file specified, using defaults");
	}
	HANDY_INIT();
#else
	BH_LOG(*cfg->log, DNET_LOG_INFO, "monitor: stats subsystem disabled at compile time");
#endif
}

monitor::~monitor()
{
	//TODO: is node still alive here? If so, add shutdown log messages
	// for both monitoring and handystats
	stop();
#if defined(HAVE_HANDYSTATS) && !defined(HANDYSTATS_DISABLE)
	HANDY_FINALIZE();
#endif
}

void monitor::stop() {
	m_server.stop();
}

void add_provider(struct dnet_node *n, stat_provider *provider, const std::string &name) {
	auto real_monitor = get_monitor(n);
	if (real_monitor)
		real_monitor->get_statistics().add_provider(provider, name);
	else
		delete provider;
}

void remove_provider(dnet_node *n, const std::string &name)
{
	auto real_monitor = get_monitor(n);
	if (real_monitor)
		real_monitor->get_statistics().remove_provider(name);
}

static void init_io_stat_provider(struct dnet_node *n, struct dnet_config *cfg) {
	try {
		add_provider(n, new io_stat_provider(n), "io");
	} catch (std::exception &e) {
		BH_LOG(*cfg->log, DNET_LOG_ERROR, "monitor: failed to initialize io_stat_provider: %s.", e.what());
	}
}

static void init_backends_stat_provider(struct dnet_node *n, struct dnet_config *cfg) {
	try {
		add_provider(n, new backends_stat_provider(n), "backends");
	} catch (std::exception &e) {
		BH_LOG(*cfg->log, DNET_LOG_ERROR, "monitor: failed to initialize backends_stat_provider: %s.", e.what());
	}
}

static void init_procfs_provider(struct dnet_node *n, struct dnet_config *cfg) {
	try {
		add_provider(n, new procfs_provider(n), "procfs");
	} catch (std::exception &e) {
		BH_LOG(*cfg->log, DNET_LOG_ERROR, "monitor: failed to initialize procfs_stat_provider: %s.", e.what());
	}
}

static void init_top_provider(struct dnet_node *n, struct dnet_config *cfg) {
	try {
		using namespace ioremap::elliptics::config;
		const auto &data = *static_cast<const config_data *>(n->config_data);
		const auto &monitor = data.monitor_config;
		if (!monitor)
			return;

		add_provider(n, new top_provider(n, monitor->top_k, monitor->events_limit, monitor->period_in_seconds), "top");
	} catch (const std::exception &e) {
		BH_LOG(*cfg->log, DNET_LOG_ERROR, "monitor: failed to initialize top_stat_provider: %s.", e.what());
	}
}

}} /* namespace ioremap::monitor */

int dnet_monitor_init(struct dnet_node *n, struct dnet_config *cfg) {
	if (!cfg->monitor_port || !cfg->family) {
		n->monitor = NULL;
		BH_LOG(*cfg->log, DNET_LOG_ERROR, "monitor: monitor hasn't been initialized because monitor port is zero.");
		return 0;
	}

	try {
		n->monitor = static_cast<void*>(new ioremap::monitor::monitor(n, cfg));
	} catch (const std::exception &e) {
		BH_LOG(*cfg->log, DNET_LOG_ERROR, "monitor: failed to initialize monitor on port: %d: %s.", cfg->monitor_port, e.what());
		return -ENOMEM;
	}

	ioremap::monitor::init_io_stat_provider(n, cfg);
	ioremap::monitor::init_backends_stat_provider(n, cfg);
	ioremap::monitor::init_procfs_provider(n, cfg);
	ioremap::monitor::init_top_provider(n, cfg);

	return 0;
}

void dnet_monitor_exit(struct dnet_node *n) {
	auto real_monitor = get_monitor(n);
	if (real_monitor) {
		n->monitor = NULL;
		delete real_monitor;
	}
}

void dnet_monitor_add_provider(struct dnet_node *n, struct stat_provider_raw stat, const char *name) {
	try {
		auto provider = new ioremap::monitor::raw_provider(stat);
		ioremap::monitor::add_provider(n, provider, std::string(name));
	} catch (std::exception &e) {
		std::cerr << e.what() << std::endl;
	}
}

void dnet_monitor_remove_provider(struct dnet_node *n, const char *name) {
	ioremap::monitor::remove_provider(n, std::string(name));
}

void monitor_command_counter(struct dnet_node *n, const int cmd, const int trans,
                             const int err, const int cache,
                             const uint32_t size, const unsigned long time) {
	auto real_monitor = get_monitor(n);
	if (real_monitor)
		real_monitor->get_statistics().command_counter(cmd, trans, err,
		                                               cache, size, time);
}

int dnet_monitor_process_cmd(struct dnet_net_state *orig, struct dnet_cmd *cmd __unused, void *data)
{
	if (cmd->size != sizeof(dnet_monitor_stat_request)) {
		dnet_log(orig->n, DNET_LOG_DEBUG, "monitor: %s: %s: process MONITOR_STAT, invalid size: %llu",
			dnet_state_dump_addr(orig), dnet_dump_id(&cmd->id), static_cast<unsigned long long>(cmd->size));
		return -EINVAL;
	}

	struct dnet_node *n = orig->n;
	struct dnet_monitor_stat_request *req = static_cast<struct dnet_monitor_stat_request *>(data);
	dnet_convert_monitor_stat_request(req);
	static const std::string disabled_reply = ioremap::monitor::compress("{\"monitor_status\":\"disabled\"}");

	dnet_log(orig->n, DNET_LOG_DEBUG, "monitor: %s: %s: process MONITOR_STAT, categories: %lx, monitor: %p",
		dnet_state_dump_addr(orig), dnet_dump_id(&cmd->id), req->categories, n->monitor);

	auto real_monitor = get_monitor(n);
	if (!real_monitor)
		return dnet_send_reply(orig, cmd, disabled_reply.c_str(), disabled_reply.size(), 0);

	try {
		auto json = real_monitor->get_statistics().report(req->categories);
		return dnet_send_reply(orig, cmd, &*json.begin(), json.size(), 0);
	} catch(std::exception &e) {
		const std::string rep = ioremap::monitor::compress("{\"monitor_status\":\"failed: " + std::string(e.what()) + "\"}");
		dnet_log(orig->n, DNET_LOG_DEBUG, "monitor: failed to generate json: %s", e.what());
		return dnet_send_reply(orig, cmd, &*rep.begin(), rep.size(), 0);
	}
}
