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

#include <exception>

#include "library/elliptics.h"
#include "io_stat_provider.hpp"
#include "react_stat_provider.hpp"

namespace ioremap { namespace monitor {

monitor::monitor(struct dnet_node *n, struct dnet_config *cfg)
: m_node(n)
, m_server(*this, cfg->monitor_port)
, m_statistics(*this)
{}

void monitor::stop() {
	m_server.stop();
}

void add_provider(struct dnet_node *n, stat_provider *provider, const std::string &name) {
	if (!n->monitor) {
		delete provider;
		return;
	}

	auto real_monitor = static_cast<monitor*>(n->monitor);
	if (real_monitor)
		real_monitor->get_statistics().add_provider(provider, name);
	else
		delete provider;
}

void remove_provider(dnet_node *n, const std::string &name)
{
	if (!n->monitor) {
		return;
	}

	auto real_monitor = static_cast<monitor*>(n->monitor);
	if (real_monitor)
		real_monitor->get_statistics().remove_provider(name);
}

}} /* namespace ioremap::monitor */

int dnet_monitor_init(struct dnet_node *n, struct dnet_config *cfg) {
	if (!cfg->monitor_port || !cfg->family) {
		n->monitor = NULL;
		dnet_log_raw_log_only(cfg->log, DNET_LOG_DATA, "monitor: monitor hasn't been initialized because monitor port is zero.");
		return 0;
	}

	try {
		n->monitor = static_cast<void*>(new ioremap::monitor::monitor(n, cfg));
	} catch (const std::exception &e) {
		dnet_log_raw_log_only(cfg->log, DNET_LOG_ERROR, "monitor: failed to initialize monitor on port: %d: %s.", cfg->monitor_port, e.what());
		return -ENOMEM;
	}

	return 0;
}

static ioremap::monitor::monitor* monitor_cast(void* monitor) {
	return static_cast<ioremap::monitor::monitor*>(monitor);
}

void dnet_monitor_exit(struct dnet_node *n) {
	if (!n->monitor)
		return;

	auto monitor = n->monitor;
	n->monitor = NULL;

	auto real_monitor = monitor_cast(monitor);
	if (real_monitor) {
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
	if (!n->monitor)
		return;

	auto real_monitor = monitor_cast(n->monitor);
	if (real_monitor)
		real_monitor->get_statistics().command_counter(cmd, trans, err,
		                                               cache, size, time);
}

void dnet_monitor_init_io_stat_provider(struct dnet_node *n) {
	if (!n->monitor)
		return;

	auto real_monitor = monitor_cast(n->monitor);
	if (real_monitor) {
		try {
			real_monitor->get_statistics().add_provider(new ioremap::monitor::io_stat_provider(n), "io");
		} catch (std::exception &e) {
			std::cerr << e.what() << std::endl;
		}
	}
}

void dnet_monitor_init_react_stat_provider(struct dnet_node *n) {
	if (!n->monitor)
		return;

	auto real_monitor = monitor_cast(n->monitor);
	if (real_monitor) {
		try {
			auto provider = new ioremap::monitor::react_stat_provider();
			real_monitor->get_statistics().add_provider(provider, "call_tree");
			n->react_aggregator = static_cast<void*> (&provider->get_react_aggregator());
		} catch (std::exception &e) {
			std::cerr << e.what() << std::endl;
		}
	}
}

int dnet_monitor_process_cmd(struct dnet_net_state *orig, struct dnet_cmd *cmd __unused, void *data)
{
	react::action_guard monitor_process_cmd_guard(ACTION_DNET_MONITOR_PROCESS_CMD);

	if (cmd->size != sizeof(dnet_monitor_stat_request)) {
		dnet_log(orig->n, DNET_LOG_DEBUG, "monitor: %s: %s: process MONITOR_STAT, invalid size: %llu",
			dnet_state_dump_addr(orig), dnet_dump_id(&cmd->id), static_cast<unsigned long long>(cmd->size));
		return -EINVAL;
	}

	struct dnet_node *n = orig->n;
	struct dnet_monitor_stat_request *req = static_cast<struct dnet_monitor_stat_request *>(data);
	dnet_convert_monitor_stat_request(req);
	static const std::string disabled_reply = "{\"monitor_status\":\"disabled\"}";

	dnet_log(orig->n, DNET_LOG_DEBUG, "monitor: %s: %s: process MONITOR_STAT, categories: %lx, monitor: %p",
		dnet_state_dump_addr(orig), dnet_dump_id(&cmd->id), req->categories, n->monitor);

	if (!n->monitor)
		return dnet_send_reply(orig, cmd, disabled_reply.c_str(), disabled_reply.size(), 0);

	auto real_monitor = monitor_cast(n->monitor);
	if (!real_monitor)
		return dnet_send_reply(orig, cmd, disabled_reply.c_str(), disabled_reply.size(), 0);

	auto json = real_monitor->get_statistics().report(req->categories);
	return dnet_send_reply(orig, cmd, &*json.begin(), json.size(), 0);
}
