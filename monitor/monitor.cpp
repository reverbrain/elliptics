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

#include "../library/elliptics.h"

namespace ioremap { namespace monitor {

monitor::monitor(struct dnet_node *n, struct dnet_config *cfg)
: m_node(n)
, m_server(*this, cfg->monitor_port)
, m_statistics(*this)
{}

void monitor::stop() {
	m_server.stop();
}

}} /* namespace ioremap::monitor */

int dnet_monitor_init(struct dnet_node *n, struct dnet_config *cfg) {
	if (!cfg->monitor_port) {
		n->monitor = NULL;
		dnet_log(n, DNET_LOG_INFO, "Monitor hasn't been initialized because monitor port is zero\n");
		return 0;
	}

	try {
		n->monitor = static_cast<void*>(new ioremap::monitor::monitor(n, cfg));
	} catch (const std::exception &e) {
		dnet_log(n, DNET_LOG_ERROR, "Could not create monitor: %s\n", e.what());
		return -ENOMEM;
	}

	return 0;
}

static ioremap::monitor::monitor* monitor_cast(void* monitor) {
	return static_cast<ioremap::monitor::monitor*>(monitor);
}

void dnet_monitor_exit(struct dnet_node *n) {
	auto real_monitor = monitor_cast(n->monitor);
	if (real_monitor) {
		delete real_monitor;
		n->monitor = NULL;
	}
}

void dnet_monitor_add_provider(void* monitor, struct stat_provider_raw stat, const char *name) {
	auto real_monitor = monitor_cast(monitor);
	if (real_monitor) {
		auto provider = new ioremap::monitor::raw_provider(stat);
		real_monitor->get_statistics().add_provider(provider, std::string(name));
	}
}

void dnet_monitor_log(void *monitor) {
	auto real_monitor = monitor_cast(monitor);
	if (real_monitor) {
		real_monitor->get_statistics().log();
	}
}

void monitor_command_counter(void *monitor, const int cmd, const int trans,
                             const int err, const int cache,
                             const uint32_t size, const unsigned long time) {
	auto real_monitor = monitor_cast(monitor);
	if (real_monitor) {
		real_monitor->get_statistics().command_counter(cmd, trans, err, cache, size, time);
	}
}
