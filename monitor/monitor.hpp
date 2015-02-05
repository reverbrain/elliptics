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

#ifndef __DNET_MONITOR_MONITOR_HPP
#define __DNET_MONITOR_MONITOR_HPP

#include "../library/elliptics.h"

#include "server.hpp"
#include "statistics.hpp"

struct dnet_node;

namespace ioremap { namespace elliptics { namespace config {
class config;
class config_data;
}}}

namespace ioremap { namespace monitor {

struct monitor_config
{
	unsigned int	monitor_port;
	bool			has_top;
	size_t			top_k;
	size_t			events_size;
	int				period_in_seconds;

	static std::unique_ptr<monitor_config> parse(const ioremap::elliptics::config::config &monitor);
};

class stat_provider;

/*!
 * Main monitoring class which connects different parts of monitoring subsystem
 */
class monitor {
public:

	/*!
	 * Constructor: initializes monitor by \a cfg configuration
	 */
	monitor(struct dnet_node *n, struct dnet_config *cfg);

	/*!
	 * Destructor: deactivates everything, calls stop()
	 */
	~monitor();

	/*!
	 * Stops monitor: stops listening incoming port, frees all providers etc.
	 */
	void stop();

	/*!
	 * Returns \a m_statistics - provides access to monitor statistics collector
	 */
	statistics& get_statistics() { return m_statistics; }

	struct dnet_node *node() { return m_node; }

private:
	struct dnet_node	*m_node;
	server		m_server;
	statistics	m_statistics;
};

void add_provider(struct dnet_node *n, stat_provider *provider, const std::string &name);
void remove_provider(struct dnet_node *n, const std::string &name);

}} /* namespace ioremap::monitor */

#endif /* __DNET_MONITOR_MONITOR_HPP */
