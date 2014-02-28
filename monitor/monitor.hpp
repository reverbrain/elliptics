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

namespace ioremap { namespace monitor {

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
	 * Returns \a m_node - provides access to node that was used in monitor creation
	 */
	dnet_node *node() { return m_node; }

	/*!
	 * Stops monitor: stops listening incoming port, frees all providers etc.
	 */
	void stop();

	/*!
	 * Returns \a m_statistics - provides access to monitor statistics collector
	 */
	statistics& get_statistics() { return m_statistics; }

private:
	dnet_node	*m_node;
	server		m_server;
	statistics	m_statistics;
};

void dnet_monitor_add_provider(struct dnet_node *n, stat_provider *provider, const char *name);

}} /* namespace ioremap::monitor */

#endif /* __DNET_MONITOR_MONITOR_HPP */
