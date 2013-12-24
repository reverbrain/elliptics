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

class monitor {
public:
	monitor(struct dnet_node *n, struct dnet_config *cfg);

	dnet_node *node() { return m_node; }
	void stop();
	statistics& get_statistics() { return m_statistics; }

private:
	dnet_node	*m_node;
	server		m_server;
	statistics	m_statistics;
};

}} /* namespace ioremap::monitor */

#endif /* __DNET_MONITOR_MONITOR_HPP */
