/*
 * Copyright 2015+ Budnik Andrey <budnik27@gmail.com>
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

#include "top_stats.hpp"
#include "monitor.hpp"

namespace ioremap { namespace monitor {

top_stats::top_stats(size_t top_length, size_t events_size, int period_in_seconds)
: m_stats(events_size, period_in_seconds),
 m_top_length(top_length)
{}

void top_stats::update_stats(const struct dnet_cmd *cmd, uint64_t size)
{
	if (size > 0 && cmd->cmd == DNET_CMD_READ) {
		key_stat_event event(cmd->id, size, 1., time(nullptr));
		m_stats.add_event(event, event.get_time());
	}
}

}} /* namespace ioremap::monitor */

