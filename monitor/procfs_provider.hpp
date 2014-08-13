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

#ifndef __DNET_MONITOR_PROCFS_PROVIDER_HPP
#define __DNET_MONITOR_PROCFS_PROVIDER_HPP

#include "statistics.hpp"

namespace ioremap { namespace monitor {

/*!
 * Provider statistics gethered from procfs
 */
class procfs_provider : public stat_provider {
public:
	procfs_provider(struct dnet_node *node);

	virtual std::string json(uint64_t categories) const;

private:
	struct dnet_node *m_node;
};

}} /* namespace ioremap::monitor */

#endif /* __DNET_MONITOR_PROCFS_PROVIDER_HPP */
