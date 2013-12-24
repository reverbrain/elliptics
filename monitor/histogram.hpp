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

#ifndef __DNET_MONITOR_HISTOGRAM_HPP
#define __DNET_MONITOR_HISTOGRAM_HPP

#include <vector>
#include <list>
#include <string>

#include "rapidjson/document.h"

namespace ioremap { namespace monitor {

class histogram {
public:
	histogram(const std::vector<std::pair<uint64_t, std::string>> &xs,
	          const std::vector<std::pair<uint64_t, std::string>> &ys);

	void update(uint64_t x, uint64_t y);

	rapidjson::Value& report(rapidjson::Value &stat_value,
	                         rapidjson::Document::AllocatorType &allocator);
	void clear_last();

	struct data {
		data(size_t size);
		std::vector<uint_fast64_t>	counters;
		struct timeval				timestamp;
	};

private:
	rapidjson::Value& print_data(rapidjson::Value &stat_value,
	                             rapidjson::Document::AllocatorType &allocator,
	                             histogram::data &data);
	size_t get_indx(uint64_t x, uint64_t y);

	std::vector<std::pair<uint64_t, std::string>>	m_xs;
	std::vector<std::pair<uint64_t, std::string>>	m_ys;
	std::list<data>									m_snapshots;
	data											m_last_data;
};

std::vector<std::pair<uint64_t, std::string>> default_xs();
std::vector<std::pair<uint64_t, std::string>> default_ys();
}} /* namespace ioremap::monitor */

#endif /* __DNET_MONITOR_HISTOGRAM_HPP */
