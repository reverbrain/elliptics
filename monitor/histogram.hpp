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

/*!
 * \internal
 *
 * Implementation of 2D histogram
 */
class histogram {
public:
	/*!
	 * \internal
	 *
	 * Constructor: initializes histogram, sets absciss's tags as \a xs,
	 * ordinate's tags as ys and number of histogram snapshots in \a history_depth
	 */
	histogram(const std::vector<std::pair<uint64_t, std::string>> &xs,
	          const std::vector<std::pair<uint64_t, std::string>> &ys,
	          size_t history_depth = 5);

	/*!
	 * \internal
	 *
	 * Increased by 1 cell counter located at \a x, \a y
	 */
	void update(uint64_t x, uint64_t y);

	/*!
	 * \internal
	 *
	 * Fills and returns \a stat_value by histogram statistics
	 * \a allocator - document allocator that is required by rapidjson
	 */
	rapidjson::Value& report(rapidjson::Value &stat_value,
	                         rapidjson::Document::AllocatorType &allocator);

	/*!
	 * \internal
	 *
	 * Data of one histogram snapshot
	 */
	struct data {
		data(size_t size, const struct timeval *time = NULL);
		/*!
		 * \internal
		 *
		 * Snapshot's counters
		 */
		std::vector<uint_fast64_t>	counters;
		/*!
		 * \internal
		 *
		 * Timestamp of snapshot creation
		 */
		struct timeval				timestamp;
	};

private:

	/*!
	 * \internal
	 *
	 * Fills and returns \a stat_value by snapshot \a data statistics
	 * \a allocator - document allocator that is required by rapidjson
	 */
	rapidjson::Value& print_data(rapidjson::Value &stat_value,
	                             rapidjson::Document::AllocatorType &allocator,
	                             histogram::data &data);

	/*!
	 * \internal
	 *
	 * Computes and returns index of counters from \a x, \a y
	 */
	size_t get_indx(uint64_t x, uint64_t y);

	/*!
	 * \internal
	 *
	 * Clears last snapshot
	 */
	void clear_last();

	/*!
	 * \internal
	 *
	 * Validates last snapshot timestamp if it is needed adds new snapshot
	 */
	void validate_snapshots();

	/*!
	 * \internal
	 *
	 * Absciss's tags
	 */
	std::vector<std::pair<uint64_t, std::string>>	m_xs;
	/*!
	 * \internal
	 *
	 * Ordinate's tags
	 */
	std::vector<std::pair<uint64_t, std::string>>	m_ys;
	/*!
	 * \internal
	 *
	 * Snapshots
	 */
	std::list<data>									m_snapshots;
	/*!
	 * \internal
	 *
	 * Last snapshot which is filled now
	 */
	data											m_last_data;
	/*!
	 * \internal
	 *
	 * Number of histogram snapshots
	 */
	size_t											m_history_depth;
};

/*!
 * \internal
 *
 * Creates default absciss's tags.
 */
std::vector<std::pair<uint64_t, std::string>> default_xs();
/*!
 * \internal
 *
 * Creates default ordinate's tags.
 */
std::vector<std::pair<uint64_t, std::string>> default_ys();
}} /* namespace ioremap::monitor */

#endif /* __DNET_MONITOR_HISTOGRAM_HPP */
