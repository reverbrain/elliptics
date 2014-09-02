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

#ifndef __DNET_MONITOR_STATISTICS_HPP
#define __DNET_MONITOR_STATISTICS_HPP

#if __GNUC__ == 4 && __GNUC_MINOR__ < 5
#  include <cstdatomic>
#else
#  include <atomic>
#endif
#include <mutex>
#include <sstream>
#include <thread>

#include <boost/array.hpp>

#include "rapidjson/document.h"

#include "../library/elliptics.h"

#include "histogram.hpp"
#include "monitor.h"

namespace ioremap { namespace monitor {

class monitor;

/*!
 * \internal
 *
 * Interface of statistics provider
 * Subsystems which wants to have their own statistics should create provider
 * and add it to statistics via add_provider method
 */
class stat_provider {
public:

	/*!
	 * \internal
	 *
	 * Returns json string of the real provider statistics
	 * \a categories - categories which statistics should be included to json
	 */
	virtual std::string json(uint64_t categories) const = 0;

	/*!
	 * \internal
	 *
	 * Destructor
	 */
	virtual ~stat_provider() {}
};

/*!
 * \internal
 *
 * Raw provide which wraps C provider for using in statistics
 */
class raw_provider : public stat_provider {
public:

	/*!
	 * \internal
	 *
	 * Constructor: initializes provider by C provider \a stat
	 */
	raw_provider(stat_provider_raw stat)
	: m_stat(stat)
	{}

	/*!
	 * \internal
	 *
	 * Destructor: calls stopping C provider
	 */
	virtual ~raw_provider() {
		m_stat.stop(m_stat.stat_private);
	}

	/*!
	 * \internal
	 *
	 * Returns json string of the real provider statistics
	 * \a categories - categories which statistics should be included to json
	 */
	virtual std::string json(uint64_t categories) const {
		auto json = m_stat.json(m_stat.stat_private, categories);
		return json ? json : std::string();
	}

private:
	stat_provider_raw	m_stat;
};

struct base_counter {
	uint64_t successes;
	uint64_t failures;
};

struct ext_counter {
	base_counter	counter;
	uint64_t		size;
	uint64_t		time;
};

struct source_counter {
	ext_counter	outside;
	ext_counter	internal;
};

/*!
 * \internal
 *
 * Counters that connected with each command
 */
struct command_counters {
	source_counter	cache;
	source_counter	disk;
};

/*!
 * \internal
 *
 * Commands histograms which consists of 4 histograms (size vs time)
 * for \a cache, \a disk, \a cache_internal and \a disk_internal
 */
struct command_histograms {
	command_histograms(const std::vector<std::pair<uint64_t, std::string>> &xs,
	                   const std::vector<std::pair<uint64_t, std::string>> &ys)
	: cache(xs, ys)
	, cache_internal(xs, ys)
	, disk(xs, ys)
	, disk_internal(xs, ys)
	{}

	/*!
	 * \internal
	 *
	 * Hisogram size vs time of commands executed in cache
	 */
	histogram	cache;
	/*!
	 * \internal
	 *
	 * Hisogram size vs time of commands executed in cache
	 * which wasn't genereted by client
	 */
	histogram	cache_internal;
	/*!
	 * \internal
	 *
	 * Hisogram size vs time of commands executed in disk
	 */
	histogram	disk;
	/*!
	 * \internal
	 *
	 * Hisogram size vs time of commands executed in disk
	 * which wasn't genereted by client
	 */
	histogram	disk_internal;
};

/*!
 * \internal
 *
 * Main statistics class which corresponding for:
 *     collecting basic statistics
 *     interviewing external statistics provider
 *     generating final statistics report in json format
 */
class statistics {
public:
	/*!
	 * \internal
	 *
	 * Constructor: initializes statistics by \a mon
	 */
	statistics(monitor& mon, struct dnet_config *cfg);

	/*!
	 * \internal
	 *
	 * Generates and returns json statistics for specified \a category
	 * For that statistics will interview all external statistics provider
	 * which supports \a categories
	 */
	std::string report(uint64_t categories);

	/*!
	 * \internal
	 *
	 * Adds executed command properties to different command statistics
	 * \a cmd - identifier of the command
	 * \a trans - number of transaction
	 * \a err - error code
	 * \a cache - flag which shows was the command executed by cache
	 * \a size - size of data that takes a part in command execution
	 * \a time - time spended on command execution
	 */
	void command_counter(int cmd, const int trans, const int err, const int cache,
	                     const uint32_t size, const unsigned long time);

	/*!
	 * \internal
	 *
	 * Adds \a stat statistics provider with \a name to the list of
	 * external statistics provider
	 */
	void add_provider(stat_provider *stat, const std::string &name);
	void remove_provider(const std::string &name);
private:
	/*!
	 * \internal
	 *
	 * Fills \a a stat_value by commands statistics and returns it
	 * \a allocator - document allocator that is required by rapidjson
	 */
	rapidjson::Value& commands_report(rapidjson::Value &stat_value,
	                                  rapidjson::Document::AllocatorType &allocator);

	/*!
	 * \internal
	 *
	 * Fills \a stat_value by commands histograms statistics and returns it
	 * \a allocator - document allocator that is required by rapidjson
	 */
	rapidjson::Value& histogram_report(rapidjson::Value &stat_value,
	                                   rapidjson::Document::AllocatorType &allocator);

	/*!
	 * \internal
	 * Fills \a stat_value by usefull vm statistics and returns it
	 * \a allocator - document allocator that is required by rapidjson
	 */
	rapidjson::Value& vm_report(rapidjson::Value &stat_value,
	                            rapidjson::Document::AllocatorType &allocator);

	rapidjson::Value& proc_io_report(rapidjson::Value &stat_value,
	                                 rapidjson::Document::AllocatorType &allocator);

	rapidjson::Value& proc_stat(rapidjson::Value &stat_value,
	                            rapidjson::Document::AllocatorType &allocator);

	/*!
	 * \internal
	 *
	 * Lock for controlling access to commands statistics
	 */
	mutable std::mutex				m_cmd_stats_mutex;
	/*!
	 * \internal
	 *
	 * Commands statistics
	 */
	boost::array<command_counters, __DNET_CMD_MAX> m_cmd_stats;

	/*!
	 * \internal
	 *
	 * Lock for controlling access to \a m_cmd_info_previous
	 */
	mutable std::mutex				m_cmd_info_previous_mutex;

	/*!
	 * \internal
	 *
	 * Reference to monitor that created the statistics
	 */
	monitor							&m_monitor;

	/*!
	 * \internal
	 *
	 * Lock for controlling access to histograms
	 */
	mutable std::mutex				m_histograms_mutex;
	/*!
	 * \internal
	 *
	 * Histograms for read command
	 */
	command_histograms				m_read_histograms;
	/*!
	 * \internal
	 *
	 * Histograms for write command
	 */
	command_histograms				m_write_histograms;
	/*!
	 * \internal
	 *
	 * Histograms for index update command
	 */
	command_histograms				m_indx_update_histograms;
	/*!
	 * \internal
	 *
	 * Histograms for index update internal command
	 */
	command_histograms				m_indx_internal_histograms;

	/*!
	 * \internal
	 *
	 * Lock for controlling access to vector of external statistics provider
	 */
	mutable std::mutex				m_provider_mutex;
	std::vector<std::pair<std::unique_ptr<stat_provider>, std::string>>	m_stat_providers;
};

}} /* namespace ioremap::monitor */

#endif /* __DNET_MONITOR_STATISTICS_HPP */
