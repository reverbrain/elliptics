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
#include <map>

#include <boost/thread/locks.hpp>
#include <boost/thread/shared_mutex.hpp>

#include "rapidjson/document.h"

#include "../library/elliptics.h"

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

	bool has_data() const {
		return successes != 0 || failures != 0;
	}

	base_counter() : successes(0), failures(0) {}
};

struct ext_counter {
	base_counter	counter;
	uint64_t		size;
	uint64_t		time;

	bool has_data() const {
		return size != 0 || time != 0 || counter.has_data();
	}

	ext_counter() : size(0), time(0) {}
};

struct source_counter {
	ext_counter	outside;
	ext_counter	internal;

	bool has_data() const {
		return outside.has_data() || internal.has_data();
	}
};

/*!
 * \internal
 *
 * Counters that connected with each command
 */
struct command_counters {
	source_counter	cache;
	source_counter	disk;

	bool has_data() const {
		return cache.has_data() || disk.has_data();
	}
};

/*!
 * \internal
 *
 * Command (read, write and so on) counters.
 * This structure can be embedded into each backend and also into @statistics class
 * to maintain global command counters.
 *
 */
class command_stats {
public:
	command_stats();

	/*!
	 * Adds executed command properties to different command statistics
	 * \a cmd - identifier of the command
	 * \a trans - number of transaction
	 * \a err - error code
	 * \a cache - flag which shows was the command executed by cache
	 * \a size - size of data that takes a part in command execution
	 * \a time - time spended on command execution
	 */
	void command_counter(const int cmd, const int trans, const int err, const int cache,
	                     const uint64_t size, const unsigned long time);

	/*!
	 * Fills \a a stat_value by commands statistics and returns it
	 * \a allocator - document allocator that is required by rapidjson
	 */
	rapidjson::Value& commands_report(dnet_node *node, rapidjson::Value &stat_value,
	                                  rapidjson::Document::AllocatorType &allocator) const;

private:
	/*!
	 * \internal
	 *
	 * Lock for controlling access to commands statistics
	 */
	mutable std::mutex m_cmd_stats_mutex;

	/*!
	 * \internal
	 *
	 * Commands statistics
	 */
	std::vector<command_counters> m_cmd_stats;
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
	typedef boost::shared_mutex rw_lock;
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
	void command_counter(const int cmd, const int trans, const int err, const int cache,
	                     const uint64_t size, const unsigned long time);

	/*!
	 * \internal
	 *
	 * Adds \a stat statistics provider with \a name to the list of
	 * external statistics provider
	 */
	void add_provider(stat_provider *stat, const std::string &name);
	void remove_provider(const std::string &name);
	std::shared_ptr<stat_provider> get_provider(const std::string &name);
private:
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
	 * Global command statistics counters
	 */
	command_stats m_command_stats;

	/*!
	 * \internal
	 *
	 * Lock for controlling access to \a m_cmd_info_previous
	 */
	std::mutex m_cmd_info_previous_mutex;

	/*!
	 * \internal
	 *
	 * Reference to monitor that created the statistics
	 */
	monitor &m_monitor;

	/*!
	 * \internal
	 *
	 * Lock for controlling access to vector of external statistics provider
	 */
	rw_lock m_provider_lock;

	std::map<std::string, std::shared_ptr<stat_provider>> m_stat_providers;
};

}} /* namespace ioremap::monitor */

#endif /* __DNET_MONITOR_STATISTICS_HPP */
