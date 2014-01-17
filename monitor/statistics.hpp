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

class stat_provider {
public:
	virtual std::string json() const = 0;
	virtual bool check_category(int category) const = 0;
	virtual ~stat_provider() {}
};

class raw_provider : public stat_provider {
public:
	raw_provider(stat_provider_raw stat)
	: m_stat(stat)
	{}

	virtual ~raw_provider() {
		m_stat.stop(m_stat.stat_private);
	}

	virtual std::string json() const {
		return std::string(m_stat.json(m_stat.stat_private));
	}

	virtual bool check_category(int category) const {
		return m_stat.check_category(m_stat.stat_private, category);
	}

private:
	stat_provider_raw	m_stat;
};

struct command_counters {
	uint_fast64_t	cache_successes;
	uint_fast64_t	cache_failures;
	uint_fast64_t	cache_internal_successes;
	uint_fast64_t	cache_internal_failures;
	uint_fast64_t	disk_successes;
	uint_fast64_t	disk_failures;
	uint_fast64_t	disk_internal_successes;
	uint_fast64_t	disk_internal_failures;

	uint_fast64_t	cache_size;
	uint_fast64_t	cache_internal_size;
	uint_fast64_t	disk_size;
	uint_fast64_t	disk_internal_size;
	uint_fast64_t	cache_time;
	uint_fast64_t	disk_time;
	uint_fast64_t	cache_internal_time;
	uint_fast64_t	disk_internal_time;
};

struct command_stat_info {
	int				cmd;
	size_t			size;
	unsigned long	time;
	bool			internal;
	bool			cache;
};

struct command_histograms {
	command_histograms(const std::vector<std::pair<uint64_t, std::string>> &xs,
	                   const std::vector<std::pair<uint64_t, std::string>> &ys)
	: cache(xs, ys)
	, disk(xs, ys)
	, cache_internal(xs, ys)
	, disk_internal(xs, ys)
	{}

	histogram	cache;
	histogram	disk;
	histogram	cache_internal;
	histogram	disk_internal;
};

class statistics {
public:
	statistics(monitor& mon);
	std::string report(int category);
	void log();
	void command_counter(int cmd, const int trans, const int err, const int cache,
	                     const uint32_t size, const unsigned long time);
	void add_provider(stat_provider *stat, const std::string &name);
private:
	rapidjson::Value& io_queue_report(rapidjson::Value &stat_value, rapidjson::Document::AllocatorType &allocator);
	rapidjson::Value& commands_report(rapidjson::Value &stat_value, rapidjson::Document::AllocatorType &allocator);
	rapidjson::Value& history_report(rapidjson::Value &stat_value, rapidjson::Document::AllocatorType &allocator);
	rapidjson::Value& histogram_report(rapidjson::Value &stat_value, rapidjson::Document::AllocatorType &allocator);

	mutable std::mutex				m_cmd_info_mutex;
	boost::array<command_counters, __DNET_CMD_MAX> m_cmd_stats;

	struct timeval					m_start_time;

	std::vector<command_stat_info>	m_cmd_info_current;
	mutable std::mutex				m_cmd_info_previous_mutex;
	std::vector<command_stat_info>	m_cmd_info_previous;

	monitor							&m_monitor;

	mutable std::mutex				m_histograms_mutex;
	command_histograms				m_read_histograms;
	command_histograms				m_write_histograms;
	command_histograms				m_indx_update_histograms;
	command_histograms				m_indx_internal_histograms;

	mutable std::mutex							m_provider_mutex;
	std::vector<std::pair<std::unique_ptr<stat_provider>, std::string>>	m_stat_providers;
};

}} /* namespace ioremap::monitor */

#endif /* __DNET_MONITOR_STATISTICS_HPP */
