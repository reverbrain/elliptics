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

#include <atomic>
#include <sstream>
#include <thread>

#include <boost/array.hpp>

#include "../library/elliptics.h"

namespace ioremap { namespace monitor {

class monitor;

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

struct hist_counter {
	uint_fast64_t	cache;
	uint_fast64_t	cache_internal;
	uint_fast64_t	disk;
	uint_fast64_t	disk_internal;
};

struct command_stat_info;

struct histograms {
	histograms() {
		clear();
	}
	void clear() {
		memset(read_counters.c_array(), 0, sizeof(hist_counter) * read_counters.size());
		memset(write_counters.c_array(), 0, sizeof(hist_counter) * write_counters.size());
		memset(indx_update_counters.c_array(), 0, sizeof(hist_counter) * indx_update_counters.size());
		memset(indx_internal_counters.c_array(), 0, sizeof(hist_counter) * indx_internal_counters.size());
	}
	boost::array<hist_counter, 16>	read_counters;
	boost::array<hist_counter, 16>	write_counters;
	boost::array<hist_counter, 16>	indx_update_counters;
	boost::array<hist_counter, 16>	indx_internal_counters;
	struct timeval					start;

	int get_indx(const uint32_t size, const unsigned long time) {
		uint32_t sz_ind = 0;
		uint32_t tm_ind = 0;
		if (size > 10000)
			sz_ind = 3;
		else if (size > 1000)
			sz_ind = 2;
		else if (size > 500)
			sz_ind = 1;

		if (time > 1000000)
			tm_ind = 3;
		else if (time > 100000)
			tm_ind = 2;
		else if (time > 5000)
			tm_ind = 1;

		return 4 * sz_ind + tm_ind;
	}

	void command_counter(int cmd, const int trans, const int cache,
	                     const uint32_t size, const unsigned long time) {
		boost::array<hist_counter, 16> *counters = NULL;
		switch(cmd) {
			case DNET_CMD_READ:				counters = &read_counters;			break;
			case DNET_CMD_WRITE:			counters = &write_counters;			break;
			case DNET_CMD_INDEXES_UPDATE:	counters = &indx_update_counters;	break;
			case DNET_CMD_INDEXES_INTERNAL:	counters = &indx_internal_counters;	break;
		}

		if (counters == NULL)
			return;

		hist_counter &counter = (*counters)[get_indx(size, time)];

		if (cache) {
			if (trans) {
				++counter.cache;
			} else {
				++counter.cache_internal;
			}
		} else {
			if (trans) {
				++counter.disk;
			} else {
				++counter.disk_internal;
			}
		}
	}
};

class statistics {
public:
	statistics(monitor& mon);
	std::string report();
	void cache_stat(std::ostringstream &stream);
	void log();
	void command_counter(int cmd, const int trans, const int err, const int cache,
	                     const uint32_t size, const unsigned long time);
	void io_queue_stat(const uint64_t current_size,
	                   const uint64_t min_size, const uint64_t max_size,
	                   const uint64_t volume, const uint64_t time);
private:
	int cmd_index(int cmd, const int err);
	void stat_report(std::ostringstream &stream);
	void print(std::ostringstream &stream, const command_stat_info &info, bool comma);
	void cmd_report(std::ostringstream &stream);
	histograms prepare_fivesec_histogram();
	void print_hist(std::ostringstream &stream, const boost::array<hist_counter, 16> &hist, const char *name);
	void hist_report(std::ostringstream &stream);

	std::atomic_uint_fast64_t	m_io_queue_size;
	std::atomic_uint_fast64_t	m_io_queue_volume;
	std::atomic_uint_fast64_t	m_io_queue_max;
	std::atomic_uint_fast64_t	m_io_queue_min;
	std::atomic_uint_fast64_t	m_io_queue_time;

	mutable std::mutex				m_cmd_info_mutex;
	boost::array<command_counters, __DNET_CMD_MAX> m_cmd_stats;

	struct timeval					m_start_time;

	std::vector<command_stat_info>	m_cmd_info_current;
	mutable std::mutex				m_cmd_info_previous_mutex;
	std::vector<command_stat_info>	m_cmd_info_previous;

	mutable std::mutex				m_histograms_mutex;
	std::vector<histograms>			m_histograms;
	std::vector<histograms>			m_histograms_previous;
	histograms						m_last_histograms;
	monitor							&m_monitor;
};

}} /* namespace ioremap::monitor */

#endif /* __DNET_MONITOR_STATISTICS_HPP */