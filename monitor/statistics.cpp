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

#include "statistics.hpp"

#include <libunwind.h>
#include <libunwind-ptrace.h>

#include "monitor.hpp"
#include "../cache/cache.hpp"

#include "rapidjson/writer.h"
#include "rapidjson/stringbuffer.h"

namespace ioremap { namespace monitor {
statistics::statistics(monitor& mon)
: m_monitor(mon) {
	memset(m_cmd_stats.c_array(), 0, sizeof(command_counters) * m_cmd_stats.size());
	gettimeofday(&m_start_time, NULL);
}

void statistics::command_counter(int cmd, const int trans, const int err, const int cache,
                     const uint32_t size, const unsigned long time) {
	if (cmd >= __DNET_CMD_MAX || cmd <= 0)
		cmd = DNET_CMD_UNKNOWN;

	std::unique_lock<std::mutex> guard(m_cmd_info_mutex);
	if (cache) {
		if (trans) {
			if(!err)
				m_cmd_stats[cmd].cache_successes++;
			else
				m_cmd_stats[cmd].cache_failures++;
			m_cmd_stats[cmd].cache_size += size;
			m_cmd_stats[cmd].cache_time += time;
		} else {
			if(!err)
				m_cmd_stats[cmd].cache_internal_successes++;
			else
				m_cmd_stats[cmd].cache_internal_failures++;
			m_cmd_stats[cmd].cache_internal_size += size;
			m_cmd_stats[cmd].cache_internal_time += time;
		}
	} else {
		if (trans) {
			if(!err)
				m_cmd_stats[cmd].disk_successes++;
			else
				m_cmd_stats[cmd].disk_failures++;
			m_cmd_stats[cmd].disk_size += size;
			m_cmd_stats[cmd].disk_time += time;
		} else {
			if(!err)
				m_cmd_stats[cmd].disk_internal_successes++;
			else
				m_cmd_stats[cmd].disk_internal_failures++;
			m_cmd_stats[cmd].disk_internal_size += size;
			m_cmd_stats[cmd].disk_internal_time += time;
		}
	}

	m_cmd_info_current.emplace_back(command_stat_info{cmd, size, time, trans == 0, cache != 0});

	if (m_cmd_info_current.size() >= 50000) {
		std::unique_lock<std::mutex> swap_guard(m_cmd_info_previous_mutex);
		m_cmd_info_previous.clear();
		m_cmd_info_current.swap(m_cmd_info_previous);
	}

	struct timeval current;
	gettimeofday(&current, NULL);

	histograms *hist = NULL;

	std::unique_lock<std::mutex> hist_guard(m_histograms_mutex);
	if (m_histograms.empty()) {
		m_histograms.emplace_back(histograms());
		hist = &m_histograms.back();
	} else {
		if (current.tv_sec - m_histograms.back().start.tv_sec < 1) {
			hist = &m_histograms.back();
		} else {
			if (m_histograms.size() == 5) {
				m_histograms_previous.clear();
				m_histograms_previous.swap(m_histograms);
			}
			m_histograms.emplace_back(histograms());
			hist = &m_histograms.back();
		}
	}

	hist->command_counter(cmd, trans, cache, size, time);
	m_last_histograms.command_counter(cmd, trans, cache, size, time);
}

void statistics::io_queue_stat(const uint64_t current_size,
                   const uint64_t min_size, const uint64_t max_size,
                   const uint64_t volume, const uint64_t time) {
	m_io_queue_size = current_size;
	m_io_queue_volume = volume;
	m_io_queue_max = max_size;
	m_io_queue_min = min_size;
	m_io_queue_time = time;
}

int statistics::cmd_index(int cmd, const int err) {
	if (cmd >= __DNET_CMD_MAX || cmd <= 0)
		cmd = DNET_CMD_UNKNOWN;

	cmd = cmd * 2 + (err ? 1 : 0);
	return cmd;
}

inline std::string convert_report(const rapidjson::Document &report) {
	rapidjson::StringBuffer buffer;
	rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
	report.Accept(writer);
	return buffer.GetString();
}

std::string statistics::report() {
	rapidjson::Document report;
	report.SetObject();
	auto &allocator = report.GetAllocator();

	struct timeval end_time;
	gettimeofday(&end_time, NULL);
	auto time = (end_time.tv_sec - m_start_time.tv_sec) * 1000000 +
	                      (end_time.tv_usec - m_start_time.tv_usec);
	m_start_time = end_time;
	report.AddMember("time", time, allocator);

	rapidjson::Value cache_value(rapidjson::kObjectType);
	report.AddMember("cache_stat", cache_stat(cache_value, allocator), allocator);
	rapidjson::Value commands_value(rapidjson::kObjectType);
	report.AddMember("commands_stat", commands_stat(commands_value, allocator), allocator);
	rapidjson::Value history_value(rapidjson::kArrayType);
	report.AddMember("history_stat", history_report(history_value, allocator), allocator);
	rapidjson::Value histogram_value(rapidjson::kObjectType);
	report.AddMember("histogram", histogram_report(histogram_value, allocator), allocator);

	return convert_report(report);
}

rapidjson::Value& statistics::cache_stat(rapidjson::Value &stat_value, rapidjson::Document::AllocatorType &allocator) {
	if (!m_monitor.node()->cache)
		return stat_value;

	auto cache = static_cast<ioremap::cache::cache_manager*>(m_monitor.node()->cache);
	auto stat = cache->get_total_cache_stats();

	stat_value.AddMember("size", stat.size_of_objects, allocator)
	          .AddMember("removing size", stat.size_of_objects_marked_for_deletion, allocator)
	          .AddMember("objects", stat.number_of_objects, allocator)
	          .AddMember("removing objects", stat.number_of_objects_marked_for_deletion, allocator);

	rapidjson::Value pages_sizes(rapidjson::kArrayType);
	for (auto it = stat.pages_sizes.begin(), end = stat.pages_sizes.end(); it != end; ++it) {
		pages_sizes.PushBack(*it, allocator);
	}
	stat_value.AddMember("pages sizes", pages_sizes, allocator);

	rapidjson::Value pages_max_sizes(rapidjson::kArrayType);
	for (auto it = stat.pages_max_sizes.begin(), end = stat.pages_max_sizes.end(); it != end; ++it) {
		pages_max_sizes.PushBack(*it, allocator);
	}
	stat_value.AddMember("pages max sizes", pages_max_sizes, allocator);

	return stat_value;
}

void statistics::log() {
	dnet_log(m_monitor.node(), DNET_LOG_ERROR, "%s", report().c_str());
}

rapidjson::Value& statistics::commands_stat(rapidjson::Value &stat_value, rapidjson::Document::AllocatorType &allocator) {
	std::unique_lock<std::mutex> guard(m_cmd_info_mutex);
	for (int i = 1; i < __DNET_CMD_MAX; ++i) {
		auto &cmd_stat = m_cmd_stats[i];
		stat_value.AddMember(dnet_cmd_string(i),
		                     rapidjson::Value(rapidjson::kObjectType)
		                     .AddMember("cache",
		                                rapidjson::Value(rapidjson::kObjectType)
		                                .AddMember("successes", cmd_stat.cache_successes, allocator)
		                                .AddMember("failures",  cmd_stat.cache_failures, allocator),
		                                allocator)
		                     .AddMember("cache_internal",
		                                rapidjson::Value(rapidjson::kObjectType)
		                                .AddMember("successes", cmd_stat.cache_internal_successes, allocator)
		                                .AddMember("failures",  cmd_stat.cache_internal_failures, allocator),
		                                allocator)
		                     .AddMember("disk",
		                                rapidjson::Value(rapidjson::kObjectType)
		                                .AddMember("successes", cmd_stat.disk_successes, allocator)
		                                .AddMember("failures",  cmd_stat.disk_failures, allocator),
		                                allocator)
		                     .AddMember("disk_internal",
		                                rapidjson::Value(rapidjson::kObjectType)
		                                .AddMember("successes", cmd_stat.disk_internal_successes, allocator)
		                                .AddMember("failures",  cmd_stat.disk_internal_failures, allocator),
		                                allocator)
		                     .AddMember("cache_size",
		                                cmd_stat.cache_size,
		                                allocator)
		                     .AddMember("cache_intenal_size",
		                                cmd_stat.cache_internal_size,
		                                allocator)
		                     .AddMember("disk_size",
		                                cmd_stat.disk_size,
		                                allocator)
		                     .AddMember("disk_internal_size",
		                                cmd_stat.disk_internal_size,
		                                allocator)
		                     .AddMember("cache_time",
		                                cmd_stat.cache_time,
		                                allocator)
		                     .AddMember("cache_internal_time",
		                                cmd_stat.cache_internal_time,
		                                allocator)
		                     .AddMember("disk_time",
		                                cmd_stat.disk_time,
		                                allocator)
		                     .AddMember("disk_internal_time",
		                                cmd_stat.disk_internal_time,
		                                allocator),
		                     allocator);
	}
	return stat_value;
}

inline rapidjson::Value& history_print(rapidjson::Value &stat_value,
                                       rapidjson::Document::AllocatorType &allocator,
                                       const command_stat_info &info) {
	stat_value.AddMember(dnet_cmd_string(info.cmd),
	                     rapidjson::Value(rapidjson::kObjectType)
	                     .AddMember("internal", (info.internal ? "true" : "false"), allocator)
	                     .AddMember("cache", (info.cache ? "true" : "false"), allocator)
	                     .AddMember("size", info.size, allocator)
	                     .AddMember("time", info.time, allocator),
	                     allocator);
	return stat_value;
}

rapidjson::Value& statistics::history_report(rapidjson::Value &stat_value, rapidjson::Document::AllocatorType &allocator) {
	if(m_cmd_info_previous.empty() && m_cmd_info_current.empty())
		return stat_value;

	{
		std::unique_lock<std::mutex> guard(m_cmd_info_previous_mutex);
		const auto begin = m_cmd_info_previous.begin(), end = m_cmd_info_previous.end();
		for (auto it = begin; it != end; ++it) {
			rapidjson::Value cmd_value(rapidjson::kObjectType);
			stat_value.PushBack(history_print(cmd_value, allocator, *it), allocator);
		}
		m_cmd_info_previous.clear();
	} {
		std::unique_lock<std::mutex> guard(m_cmd_info_mutex);
		const auto begin = m_cmd_info_current.begin(), end = m_cmd_info_current.end();
		for (auto it = begin; it != end; ++it) {
			rapidjson::Value cmd_value(rapidjson::kObjectType);
			stat_value.PushBack(history_print(cmd_value, allocator, *it), allocator);
		}
		m_cmd_info_current.clear();
	}

	return stat_value;
}

histograms statistics::prepare_fivesec_histogram() {
	histograms ret;
	if (!m_histograms.empty()) {
		ret.start = m_histograms.front().start;
		for (auto it = m_histograms.begin(), itEnd = m_histograms.end(); it != itEnd; ++it) {
			auto begin = it->read_counters.begin(), end = it->read_counters.end();
			for (auto i = begin; i != end; ++i) {
				ret.read_counters[i-begin].cache += i->cache;
				ret.read_counters[i-begin].disk += i->disk;
				ret.read_counters[i-begin].cache_internal += i->cache_internal;
				ret.read_counters[i-begin].disk_internal += i->disk_internal;
			}
			begin = it->write_counters.begin();
			end = it->write_counters.end();
			for (auto i = begin; i != end; ++i) {
				ret.write_counters[i-begin].cache += i->cache;
				ret.write_counters[i-begin].disk += i->disk;
				ret.write_counters[i-begin].cache_internal += i->cache_internal;
				ret.write_counters[i-begin].disk_internal += i->disk_internal;
			}
			begin = it->indx_update_counters.begin();
			end = it->indx_update_counters.end();
			for (auto i = begin; i != end; ++i) {
				ret.indx_update_counters[i-begin].cache += i->cache;
				ret.indx_update_counters[i-begin].disk += i->disk;
				ret.indx_update_counters[i-begin].cache_internal += i->cache_internal;
				ret.indx_update_counters[i-begin].disk_internal += i->disk_internal;
			}
			begin = it->indx_internal_counters.begin();
			end = it->indx_internal_counters.end();
			for (auto i = begin; i != end; ++i) {
				ret.indx_internal_counters[i-begin].cache += i->cache;
				ret.indx_internal_counters[i-begin].disk += i->disk;
				ret.indx_internal_counters[i-begin].cache_internal += i->cache_internal;
				ret.indx_internal_counters[i-begin].disk_internal += i->disk_internal;
			}
		}
	}
	auto left = 5 - m_histograms.size();
	if (!m_histograms_previous.empty() && left > 0) {
		for (auto it = m_histograms_previous.rbegin(),
		     itEnd = m_histograms_previous.rbegin() + left;
		     it != itEnd; ++it) {
			auto begin = it->read_counters.begin(), end = it->read_counters.end();
			for (auto i = begin; i != end; ++i) {
				ret.read_counters[i-begin].cache += i->cache;
				ret.read_counters[i-begin].disk += i->disk;
				ret.read_counters[i-begin].cache_internal += i->cache_internal;
				ret.read_counters[i-begin].disk_internal += i->disk_internal;
			}
			begin = it->write_counters.begin();
			end = it->write_counters.end();
			for (auto i = begin; i != end; ++i) {
				ret.write_counters[i-begin].cache += i->cache;
				ret.write_counters[i-begin].disk += i->disk;
				ret.write_counters[i-begin].cache_internal += i->cache_internal;
				ret.write_counters[i-begin].disk_internal += i->disk_internal;
			}
			begin = it->indx_update_counters.begin();
			end = it->indx_update_counters.end();
			for (auto i = begin; i != end; ++i) {
				ret.indx_update_counters[i-begin].cache += i->cache;
				ret.indx_update_counters[i-begin].disk += i->disk;
				ret.indx_update_counters[i-begin].cache_internal += i->cache_internal;
				ret.indx_update_counters[i-begin].disk_internal += i->disk_internal;
			}
			begin = it->indx_internal_counters.begin();
			end = it->indx_internal_counters.end();
			for (auto i = begin; i != end; ++i) {
				ret.indx_internal_counters[i-begin].cache += i->cache;
				ret.indx_internal_counters[i-begin].disk += i->disk;
				ret.indx_internal_counters[i-begin].cache_internal += i->cache_internal;
				ret.indx_internal_counters[i-begin].disk_internal += i->disk_internal;
			}
		}
	}
	return ret;
}

inline uint_fast64_t get_stat(const boost::array<hist_counter, 16> &hist, size_t i, int place) {
	switch (place) {
		case 0:
			return hist[i].cache;
		case 1:
			return hist[i].disk;
		case 2:
			return hist[i].cache_internal;
		case 3:
			return hist[i].disk_internal;
		default:
			return hist[i].cache;
	}
}

inline void add_stat(rapidjson::Value &value,
                     rapidjson::Document::AllocatorType &allocator,
                     const char* name, const boost::array<hist_counter, 16> &hist,
                     int place) {
	size_t i = 0;
	rapidjson::Value stat(rapidjson::kObjectType);
	const char* tags_size[] = {"0 bytes", "501 bytes", "1001 bytes", "10001 bytes"};
	const char* tags_time[] = {"0 usecs", "5001 usecs", "100001 usecs", "1000001 usecs"};
	for (size_t j = 0, j_end = sizeof(tags_size) / sizeof(tags_size[0]); j < j_end; ++j) {
		rapidjson::Value time(rapidjson::kObjectType);
		for (size_t t = 0, t_end = sizeof(tags_time) / sizeof(tags_time[0]); t < t_end; ++t) {
			time.AddMember(tags_time[t], get_stat(hist, i++, place), allocator);
		}
		stat.AddMember(tags_size[j], time, allocator);
	}
	value.AddMember(name, stat, allocator);
}

inline void histogram_print(rapidjson::Value &stat_value,
                            rapidjson::Document::AllocatorType &allocator,
                            const boost::array<hist_counter, 16> &hist,
                            const char *name) {
	rapidjson::Value value(rapidjson::kObjectType);
	add_stat(value, allocator, "cache", hist, 0);
	add_stat(value, allocator, "disk", hist, 1);
	add_stat(value, allocator, "cache_internal", hist, 2);
	add_stat(value, allocator, "disk_internal", hist, 3);
	stat_value.AddMember(name, value, allocator);
}

rapidjson::Value& statistics::histogram_report(rapidjson::Value &stat_value, rapidjson::Document::AllocatorType &allocator) {
	std::unique_lock<std::mutex> guard(m_histograms_mutex);
	auto fivesec_hist = prepare_fivesec_histogram();
	histogram_print(stat_value, allocator, m_last_histograms.read_counters, "last_reads");
	histogram_print(stat_value, allocator, m_last_histograms.write_counters, "last_writes");
	histogram_print(stat_value, allocator, m_last_histograms.indx_update_counters, "last_indx_updates");
	histogram_print(stat_value, allocator, m_last_histograms.indx_internal_counters, "last_indx_internals");
	histogram_print(stat_value, allocator, fivesec_hist.read_counters, "5sec_reads");
	histogram_print(stat_value, allocator, fivesec_hist.write_counters, "5sec_writes");
	histogram_print(stat_value, allocator, fivesec_hist.indx_update_counters, "5sec_indx_updates");
	histogram_print(stat_value, allocator, fivesec_hist.indx_internal_counters, "5sec_indx_internals");

	m_last_histograms.clear();
	return stat_value;
}

void statistics::print_stacktraces(std::ostringstream &/*stream*/) {
	auto pid = getpid();
	printf("PID: %d\n", pid);
	unw_cursor_t cursor;
	unw_context_t uc;
	unw_word_t ip, sp, off;
	unw_proc_info_t pi;
	int n = 0, ret;
	unw_addr_space_t as;
	as = unw_create_addr_space(&_UPT_accessors, 0);
	unw_accessors_t *ui = (unw_accessors_t*)_UPT_create (pid);

	ret = unw_init_remote(&cursor, as, &pid);

	unw_getcontext(&uc);
	unw_init_local(&cursor, &uc);
	char buff[1024];
	while (unw_step(&cursor) > 0) {
		unw_get_proc_name(&cursor, buff, 1024, &off);
		unw_get_reg(&cursor, UNW_REG_IP, &ip);
		unw_get_reg(&cursor, UNW_REG_SP, &sp);
		printf ("ip = %lx, sp = %lx: %s\n", (long) ip, (long) sp, buff);
	}

	_UPT_destroy(ui);
}

}} /* namespace ioremap::monitor */
