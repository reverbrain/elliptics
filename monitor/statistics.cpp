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

#include "monitor.hpp"
#include "../cache/cache.hpp"

#include "rapidjson/writer.h"
#include "rapidjson/stringbuffer.h"

namespace ioremap { namespace monitor {

statistics::statistics(monitor& mon)
: m_monitor(mon)
, m_read_histograms(default_xs(), default_ys())
, m_write_histograms(default_xs(), default_ys())
, m_indx_update_histograms(default_xs(), default_ys())
, m_indx_internal_histograms(default_xs(), default_ys()) {
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
			if (!err)
				m_cmd_stats[cmd].cache_successes++;
			else
				m_cmd_stats[cmd].cache_failures++;
			m_cmd_stats[cmd].cache_size += size;
			m_cmd_stats[cmd].cache_time += time;
		} else {
			if (!err)
				m_cmd_stats[cmd].cache_internal_successes++;
			else
				m_cmd_stats[cmd].cache_internal_failures++;
			m_cmd_stats[cmd].cache_internal_size += size;
			m_cmd_stats[cmd].cache_internal_time += time;
		}
	} else {
		if (trans) {
			if (!err)
				m_cmd_stats[cmd].disk_successes++;
			else
				m_cmd_stats[cmd].disk_failures++;
			m_cmd_stats[cmd].disk_size += size;
			m_cmd_stats[cmd].disk_time += time;
		} else {
			if (!err)
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

	std::unique_lock<std::mutex> hist_guard(m_histograms_mutex);
	command_histograms *hist = NULL;

	switch (cmd) {
		case DNET_CMD_READ:
			hist = &m_read_histograms;
			break;
		case DNET_CMD_WRITE:
			hist = &m_write_histograms;
			break;
		case DNET_CMD_INDEXES_UPDATE:
			hist = &m_indx_update_histograms;
			break;
		case DNET_CMD_INDEXES_INTERNAL:
			hist = &m_indx_internal_histograms;
			break;
		default:
			return;
	}

	if (cache) {
		if (trans)
			hist->cache.update(time, size);
		else
			hist->cache_internal.update(time, size);
	} else {
		if (trans)
			hist->disk.update(time, size);
		else
			hist->disk_internal.update(time, size);
	}
}

void statistics::add_provider(stat_provider *stat, const std::string &name) {
	std::unique_lock<std::mutex> guard(m_provider_mutex);
	m_stat_providers.emplace_back(std::unique_ptr<stat_provider>(stat), name);
}

inline std::string convert_report(const rapidjson::Document &report) {
	rapidjson::StringBuffer buffer;
	rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
	report.Accept(writer);
	return buffer.GetString();
}

std::string statistics::report(int category) {
	rapidjson::Document report;
	report.SetObject();
	auto &allocator = report.GetAllocator();

	struct timeval end_time;
	gettimeofday(&end_time, NULL);
	auto time = (end_time.tv_sec - m_start_time.tv_sec) * 1000000 +
	                      (end_time.tv_usec - m_start_time.tv_usec);
	m_start_time = end_time;
	report.AddMember("time", time, allocator);

	if (category == DNET_MONITOR_ALL || category == DNET_MONITOR_IO_QUEUE) {
		rapidjson::Value io_queue_value(rapidjson::kObjectType);
		report.AddMember("io_queue_stat", io_queue_report(io_queue_value, allocator), allocator);
	}

	if (category == DNET_MONITOR_ALL || category == DNET_MONITOR_COMMANDS) {
		rapidjson::Value commands_value(rapidjson::kObjectType);
		report.AddMember("commands_stat", commands_report(commands_value, allocator), allocator);
	}

	if (category == DNET_MONITOR_ALL || category == DNET_MONITOR_COMMANDS) {
		rapidjson::Value history_value(rapidjson::kArrayType);
		report.AddMember("history_stat", history_report(history_value, allocator), allocator);
	}

	if (category == DNET_MONITOR_ALL || category == DNET_MONITOR_IO_HISTOGRAMS) {
		rapidjson::Value histogram_value(rapidjson::kObjectType);
		report.AddMember("histogram", histogram_report(histogram_value, allocator), allocator);
	}

	std::unique_lock<std::mutex> guard(m_provider_mutex);
	for (auto it = m_stat_providers.cbegin(), end = m_stat_providers.cend(); it != end; ++it) {
		if (!it->first->check_category(category))
			continue;
		rapidjson::Document value_doc;
		value_doc.Parse<0>(it->first->json().c_str());
		report.AddMember(it->second.c_str(),
		                 static_cast<rapidjson::Value&>(value_doc),
		                 allocator);
	}


	return convert_report(report);
}

rapidjson::Value& statistics::io_queue_report(rapidjson::Value &stat_value, rapidjson::Document::AllocatorType &allocator) {
	auto st = m_monitor.node()->io->recv_pool->list_stats;
	auto elapsed_seconds = (m_start_time.tv_sec - st.time_base.tv_sec) * 1000000 +
	                       (m_start_time.tv_usec - st.time_base.tv_usec);

	auto min = st.min_list_size;
	if (min == ~0ULL)
		min = 0ULL;


	stat_value.AddMember("size", st.list_size, allocator)
	          .AddMember("volume", st.volume, allocator)
	          .AddMember("min", min, allocator)
	          .AddMember("max", st.max_list_size, allocator)
	          .AddMember("time", elapsed_seconds, allocator);
	return stat_value;
}

void statistics::log() {
	dnet_log(m_monitor.node(), DNET_LOG_ERROR, "%s", report(DNET_MONITOR_ALL).c_str());
}

rapidjson::Value& statistics::commands_report(rapidjson::Value &stat_value, rapidjson::Document::AllocatorType &allocator) {
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
	if (m_cmd_info_previous.empty() && m_cmd_info_current.empty())
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

inline rapidjson::Value& command_histograms_print(rapidjson::Value &stat_value,
                            rapidjson::Document::AllocatorType &allocator,
                            command_histograms &histograms) {
	rapidjson::Value disk(rapidjson::kObjectType);
	rapidjson::Value cache(rapidjson::kObjectType);
	rapidjson::Value disk_internal(rapidjson::kObjectType);
	rapidjson::Value cache_internal(rapidjson::kObjectType);

	stat_value.AddMember("disk",
	                     histograms.disk.report(disk, allocator),
	                     allocator)
	          .AddMember("cache",
	                     histograms.cache.report(cache, allocator),
	                     allocator)
	          .AddMember("disk_internal",
	                     histograms.disk_internal.report(disk_internal, allocator),
	                     allocator)
	          .AddMember("cache_internal",
	                     histograms.cache_internal.report(cache_internal, allocator),
	                     allocator);

	return stat_value;
}

rapidjson::Value& statistics::histogram_report(rapidjson::Value &stat_value, rapidjson::Document::AllocatorType &allocator) {
	std::unique_lock<std::mutex> guard(m_histograms_mutex);

	rapidjson::Value read_stat(rapidjson::kObjectType);
	rapidjson::Value write_stat(rapidjson::kObjectType);
	rapidjson::Value indx_update(rapidjson::kObjectType);
	rapidjson::Value indx_internal(rapidjson::kObjectType);

	stat_value.AddMember("read",
	                     command_histograms_print(read_stat, allocator, m_read_histograms),
	                     allocator)
	          .AddMember("write",
	                     command_histograms_print(write_stat, allocator, m_write_histograms),
	                     allocator)
	          .AddMember("indx_update",
	                     command_histograms_print(indx_update, allocator, m_indx_update_histograms),
	                     allocator)
	          .AddMember("indx_internal",
	                     command_histograms_print(indx_internal, allocator, m_indx_internal_histograms),
	                     allocator);
	return stat_value;
}

}} /* namespace ioremap::monitor */
