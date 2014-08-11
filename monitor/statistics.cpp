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
#include "cache/cache.hpp"

#include "rapidjson/writer.h"
#include "rapidjson/stringbuffer.h"

namespace ioremap { namespace monitor {

statistics::statistics(monitor& mon, struct dnet_config *cfg)
: m_monitor(mon)
, m_read_histograms(default_xs(), default_ys())
, m_write_histograms(default_xs(), default_ys())
, m_indx_update_histograms(default_xs(), default_ys())
, m_indx_internal_histograms(default_xs(), default_ys())
, m_history_length(cfg->monitor_history_length) {
	memset(m_cmd_stats.c_array(), 0, sizeof(command_counters) * m_cmd_stats.size());
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

	if (m_history_length > 0) {
		m_cmd_info_current.emplace_back(command_stat_info{cmd, size, time, trans == 0, cache != 0});

		if (m_cmd_info_current.size() >= m_history_length) {
			std::unique_lock<std::mutex> swap_guard(m_cmd_info_previous_mutex);
			m_cmd_info_current.swap(m_cmd_info_previous);
			m_cmd_info_current.clear();
		}
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

struct provider_remover_condition
{
	std::string name;

	bool operator() (const std::pair<std::unique_ptr<stat_provider>, std::string> &pair)
	{
		return pair.second == name;
	}
};

void statistics::remove_provider(const std::string &name) {
	provider_remover_condition condition = { name };

	std::unique_lock<std::mutex> guard(m_provider_mutex);
	auto it = std::remove_if(m_stat_providers.begin(), m_stat_providers.end(), condition);
	m_stat_providers.erase(it, m_stat_providers.end());
}

inline std::string convert_report(const rapidjson::Document &report) {
	rapidjson::StringBuffer buffer;
	rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
	report.Accept(writer);
	return buffer.GetString();
}

std::string statistics::report(uint64_t categories) {
	rapidjson::Document report;
	dnet_log(m_monitor.node(), DNET_LOG_INFO, "monitor: collecting statistics for categories: %lx\n", categories);
	report.SetObject();
	auto &allocator = report.GetAllocator();

	struct timeval time;
	gettimeofday(&time, NULL);

	rapidjson::Value timestamp(rapidjson::kObjectType);
	timestamp.AddMember("tv_sec", time.tv_sec, allocator);
	timestamp.AddMember("tv_usec", time.tv_usec, allocator);
	report.AddMember("timestamp", timestamp, allocator);
	report.AddMember("monitor_status", "enabled", allocator);

	if (categories & DNET_MONITOR_COMMANDS) {
		rapidjson::Value commands_value(rapidjson::kObjectType);
		report.AddMember("commands_stat", commands_report(commands_value, allocator), allocator);

		rapidjson::Value history_value(rapidjson::kArrayType);
		report.AddMember("history_stat", history_report(history_value, allocator), allocator);
	}

	if (categories & DNET_MONITOR_IO_HISTOGRAMS) {
		rapidjson::Value histogram_value(rapidjson::kObjectType);
		report.AddMember("histogram", histogram_report(histogram_value, allocator), allocator);
	}

	std::unique_lock<std::mutex> guard(m_provider_mutex);
	for (auto it = m_stat_providers.cbegin(), end = m_stat_providers.cend(); it != end; ++it) {
		auto json = it->first->json(categories);
		if (json.empty())
			continue;
		rapidjson::Document value_doc(&allocator);
		value_doc.Parse<0>(json.c_str());
		report.AddMember(it->second.c_str(),
		                 allocator,
		                 static_cast<rapidjson::Value&>(value_doc),
		                 allocator);
	}

	dnet_log(m_monitor.node(), DNET_LOG_DEBUG, "monitor: finished generating json statistics for categories: %lx\n", categories);
	return convert_report(report);
}

rapidjson::Value& statistics::commands_report(rapidjson::Value &stat_value, rapidjson::Document::AllocatorType &allocator) {
	std::unique_lock<std::mutex> guard(m_cmd_info_mutex);
	for (int i = 1; i < __DNET_CMD_MAX; ++i) {
		auto &cmd_stat = m_cmd_stats[i];
		stat_value.AddMember(dnet_cmd_string(i),
	                         allocator,
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
	                     allocator,
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
	} {
		std::unique_lock<std::mutex> guard(m_cmd_info_mutex);
		const auto begin = m_cmd_info_current.begin(), end = m_cmd_info_current.end();
		for (auto it = begin; it != end; ++it) {
			rapidjson::Value cmd_value(rapidjson::kObjectType);
			stat_value.PushBack(history_print(cmd_value, allocator, *it), allocator);
		}
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
