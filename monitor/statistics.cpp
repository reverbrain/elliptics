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
#include "elliptics/backends.h"
#include "monitor/compress.hpp"

//FIXME: elliptics uses rather modified version of rapidjson
// which is partially incompatible with a stock version used by
// handystats, so its a necessity to include exactly prettywriter.h,
// its effectively forces selection of elliptics' version of rapidjson
// in its entirety.
#include "rapidjson/prettywriter.h"

#ifdef HAVE_HANDYSTATS
#include <handystats/json_dump.hpp>
#endif

namespace ioremap { namespace monitor {

static void ext_stat_json(const ext_counter &ext_stat,
		rapidjson::Value &stat_value, rapidjson::Document::AllocatorType &allocator) {
	stat_value.AddMember("successes", ext_stat.counter.successes, allocator);
	stat_value.AddMember("failures", ext_stat.counter.failures, allocator);
	stat_value.AddMember("size", ext_stat.size, allocator);
	stat_value.AddMember("time", ext_stat.time, allocator);
}

static void source_stat_json(const source_counter &source_stat, rapidjson::Value &stat_value,
		rapidjson::Document::AllocatorType &allocator) {
	rapidjson::Value outside_stat(rapidjson::kObjectType);
	ext_stat_json(source_stat.outside, outside_stat, allocator);
	stat_value.AddMember("outside", outside_stat, allocator);

	rapidjson::Value internal_stat(rapidjson::kObjectType);
	ext_stat_json(source_stat.internal, internal_stat, allocator);
	stat_value.AddMember("internal", internal_stat, allocator);
}

static void dnet_stat_count_json(const dnet_stat_count &counter, rapidjson::Value &stat_value,
		rapidjson::Document::AllocatorType &allocator) {
	stat_value.AddMember("successes", counter.count, allocator);
	stat_value.AddMember("failures", counter.err, allocator);
}

static void node_stat_json(dnet_node *n, int cmd, rapidjson::Value &stat_value,
		rapidjson::Document::AllocatorType &allocator) {
	rapidjson::Value storage_stat(rapidjson::kObjectType);
	dnet_stat_count_json(n->counters[cmd], storage_stat, allocator);
	stat_value.AddMember("storage", storage_stat, allocator);

	rapidjson::Value proxy_stat(rapidjson::kObjectType);
	dnet_stat_count_json(n->counters[cmd + __DNET_CMD_MAX], proxy_stat, allocator);
	stat_value.AddMember("proxy", proxy_stat, allocator);
}

static void cmd_stat_json(dnet_node *node, int cmd, const command_counters &cmd_stat,
		rapidjson::Value &stat_value, rapidjson::Document::AllocatorType &allocator) {
	rapidjson::Value cache_stat(rapidjson::kObjectType);
	source_stat_json(cmd_stat.cache, cache_stat, allocator);
	stat_value.AddMember("cache", cache_stat, allocator);

	rapidjson::Value disk_stat(rapidjson::kObjectType);
	source_stat_json(cmd_stat.disk, disk_stat, allocator);
	stat_value.AddMember("disk", disk_stat, allocator);

	/*
	 * @node is only set for global counters
	 */
	if (node) {
		rapidjson::Value total_stat(rapidjson::kObjectType);
		node_stat_json(node, cmd, total_stat, allocator);
		stat_value.AddMember("total", total_stat, allocator);
	}
}

static void single_client_stat_json(dnet_net_state *st, rapidjson::Value &stat_value,
		rapidjson::Document::AllocatorType &allocator) {
	for (int i = 1; i < __DNET_CMD_MAX; ++i) {
		if (st->stat[i].count != 0 || st->stat[i].err != 0) {
			rapidjson::Value cmd_stat(rapidjson::kObjectType);
			dnet_stat_count_json(st->stat[i], cmd_stat, allocator);
			stat_value.AddMember(dnet_cmd_string(i), allocator, cmd_stat, allocator);
		}
	}
}

static void clients_stat_json(dnet_node *n, rapidjson::Value &stat_value,
		rapidjson::Document::AllocatorType &allocator) {
	struct dnet_net_state *st;

	pthread_mutex_lock(&n->state_lock);
	try {
		list_for_each_entry(st, &n->empty_state_list, node_entry) {
			rapidjson::Value client_stat(rapidjson::kObjectType);
			single_client_stat_json(st, client_stat, allocator);
			stat_value.AddMember(dnet_addr_string(&st->addr), allocator, client_stat, allocator);
		}
	} catch(std::exception &e) {
		pthread_mutex_unlock(&n->state_lock);
		dnet_log(n, DNET_LOG_ERROR, "monitor: failed collecting client state stats: %s", e.what());
		throw;
	} catch(...) {
		pthread_mutex_unlock(&n->state_lock);
		dnet_log(n, DNET_LOG_ERROR, "monitor: failed collecting client state stats: unknown exception");
		throw;
	}
	pthread_mutex_unlock(&n->state_lock);
}


command_stats::command_stats()
{
	m_cmd_stats.resize(__DNET_CMD_MAX);
}

void command_stats::command_counter(const int orig_cmd,
                                 const int trans,
                                 const int err,
                                 const int cache,
                                 const uint64_t size,
                                 const unsigned long time)
{
	int cmd = orig_cmd;

	if (cmd >= __DNET_CMD_MAX || cmd <= 0)
		cmd = DNET_CMD_UNKNOWN;

	std::unique_lock<std::mutex> guard(m_cmd_stats_mutex);
	auto &place = cache ? m_cmd_stats[cmd].cache : m_cmd_stats[cmd].disk;
	auto &source = trans ? place.outside : place.internal;
	auto &counter = err ? source.counter.failures : source.counter.successes;

	++counter;
	source.size += size;
	source.time += time;
}

rapidjson::Value& command_stats::commands_report(dnet_node *node, rapidjson::Value &stat_value,
		rapidjson::Document::AllocatorType &allocator) const {
	std::unique_lock<std::mutex> guard(m_cmd_stats_mutex);
	std::vector<command_counters> tmp_stats = m_cmd_stats;
	guard.unlock();

	for (int i = 1; i < __DNET_CMD_MAX; ++i) {
		if (tmp_stats[i].has_data()) {
			rapidjson::Value cmd_stat(rapidjson::kObjectType);
			cmd_stat_json(node, i, tmp_stats[i], cmd_stat, allocator);
			stat_value.AddMember(dnet_cmd_string(i), allocator, cmd_stat, allocator);
		}
	}

	return stat_value;
}


void statistics::command_counter(const int cmd,
                                 const int trans,
                                 const int err,
                                 const int cache,
                                 const uint64_t size,
                                 const unsigned long time)
{
	m_command_stats.command_counter(cmd, trans, err, cache, size, time);
}

statistics::statistics(monitor& mon, struct dnet_config *cfg) : m_monitor(mon)
{
	(void) cfg;
}

void statistics::add_provider(stat_provider *stat, const std::string &name)
{
	boost::unique_lock<rw_lock> guard(m_provider_lock);
	m_stat_providers.insert(make_pair(name, std::shared_ptr<stat_provider>(stat)));
}

void statistics::remove_provider(const std::string &name)
{
	boost::unique_lock<rw_lock> guard(m_provider_lock);
	m_stat_providers.erase(name);
}

inline std::string convert_report(const rapidjson::Document &report)
{
	rapidjson::StringBuffer buffer;
	rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
	report.Accept(writer);
	return compress(buffer.GetString());
}

std::string statistics::report(uint64_t categories)
{
	rapidjson::Document report;
	dnet_log(m_monitor.node(), DNET_LOG_INFO, "monitor: collecting statistics for categories: %lx", categories);
	report.SetObject();
	auto &allocator = report.GetAllocator();

	dnet_time time;
	dnet_current_time(&time);

	rapidjson::Value timestamp(rapidjson::kObjectType);
	timestamp.AddMember("tv_sec", time.tsec, allocator);
	timestamp.AddMember("tv_usec", time.tnsec / 1000, allocator);
	report.AddMember("timestamp", timestamp, allocator);
	report.AddMember("string_timestamp", dnet_print_time(&time), allocator);

	report.AddMember("monitor_status", "enabled", allocator);

	if (categories & DNET_MONITOR_COMMANDS) {
		rapidjson::Value commands_value(rapidjson::kObjectType);
		m_command_stats.commands_report(m_monitor.node(), commands_value, allocator);

		rapidjson::Value clients_stat(rapidjson::kObjectType);
		clients_stat_json(m_monitor.node(), clients_stat, allocator);
		commands_value.AddMember("clients", clients_stat, allocator);

		report.AddMember("commands", commands_value, allocator);
	}

	if (categories & DNET_MONITOR_STATS) {
#if defined(HAVE_HANDYSTATS) && !defined(HANDYSTATS_DISABLE)
		rapidjson::Value stats_value(rapidjson::kObjectType);
		handystats::json::fill(stats_value, allocator, *HANDY_METRICS_DUMP());
		report.AddMember("stats", stats_value, allocator);
#else
		report.AddMember("__stats__", "stats subsystem disabled at compile time", allocator);
#endif
	}

	boost::shared_lock<rw_lock> guard(m_provider_lock);
	for (auto it = m_stat_providers.cbegin(), end = m_stat_providers.cend(); it != end; ++it) {
		auto json = it->second->json(categories);
		if (json.empty())
			continue;
		rapidjson::Document value_doc(&allocator);
		value_doc.Parse<0>(json.c_str());
		report.AddMember(it->first.c_str(),
		                 allocator,
		                 static_cast<rapidjson::Value&>(value_doc),
		                 allocator);
	}

	dnet_log(m_monitor.node(), DNET_LOG_DEBUG,
			"monitor: finished generating json statistics for categories: %lx", categories);
	return convert_report(report);
}

}} /* namespace ioremap::monitor */
