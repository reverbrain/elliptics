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

#include "backends_stat_provider.hpp"
#include "statistics.hpp"

#include "library/elliptics.h"
#include "library/backend.h"

#include "rapidjson/document.h"
#include "rapidjson/writer.h"
#include "rapidjson/stringbuffer.h"
#include "cache/cache.hpp"

namespace ioremap { namespace monitor {

backends_stat_provider::backends_stat_provider(struct dnet_node *node)
: m_node(node)
{}

/*
 * Gets statistics from lowlevel backend and writes it to "backend" section
 */
static void fill_backend_backend(rapidjson::Value &stat_value,
                                 rapidjson::Document::AllocatorType &allocator,
                                 const struct dnet_backend_io &backend,
                                 const dnet_backend_info &config_backend) {
	char *json_stat = NULL;
	size_t size = 0;
	struct dnet_backend_callbacks *cb = backend.cb;
	if (cb->storage_stat_json) {
		cb->storage_stat_json(cb->command_private, &json_stat, &size);
		if (json_stat && size) {
			rapidjson::Document backend_value(&allocator);
			backend_value.Parse<0>(json_stat);
			backend_value["config"].AddMember("group", config_backend.group, allocator);
			stat_value.AddMember("backend",
			                     static_cast<rapidjson::Value&>(backend_value),
			                     allocator);
		}
	}

	free(json_stat);
}

static void dump_list_stats(rapidjson::Value &stat, list_stat &list_stats, rapidjson::Document::AllocatorType &allocator) {
	stat.AddMember("current_size", list_stats.list_size, allocator);
}

/*
 * Fills io section of one backend
 */
static void fill_backend_io(rapidjson::Value &stat_value,
                            rapidjson::Document::AllocatorType &allocator,
                            const struct dnet_backend_io &backend) {
	rapidjson::Value io_value(rapidjson::kObjectType);

	rapidjson::Value blocking_stat(rapidjson::kObjectType);
	dump_list_stats(blocking_stat, backend.pool.recv_pool.pool->list_stats, allocator);
	io_value.AddMember("blocking", blocking_stat, allocator);

	rapidjson::Value nonblocking_stat(rapidjson::kObjectType);
	dump_list_stats(nonblocking_stat, backend.pool.recv_pool_nb.pool->list_stats, allocator);
	io_value.AddMember("nonblocking", nonblocking_stat, allocator);

	stat_value.AddMember("io", io_value, allocator);
}

/*
 * Fills cache section of one backend
 */
static void fill_backend_cache(rapidjson::Value &stat_value,
                               rapidjson::Document::AllocatorType &allocator,
                               const struct dnet_backend_io &backend) {
	if (backend.cache) {
		ioremap::cache::cache_manager *cache = (ioremap::cache::cache_manager *)backend.cache;
		rapidjson::Document caches_value(&allocator);
		caches_value.Parse<0>(cache->stat_json().c_str());
		stat_value.AddMember("cache",
		                     static_cast<rapidjson::Value&>(caches_value),
		                     allocator);
	}
}

/*
 * Fills status section of one backend
 */
static void fill_backend_status(rapidjson::Value &stat_value,
                                rapidjson::Document::AllocatorType &allocator,
                                struct dnet_node *node,
                                dnet_backend_status &status,
                                size_t backend_id) {
	backend_fill_status_nolock(node, &status, backend_id);

	rapidjson::Value status_value(rapidjson::kObjectType);
	status_value.AddMember("state", status.state, allocator);
	status_value.AddMember("string_state", dnet_backend_state_string(status.state), allocator);
	status_value.AddMember("defrag_state", status.defrag_state, allocator);
	status_value.AddMember("string_defrag_state", dnet_backend_defrag_state_string(status.defrag_state), allocator);

	rapidjson::Value last_start(rapidjson::kObjectType);
	last_start.AddMember("tv_sec", status.last_start.tsec, allocator);
	last_start.AddMember("tv_usec", status.last_start.tnsec / 1000, allocator);
	status_value.AddMember("last_start", last_start, allocator);

	status_value.AddMember("string_last_time", dnet_print_time(&status.last_start), allocator);
	status_value.AddMember("last_start_err", status.last_start_err, allocator);
	status_value.AddMember("read_only", status.read_only == 1, allocator);
	status_value.AddMember("delay", status.delay, allocator);

	stat_value.AddMember("status", status_value, allocator);
}

/*
 * This function is called to fill in config values read from the config for non-enabled (yet) backends.
 *
 * If config template provides API for serializing parsed config values to json
 * it fills 'backend::config' section otherwise it uses unparsed values from original config
 * and fills 'backend::config_template'.
 *
 * After backend has been enabled, @fill_backend_backend() is called instead.
 */
static void fill_disabled_backend_config(rapidjson::Value &stat_value,
                                         rapidjson::Document::AllocatorType &allocator,
                                         const dnet_backend_info &config_backend) {
	rapidjson::Value backend_value(rapidjson::kObjectType);

	/* If config template provides API for serializing parsed config values to json - use it */
	if (config_backend.config_template.to_json) {
		char *json_stat = NULL;
		size_t size = 0;

		dnet_config_backend config = config_backend.config_template;
		std::vector<char> data(config.size, '\0');
		config.data = data.data();
		config.log = config_backend.log.get();

		for (auto it = config_backend.options.begin(); it != config_backend.options.end(); ++it) {
			const dnet_backend_config_entry &entry = *it;

			std::vector<char> tmp(entry.value_template.begin(), entry.value_template.end());
			entry.entry->callback(&config, entry.entry->key, tmp.data());
		}

		config.to_json(&config, &json_stat, &size);
		if (json_stat && size) {
			rapidjson::Document config_value(&allocator);
			config_value.Parse<0>(json_stat);
			config_value.AddMember("group", config_backend.group, allocator);
			backend_value.AddMember("config",
			                        static_cast<rapidjson::Value&>(config_value),
			                        allocator);
		}
		free(json_stat);
	} else {
		rapidjson::Value config_value(rapidjson::kObjectType);
		for (auto it = config_backend.options.begin(); it != config_backend.options.end(); ++it) {
			const dnet_backend_config_entry &entry = *it;

			rapidjson::Value tmp_val(entry.value_template.data(), allocator);
			config_value.AddMember(entry.entry->key, tmp_val, allocator);
		}
		config_value.AddMember("group", config_backend.group, allocator);
		backend_value.AddMember("config_template", config_value, allocator);
	}

	stat_value.AddMember("backend", backend_value, allocator);
}

/*
 * Fills all sections of one backend
 */
static rapidjson::Value& backend_stats_json(uint64_t categories,
                                            rapidjson::Value &stat_value,
                                            rapidjson::Document::AllocatorType &allocator,
                                            struct dnet_node *node,
                                            size_t backend_id) {
	dnet_backend_status status;
	memset(&status, 0, sizeof(status));

	const auto &config_backend = node->config_data->backends->backends[backend_id];

	stat_value.AddMember("backend_id", backend_id, allocator);
	fill_backend_status(stat_value, allocator, node, status, backend_id);

	if (status.state == DNET_BACKEND_ENABLED && node->io) {
		const struct dnet_backend_io & backend = node->io->backends[backend_id];

		if (categories & DNET_MONITOR_COMMANDS) {
			const command_stats *stats = (command_stats *)(backend.command_stats);
			rapidjson::Value commands_value(rapidjson::kObjectType);
			stat_value.AddMember("commands", stats->commands_report(NULL, commands_value, allocator), allocator);
		}

		if (categories & DNET_MONITOR_BACKEND) {
			fill_backend_backend(stat_value, allocator, backend, config_backend);
		}
		if (categories & DNET_MONITOR_IO) {
			fill_backend_io(stat_value, allocator, backend);
		}
		if (categories & DNET_MONITOR_CACHE) {
			fill_backend_cache(stat_value, allocator, backend);
		}
	} else if (categories & DNET_MONITOR_BACKEND) {
		fill_disabled_backend_config(stat_value, allocator, config_backend);
	}

	return stat_value;
}

static bool backend_check_state_nolock(struct dnet_node *node, size_t backend_id) {
	return node->config_data->backends->backends[backend_id].state != DNET_BACKEND_UNITIALIZED;
}

/*
 * Fills all section of all backends
 */
static void backends_stats_json(uint64_t categories,
                                rapidjson::Value &stat_value,
                                rapidjson::Document::AllocatorType &allocator,
                                struct dnet_node *node) {
	const auto &backends = node->config_data->backends->backends;
	for (size_t i = 0; i < backends.size(); ++i) {
		std::lock_guard<std::mutex> guard(*node->config_data->backends->backends[i].state_mutex);
		if (!backend_check_state_nolock(node, i))
			continue;
		rapidjson::Value backend_stat(rapidjson::kObjectType);
		stat_value.AddMember(std::to_string(static_cast<unsigned long long>(i)).c_str(),
		                     allocator,
		                     backend_stats_json(categories, backend_stat, allocator, node, i),
		                     allocator);
	}
}

/*
 * Generates json statistics from all backends
 */
std::string backends_stat_provider::json(uint64_t categories) const {
	if (!(categories & DNET_MONITOR_IO) &&
	    !(categories & DNET_MONITOR_CACHE) &&
	    !(categories & DNET_MONITOR_BACKEND))
	    return std::string();

	rapidjson::Document doc;
	doc.SetObject();
	auto &allocator = doc.GetAllocator();

	backends_stats_json(categories, doc, allocator, m_node);

	rapidjson::StringBuffer buffer;
	rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
	doc.Accept(writer);
	return buffer.GetString();
}

}} /* namespace ioremap::monitor */

#include <fstream>

int dnet_backend_command_stats_init(struct dnet_backend_io *backend_io)
{
	int err = 0;

	try {
		backend_io->command_stats = (void *)(new ioremap::monitor::command_stats());
	} catch (...) {
		backend_io->command_stats = NULL;
		err = -ENOMEM;
	}

	return err;
}

void dnet_backend_command_stats_cleanup(struct dnet_backend_io *backend_io)
{
	delete (ioremap::monitor::command_stats *)backend_io->command_stats;
	backend_io->command_stats = NULL;
}

void dnet_backend_command_stats_update(struct dnet_node *node, struct dnet_backend_io *backend_io,
		struct dnet_cmd *cmd, uint64_t size, int handled_in_cache, int err, long diff)
{
	ioremap::monitor::command_stats *stats = (ioremap::monitor::command_stats *)backend_io->command_stats;

	assert(stats != NULL);

	(void) node;

	stats->command_counter(cmd->cmd, cmd->trans, err, handled_in_cache, size, diff);
}
