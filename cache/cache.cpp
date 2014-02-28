/*
* 2012+ Copyright (c) Evgeniy Polyakov <zbr@ioremap.net>
* 2013+ Copyright (c) Ruslan Nigmatullin <euroelessar@yandex.ru>
* 2013+ Copyright (c) Andrey Kashin <kashin.andrej@gmail.com>
* All rights reserved.
*
* This program is free software; you can redistribute it and/or modify
* it under the terms of the GNU Lesser General Public License as published by
* the Free Software Foundation; either version 2 of the License, or
* (at your option) any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
* GNU Lesser General Public License for more details.
*/

#include "cache.hpp"
#include "slru_cache.hpp"

#include <fstream>

#include "boost/lexical_cast.hpp"

#include "monitor/monitor.h"
#include "monitor/monitor.hpp"
#include "monitor/statistics.hpp"
#include "monitor/rapidjson/document.h"
#include "monitor/rapidjson/writer.h"
#include "monitor/rapidjson/stringbuffer.h"

namespace ioremap { namespace cache {

namespace actions {

actions_set_t cache_actions;

const int ACTION_CACHE = cache_actions.define_new_action("CACHE");
const int ACTION_WRITE = cache_actions.define_new_action("WRITE");
const int ACTION_READ = cache_actions.define_new_action("READ");
const int ACTION_REMOVE = cache_actions.define_new_action("REMOVE");
const int ACTION_LOOKUP = cache_actions.define_new_action("LOOKUP");
const int ACTION_LOCK = cache_actions.define_new_action("LOCK");
const int ACTION_FIND = cache_actions.define_new_action("FIND");
const int ACTION_ADD_TO_PAGE = cache_actions.define_new_action("ADD_TO_PAGE");
const int ACTION_RESIZE_PAGE = cache_actions.define_new_action("RESIZE_PAGE");
const int ACTION_SYNC_AFTER_APPEND = cache_actions.define_new_action("SYNC_AFTER_APPEND");
const int ACTION_WRITE_APPEND_ONLY = cache_actions.define_new_action("WRITE_APPEND_ONLY");
const int ACTION_WRITE_AFTER_APPEND_ONLY = cache_actions.define_new_action("WRITE_AFTER_APPEND_ONLY");
const int ACTION_POPULATE_FROM_DISK = cache_actions.define_new_action("POPULATE_FROM_DISK");
const int ACTION_CLEAR = cache_actions.define_new_action("CLEAR");
const int ACTION_LIFECHECK = cache_actions.define_new_action("LIFECHECK");
const int ACTION_CREATE_DATA = cache_actions.define_new_action("CREATE_DATA");
const int ACTION_CAS = cache_actions.define_new_action("CAS");
const int ACTION_MODIFY = cache_actions.define_new_action("MODIFY");
const int ACTION_DECREASE_KEY = cache_actions.define_new_action("DECREASE_KEY");
const int ACTION_MOVE_RECORD = cache_actions.define_new_action("MOVE_RECORD");
const int ACTION_ERASE = cache_actions.define_new_action("ERASE");
const int ACTION_REMOVE_LOCAL = cache_actions.define_new_action("REMOVE_LOCAL");
const int ACTION_LOCAL_LOOKUP = cache_actions.define_new_action("LOCAL_LOOKUP");
const int ACTION_INIT = cache_actions.define_new_action("INIT");
const int ACTION_LOCAL_READ = cache_actions.define_new_action("LOCAL_READ");
const int ACTION_PREPARE = cache_actions.define_new_action("PREPARE");
const int ACTION_LOCAL_WRITE = cache_actions.define_new_action("LOCAL_WRITE");
const int ACTION_PREPARE_SYNC = cache_actions.define_new_action("PREPARE_SYNC");
const int ACTION_SYNC = cache_actions.define_new_action("SYNC");
const int ACTION_SYNC_BEFORE_OPERATION = cache_actions.define_new_action("SYNC_BEFORE_OPERATION");
const int ACTION_ERASE_ITERATE = cache_actions.define_new_action("ERASE_ITERATE");
const int ACTION_SYNC_ITERATE = cache_actions.define_new_action("SYNC_ITERATE");
const int ACTION_DNET_OPLOCK = cache_actions.define_new_action("DNET_OPLOCK");
const int ACTION_DESTRUCT = cache_actions.define_new_action("DESTRUCT");

}

class cache_stat_provider : public ioremap::monitor::stat_provider {
public:
	cache_stat_provider(const cache_manager &manager)
	: m_manager(manager)
	{}

	virtual std::string json() const {
		return m_manager.stat_json();
	}

	virtual bool check_category(int category) const {
		return category == DNET_MONITOR_CACHE || category == DNET_MONITOR_ALL;
	}

private:
	const cache_manager	&m_manager;
};

cache_manager::cache_manager(struct dnet_node *n) {
	size_t caches_number = n->caches_number;
	m_cache_pages_number = n->cache_pages_number;
	m_max_cache_size = n->cache_size;
	size_t max_size = m_max_cache_size / caches_number;

	size_t proportionsSum = 0;
	for (size_t i = 0; i < m_cache_pages_number; ++i) {
		proportionsSum += n->cache_pages_proportions[i];
	}

	std::vector<size_t> pages_max_sizes(m_cache_pages_number);
	for (size_t i = 0; i < m_cache_pages_number; ++i) {
		pages_max_sizes[i] = max_size * (n->cache_pages_proportions[i] * 1.0 / proportionsSum);
	}

	for (size_t i = 0; i < caches_number; ++i) {
		m_caches.emplace_back(std::make_shared<slru_cache_t>(n, pages_max_sizes));
	}

	ioremap::monitor::dnet_monitor_add_provider(n, new cache_stat_provider(*this), "cache");
}

cache_manager::~cache_manager() {
}

int cache_manager::write(const unsigned char *id, dnet_net_state *st, dnet_cmd *cmd, dnet_io_attr *io, const char *data) {
	return m_caches[idx(id)]->write(id, st, cmd, io, data);
}

std::shared_ptr<raw_data_t> cache_manager::read(const unsigned char *id, dnet_cmd *cmd, dnet_io_attr *io) {
	return m_caches[idx(id)]->read(id, cmd, io);
}

int cache_manager::remove(const unsigned char *id, dnet_io_attr *io) {
	return m_caches[idx(id)]->remove(id, io);
}

int cache_manager::lookup(const unsigned char *id, dnet_net_state *st, dnet_cmd *cmd) {
	return m_caches[idx(id)]->lookup(id, st, cmd);
}

int cache_manager::indexes_find(dnet_cmd *cmd, dnet_indexes_request *request) {
	(void) cmd;
	(void) request;
	return -ENOTSUP;
}

int cache_manager::indexes_update(dnet_cmd *cmd, dnet_indexes_request *request) {
	(void) cmd;
	(void) request;
	return -ENOTSUP;
}

int cache_manager::indexes_internal(dnet_cmd *cmd, dnet_indexes_request *request) {
	(void) cmd;
	(void) request;
	return -ENOTSUP;
}

void cache_manager::clear() {
	time_stats_updater_t time_stats_updater;
	ioremap::cache::local::thread_time_stats_updater = &time_stats_updater;
	for (size_t i = 0; i < m_caches.size(); ++i) {
		m_caches[i]->clear();
	}
	ioremap::cache::local::thread_time_stats_updater = NULL;
}

size_t cache_manager::cache_size() const {
	return m_max_cache_size;
}

size_t cache_manager::cache_pages_number() const {
	return m_cache_pages_number;
}

cache_stats cache_manager::get_total_cache_stats() const {
	cache_stats stats;
	stats.pages_sizes.resize(m_cache_pages_number);
	stats.pages_max_sizes.resize(m_cache_pages_number);
	for (size_t i = 0; i < m_caches.size(); ++i) {
		const cache_stats &page_stats = m_caches[i]->get_cache_stats();
		stats.number_of_objects += page_stats.number_of_objects;
		stats.number_of_objects_marked_for_deletion += page_stats.number_of_objects_marked_for_deletion;
		stats.size_of_objects_marked_for_deletion += page_stats.size_of_objects_marked_for_deletion;
		stats.size_of_objects += page_stats.size_of_objects;

		for (size_t j = 0; j < m_cache_pages_number; ++j) {
			stats.pages_sizes[j] += page_stats.pages_sizes[j];
			stats.pages_max_sizes[j] += page_stats.pages_max_sizes[j];
		}
	}
	return stats;
}

std::vector<cache_stats> cache_manager::get_caches_stats() const {
	std::vector<cache_stats> caches_stats;
	for (size_t i = 0; i < m_caches.size(); ++i) {
		caches_stats.push_back(m_caches[i]->get_cache_stats());
	}
	return caches_stats;
}

rapidjson::Value &cache_manager::get_total_caches_size_stats_json(rapidjson::Value &stat_value, rapidjson::Document::AllocatorType &allocator) const {
	cache_stats stats = get_total_cache_stats();
	return stats.to_json(stat_value, allocator);
}

std::string get_cache_name(int id, size_t number_length) {
	std::string name = boost::lexical_cast<std::string> (id);
	std::string prefix(number_length - name.length(), '0');
	return "Cache_" + prefix + name;
}

rapidjson::Value &cache_manager::get_caches_size_stats_json(rapidjson::Value &stat_value, rapidjson::Document::AllocatorType &allocator) const {
	for (size_t i = 0; i < m_caches.size(); ++i) {
		rapidjson::Value cache_time_stats(rapidjson::kObjectType);
		stat_value.AddMember(get_cache_name(i, 2).c_str(), allocator, m_caches[i]->get_cache_stats().to_json(cache_time_stats, allocator), allocator);
	}
	return stat_value;
}

rapidjson::Value &cache_manager::get_total_caches_time_stats_json(rapidjson::Value &stat_value, rapidjson::Document::AllocatorType &allocator) const {
	time_stats_tree_t total_caches_time_stats(actions::cache_actions);
	for (size_t i = 0; i < m_caches.size(); ++i) {
		m_caches[i]->get_time_stats().merge_into(total_caches_time_stats);
	}
	total_caches_time_stats.to_json(stat_value, allocator);
	return stat_value;
}

rapidjson::Value &cache_manager::get_caches_time_stats_json(rapidjson::Value &stat_value, rapidjson::Document::AllocatorType &allocator) const {
	for (size_t i = 0; i < m_caches.size(); ++i) {
		rapidjson::Value cache_time_stats(rapidjson::kObjectType);
		stat_value.AddMember(get_cache_name(i, 2).c_str(), m_caches[i]->get_time_stats().to_json(cache_time_stats, allocator), allocator);
	}
	return stat_value;
}

std::string cache_manager::stat_json() const {
	rapidjson::Document doc;
	doc.SetObject();
	auto &allocator = doc.GetAllocator();

	rapidjson::Value total_cache(rapidjson::kObjectType);

	rapidjson::Value size_stats(rapidjson::kObjectType);
	get_total_caches_size_stats_json(size_stats, allocator);

	rapidjson::Value time_stats(rapidjson::kObjectType);
	get_total_caches_time_stats_json(time_stats, allocator);

	total_cache.AddMember("size_stats", size_stats, allocator);
	total_cache.AddMember("time_stats", time_stats, allocator);
	doc.AddMember("total_cache", total_cache, allocator);

	rapidjson::Value caches(rapidjson::kObjectType);
	get_caches_size_stats_json(caches, allocator);
	doc.AddMember("caches", caches, allocator);

	rapidjson::StringBuffer buffer;
	rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
	doc.Accept(writer);
	return buffer.GetString();
}

size_t cache_manager::idx(const unsigned char *id) {
	size_t i = *(size_t *)id;
	size_t j = *(size_t *)(id + DNET_ID_SIZE - sizeof(size_t));
	return (i ^ j) % m_caches.size();
}

}} /* namespace ioremap::cache */

namespace ioremap { namespace cache { namespace local {
	__thread time_stats_updater_t *thread_time_stats_updater = NULL;
}}}

using namespace ioremap::cache;

int dnet_cmd_cache_io(struct dnet_net_state *st, struct dnet_cmd *cmd, struct dnet_io_attr *io, char *data)
{
	struct dnet_node *n = st->n;
	int err = -ENOTSUP;

	if (!n->cache) {
		if (io->flags & DNET_IO_FLAGS_CACHE) {
			dnet_log(n, DNET_LOG_NOTICE, "%s: cache is not supported\n", dnet_dump_id(&cmd->id));
		}
		return -ENOTSUP;
	}

	cache_manager *cache = (cache_manager *)n->cache;
	std::shared_ptr<raw_data_t> d;
	time_stats_updater_t time_stats_updater;
	ioremap::cache::local::thread_time_stats_updater = &time_stats_updater;

	try {
		switch (cmd->cmd) {
			case DNET_CMD_WRITE:
				err = cache->write(io->id, st, cmd, io, data);
				break;
			case DNET_CMD_READ:
				d = cache->read(io->id, cmd, io);
				if (!d) {
					if (!(io->flags & DNET_IO_FLAGS_CACHE)) {
						return -ENOTSUP;
					}

					err = -ENOENT;
					break;
				}

				if (io->offset + io->size > d->size()) {
					dnet_log_raw(n, DNET_LOG_ERROR, "%s: %s cache: invalid offset/size: "
							"offset: %llu, size: %llu, cached-size: %zd\n",
							dnet_dump_id(&cmd->id), dnet_cmd_string(cmd->cmd),
							(unsigned long long)io->offset, (unsigned long long)io->size,
							d->size());
					err = -EINVAL;
					break;
				}

				if (io->size == 0)
					io->size = d->size() - io->offset;

				cmd->flags &= ~DNET_FLAGS_NEED_ACK;
				err = dnet_send_read_data(st, cmd, io, (char *)d->data().data() + io->offset, -1, io->offset, 0);
				break;
			case DNET_CMD_DEL:
				err = cache->remove(cmd->id.id, io);
				break;
		}
	} catch (const std::exception &e) {
		dnet_log_raw(n, DNET_LOG_ERROR, "%s: %s cache operation failed: %s\n",
				dnet_dump_id(&cmd->id), dnet_cmd_string(cmd->cmd), e.what());
		err = -ENOENT;
	}

	ioremap::cache::local::thread_time_stats_updater = NULL;
	return err;
}

int dnet_cmd_cache_indexes(struct dnet_net_state *st, struct dnet_cmd *cmd, struct dnet_indexes_request *request)
{
	struct dnet_node *n = st->n;
	int err = -ENOTSUP;

	if (!n->cache) {
		dnet_log(n, DNET_LOG_ERROR, "%s: cache is not supported\n", dnet_dump_id(&cmd->id));
		return -ENOTSUP;
	}

	cache_manager *cache = (cache_manager *)n->cache;
	time_stats_updater_t time_stats_updater;
	ioremap::cache::local::thread_time_stats_updater = &time_stats_updater;

	try {
		switch (cmd->cmd) {
			case DNET_CMD_INDEXES_FIND:
				err = cache->indexes_find(cmd, request);
				break;
			case DNET_CMD_INDEXES_UPDATE:
				err = cache->indexes_update(cmd, request);
				break;
			case DNET_CMD_INDEXES_INTERNAL:
				err = cache->indexes_internal(cmd, request);
				break;
		}
	} catch (const std::exception &e) {
		dnet_log_raw(n, DNET_LOG_ERROR, "%s: %s cache operation failed: %s\n",
				dnet_dump_id(&cmd->id), dnet_cmd_string(cmd->cmd), e.what());
		err = -ENOENT;
	}

	ioremap::cache::local::thread_time_stats_updater = NULL;
	return err;
}

int dnet_cmd_cache_lookup(struct dnet_net_state *st, struct dnet_cmd *cmd)
{
	struct dnet_node *n = st->n;
	int err = -ENOTSUP;

	if (!n->cache) {
		return -ENOTSUP;
	}

	cache_manager *cache = (cache_manager *)n->cache;
	time_stats_updater_t time_stats_updater;
	ioremap::cache::local::thread_time_stats_updater = &time_stats_updater;

	try {
		err = cache->lookup(cmd->id.id, st, cmd);
	} catch (const std::exception &e) {
		dnet_log_raw(n, DNET_LOG_ERROR, "%s: %s cache operation failed: %s\n",
				dnet_dump_id(&cmd->id), dnet_cmd_string(cmd->cmd), e.what());
		err = -ENOENT;
	}

	ioremap::cache::local::thread_time_stats_updater = NULL;
	return err;
}

int dnet_cache_init(struct dnet_node *n)
{
	if (!n->cache_size)
		return 0;

	try {
		n->cache = (void *)(new cache_manager(n));
	} catch (const std::exception &e) {
		dnet_log_raw(n, DNET_LOG_ERROR, "Could not create cache: %s\n", e.what());
		return -ENOMEM;
	}

	return 0;
}

void dnet_cache_cleanup(struct dnet_node *n)
{
	if (n->cache) {
		delete (cache_manager *)n->cache;
	}
}
