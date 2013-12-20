/*
 * 2012+ Copyright (c) Evgeniy Polyakov <zbr@ioremap.net>
 * All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 */

#include "cache.hpp"
#include "slru_cache.hpp"

#include <fstream>

namespace ioremap { namespace cache {

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

	stop = false;
	m_dump_stats = std::thread(std::bind(&cache_manager::dump_stats, this));
}

cache_manager::~cache_manager() {
	//Stops all caches in parallel. Avoids sleeping in all cache distructors
	for (auto it(m_caches.begin()), end(m_caches.end()); it != end; ++it) {
		(*it)->stop(); //Sets cache as stopped
	}
	stop = true;
	m_dump_stats.join();
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
	for (size_t i = 0; i < m_caches.size(); ++i) {
		m_caches[i]->clear();
	}
}

size_t cache_manager::cache_size() const
{
	return m_max_cache_size;
}

size_t cache_manager::cache_pages_number() const
{
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

		stats.total_lifecheck_time += page_stats.total_lifecheck_time;
		stats.total_write_time += page_stats.total_write_time;
		stats.total_write_find_time += page_stats.total_write_find_time;
		stats.total_write_create_data_time += page_stats.total_write_create_data_time;
		stats.total_write_populate_from_disk_time += page_stats.total_write_populate_from_disk_time;
		stats.total_write_resize_page_time += page_stats.total_write_resize_page_time;
		stats.total_read_time += page_stats.total_read_time;
		stats.total_remove_time += page_stats.total_remove_time;
		stats.total_lookup_time += page_stats.total_lookup_time;
		stats.total_resize_time += page_stats.total_resize_time;

		for (size_t j = 0; j < m_cache_pages_number; ++j) {
			stats.pages_sizes[j] += page_stats.pages_sizes[j];
			stats.pages_max_sizes[j] += page_stats.pages_max_sizes[j];
		}
	}
	return stats;
}

std::vector<cache_stats> cache_manager::get_caches_stats() const
{
	std::vector<cache_stats> caches_stats;
	for (size_t i = 0; i < m_caches.size(); ++i) {
		caches_stats.push_back(m_caches[i]->get_cache_stats());
	}
	return caches_stats;
}

void cache_manager::dump_stats() const
{
	while (!stop) {
		std::ofstream os("cache.stat");
		std::vector<cache_stats> stats = get_caches_stats();

		{
			cache_stats stat = get_total_cache_stats();
			os << "TOTAL" << "\n"
				<< "number_of_objects " << stat.number_of_objects << "\n"
				<< "size_of_objects " << stat.size_of_objects << "\n"
				<< "number_of_objects_marked_for_deletion " << stat.number_of_objects_marked_for_deletion << "\n"
				<< "size_of_objects_marked_for_deletion " << stat.size_of_objects_marked_for_deletion << "\n"
				<< "total_lifecheck_time " << stat.total_lifecheck_time << "\n"
				<< "total_write_time " << stat.total_write_time << "\n"
				<< "total_write_find_time " << stat.total_write_find_time << "\n"
				<< "total_write_create_data_time " << stat.total_write_create_data_time << "\n"
				<< "total_write_populate_from_disk_time " << stat.total_write_populate_from_disk_time << "\n"
				<< "total_write_resize_time " << stat.total_write_resize_page_time << "\n"
				<< "total_read_time " << stat.total_read_time << "\n"
				<< "total_remove_time " << stat.total_remove_time << "\n"
				<< "total_lookup_time " << stat.total_lookup_time << "\n"
				<< "total_resize_time " << stat.total_resize_time << "\n";
			os << "\n";
		}

		for (size_t i = 0; i < stats.size(); ++i) {
			cache_stats stat = stats[i];

			os << "CACHE " << i << "\n"
				<< "number_of_objects " << stat.number_of_objects << "\n"
				<< "size_of_objects " << stat.size_of_objects << "\n"
				<< "number_of_objects_marked_for_deletion " << stat.number_of_objects_marked_for_deletion << "\n"
				<< "size_of_objects_marked_for_deletion " << stat.size_of_objects_marked_for_deletion << "\n"
				<< "total_lifecheck_time " << stat.total_lifecheck_time << "\n"
				<< "total_write_time " << stat.total_write_time << "\n"
				<< "total_write_find_time " << stat.total_write_find_time << "\n"
				<< "total_write_create_data_time " << stat.total_write_create_data_time << "\n"
				<< "total_write_populate_from_disk_time " << stat.total_write_populate_from_disk_time << "\n"
				<< "total_write_resize_time " << stat.total_write_resize_page_time << "\n"
				<< "total_read_time " << stat.total_read_time << "\n"
				<< "total_remove_time " << stat.total_remove_time << "\n"
				<< "total_lookup_time " << stat.total_lookup_time << "\n"
				<< "total_resize_time " << stat.total_resize_time << "\n";
			os << "\n";
		}
		os.close();
		sleep(1);
	}
}

size_t cache_manager::idx(const unsigned char *id) {
	size_t i = *(size_t *)id;
	size_t j = *(size_t *)(id + DNET_ID_SIZE - sizeof(size_t));
	return (i ^ j) % m_caches.size();
}

}}

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

	return err;
}

int dnet_cmd_cache_lookup(struct dnet_net_state *st, struct dnet_cmd *cmd)
{
	struct dnet_node *n = st->n;
	int err = -ENOTSUP;

	if (!n->cache) {
		dnet_log(n, DNET_LOG_ERROR, "%s: cache is not supported\n", dnet_dump_id(&cmd->id));
		return -ENOTSUP;
	}

	cache_manager *cache = (cache_manager *)n->cache;

	try {
		cache->lookup(cmd->id.id, st, cmd);
	} catch (const std::exception &e) {
		dnet_log_raw(n, DNET_LOG_ERROR, "%s: %s cache operation failed: %s\n",
				dnet_dump_id(&cmd->id), dnet_cmd_string(cmd->cmd), e.what());
		err = -ENOENT;
	}

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
	if (n->cache)
		delete (cache_manager *)n->cache;
}
