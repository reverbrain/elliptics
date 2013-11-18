/*
 * 2012+ Copyright (c) Evgeniy Polyakov <zbr@ioremap.net>
 * All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include "cache.hpp"
#include "lru_cache.hpp"
#include "slru_cache.hpp"

namespace ioremap { namespace cache {

class cache_manager {
	public:
		cache_manager(struct dnet_node *n, int num = 16) {
			size_t max_size = (n->cache_size) / num;
			std::vector<size_t> pages_max_sizes = {max_size / 2, max_size / 2};
			for (int i  = 0; i < num; ++i) {
//				m_caches.emplace_back(std::make_shared<lru_cache_t>(n, n->cache_size / num));
				m_caches.emplace_back(std::make_shared<slru_cache_t>(n, pages_max_sizes));
			}
		}

		~cache_manager() {
			//Stops all caches in parallel. Avoids sleeping in all cache distructors
			for (auto it(m_caches.begin()), end(m_caches.end()); it != end; ++it) {
				(*it)->stop(); //Sets cache as stopped
			}
		}

		int write(const unsigned char *id, dnet_net_state *st, dnet_cmd *cmd, dnet_io_attr *io, const char *data) {
			return m_caches[idx(id)]->write(id, st, cmd, io, data);
		}

		std::shared_ptr<raw_data_t> read(const unsigned char *id, dnet_cmd *cmd, dnet_io_attr *io) {
			return m_caches[idx(id)]->read(id, cmd, io);
		}

		int remove(const unsigned char *id, dnet_io_attr *io) {
			return m_caches[idx(id)]->remove(id, io);
		}

		int lookup(const unsigned char *id, dnet_net_state *st, dnet_cmd *cmd) {
			return m_caches[idx(id)]->lookup(id, st, cmd);
		}

		int indexes_find(dnet_cmd *cmd, dnet_indexes_request *request) {
			(void) cmd;
			(void) request;
			return -ENOTSUP;
		}

		int indexes_update(dnet_cmd *cmd, dnet_indexes_request *request) {
			(void) cmd;
			(void) request;
			return -ENOTSUP;
		}

		int indexes_internal(dnet_cmd *cmd, dnet_indexes_request *request) {
			(void) cmd;
			(void) request;
			return -ENOTSUP;
		}

	private:
		std::vector<std::shared_ptr<slru_cache_t>> m_caches;

		size_t idx(const unsigned char *id) {
			unsigned i = *(unsigned *)id;
			return i % m_caches.size();
		}
};

}}

using namespace ioremap::cache;

int dnet_cmd_cache_io(struct dnet_net_state *st, struct dnet_cmd *cmd, struct dnet_io_attr *io, char *data)
{
	struct dnet_node *n = st->n;
	int err = -ENOTSUP;

	if (!n->cache) {
		dnet_log(n, DNET_LOG_NOTICE, "%s: cache is not supported\n", dnet_dump_id(&cmd->id));
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
		n->cache = (void *)(new cache_manager(n, 16));
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
