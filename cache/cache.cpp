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

#include <iostream>
#include <deque>
#include <vector>
#include <deque>
#include <mutex>
#include <thread>

#include <boost/unordered_map.hpp>
#include <boost/intrusive/list.hpp>
#include <boost/intrusive/set.hpp>

#include "../library/elliptics.h"

#include "elliptics/packet.h"
#include "elliptics/interface.h"

namespace ioremap { namespace cache {

class raw_data_t {
	public:
		raw_data_t(const char *data, size_t size) {
			m_data.reserve(size);
			m_data.insert(m_data.begin(), data, data + size);
		}

		std::vector<char> &data(void) {
			return m_data;
		}

		size_t size(void) {
			return m_data.size();
		}

	private:
		std::vector<char> m_data;
};

struct data_lru_tag_t;
typedef boost::intrusive::list_base_hook<boost::intrusive::tag<data_lru_tag_t>,
					 boost::intrusive::link_mode<boost::intrusive::safe_link>
					> lru_list_base_hook_t;
struct data_set_tag_t;
typedef boost::intrusive::set_base_hook<boost::intrusive::tag<data_set_tag_t>,
					 boost::intrusive::link_mode<boost::intrusive::safe_link>
					> set_base_hook_t;

struct time_set_tag_t;
typedef boost::intrusive::set_base_hook<boost::intrusive::tag<time_set_tag_t>,
					 boost::intrusive::link_mode<boost::intrusive::safe_link>
					> time_set_base_hook_t;

class data_t : public lru_list_base_hook_t, public set_base_hook_t, public time_set_base_hook_t {
	public:
		data_t(const unsigned char *id) : m_lifetime(0) {
			memcpy(m_id.id, id, DNET_ID_SIZE);
		}

		data_t(const unsigned char *id, size_t lifetime, const char *data, size_t size, bool remove_from_disk) :
		m_lifetime(0), m_remove_from_disk(remove_from_disk) {
			memcpy(m_id.id, id, DNET_ID_SIZE);

			if (lifetime)
				m_lifetime = lifetime + time(NULL);

			m_data.reset(new raw_data_t(data, size));
		}

		~data_t() {
		}

		const struct dnet_raw_id &id(void) const {
			return m_id;
		}

		std::shared_ptr<raw_data_t> data(void) const {
			return m_data;
		}

		size_t lifetime(void) const {
			return m_lifetime;
		}

		bool remove_from_disk() const {
			return m_remove_from_disk;
		}

		size_t size(void) const {
			return m_data->size();
		}

		friend bool operator< (const data_t &a, const data_t &b) {
			return dnet_id_cmp_str(a.id().id, b.id().id) < 0;
		}

		friend bool operator> (const data_t &a, const data_t &b) {
			return dnet_id_cmp_str(a.id().id, b.id().id) > 0;
		}

		friend bool operator== (const data_t &a, const data_t &b) {
			return dnet_id_cmp_str(a.id().id, b.id().id) == 0;
		}

	private:
		size_t m_lifetime;
		bool m_remove_from_disk;
		struct dnet_raw_id m_id;
		std::shared_ptr<raw_data_t> m_data;
};

typedef boost::intrusive::list<data_t, boost::intrusive::base_hook<lru_list_base_hook_t> > lru_list_t;
typedef boost::intrusive::set<data_t, boost::intrusive::base_hook<set_base_hook_t>,
					  boost::intrusive::compare<std::less<data_t> >
			     > iset_t;

struct lifetime_less {
	bool operator() (const data_t &x, const data_t &y) const {
		return x.lifetime() < y.lifetime();
	}
};

typedef boost::intrusive::set<data_t, boost::intrusive::base_hook<time_set_base_hook_t>,
					  boost::intrusive::compare<lifetime_less>
			     > life_set_t;

class cache_t {
	public:
		cache_t(struct dnet_node *n, size_t max_size) :
		m_need_exit(false),
		m_node(n),
		m_cache_size(0),
		m_max_cache_size(max_size) {
			m_lifecheck = std::thread(std::bind(&cache_t::life_check, this));
		}

		~cache_t() {
			stop();
			m_lifecheck.join();

			while (!m_lru.empty()) {
				data_t raw = m_lru.front();
				erase_element(&raw);
			}
		}

		void stop(void) {
			m_need_exit = true;
		}

		void write(const unsigned char *id, size_t lifetime, const char *data, size_t size, bool remove_from_disk) {
			std::lock_guard<std::mutex> guard(m_lock);

			iset_t::iterator it = m_set.find(id);
			if (it != m_set.end())
				erase_element(&(*it));

			if (size + m_cache_size > m_max_cache_size)
				resize(size * 2);

			/*
			 * nothing throws exception below this 'new' operator, so there is no try/catch block
			 */
			data_t *raw = new data_t(id, lifetime, data, size, remove_from_disk);

			m_set.insert(*raw);
			m_lru.push_back(*raw);
			if (lifetime)
				m_lifeset.insert(*raw);

			m_cache_size += size;
		}

		std::shared_ptr<raw_data_t> read(const unsigned char *id) {
			std::lock_guard<std::mutex> guard(m_lock);

			iset_t::iterator it = m_set.find(id);
			if (it != m_set.end()) {
				m_lru.erase(m_lru.iterator_to(*it));
				m_lru.push_back(*it);
				return it->data();
			}

			return std::shared_ptr<raw_data_t>();
		}

		bool remove(const unsigned char *id) {
			bool removed = false;
			bool remove_from_disk = false;

			std::unique_lock<std::mutex> guard(m_lock);
			iset_t::iterator it = m_set.find(id);
			if (it != m_set.end()) {
				remove_from_disk = it->remove_from_disk();
				erase_element(&(*it));
				removed = true;
			}

			guard.unlock();

			if (remove_from_disk) {
				struct dnet_id raw;
				memset(&raw, 0, sizeof(struct dnet_id));

				dnet_setup_id(&raw, 0, (unsigned char *)id);

				dnet_remove_local(m_node, &raw);
			}

			return removed;
		}

	private:
		bool m_need_exit;
		struct dnet_node *m_node;
		size_t m_cache_size, m_max_cache_size;
		std::mutex m_lock;
		iset_t m_set;
		lru_list_t m_lru;
		life_set_t m_lifeset;
		std::thread m_lifecheck;

		cache_t(const cache_t &) = delete;

		void resize(size_t reserve) {
			while (!m_lru.empty()) {
				data_t *raw = &m_lru.front();

				erase_element(raw);


				/* break early if free space in cache more than requested reserve */
				if (m_max_cache_size - m_cache_size > reserve)
					break;
			}
		}

		void erase_element(data_t *obj) {
			m_lru.erase(m_lru.iterator_to(*obj));
			m_set.erase(m_set.iterator_to(*obj));
			if (obj->lifetime())
				m_lifeset.erase(m_lifeset.iterator_to(*obj));

			m_cache_size -= obj->size();

			delete obj;
		}

		void life_check(void) {
			while (!m_need_exit) {
				std::deque<struct dnet_id> remove;

				while (!m_need_exit && !m_lifeset.empty()) {
					size_t time = ::time(NULL);

					std::lock_guard<std::mutex> guard(m_lock);

					if (m_lifeset.empty())
						break;

					life_set_t::iterator it = m_lifeset.begin();
					if (it->lifetime() > time)
						break;

					if (it->remove_from_disk()) {
						struct dnet_id id;
						memset(&id, 0, sizeof(struct dnet_id));

						dnet_setup_id(&id, 0, (unsigned char *)it->id().id);

						remove.push_back(id);
					}

					erase_element(&(*it));
				}

				for (std::deque<struct dnet_id>::iterator it = remove.begin(); it != remove.end(); ++it) {
					dnet_remove_local(m_node, &(*it));
				}

				sleep(1);
			}
		}
};

class cache_manager {
	public:
		cache_manager(struct dnet_node *n, int num = 16) {
			for (int i  = 0; i < num; ++i) {
				m_caches.emplace_back(std::make_shared<cache_t>(n, n->cache_size / num));
			}
		}

		~cache_manager() {
			for (auto it = m_caches.begin(); it != m_caches.end(); ++it) {
				(*it)->stop();
			}
		}

		void write(const unsigned char *id, size_t lifetime, const char *data, size_t size, bool remove_from_disk) {
			m_caches[idx(id)]->write(id, lifetime, data, size, remove_from_disk);
		}

		std::shared_ptr<raw_data_t> read(const unsigned char *id) {
			return m_caches[idx(id)]->read(id);
		}

		bool remove(const unsigned char *id) {
			return m_caches[idx(id)]->remove(id);
		}

	private:
		std::vector<std::shared_ptr<cache_t>> m_caches;

		int idx(const unsigned char *id) {
			int i = *(int *)id;
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
		dnet_log(n, DNET_LOG_ERROR, "%s: cache is not supported\n", dnet_dump_id(&cmd->id));
		return -ENOTSUP;
	}

	cache_manager *cache = (cache_manager *)n->cache;

	try {
		std::shared_ptr<raw_data_t> d;

		switch (cmd->cmd) {
			case DNET_CMD_WRITE:
				if (io->flags & DNET_IO_FLAGS_COMPARE_AND_SWAP) {
					d = cache->read(io->id);
					if (d) {
						struct dnet_raw_id csum;
						dnet_transform_node(n, d->data().data(), d->data().size(), csum.id, sizeof(csum.id));

						if (memcmp(csum.id, io->parent, DNET_ID_SIZE)) {
							dnet_log(n, DNET_LOG_ERROR, "%s: cas: cache checksum mismatch\n", dnet_dump_id(&cmd->id));
							err = -EBADFD;
							break;
						}
					}
				}

				cache->write(io->id, io->start, data, io->size, !!(io->flags & DNET_IO_FLAGS_CACHE_REMOVE_FROM_DISK));
				err = 0;
				break;
			case DNET_CMD_READ:
				d = cache->read(io->id);
				if (!d) {
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

				io->size = d->size();
				cmd->flags &= ~DNET_FLAGS_NEED_ACK;
				err = dnet_send_read_data(st, cmd, io, (char *)d->data().data() + io->offset, -1, io->offset, 0);
				break;
			case DNET_CMD_DEL:
				err = -ENOENT;
				if (cache->remove(cmd->id.id))
					err = 0;
				break;
		}
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
