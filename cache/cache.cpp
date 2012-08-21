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
#include <vector>

#include <boost/unordered_map.hpp>
#include <boost/shared_array.hpp>
#include <boost/shared_ptr.hpp>
#include <boost/make_shared.hpp>
#include <boost/thread.hpp>
#include <boost/intrusive/list.hpp>
#include <boost/intrusive/set.hpp>

#include "../library/elliptics.h"

#include "elliptics/packet.h"
#include "elliptics/interface.h"

namespace ioremap { namespace cache {

struct key_t {
	key_t(const unsigned char *id) {
		memcpy(this->id, id, DNET_ID_SIZE);
	}

	unsigned char id[DNET_ID_SIZE];
};

size_t hash(const unsigned char *id) {
	size_t num = DNET_ID_SIZE / sizeof(size_t);

	size_t *ptr = (size_t *)id;
	size_t hash = 0x883eaf5a;
	for (size_t i = 0; i < num; ++i)
		hash ^= ptr[i];

	return hash;
}

struct hash_t {
	std::size_t operator()(const key_t &key) const {
		return ioremap::cache::hash(key.id);
	}
};

struct equal_to {
	bool operator() (const key_t &x, const key_t &y) const {
		return memcmp(x.id, y.id, DNET_ID_SIZE) == 0;
	}
};

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

		data_t(const unsigned char *id, size_t lifetime, const char *data, size_t size) : m_lifetime(0) {
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

		boost::shared_ptr<raw_data_t> data(void) const {
			return m_data;
		}

		size_t lifetime(void) const {
			return m_lifetime;
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
		struct dnet_raw_id m_id;
		boost::shared_ptr<raw_data_t> m_data;
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
		cache_t(size_t cache_size) : m_need_exit(false), m_cache_size(0), m_max_cache_size(cache_size) {
			m_lifecheck = boost::thread(boost::bind(&cache_t::life_check, this));
		}

		~cache_t() {
			m_need_exit = true;
			m_lifecheck.join();

			while (!m_lru.empty()) {
				data_t raw = m_lru.front();
				erase_element(&raw);
			}
		}

		void write(const unsigned char *id, size_t lifetime, const char *data, size_t size) {
			boost::mutex::scoped_lock guard(m_lock);

			iset_t::iterator it = m_set.find(id);
			if (it != m_set.end())
				erase_element(&(*it));

			if (size + m_cache_size > m_max_cache_size)
				resize(size * 2);

			/*
			 * nothing throws exception below this 'new' operator, so there is no try/catch block
			 */
			data_t *raw = new data_t(id, lifetime, data, size);

			m_set.insert(*raw);
			m_lru.push_back(*raw);
			if (lifetime)
				m_lifeset.insert(*raw);

			m_cache_size += size;
		}

		boost::shared_ptr<raw_data_t> read(const unsigned char *id) {
			boost::mutex::scoped_lock guard(m_lock);

			iset_t::iterator it = m_set.find(id);
			if (it == m_set.end())
				throw std::runtime_error("no record");

			m_lru.erase(m_lru.iterator_to(*it));
			m_lru.push_back(*it);
			return it->data();
		}

		bool remove(const unsigned char *id) {
			bool removed = false;

			boost::mutex::scoped_lock guard(m_lock);
			iset_t::iterator it = m_set.find(id);
			if (it != m_set.end()) {
				erase_element(&(*it));
				removed = true;
			}

			return removed;
		}

	private:
		bool m_need_exit;
		size_t m_cache_size, m_max_cache_size;
		boost::mutex m_lock;
		iset_t m_set;
		lru_list_t m_lru;
		life_set_t m_lifeset;
		boost::thread m_lifecheck;

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
				while (!m_need_exit && !m_lifeset.empty()) {
					size_t time = ::time(NULL);

					boost::mutex::scoped_lock guard(m_lock);

					if (m_lifeset.empty())
						break;

					life_set_t::iterator it = m_lifeset.begin();
					if (it->lifetime() > time)
						break;

					erase_element(&(*it));
				}

				sleep(1);
			}
		}
};

}}

using namespace ioremap::cache;

int dnet_cmd_cache_io(struct dnet_net_state *st, struct dnet_cmd *cmd, char *data)
{
	struct dnet_node *n = st->n;
	int err = -ENOTSUP;

	if (!n->cache)
		return -ENOTSUP;

	cache_t *cache = (cache_t *)n->cache;

	try {
		struct dnet_io_attr *io = (struct dnet_io_attr *)data;
		boost::shared_ptr<raw_data_t> d;

		data += sizeof(struct dnet_io_attr);

		switch (cmd->cmd) {
			case DNET_CMD_WRITE:
				cache->write(io->id, io->start, data, io->size);
				err = 0;
				break;
			case DNET_CMD_READ:
				d = cache->read(io->id);
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
		n->cache = (void *)(new cache_t(n->cache_size));
	} catch (const std::exception &e) {
		dnet_log_raw(n, DNET_LOG_ERROR, "Could not create cache: %s\n", e.what());
		return -ENOMEM;
	}

	return 0;
}

void dnet_cache_cleanup(struct dnet_node *n)
{
	if (n->cache)
		delete (cache_t *)n->cache;
}
