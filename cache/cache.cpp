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
#include "../indexes/local_session.h"

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

struct sync_set_tag_t;
typedef boost::intrusive::set_base_hook<boost::intrusive::tag<sync_set_tag_t>,
					 boost::intrusive::link_mode<boost::intrusive::safe_link>
					> sync_set_base_hook_t;

class data_t : public lru_list_base_hook_t, public set_base_hook_t, public time_set_base_hook_t, public sync_set_base_hook_t {
	public:
		data_t(const unsigned char *id)
		{
			memcpy(m_id.id, id, DNET_ID_SIZE);
		}

		data_t(const unsigned char *id, size_t lifetime, const char *data, size_t size, bool remove_from_disk) :
			m_lifetime(0), m_synctime(0), m_user_flags(0),
			m_remove_from_disk(remove_from_disk), m_remove_from_cache(false), m_only_append(false)
			{
			memcpy(m_id.id, id, DNET_ID_SIZE);
			dnet_empty_time(&m_timestamp);

			if (lifetime)
				m_lifetime = lifetime + time(NULL);

			m_data.reset(new raw_data_t(data, size));
		}

		data_t(const data_t &other) = delete;
		data_t &operator =(const data_t &other) = delete;

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

		void set_lifetime(size_t lifetime) {
			m_lifetime = lifetime;
		}

		size_t synctime() const {
			return m_synctime;
		}

		void set_synctime(size_t synctime) {
			m_synctime = synctime;
		}

		void clear_synctime() {
			m_synctime = 0;
		}

		const dnet_time &timestamp() const {
			return m_timestamp;
		}

		void set_timestamp(const dnet_time &timestamp) {
			m_timestamp = timestamp;
		}

		uint64_t user_flags() const {
			return m_user_flags;
		}

		void set_user_flags(uint64_t user_flags) {
			m_user_flags = user_flags;
		}

		bool remove_from_disk() const {
			return m_remove_from_disk;
		}

		bool remove_from_cache() const {
			return m_remove_from_cache;
		}

		void set_remove_from_cache(bool remove_from_cache) {
			m_remove_from_cache = remove_from_cache;
		}

		bool only_append() const {
			return m_only_append;
		}

		void set_only_append(bool only_append) {
			m_only_append = only_append;
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
		size_t m_synctime;
		dnet_time m_timestamp;
		uint64_t m_user_flags;
		bool m_remove_from_disk;
		bool m_remove_from_cache;
		bool m_only_append;
		struct dnet_raw_id m_id;
		std::shared_ptr<raw_data_t> m_data;
};

typedef boost::intrusive::list<data_t, boost::intrusive::base_hook<lru_list_base_hook_t> > lru_list_t;
typedef boost::intrusive::set<data_t, boost::intrusive::base_hook<set_base_hook_t>,
					  boost::intrusive::compare<std::less<data_t> >
			     > iset_t;

struct lifetime_less {
	bool operator() (const data_t &x, const data_t &y) const {
		return x.lifetime() < y.lifetime()
			|| (x.lifetime() == y.lifetime() && ((&x) < (&y)));
	}
};

typedef boost::intrusive::set<data_t, boost::intrusive::base_hook<time_set_base_hook_t>,
					  boost::intrusive::compare<lifetime_less>
			     > life_set_t;

struct synctime_less {
	bool operator() (const data_t &x, const data_t &y) const {
		return x.synctime() < y.synctime()
			|| (x.synctime() == y.synctime() && ((&x) < (&y)));
	}
};

typedef boost::intrusive::set<data_t, boost::intrusive::base_hook<sync_set_base_hook_t>,
					  boost::intrusive::compare<synctime_less>
			     > sync_set_t;

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

			m_max_cache_size = 0; //sets max_size to 0 for erasing lru set
			resize(0);

			std::lock_guard<std::mutex> guard(m_lock);

			while(!m_syncset.empty()) { //removes datas from syncset
				erase_element(&*m_syncset.begin());
			}

			while(!m_lifeset.empty()) { //removes datas from lifeset
				erase_element(&*m_lifeset.begin());
			}
		}

		void stop() {
			m_need_exit = true;
		}

		int write(const unsigned char *id, dnet_net_state *st, dnet_cmd *cmd, dnet_io_attr *io, const char *data) {
			const size_t lifetime = io->start;
			const size_t size = io->size;
			const bool remove_from_disk = (io->flags & DNET_IO_FLAGS_CACHE_REMOVE_FROM_DISK);
			const bool cache = (io->flags & DNET_IO_FLAGS_CACHE);
			const bool cache_only = (io->flags & DNET_IO_FLAGS_CACHE_ONLY);
			const bool append = (io->flags & DNET_IO_FLAGS_APPEND);

			dnet_log(m_node, DNET_LOG_DEBUG, "%s: CACHE: before guard\n", dnet_dump_id_str(id));
			std::unique_lock<std::mutex> guard(m_lock);
			dnet_log(m_node, DNET_LOG_DEBUG, "%s: CACHE: after guard\n", dnet_dump_id_str(id));

			iset_t::iterator it = m_set.find(id);

			if (it == m_set.end() && !cache) {
				dnet_log(m_node, DNET_LOG_DEBUG, "%s: CACHE: not a cache call\n", dnet_dump_id_str(id));
				return -ENOTSUP;
			}

			// Optimization for append-only commands
			if (!cache_only) {
				if (append && (it == m_set.end() || it->only_append())) {
					if (it == m_set.end()) {
						it = create_data(id, 0, 0, false);
						it->set_only_append(true);
						it->set_synctime(time(NULL) + m_node->cache_sync_timeout);
						m_syncset.insert(*it);
					}

					auto &raw = it->data()->data();

					m_cache_size -= raw.size();
					m_lru.erase(m_lru.iterator_to(*it));

					const size_t new_size = raw.size() + io->size;

					if (m_cache_size + new_size > m_max_cache_size) {
						dnet_log(m_node, DNET_LOG_DEBUG, "%s: CACHE: resize called\n", dnet_dump_id_str(id));
						resize(new_size * 2);
						dnet_log(m_node, DNET_LOG_DEBUG, "%s: CACHE: resize finished\n", dnet_dump_id_str(id));
					}

					m_lru.push_back(*it);
					m_cache_size += new_size;

					raw.insert(raw.end(), data, data + io->size);

					it->set_timestamp(io->timestamp);
					it->set_user_flags(io->user_flags);

					cmd->flags &= ~DNET_FLAGS_NEED_ACK;
					return dnet_send_file_info_ts_without_fd(st, cmd, data, io->size, &io->timestamp);
				} else if (it != m_set.end() && it->only_append()) {
					sync_after_append(guard, false, &*it);

					local_session sess(m_node);
					sess.set_ioflags(DNET_IO_FLAGS_NOCACHE | DNET_IO_FLAGS_APPEND);

					int err = m_node->cb->command_handler(st, m_node->cb->command_private, cmd, io);
					dnet_log(m_node, DNET_LOG_DEBUG, "%s: CACHE: second write result, err: %d", dnet_dump_id_str(id), err);

					it = populate_from_disk(guard, id, false, &err);

					dnet_log(m_node, DNET_LOG_DEBUG, "%s: CACHE: read result, err: %d", dnet_dump_id_str(id), err);
					cmd->flags &= ~DNET_FLAGS_NEED_ACK;
					return err;
				}
			}

			if (it == m_set.end()) {
				dnet_log(m_node, DNET_LOG_DEBUG, "%s: CACHE: not exist\n", dnet_dump_id_str(id));
				// If file not found and CACHE flag is not set - fallback to backend request
				if (!cache_only && io->offset != 0) {
					int err = 0;
					it = populate_from_disk(guard, id, remove_from_disk, &err);

					if (err != 0 && err != -ENOENT)
						return err;
				}

				// Create empty data for code simplifing
				if (it == m_set.end())
					it = create_data(id, 0, 0, remove_from_disk);
			} else {
				dnet_log(m_node, DNET_LOG_DEBUG, "%s: CACHE: exists\n", dnet_dump_id_str(id));
			}
			dnet_log(m_node, DNET_LOG_DEBUG, "%s: CACHE: data ensured\n", dnet_dump_id_str(id));

			raw_data_t &raw = *it->data();

			if (io->flags & DNET_IO_FLAGS_COMPARE_AND_SWAP) {
				// Data is already in memory, so it's free to use it
				// raw.size() is zero only if there is no such file on the server
				if (raw.size() != 0) {
					struct dnet_raw_id csum;
					dnet_transform_node(m_node, raw.data().data(), raw.size(), csum.id, sizeof(csum.id));

					if (memcmp(csum.id, io->parent, DNET_ID_SIZE)) {
						dnet_log(m_node, DNET_LOG_ERROR, "%s: cas: cache checksum mismatch\n", dnet_dump_id(&cmd->id));
						return -EBADFD;
					}
				}
			}

			dnet_log(m_node, DNET_LOG_DEBUG, "%s: CACHE: CAS checked\n", dnet_dump_id_str(id));

			size_t new_size = 0;

			if (append) {
				new_size = raw.size() + size;
			} else {
				new_size = io->offset + io->size;
			}

			// Recalc used space, free enough space for new data, move object to the end of the queue
			m_cache_size -= raw.size();
			m_lru.erase(m_lru.iterator_to(*it));

			if (m_cache_size + new_size > m_max_cache_size) {
				dnet_log(m_node, DNET_LOG_DEBUG, "%s: CACHE: resize called\n", dnet_dump_id_str(id));
				resize(new_size * 2);
				dnet_log(m_node, DNET_LOG_DEBUG, "%s: CACHE: resize finished\n", dnet_dump_id_str(id));
			}

			m_lru.push_back(*it);
			it->set_remove_from_cache(false);
			m_cache_size += new_size;

			if (append) {
				raw.data().insert(raw.data().end(), data, data + size);
			} else {
				raw.data().resize(new_size);
				memcpy(raw.data().data() + io->offset, data, size);
			}

			dnet_log(m_node, DNET_LOG_DEBUG, "%s: CACHE: data modified\n", dnet_dump_id_str(id));

			// Mark data as dirty one, so it will be synced to the disk
			if (!it->synctime() && !(io->flags & DNET_IO_FLAGS_CACHE_ONLY)) {
				it->set_synctime(time(NULL) + m_node->cache_sync_timeout);
				m_syncset.insert(*it);
			}

			if (it->lifetime())
				m_lifeset.erase(m_lifeset.iterator_to(*it));

			if (lifetime) {
				it->set_lifetime(lifetime + time(NULL));
				m_lifeset.insert(*it);
			}

			it->set_timestamp(io->timestamp);
			it->set_user_flags(io->user_flags);

			dnet_log(m_node, DNET_LOG_DEBUG, "%s: CACHE: finished write\n", dnet_dump_id_str(id));

			cmd->flags &= ~DNET_FLAGS_NEED_ACK;
			return dnet_send_file_info_ts_without_fd(st, cmd, raw.data().data() + io->offset, io->size, &io->timestamp);
		}

		std::shared_ptr<raw_data_t> read(const unsigned char *id, dnet_cmd *cmd, dnet_io_attr *io) {
			const bool cache = (io->flags & DNET_IO_FLAGS_CACHE);
			const bool cache_only = (io->flags & DNET_IO_FLAGS_CACHE_ONLY);

			dnet_log(m_node, DNET_LOG_DEBUG, "%s: CACHE READ: before guard\n", dnet_dump_id_str(id));
			std::unique_lock<std::mutex> guard(m_lock);
			dnet_log(m_node, DNET_LOG_DEBUG, "%s: CACHE READ: after guard\n", dnet_dump_id_str(id));

			iset_t::iterator it = m_set.find(id);
			if (it != m_set.end() && it->only_append()) {
				sync_after_append(guard, true, &*it);
				dnet_log(m_node, DNET_LOG_DEBUG, "%s: CACHE READ: synced append-only data\n", dnet_dump_id_str(id));

				it = m_set.end();
			}

			if (it == m_set.end() && cache && !cache_only) {
				dnet_log(m_node, DNET_LOG_DEBUG, "%s: CACHE READ: not exist\n", dnet_dump_id_str(id));
				int err = 0;
				it = populate_from_disk(guard, id, false, &err);
			} else {
				dnet_log(m_node, DNET_LOG_DEBUG, "%s: CACHE READ: exists\n", dnet_dump_id_str(id));
			}

			dnet_log(m_node, DNET_LOG_DEBUG, "%s: CACHE READ: data ensured\n", dnet_dump_id_str(id));

			if (it != m_set.end()) {
				m_lru.erase(m_lru.iterator_to(*it));
				it->set_remove_from_cache(false);
				m_lru.push_back(*it);

				io->timestamp = it->timestamp();
				io->user_flags = it->user_flags();
				dnet_log(m_node, DNET_LOG_DEBUG, "%s: CACHE READ: returned\n", dnet_dump_id_str(id));
				return it->data();
			}

			return std::shared_ptr<raw_data_t>();
		}

		int remove(const unsigned char *id, dnet_io_attr *io) {
			const bool cache_only = (io->flags & DNET_IO_FLAGS_CACHE_ONLY);
			bool remove_from_disk = !cache_only;
			int err = -ENOENT;

			std::unique_lock<std::mutex> guard(m_lock);
			iset_t::iterator it = m_set.find(id);
			if (it != m_set.end()) {
				// If cache_only is not set the data also should be remove from the disk
				// If data is marked and cache_only is not set - data must be synced to the disk
				remove_from_disk |= it->remove_from_disk();
				if (it->synctime() && !cache_only) {
					m_syncset.erase(m_syncset.iterator_to(*it));
					it->clear_synctime();
				}
				erase_element(&(*it));
				err = 0;
			}

			guard.unlock();

			if (remove_from_disk) {
				struct dnet_id raw;
				memset(&raw, 0, sizeof(struct dnet_id));

				dnet_setup_id(&raw, 0, (unsigned char *)id);

				int local_err = dnet_remove_local(m_node, &raw);
				if (local_err != -ENOENT)
					err = local_err;
			}

			return err;
		}

		int lookup(const unsigned char *id, dnet_net_state *st, dnet_cmd *cmd) {
			int err = 0;

			std::unique_lock<std::mutex> guard(m_lock);
			iset_t::iterator it = m_set.find(id);
			if (it == m_set.end()) {
				return -ENOTSUP;
			}

			dnet_time timestamp = it->timestamp();

			guard.unlock();

			local_session sess(m_node);

			cmd->flags |= DNET_FLAGS_NOCACHE;

			ioremap::elliptics::data_pointer data = sess.lookup(*cmd, &err);

			cmd->flags &= ~DNET_FLAGS_NOCACHE;

			if (err) {
				cmd->flags &= ~DNET_FLAGS_NEED_ACK;
				return dnet_send_file_info_ts_without_fd(st, cmd, NULL, 0, &timestamp);
			}

			dnet_file_info *info = data.skip<dnet_addr>().data<dnet_file_info>();
			info->mtime = timestamp;

			cmd->flags &= (DNET_FLAGS_MORE | DNET_FLAGS_NEED_ACK);
			return dnet_send_reply(st, cmd, data.data(), data.size(), 0);
		}

	private:
		bool m_need_exit;
		struct dnet_node *m_node;
		size_t m_cache_size, m_max_cache_size;
		std::mutex m_lock;
		iset_t m_set;
		lru_list_t m_lru;
		life_set_t m_lifeset;
		sync_set_t m_syncset;
		std::thread m_lifecheck;

		cache_t(const cache_t &) = delete;

		iset_t::iterator create_data(const unsigned char *id, const char *data, size_t size, bool remove_from_disk) {
			if (m_cache_size + size > m_max_cache_size) {
				dnet_log(m_node, DNET_LOG_DEBUG, "%s: CACHE: resize called from create_data\n", dnet_dump_id_str(id));
				resize(size);
				dnet_log(m_node, DNET_LOG_DEBUG, "%s: CACHE: resize finished from create_data\n", dnet_dump_id_str(id));
			}

			data_t *raw = new data_t(id, 0, data, size, remove_from_disk);

			m_cache_size += size;

			m_lru.push_back(*raw);
			return m_set.insert(*raw).first;
		}

		iset_t::iterator populate_from_disk(std::unique_lock<std::mutex> &guard, const unsigned char *id, bool remove_from_disk, int *err) {
			if (guard.owns_lock()) {
				guard.unlock();
			}

			local_session sess(m_node);
			sess.set_ioflags(DNET_IO_FLAGS_NOCACHE);

			dnet_id raw_id;
			memset(&raw_id, 0, sizeof(raw_id));
			memcpy(raw_id.id, id, DNET_ID_SIZE);

			uint64_t user_flags = 0;
			dnet_time timestamp;
			dnet_empty_time(&timestamp);

			dnet_log(m_node, DNET_LOG_DEBUG, "%s: CACHE: populating from disk started\n", dnet_dump_id_str(id));

			ioremap::elliptics::data_pointer data = sess.read(raw_id, &user_flags, &timestamp, err);

			dnet_log(m_node, DNET_LOG_DEBUG, "%s: CACHE: populating from disk finished: %d\n", dnet_dump_id_str(id), *err);

			guard.lock();

			if (*err == 0) {
				auto it = create_data(id, reinterpret_cast<char *>(data.data()), data.size(), remove_from_disk);
				it->set_user_flags(user_flags);
				it->set_timestamp(timestamp);
				return it;
			}

			return m_set.end();
		}

		void resize(size_t reserve) {
			size_t removed_size = 0;

			for (auto it = m_lru.begin(); it != m_lru.end();) {
				if (m_max_cache_size > m_cache_size + reserve + removed_size)
					break;

				data_t *raw = &*it;
				++it;

				if (raw->synctime() || raw->remove_from_cache()) {
					if (!raw->remove_from_cache()) {
						raw->set_remove_from_cache(true);

						m_syncset.erase(m_syncset.iterator_to(*raw));
						raw->set_synctime(1);
						m_syncset.insert(*raw);
					}
					removed_size += raw->size();
				} else {
					erase_element(raw);
				}
			}
		}

		void erase_element(data_t *obj) {
			m_lru.erase(m_lru.iterator_to(*obj));
			m_set.erase(m_set.iterator_to(*obj));
			if (obj->lifetime())
				m_lifeset.erase(m_lifeset.iterator_to(*obj));

			if (obj->synctime()) {
				sync_element(obj);

				m_syncset.erase(m_syncset.iterator_to(*obj));
				obj->clear_synctime();
			}

			m_cache_size -= obj->size();

			delete obj;
		}

		void sync_element(const dnet_id &raw, bool after_append, const std::vector<char> &data, uint64_t user_flags, const dnet_time &timestamp) {
			local_session sess(m_node);
			sess.set_ioflags(DNET_IO_FLAGS_NOCACHE | (after_append ? DNET_IO_FLAGS_APPEND : 0));

			int err = sess.write(raw, data.data(), data.size(), user_flags, timestamp);
			if (err) {
				dnet_log(m_node, DNET_LOG_ERROR, "%s: CACHE: forced to sync to disk, err: %d\n", dnet_dump_id_str(raw.id), err);
			} else {
				dnet_log(m_node, DNET_LOG_DEBUG, "%s: CACHE: forced to sync to disk, err: %d\n", dnet_dump_id_str(raw.id), err);
			}
		}

		void sync_element(data_t *obj) {
			struct dnet_id raw;
			memset(&raw, 0, sizeof(struct dnet_id));
			memcpy(raw.id, obj->id().id, DNET_ID_SIZE);

			auto &data = obj->data()->data();

			sync_element(raw, obj->only_append(), data, obj->user_flags(), obj->timestamp());
		}

		void sync_after_append(std::unique_lock<std::mutex> &guard, bool lock_guard, data_t *obj) {
			std::shared_ptr<raw_data_t> raw_data = obj->data();
			m_syncset.erase(m_syncset.iterator_to(*obj));
			obj->set_synctime(0);

			dnet_id id;
			memset(&id, 0, sizeof(id));
			memcpy(id.id, obj->id().id, DNET_ID_SIZE);

			uint64_t user_flags = obj->user_flags();
			dnet_time timestamp = obj->timestamp();

			erase_element(&*obj);

			guard.unlock();

			local_session sess(m_node);
			sess.set_ioflags(DNET_IO_FLAGS_NOCACHE | DNET_IO_FLAGS_APPEND);

			auto &raw = raw_data->data();

			int err = sess.write(id, raw.data(), raw.size(), user_flags, timestamp);
			dnet_log(m_node, DNET_LOG_DEBUG, "%s: CACHE: sync after append, err: %d", dnet_dump_id_str(id.id), err);

			if (lock_guard)
				guard.lock();
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

				dnet_id id;
				std::vector<char> data;
				uint64_t user_flags;
				dnet_time timestamp;

				memset(&id, 0, sizeof(id));

				while (!m_need_exit && !m_syncset.empty()) {
					size_t time = ::time(NULL);

					std::unique_lock<std::mutex> guard(m_lock);

					if (m_syncset.empty())
						break;

					sync_set_t::iterator it = m_syncset.begin();

					data_t *obj = &*it;
					if (obj->synctime() > time)
						break;

					if (obj->only_append()) {
						sync_after_append(guard, false, obj);
						continue;
					}

					memcpy(id.id, obj->id().id, DNET_ID_SIZE);
					data = it->data()->data();
					user_flags = obj->user_flags();
					timestamp = obj->timestamp();

					m_syncset.erase(it);
					obj->clear_synctime();

					guard.unlock();

					sync_element(id, false, data, user_flags, timestamp);

					guard.lock();

					auto jt = m_set.find(id.id);
					if (jt != m_set.end()) {
						if (jt->remove_from_cache()) {
							erase_element(&*jt);
						}
					}
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
		std::vector<std::shared_ptr<cache_t>> m_caches;

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
