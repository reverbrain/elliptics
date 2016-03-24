/*
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

#ifndef _GLIBCXX_USE_NANOSLEEP
#define _GLIBCXX_USE_NANOSLEEP
#endif

#include "slru_cache.hpp"
#include "library/request_queue.h"
#include <cassert>

#include "monitor/measure_points.h"

// Cache implementation is moderately instrumented with statistics gathering
// to provide insight into details of different cache operations.
// But overly detailed stats can also be confusing, so while some measuring
// points are always on, others are turned off by default.
// Use symbol DETAILED_CACHE_STATS to turn them on at compile time.
//
#ifdef DETAILED_CACHE_STATS
	#define METRIC_PREFIX(name) "slru_cache." name
	#define TIMER_SCOPE(name) HANDY_TIMER_SCOPE(METRIC_PREFIX(name))
	#define TIMER_START(name) HANDY_TIMER_START(METRIC_PREFIX(name), dnet_get_id())
	#define TIMER_STOP(name) HANDY_TIMER_STOP(METRIC_PREFIX(name), dnet_get_id())
#else
	#define TIMER_SCOPE(...)
	#define TIMER_START(...)
	#define TIMER_STOP(...)
#endif

namespace ioremap { namespace cache {

// public:

slru_cache_t::slru_cache_t(struct dnet_backend_io *backend, struct dnet_node *n,
	const std::vector<size_t> &cache_pages_max_sizes, unsigned sync_timeout) :
	m_backend(backend),
	m_node(n),
	m_cache_pages_number(cache_pages_max_sizes.size()),
	m_cache_pages_max_sizes(cache_pages_max_sizes),
	m_cache_pages_sizes(m_cache_pages_number, 0),
	m_cache_pages_lru(new lru_list_t[m_cache_pages_number]),
	m_clear_occured(false),
	m_sync_timeout(sync_timeout) {
	m_lifecheck = std::thread(std::bind(&slru_cache_t::life_check, this));
}

slru_cache_t::~slru_cache_t() {
	TIMER_SCOPE("dtor");
	dnet_log(m_node, DNET_LOG_NOTICE, "cache: disable: backend: %zu: destructing SLRU cache\n", m_backend->backend_id);
	m_lifecheck.join();
	dnet_log(m_node, DNET_LOG_NOTICE, "cache: disable: backend: %zu: clearing\n", m_backend->backend_id);
	clear();
	dnet_log(m_node, DNET_LOG_NOTICE, "cache: disable: backend: %zu: destructed\n", m_backend->backend_id);
}

int slru_cache_t::write(const unsigned char *id, dnet_net_state *st, dnet_cmd *cmd, dnet_io_attr *io, const char *data) {
	TIMER_SCOPE("write");

	const size_t lifetime = io->start;
	const size_t size = io->size;
	const bool remove_from_disk = (io->flags & DNET_IO_FLAGS_CACHE_REMOVE_FROM_DISK);
	const bool cache = (io->flags & DNET_IO_FLAGS_CACHE);
	const bool cache_only = (io->flags & DNET_IO_FLAGS_CACHE_ONLY);
	const bool append = (io->flags & DNET_IO_FLAGS_APPEND);

	TIMER_START("write.lock");
	elliptics_unique_lock<std::mutex> guard(m_lock, m_node, "%s: CACHE WRITE: %p", dnet_dump_id_str(id), this);
	TIMER_STOP("write.lock");

	TIMER_START("write.find");
	data_t* it = m_treap.find(id);
	TIMER_STOP("write.find");

	if (!it && !cache) {
		dnet_log(m_node, DNET_LOG_DEBUG, "%s: CACHE: not a cache call", dnet_dump_id_str(id));
		return -ENOTSUP;
	}

	// Optimization for append-only commands
	if (!cache_only) {
		if (append && (!it || it->only_append())) {
			TIMER_SCOPE("write.append_only");

			bool new_page = false;
			if (!it) {
				it = create_data(id, 0, 0, false);
				new_page = true;
				it->set_only_append(true);
				size_t previous_eventtime = it->eventtime();
				it->set_synctime(time(NULL) + m_sync_timeout);

				if (previous_eventtime != it->eventtime()) {
					TIMER_SCOPE("write.decrease_key");
					m_treap.decrease_key(it);
				}
			}

			auto &raw = it->data()->data();
			size_t page_number = it->cache_page_number();
			size_t new_page_number = page_number;
			size_t new_size = it->size() + io->size;

			// Moving item to hotter page
			if (!new_page) {
				new_page_number = get_next_page_number(page_number);
			}

			remove_data_from_page(id, page_number, &*it);
			resize_page(id, new_page_number, 2 * new_size);

			if (it->remove_from_cache()) {
				m_cache_stats.size_of_objects_marked_for_deletion -= it->size();
			}
			m_cache_stats.size_of_objects -= it->size();
			raw.insert(raw.end(), data, data + io->size);
			m_cache_stats.size_of_objects += it->size();
			if (it->remove_from_cache()) {
				m_cache_stats.size_of_objects_marked_for_deletion += it->size();
			}

			insert_data_into_page(id, new_page_number, &*it);

			it->set_timestamp(io->timestamp);
			it->set_user_flags(io->user_flags);

			cmd->flags &= ~DNET_FLAGS_NEED_ACK;
			return dnet_send_file_info_ts_without_fd(st, cmd, data, io->size, &io->timestamp);
		} else if (it && it->only_append()) {
			TIMER_SCOPE("write.after_append_only");

			sync_after_append(guard, false, &*it);

			local_session sess(m_backend, m_node);
			sess.set_ioflags(DNET_IO_FLAGS_NOCACHE | DNET_IO_FLAGS_APPEND);

			int err = m_backend->cb->command_handler(st, m_backend->cb->command_private, cmd, io);

			it = populate_from_disk(guard, id, false, &err);

			cmd->flags &= ~DNET_FLAGS_NEED_ACK;
			return err;
		}
	}

	bool new_page = false;

	if (!it) {
		// If file not found and CACHE flag is not set - fallback to backend request
		if (!cache_only && io->offset != 0) {
			int err = 0;
			it = populate_from_disk(guard, id, remove_from_disk, &err);
			new_page = true;

			if (err != 0 && err != -ENOENT)
				return err;
		}

		// Create empty data for code simplifyng
		if (!it) {
			it = create_data(id, 0, 0, remove_from_disk);
			new_page = true;
		}
	}

	raw_data_t &raw = *it->data();

	if (io->flags & DNET_IO_FLAGS_COMPARE_AND_SWAP) {
		TIMER_SCOPE("write.cas");

		// Data is already in memory, so it's free to use it
		// raw.size() is zero only if there is no such file on the server
		if (raw.size() != 0) {
			struct dnet_raw_id csum;
			dnet_transform_node(m_node, raw.data().data(), raw.size(), csum.id, sizeof(csum.id));

			if (memcmp(csum.id, io->parent, DNET_ID_SIZE)) {
				dnet_log(m_node, DNET_LOG_ERROR, "%s: cas: cache checksum mismatch", dnet_dump_id(&cmd->id));
				return -EBADFD;
			}
		}
	}

	if (io->flags & DNET_IO_FLAGS_CAS_TIMESTAMP) {
		TIMER_SCOPE("write.cas_timestamp");

		if (raw.size() != 0) {
			struct dnet_time cache_ts = it->timestamp();

			// cache timestamp is greater than timestamp of the data to be written
			// do not allow it
			if (dnet_time_cmp(&cache_ts, &io->timestamp) > 0) {
				dnet_log(m_node, DNET_LOG_ERROR, "%s: cas: cache timestamp is larger "
						"than data to be written timestamp: "
						"cache-ts: %lld.%lld, data-ts: %lld.%lld",
						dnet_dump_id(&cmd->id),
						(unsigned long long)cache_ts.tsec, (unsigned long long)cache_ts.tnsec,
						(unsigned long long)io->timestamp.tsec, (unsigned long long)io->timestamp.tnsec);
				return -EBADFD;
			}
		}
	}

	dnet_log(m_node, DNET_LOG_DEBUG, "%s: CACHE: CAS checked", dnet_dump_id_str(id));

	size_t new_data_size = 0;

	if (append) {
		new_data_size = raw.size() + size;
	} else {
		new_data_size = io->offset + io->size;
	}

	size_t new_size = new_data_size + it->overhead_size();

	size_t page_number = it->cache_page_number();
	size_t new_page_number = page_number;

	if (!new_page) {
		new_page_number = get_next_page_number(page_number);
	}

	remove_data_from_page(id, page_number, &*it);
	resize_page(id, new_page_number, 2 * new_size);

	if (it->remove_from_cache()) {
		m_cache_stats.size_of_objects_marked_for_deletion -= it->size();
	}
	m_cache_stats.size_of_objects -= it->size();

	TIMER_START("write.modify");
	if (append) {
		raw.data().insert(raw.data().end(), data, data + size);
	} else {
		raw.data().resize(new_data_size);
		memcpy(raw.data().data() + io->offset, data, size);
	}
	TIMER_STOP("write.modify");
	m_cache_stats.size_of_objects += it->size();

	it->set_remove_from_cache(false);
	insert_data_into_page(id, new_page_number, &*it);

	// Mark data as dirty one, so it will be synced to the disk

	size_t previous_eventtime = it->eventtime();

	if (!it->synctime() && !(io->flags & DNET_IO_FLAGS_CACHE_ONLY)) {
		it->set_synctime(time(NULL) + m_sync_timeout);
	}

	if (lifetime) {
		it->set_lifetime(lifetime + time(NULL));
	}

	if (previous_eventtime != it->eventtime()) {
		TIMER_SCOPE("write.decrease_key");
		m_treap.decrease_key(it);
	}

	it->set_timestamp(io->timestamp);
	it->set_user_flags(io->user_flags);

	cmd->flags &= ~DNET_FLAGS_NEED_ACK;
	return dnet_send_file_info_ts_without_fd(st, cmd, raw.data().data() + io->offset, io->size, &io->timestamp);
}

std::shared_ptr<raw_data_t> slru_cache_t::read(const unsigned char *id, dnet_cmd *cmd, dnet_io_attr *io) {
	TIMER_SCOPE("read");

	const bool cache = (io->flags & DNET_IO_FLAGS_CACHE);
	const bool cache_only = (io->flags & DNET_IO_FLAGS_CACHE_ONLY);
	(void) cmd;

	TIMER_START("read.lock");
	elliptics_unique_lock<std::mutex> guard(m_lock, m_node, "%s: CACHE READ: %p", dnet_dump_id_str(id), this);
	TIMER_STOP("read.lock");

	bool new_page = false;

	TIMER_START("read.find");
	data_t* it = m_treap.find(id);
	TIMER_STOP("read.find");

	if (it && it->only_append()) {
		sync_after_append(guard, true, &*it);
		it = NULL;
	}

	if (!it && cache && !cache_only) {
		int err = 0;
		it = populate_from_disk(guard, id, false, &err);
		new_page = true;
	}

	if (it) {
		size_t page_number = it->cache_page_number();
		size_t new_page_number = page_number;

		if (it->remove_from_cache()) {
			m_cache_stats.size_of_objects_marked_for_deletion -= it->size();
		}
		it->set_remove_from_cache(false);

		if (!new_page) {
			new_page_number = get_next_page_number(page_number);
		}

		move_data_between_pages(id, page_number, new_page_number, &*it);

		io->timestamp = it->timestamp();
		io->user_flags = it->user_flags();
		return it->data();
	}

	return std::shared_ptr<raw_data_t>();
}

int slru_cache_t::remove(const unsigned char *id, dnet_io_attr *io) {
	TIMER_SCOPE("remove");

	const bool cache_only = (io->flags & DNET_IO_FLAGS_CACHE_ONLY);
	bool remove_from_disk = !cache_only;
	int err = -ENOENT;

	TIMER_START("remove.lock");
	elliptics_unique_lock<std::mutex> guard(m_lock, m_node, "%s: CACHE REMOVE: %p", dnet_dump_id_str(id), this);
	TIMER_STOP("remove.lock");

	TIMER_START("remove.find");
	data_t* it = m_treap.find(id);
	TIMER_STOP("remove.find");

	if (it) {
		// If cache_only is not set the data also should be remove from the disk
		// If data is marked and cache_only is not set - data must not be synced to the disk
		remove_from_disk |= it->remove_from_disk();
		if (it->synctime() && !cache_only) {
			size_t previous_eventtime = it->eventtime();
			it->clear_synctime();

			if (previous_eventtime != it->eventtime()) {
				TIMER_SCOPE("remove.decrease_key");
				m_treap.decrease_key(it);
			}
		}
		if (it->is_syncing()) {
			it->set_sync_state(data_t::sync_state_t::ERASE_PHASE);
		}
		erase_element(&(*it));
		err = 0;
	}

	guard.unlock();

	if (remove_from_disk) {
		struct dnet_id raw;
		memset(&raw, 0, sizeof(struct dnet_id));

		dnet_setup_id(&raw, 0, (unsigned char *)id);

		TIMER_SCOPE("remove.local");

		int local_err = dnet_remove_local(m_backend, m_node, &raw);
		if (local_err != -ENOENT)
			err = local_err;
	}

	return err;
}

int slru_cache_t::lookup(const unsigned char *id, dnet_net_state *st, dnet_cmd *cmd) {
	TIMER_SCOPE("lookup");

	int err = 0;

	TIMER_START("lookup.lock");
	elliptics_unique_lock<std::mutex> guard(m_lock, m_node, "%s: CACHE LOOKUP: %p", dnet_dump_id_str(id), this);
	TIMER_STOP("lookup.lock");

	TIMER_START("lookup.find");
	data_t* it = m_treap.find(id);
	TIMER_STOP("lookup.find");

	if (!it) {
		return -ENOENT;
	}

	auto timestamp = it->timestamp();

	guard.unlock();

	// go check object on disk
	TIMER_START("lookup.local");
	local_session sess(m_backend, m_node);
	cmd->flags |= DNET_FLAGS_NOCACHE;
	ioremap::elliptics::data_pointer data = sess.lookup(*cmd, &err);
	cmd->flags &= ~DNET_FLAGS_NOCACHE;
	TIMER_STOP("lookup.local");

	cmd->flags &= ~(DNET_FLAGS_MORE | DNET_FLAGS_NEED_ACK);

	if (err) {
		// zero size means 'we didn't find key on disk', but yet it exists in cache
		// lookup by its nature is 'show me what is on disk' command
		return dnet_send_file_info_ts_without_fd(st, cmd, NULL, 0, &timestamp);
	}

	auto info = data.skip<dnet_addr>().data<dnet_file_info>();
	info->mtime = timestamp;

	return dnet_send_reply(st, cmd, data.data(), data.size(), 0);
}

void slru_cache_t::clear() {
	TIMER_SCOPE("clear");

	std::vector<size_t> cache_pages_max_sizes = m_cache_pages_max_sizes;

	TIMER_START("clear.lock");
	elliptics_unique_lock<std::mutex> guard(m_lock, m_node, "CACHE CLEAR: %p", this);
	TIMER_STOP("clear.lock");
	m_clear_occured = true;

	for (size_t page_number = 0; page_number < m_cache_pages_number; ++page_number) {
		m_cache_pages_max_sizes[page_number] = 0;
		resize_page((unsigned char *) "", page_number, 0);
	}

	while (!m_treap.empty()) {
		data_t *obj = m_treap.top();

		sync_if_required(obj, guard);
		obj->set_sync_state(data_t::sync_state_t::NOT_SYNCING);

		erase_element(obj);
	}

	m_cache_pages_max_sizes = cache_pages_max_sizes;
}

cache_stats slru_cache_t::get_cache_stats() const {
	m_cache_stats.pages_sizes = m_cache_pages_sizes;
	m_cache_stats.pages_max_sizes = m_cache_pages_max_sizes;
	return m_cache_stats;
}

// private:


void slru_cache_t::sync_if_required(data_t* it, elliptics_unique_lock<std::mutex> &guard) {
	TIMER_SCOPE("sync_if_required");

	if (it && it->is_syncing()) {
		dnet_id id;
		memset(&id, 0, sizeof(id));
		memcpy(id.id, it->id().id, DNET_ID_SIZE);

		std::vector<char> data;
		uint64_t user_flags;
		dnet_time timestamp;

		bool only_append = it->only_append();
		data = it->data()->data();
		user_flags = it->user_flags();
		timestamp = it->timestamp();

		guard.unlock();

		// sync_element uses local_session which always uses DNET_FLAGS_NOLOCK
		if (it->is_syncing()) {
			sync_element(id, only_append, data, user_flags, timestamp);
			it->set_sync_state(data_t::sync_state_t::ERASE_PHASE);
		}

		guard.lock();
	}
}

void slru_cache_t::insert_data_into_page(const unsigned char *id, size_t page_number, data_t *data) {
	TIMER_SCOPE("add_to_page");

	elliptics_timer timer;
	size_t size = data->size();

	// Recalc used space, free enough space for new data, move object to the end of the queue
	if (m_cache_pages_sizes[page_number] + size > m_cache_pages_max_sizes[page_number]) {
		dnet_log(m_node, DNET_LOG_DEBUG, "%s: CACHE: resize called: %lld ms", dnet_dump_id_str(id), timer.restart());
		resize_page(id, page_number, size);
		dnet_log(m_node, DNET_LOG_DEBUG, "%s: CACHE: resize finished: %lld ms", dnet_dump_id_str(id), timer.restart());
	}

	data->set_cache_page_number(page_number);
	m_cache_pages_lru[page_number].push_back(*data);
	m_cache_pages_sizes[page_number] += size;
}

void slru_cache_t::remove_data_from_page(const unsigned char *id, size_t page_number, data_t *data) {
	(void) id;
	m_cache_pages_sizes[page_number] -= data->size();
	if (!data->is_removed_from_page()) {
		m_cache_pages_lru[page_number].erase(m_cache_pages_lru[page_number].iterator_to(*data));
		data->set_removed_from_page(true);
	}
}

void slru_cache_t::move_data_between_pages(const unsigned char *id, size_t source_page_number, size_t destination_page_number, data_t *data) {
	TIMER_SCOPE("move_record");

	if (source_page_number != destination_page_number) {
		remove_data_from_page(id, source_page_number, data);
		insert_data_into_page(id, destination_page_number, data);
	}
}

data_t* slru_cache_t::create_data(const unsigned char *id, const char *data, size_t size, bool remove_from_disk) {
	TIMER_SCOPE("create_data");

	size_t last_page_number = m_cache_pages_number - 1;

	data_t *raw = new data_t(id, 0, data, size, remove_from_disk);

	insert_data_into_page(id, last_page_number, raw);

	m_cache_stats.number_of_objects++;
	m_cache_stats.size_of_objects += raw->size();
	m_treap.insert(raw);
	return raw;
}

data_t* slru_cache_t::populate_from_disk(elliptics_unique_lock<std::mutex> &guard, const unsigned char *id, bool remove_from_disk, int *err) {
	TIMER_SCOPE("populate_from_disk");

	if (guard.owns_lock()) {
		guard.unlock();
	}

	local_session sess(m_backend, m_node);
	sess.set_ioflags(DNET_IO_FLAGS_NOCACHE);

	dnet_id raw_id;
	memset(&raw_id, 0, sizeof(raw_id));
	memcpy(raw_id.id, id, DNET_ID_SIZE);

	uint64_t user_flags = 0;
	dnet_time timestamp;
	dnet_empty_time(&timestamp);

	TIMER_START("populate_from_disk.local_read");
	ioremap::elliptics::data_pointer data = sess.read(raw_id, &user_flags, &timestamp, err);
	TIMER_STOP("populate_from_disk.local_read");

	TIMER_START("populate_from_disk.lock");
	guard.lock();
	TIMER_STOP("populate_from_disk.lock");

	if (*err == 0) {
		auto it = create_data(id, reinterpret_cast<char *>(data.data()), data.size(), remove_from_disk);
		it->set_user_flags(user_flags);
		it->set_timestamp(timestamp);

		return it;
	}

	return NULL;
}

bool slru_cache_t::have_enough_space(const unsigned char *id, size_t page_number, size_t reserve) {
	(void) id;
	return m_cache_pages_max_sizes[page_number] >= reserve;
}

void slru_cache_t::resize_page(const unsigned char *id, size_t page_number, size_t reserve) {
	TIMER_SCOPE("resize_page");

	size_t removed_size = 0;
	size_t &cache_size = m_cache_pages_sizes[page_number];
	size_t &max_cache_size = m_cache_pages_max_sizes[page_number];
	size_t previous_page_number = get_previous_page_number(page_number);

	for (auto it = m_cache_pages_lru[page_number].begin(), end = m_cache_pages_lru[page_number].end(); it != end;) {
		if (max_cache_size + removed_size >= cache_size + reserve)
			break;

		data_t *raw = &*it;
		++it;

		// If page is not last move object to previous page
		if (previous_page_number < m_cache_pages_number) {
			move_data_between_pages(id, page_number, previous_page_number, raw);
		} else {
			if (raw->synctime() || raw->remove_from_cache()) {
				if (!raw->remove_from_cache()) {
					m_cache_stats.number_of_objects_marked_for_deletion++;
					m_cache_stats.size_of_objects_marked_for_deletion += raw->size();
					raw->set_remove_from_cache(true);

					size_t previous_eventtime = raw->eventtime();
					raw->set_synctime(1);
					if (previous_eventtime != raw->eventtime()) {
						TIMER_SCOPE("resize_page.decrease_key");
						m_treap.decrease_key(raw);
					}
				}
				removed_size += raw->size();
				m_cache_pages_lru[page_number].erase(m_cache_pages_lru[page_number].iterator_to(*raw));
				raw->set_removed_from_page(true);
			} else {
				erase_element(raw);
			}
		}
	}
}

void slru_cache_t::erase_element(data_t *obj) {
	TIMER_SCOPE("erase");

	if (obj->will_be_erased()) {
		if (!obj->remove_from_cache()) {
			m_cache_stats.size_of_objects_marked_for_deletion += obj->size();
			obj->set_remove_from_cache(true);
		}
		return;
	}

	m_cache_stats.number_of_objects--;
	m_cache_stats.size_of_objects -= obj->size();

	size_t page_number = obj->cache_page_number();
	remove_data_from_page(obj->id().id, page_number, obj);
	m_treap.erase(obj);

	if (obj->synctime()) {
		sync_element(obj);
		obj->clear_synctime();
	}

	if (obj->remove_from_cache()) {
		m_cache_stats.number_of_objects_marked_for_deletion--;
		m_cache_stats.size_of_objects_marked_for_deletion -= obj->size();
	}

	delete obj;
}

void slru_cache_t::sync_element(const dnet_id &raw, bool after_append, const std::vector<char> &data, uint64_t user_flags, const dnet_time &timestamp) {
	HANDY_TIMER_SCOPE("slru_cache.sync_element");

	local_session sess(m_backend, m_node);
	sess.set_ioflags(DNET_IO_FLAGS_NOCACHE | (after_append ? DNET_IO_FLAGS_APPEND : 0));

	int err = sess.write(raw, data.data(), data.size(), user_flags, timestamp);
	if (err) {
		dnet_log(m_node, DNET_LOG_ERROR, "%s: CACHE: forced to sync to disk, err: %d", dnet_dump_id_str(raw.id), err);
	} else {
		dnet_log(m_node, DNET_LOG_DEBUG, "%s: CACHE: forced to sync to disk, err: %d", dnet_dump_id_str(raw.id), err);
	}
}

void slru_cache_t::sync_element(data_t *obj) {
	struct dnet_id raw;
	memset(&raw, 0, sizeof(struct dnet_id));
	memcpy(raw.id, obj->id().id, DNET_ID_SIZE);

	auto &data = obj->data()->data();

	sync_element(raw, obj->only_append(), data, obj->user_flags(), obj->timestamp());
}

void slru_cache_t::sync_after_append(elliptics_unique_lock<std::mutex> &guard, bool lock_guard, data_t *obj) {
	TIMER_SCOPE("sync_after_append");

	std::shared_ptr<raw_data_t> raw_data = obj->data();

	obj->clear_synctime();

	dnet_id id;
	memset(&id, 0, sizeof(id));
	memcpy(id.id, obj->id().id, DNET_ID_SIZE);

	uint64_t user_flags = obj->user_flags();
	dnet_time timestamp = obj->timestamp();

	erase_element(&*obj);

	guard.unlock();

	local_session sess(m_backend, m_node);
	sess.set_ioflags(DNET_IO_FLAGS_NOCACHE | DNET_IO_FLAGS_APPEND);

	auto &raw = raw_data->data();

	TIMER_START("sync_after_append.local_write");
	int err = sess.write(id, raw.data(), raw.size(), user_flags, timestamp);
	TIMER_STOP("sync_after_append.local_write");

	TIMER_START("sync_after_append.lock");
	if (lock_guard)
		guard.lock();
	TIMER_STOP("sync_after_append.lock");

	dnet_log(m_node, DNET_LOG_INFO, "%s: CACHE: sync after append, err: %d", dnet_dump_id_str(id.id), err);
}

void slru_cache_t::life_check(void) {

	dnet_set_name("dnet_cache_%zu", m_backend->backend_id);

	while (!need_exit()) {
		{
			TIMER_SCOPE("life_check");

			std::deque<struct dnet_id> remove;
			std::deque<data_t*> elements_for_sync;
			size_t last_time = 0;
			dnet_id id;
			memset(&id, 0, sizeof(id));

			{
				TIMER_START("life_check.lock");
				elliptics_unique_lock<std::mutex> guard(m_lock, m_node, "CACHE LIFE: %p", this);
				TIMER_STOP("life_check.lock");

				TIMER_SCOPE("life_check.prepare_sync");
				while (!need_exit() && !m_treap.empty()) {
					size_t time = ::time(NULL);
					last_time = time;

					if (m_treap.empty())
						break;

					data_t* it = m_treap.top();
					if (it->eventtime() > time)
						break;

					if (it->eventtime() == it->lifetime())
					{
						if (it->remove_from_disk()) {
							memset(&id, 0, sizeof(struct dnet_id));
							dnet_setup_id(&id, 0, (unsigned char *)it->id().id);
							remove.push_back(id);
						}

						erase_element(it);
					}
					else if (it->eventtime() == it->synctime())
					{
						elements_for_sync.push_back(it);

						size_t previous_eventtime = it->eventtime();
						it->clear_synctime();
						it->set_sync_state(data_t::sync_state_t::SYNC_PHASE);

						if (previous_eventtime != it->eventtime()) {
							TIMER_SCOPE("life_check.decrease_key");
							m_treap.decrease_key(it);
						}
					}
				}
			}

			{
				TIMER_SCOPE("life_check.sync_iterate");
				HANDY_GAUGE_SET("slru_cache.life_check.sync_iterate.element_count", elements_for_sync.size());
				for (auto it = elements_for_sync.begin(); it != elements_for_sync.end(); ++it) {
					if (m_clear_occured)
						break;

					data_t *elem = *it;
					memcpy(id.id, elem->id().id, DNET_ID_SIZE);

					TIMER_START("life_check.sync_iterate.dnet_oplock");
					dnet_oplock(m_backend, &id);
					TIMER_STOP("life_check.sync_iterate.dnet_oplock");

					// sync_element uses local_session which always uses DNET_FLAGS_NOLOCK
					if (elem->is_syncing()) {
						sync_element(id, elem->only_append(), elem->data()->data(), elem->user_flags(), elem->timestamp());
						elem->set_sync_state(data_t::sync_state_t::ERASE_PHASE);
					}

					dnet_opunlock(m_backend, &id);
				}
			}

			{
				TIMER_SCOPE("life_check.remove_local");
				for (std::deque<struct dnet_id>::iterator it = remove.begin(); it != remove.end(); ++it) {
					dnet_remove_local(m_backend, m_node, &(*it));
				}
			}

			{
				TIMER_START("life_check.lock");
				elliptics_unique_lock<std::mutex> guard(m_lock, m_node, "CACHE CLEAR PAGES: %p", this);
				TIMER_STOP("life_check.lock");

				if (!m_clear_occured) {
					TIMER_SCOPE("life_check.erase_iterate");
					for (std::deque<data_t*>::iterator it = elements_for_sync.begin(); it != elements_for_sync.end(); ++it) {
						data_t *elem = *it;
						elem->set_sync_state(data_t::sync_state_t::NOT_SYNCING);
						if (elem->synctime() <= last_time) {
							if (elem->only_append() || elem->remove_from_cache()) {
								erase_element(elem);
							}
						}
					}
				} else {
					m_clear_occured = false;
				}
			}
		}

		std::this_thread::sleep_for( std::chrono::milliseconds(1000) );
	}

}

}}
