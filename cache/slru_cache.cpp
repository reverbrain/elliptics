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

#include "slru_cache.hpp"
#include <cassert>

namespace ioremap { namespace cache {

//thread_local time_stats_updater_t *slru_cache_t::thread_time_stats_updater = nullptr;

// public:

slru_cache_t::slru_cache_t(struct dnet_node *n, const std::vector<size_t> &cache_pages_max_sizes) :
	m_need_exit(false),
	m_node(n),
	m_cache_pages_number(cache_pages_max_sizes.size()),
	m_cache_pages_max_sizes(cache_pages_max_sizes),
	m_cache_pages_sizes(m_cache_pages_number, 0),
	m_cache_pages_lru(new lru_list_t[m_cache_pages_number]) {
	m_lifecheck = std::thread(std::bind(&slru_cache_t::life_check, this));
}

slru_cache_t::~slru_cache_t() {
	stop();
	m_lifecheck.join();
	clear();
//	if (thread_time_stats_updater) {
//		delete thread_time_stats_updater;
//	}
}

void slru_cache_t::stop() {
	m_need_exit = true;
}

struct write_timer
{
	write_timer(dnet_node *node, const unsigned char *id) :
		type(generic), node(node), id(id), lock(0), find(0),
		remove_from_page(-1), add_to_page(-1), sync_after_append(-1),
		write_after_append(-1), populate(-1), cas(-1), modify(-1),
		syncset_update(-1), lifeset_update(-1)
	{
	}

	~write_timer()
	{
		const auto last = timer.elapsed();
		const auto total = total_timer.elapsed();
		const int level = total > 100 ? DNET_LOG_ERROR : DNET_LOG_DEBUG;

		switch (type) {
			case append_only:
				dnet_log(node, level, "%s: CACHE WRITE: append only, lock: %lld ms, find: %lld ms, "
					"create: %lld ms, remove_from_page: %lld ms, add_to_page: %lld, "
					"last: %lld ms, total: %lld ms\n",
					dnet_dump_id_str(id), lock, find, create,
					remove_from_page, add_to_page, last, total);
				break;
			case write_after_append_only:
				dnet_log(node, level, "%s: CACHE WRITE: write after append, lock: %lld ms, find: %lld ms, "
					"sync_after_append: %lld ms, write_after_append: %lld ms, populate: %lld, "
					"last: %lld ms, total: %lld ms\n",
					dnet_dump_id_str(id), lock, find, sync_after_append,
					write_after_append, populate, last, total);
				break;
			case generic:
				dnet_log(node, level, "%s: CACHE WRITE: write, lock: %lld ms, find: %lld ms, "
					"populate: %lld ms, create: %lld ms, cas: %lld ms, remove_from_page: %lld ms, "
					"modify: %lld ms, add_to_page: %lld ms, syncset_update: %lld ms, lifeset_update: %lld ms"
					"last: %lld ms, total: %lld ms\n",
					dnet_dump_id_str(id), lock, find, populate, create, cas, remove_from_page,
					modify, add_to_page, syncset_update, lifeset_update, last, total);
				break;
		}
	}

	inline long long int restart()
	{
		return timer.restart();
	}

	elliptics_timer total_timer;
	elliptics_timer timer;

	enum write_type {
		append_only,
		write_after_append_only,
		generic
	} type;

	dnet_node *node;
	const unsigned char *id;
	long long int lock;
	long long int find;
	long long int create;
	long long int remove_from_page;
	long long int add_to_page;
	long long int sync_after_append;
	long long int write_after_append;
	long long int populate;
	long long int cas;
	long long int modify;
	long long int syncset_update;
	long long int lifeset_update;
};

int slru_cache_t::write(const unsigned char *id, dnet_net_state *st, dnet_cmd *cmd, dnet_io_attr *io, const char *data) {
	assert(get_time_stats_updater()->get_depth() == 0);
	action_guard write_guard(get_time_stats_updater(), ACTION_WRITE);

	const size_t lifetime = io->start;
	const size_t size = io->size;
	const bool remove_from_disk = (io->flags & DNET_IO_FLAGS_CACHE_REMOVE_FROM_DISK);
	const bool cache = (io->flags & DNET_IO_FLAGS_CACHE);
	const bool cache_only = (io->flags & DNET_IO_FLAGS_CACHE_ONLY);
	const bool append = (io->flags & DNET_IO_FLAGS_APPEND);

	write_timer timer(m_node, id);

	start_action(ACTION_LOCK);
	elliptics_unique_lock<std::mutex> guard(m_lock, m_node, "%s: CACHE WRITE: %p", dnet_dump_id_str(id), this);
	stop_action(ACTION_LOCK);

	timer.lock = timer.restart();

	start_action(ACTION_FIND);
	data_t* it = m_treap.find(id);
	stop_action(ACTION_FIND);
	timer.find = timer.restart();
	sync_if_required(it, guard);

	if (!it && !cache) {

		dnet_log(m_node, DNET_LOG_DEBUG, "%s: CACHE: not a cache call\n", dnet_dump_id_str(id));
		return -ENOTSUP;
	}

	// Optimization for append-only commands
	if (!cache_only) {
		if (append && (!it || it->only_append())) {
			action_guard write_append_only_guard(get_time_stats_updater(), ACTION_WRITE_APPEND_ONLY);
			timer.type = write_timer::append_only;

			bool new_page = false;
			if (!it) {
				it = create_data(id, 0, 0, false);
				new_page = true;
				it->set_only_append(true);
				size_t previous_eventtime = it->eventtime();
				it->set_synctime(time(NULL) + m_node->cache_sync_timeout);

				timer.create = timer.restart();
				if (previous_eventtime != it->eventtime()) {
					m_treap.decrease_key(it);
				}
			}

			auto &raw = it->data()->data();
			size_t page_number = it->cache_page_number();
			size_t new_page_number = page_number;
			size_t new_size = it->size() + io->size;
			timer.remove_from_page = timer.restart();

			// Moving item to hotter page
			if (!new_page) {
				new_page_number = get_next_page_number(page_number);
			}

			remove_data_from_page(id, page_number, &*it);
			resize_page(id, new_page_number, 2 * new_size);

			m_cache_stats.size_of_objects -= it->size();
			raw.insert(raw.end(), data, data + io->size);
			m_cache_stats.size_of_objects += it->size();

			insert_data_into_page(id, new_page_number, &*it);
			timer.add_to_page = timer.restart();

			it->set_timestamp(io->timestamp);
			it->set_user_flags(io->user_flags);

			cmd->flags &= ~DNET_FLAGS_NEED_ACK;
			return dnet_send_file_info_ts_without_fd(st, cmd, data, io->size, &io->timestamp);
		} else if (it && it->only_append()) {
			action_guard write_after_append_only_guard(get_time_stats_updater(), ACTION_WRITE_AFTER_APPEND_ONLY);
			timer.type = write_timer::write_after_append_only;

			sync_after_append(guard, false, &*it);
			timer.sync_after_append = timer.restart();

			local_session sess(m_node);
			sess.set_ioflags(DNET_IO_FLAGS_NOCACHE | DNET_IO_FLAGS_APPEND);

			int err = m_node->cb->command_handler(st, m_node->cb->command_private, cmd, io);
			timer.write_after_append = timer.restart();

			it = populate_from_disk(guard, id, false, &err);

			timer.populate = timer.restart();
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
			timer.populate = timer.restart();
			new_page = true;

			if (err != 0 && err != -ENOENT)
				return err;
		}

		// Create empty data for code simplifyng
		if (!it) {
			it = create_data(id, 0, 0, remove_from_disk);
			new_page = true;
			timer.create = timer.restart();
		}
	}

	raw_data_t &raw = *it->data();

	if (io->flags & DNET_IO_FLAGS_COMPARE_AND_SWAP) {
		// Data is already in memory, so it's free to use it
		// raw.size() is zero only if there is no such file on the server
		if (raw.size() != 0) {
			struct dnet_raw_id csum;
			dnet_transform_node(m_node, raw.data().data(), raw.size(), csum.id, sizeof(csum.id));

			if (memcmp(csum.id, io->parent, DNET_ID_SIZE)) {
				timer.cas = timer.restart();
				dnet_log(m_node, DNET_LOG_ERROR, "%s: cas: cache checksum mismatch\n", dnet_dump_id(&cmd->id));
				return -EBADFD;
			}
		}
		timer.cas = timer.restart();
	}

	dnet_log(m_node, DNET_LOG_DEBUG, "%s: CACHE: CAS checked: %lld ms\n", dnet_dump_id_str(id), timer.restart());

	size_t new_data_size = 0;

	if (append) {
		new_data_size = raw.size() + size;
	} else {
		new_data_size = io->offset + io->size;
	}

	size_t new_size = new_data_size + it->overhead_size();

	size_t page_number = it->cache_page_number();
	size_t new_page_number = page_number;
	timer.remove_from_page = timer.restart();

	if (!new_page) {
		new_page_number = get_next_page_number(page_number);
	}

	remove_data_from_page(id, page_number, &*it);
	timer.restart();
	resize_page(id, new_page_number, 2 * new_size);

	m_cache_stats.size_of_objects -= it->size();
	if (append) {
		raw.data().insert(raw.data().end(), data, data + size);
	} else {
		raw.data().resize(new_data_size);
		memcpy(raw.data().data() + io->offset, data, size);
	}
	timer.modify = timer.restart();
	m_cache_stats.size_of_objects += it->size();

	it->set_remove_from_cache(false);
	insert_data_into_page(id, new_page_number, &*it);
	timer.add_to_page = timer.restart();

	dnet_log(m_node, DNET_LOG_DEBUG, "%s: CACHE: data modified: %lld ms\n", dnet_dump_id_str(id), timer.restart());

	// Mark data as dirty one, so it will be synced to the disk

	size_t previous_eventtime = it->eventtime();

	if (!it->synctime() && !(io->flags & DNET_IO_FLAGS_CACHE_ONLY)) {
		it->set_synctime(time(NULL) + m_node->cache_sync_timeout);
	}
	timer.syncset_update = timer.restart();

	if (lifetime) {
		it->set_lifetime(lifetime + time(NULL));
	}

	if (previous_eventtime != it->eventtime()) {
		m_treap.decrease_key(it);
	}
	timer.lifeset_update = timer.restart();

	it->set_timestamp(io->timestamp);
	it->set_user_flags(io->user_flags);

	cmd->flags &= ~DNET_FLAGS_NEED_ACK;
	return dnet_send_file_info_ts_without_fd(st, cmd, raw.data().data() + io->offset, io->size, &io->timestamp);
}

struct read_timer
{
	read_timer(dnet_node *node, const unsigned char *id) :
		node(node), id(id), lock(0), find(0), sync_after_append(-1),
		populate(-1), remove_from_page(-1), add_to_page(-1)
	{
	}

	~read_timer()
	{
		const unsigned long long total = total_timer.elapsed();
		const int level = total > 100 ? DNET_LOG_ERROR : DNET_LOG_DEBUG;

		dnet_log(node, level, "%s: CACHE READ: lock: %lld ms, find: %lld ms, "
			"sync_after_append: %lld ms, populate: %lld ms, "
			"remove_from_page: %lld ms, add_to_page: %lld ms, last: %lld ms, total: %lld ms\n",
			dnet_dump_id_str(id), lock, find, sync_after_append, populate,
			remove_from_page, add_to_page, timer.elapsed(), total);
	}

	inline long long int restart()
	{
		return timer.restart();
	}

	elliptics_timer total_timer;
	elliptics_timer timer;

	dnet_node *node;
	const unsigned char *id;
	long long int lock;
	long long int find;
	long long int sync_after_append;
	long long int populate;
	long long int remove_from_page;
	long long int add_to_page;
};

std::shared_ptr<raw_data_t> slru_cache_t::read(const unsigned char *id, dnet_cmd *cmd, dnet_io_attr *io) {
	action_guard read_guard(get_time_stats_updater(), ACTION_READ);

	const bool cache = (io->flags & DNET_IO_FLAGS_CACHE);
	const bool cache_only = (io->flags & DNET_IO_FLAGS_CACHE_ONLY);
	(void) cmd;

	read_timer timer(m_node, id);

	elliptics_unique_lock<std::mutex> guard(m_lock, m_node, "%s: CACHE READ: %p", dnet_dump_id_str(id), this);
	timer.lock = timer.restart();

	bool new_page = false;

	data_t* it = m_treap.find(id);
	timer.find = timer.restart();
	sync_if_required(it, guard);

	if (it && it->only_append()) {

		sync_after_append(guard, true, &*it);
		timer.sync_after_append = timer.restart();

		it = NULL;
	}

	if (!it && cache && !cache_only) {
		int err = 0;
		it = populate_from_disk(guard, id, false, &err);
		new_page = true;
		timer.populate = timer.restart();
	}

	if (it) {
		size_t page_number = it->cache_page_number();
		size_t new_page_number = page_number;

		it->set_remove_from_cache(false);

		timer.remove_from_page = timer.restart();

		if (!new_page) {
			new_page_number = get_next_page_number(page_number);
		}

		move_data_between_pages(id, page_number, new_page_number, &*it);
		timer.add_to_page = timer.restart();

		io->timestamp = it->timestamp();
		io->user_flags = it->user_flags();
		return it->data();
	}

	return std::shared_ptr<raw_data_t>();
}

struct remove_timer
{
	remove_timer(dnet_node *node, const unsigned char *id) :
		node(node), id(id), lock(0), find(0), erase(-1),
		setup(-1), local_remove(-1)
	{
	}

	~remove_timer()
	{
		const unsigned long long total = total_timer.elapsed();
		const int level = total > 100 ? DNET_LOG_ERROR : DNET_LOG_DEBUG;

		dnet_log(node, level, "%s: CACHE REMOVE: lock: %lld ms, find: %lld ms, "
			"erase: %lld ms, setup: %lld ms, local_remove: %lld ms, last: %lld ms, total: %lld ms\n",
			dnet_dump_id_str(id), lock, find, erase, setup,
			local_remove, timer.elapsed(), total);
	}

	inline long long int restart()
	{
		return timer.restart();
	}

	elliptics_timer total_timer;
	elliptics_timer timer;

	dnet_node *node;
	const unsigned char *id;
	long long int lock;
	long long int find;
	long long int erase;
	long long int setup;
	long long int local_remove;
};

int slru_cache_t::remove(const unsigned char *id, dnet_io_attr *io) {
	action_guard remove_guard(get_time_stats_updater(), ACTION_REMOVE);

	const bool cache_only = (io->flags & DNET_IO_FLAGS_CACHE_ONLY);
	bool remove_from_disk = !cache_only;
	int err = -ENOENT;

	remove_timer timer(m_node, id);

	elliptics_unique_lock<std::mutex> guard(m_lock, m_node, "%s: CACHE REMOVE: %p", dnet_dump_id_str(id), this);
	timer.lock = timer.restart();

	data_t* it = m_treap.find(id);
	timer.find = timer.restart();
	sync_if_required(it, guard);

	if (it) {

		// If cache_only is not set the data also should be remove from the disk
		// If data is marked and cache_only is not set - data must be synced to the disk
		remove_from_disk |= it->remove_from_disk();
		if (it->synctime() && !cache_only) {
			size_t previous_eventtime = it->eventtime();
			it->clear_synctime();

			if (previous_eventtime != it->eventtime()) {
				m_treap.decrease_key(it);
			}
		}
		erase_element(&(*it));
		err = 0;
		timer.erase = timer.restart();
	}

	guard.unlock();

	if (remove_from_disk) {
		struct dnet_id raw;
		memset(&raw, 0, sizeof(struct dnet_id));

		dnet_setup_id(&raw, 0, (unsigned char *)id);

		timer.setup = timer.restart();

		int local_err = dnet_remove_local(m_node, &raw);
		if (local_err != -ENOENT)
			err = local_err;

		timer.local_remove = timer.restart();
	}

	return err;
}

struct lookup_timer
{
	lookup_timer(dnet_node *node, const unsigned char *id) :
		node(node), id(id), lock(0), find(0), local_lookup(-1), parsed_info(-1)
	{
	}

	~lookup_timer()
	{
		const unsigned long long total = total_timer.elapsed();
		const int level = total > 100 ? DNET_LOG_ERROR : DNET_LOG_DEBUG;

		dnet_log(node, level, "%s: CACHE LOOKUP: lock: %lld ms, find: %lld ms, "
			"local_lookup: %lld ms, parsed_info: %lld ms, last: %lld ms, total: %lld ms\n",
			dnet_dump_id_str(id), lock, find, local_lookup, parsed_info, timer.elapsed(), total);
	}

	inline long long int restart()
	{
		return timer.restart();
	}

	elliptics_timer total_timer;
	elliptics_timer timer;

	dnet_node *node;
	const unsigned char *id;
	long long int lock;
	long long int find;
	long long int local_lookup;
	long long int parsed_info;
};

int slru_cache_t::lookup(const unsigned char *id, dnet_net_state *st, dnet_cmd *cmd) {
	action_guard lookup_guard(get_time_stats_updater(), ACTION_LOOKUP);

	int err = 0;

	lookup_timer timer(m_node, id);

	elliptics_unique_lock<std::mutex> guard(m_lock, m_node, "%s: CACHE LOOKUP: %p", dnet_dump_id_str(id), this);
	timer.lock = timer.restart();

	data_t* it = m_treap.find(id);
	timer.find = timer.restart();
	sync_if_required(it, guard);

	if (!it) {

		return -ENOTSUP;
	}

	dnet_time timestamp = it->timestamp();

	guard.unlock();

	local_session sess(m_node);

	cmd->flags |= DNET_FLAGS_NOCACHE;

	ioremap::elliptics::data_pointer data = sess.lookup(*cmd, &err);
	timer.local_lookup = timer.restart();

	cmd->flags &= ~DNET_FLAGS_NOCACHE;

	if (err) {
		cmd->flags &= ~DNET_FLAGS_NEED_ACK;
		return dnet_send_file_info_ts_without_fd(st, cmd, NULL, 0, &timestamp);
	}

	dnet_file_info *info = data.skip<dnet_addr>().data<dnet_file_info>();
	info->mtime = timestamp;
	timer.parsed_info = timer.restart();

	cmd->flags &= (DNET_FLAGS_MORE | DNET_FLAGS_NEED_ACK);
	return dnet_send_reply(st, cmd, data.data(), data.size(), 0);
}

void slru_cache_t::clear() {
//	action_guard clear_guard(get_time_stats_updater(), ACTION_CLEAR);

	std::vector<size_t> cache_pages_max_sizes = m_cache_pages_max_sizes;

	elliptics_unique_lock<std::mutex> guard(m_lock, m_node, "CACHE CLEAR: %p", this);

	for (size_t page_number = 0; page_number < m_cache_pages_number; ++page_number) {
		m_cache_pages_max_sizes[page_number] = 0;
		resize_page((unsigned char *) "", page_number, 0);
	}

	while (!m_treap.empty()) {
		erase_element(m_treap.top());
	}

	m_cache_pages_max_sizes = cache_pages_max_sizes;
}

cache_stats slru_cache_t::get_cache_stats() const {
	m_cache_stats.pages_sizes = m_cache_pages_sizes;
	m_cache_stats.pages_max_sizes = m_cache_pages_max_sizes;
	return m_cache_stats;
}

rapidjson::Value &slru_cache_t::get_time_stats(rapidjson::Value &stat_value, rapidjson::Document::AllocatorType &allocator) const {
	return m_time_stats.to_json(stat_value, allocator);
}

time_stats_tree_t &slru_cache_t::time_stats() {
	return m_time_stats;
}

void slru_cache_t::start_action(const int action_code) {
	get_time_stats_updater()->start(action_code);
}

void slru_cache_t::stop_action(const int action_code) {
	get_time_stats_updater()->stop(action_code);
}

void slru_cache_t::sync_if_required(data_t* it, elliptics_unique_lock<std::mutex> &guard) {

	if (it && it->is_syncing()) {
		dnet_id id;
		memcpy(id.id, it->id().id, DNET_ID_SIZE);

		guard.unlock();
		dnet_oplock(m_node, &id);

		// sync_element uses local_session which always uses DNET_FLAGS_NOLOCK
		if (it->is_syncing()) {
			sync_element(id, it->only_append(), it->data()->data(), it->user_flags(), it->timestamp());
			it->set_is_syncing(false);
		}

		dnet_opunlock(m_node, &id);
		guard.lock();
	}
}

time_stats_updater_t *slru_cache_t::get_time_stats_updater() {
	if (!ioremap::cache::local::thread_time_stats_updater->has_time_stats_tree()) {
		ioremap::cache::local::thread_time_stats_updater->set_time_stats_tree(m_time_stats);
	}
	return ioremap::cache::local::thread_time_stats_updater;
}

// private:

void slru_cache_t::insert_data_into_page(const unsigned char *id, size_t page_number, data_t *data) {
	action_guard add_to_page_guard(get_time_stats_updater(), ACTION_ADD_TO_PAGE);
	elliptics_timer timer;
	size_t size = data->size();

	// Recalc used space, free enough space for new data, move object to the end of the queue
	if (m_cache_pages_sizes[page_number] + size > m_cache_pages_max_sizes[page_number]) {
		dnet_log(m_node, DNET_LOG_DEBUG, "%s: CACHE: resize called: %lld ms\n", dnet_dump_id_str(id), timer.restart());
		resize_page(id, page_number, size);
		dnet_log(m_node, DNET_LOG_DEBUG, "%s: CACHE: resize finished: %lld ms\n", dnet_dump_id_str(id), timer.restart());
	}

	data->set_cache_page_number(page_number);
	m_cache_pages_lru[page_number].push_back(*data);
	m_cache_pages_sizes[page_number] += size;
}

void slru_cache_t::remove_data_from_page(const unsigned char *id, size_t page_number, data_t *data) {
	(void) id;
	m_cache_pages_sizes[page_number] -= data->size();
	m_cache_pages_lru[page_number].erase(m_cache_pages_lru[page_number].iterator_to(*data));
}

void slru_cache_t::move_data_between_pages(const unsigned char *id, size_t source_page_number, size_t destination_page_number, data_t *data) {
	if (source_page_number != destination_page_number) {
		remove_data_from_page(id, source_page_number, data);
		insert_data_into_page(id, destination_page_number, data);
	}
}

data_t* slru_cache_t::create_data(const unsigned char *id, const char *data, size_t size, bool remove_from_disk) {
	size_t last_page_number = m_cache_pages_number - 1;

	data_t *raw = new data_t(id, 0, data, size, remove_from_disk);

	insert_data_into_page(id, last_page_number, raw);

	++m_cache_stats.number_of_objects;
	m_cache_stats.size_of_objects += raw->size();
	m_treap.insert(raw);
	return raw;
}

struct populate_timer
{
	populate_timer(dnet_node *node, const unsigned char *id) :
		node(node), id(id), init(0), local_read(0), lock(-1), create(-1)
	{
	}

	~populate_timer()
	{
		const unsigned long long total = total_timer.elapsed();
		const int level = total > 100 ? DNET_LOG_ERROR : DNET_LOG_DEBUG;

		dnet_log(node, level, "%s: CACHE: populate, init: %lld ms, local_read: %lld ms, "
			"lock: %lld ms, create: %lld ms, last: %lld ms, total: %lld ms\n",
			dnet_dump_id_str(id), init, local_read, lock, create, timer.elapsed(), total);
	}

	inline long long int restart()
	{
		return timer.restart();
	}

	elliptics_timer total_timer;
	elliptics_timer timer;

	dnet_node *node;
	const unsigned char *id;
	long long int init;
	long long int local_read;
	long long int lock;
	long long int create;
};

data_t* slru_cache_t::populate_from_disk(elliptics_unique_lock<std::mutex> &guard, const unsigned char *id, bool remove_from_disk, int *err) {
	action_guard populate_from_disk_guard(get_time_stats_updater(), ACTION_POPULATE_FROM_DISK);
	if (guard.owns_lock()) {
		guard.unlock();
	}

	populate_timer timer(m_node, id);

	local_session sess(m_node);
	sess.set_ioflags(DNET_IO_FLAGS_NOCACHE);

	dnet_id raw_id;
	memset(&raw_id, 0, sizeof(raw_id));
	memcpy(raw_id.id, id, DNET_ID_SIZE);

	uint64_t user_flags = 0;
	dnet_time timestamp;
	dnet_empty_time(&timestamp);

	timer.init = timer.restart();

	ioremap::elliptics::data_pointer data = sess.read(raw_id, &user_flags, &timestamp, err);

	timer.local_read = timer.restart();

	guard.lock();

	timer.lock = timer.restart();

	if (*err == 0) {
		auto it = create_data(id, reinterpret_cast<char *>(data.data()), data.size(), remove_from_disk);
		it->set_user_flags(user_flags);
		it->set_timestamp(timestamp);

		timer.create = timer.restart();
		return it;
	}

	return NULL;
}

bool slru_cache_t::have_enough_space(const unsigned char *id, size_t page_number, size_t reserve) {
	(void) id;
	return m_cache_pages_max_sizes[page_number] >= reserve;
}

void slru_cache_t::resize_page(const unsigned char *id, size_t page_number, size_t reserve) {
//	action_guard resize_page_guard(get_time_stats_updater(), ACTION_RESIZE_PAGE);
	elliptics_timer timer;
	elliptics_timer total_timer;

	size_t removed_size = 0;
	size_t &cache_size = m_cache_pages_sizes[page_number];
	size_t &max_cache_size = m_cache_pages_max_sizes[page_number];
	size_t previous_page_number = get_previous_page_number(page_number);

	for (auto it = m_cache_pages_lru[page_number].begin(); it != m_cache_pages_lru[page_number].end();) {
		if (max_cache_size + removed_size >= cache_size + reserve)
			break;

		data_t *raw = &*it;
		++it;

		auto inc = timer.restart();

		// If page is not last move object to previous page
		if (previous_page_number < m_cache_pages_number) {
			move_data_between_pages(id, page_number, previous_page_number, raw);
			auto remove = timer.restart();
			auto insert = timer.restart();

			dnet_log(m_node, DNET_LOG_DEBUG, "%s: CACHE: resize, inc: %lld ms, remove: %lld ms, insert: %lld ms\n",
				dnet_dump_id_str(id), inc, remove, insert);
		} else {
			if (raw->synctime() || raw->remove_from_cache()) {
				if (!raw->remove_from_cache()) {
					m_cache_stats.number_of_objects_marked_for_deletion++;
					m_cache_stats.size_of_objects_marked_for_deletion += raw->size();
					raw->set_remove_from_cache(true);

					size_t previous_eventtime = raw->eventtime();
					raw->set_synctime(1);
					if (previous_eventtime != raw->eventtime()) {
						m_treap.decrease_key(raw);
					}
				}
				auto sync = timer.restart();
				removed_size += raw->size();
				dnet_log(m_node, DNET_LOG_DEBUG, "%s: CACHE: resize, inc: %lld ms, syncset: %lld ms\n",
					dnet_dump_id_str(id), inc, sync);
			} else {
				erase_element(raw);
				auto erase = timer.restart();
				dnet_log(m_node, DNET_LOG_DEBUG, "%s: CACHE: resize, inc: %lld ms, erase: %lld ms\n",
					dnet_dump_id_str(id), inc, erase);
			}
		}
	}
	m_cache_stats.total_resize_time += timer.elapsed<std::chrono::microseconds>();

	auto total = total_timer.elapsed();
	int level = total > 100 ? DNET_LOG_ERROR : DNET_LOG_DEBUG;
	dnet_log(m_node, level, "%s: CACHE: resize, total: %lld ms\n", dnet_dump_id_str(id), total_timer.restart());
}

void slru_cache_t::erase_element(data_t *obj) {
	elliptics_timer timer;

	m_cache_stats.number_of_objects--;
	m_cache_stats.size_of_objects -= obj->size();

	size_t page_number = obj->cache_page_number();
	m_cache_pages_sizes[page_number] -= obj->size();
	m_cache_pages_lru[page_number].erase(m_cache_pages_lru[page_number].iterator_to(*obj));
	m_treap.erase(obj);

	if (obj->eventtime()) {
		if (obj->synctime()) {
			sync_element(obj);
			obj->clear_synctime();
		}
	}

	if (obj->remove_from_cache())
	{
		m_cache_stats.number_of_objects_marked_for_deletion--;
		m_cache_stats.size_of_objects_marked_for_deletion -= obj->size();
	}

	dnet_log(m_node, DNET_LOG_DEBUG, "%s: CACHE: erased element: %lld ms\n", dnet_dump_id_str(obj->id().id), timer.restart());

	delete obj;
}

void slru_cache_t::sync_element(const dnet_id &raw, bool after_append, const std::vector<char> &data, uint64_t user_flags, const dnet_time &timestamp) {
	local_session sess(m_node);
	sess.set_ioflags(DNET_IO_FLAGS_NOCACHE | (after_append ? DNET_IO_FLAGS_APPEND : 0));

	int err = sess.write(raw, data.data(), data.size(), user_flags, timestamp);
	if (err) {
		dnet_log(m_node, DNET_LOG_ERROR, "%s: CACHE: forced to sync to disk, err: %d\n", dnet_dump_id_str(raw.id), err);
	} else {
		dnet_log(m_node, DNET_LOG_DEBUG, "%s: CACHE: forced to sync to disk, err: %d\n", dnet_dump_id_str(raw.id), err);
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
	action_guard sync_after_append_guard(get_time_stats_updater(), ACTION_SYNC_AFTER_APPEND);
	elliptics_timer timer;

	std::shared_ptr<raw_data_t> raw_data = obj->data();

	obj->clear_synctime();

	dnet_id id;
	memset(&id, 0, sizeof(id));
	memcpy(id.id, obj->id().id, DNET_ID_SIZE);

	uint64_t user_flags = obj->user_flags();
	dnet_time timestamp = obj->timestamp();

	const auto timer_prepare = timer.restart();

	erase_element(&*obj);

	const auto timer_erase = timer.restart();

	guard.unlock();

	local_session sess(m_node);
	sess.set_ioflags(DNET_IO_FLAGS_NOCACHE | DNET_IO_FLAGS_APPEND);

	auto &raw = raw_data->data();

	const auto timer_before_write = timer.restart();

	int err = sess.write(id, raw.data(), raw.size(), user_flags, timestamp);

	const auto timer_after_write = timer.restart();

	if (lock_guard)
		guard.lock();

	const auto timer_lock = timer.restart();

	dnet_log(m_node, DNET_LOG_INFO, "%s: CACHE: sync after append, "
			 "prepare: %lld ms, erase: %lld ms, before_write: %lld ms, after_write: %lld ms, lock: %lld ms, err: %d",
			 dnet_dump_id_str(id.id), timer_prepare, timer_erase, timer_before_write, timer_after_write, timer_lock, err);
}

void slru_cache_t::life_check(void) {
	elliptics_timer lifecheck_timer;
	while (!m_need_exit) {
		(void) lifecheck_timer.restart();
		std::deque<struct dnet_id> remove;
		std::deque<data_t*> elements_for_sync;
		size_t last_time;
		dnet_id id;

		{
			elliptics_unique_lock<std::mutex> guard(m_lock, m_node, "CACHE LIFE: %p", this);

			elements_for_sync.clear();
			while (!m_need_exit && !m_treap.empty()) {
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
						struct dnet_id id;
						memset(&id, 0, sizeof(struct dnet_id));

						dnet_setup_id(&id, 0, (unsigned char *)it->id().id);

						remove.push_back(id);
					}

					erase_element(&(*it));
				}
				else if (it->eventtime() == it->synctime())
				{
					elements_for_sync.push_back(&*it);
					it->clear_synctime();
					it->set_is_syncing(true);
				}
			}
		}

		for (auto it = elements_for_sync.begin(); it != elements_for_sync.end(); ++it) {
			data_t *elem = *it;
			memcpy(id.id, elem->id().id, DNET_ID_SIZE);
			dnet_oplock(m_node, &id);

			// sync_element uses local_session which always uses DNET_FLAGS_NOLOCK
			if (elem->is_syncing()) {
				sync_element(id, elem->only_append(), elem->data()->data(), elem->user_flags(), elem->timestamp());
				elem->set_is_syncing(false);
			}

			dnet_opunlock(m_node, &id);
		}
		for (std::deque<struct dnet_id>::iterator it = remove.begin(); it != remove.end(); ++it) {
			dnet_remove_local(m_node, &(*it));
		}

		{
			elliptics_unique_lock<std::mutex> guard(m_lock, m_node, "CACHE CLEAR PAGES: %p", this);
			for (std::deque<data_t*>::iterator it = elements_for_sync.begin(); it != elements_for_sync.end(); ++it) {
				data_t *elem = *it;
				if (elem->synctime() <= last_time) {
					if (elem->only_append() || elem->remove_from_cache()) {
						erase_element(elem);
					}
				}
			}
		}

		m_cache_stats.total_lifecheck_time += lifecheck_timer.elapsed<std::chrono::microseconds>();
		sleep(1);
	}
}

}}
