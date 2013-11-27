#include "slru_cache.hpp"
#include <cassert>

namespace ioremap { namespace cache {

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

	for (size_t page_number = 0; page_number < m_cache_pages_number; ++page_number) {
		m_cache_pages_max_sizes[page_number] = 0;
		resize_page((unsigned char *) "", page_number, 0);
	}

	elliptics_unique_lock<std::mutex> guard(m_lock, m_node, "~cache_t: %p", this);

	while(!m_syncset.empty()) { //removes datas from syncset
		erase_element(&*m_syncset.begin());
	}

	while(!m_lifeset.empty()) { //removes datas from lifeset
		erase_element(&*m_lifeset.begin());
	}
}

void slru_cache_t::stop() {
	m_need_exit = true;
}

int slru_cache_t::write(const unsigned char *id, dnet_net_state *st, dnet_cmd *cmd, dnet_io_attr *io, const char *data) {
	const size_t lifetime = io->start;
	const size_t size = io->size;
	const bool remove_from_disk = (io->flags & DNET_IO_FLAGS_CACHE_REMOVE_FROM_DISK);
	const bool cache = (io->flags & DNET_IO_FLAGS_CACHE);
	const bool cache_only = (io->flags & DNET_IO_FLAGS_CACHE_ONLY);
	const bool append = (io->flags & DNET_IO_FLAGS_APPEND);

	elliptics_timer timer;

	dnet_log(m_node, DNET_LOG_DEBUG, "%s: CACHE: before guard\n", dnet_dump_id_str(id));
	elliptics_unique_lock<std::mutex> guard(m_lock, m_node, "%s: CACHE WRITE: %p", dnet_dump_id_str(id), this);
	dnet_log(m_node, DNET_LOG_DEBUG, "%s: CACHE: after guard, lock: %lld ms\n", dnet_dump_id_str(id), timer.restart());

	iset_t::iterator it = m_set.find(id);

	if (it == m_set.end() && !cache) {
		dnet_log(m_node, DNET_LOG_DEBUG, "%s: CACHE: not a cache call\n", dnet_dump_id_str(id));
		return -ENOTSUP;
	}

	// Optimization for append-only commands
	if (!cache_only) {
		if (append && (it == m_set.end() || it->only_append())) {
			bool new_page = false;
			if (it == m_set.end()) {
				it = create_data(id, 0, 0, false);
				new_page = true;
				it->set_only_append(true);
				it->set_synctime(time(NULL) + m_node->cache_sync_timeout);
				m_syncset.insert(*it);
			}

			auto &raw = it->data()->data();
			size_t page_number = it->cache_page_number();

			remove_data_from_page(id, page_number, &*it);

			// Moving item to hotter page
			if (!new_page) {
				page_number = next_page_number(page_number);
			}

			m_cache_stats.size_of_objects -= it->size();
			raw.insert(raw.end(), data, data + io->size);
			m_cache_stats.size_of_objects += it->size();

			insert_data_into_page(id, page_number, &*it);

			it->set_timestamp(io->timestamp);
			it->set_user_flags(io->user_flags);

			cmd->flags &= ~DNET_FLAGS_NEED_ACK;
			return dnet_send_file_info_ts_without_fd(st, cmd, data, io->size, &io->timestamp);
		} else if (it != m_set.end() && it->only_append()) {
			sync_after_append(guard, false, &*it);

			dnet_log(m_node, DNET_LOG_DEBUG, "%s: CACHE: synced after append: %lld", dnet_dump_id_str(id), timer.restart());

			local_session sess(m_node);
			sess.set_ioflags(DNET_IO_FLAGS_NOCACHE | DNET_IO_FLAGS_APPEND);

			int err = m_node->cb->command_handler(st, m_node->cb->command_private, cmd, io);
			dnet_log(m_node, DNET_LOG_DEBUG, "%s: CACHE: second write result, cmd: %lld ms, err: %d", dnet_dump_id_str(id), timer.restart(), err);

			it = populate_from_disk(guard, id, false, &err);

			dnet_log(m_node, DNET_LOG_DEBUG, "%s: CACHE: read result, populate: %lld ms, err: %d", dnet_dump_id_str(id), timer.restart(), err);
			cmd->flags &= ~DNET_FLAGS_NEED_ACK;
			return err;
		}
	}

	bool new_page = false;

	if (it == m_set.end()) {
		dnet_log(m_node, DNET_LOG_DEBUG, "%s: CACHE: not exist\n", dnet_dump_id_str(id));
		// If file not found and CACHE flag is not set - fallback to backend request
		if (!cache_only && io->offset != 0) {
			int err = 0;
			it = populate_from_disk(guard, id, remove_from_disk, &err);
			new_page = true;

			if (err != 0 && err != -ENOENT)
				return err;
		}

		// Create empty data for code simplifyng
		if (it == m_set.end()) {
			it = create_data(id, 0, 0, remove_from_disk);
			new_page = true;
		}
	} else {
		dnet_log(m_node, DNET_LOG_DEBUG, "%s: CACHE: exists\n", dnet_dump_id_str(id));
	}
	dnet_log(m_node, DNET_LOG_DEBUG, "%s: CACHE: data ensured: %lld ms\n", dnet_dump_id_str(id), timer.restart());

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

	dnet_log(m_node, DNET_LOG_DEBUG, "%s: CACHE: CAS checked: %lld ms\n", dnet_dump_id_str(id), timer.restart());

	size_t new_size = 0;

	if (append) {
		new_size = raw.size() + size;
	} else {
		new_size = io->offset + io->size;
	}

	size_t page_number = it->cache_page_number();

	remove_data_from_page(id, page_number, &*it);

	if (!new_page) {
		page_number = next_page_number(page_number);
	}

	if (append) {
		m_cache_stats.size_of_objects -= it->size();
		raw.data().insert(raw.data().end(), data, data + size);
		m_cache_stats.size_of_objects += it->size();
	} else {
		m_cache_stats.size_of_objects -= it->size();
		raw.data().resize(new_size);
		memcpy(raw.data().data() + io->offset, data, size);
		m_cache_stats.size_of_objects += it->size();
	}

	it->set_remove_from_cache(false);
	insert_data_into_page(id, page_number, &*it);

	dnet_log(m_node, DNET_LOG_DEBUG, "%s: CACHE: data modified: %lld ms\n", dnet_dump_id_str(id), timer.restart());

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

	dnet_log(m_node, DNET_LOG_DEBUG, "%s: CACHE: finished write: %lld ms\n", dnet_dump_id_str(id), timer.restart());

	cmd->flags &= ~DNET_FLAGS_NEED_ACK;
	return dnet_send_file_info_ts_without_fd(st, cmd, raw.data().data() + io->offset, io->size, &io->timestamp);
}

std::shared_ptr<raw_data_t> slru_cache_t::read(const unsigned char *id, dnet_cmd *cmd, dnet_io_attr *io) {
	const bool cache = (io->flags & DNET_IO_FLAGS_CACHE);
	const bool cache_only = (io->flags & DNET_IO_FLAGS_CACHE_ONLY);
	(void) cmd;

	elliptics_timer timer;

	dnet_log(m_node, DNET_LOG_DEBUG, "%s: CACHE READ: before guard\n", dnet_dump_id_str(id));
	elliptics_unique_lock<std::mutex> guard(m_lock, m_node, "%s: CACHE READ: %p", dnet_dump_id_str(id), this);
	dnet_log(m_node, DNET_LOG_DEBUG, "%s: CACHE READ: after guard, lock: %lld ms\n", dnet_dump_id_str(id), timer.restart());

	bool new_page = false;

	iset_t::iterator it = m_set.find(id);
	if (it != m_set.end() && it->only_append()) {
		sync_after_append(guard, true, &*it);
		dnet_log(m_node, DNET_LOG_DEBUG, "%s: CACHE READ: synced append-only data, find+sync: %lld ms\n", dnet_dump_id_str(id), timer.restart());

		it = m_set.end();
	}
	timer.restart();

	if (it == m_set.end() && cache && !cache_only) {
		dnet_log(m_node, DNET_LOG_DEBUG, "%s: CACHE READ: not exist\n", dnet_dump_id_str(id));
		int err = 0;
		it = populate_from_disk(guard, id, false, &err);
		new_page = true;
	} else {
		dnet_log(m_node, DNET_LOG_DEBUG, "%s: CACHE READ: exists\n", dnet_dump_id_str(id));
	}

	dnet_log(m_node, DNET_LOG_DEBUG, "%s: CACHE READ: data ensured: %lld ms\n", dnet_dump_id_str(id), timer.restart());

	if (it != m_set.end()) {

		size_t page_number = it->cache_page_number();

		it->set_remove_from_cache(false);
		remove_data_from_page(id, page_number, &*it);

		if (!new_page) {
			page_number = next_page_number(page_number);
		}

		insert_data_into_page(id, page_number, &*it);

		io->timestamp = it->timestamp();
		io->user_flags = it->user_flags();
		dnet_log(m_node, DNET_LOG_DEBUG, "%s: CACHE READ: returned: %lld ms\n", dnet_dump_id_str(id), timer.restart());
		return it->data();
	}

	return std::shared_ptr<raw_data_t>();
}

int slru_cache_t::remove(const unsigned char *id, dnet_io_attr *io) {
	const bool cache_only = (io->flags & DNET_IO_FLAGS_CACHE_ONLY);
	bool remove_from_disk = !cache_only;
	int err = -ENOENT;

	elliptics_timer timer;

	dnet_log(m_node, DNET_LOG_DEBUG, "%s: CACHE REMOVE: before guard\n", dnet_dump_id_str(id));
	elliptics_unique_lock<std::mutex> guard(m_lock, m_node, "%s: CACHE REMOVE: %p", dnet_dump_id_str(id), this);
	dnet_log(m_node, DNET_LOG_DEBUG, "%s: CACHE REMOVE: after guard, lock: %lld ms\n", dnet_dump_id_str(id), timer.restart());

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
		dnet_log(m_node, DNET_LOG_DEBUG, "%s: CACHE REMOVE: erased: %lld ms\n", dnet_dump_id_str(id), timer.restart());
	}

	guard.unlock();

	if (remove_from_disk) {
		struct dnet_id raw;
		memset(&raw, 0, sizeof(struct dnet_id));

		dnet_setup_id(&raw, 0, (unsigned char *)id);

		dnet_log(m_node, DNET_LOG_DEBUG, "%s: CACHE REMOVE: before removing from disk\n", dnet_dump_id_str(id));
		timer.restart();
		int local_err = dnet_remove_local(m_node, &raw);
		if (local_err != -ENOENT)
			err = local_err;
		dnet_log(m_node, DNET_LOG_DEBUG, "%s: CACHE REMOVE: after removing from disk: %lld ms\n", dnet_dump_id_str(id), timer.restart());
	}

	return err;
}

int slru_cache_t::lookup(const unsigned char *id, dnet_net_state *st, dnet_cmd *cmd) {
	int err = 0;

	elliptics_timer timer;

	dnet_log(m_node, DNET_LOG_DEBUG, "%s: CACHE LOOKUP: before guard\n", dnet_dump_id_str(id));
	elliptics_unique_lock<std::mutex> guard(m_lock, m_node, "%s: CACHE LOOKUP: %p", dnet_dump_id_str(id), this);
	dnet_log(m_node, DNET_LOG_DEBUG, "%s: CACHE LOOKUP: after guard, lock: %lld ms\n", dnet_dump_id_str(id), timer.restart());

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

cache_stats slru_cache_t::get_cache_stats() const
{
	return m_cache_stats;
}

// private:

void slru_cache_t::insert_data_into_page(const unsigned char *id, size_t page_number, data_t *data)
{
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

void slru_cache_t::remove_data_from_page(const unsigned char *id, size_t page_number, data_t *data)
{
	(void) id;
	m_cache_pages_sizes[page_number] -= data->size();
	m_cache_pages_lru[page_number].erase(m_cache_pages_lru[page_number].iterator_to(*data));
}

iset_t::iterator slru_cache_t::create_data(const unsigned char *id, const char *data, size_t size, bool remove_from_disk) {
	size_t last_page_number = m_cache_pages_number - 1;

	data_t *raw = new data_t(id, 0, data, size, remove_from_disk);

	insert_data_into_page(id, last_page_number, raw);

	++m_cache_stats.number_of_objects;
	m_cache_stats.size_of_objects += raw->size();
	return m_set.insert(*raw).first;
}

iset_t::iterator slru_cache_t::populate_from_disk(elliptics_unique_lock<std::mutex> &guard, const unsigned char *id, bool remove_from_disk, int *err) {
	if (guard.owns_lock()) {
		guard.unlock();
	}

	elliptics_timer timer;

	local_session sess(m_node);
	sess.set_ioflags(DNET_IO_FLAGS_NOCACHE);

	dnet_id raw_id;
	memset(&raw_id, 0, sizeof(raw_id));
	memcpy(raw_id.id, id, DNET_ID_SIZE);

	uint64_t user_flags = 0;
	dnet_time timestamp;
	dnet_empty_time(&timestamp);

	dnet_log(m_node, DNET_LOG_DEBUG, "%s: CACHE: populating from disk started: %lld ms\n", dnet_dump_id_str(id), timer.restart());

	ioremap::elliptics::data_pointer data = sess.read(raw_id, &user_flags, &timestamp, err);

	dnet_log(m_node, DNET_LOG_DEBUG, "%s: CACHE: populating from disk finished: %lld ms, err: %d\n", dnet_dump_id_str(id), timer.restart(), *err);

	dnet_log(m_node, DNET_LOG_DEBUG, "%s: CACHE: populating from disk, before lock: %lld ms\n", dnet_dump_id_str(id), timer.restart());
	guard.lock();
	dnet_log(m_node, DNET_LOG_DEBUG, "%s: CACHE: populating from disk, after lock: %lld ms\n", dnet_dump_id_str(id), timer.restart());

	if (*err == 0) {
		auto it = create_data(id, reinterpret_cast<char *>(data.data()), data.size(), remove_from_disk);
		it->set_user_flags(user_flags);
		it->set_timestamp(timestamp);
		dnet_log(m_node, DNET_LOG_DEBUG, "%s: CACHE: populating from disk, data created: %lld ms\n", dnet_dump_id_str(id), timer.restart());
		return it;
	}

	return m_set.end();
}

void slru_cache_t::resize_page(const unsigned char *id, size_t page_number, size_t reserve) {
	size_t removed_size = 0;
	size_t &cache_size = m_cache_pages_sizes[page_number];
	size_t &max_cache_size = m_cache_pages_max_sizes[page_number];
	size_t previous_page = previous_page_number(page_number);

	for (auto it = m_cache_pages_lru[page_number].begin(); it != m_cache_pages_lru[page_number].end();) {
		if (max_cache_size + removed_size >= cache_size + reserve)
			break;

		data_t *raw = &*it;
		++it;

		// If page is not last move object to previous page
		if (previous_page < m_cache_pages_number) {
			remove_data_from_page(id, page_number, raw);
			insert_data_into_page(id, previous_page, raw);
		} else {
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
}

void slru_cache_t::erase_element(data_t *obj) {
	elliptics_timer timer;

	size_t page_number = obj->cache_page_number();
	m_cache_pages_lru[page_number].erase(m_cache_pages_lru[page_number].iterator_to(*obj));
	m_set.erase(m_set.iterator_to(*obj));
	if (obj->lifetime())
		m_lifeset.erase(m_lifeset.iterator_to(*obj));

	if (obj->synctime()) {
		sync_element(obj);

		m_syncset.erase(m_syncset.iterator_to(*obj));
		obj->clear_synctime();
	}

	m_cache_pages_sizes[page_number] -= obj->size();
	--m_cache_stats.number_of_objects;
	m_cache_stats.size_of_objects -= obj->size();

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
	elliptics_timer timer;

	std::shared_ptr<raw_data_t> raw_data = obj->data();
	m_syncset.erase(m_syncset.iterator_to(*obj));
	obj->set_synctime(0);

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
	while (!m_need_exit) {
		std::deque<struct dnet_id> remove;

		while (!m_need_exit && !m_lifeset.empty()) {
			size_t time = ::time(NULL);

			elliptics_unique_lock<std::mutex> guard(m_lock, m_node, "CACHE LIFE: %p", this);

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

			elliptics_unique_lock<std::mutex> guard(m_lock, m_node, "CACHE SYNC: %p", this);

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
			dnet_oplock(m_node, &id);

			// sync_element uses local_session which always uses DNET_FLAGS_NOLOCK
			sync_element(id, false, data, user_flags, timestamp);

			dnet_opunlock(m_node, &id);
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

}}
