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

#ifndef CACHE_HPP
#define CACHE_HPP

#include <vector>
#include <mutex>
#include <thread>
#include <cstdio>
#include <unordered_map>
#include <limits>
#if __GNUC__ == 4 && __GNUC_MINOR__ < 5
#  include <cstdatomic>
#else
#  include <atomic>
#endif

#include <boost/intrusive/list.hpp>

#include "library/elliptics.h"
#include "indexes/local_session.h"

#include "elliptics/packet.h"
#include "elliptics/interface.h"

#include "monitor/rapidjson/document.h"
#include "monitor/rapidjson/writer.h"
#include "monitor/rapidjson/stringbuffer.h"

#include "treap.hpp"

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
boost::intrusive::link_mode<boost::intrusive::safe_link>, boost::intrusive::optimize_size<true>
> lru_list_base_hook_t;

class data_t;

template<>
struct treap_node_traits<data_t>
{
    typedef const uint8_t* key_type;
    typedef size_t priority_type;
};

class data_t : public lru_list_base_hook_t, public treap_node_t<data_t> {
public:
	enum class sync_state_t : char {
		NOT_SYNCING,
		SYNC_PHASE,
		ERASE_PHASE,
	};

	data_t(const unsigned char *id) :
		m_lifetime(0), m_synctime(0), m_user_flags(0),
		m_remove_from_disk(false), m_remove_from_cache(false),
		m_only_append(false), m_removed_from_page(true), m_sync_state(sync_state_t::NOT_SYNCING) {
		memcpy(m_id.id, id, DNET_ID_SIZE);
		dnet_empty_time(&m_timestamp);
	}

	data_t(const unsigned char *id, size_t lifetime, const char *data, size_t size, bool remove_from_disk) :
		m_lifetime(0), m_synctime(0), m_user_flags(0),
		m_remove_from_disk(remove_from_disk), m_remove_from_cache(false),
		m_only_append(false), m_removed_from_page(true), m_sync_state(sync_state_t::NOT_SYNCING) {
		memcpy(m_id.id, id, DNET_ID_SIZE);
		dnet_empty_time(&m_timestamp);

		if (lifetime)
			m_lifetime = lifetime + time(NULL);

		m_data.reset(new raw_data_t(data, size));
	}

	data_t(const data_t &other) = delete;
	data_t &operator =(const data_t &other) = delete;

	~data_t() {
		if (!is_removed_from_page()) {
			std::cerr << "~data_t(): element is not removed from cache" << std::endl;
		}
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

	size_t eventtime() const {
		size_t time = 0;
		if (!time || (lifetime() && time > lifetime()))
		{
			time = lifetime();
		}
		if (!time || (synctime() && time > synctime()))
		{
			time = synctime();
		}
		if (!time)
		{
			time = std::numeric_limits<size_t>::max();
		}
		return time;
	}

	size_t cache_page_number() const {
		return m_cache_page_number;
	}

	void set_cache_page_number(size_t cache_page_number) {
		m_cache_page_number = cache_page_number;
		if (!is_removed_from_page()) {
			std::cerr << "Element is not removed from cache page" << std::endl;
		}
		set_removed_from_page(false);
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

	sync_state_t sync_state() const {
		return m_sync_state;
	}

	void set_sync_state(sync_state_t sync_state) {
		m_sync_state = sync_state;
	}

	bool is_syncing() const {
		return m_sync_state == sync_state_t::SYNC_PHASE;
	}

	bool will_be_erased() const {
		return m_sync_state != sync_state_t::NOT_SYNCING;
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

	bool is_removed_from_page() const {
		return m_removed_from_page;
	}

	void set_removed_from_page(bool removed_from_page) {
		m_removed_from_page = removed_from_page;
	}

	size_t size(void) const {
		return capacity() + overhead_size();
	}

	size_t overhead_size(void) const {
		return sizeof(*this) + sizeof(*m_data);
	}

	size_t capacity(void) const {
		return m_data->data().capacity();
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

    // treap_node_t
    typedef typename treap_node_traits<data_t>::key_type key_type;
    typedef typename treap_node_traits<data_t>::priority_type priority_type;

    key_type get_key() const {
        return m_id.id;
    }

    priority_type get_priority() const {
        return eventtime();
    }

    inline static int compare_keys(const key_type &a, const key_type &b) {
        return dnet_id_cmp_str(a, b);
    }

    inline static int compare_priorities(const priority_type &a, const priority_type &b) {
        if (a < b) {
			return 1;
		}

		if (a > b) {
			return -1;
		}

		return 0;
    }

private:
	size_t m_lifetime;
	size_t m_synctime;
	dnet_time m_timestamp;
	uint64_t m_user_flags;
	bool m_remove_from_disk;
	bool m_remove_from_cache;
	bool m_only_append;
	bool m_removed_from_page;
	sync_state_t m_sync_state;
	char m_cache_page_number;
	struct dnet_raw_id m_id;
	std::shared_ptr<raw_data_t> m_data;
};

struct record_info {
	record_info(data_t* obj) {
		only_append = obj->only_append();
		memcpy(id.id, obj->id().id, DNET_ID_SIZE);
		data = obj->data()->data();
		user_flags = obj->user_flags();
		timestamp = obj->timestamp();
		is_synced = false;
	}

	bool operator< (const record_info& other) const {
		return dnet_id_cmp_str(id.id, other.id.id) < 0;
	}

	bool is_synced;
	bool only_append;
	dnet_id id;
	std::vector<char> data;
	uint64_t user_flags;
	dnet_time timestamp;
};

struct record_id_less {
	bool operator() (const record_info& lhs, const unsigned char* id) const {
		return dnet_id_cmp_str(lhs.id.id, id);
	}
};

typedef boost::intrusive::list<data_t, boost::intrusive::base_hook<lru_list_base_hook_t> > lru_list_t;

struct eventtime_less {
	bool operator() (const data_t &x, const data_t &y) const {
		return x.eventtime() < y.eventtime()
				|| (x.eventtime() == y.eventtime() && ((&x) < (&y)));
	}
};

typedef treap<data_t> treap_t;

struct cache_stats {
	cache_stats():
		number_of_objects(0), size_of_objects(0),
		number_of_objects_marked_for_deletion(0), size_of_objects_marked_for_deletion(0) {}

	std::size_t number_of_objects;
	std::size_t size_of_objects;
	std::size_t number_of_objects_marked_for_deletion;
	std::size_t size_of_objects_marked_for_deletion;

	std::vector<size_t> pages_sizes;
	std::vector<size_t> pages_max_sizes;

	rapidjson::Value& to_json(rapidjson::Value &stat_value, rapidjson::Document::AllocatorType &allocator) const {
		stat_value.AddMember("size", size_of_objects, allocator)
				  .AddMember("removing_size", size_of_objects_marked_for_deletion, allocator)
				  .AddMember("objects", number_of_objects, allocator)
				  .AddMember("removing_objects", number_of_objects_marked_for_deletion, allocator);

		rapidjson::Value pages_sizes_stat(rapidjson::kArrayType);
		for (auto it = pages_sizes.begin(), end = pages_sizes.end(); it != end; ++it) {
			pages_sizes_stat.PushBack(*it, allocator);
		}
		stat_value.AddMember("pages_sizes", pages_sizes_stat, allocator);

		rapidjson::Value pages_max_sizes_stat(rapidjson::kArrayType);
		for (auto it = pages_max_sizes.begin(), end = pages_max_sizes.end(); it != end; ++it) {
			pages_max_sizes_stat.PushBack(*it, allocator);
		}
		stat_value.AddMember("pages_max_sizes", pages_max_sizes_stat, allocator);
		return stat_value;
	}
};

class slru_cache_t;

class cache_manager {
	public:
		cache_manager(dnet_backend_io *backend, dnet_node *n, const cache_config &config);

		~cache_manager();

		int write(const unsigned char *id, dnet_net_state *st, dnet_cmd *cmd, dnet_io_attr *io, const char *data);

		std::shared_ptr<raw_data_t> read(const unsigned char *id, dnet_cmd *cmd, dnet_io_attr *io);

		int remove(const unsigned char *id, dnet_io_attr *io);

		int lookup(const unsigned char *id, dnet_net_state *st, dnet_cmd *cmd);

		int indexes_find(dnet_cmd *cmd, dnet_indexes_request *request);

		int indexes_update(dnet_cmd *cmd, dnet_indexes_request *request);

		int indexes_internal(dnet_cmd *cmd, dnet_indexes_request *request);

		void clear();

		size_t cache_size() const;

		size_t cache_pages_number() const;

		cache_stats get_total_cache_stats() const;

		std::vector<cache_stats> get_caches_stats() const;

		rapidjson::Value& get_total_caches_size_stats_json(rapidjson::Value& stat_value, rapidjson::Document::AllocatorType &allocator) const;

		rapidjson::Value& get_total_caches_time_stats_json(rapidjson::Value& stat_value, rapidjson::Document::AllocatorType &allocator) const;

		rapidjson::Value& get_caches_size_stats_json(rapidjson::Value& stat_value, rapidjson::Document::AllocatorType &allocator) const;

		rapidjson::Value& get_caches_time_stats_json(rapidjson::Value& stat_value, rapidjson::Document::AllocatorType &allocator) const;

		std::string stat_json() const;

	private:
		dnet_node *m_node;
		std::vector<std::shared_ptr<slru_cache_t>> m_caches;
		size_t m_max_cache_size;
		size_t m_cache_pages_number;

		size_t idx(const unsigned char *id);
};

template <typename T>
class elliptics_unique_lock
{
public:
	elliptics_unique_lock(T &mutex, dnet_node *node, const char *format, ...) __attribute__ ((format(printf, 4, 5)))
		: m_node(node)
	{
		va_list args;
		va_start(args, format);

		vsnprintf(m_name, sizeof(m_name), format, args);

		va_end(args);

		long vatime = m_timer.elapsed();
		m_guard = std::move(std::unique_lock<T>(mutex));
		dnet_log_level level = DNET_LOG_DEBUG;

		if (m_timer.elapsed() > 100)
			level = DNET_LOG_ERROR;

		if (m_timer.elapsed() > 0) {
			dnet_log(m_node, level, "%s: cache lock: constructor: vatime: %ld, total: %lld ms", m_name, vatime, m_timer.elapsed());
		}

		m_timer.restart();
	}

	~elliptics_unique_lock()
	{
		if (owns_lock())
			unlock();
	}

	bool owns_lock() const
	{
		return m_guard.owns_lock();
	}

	void lock()
	{
		m_guard.lock();
		dnet_log_level level = DNET_LOG_DEBUG;

		if (m_timer.elapsed() > 100)
			level = DNET_LOG_ERROR;

		if (m_timer.elapsed() > 0) {
			dnet_log(m_node, level, "%s: cache lock: lock: %lld ms", m_name, m_timer.elapsed());
		}

		m_timer.restart();
	}

	void unlock()
	{
		m_guard.unlock();

		dnet_log_level level = DNET_LOG_DEBUG;

		if (m_timer.elapsed() > 100)
			level = DNET_LOG_ERROR;

		if (m_timer.elapsed() > 0) {
			dnet_log(m_node, level, "%s: cache lock: unlock: %lld ms", m_name, m_timer.elapsed());
		}
		m_timer.restart();
	}

private:
	std::unique_lock<T> m_guard;
	dnet_node *m_node;
	char m_name[256];
	elliptics_timer m_timer;
};

}}

#endif // CACHE_HPP
