#ifndef CACHE_HPP
#define CACHE_HPP

#include <vector>
#include <mutex>
#include <thread>
#include <cstdio>
#include <unordered_map>
#include <limits>

#include <boost/intrusive/list.hpp>

#include "../library/elliptics.h"
#include "../indexes/local_session.h"

#include "elliptics/packet.h"
#include "elliptics/interface.h"

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

class data_t : public lru_list_base_hook_t, public treap_node_t<data_t> {
public:
	data_t(const unsigned char *id) {
		memcpy(m_id.id, id, DNET_ID_SIZE);
	}

	data_t(const unsigned char *id, size_t lifetime, const char *data, size_t size, bool remove_from_disk) :
		m_lifetime(0), m_synctime(0), m_user_flags(0),
		m_remove_from_disk(remove_from_disk), m_remove_from_cache(false), m_only_append(false) {
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

private:
	size_t m_lifetime;
	size_t m_synctime;
	dnet_time m_timestamp;
	uint64_t m_user_flags;
	bool m_remove_from_disk;
	bool m_remove_from_cache;
	bool m_only_append;
	char m_cache_page_number;
	struct dnet_raw_id m_id;
	std::shared_ptr<raw_data_t> m_data;
};

typedef boost::intrusive::list<data_t, boost::intrusive::base_hook<lru_list_base_hook_t> > lru_list_t;

struct eventtime_less {
	bool operator() (const data_t &x, const data_t &y) const {
		return x.eventtime() < y.eventtime()
				|| (x.eventtime() == y.eventtime() && ((&x) < (&y)));
	}
};

typedef Treap<data_t> treap_t;

struct cache_stats {
	cache_stats(): size_of_objects(0), number_of_objects(0), number_of_objects_marked_for_deletion(0),
		size_of_objects_marked_for_deletion(0) {}

	size_t size_of_objects;
	size_t number_of_objects;
	size_t number_of_objects_marked_for_deletion;
	size_t size_of_objects_marked_for_deletion;
	std::vector<size_t> pages_sizes;
	std::vector<size_t> pages_max_sizes;
};

class slru_cache_t;

class cache_manager {
	public:
		cache_manager(struct dnet_node *n);

		~cache_manager();

		int write(const unsigned char *id, dnet_net_state *st, dnet_cmd *cmd, dnet_io_attr *io, const char *data);

		std::shared_ptr<raw_data_t> read(const unsigned char *id, dnet_cmd *cmd, dnet_io_attr *io);

		int remove(const unsigned char *id, dnet_io_attr *io);

		int lookup(const unsigned char *id, dnet_net_state *st, dnet_cmd *cmd);

		int indexes_find(dnet_cmd *cmd, dnet_indexes_request *request);

		int indexes_update(dnet_cmd *cmd, dnet_indexes_request *request);

		int indexes_internal(dnet_cmd *cmd, dnet_indexes_request *request);

		size_t cache_size() const;

		size_t cache_pages_number() const;

		cache_stats get_total_cache_stats() const;

		std::vector<cache_stats> get_caches_stats() const;

	private:
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

		m_guard = std::move(std::unique_lock<T>(mutex));
		int level = DNET_LOG_DEBUG;

		if (m_timer.elapsed() > 100)
			level = DNET_LOG_ERROR;

		dnet_log(m_node, level, "%s: cache lock: constructor: %lld ms\n", m_name, m_timer.elapsed());
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
		int level = DNET_LOG_DEBUG;

		if (m_timer.elapsed() > 100)
			level = DNET_LOG_ERROR;
		dnet_log(m_node, level, "%s: cache lock: lock: %lld ms\n", m_name, m_timer.elapsed());
		m_timer.restart();
	}

	void unlock()
	{
		m_guard.unlock();

		int level = DNET_LOG_DEBUG;

		if (m_timer.elapsed() > 100)
			level = DNET_LOG_ERROR;
		dnet_log(m_node, level, "%s: cache lock: unlock: %lld ms\n", m_name, m_timer.elapsed());
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
