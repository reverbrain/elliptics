#ifndef IOREMAP_ELLIPTICS_REQUEST_QUEUE_HPP
#define IOREMAP_ELLIPTICS_REQUEST_QUEUE_HPP

#include "elliptics.h"
#include "murmurhash.h"

#ifdef __cplusplus
#include <unordered_map>
#include <condition_variable>
#include <mutex>
#include <atomic>

namespace std
{
	template<>
	struct hash<dnet_id>
	{
		typedef dnet_id argument_type;
		typedef std::size_t result_type;

		result_type operator()(const argument_type &key) const
		{
			return MurmurHash64A(reinterpret_cast<const char *>(&key), sizeof(dnet_id), 0);
		}
	};
}

inline bool operator == (const dnet_id &lhs, const dnet_id &rhs)
{
	return !dnet_id_cmp(&lhs, &rhs);
}

struct dnet_locks_entry
{
	std::condition_variable unlock_event;
};

class dnet_request_queue
{
public:
	dnet_request_queue(int num_pool_threads);
	~dnet_request_queue();

	void push_request(dnet_io_req *req);

	dnet_io_req *pop_request(dnet_work_io *wio);
	void release_request(const dnet_io_req *req);

	void lock_key(const dnet_id *id);
	void unlock_key(const dnet_id *id);

	void get_list_stats(struct list_stat *stats) const;

private:
	dnet_io_req *take_request(dnet_work_io *wio);
	void release_key(const dnet_id *id);
	dnet_locks_entry *take_lock_entry();
	void put_lock_entry(dnet_locks_entry *entry);

private:
	struct list_head m_queue;
	std::mutex m_queue_mutex;
	std::condition_variable m_queue_wait;

	std::atomic_ullong m_queue_size;

	std::unordered_map<dnet_id, dnet_locks_entry *> m_locked_keys;
	std::list<dnet_locks_entry *> m_lock_pool;
	std::mutex m_mutex;
};

extern "C" {
#endif // __cplusplus

void *dnet_create_request_queue(int num_pool_threads);
void dnet_destroy_request_queue(void *queue);

void dnet_push_request(struct dnet_work_pool *pool, struct dnet_io_req *req);
struct dnet_io_req *dnet_pop_request(struct dnet_work_io *wio);
void dnet_release_request(struct dnet_work_io *wio, const struct dnet_io_req *req);

void dnet_get_pool_list_stats(struct dnet_work_pool *pool, struct list_stat *stats);

void dnet_oplock(struct dnet_backend_io *backend, const struct dnet_id *id);
void dnet_opunlock(struct dnet_backend_io *backend, const struct dnet_id *id);

#ifdef __cplusplus
} // extern "C"
#endif

#endif // IOREMAP_ELLIPTICS_REQUEST_QUEUE_HPP
