#include "request_queue.h"


dnet_request_queue::dnet_request_queue()
: m_queue_size(0)
{
	INIT_LIST_HEAD(&m_queue);
}

dnet_request_queue::~dnet_request_queue()
{
	for (auto it = m_lock_pool.begin(); it != m_lock_pool.end(); ++it) {
		delete *it;
	}

	struct dnet_io_req *r, *tmp;
	list_for_each_entry_safe(r, tmp, &m_queue, req_entry) {
		list_del(&r->req_entry);
		dnet_io_req_free(r);
	}
}

void dnet_request_queue::push_request(dnet_io_req *req)
{
	{
		std::unique_lock<std::mutex> lock(m_queue_mutex);
		list_add_tail(&req->req_entry, &m_queue);
		++m_queue_size;
	}
	m_queue_wait.notify_one();
}

dnet_io_req *dnet_request_queue::pop_request(dnet_work_io *wio)
{
	std::unique_lock<std::mutex> lock(m_queue_mutex);

	auto r = take_request(wio);
	if (!r) {
		m_queue_wait.wait_for(lock, std::chrono::seconds(1));
		r = take_request(wio);
	}

	if (r) {
		list_del_init(&r->req_entry);
		--m_queue_size;
	}

	return r;
}

dnet_io_req *dnet_request_queue::take_request(dnet_work_io *wio)
{
	dnet_work_pool *pool = wio->pool;
	dnet_io_req *it, *tmp;
	uint64_t trans;

	/*
	 * Comment below is only related to client IO threads processing replies from the server.
	 *
	 * At any given moment of time it is forbidden for 2 IO threads to process replies for the same transaction.
	 * This may lead to the situation, when thread 1 processes final ack, while thread 2 is being handling received data.
	 * Thread 1 will free resources, which leads thread 2 to crash the whole process.
	 *
	 * Thus any transaction may only be processed on single thread at any given time.
	 * But it is possible to ping-pong transaction between multiple IO threads as long as each IO thread
	 * processes different transaction reply simultaneously.
	 *
	 * We must set current thread index to -1 to highlight that current thread currently does not perform any task,
	 * so it can be assigned any transaction reply, if it is not already claimed by another thread.
	 *
	 * If we leave here previously processed transaction id, we might stuck, since all threads will wait for those
	 * transactions they are assigned to, thus not allowing any further process, since no thread will be able to
	 * process current request and move to the next one.
	 */
	wio->trans = ~0ULL;

	if (!list_empty(&wio->list)) {
		it = list_first_entry(&wio->list, struct dnet_io_req, req_entry);
		auto cmd = reinterpret_cast<const dnet_cmd *>(it->header);
		trans = cmd->trans;
		wio->trans = trans;
		return it;
	}

	std::unique_lock<std::mutex> lock(m_locks_mutex);

	list_for_each_entry_safe(it, tmp, &m_queue, req_entry) {
		auto cmd = reinterpret_cast<const dnet_cmd *>(it->header);

		/* This is not a transaction reply, process it right now */
		if (!(cmd->flags & DNET_FLAGS_REPLY)) {
			if (cmd->flags & DNET_FLAGS_NOLOCK)
				return it;

			if (m_locked_keys.count(cmd->id) == 0) {
				auto lock_entry = take_lock_entry();
				m_locked_keys.insert(std::make_pair(cmd->id, lock_entry));
				return it;
			}
		} else {
			trans = cmd->trans;
			bool trans_in_process = false;

			for (int i = 0; i < pool->num; ++i) {
				/* Someone claimed transaction @tid */
				if (pool->wio_list[i].trans == trans) {
					list_move_tail(&it->req_entry, &pool->wio_list[i].list);
					trans_in_process = true;
					break;
				}
			}

			if (!trans_in_process) {
				wio->trans = trans;
				return it;
			}
		}
	}

	return nullptr;
}

void dnet_request_queue::release_request(const dnet_io_req *req)
{
	auto cmd = reinterpret_cast<const dnet_cmd *>(req->header);
	if (!(cmd->flags & DNET_FLAGS_REPLY) &&
	    !(cmd->flags & DNET_FLAGS_NOLOCK)) {
		release_key(&cmd->id);
	}
}

void dnet_request_queue::lock_key(const dnet_id *id)
{
	std::unique_lock<std::mutex> lock(m_locks_mutex);
	while (1) {
		auto it = m_locked_keys.find(*id);
		if (it == m_locked_keys.end())
			break;

		auto lock_entry = it->second;
		lock_entry->unlock_event.wait_for(lock, std::chrono::seconds(1));
	}
	auto lock_entry = take_lock_entry();
	m_locked_keys.insert(std::make_pair(*id, lock_entry));
}

void dnet_request_queue::unlock_key(const dnet_id *id)
{
	release_key(id);
	m_queue_wait.notify_one();
}

void dnet_request_queue::release_key(const dnet_id *id)
{
	std::unique_lock<std::mutex> lock(m_locks_mutex);
	auto it = m_locked_keys.find(*id);
	if (it != m_locked_keys.end()) {
		auto lock_entry = it->second;
		m_locked_keys.erase(it);
		put_lock_entry(lock_entry);
		lock_entry->unlock_event.notify_one();
	}
}

dnet_locks_entry *dnet_request_queue::take_lock_entry()
{
	if (m_lock_pool.empty()) {
		auto entry = new(std::nothrow) dnet_locks_entry;
		m_lock_pool.push_back(entry);
	}
	auto entry = m_lock_pool.front();
	m_lock_pool.pop_front();
	return entry;
}

void dnet_request_queue::put_lock_entry(dnet_locks_entry *entry)
{
	m_lock_pool.push_back(entry);
}

void dnet_request_queue::get_list_stats(struct list_stat *stats) const
{
	stats->list_size = m_queue_size;
}


void dnet_push_request(struct dnet_work_pool *pool, struct dnet_io_req *req)
{
	auto queue = reinterpret_cast<dnet_request_queue*>(pool->request_queue);
	queue->push_request(req);
}

struct dnet_io_req *dnet_pop_request(struct dnet_work_io *wio)
{
	struct dnet_work_pool *pool = wio->pool;
	auto queue = reinterpret_cast<dnet_request_queue*>(pool->request_queue);
	return queue->pop_request(wio);
}

void dnet_release_request(struct dnet_work_io *wio, const struct dnet_io_req *req)
{
	auto queue = reinterpret_cast<dnet_request_queue*>(wio->pool->request_queue);
	queue->release_request(req);
}

void dnet_oplock(struct dnet_backend_io *backend, const struct dnet_id *id)
{
	auto pool = backend->pool.recv_pool.pool;
	auto queue = reinterpret_cast<dnet_request_queue*>(pool->request_queue);
	queue->lock_key(id);
}

void dnet_opunlock(struct dnet_backend_io *backend, const struct dnet_id *id)
{
	auto pool = backend->pool.recv_pool.pool;
	auto queue = reinterpret_cast<dnet_request_queue*>(pool->request_queue);
	queue->unlock_key(id);
}

void dnet_get_pool_list_stats(struct dnet_work_pool *pool, struct list_stat *stats)
{
	auto queue = reinterpret_cast<dnet_request_queue*>(pool->request_queue);
	queue->get_list_stats(stats);
}

void *dnet_create_request_queue()
{
	return new(std::nothrow) dnet_request_queue;
}

void dnet_destroy_request_queue(void *queue)
{
	delete reinterpret_cast<dnet_request_queue*>(queue);
}
