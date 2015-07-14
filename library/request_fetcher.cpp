#include "request_fetcher.h"


dnet_request_fetcher::dnet_request_fetcher(int num_pool_threads)
{
	m_locked_keys.reserve(num_pool_threads);
}

/*
TODO: refactor & write comments
TODO: do not copy dnet_id, use std::unordered_set<struct dnet_id *> ?
TODO: deadbeaf in locks.c
 */
dnet_io_req *dnet_request_fetcher::take_request(dnet_work_io *wio)
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

	list_for_each_entry_safe(it, tmp, &pool->list, req_entry) {
		auto cmd = reinterpret_cast<const dnet_cmd *>(it->header);

		/* This is not a transaction reply, process it right now */
		if (!(cmd->flags & DNET_FLAGS_REPLY)) {
			if (cmd->flags & DNET_FLAGS_NOLOCK)
				return it;

			if (m_locked_keys.count(cmd->id) == 0) {
				m_locked_keys.insert(cmd->id);
				return it;
			} else
				continue;
		}

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

	return nullptr;
}

void dnet_request_fetcher::release_request(const dnet_io_req *req)
{
	auto cmd = reinterpret_cast<const dnet_cmd *>(req->header);
	if (!(cmd->flags & DNET_FLAGS_REPLY) &&
	    !(cmd->flags & DNET_FLAGS_NOLOCK)) {
		m_locked_keys.erase(cmd->id);
	}
}


struct dnet_io_req *dnet_take_request(struct dnet_work_io *wio)
{
	auto fetcher = reinterpret_cast<dnet_request_fetcher*>(wio->pool->request_fetcher);
	return fetcher->take_request(wio);
}

void dnet_release_request(struct dnet_work_io *wio, const struct dnet_io_req *req)
{
	auto fetcher = reinterpret_cast<dnet_request_fetcher*>(wio->pool->request_fetcher);
	fetcher->release_request(req);
}

void *dnet_create_request_fetcher(int num_pool_threads)
{
	return new(std::nothrow) dnet_request_fetcher(num_pool_threads);
}

void dnet_destroy_request_fetcher(void *fetcher)
{
	delete reinterpret_cast<dnet_request_fetcher*>(fetcher);
}
