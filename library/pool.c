/*
 * Copyright 2008+ Evgeniy Polyakov <zbr@ioremap.net>
 *
 * This file is part of Elliptics.
 * 
 * Elliptics is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * Elliptics is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public License
 * along with Elliptics.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <sys/stat.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>

#include "elliptics.h"
#include "elliptics/interface.h"

static char *dnet_work_io_mode_string[] = {
	[DNET_WORK_IO_MODE_BLOCKING] = "BLOCKING",
	[DNET_WORK_IO_MODE_NONBLOCKING] = "NONBLOCKING",
};

__thread uint32_t trace_id = 0;

static char *dnet_work_io_mode_str(int mode)
{
	if (mode < 0 || mode >= (int)ARRAY_SIZE(dnet_work_io_mode_string))
		return NULL;

	return dnet_work_io_mode_string[mode];
}

static void dnet_work_pool_cleanup(struct dnet_work_pool *pool)
{
	struct dnet_io_req *r, *tmp;
	struct dnet_work_io *wio, *wio_tmp;

	list_for_each_entry_safe(wio, wio_tmp, &pool->wio_list, wio_entry) {
		pthread_join(wio->tid, NULL);
		list_del(&wio->wio_entry);
		free(wio);
	}


	list_for_each_entry_safe(r, tmp, &pool->list, req_entry) {
		list_del(&r->req_entry);
		dnet_io_req_free(r);
	}

	pthread_cond_destroy(&pool->wait);
	pthread_mutex_destroy(&pool->lock);
	free(pool->trans);
	free(pool);
}

static int dnet_work_pool_grow(struct dnet_node *n, struct dnet_work_pool *pool, int num, void *(* process)(void *))
{
	int i, err;
	struct dnet_work_io *wio, *tmp;

	pthread_mutex_lock(&pool->lock);

	pool->trans = realloc(pool->trans, sizeof(uint64_t) * (pool->num + num));

	for (i = 0; i < num; ++i) {
		wio = malloc(sizeof(struct dnet_work_io));
		if (!wio) {
			err = -ENOMEM;
			goto err_out_io_threads;
		}

		wio->thread_index = i;
		wio->pool = pool;

		pool->trans[pool->num + i] = ~0ULL;

		err = pthread_create(&wio->tid, NULL, process, wio);
		if (err) {
			free(wio);
			err = -err;
			dnet_log(n, DNET_LOG_ERROR, "Failed to create IO thread: %d\n", err);
			goto err_out_io_threads;
		}

		list_add_tail(&wio->wio_entry, &pool->wio_list);
	}

	dnet_log(n, DNET_LOG_INFO, "Grew %s pool by: %d -> %d IO threads\n",
			dnet_work_io_mode_str(pool->mode), pool->num, pool->num + num);

	pool->num += num;
	pthread_mutex_unlock(&pool->lock);

	return 0;

err_out_io_threads:
	list_for_each_entry_safe(wio, tmp, &pool->wio_list, wio_entry) {
		pthread_join(wio->tid, NULL);
		list_del(&wio->wio_entry);
		free(wio);
	}

	pthread_mutex_unlock(&pool->lock);

	return err;
}

static struct dnet_work_pool *dnet_work_pool_alloc(struct dnet_node *n, int num, int mode, void *(* process)(void *))
{
	struct dnet_work_pool *pool;
	int err;

	pool = malloc(sizeof(struct dnet_work_pool));
	if (!pool) {
		err = -ENOMEM;
		goto err_out_exit;
	}

	memset(pool, 0, sizeof(struct dnet_work_pool));

	pool->num = 0;
	pool->mode = mode;
	pool->n = n;
	INIT_LIST_HEAD(&pool->list);
	list_stat_init(&pool->list_stats);
	INIT_LIST_HEAD(&pool->wio_list);

	err = pthread_mutex_init(&pool->lock, NULL);
	if (err) {
		err = -err;
		goto err_out_free;
	}

	err = pthread_cond_init(&pool->wait, NULL);
	if (err) {
		err = -err;
		goto err_out_mutex_destroy;
	}

	err = dnet_work_pool_grow(n, pool, num, process);
	if (err)
		goto err_out_cond_destroy;

	return pool;

err_out_cond_destroy:
	pthread_cond_destroy(&pool->wait);
err_out_mutex_destroy:
	pthread_mutex_destroy(&pool->lock);
err_out_free:
	free(pool);
err_out_exit:
	return NULL;
}

/* As an example (with hardcoded loglevel and one second interval) */
static inline void list_stat_log(struct list_stat *st, struct dnet_node *node, const char *list_name) {
	struct timeval tv;
	gettimeofday(&tv, NULL);

	if ((tv.tv_sec - st->time_base.tv_sec) >= 1) {
		double elapsed_seconds = (double)(tv.tv_sec - st->time_base.tv_sec) * 1000000 + (tv.tv_usec - st->time_base.tv_usec);
		elapsed_seconds /= 1000000;
		dnet_log(node, DNET_LOG_INFO, "%s report: elapsed: %.3f s, current size: %ld, min: %ld, max: %ld, volume: %ld\n",
			list_name, elapsed_seconds, st->list_size, st->min_list_size, st->max_list_size, st->volume);

		list_stat_reset(st, &tv);
	}
}


static void *dnet_io_process(void *data_);
static void dnet_schedule_io(struct dnet_node *n, struct dnet_io_req *r)
{
	struct dnet_io *io = n->io;
	struct dnet_work_pool *pool = io->recv_pool;
	struct dnet_cmd *cmd = r->header;
	int nonblocking = !!(cmd->flags & DNET_FLAGS_NOLOCK);

	if (cmd->size > 0) {
		dnet_log(r->st->n, DNET_LOG_DEBUG, "%s: %s: RECV cmd: %s: cmd-size: %llu, nonblocking: %d\n",
			dnet_state_dump_addr(r->st), dnet_dump_id(r->header), dnet_cmd_string(cmd->cmd),
			(unsigned long long)cmd->size, nonblocking);
	} else if ((cmd->size == 0) && !(cmd->flags & DNET_FLAGS_MORE) && (cmd->trans & DNET_TRANS_REPLY)) {
		dnet_log(r->st->n, DNET_LOG_DEBUG, "%s: %s: RECV ACK: %s: nonblocking: %d\n",
			dnet_state_dump_addr(r->st), dnet_dump_id(r->header), dnet_cmd_string(cmd->cmd), nonblocking);
	} else {
		unsigned long long tid = cmd->trans & ~DNET_TRANS_REPLY;
		int reply = !!(cmd->trans & DNET_TRANS_REPLY);

		dnet_log(r->st->n, DNET_LOG_DEBUG, "%s: %s: RECV: %s: nonblocking: %d, cmd-size: %llu, cflags: 0x%llx, trans: %lld, reply: %d\n",
			dnet_state_dump_addr(r->st), dnet_dump_id(r->header), dnet_cmd_string(cmd->cmd), nonblocking,
			(unsigned long long)cmd->size, (unsigned long long)cmd->flags, tid, reply);
	}

	if (nonblocking)
		pool = io->recv_pool_nb;

	pthread_mutex_lock(&pool->lock);
	list_add_tail(&r->req_entry, &pool->list);
	list_stat_size_increase(&pool->list_stats, 1);
	list_stat_log(&pool->list_stats, r->st->n, "input io queue");
	pthread_cond_signal(&pool->wait);
	pthread_mutex_unlock(&pool->lock);
}


void dnet_schedule_command(struct dnet_net_state *st)
{
	st->rcv_flags = DNET_IO_CMD;

	if (st->rcv_data) {
#if 0
		struct dnet_cmd *c = &st->rcv_cmd;
		unsigned long long tid = c->trans & ~DNET_TRANS_REPLY;
		dnet_log(st->n, DNET_LOG_DEBUG, "freed: size: %llu, trans: %llu, reply: %d, ptr: %p.\n",
						(unsigned long long)c->size, tid, tid != c->trans, st->rcv_data);
#endif
		free(st->rcv_data);
		st->rcv_data = NULL;
	}

	st->rcv_end = sizeof(struct dnet_cmd);
	st->rcv_offset = 0;
}

static int dnet_process_recv_single(struct dnet_net_state *st)
{
	struct dnet_node *n = st->n;
	struct dnet_io_req *r;
	void *data;
	uint64_t size;
	int err;

again:
	/*
	 * Reading command first.
	 */
	if (st->rcv_flags & DNET_IO_CMD)
		data = &st->rcv_cmd;
	else
		data = st->rcv_data;
	data += st->rcv_offset;
	size = st->rcv_end - st->rcv_offset;

	if (size) {
		err = recv(st->read_s, data, size, 0);
		if (err < 0) {
			err = -EAGAIN;
			if (errno != EAGAIN && errno != EINTR) {
				err = -errno;
				dnet_log_err(n, "%s: failed to receive data, socket: %d/%d",
						dnet_state_dump_addr(st), st->read_s, st->write_s);
				goto out;
			}

			goto out;
		}

		if (err == 0) {
			dnet_log(n, DNET_LOG_ERROR, "%s: peer has disconnected, socket: %d/%d.\n",
				dnet_state_dump_addr(st), st->read_s, st->write_s);
			err = -ECONNRESET;
			goto out;
		}

		st->rcv_offset += err;
	}

	if (st->rcv_offset != st->rcv_end)
		goto again;

	if (st->rcv_flags & DNET_IO_CMD) {
		unsigned long long tid;
		struct dnet_cmd *c = &st->rcv_cmd;

		dnet_convert_cmd(c);

		tid = c->trans & ~DNET_TRANS_REPLY;

		dnet_log(n, DNET_LOG_DEBUG, "%s: received trans: %llu / 0x%llx, "
				"reply: %d, size: %llu, flags: 0x%llx, status: %d.\n",
				dnet_dump_id(&c->id), tid, (unsigned long long)c->trans,
				!!(c->trans & DNET_TRANS_REPLY),
				(unsigned long long)c->size, (unsigned long long)c->flags, c->status);

		r = malloc(c->size + sizeof(struct dnet_cmd) + sizeof(struct dnet_io_req));
		if (!r) {
			err = -ENOMEM;
			goto out;
		}
		memset(r, 0, sizeof(struct dnet_io_req));

		r->header = r + 1;
		r->hsize = sizeof(struct dnet_cmd);
		memcpy(r->header, &st->rcv_cmd, sizeof(struct dnet_cmd));

		st->rcv_data = r;
		st->rcv_offset = sizeof(struct dnet_io_req) + sizeof(struct dnet_cmd);
		st->rcv_end = st->rcv_offset + c->size;
		st->rcv_flags &= ~DNET_IO_CMD;

		if (c->size) {
			r->data = r->header + sizeof(struct dnet_cmd);
			r->dsize = c->size;

			/*
			 * We read the command header, now get the data.
			 */
			goto again;
		}
	}

	r = st->rcv_data;
	st->rcv_data = NULL;

	dnet_schedule_command(st);

	r->st = dnet_state_get(st);

	dnet_schedule_io(n, r);
	return 0;

out:
	if (err != -EAGAIN && err != -EINTR)
		dnet_schedule_command(st);

	return err;
}

int dnet_socket_local_addr(int s, struct dnet_addr *addr)
{
	int err;
	socklen_t len;

	len = addr->addr_len = sizeof(addr->addr);

	err = getsockname(s, (struct sockaddr *)addr->addr, &len);
	if (err < 0)
		return -errno;

	addr->addr_len = len;
	addr->family = ((struct sockaddr *)addr->addr)->sa_family;
	return 0;
}

int dnet_local_addr_index(struct dnet_node *n, struct dnet_addr *addr)
{
	int i;

	for (i = 0; i < n->addr_num; ++i) {
		if (dnet_addr_equal(addr, &n->addrs[i]))
			return i;
	}

	return -1;
}

int dnet_state_accept_process(struct dnet_net_state *orig, struct epoll_event *ev __unused)
{
	struct dnet_node *n = orig->n;
	int err, cs, idx;
	struct dnet_addr addr, saddr;
	struct dnet_net_state *st;
	socklen_t salen;
	char client_addr[128], server_addr[128];

	memset(&addr, 0, sizeof(addr));

	salen = addr.addr_len = sizeof(addr.addr);
	cs = accept(orig->read_s, (struct sockaddr *)&addr.addr, &salen);
	if (cs < 0) {
		err = -errno;

		/* EAGAIN (or EWOULDBLOCK) is totally good here */
		if (err == -EAGAIN || err == -EWOULDBLOCK) {
			goto err_out_exit;
		}

		/* Some error conditions considered "recoverable" and treated the same way as EAGAIN */
		dnet_log_err(n, "Failed to accept new client at %s", dnet_state_dump_addr(orig));
		if (err == -ECONNABORTED || err == -EMFILE || err == -ENOBUFS || err == -ENOMEM) {
			err = -EAGAIN;
			goto err_out_exit;
		}

		/* Others are too bad to live with */
		dnet_log_err(n, "FATAL: Can't recover from this error, exiting...");
		exit(err);
	}
	addr.family = orig->addr.family;
	addr.addr_len = salen;

	dnet_set_sockopt(cs);

	err = dnet_socket_local_addr(cs, &saddr);
	if (err) {
		dnet_log(n, DNET_LOG_ERROR, "%s: failed to resolve server addr for connected client: %s [%d]\n",
				dnet_server_convert_dnet_addr_raw(&addr, client_addr, sizeof(client_addr)), strerror(-err), -err);
		goto err_out_exit;
	}

	idx = dnet_local_addr_index(n, &saddr);

	st = dnet_state_create(n, 0, NULL, 0, &addr, cs, &err, 0, idx, dnet_state_net_process);
	if (!st) {
		dnet_log(n, DNET_LOG_ERROR, "%s: Failed to create state for accepted client: %s [%d]\n",
				dnet_server_convert_dnet_addr_raw(&addr, client_addr, sizeof(client_addr)), strerror(-err), -err);
		err = -EAGAIN;

		/* We do not close socket, since it is closed in dnet_state_create() */
		goto err_out_exit;
	}

	dnet_log(n, DNET_LOG_INFO, "Accepted client %s, socket: %d, server address: %s, idx: %d.\n",
			dnet_server_convert_dnet_addr_raw(&addr, client_addr, sizeof(client_addr)), cs,
			dnet_server_convert_dnet_addr_raw(&saddr, server_addr, sizeof(server_addr)), idx);

	return 0;

err_out_exit:
	return err;
}

void dnet_unschedule_send(struct dnet_net_state *st)
{
	epoll_ctl(st->epoll_fd, EPOLL_CTL_DEL, st->write_s, NULL);
}

void dnet_unschedule_recv(struct dnet_net_state *st)
{
	epoll_ctl(st->epoll_fd, EPOLL_CTL_DEL, st->read_s, NULL);
}

static int dnet_process_send_single(struct dnet_net_state *st)
{
	struct dnet_io_req *r = NULL;
	int err;

	while (1) {
		r = NULL;

		pthread_mutex_lock(&st->send_lock);
		if (!list_empty(&st->send_list)) {
			r = list_first_entry(&st->send_list, struct dnet_io_req, req_entry);
		} else {
			dnet_unschedule_send(st);
		}
		pthread_mutex_unlock(&st->send_lock);

		if (!r) {
			err = -EAGAIN;
			goto err_out_exit;
		}

		err = dnet_send_request(st, r);
		if (st->send_offset == (r->dsize + r->hsize + r->fsize)) {
			pthread_mutex_lock(&st->send_lock);
			list_del(&r->req_entry);
			pthread_mutex_unlock(&st->send_lock);

			if (atomic_read(&st->send_queue_size) > 0)
				if (atomic_dec(&st->send_queue_size) == DNET_SEND_WATERMARK_LOW) {
					dnet_log(st->n, DNET_LOG_DEBUG,
							"State low_watermark reached: %s: %d, waking up\n",
							dnet_server_convert_dnet_addr(&st->addr),
							atomic_read(&st->send_queue_size));
					pthread_cond_broadcast(&st->send_wait);
				}

			dnet_io_req_free(r);
			st->send_offset = 0;
		}

		if (err)
			goto err_out_exit;
	}

err_out_exit:
	if ((err < 0) && (atomic_read(&st->send_queue_size) > 0))
		pthread_cond_broadcast(&st->send_wait);

	return err;
}

static int dnet_schedule_network_io(struct dnet_net_state *st, int send)
{
	struct epoll_event ev;
	int err, fd;

	if (st->__need_exit) {
		dnet_log_err(st->n, "%s: scheduling %s event on reset state: need-exit: %d\n",
				dnet_state_dump_addr(st), send ? "SEND" : "RECV", st->__need_exit);
		return st->__need_exit;
	}

	if (send) {
		ev.events = EPOLLOUT;
		fd = st->write_s;
	} else {
		ev.events = EPOLLIN;
		fd = st->read_s;
	}
	ev.data.ptr = st;

	err = epoll_ctl(st->epoll_fd, EPOLL_CTL_ADD, fd, &ev);
	if (err < 0) {
		err = -errno;

		if (err == -EEXIST) {
			err = 0;
		} else {
			dnet_log_err(st->n, "%s: failed to add %s event", dnet_state_dump_addr(st), send ? "SEND" : "RECV");
		}
	}

	return err;
}

int dnet_schedule_send(struct dnet_net_state *st)
{
	return dnet_schedule_network_io(st, 1);
}

int dnet_schedule_recv(struct dnet_net_state *st)
{
	return dnet_schedule_network_io(st, 0);
}

int dnet_state_net_process(struct dnet_net_state *st, struct epoll_event *ev)
{
	int err = -ECONNRESET;

	if (ev->events & EPOLLIN) {
		err = dnet_process_recv_single(st);
		if (err && (err != -EAGAIN))
			goto err_out_exit;
	}
	if (ev->events & EPOLLOUT) {
		err = dnet_process_send_single(st);
		if (err && (err != -EAGAIN))
			goto err_out_exit;
	}

	if (ev->events & (EPOLLHUP | EPOLLERR)) {
		dnet_log(st->n, DNET_LOG_ERROR, "%s: received error event mask 0x%x\n", dnet_state_dump_addr(st), ev->events);
		err = -ECONNRESET;
	}
err_out_exit:
	return err;
}

static void *dnet_io_process_network(void *data_)
{
	struct dnet_net_io *nio = data_;
	struct dnet_node *n = nio->n;
	struct dnet_net_state *st;
	struct epoll_event ev;
	int err = 0;

	dnet_set_name("net_pool");

	while (!n->need_exit) {
		err = epoll_wait(nio->epoll_fd, &ev, 1, 1000);
		if (err == 0)
			continue;

		if (err < 0) {
			err = -errno;

			if (err == -EAGAIN || err == -EINTR)
				continue;

			dnet_log_err(n, "Failed to wait for IO fds");
			n->need_exit = err;
			break;
		}

		st = ev.data.ptr;
		st->epoll_fd = nio->epoll_fd;

		while (1) {
			err = st->process(st, &ev);
			if (err == 0)
				continue;

			if (err == -EAGAIN && st->stall < DNET_DEFAULT_STALL_TRANSACTIONS)
				break;

			if (err < 0 || st->stall >= DNET_DEFAULT_STALL_TRANSACTIONS) {
				if (!err)
					err = -ETIMEDOUT;

				dnet_state_reset(st, err);

				pthread_mutex_lock(&st->send_lock);
				dnet_unschedule_send(st);
				dnet_unschedule_recv(st);
				pthread_mutex_unlock(&st->send_lock);

				dnet_add_reconnect_state(st->n, &st->addr, st->__join_state);

				// state still contains a fair number of transactions in its queue
				// they will not be cleaned up here - dnet_state_put() will only drop refctn by 1,
				// while every transaction holds a reference
				//
				// IO thread could remove transaction, it is the only place allowed to do it.
				// transactions may live in the tree and be accessed without locks in IO thread,
				// IO thread is kind of 'owner' of the transaction processing
				dnet_state_put(st);
				break;
			}
		}
	}

	return &n->need_exit;
}

static void dnet_io_cleanup_states(struct dnet_node *n)
{
	struct dnet_net_state *st, *tmp;

	list_for_each_entry_safe(st, tmp, &n->storage_state_list, storage_state_entry) {
		dnet_unschedule_send(st);
		dnet_unschedule_recv(st);

		dnet_state_reset(st, -EUCLEAN);

		dnet_state_clean(st);
		dnet_state_put(st);
	}
}

struct dnet_io_process_data {
	struct dnet_node *n;
	int thread_number;
};

static struct dnet_io_req *take_request(struct dnet_work_pool *pool, int thread_index)
{
	struct dnet_io_req *it = NULL;
	struct dnet_cmd *cmd;
	uint64_t tid;
	int i;
	int ok;

	list_for_each_entry(it, &pool->list, req_entry) {
		cmd = it->header;
		tid = cmd->trans & ~DNET_TRANS_REPLY;
		ok = 1;

		/* This is not a transaction reply, process it right now */
		if (!(cmd->trans & DNET_TRANS_REPLY))
			return it;

		for (i = 0; i < pool->num; ++i) {
			 /* Someone claimed transaction @tid */
			if (pool->trans[i] == tid) {
				 /* Its our transaction, let's handle it */
				if (i == thread_index) {
					/* its the last transaction in given set, clear 'claim' flag for current thread */
					if (!(cmd->flags & DNET_FLAGS_MORE))
						pool->trans[thread_index] = ~0ULL;

					return it;
				}

				/* we should not touch it */
				ok = 0;
				break;
			}
		}

		/*
		 * 'ok' here means no one claimed given transaction, we can process it,
		 * but only if 'we' do not wait for another transaction already.
		 */
		if (ok) {
			if (pool->trans[thread_index] == ~0ULL) {
				/* only claim this transaction if there will be others */
				if (cmd->flags & DNET_FLAGS_MORE)
					pool->trans[thread_index] = tid;
				return it;
			}
		}
	}

	return NULL;
}

static void *dnet_io_process(void *data_)
{
	struct dnet_work_io *wio = data_;
	struct dnet_work_pool *pool = wio->pool;
	struct dnet_node *n = pool->n;
	struct dnet_net_state *st;
	struct timespec ts;
	struct timeval tv;
	struct dnet_io_req *r;
	int err;
	struct dnet_cmd *cmd;

	dnet_set_name("io_pool");

	while (!n->need_exit) {
		r = NULL;
		err = 0;

		gettimeofday(&tv, NULL);
		ts.tv_sec = tv.tv_sec + 1;
		ts.tv_nsec = tv.tv_usec * 1000;

		pthread_mutex_lock(&pool->lock);

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
		pool->trans[wio->thread_index] = -1;

		if (!(r = take_request(pool, wio->thread_index))) {
			err = pthread_cond_timedwait(&pool->wait, &pool->lock, &ts);
			if ((r = take_request(pool, wio->thread_index)))
				err = 0;
		}

		if (r) {
			list_del_init(&r->req_entry);
			list_stat_size_decrease(&pool->list_stats, 1);
		}
		pthread_mutex_unlock(&pool->lock);

		if (!r || err)
			continue;

		st = r->st;
		cmd = r->header;
		trace_id = cmd->id.trace_id;

		dnet_log(n, DNET_LOG_DEBUG, "%s: %s: got IO event: %p: hsize: %zu, dsize: %zu, mode: %s\n",
			dnet_state_dump_addr(st), dnet_dump_id(r->header), r, r->hsize, r->dsize, dnet_work_io_mode_str(pool->mode));

		err = dnet_process_recv(st, r);
		trace_id = 0;

		dnet_io_req_free(r);
		dnet_state_put(st);
	}

	return NULL;
}

int dnet_io_init(struct dnet_node *n, struct dnet_config *cfg)
{
	int err, i;
	int io_size = sizeof(struct dnet_io) + sizeof(struct dnet_net_io) * cfg->net_thread_num;

	n->io = malloc(io_size);
	if (!n->io) {
		err = -ENOMEM;
		goto err_out_exit;
	}

	memset(n->io, 0, io_size);

	n->io->net_thread_num = cfg->net_thread_num;
	n->io->net_thread_pos = 0;
	n->io->net = (struct dnet_net_io *)(n->io + 1);

	n->io->recv_pool = dnet_work_pool_alloc(n, cfg->io_thread_num, DNET_WORK_IO_MODE_BLOCKING, dnet_io_process);
	if (!n->io->recv_pool) {
		err = -ENOMEM;
		goto err_out_free;
	}

	n->io->recv_pool_nb = dnet_work_pool_alloc(n, cfg->nonblocking_io_thread_num, DNET_WORK_IO_MODE_NONBLOCKING, dnet_io_process);
	if (!n->io->recv_pool_nb) {
		err = -ENOMEM;
		goto err_out_free_recv_pool;
	}

	for (i=0; i<n->io->net_thread_num; ++i) {
		struct dnet_net_io *nio = &n->io->net[i];

		nio->n = n;

		nio->epoll_fd = epoll_create(10000);
		if (nio->epoll_fd < 0) {
			err = -errno;
			dnet_log_err(n, "Failed to create epoll fd");
			goto err_out_net_destroy;
		}

		fcntl(nio->epoll_fd, F_SETFD, FD_CLOEXEC);
		fcntl(nio->epoll_fd, F_SETFL, O_NONBLOCK);

		err = pthread_create(&nio->tid, NULL, dnet_io_process_network, nio);
		if (err) {
			close(nio->epoll_fd);
			err = -err;
			dnet_log(n, DNET_LOG_ERROR, "Failed to create network processing thread: %d\n", err);
			goto err_out_net_destroy;
		}
	}

	return 0;

err_out_net_destroy:
	while (--i >= 0) {
		pthread_join(n->io->net[i].tid, NULL);
		close(n->io->net[i].epoll_fd);
	}

	dnet_work_pool_cleanup(n->io->recv_pool_nb);
err_out_free_recv_pool:
	dnet_work_pool_cleanup(n->io->recv_pool);
err_out_free:
	free(n->io);
err_out_exit:
	n->io = NULL;
	return err;
}

void dnet_io_exit(struct dnet_node *n)
{
	struct dnet_io *io = n->io;
	int i;

	n->need_exit = 1;

	for (i=0; i<io->net_thread_num; ++i) {
		pthread_join(io->net[i].tid, NULL);
		close(io->net[i].epoll_fd);
	}

	dnet_work_pool_cleanup(io->recv_pool_nb);
	dnet_work_pool_cleanup(io->recv_pool);

	dnet_io_cleanup_states(n);

	free(io);
}
