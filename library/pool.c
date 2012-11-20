/*
 * 2011+ Copyright (c) Evgeniy Polyakov <zbr@ioremap.net>
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
	free(pool);
}

static int dnet_work_pool_grow(struct dnet_node *n, struct dnet_work_pool *pool, int num, void *(* process)(void *))
{
	int i, err;
	struct dnet_work_io *wio, *tmp;

	pthread_mutex_lock(&pool->lock);

	for (i = 0; i < num; ++i) {
		wio = malloc(sizeof(struct dnet_work_io));
		if (!wio) {
			err = -ENOMEM;
			goto err_out_io_threads;
		}

		wio->thread_index = i;
		wio->pool = pool;
		list_add_tail(&wio->wio_entry, &pool->wio_list);

		err = pthread_create(&wio->tid, NULL, process, wio);
		if (err) {
			err = -err;
			dnet_log(n, DNET_LOG_ERROR, "Failed to create IO thread: %d\n", err);
			goto err_out_io_threads;
		}
	}

	dnet_log(n, DNET_LOG_INFO, "Grew %s pool by: %d -> %d IO threads\n",
			dnet_work_io_mode_str(pool->mode), pool->num, pool->num + num);

	atomic_add(&pool->avail, num);
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
	atomic_set(&pool->avail, 0);
	pool->mode = mode;
	pool->n = n;
	INIT_LIST_HEAD(&pool->list);
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

static void *dnet_io_process(void *data_);
static void dnet_schedule_io(struct dnet_node *n, struct dnet_io_req *r)
{
	struct dnet_io *io = n->io;
	struct dnet_cmd *cmd = r->header;
	int nonblocking = !!(cmd->flags & DNET_FLAGS_NOLOCK);
	struct dnet_work_pool *pool = io->recv_pool;

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

		dnet_log(r->st->n, DNET_LOG_DEBUG, "%s: %s: RECV: %s: nonblocking: %d, cmd-size: %llu, cflags: %llx, trans: %lld, reply: %d\n",
			dnet_state_dump_addr(r->st), dnet_dump_id(r->header), dnet_cmd_string(cmd->cmd), nonblocking,
			(unsigned long long)cmd->size, (unsigned long long)cmd->flags, tid, reply);
	}


	if (nonblocking)
		pool = io->recv_pool_nb;

#define cmd_is_exec_match(__cmd) (((__cmd)->cmd == DNET_CMD_EXEC) && ((__cmd)->size >= sizeof(struct sph)) && !((__cmd)->trans & DNET_TRANS_REPLY))

	if (!list_empty(&pool->list) && cmd_is_exec_match(cmd)) {
		int pool_has_blocked_sph = 0;
		struct dnet_io_req *tmp;
		struct sph *sph;
		int edge_num = pool->num / 4 + 1;

		pthread_mutex_lock(&pool->lock);
		list_for_each_entry(tmp, &pool->list, req_entry) {
			struct dnet_cmd *tmp_cmd = tmp->header;
			unsigned long long tid = tmp_cmd->trans & ~DNET_TRANS_REPLY;
			int reply = !!(tmp_cmd->trans & DNET_TRANS_REPLY);
			unsigned long long sph_flags = 0;
			int sph_match = 0;

			if (cmd_is_exec_match(tmp_cmd)) {
				sph = (struct sph *)tmp->data;
				sph_flags = sph->flags;
				sph_match = 1;
			}


			dnet_log(r->st->n, DNET_LOG_DEBUG, "%s: %s: pool-grow: %s: cmd-size: %llu, cflags: %llx, "
					"trans: %lld, reply: %d, sph-flags: %llx (match: %d), avail: %d\n",
				dnet_state_dump_addr(tmp->st), dnet_dump_id(tmp->header), dnet_cmd_string(tmp_cmd->cmd),
				(unsigned long long)tmp_cmd->size, (unsigned long long)tmp_cmd->flags,
				tid, reply, sph_flags, sph_match, atomic_read(&pool->avail));

			if (cmd_is_exec_match(tmp_cmd)) {
				sph = (struct sph *)tmp->data;
				if (sph->flags & DNET_SPH_FLAGS_SRC_BLOCK) {
					pool_has_blocked_sph = 1;
					break;
				}
			}
		}
		pthread_mutex_unlock(&pool->lock);

		sph = (struct sph *)r->data;
		if ((sph->flags & DNET_SPH_FLAGS_SRC_BLOCK) && pool_has_blocked_sph && (atomic_read(&pool->avail) < edge_num)) {
			dnet_work_pool_grow(n, pool, edge_num, dnet_io_process);
		}
	}

	pthread_mutex_lock(&pool->lock);
	list_add_tail(&r->req_entry, &pool->list);
	pthread_cond_broadcast(&pool->wait);
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
				dnet_log_err(n, "failed to receive data, socket: %d", st->read_s);
				goto out;
			}

			goto out;
		}

		if (err == 0) {
			dnet_log(n, DNET_LOG_ERROR, "Peer %s has disconnected.\n",
				dnet_server_convert_dnet_addr(&st->addr));
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

		dnet_log(n, DNET_LOG_DEBUG, "%s: received trans: %llu / %llx, "
				"reply: %d, size: %llu, flags: %llx, status: %d.\n",
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

int dnet_state_accept_process(struct dnet_net_state *orig, struct epoll_event *ev __unused)
{
	struct dnet_node *n = orig->n;
	int err, cs;
	struct dnet_addr addr;
	struct dnet_net_state *st;

	memset(&addr, 0, sizeof(addr));

	addr.addr_len = sizeof(addr.addr);
	cs = accept(orig->read_s, (struct sockaddr *)&addr.addr, &addr.addr_len);
	if (cs <= 0) {
		err = -errno;
		if (err != -EAGAIN)
			dnet_log_err(n, "failed to accept new client at %s", dnet_state_dump_addr(orig));
		goto err_out_exit;
	}

	dnet_set_sockopt(cs);

	st = dnet_state_create(n, 0, NULL, 0, &addr, cs, &err, 0, dnet_state_net_process);
	if (!st) {
		dnet_log(n, DNET_LOG_ERROR, "%s: Failed to create state for accepted client: %s [%d]\n",
				dnet_server_convert_dnet_addr(&addr), strerror(-err), -err);
		err = -EAGAIN;
		goto err_out_exit;
	}

	dnet_log(n, DNET_LOG_INFO, "Accepted client %s, socket: %d.\n",
			dnet_server_convert_dnet_addr(&addr), cs);

	return 0;
	/* socket is closed in dnet_state_create() */
err_out_exit:
	return err;
}

void dnet_unschedule_send(struct dnet_net_state *st)
{
	struct epoll_event ev;

	ev.events = EPOLLOUT;
	ev.data.ptr = st;

	epoll_ctl(st->epoll_fd, EPOLL_CTL_DEL, st->write_s, &ev);
}

void dnet_unschedule_recv(struct dnet_net_state *st)
{
	struct epoll_event ev;

	ev.events = EPOLLIN;
	ev.data.ptr = st;

	epoll_ctl(st->epoll_fd, EPOLL_CTL_DEL, st->read_s, &ev);
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
		if (err)
			goto err_out_exit;
	}

err_out_exit:
	return err;
}

static int dnet_schedule_network_io(struct dnet_net_state *st, int send)
{
	struct epoll_event ev;
	int err, fd;

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
		dnet_log(st->n, DNET_LOG_ERROR, "%s: received error event mask %x\n", dnet_state_dump_addr(st), ev->events);
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
	int err = 0, check;
	struct dnet_trans *t, *tmp;
	struct timeval tv;
	struct list_head head;

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
		check = st->stall;

		while (1) {
			err = st->process(st, &ev);
			if (err == 0)
				continue;

			if (err == -EAGAIN && st->stall < DNET_DEFAULT_STALL_TRANSACTIONS)
				break;

			if (err < 0 || st->stall >= DNET_DEFAULT_STALL_TRANSACTIONS) {
				dnet_state_reset(st);
				check = 0;
				break;
			}
		}

		if (!check)
			continue;

		gettimeofday(&tv, NULL);

		INIT_LIST_HEAD(&head);

		pthread_mutex_lock(&st->trans_lock);
		list_for_each_entry_safe(t, tmp, &st->trans_list, trans_list_entry) {
			if (t->time.tv_sec >= tv.tv_sec)
				break;

			dnet_trans_remove_nolock(&st->trans_root, t);
			list_move(&t->trans_list_entry, &head);
		}
		pthread_mutex_unlock(&st->trans_lock);

		list_for_each_entry_safe(t, tmp, &head, trans_list_entry) {
			list_del_init(&t->trans_list_entry);

			t->cmd.flags = 0;
			t->cmd.size = 0;
			t->cmd.status = -ETIMEDOUT;

			dnet_log(st->n, DNET_LOG_ERROR, "%s: destructing trans: %llu on TIMEOUT\n",
					dnet_state_dump_addr(st), (unsigned long long)t->trans);

			if (t->complete)
				t->complete(st, &t->cmd, t->priv);

			dnet_trans_put(t);
		}
	}

	return &n->need_exit;
}

static void dnet_io_cleanup_states(struct dnet_node *n)
{
	struct dnet_net_state *st, *tmp;

	list_for_each_entry_safe(st, tmp, &n->storage_state_list, storage_state_entry) {
		dnet_state_reset(st);
	}
}

struct dnet_io_process_data {
	struct dnet_node *n;
	int thread_number;
};

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

	dnet_set_name("io_pool");

	while (!n->need_exit) {
		r = NULL;
		err = 0;

		gettimeofday(&tv, NULL);
		ts.tv_sec = tv.tv_sec + 1;
		ts.tv_nsec = tv.tv_usec * 1000;

		pthread_mutex_lock(&pool->lock);

		if (!list_empty(&pool->list)) {
			r = list_first_entry(&pool->list, struct dnet_io_req, req_entry);
		} else {
			err = pthread_cond_timedwait(&pool->wait, &pool->lock, &ts);
			if (!list_empty(&pool->list)) {
				r = list_first_entry(&pool->list, struct dnet_io_req, req_entry);
				err = 0;
			}
		}

		if (r) {
			list_del_init(&r->req_entry);
			atomic_dec(&pool->avail);
		}
		pthread_mutex_unlock(&pool->lock);

		if (!r || err)
			continue;

		st = r->st;

		dnet_log(n, DNET_LOG_DEBUG, "%s: %s: got IO event: %p: hsize: %zu, dsize: %zu, mode: %s\n",
			dnet_state_dump_addr(st), dnet_dump_id(r->header), r, r->hsize, r->dsize, dnet_work_io_mode_str(pool->mode));

		err = dnet_process_recv(st, r);

		dnet_io_req_free(r);
		dnet_state_put(st);

		atomic_inc(&pool->avail);
	}

	return NULL;
}

int dnet_io_init(struct dnet_node *n, struct dnet_config *cfg)
{
	int err, i;
	struct dnet_io *io;
	int io_size = sizeof(struct dnet_io) + sizeof(struct dnet_net_io) * cfg->net_thread_num;

	io = malloc(io_size);
	if (!io) {
		err = -ENOMEM;
		goto err_out_exit;
	}

	memset(io, 0, io_size);

	io->net_thread_num = cfg->net_thread_num;
	io->net_thread_pos = 0;
	io->net = (struct dnet_net_io *)(io + 1);

	io->recv_pool = dnet_work_pool_alloc(n, cfg->io_thread_num, DNET_WORK_IO_MODE_BLOCKING, dnet_io_process);
	if (!io->recv_pool) {
		err = -ENOMEM;
		goto err_out_free;
	}

	io->recv_pool_nb = dnet_work_pool_alloc(n, cfg->nonblocking_io_thread_num, DNET_WORK_IO_MODE_NONBLOCKING, dnet_io_process);
	if (!io->recv_pool_nb) {
		err = -ENOMEM;
		goto err_out_free_recv_pool;
	}

	for (i=0; i<io->net_thread_num; ++i) {
		struct dnet_net_io *nio = &io->net[i];

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

	n->io = io;
	return 0;

err_out_net_destroy:
	while (--i >= 0) {
		pthread_join(io->net[i].tid, NULL);
		close(io->net[i].epoll_fd);
	}

	dnet_work_pool_cleanup(io->recv_pool_nb);
err_out_free_recv_pool:
	dnet_work_pool_cleanup(io->recv_pool);
err_out_free:
	free(io);
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
