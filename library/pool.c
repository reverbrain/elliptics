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
#include <netinet/in.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>

#include "elliptics.h"
#include "elliptics/interface.h"
#include "../monitor/monitor.h"
#include "../monitor/measure_points.h"

static char *dnet_work_io_mode_string[] = {
	[DNET_WORK_IO_MODE_BLOCKING] = "BLOCKING",
	[DNET_WORK_IO_MODE_NONBLOCKING] = "NONBLOCKING",
	[DNET_WORK_IO_MODE_CONTROL] = "CONTROL",
};

static char *dnet_work_io_mode_str(int mode)
{
	if (mode < 0 || mode >= (int)ARRAY_SIZE(dnet_work_io_mode_string))
		return NULL;

	return dnet_work_io_mode_string[mode];
}

void dnet_work_pool_cleanup(struct dnet_work_pool_place *place)
{
	int i;
	struct dnet_io_req *r, *tmp;
	struct dnet_work_io *wio;

	pthread_mutex_lock(&place->lock);

	for (i = 0; i < place->pool->num; ++i) {
		wio = &place->pool->wio_list[i];
		pthread_join(wio->tid, NULL);
	}


	list_for_each_entry_safe(r, tmp, &place->pool->list, req_entry) {
		list_del(&r->req_entry);
		dnet_io_req_free(r);
	}

	for (i = 0; i < place->pool->num; ++i) {
		wio = &place->pool->wio_list[i];

		list_for_each_entry_safe(r, tmp, &wio->list, req_entry) {
			list_del(&r->req_entry);
			dnet_io_req_free(r);
		}
	}

	pthread_mutex_destroy(&place->pool->lock);
	pthread_cond_destroy(&place->pool->wait);

	free(place->pool->wio_list);
	free(place->pool);

	place->pool = NULL;

	pthread_mutex_unlock(&place->lock);
}

static int dnet_work_pool_grow(struct dnet_node *n, struct dnet_work_pool *pool, int num, void *(* process)(void *))
{
	int i = 0, j, err;
	struct dnet_work_io *wio;

	pthread_mutex_lock(&pool->lock);

	pool->wio_list = malloc(num * sizeof(struct dnet_work_io));
	if (!pool->wio_list) {
		err = -ENOMEM;
		goto err_out_io_threads;
	}

	for (i = 0; i < num; ++i) {
		wio = &pool->wio_list[i];

		wio->thread_index = i;
		wio->pool = pool;
		wio->trans = ~0ULL;
		INIT_LIST_HEAD(&wio->list);

		err = pthread_create(&wio->tid, NULL, process, wio);
		if (err) {
			err = -err;
			dnet_log(n, DNET_LOG_ERROR, "Failed to create IO thread: %d", err);
			goto err_out_io_threads;
		}
	}

	dnet_log(n, DNET_LOG_INFO, "Grew %s pool by: %d -> %d IO threads",
			dnet_work_io_mode_str(pool->mode), pool->num, pool->num + num);

	pool->num = num;
	pthread_mutex_unlock(&pool->lock);

	return 0;

err_out_io_threads:
	for (j = 0; j < i; ++j) {
		wio = &pool->wio_list[j];
		pthread_join(wio->tid, NULL);
	}

	free(pool->wio_list);

	pthread_mutex_unlock(&pool->lock);

	return err;
}

static int dnet_work_pool_place_init(struct dnet_work_pool_place *pool)
{
	int err;
	memset(pool, 0, sizeof(struct dnet_work_pool_place));

	err = pthread_mutex_init(&pool->lock, NULL);
	if (err) {
		err = -err;
		goto err_out_exit;
	}

	err = pthread_cond_init(&pool->wait, NULL);
	if (err) {
		err = -err;
		goto err_out_mutex_destroy;
	}

err_out_mutex_destroy:
	pthread_mutex_destroy(&pool->lock);
err_out_exit:
	return err;
}

static void dnet_work_pool_place_cleanup(struct dnet_work_pool_place *pool)
{
	pthread_mutex_destroy(&pool->lock);
	pthread_cond_destroy(&pool->wait);
}

int dnet_work_pool_alloc(struct dnet_work_pool_place *place, struct dnet_node *n,
	struct dnet_backend_io *io, int num, int mode, void *(* process)(void *))
{
	int err;

	pthread_mutex_lock(&place->lock);

	place->pool = malloc(sizeof(struct dnet_work_pool));
	if (!place->pool) {
		err = -ENOMEM;
		goto err_out_exit;
	}

	memset(place->pool, 0, sizeof(struct dnet_work_pool));

	err = pthread_mutex_init(&place->pool->lock, NULL);
	if (err) {
		err = -err;
		goto err_out_free;
	}

	err = pthread_cond_init(&place->pool->wait, NULL);
	if (err) {
		err = -err;
		goto err_out_mutex_destroy;
	}

	place->pool->num = 0;
	place->pool->mode = mode;
	place->pool->n = n;
	place->pool->io = io;
	INIT_LIST_HEAD(&place->pool->list);
	list_stat_init(&place->pool->list_stats);

	err = dnet_work_pool_grow(n, place->pool, num, process);
	if (err)
		goto err_out_cond_destroy;

	pthread_mutex_unlock(&place->lock);

	return err;

err_out_cond_destroy:
	pthread_cond_destroy(&place->pool->wait);
err_out_mutex_destroy:
	pthread_mutex_destroy(&place->pool->lock);
err_out_free:
	free(place->pool);
err_out_exit:
	pthread_mutex_unlock(&place->lock);
	return err;
}

// Keep this enums in sync with enums from dnet_process_cmd_without_backend_raw
static int dnet_cmd_needs_backend(int command)
{
	switch (command) {
	case DNET_CMD_AUTH:
	case DNET_CMD_STATUS:
	case DNET_CMD_REVERSE_LOOKUP:
	case DNET_CMD_JOIN:
	case DNET_CMD_ROUTE_LIST:
	case DNET_CMD_EXEC:
	case DNET_CMD_MONITOR_STAT:
	case DNET_CMD_BACKEND_CONTROL:
	case DNET_CMD_BACKEND_STATUS:
		return 0;
	}
	return 1;
}

static inline void make_thread_stat_id(char *buffer, int size, struct dnet_work_pool *pool)
{
	/* Could have used dnet_work_io_mode_str() to get string name
	 for the pool's mode, but for statistic lowercase names works better and
	 dnet_work_io_mode_str() provides mode names in uppercase.
	*/
	const char *mode_marker = ((pool->mode == DNET_WORK_IO_MODE_BLOCKING) ? "blocking" : "nonblocking");
	if (pool->io) {
		snprintf(buffer, size - 1, "%zu.%s", pool->io->backend_id, mode_marker);
	} else {
		snprintf(buffer, size - 1, "sys.%s", mode_marker);
	}
}

void dnet_schedule_io(struct dnet_node *n, struct dnet_io_req *r)
{
	struct dnet_work_pool_place *place = NULL;
	struct dnet_work_pool_place *backend_place = NULL;
	struct dnet_work_pool *pool = NULL;
	struct dnet_io_pool *io_pool = &n->io->pool;
	struct dnet_cmd *cmd = r->header;
	int nonblocking = !!(cmd->flags & DNET_FLAGS_NOLOCK);
	ssize_t backend_id = -1;
	char thread_stat_id[255];

	if (cmd->size > 0) {
		dnet_log(r->st->n, DNET_LOG_DEBUG, "%s: %s: RECV cmd: %s: cmd-size: %llu, nonblocking: %d",
			dnet_state_dump_addr(r->st), dnet_dump_id(r->header), dnet_cmd_string(cmd->cmd),
			(unsigned long long)cmd->size, nonblocking);
	} else if ((cmd->size == 0) && !(cmd->flags & DNET_FLAGS_MORE) && (cmd->flags & DNET_FLAGS_REPLY)) {
		dnet_log(r->st->n, DNET_LOG_DEBUG, "%s: %s: RECV ACK: %s: nonblocking: %d",
			dnet_state_dump_addr(r->st), dnet_dump_id(r->header), dnet_cmd_string(cmd->cmd), nonblocking);
	} else {
		unsigned long long tid = cmd->trans;
		int reply = !!(cmd->flags & DNET_FLAGS_REPLY);

		dnet_log(r->st->n, DNET_LOG_DEBUG, "%s: %s: RECV: %s: nonblocking: %d, cmd-size: %llu, cflags: %s, trans: %lld, reply: %d",
			dnet_state_dump_addr(r->st), dnet_dump_id(r->header), dnet_cmd_string(cmd->cmd), nonblocking,
			(unsigned long long)cmd->size, dnet_flags_dump_cflags(cmd->flags), tid, reply);
	}

	if (cmd->flags & DNET_FLAGS_DIRECT_BACKEND)
		backend_id = cmd->backend_id;
	else if (dnet_cmd_needs_backend(cmd->cmd))
		backend_id = dnet_state_search_backend(n, &cmd->id);

	if (backend_id >= 0 && backend_id < (ssize_t)n->io->backends_count) {
		io_pool = &n->io->backends[backend_id].pool;
		if (nonblocking) {
			place = &io_pool->recv_pool_nb;
		} else {
			place = &io_pool->recv_pool;
		}

		if (place) {
			pthread_mutex_lock(&place->lock);
			if (!place->pool) {
				pthread_mutex_unlock(&place->lock);
				io_pool = &n->io->pool;
				place = NULL;
			}
		}
	}

	backend_place = place;

	if (place == NULL) {
		if (nonblocking) {
			place = &io_pool->recv_pool_nb;
		} else {
			place = &io_pool->recv_pool;
		}

		pthread_mutex_lock(&place->lock);
	}

	pool = place->pool;

	make_thread_stat_id(thread_stat_id, sizeof(thread_stat_id), pool);

	// If we are processing the command we should update cmd->backend_id to actual one
	if (!(cmd->flags & DNET_FLAGS_REPLY)) {
		if (pool->io)
			cmd->backend_id = pool->io->backend_id;
		else
			cmd->backend_id = -1;
	}

	dnet_log(n, DNET_LOG_DEBUG, "%s: %s: backend_id: %zd, place: %p, backend_place: %p, backend_place->pool->backend_id: %zd, cmd->backend_id: %d",
		dnet_state_dump_addr(r->st), dnet_dump_id(r->header), backend_id, place, backend_place,
		backend_place && backend_place->pool->io ? (ssize_t)backend_place->pool->io->backend_id : (ssize_t)-1,
		cmd->backend_id);

	pthread_mutex_lock(&pool->lock);

	list_add_tail(&r->req_entry, &pool->list);
	list_stat_size_increase(&pool->list_stats, 1);

	pthread_mutex_unlock(&pool->lock);
	pthread_cond_signal(&pool->wait);

	pthread_mutex_unlock(&place->lock);

	FORMATTED(HANDY_TIMER_START, ("pool.%s.queue.wait_time", thread_stat_id), (uint64_t)&r->req_entry);
	FORMATTED(HANDY_COUNTER_INCREMENT, ("pool.%s.queue.size", thread_stat_id), 1);
	HANDY_COUNTER_INCREMENT("io.input.queue.size", 1);
}


void dnet_schedule_command(struct dnet_net_state *st)
{
	st->rcv_flags = DNET_IO_CMD;

	if (st->rcv_data) {
#if 0
		struct dnet_cmd *c = &st->rcv_cmd;
		unsigned long long tid = c->trans;
		dnet_log(st->n, DNET_LOG_DEBUG, "freed: size: %llu, trans: %llu, reply: %d, ptr: %p.",
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

	dnet_node_set_trace_id(n->log, st->rcv_cmd.trace_id, st->rcv_cmd.flags & DNET_FLAGS_TRACE_BIT, (ssize_t)-1);
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
			dnet_log(n, DNET_LOG_ERROR, "%s: peer has disconnected, socket: %d/%d.",
				dnet_state_dump_addr(st), st->read_s, st->write_s);
			err = -ECONNRESET;
			goto out;
		}

		dnet_node_unset_trace_id();
		dnet_node_set_trace_id(n->log, st->rcv_cmd.trace_id, st->rcv_cmd.flags & DNET_FLAGS_TRACE_BIT, (ssize_t)-1);

		st->rcv_offset += err;
	}

	if (st->rcv_offset != st->rcv_end)
		goto again;

	if (st->rcv_flags & DNET_IO_CMD) {
		unsigned long long tid;
		struct dnet_cmd *c = &st->rcv_cmd;

		dnet_convert_cmd(c);

		tid = c->trans;

		dnet_log(n, DNET_LOG_DEBUG, "%s: received trans: %llu / 0x%llx, "
				"reply: %d, size: %llu, flags: %s, status: %d.",
				dnet_dump_id(&c->id), tid, (unsigned long long)c->trans,
				!!(c->flags & DNET_FLAGS_REPLY),
				(unsigned long long)c->size, dnet_flags_dump_cflags(c->flags), c->status);

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
	dnet_node_unset_trace_id();
	return 0;

out:
	if (err != -EAGAIN && err != -EINTR)
		dnet_schedule_command(st);

	dnet_node_unset_trace_id();
	return err;
}

/*
 * Tries to unmap IPv4 from IPv6.
 * If it is succeeded addr will contain valid unmapped IPv4 address
 * otherwise it will contain original address.
 */
static void try_to_unmap_ipv4(struct dnet_addr *addr) {
	struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *) addr->addr;

	/*
	 * if address isn't IPv6 or it isn't mapped IPv4 then there is nothing to be unmapped
	 */
	if (addr->family != AF_INET6 || !IN6_IS_ADDR_V4MAPPED(&sin6->sin6_addr))
		return;

	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));

	sin.sin_family = AF_INET;
	sin.sin_port = sin6->sin6_port;
	// copies last 4 bytes from mapped IPv6 that represents original IPv4 address
	memcpy(&sin.sin_addr.s_addr, &sin6->sin6_addr.s6_addr[12], 4);

	memcpy(&addr->addr, &sin, sizeof(sin));
	addr->addr_len = sizeof(sin);
	addr->family = AF_INET;
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

	try_to_unmap_ipv4(addr);
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
	cs = accept(orig->accept_s, (struct sockaddr *)&addr.addr, &salen);
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
		dnet_log(n, DNET_LOG_ERROR, "FATAL: Can't recover from this error: %d, exiting...", err);
		exit(err);
	}

	addr.family = orig->addr.family;
	addr.addr_len = salen;

	try_to_unmap_ipv4(&addr);

	dnet_set_sockopt(n, cs);

	err = dnet_socket_local_addr(cs, &saddr);
	if (err) {
		dnet_log(n, DNET_LOG_ERROR, "%s: failed to resolve server addr for connected client: %s [%d]",
				dnet_addr_string_raw(&addr, client_addr, sizeof(client_addr)), strerror(-err), -err);
		goto err_out_exit;
	}

	idx = dnet_local_addr_index(n, &saddr);

	st = dnet_state_create(n, NULL, 0, &addr, cs, &err, 0, 0, idx, 0, NULL, 0);
	if (!st) {
		dnet_log(n, DNET_LOG_ERROR, "%s: Failed to create state for accepted client: %s [%d]",
				dnet_addr_string_raw(&addr, client_addr, sizeof(client_addr)), strerror(-err), -err);
		err = -EAGAIN;

		/* We do not close socket, since it is closed in dnet_state_create() */
		goto err_out_exit;
	}

	// @dnet_net_state() returns state with 2 reference counters
	dnet_state_put(st);

	dnet_log(n, DNET_LOG_INFO, "Accepted client %s, socket: %d, server address: %s, idx: %d.",
			dnet_addr_string_raw(&addr, client_addr, sizeof(client_addr)), cs,
			dnet_addr_string_raw(&saddr, server_addr, sizeof(server_addr)), idx);

	return 0;

err_out_exit:
	return err;
}

void dnet_unschedule_send(struct dnet_net_state *st)
{
	if (st->write_s >= 0)
		epoll_ctl(st->epoll_fd, EPOLL_CTL_DEL, st->write_s, NULL);
}

void dnet_unschedule_all(struct dnet_net_state *st)
{
	if (st->read_s >= 0)
		epoll_ctl(st->epoll_fd, EPOLL_CTL_DEL, st->read_s, NULL);
	if (st->write_s >= 0)
		epoll_ctl(st->epoll_fd, EPOLL_CTL_DEL, st->write_s, NULL);
	if (st->accept_s >= 0)
		epoll_ctl(st->epoll_fd, EPOLL_CTL_DEL, st->accept_s, NULL);
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

			pthread_mutex_lock(&st->n->io->full_lock);
			list_stat_size_decrease(&st->n->io->output_stats, 1);
			pthread_mutex_unlock(&st->n->io->full_lock);
			HANDY_COUNTER_DECREMENT("io.output.queue.size", 1);

			if (atomic_read(&st->send_queue_size) > 0)
				if (atomic_dec(&st->send_queue_size) == DNET_SEND_WATERMARK_LOW) {
					dnet_log(st->n, DNET_LOG_DEBUG,
							"State low_watermark reached: %s: %d, waking up",
							dnet_addr_string(&st->addr),
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
		dnet_log_err(st->n, "%s: scheduling %s event on reset state: need-exit: %d",
				dnet_state_dump_addr(st), send ? "SEND" : "RECV", st->__need_exit);
		return st->__need_exit;
	}

	if (send) {
		ev.events = EPOLLOUT;
		fd = st->write_s;
		pthread_mutex_lock(&st->n->io->full_lock);
		list_stat_size_increase(&st->n->io->output_stats, 1);
		pthread_mutex_unlock(&st->n->io->full_lock);
		HANDY_COUNTER_INCREMENT("io.output.queue.size", 1);

		ev.data.ptr = &st->write_data;
	} else {
		ev.events = EPOLLIN;
		fd = st->read_s;

		ev.data.ptr = &st->read_data;
	}

	if (fd >= 0) {
		err = epoll_ctl(st->epoll_fd, EPOLL_CTL_ADD, fd, &ev);
	} else {
		err = 0;
	}

	if (err < 0) {
		err = -errno;

		if (err == -EEXIST) {
			err = 0;
		} else {
			dnet_log_err(st->n, "%s: failed to add %s event, fd: %d", dnet_state_dump_addr(st), send ? "SEND" : "RECV", fd);
		}
	} else if (!send && st->accept_s >= 0) {
		ev.data.ptr = &st->accept_data;
		err = epoll_ctl(st->epoll_fd, EPOLL_CTL_ADD, st->accept_s, &ev);

		if (err < 0) {
			err = -errno;

			dnet_log_err(st->n, "%s: failed to add %s event, fd: %d", dnet_state_dump_addr(st), "ACCEPT", st->accept_s);
		}
	}

	if (send)
		pthread_cond_broadcast(&st->n->io->full_wait);

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

static int dnet_state_net_process(struct dnet_net_state *st, struct epoll_event *ev)
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
		dnet_log(st->n, DNET_LOG_ERROR, "%s: received error event mask 0x%x", dnet_state_dump_addr(st), ev->events);
		err = -ECONNRESET;
	}
err_out_exit:
	return err;
}

static void dnet_check_work_pool_place(struct dnet_work_pool_place *place, uint64_t *list_size, uint64_t *threads_count)
{
	struct dnet_work_pool *pool;

	pthread_mutex_lock(&place->lock);
	pool = place->pool;
	if (pool) {
		pthread_mutex_lock(&pool->lock);
		*list_size += pool->list_stats.list_size;
		*threads_count += pool->num;
		pthread_mutex_unlock(&pool->lock);
	}
	pthread_mutex_unlock(&place->lock);
}

static void dnet_check_io_pool(struct dnet_io_pool *io, uint64_t *list_size, uint64_t *threads_count)
{
	dnet_check_work_pool_place(&io->recv_pool, list_size, threads_count);
	dnet_check_work_pool_place(&io->recv_pool_nb, list_size, threads_count);
}

static int dnet_check_io(struct dnet_io *io)
{
	uint64_t list_size = 0;
	uint64_t threads_count = 0;

	dnet_check_io_pool(&io->pool, &list_size, &threads_count);

	if (io->backends) {
		size_t i;
		for (i = 0; i < io->backends_count; ++i) {
			dnet_check_io_pool(&io->backends[i].pool, &list_size, &threads_count);
		}
	}

	if (list_size <= threads_count * 1000)
		return 1;

	return 0;
}

static void dnet_shuffle_epoll_events(struct epoll_event *evs, int size) {
	int i = 0, j = 0;
	struct epoll_event tmp;

	if (size < 1)
		return;

	for (i = 0; i < size - 1; ++i) {
		j = i + rand() / (RAND_MAX / (size - i) + 1);

		// In case if j == i we can't use memcpy because of the overlap
		memcpy(&tmp, evs + j, sizeof(struct epoll_event));
		memmove(evs + j, evs + i, sizeof(struct epoll_event));
		memcpy(evs + i, &tmp, sizeof(struct epoll_event));
	}
}

static void *dnet_io_process_network(void *data_)
{
	struct dnet_net_io *nio = data_;
	struct dnet_node *n = nio->n;
	struct dnet_net_epoll_data *data;
	struct dnet_net_state *st;
	struct epoll_event *evs = malloc(sizeof(struct epoll_event));
	struct epoll_event *evs_tmp = NULL;
	int evs_size = 1;
	int tmp = 0;
	int err = 0;
	int i = 0;
	struct timeval prev_tv, curr_tv;

	dnet_set_name("dnet_net");

	dnet_log(n, DNET_LOG_NOTICE, "started net pool");

	if (evs == NULL) {
		dnet_log(n, DNET_LOG_ERROR, "Not enough memory to allocate epoll_events");
		goto err_out_exit;
	}

	// get current timestamp for future outputting "Net pool is suspended..." logging
	gettimeofday(&prev_tv, NULL);

	while (!n->need_exit) {
		// get current number of states
		tmp = dnet_node_state_num(n);
		if (evs_size < tmp) {
			tmp *= 2; // tries to increase number of epoll_events
			evs_tmp = (struct epoll_event *)realloc(evs, sizeof(struct epoll_event) * tmp);
			if (evs_tmp) {
				evs = evs_tmp;
				evs_size = tmp;
			}
		}

		err = epoll_wait(nio->epoll_fd, evs, evs_size, 1000);
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

		// tmp will counts number of send events
		tmp = 0;
		// suffles available epoll_events
		dnet_shuffle_epoll_events(evs, err);
		for (i = 0; i < err; ++i) {
			data = evs[i].data.ptr;
			st = data->st;
			st->epoll_fd = nio->epoll_fd;

			if (data->fd == st->accept_s) {
				// We have to accept new connection
				++tmp;
				err = dnet_state_accept_process(st, &evs[i]);
			} else if ((evs[i].events & EPOLLOUT) || dnet_check_io(n->io)) {
				// if event is send or io pool queues are not full then process it
				++tmp;
				err = dnet_state_net_process(st, &evs[i]);
			}
			else
				continue;

			if (err == 0)
				continue;

			if (err == -EAGAIN && st->stall < DNET_DEFAULT_STALL_TRANSACTIONS)
				continue;

			if (err < 0 || st->stall >= DNET_DEFAULT_STALL_TRANSACTIONS) {
				if (!err)
					err = -ETIMEDOUT;

				char addr_str[128] = "no address";
				if (n->addr_num) {
					dnet_addr_string_raw(&n->addrs[0], addr_str, sizeof(addr_str));
				}
				dnet_log(n, DNET_LOG_ERROR, "self: addr: %s, resetting state: %p", addr_str, st);
				dnet_log(n, DNET_LOG_ERROR, "self: addr: %s, resetting state: %s", addr_str, dnet_state_dump_addr(st));

				dnet_state_reset(st, err);

				pthread_mutex_lock(&st->send_lock);
				dnet_unschedule_all(st);
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
				continue;
			}
		}

		// wait condition variable if no data was sended and io pool queues are still full
		if (tmp == 0 && dnet_check_io(n->io) == 0) {
			gettimeofday(&curr_tv, NULL);
			// print log only if previous log was writed more then 1 seconds
			if ((curr_tv.tv_sec - prev_tv.tv_sec) > 1) {
				dnet_log(n, DNET_LOG_INFO, "Net pool is suspended bacause io pool queues is full");
				prev_tv = curr_tv;
			}
			// wait condition variable - io queues has a free slot or some socket has something to send
			pthread_mutex_lock(&n->io->full_lock);
			n->io->blocked = 1;
			pthread_cond_wait(&n->io->full_wait, &n->io->full_lock);
			n->io->blocked = 0;
			pthread_mutex_unlock(&n->io->full_lock);
		}
	}

	free(evs);

err_out_exit:
	dnet_log(n, DNET_LOG_NOTICE, "finished net pool");
	return &n->need_exit;
}

static void dnet_io_cleanup_states(struct dnet_node *n)
{
	struct dnet_net_state *st, *tmp;

	list_for_each_entry_safe(st, tmp, &n->storage_state_list, storage_state_entry) {
		dnet_unschedule_all(st);

		dnet_state_reset(st, -EUCLEAN);

		dnet_state_clean(st);
		dnet_state_put(st);
	}

	n->st = NULL;
}

static struct dnet_io_req *take_request(struct dnet_work_io *wio)
{
	struct dnet_work_pool *pool = wio->pool;
	struct dnet_io_req *it = NULL, *tmp;
	struct dnet_cmd *cmd;
	uint64_t trans;
	int i;
	int ok;

	if (!list_empty(&wio->list)) {
		it = list_first_entry(&wio->list, struct dnet_io_req, req_entry);
		cmd = it->header;
		trans = cmd->trans;
		wio->trans = trans;
		return it;
	}

	list_for_each_entry_safe(it, tmp, &pool->list, req_entry) {
		cmd = it->header;
		trans = cmd->trans;
		ok = 1;

		/* This is not a transaction reply, process it right now */
		if (!(cmd->flags & DNET_FLAGS_REPLY))
			return it;

		for (i = 0; i < pool->num; ++i) {
			 /* Someone claimed transaction @tid */
			if (pool->wio_list[i].trans == trans) {
				list_move_tail(&it->req_entry, &pool->wio_list[i].list);
				ok = 0;
				break;
			}
		}

		if (ok) {
			wio->trans = trans;
			return it;
		}
	}

	return NULL;
}

void *dnet_io_process(void *data_)
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
	int nonblocking = (pool->mode == DNET_WORK_IO_MODE_NONBLOCKING);
	char thread_stat_id[255];

	if (pool->io) {
		dnet_set_name("dnet_%sio_%zu", nonblocking ? "nb_" : "", pool->io->backend_id);
	} else {
		dnet_set_name("dnet_%sio", nonblocking ? "nb_" : "");
	}

	make_thread_stat_id(thread_stat_id, sizeof(thread_stat_id), pool);

	dnet_log(n, DNET_LOG_NOTICE, "started io thread: #%d, nonblocking: %d, backend: %zd",
		wio->thread_index, nonblocking, pool->io ? (ssize_t)pool->io->backend_id : -1);


	while (!n->need_exit && (!pool->io || !pool->io->need_exit)) {
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
		wio->trans = ~0ULL;

		if (!(r = take_request(wio))) {
			err = pthread_cond_timedwait(&pool->wait, &pool->lock, &ts);
			if ((r = take_request(wio)))
				err = 0;
		}

		if (r) {
			list_del_init(&r->req_entry);
			list_stat_size_decrease(&pool->list_stats, 1);
			pthread_cond_broadcast(&n->io->full_wait);
		}
		pthread_mutex_unlock(&pool->lock);

		if (!r || err)
			continue;

		HANDY_COUNTER_DECREMENT("io.input.queue.size", 1);

		FORMATTED(HANDY_COUNTER_DECREMENT, ("pool.%s.queue.size", thread_stat_id), 1);
		FORMATTED(HANDY_TIMER_STOP, ("pool.%s.queue.wait_time", thread_stat_id), (uint64_t)r);

		FORMATTED(HANDY_COUNTER_INCREMENT, ("pool.%s.active_threads", thread_stat_id), 1);

		st = r->st;
		cmd = r->header;

		dnet_node_set_trace_id(n->log, cmd->trace_id, cmd->flags & DNET_FLAGS_TRACE_BIT, pool->io ? (ssize_t)pool->io->backend_id : (ssize_t)-1);

		dnet_log(n, DNET_LOG_DEBUG, "%s: %s: got IO event: %p: cmd: %s, hsize: %zu, dsize: %zu, mode: %s, backend_id: %zd",
			dnet_state_dump_addr(st), dnet_dump_id(r->header), r, dnet_cmd_string(cmd->cmd), r->hsize, r->dsize, dnet_work_io_mode_str(pool->mode),
			pool->io ? (ssize_t)pool->io->backend_id : (ssize_t)-1);

		err = dnet_process_recv(pool->io, st, r);

		dnet_log(n, DNET_LOG_DEBUG, "%s: %s: processed IO event: %p, cmd: %s",
			dnet_state_dump_addr(st), dnet_dump_id(r->header), r, dnet_cmd_string(cmd->cmd));

		dnet_node_unset_trace_id();

		dnet_io_req_free(r);
		dnet_state_put(st);

		FORMATTED(HANDY_COUNTER_DECREMENT, ("pool.%s.active_threads", thread_stat_id), 1);
	}

	dnet_log(n, DNET_LOG_NOTICE, "finished io thread: #%d, nonblocking: %d, backend: %zd",
		wio->thread_index, pool->mode == DNET_WORK_IO_MODE_NONBLOCKING, pool->io ? (ssize_t)pool->io->backend_id : -1);

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

	err = pthread_mutex_init(&n->io->full_lock, NULL);
	if (err) {
		err = -err;
		goto err_out_free;
	}

	err = pthread_cond_init(&n->io->full_wait, NULL);
	if (err) {
		err = -err;
		goto err_out_free_mutex;
	}

	err = pthread_mutex_init(&n->io->backends_lock, NULL);
	if (err) {
		err = -err;
		goto err_out_free_cond;
	}

	list_stat_init(&n->io->output_stats);

	n->io->net_thread_num = cfg->net_thread_num;
	n->io->net_thread_pos = 0;
	n->io->net = (struct dnet_net_io *)(n->io + 1);

	err = dnet_work_pool_place_init(&n->io->pool.recv_pool);
	if (err) {
		goto err_out_free_backends_lock;
	}

	err = dnet_work_pool_alloc(&n->io->pool.recv_pool, n, NULL, cfg->io_thread_num, DNET_WORK_IO_MODE_BLOCKING, dnet_io_process);
	if (err) {
		goto err_out_cleanup_recv_place;
	}

	err = dnet_work_pool_place_init(&n->io->pool.recv_pool_nb);
	if (err) {
		goto err_out_free_recv_pool;
	}

	err = dnet_work_pool_alloc(&n->io->pool.recv_pool_nb, n, NULL, cfg->nonblocking_io_thread_num, DNET_WORK_IO_MODE_NONBLOCKING, dnet_io_process);
	if (err) {
		goto err_out_cleanup_recv_place_nb;
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
			dnet_log(n, DNET_LOG_ERROR, "Failed to create network processing thread: %d", err);
			goto err_out_net_destroy;
		}
	}

	return 0;

err_out_net_destroy:
	n->need_exit = 1;
	while (--i >= 0) {
		pthread_join(n->io->net[i].tid, NULL);
		close(n->io->net[i].epoll_fd);
	}

	dnet_work_pool_cleanup(&n->io->pool.recv_pool_nb);
err_out_cleanup_recv_place_nb:
	dnet_work_pool_place_cleanup(&n->io->pool.recv_pool_nb);
err_out_free_recv_pool:
	n->need_exit = 1;
	dnet_work_pool_cleanup(&n->io->pool.recv_pool);
err_out_cleanup_recv_place:
	dnet_work_pool_place_cleanup(&n->io->pool.recv_pool);
err_out_free_backends_lock:
	pthread_mutex_destroy(&n->io->backends_lock);
err_out_free_cond:
	pthread_cond_destroy(&n->io->full_wait);
err_out_free_mutex:
	pthread_mutex_destroy(&n->io->full_lock);
err_out_free:
	free(n->io);
err_out_exit:
	n->io = NULL;
	return err;
}

int dnet_server_io_init(struct dnet_node *n)
{
	int err;
	size_t j = 0, k = 0;

	n->io->backends_count = dnet_backend_info_list_count(n->config_data->backends);
	n->io->backends = calloc(n->io->backends_count, sizeof(struct dnet_backend_io));
	if (!n->io->backends) {
		err = -ENOMEM;
		goto err_out_exit;
	}

	for (j = 0; j < n->io->backends_count; ++j) {
		struct dnet_backend_io *io = &n->io->backends[j];
		io->backend_id = j;

		err = dnet_work_pool_place_init(&io->pool.recv_pool);
		if (err) {
			goto err_out_free_backends_io;
		}

		err = dnet_work_pool_place_init(&io->pool.recv_pool_nb);
		if (err) {
			dnet_work_pool_place_cleanup(&io->pool.recv_pool);
			goto err_out_free_backends_io;
		}
	}
	return 0;

err_out_free_backends_io:
	for (k = 0; k < j; ++k) {
		struct dnet_backend_io *io = &n->io->backends[k];
		io->need_exit = 1;
	}
	for (k = 0; k < j; ++k) {
		struct dnet_backend_io *io = &n->io->backends[k];
		dnet_work_pool_cleanup(&io->pool.recv_pool);
		dnet_work_pool_cleanup(&io->pool.recv_pool_nb);
	}
	free(n->io->backends);
err_out_exit:
	return err;
}

void dnet_io_exit(struct dnet_node *n)
{
	struct dnet_io *io = n->io;
	int i;
	size_t j;

	n->need_exit = 1;

	for (j = 0; j < n->io->backends_count; ++j) {
		struct dnet_backend_io *io = &n->io->backends[j];
		io->need_exit = 1;
	}

	for (i=0; i<io->net_thread_num; ++i) {
		pthread_join(io->net[i].tid, NULL);
		close(io->net[i].epoll_fd);
	}

	dnet_work_pool_cleanup(&n->io->pool.recv_pool_nb);
	dnet_work_pool_place_cleanup(&n->io->pool.recv_pool_nb);

	dnet_work_pool_cleanup(&n->io->pool.recv_pool);
	dnet_work_pool_place_cleanup(&n->io->pool.recv_pool);

	for (j = 0; j < n->io->backends_count; ++j) {
		struct dnet_backend_io *io = &n->io->backends[j];
		if (io->pool.recv_pool.pool)
			dnet_work_pool_cleanup(&io->pool.recv_pool);
		if (io->pool.recv_pool_nb.pool)
			dnet_work_pool_cleanup(&io->pool.recv_pool_nb);
		dnet_work_pool_place_cleanup(&io->pool.recv_pool_nb);
		dnet_work_pool_place_cleanup(&io->pool.recv_pool);
	}

	dnet_io_cleanup_states(n);

	free(io);
	n->io = NULL;
}
