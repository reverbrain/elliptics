/*
 * 2008+ Copyright (c) Evgeniy Polyakov <zbr@ioremap.net>
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

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <poll.h>
#include <fcntl.h>

#include <netinet/tcp.h>

#include "elliptics.h"
#include "elliptics/packet.h"
#include "elliptics/interface.h"

#ifndef POLLRDHUP
#define POLLRDHUP 0x2000
#endif

static int dnet_socket_connect(struct dnet_node *n, int s, struct sockaddr *sa, unsigned int salen)
{
	int err;

	fcntl(s, F_SETFL, O_NONBLOCK);
	fcntl(s, F_SETFD, FD_CLOEXEC);

	err = connect(s, sa, salen);
	if (err) {
		struct pollfd pfd;
		socklen_t slen;
		int status;

		pfd.fd = s;
		pfd.revents = 0;
		pfd.events = POLLOUT;

		err = -errno;
		if (err != -EINPROGRESS) {
			dnet_log_err(n, "Failed to connect to %s:%d",
				dnet_server_convert_addr(sa, salen),
				dnet_server_convert_port(sa, salen));
			goto err_out_exit;
		}

		err = poll(&pfd, 1, n->wait_ts.tv_sec * 1000 > 2000 ? n->wait_ts.tv_sec : 2000);
		if (err < 0)
			goto err_out_exit;
		if (err == 0) {
			err = -ETIMEDOUT;
			dnet_log_err(n, "Failed to wait to connect to %s:%d",
				dnet_server_convert_addr(sa, salen),
				dnet_server_convert_port(sa, salen));
			goto err_out_exit;
		}
		if ((!(pfd.revents & POLLOUT)) || (pfd.revents & (POLLERR | POLLHUP))) {
			err = -ECONNREFUSED;
			dnet_log_err(n, "Connection refused by %s:%d",
				dnet_server_convert_addr(sa, salen),
				dnet_server_convert_port(sa, salen));
			goto err_out_exit;
		}

		status = 0;
		slen = 4;
		err = getsockopt(s, SOL_SOCKET, SO_ERROR, &status, &slen);
		if (err || status) {
			err = -errno;
			if (!err)
				err = -status;
			dnet_log_err(n, "Failed to connect to %s:%d: %s [%d]",
				dnet_server_convert_addr(sa, salen),
				dnet_server_convert_port(sa, salen),
				strerror(-err), err);
			goto err_out_exit;
		}
	}

	dnet_set_sockopt(s);

	dnet_log(n, DNET_LOG_INFO, "Connected to %s:%d.\n",
		dnet_server_convert_addr(sa, salen),
		dnet_server_convert_port(sa, salen));

	err = 0;

err_out_exit:
	return err;
}

int dnet_socket_create_addr(struct dnet_node *n, int sock_type, int proto, int family,
		struct sockaddr *sa, unsigned int salen, int listening)
{
	int s, err = -1;

	sa->sa_family = family;
	s = socket(family, sock_type, proto);
	if (s < 0) {
		err = -errno;
		dnet_log_err(n, "Failed to create socket for %s:%d: "
				"family: %d, sock_type: %d, proto: %d",
				dnet_server_convert_addr(sa, salen),
				dnet_server_convert_port(sa, salen),
				sa->sa_family, sock_type, proto);
		goto err_out_exit;
	}

	if (listening) {
		err = 1;
		setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &err, 4);

		err = bind(s, sa, salen);
		if (err) {
			err = -errno;
			dnet_log_err(n, "Failed to bind to %s:%d",
				dnet_server_convert_addr(sa, salen),
				dnet_server_convert_port(sa, salen));
			goto err_out_close;
		}

		err = listen(s, 10240);
		if (err) {
			err = -errno;
			dnet_log_err(n, "Failed to listen at %s:%d",
				dnet_server_convert_addr(sa, salen),
				dnet_server_convert_port(sa, salen));
			goto err_out_close;
		}

		dnet_log(n, DNET_LOG_INFO, "Server is now listening at %s:%d.\n",
				dnet_server_convert_addr(sa, salen),
				dnet_server_convert_port(sa, salen));

		fcntl(s, F_SETFL, O_NONBLOCK);
		fcntl(s, F_SETFD, FD_CLOEXEC);
	} else {
		err = dnet_socket_connect(n, s, sa, salen);
		if (err)
			goto err_out_close;
	}

	return s;

err_out_close:
	dnet_sock_close(s);
err_out_exit:
	return err;
}

int dnet_fill_addr(struct dnet_addr *addr, const char *saddr, const char *port, const int family,
		const int sock_type, const int proto)
{
	struct addrinfo *ai = NULL, hint;
	int err;

	memset(&hint, 0, sizeof(struct addrinfo));

	hint.ai_family = family;
	hint.ai_socktype = sock_type;
	hint.ai_protocol = proto;

	err = getaddrinfo(saddr, port, &hint, &ai);
	if (err || ai == NULL)
		goto err_out_exit;

	if (addr->addr_len >= ai->ai_addrlen)
		addr->addr_len = ai->ai_addrlen;
	else {
		err = -ENOBUFS;
		goto err_out_free;
	}
	memcpy(addr->addr, ai->ai_addr, addr->addr_len);

err_out_free:
	freeaddrinfo(ai);
err_out_exit:
	return err;
}

int dnet_socket_create(struct dnet_node *n, struct dnet_config *cfg,
		struct dnet_addr *addr, int listening)
{
	int s, err = -EINVAL;
	struct dnet_net_state *st;

	if (cfg->sock_type != n->sock_type)
		cfg->sock_type = n->sock_type;
	if (cfg->proto != n->proto)
		cfg->proto = n->proto;

	err = dnet_fill_addr(addr, cfg->addr, cfg->port, cfg->family, cfg->sock_type, cfg->proto);
	if (err) {
		dnet_log(n, DNET_LOG_ERROR, "Failed to get address info for %s:%s, family: %d, err: %d: %s.\n",
				cfg->addr, cfg->port, cfg->family, err, strerror(-err));
		goto err_out_exit;
	}

	st = dnet_state_search_by_addr(n, addr);
	if (st) {
		dnet_log(n, DNET_LOG_ERROR, "Address %s:%s already exists in route table\n", cfg->addr, cfg->port);
		err = -EEXIST;
		dnet_state_put(st);
		goto err_out_exit;
	}

	s = dnet_socket_create_addr(n, cfg->sock_type, cfg->proto, cfg->family,
			(struct sockaddr *)addr->addr, addr->addr_len, listening);
	if (s < 0) {
		err = s;
		goto err_out_exit;
	}

	return s;

err_out_exit:
	return err;
}

static void dnet_state_clean(struct dnet_net_state *st)
{
	struct rb_node *rb_node;
	struct dnet_trans *t;
	int num = 0;

	while (1) {
		t = NULL;

		pthread_mutex_lock(&st->trans_lock);
		rb_node = rb_first(&st->trans_root);
		if (rb_node) {
			t = rb_entry(rb_node, struct dnet_trans, trans_entry);
			dnet_trans_get(t);
			dnet_trans_remove_nolock(&st->trans_root, t);
			list_del_init(&t->trans_list_entry);
		}
		pthread_mutex_unlock(&st->trans_lock);

		if (!t)
			break;

		dnet_trans_put(t);
		dnet_trans_put(t);
		num++;
	}

	dnet_log(st->n, DNET_LOG_NOTICE, "Cleaned state %s, transactions freed: %d\n", dnet_state_dump_addr(st), num);
}

/*
 * Eventually we may end up with proper reference counters here, but for now let's just copy the whole buf.
 * Large data blocks are being sent through sendfile anyway, so it should not be _that_ costly operation.
 */
static int dnet_io_req_queue(struct dnet_net_state *st, struct dnet_io_req *orig)
{
	void *buf;
	struct dnet_io_req *r;
	int offset = 0;
	int err;

	buf = r = malloc(sizeof(struct dnet_io_req) + orig->dsize + orig->hsize);
	if (!r) {
		err = -ENOMEM;
		goto err_out_exit;
	}
	memset(r, 0, sizeof(struct dnet_io_req));
	r->fd = -1;

	if (orig->header && orig->hsize) {
		r->header = buf + sizeof(struct dnet_io_req);
		r->hsize = orig->hsize;

		offset = r->hsize;
		memcpy(r->header, orig->header, r->hsize);
	}

	if (orig->data && orig->dsize) {
		r->data = buf + sizeof(struct dnet_io_req) + offset;
		r->dsize = orig->dsize;
		
		offset += r->dsize;
		memcpy(r->data, orig->data, r->dsize);
	}

	if (orig->fd >= 0 && orig->fsize) {
		r->fd = orig->fd;
		r->close_on_exit = orig->close_on_exit;
		r->local_offset = orig->local_offset;
		r->fsize = orig->fsize;
	}

	pthread_mutex_lock(&st->send_lock);
	list_add_tail(&r->req_entry, &st->send_list);

	if (!st->need_exit)
		dnet_schedule_send(st);
	pthread_mutex_unlock(&st->send_lock);

	return 0;

err_out_exit:
	return err;
}

void dnet_io_req_free(struct dnet_io_req *r)
{
	if (r->fd >= 0 && r->fsize && r->close_on_exit)
		close(r->fd);
	free(r);
}

static int dnet_wait(struct dnet_net_state *st, unsigned int events, long timeout)
{
	struct pollfd pfd;
	int err;

	pfd.fd = st->read_s;
	pfd.revents = 0;
	pfd.events = events;

	err = poll(&pfd, 1, timeout);
	if (err < 0) {
		if (errno == EAGAIN || errno == EINTR) {
			err = -EAGAIN;
			goto out_exit;
		}

		dnet_log(st->n, DNET_LOG_ERROR, "Failed to wait for descriptor: err: %d, socket: %d.\n",
				err, st->read_s);
		err = -errno;
		goto out_exit;
	}

	if (err == 0) {
		err = -EAGAIN;
		goto out_exit;
	}

	if (pfd.revents & (POLLRDHUP | POLLERR | POLLHUP | POLLNVAL)) {
		dnet_log(st->n, DNET_LOG_DSA, "Connection reset by peer: sock: %d, revents: %x.\n",
			st->read_s, pfd.revents);
		err = -ECONNRESET;
		goto out_exit;
	}

	if (pfd.revents & events) {
		err = 0;
		goto out_exit;
	}

	dnet_log(st->n, DNET_LOG_ERROR, "Socket reported error: sock: %d, revents: %x.\n",
			st->read_s, pfd.revents);
	err = -EINVAL;
out_exit:
	if (st->n->need_exit || st->need_exit) {
		dnet_log(st->n, DNET_LOG_ERROR, "Need to exit.\n");
		err = -EIO;
	}

	return err;
}

ssize_t dnet_send_nolock(struct dnet_net_state *st, void *data, uint64_t size)
{
	ssize_t err = 0;
	struct dnet_node *n = st->n;

	while (size) {
		err = send(st->write_s, data, size, 0);
		if (err < 0) {
			err = -errno;
			if (err != -EAGAIN)
				dnet_log_err(n, "Failed to send packet: size: %llu, socket: %d",
					(unsigned long long)size, st->write_s);
			break;
		}

		if (err == 0) {
			dnet_log(n, DNET_LOG_ERROR, "Peer %s has dropped the connection: socket: %d.\n", dnet_state_dump_addr(st), st->write_s);
			err = -ECONNRESET;
			break;
		}

		data += err;
		size -= err;
		st->send_offset += err;

		err = 0;
	}

	return err;
}

ssize_t dnet_send(struct dnet_net_state *st, void *data, uint64_t size)
{
	struct dnet_io_req r;

	memset(&r, 0, sizeof(r));
	r.data = data;
	r.dsize = size;
	r.fd = -1;

	return dnet_io_req_queue(st, &r);
}

ssize_t dnet_send_data(struct dnet_net_state *st, void *header, uint64_t hsize, void *data, uint64_t dsize)
{
	struct dnet_io_req r;

	memset(&r, 0, sizeof(r));
	r.header = header;
	r.hsize = hsize;
	r.data = data;
	r.dsize = dsize;
	r.fd = -1;

	return dnet_io_req_queue(st, &r);
}

static ssize_t dnet_send_fd_nolock(struct dnet_net_state *st, int fd, uint64_t offset, uint64_t dsize)
{
	ssize_t err;

	while (dsize) {
		err = dnet_sendfile(st, fd, &offset, dsize);
		if (err < 0)
			break;
		if (err == 0) {
			err = -ENODATA;
			dnet_log_err(st->n, "Looks like truncated file: fd: %d, offset: %llu, size: %llu.\n",
					fd, (unsigned long long)offset, (unsigned long long)dsize);
			break;
		}

		dsize -= err;
		st->send_offset += err;
		err = 0;
	}

	return err;
}

ssize_t dnet_send_fd(struct dnet_net_state *st, void *header, uint64_t hsize,
		int fd, uint64_t offset, uint64_t fsize, int close_on_exit)
{
	struct dnet_io_req r;

	memset(&r, 0, sizeof(r));
	r.header = header;
	r.hsize = hsize;
	r.fd = fd;
	r.close_on_exit = close_on_exit;
	r.local_offset = offset;
	r.fsize = fsize;

	return dnet_io_req_queue(st, &r);
}

static void dnet_trans_timestamp(struct dnet_net_state *st, struct dnet_trans *t)
{
	gettimeofday(&t->time, NULL);
	t->time.tv_sec += st->n->wait_ts.tv_sec;

	list_move_tail(&t->trans_list_entry, &st->trans_list);
}

int dnet_trans_send(struct dnet_trans *t, struct dnet_io_req *req)
{
	struct dnet_net_state *st = req->st;
	int err;

	dnet_trans_get(t);

	pthread_mutex_lock(&st->trans_lock);
	err = dnet_trans_insert_nolock(&st->trans_root, t);
	if (!err)
		dnet_trans_timestamp(st, t);
	pthread_mutex_unlock(&st->trans_lock);
	if (err)
		goto err_out_put;

	err = dnet_io_req_queue(st, req);
	if (err)
		goto err_out_remove;

	dnet_trans_put(t);
	return 0;

err_out_remove:
	dnet_trans_remove(t);
err_out_put:
	dnet_trans_put(t);
	return err;
}

int dnet_recv(struct dnet_net_state *st, void *data, unsigned int size)
{
	int err;
	int wait = st->n->wait_ts.tv_sec;

	while (size) {
		err = dnet_wait(st, POLLIN, 1000);
		if (err < 0) {
			if (err == -EAGAIN) {
				if (--wait > 0)
					continue;

				err = -ETIMEDOUT;
			}
			return err;
		}

		err = recv(st->read_s, data, size, 0);
		if (err < 0) {
			dnet_log_err(st->n, "Failed to recv packet: size: %u", size);
			return err;
		}

		if (err == 0) {
			dnet_log(st->n, DNET_LOG_ERROR, "dnet_recv: peer %s has disconnected.\n",
					dnet_server_convert_dnet_addr(&st->addr));
			return -ECONNRESET;
		}

		data += err;
		size -= err;
		wait = st->n->wait_ts.tv_sec;
	}

	return 0;
}

static struct dnet_trans *dnet_trans_new(struct dnet_net_state *st)
{
	struct dnet_trans *t;

	t = dnet_trans_alloc(st->n, 0);
	if (!t)
		goto err_out_exit;

	return t;

err_out_exit:
	return NULL;
}

int dnet_add_reconnect_state(struct dnet_node *n, struct dnet_addr *addr, unsigned int join_state)
{
	struct dnet_addr_storage *a, *it;
	int err = 0;

	if (!join_state || n->need_exit) {
		if (!join_state)
			dnet_log(n, DNET_LOG_INFO, "Do not add reconnection addr: %s, join state: %x.\n",
				dnet_server_convert_dnet_addr(addr), join_state);
		goto out_exit;
	}

	a = malloc(sizeof(struct dnet_addr_storage));
	if (!a) {
		err = -ENOMEM;
		goto out_exit;
	}
	memset(a, 0, sizeof(struct dnet_addr_storage));

	memcpy(&a->addr, addr, sizeof(struct dnet_addr));
	a->__join_state = join_state;

	pthread_mutex_lock(&n->reconnect_lock);
	list_for_each_entry(it, &n->reconnect_list, reconnect_entry) {
		if (!memcmp(&it->addr, &a->addr, sizeof(struct dnet_addr))) {
			dnet_log(n, DNET_LOG_INFO, "Address already exists in reconnection array: addr: %s, join state: %x.\n",
				dnet_server_convert_dnet_addr(&a->addr), join_state);
			err = -EEXIST;
			break;
		}
	}

	if (!err) {
		dnet_log(n, DNET_LOG_INFO, "Added reconnection addr: %s, join state: %x.\n",
			dnet_server_convert_dnet_addr(&a->addr), join_state);
		list_add_tail(&a->reconnect_entry, &n->reconnect_list);
	}
	pthread_mutex_unlock(&n->reconnect_lock);

	if (err)
		free(a);

out_exit:
	return err;
}

static int dnet_trans_complete_forward(struct dnet_net_state *state __unused, struct dnet_cmd *cmd, void *priv)
{
	struct dnet_trans *t = priv;
	struct dnet_net_state *orig = t->orig;
	int err = -EINVAL;

	if (!is_trans_destroyed(state, cmd)) {
		uint64_t size = cmd->size;

		cmd->trans = t->rcv_trans | DNET_TRANS_REPLY;

		dnet_convert_cmd(cmd);

		err = dnet_send_data(orig, cmd, sizeof(struct dnet_cmd), cmd + 1, size);
	}

	return err;
}

static int dnet_trans_forward(struct dnet_trans *t, struct dnet_io_req *r,
		struct dnet_net_state *orig, struct dnet_net_state *forward)
{
	struct dnet_cmd *cmd = r->header;

	memcpy(&t->cmd, cmd, sizeof(struct dnet_cmd));

	t->rcv_trans = cmd->trans;
	cmd->trans = t->cmd.trans = t->trans = atomic_inc(&orig->n->trans);

	dnet_convert_cmd(cmd);

	t->command = cmd->cmd;
	t->complete = dnet_trans_complete_forward;
	t->priv = t;

	t->orig = dnet_state_get(orig);
	t->st = dnet_state_get(forward);

	r->st = forward;

	{
		char saddr[128];
		char daddr[128];

		dnet_log(orig->n, DNET_LOG_INFO, "%s: forwarding %s trans: %s -> %s, trans: %llu -> %llu\n",
				dnet_dump_id(&t->cmd.id), dnet_cmd_string(t->command),
				dnet_server_convert_dnet_addr_raw(&orig->addr, saddr, sizeof(saddr)),
				dnet_server_convert_dnet_addr_raw(&forward->addr, daddr, sizeof(daddr)),
				(unsigned long long)t->rcv_trans, (unsigned long long)t->trans);
	}

	return dnet_trans_send(t, r);
}

int dnet_process_recv(struct dnet_net_state *st, struct dnet_io_req *r)
{
	int err = 0;
	struct dnet_trans *t = NULL;
	struct dnet_node *n = st->n;
	struct dnet_net_state *forward_state;
	struct dnet_cmd *cmd = r->header;

	if (cmd->trans & DNET_TRANS_REPLY) {
		uint64_t tid = cmd->trans & ~DNET_TRANS_REPLY;

		pthread_mutex_lock(&st->trans_lock);
		t = dnet_trans_search(&st->trans_root, tid);
		if (t) {
			if (!(cmd->flags & DNET_FLAGS_MORE)) {
				dnet_trans_remove_nolock(&st->trans_root, t);
				list_del_init(&t->trans_list_entry);
			} else
				dnet_trans_timestamp(st, t);
		}
		pthread_mutex_unlock(&st->trans_lock);

		if (!t) {
			dnet_log(n, DNET_LOG_ERROR, "%s: could not find transaction for reply: trans %llu.\n",
				dnet_dump_id(&cmd->id), (unsigned long long)tid);
			err = 0;
			goto err_out_exit;
		}

		if (t->complete)
			t->complete(t->st, cmd, t->priv);

		dnet_trans_put(t);
		if (!(cmd->flags & DNET_FLAGS_MORE)) {
			memcpy(&t->cmd, cmd, sizeof(struct dnet_cmd));
			dnet_trans_put(t);
		}
		goto out;
	}
#if 1
	forward_state = dnet_state_get_first(n, &cmd->id);
	if (!forward_state || forward_state == st || forward_state == n->st ||
			(st->rcv_cmd.flags & DNET_FLAGS_DIRECT)) {
		dnet_state_put(forward_state);

		err = dnet_process_cmd_raw(st, cmd, r->data);
		goto out;
	}

	t = dnet_trans_new(st);
	if (!t) {
		err = -ENOMEM;
		goto err_out_put_forward;
	}

	err = dnet_trans_forward(t, r, st, forward_state);
	if (err)
		goto err_out_destroy;

	dnet_state_put(forward_state);
#else
	err = dnet_process_cmd_raw(st, cmd, r->data);
#endif
out:
	return err;

err_out_destroy:
	dnet_trans_put(t);
err_out_put_forward:
	dnet_state_put(forward_state);
err_out_exit:
	if (t)
		dnet_log(n, DNET_LOG_ERROR, "%s: error during received transaction processing: trans %llu, reply: %d, error: %d.\n",
			dnet_dump_id(&t->cmd.id), (t->cmd.trans & ~DNET_TRANS_REPLY),
			!!(t->cmd.trans & DNET_TRANS_REPLY), err);
	return err;
}

void dnet_state_remove_nolock(struct dnet_net_state *st)
{
	list_del_init(&st->state_entry);
	list_del_init(&st->storage_state_entry);
	dnet_idc_destroy_nolock(st);
}

static void dnet_state_remove(struct dnet_net_state *st)
{
	struct dnet_node *n = st->n;

	pthread_mutex_lock(&n->state_lock);
	dnet_state_remove_nolock(st);
	pthread_mutex_unlock(&n->state_lock);
}

void dnet_state_reset(struct dnet_net_state *st)
{
	dnet_state_remove(st);

	pthread_mutex_lock(&st->send_lock);
	if (!st->need_exit)
		st->need_exit = -ECONNRESET;
	dnet_unschedule_send(st);
	pthread_mutex_unlock(&st->send_lock);

	dnet_unschedule_recv(st);

	dnet_add_reconnect_state(st->n, &st->addr, st->__join_state);

	dnet_state_clean(st);
	dnet_state_put(st);
}

void dnet_sock_close(int s)
{
	shutdown(s, 2);
	close(s);
}

void dnet_set_sockopt(int s)
{
	struct linger l;
	int opt;

	opt = 1;
	setsockopt(s, SOL_SOCKET, SO_KEEPALIVE, &opt, 4);

	opt = 3;
	setsockopt(s, IPPROTO_TCP, TCP_KEEPCNT, &opt, 4);
	opt = 10;
	setsockopt(s, IPPROTO_TCP, TCP_KEEPIDLE, &opt, 4);
	opt = 10;
	setsockopt(s, IPPROTO_TCP, TCP_KEEPINTVL, &opt, 4);

	l.l_onoff = 1;
	l.l_linger = 1;

	setsockopt(s, SOL_SOCKET, SO_LINGER, &l, sizeof(l));

	fcntl(s, F_SETFD, FD_CLOEXEC);
	fcntl(s, F_SETFL, O_NONBLOCK);
}

int dnet_setup_control_nolock(struct dnet_net_state *st)
{
	struct dnet_node *n = st->n;
	struct dnet_io *io = n->io;
	int err, pos;

	if (st->epoll_fd == -1) {
		pos = io->net_thread_pos;
		if (++io->net_thread_pos >= io->net_thread_num)
			io->net_thread_pos = 0;
		st->epoll_fd = io->net[pos].epoll_fd;

		err = dnet_schedule_recv(st);
		if (err)
			goto err_out_unschedule;
	}

	return 0;

err_out_unschedule:
	dnet_unschedule_send(st);
	dnet_unschedule_recv(st);

	st->epoll_fd = -1;
	list_del_init(&st->storage_state_entry);
	return err;
}

static int dnet_auth_complete(struct dnet_net_state *state, struct dnet_cmd *cmd, void *priv __unused)
{
	struct dnet_node *n;

	if (!state || !cmd)
		return -EPERM;

	/* this means this callback at least has state and cmd */
	if (!is_trans_destroyed(state, cmd)) {
		n = state->n;

		if (cmd->status == 0) {
			dnet_log(n, DNET_LOG_INFO, "%s: authentication request suceeded\n", dnet_state_dump_addr(state));
			return 0;
		}

		dnet_log(n, DNET_LOG_ERROR, "%s: authentication request failed: %d\n", dnet_state_dump_addr(state), cmd->status);

		state->__join_state = 0;
		dnet_state_reset(state);
	}

	return cmd->status;
}

static int dnet_auth_send(struct dnet_net_state *st)
{
	struct dnet_node *n = st->n;
	struct dnet_trans_control ctl;
	struct dnet_auth a;

	memset(&a, 0, sizeof(struct dnet_auth));

	memcpy(a.cookie, n->cookie, DNET_AUTH_COOKIE_SIZE);
	dnet_convert_auth(&a);

	memset(&ctl, 0, sizeof(struct dnet_trans_control));

	ctl.cmd = DNET_CMD_AUTH;
	ctl.cflags = DNET_FLAGS_DIRECT | DNET_FLAGS_NEED_ACK;
	ctl.size = sizeof(struct dnet_auth);
	ctl.data = &a;

	ctl.complete = dnet_auth_complete;

	return dnet_trans_alloc_send_state(st, &ctl);
}

struct dnet_net_state *dnet_state_create(struct dnet_node *n,
		int group_id, struct dnet_raw_id *ids, int id_num,
		struct dnet_addr *addr, int s, int *errp, int join,
		int (* process)(struct dnet_net_state *st, struct epoll_event *ev))
{
	int err = -ENOMEM;
	struct dnet_net_state *st;

	if (ids && id_num) {
		st = dnet_state_search_by_addr(n, addr);
		if (st) {
			err = -EEXIST;
			dnet_state_put(st);
			goto err_out_close;
		}
	}

	st = malloc(sizeof(struct dnet_net_state));
	if (!st)
		goto err_out_close;

	memset(st, 0, sizeof(struct dnet_net_state));

	st->read_s = s;
	st->write_s = dup(s);
	if (st->write_s < 0) {
		err = -errno;
		dnet_log_err(n, "%s: failed to duplicate socket", dnet_server_convert_dnet_addr(addr));
		goto err_out_free;
	}

	fcntl(st->write_s, F_SETFD, FD_CLOEXEC);

	st->n = n;

	st->process = process;

	st->la = 1;
	st->weight = DNET_STATE_MAX_WEIGHT / 2;
	st->median_read_time = 1000; /* useconds for start */

	INIT_LIST_HEAD(&st->state_entry);
	INIT_LIST_HEAD(&st->storage_state_entry);

	st->trans_root = RB_ROOT;
	INIT_LIST_HEAD(&st->trans_list);

	st->epoll_fd = -1;

	err = pthread_mutex_init(&st->trans_lock, NULL);
	if (err) {
		err = -err;
		dnet_log_err(n, "Failed to initialize transaction mutex: %d", err);
		goto err_out_dup_destroy;
	}

	INIT_LIST_HEAD(&st->send_list);
	err = pthread_mutex_init(&st->send_lock, NULL);
	if (err) {
		err = -err;
		dnet_log_err(n, "Failed to initialize send mutex: %d", err);
		goto err_out_trans_destroy;
	}

	atomic_init(&st->refcnt, 1);

	memcpy(&st->addr, addr, sizeof(struct dnet_addr));

	dnet_schedule_command(st);
	st->__join_state = join;

	if (n->client_prio) {
		err = setsockopt(st->read_s, IPPROTO_IP, IP_TOS, &n->client_prio, 4);
		if (err) {
			err = -errno;
			dnet_log_err(n, "could not set read client prio %d", n->client_prio);
		}
		err = setsockopt(st->write_s, IPPROTO_IP, IP_TOS, &n->client_prio, 4);
		if (err) {
			err = -errno;
			dnet_log_err(n, "could not set write client prio %d", n->client_prio);
		}
		
		if (!err) {
			dnet_log(n, DNET_LOG_INFO, "%s: client net TOS value set to %d\n",
					dnet_server_convert_dnet_addr(addr), n->client_prio);
		}
	}

	/*
	 * it is possible that state can be removed after inserted into route table,
	 * so we should grab a reference here and drop it after we are done
	 */
	dnet_state_get(st);

	if (ids && id_num) {
		err = dnet_idc_create(st, group_id, ids, id_num);
		if (err)
			goto err_out_send_destroy;

		if ((st->__join_state == DNET_JOIN) && n->st) {
			pthread_mutex_lock(&n->state_lock);
			err = dnet_state_join_nolock(st);
			pthread_mutex_unlock(&n->state_lock);

			err = dnet_auth_send(st);
		}
	} else {
		pthread_mutex_lock(&n->state_lock);
		list_add_tail(&st->state_entry, &n->empty_state_list);
		list_add_tail(&st->storage_state_entry, &n->storage_state_list);

		err = dnet_setup_control_nolock(st);
		if (err)
			goto err_out_unlock;
		pthread_mutex_unlock(&n->state_lock);
	}

	if (atomic_read(&st->refcnt) == 1) {
		err = st->need_exit;
		if (!err)
			err = -ECONNRESET;
	}
	dnet_state_put(st);

	if (err)
		goto err_out_exit;

	return st;

err_out_unlock:
	list_del_init(&st->state_entry);
	pthread_mutex_unlock(&n->state_lock);
err_out_send_destroy:
	dnet_state_put(st);
	pthread_mutex_destroy(&st->send_lock);
err_out_trans_destroy:
	pthread_mutex_destroy(&st->trans_lock);
err_out_dup_destroy:
	dnet_sock_close(st->write_s);
err_out_free:
	free(st);
err_out_close:
	dnet_sock_close(s);

err_out_exit:
	if (err == -EEXIST)
		dnet_log(n, DNET_LOG_ERROR, "%s: state already exists.\n", dnet_server_convert_dnet_addr(addr));
	*errp = err;
	return NULL;
}

int dnet_state_num(struct dnet_node *n)
{
	struct dnet_net_state *st;
	struct dnet_group *g;
	int num = 0;

	pthread_mutex_lock(&n->state_lock);
	list_for_each_entry(g, &n->group_list, group_entry) {
		list_for_each_entry(st, &g->state_list, state_entry)
			num++;
	}
	pthread_mutex_unlock(&n->state_lock);

	return num;
}

static void dnet_state_send_clean(struct dnet_net_state *st)
{
	struct dnet_io_req *r, *tmp;

	list_for_each_entry_safe(r, tmp, &st->send_list, req_entry) {
		list_del(&r->req_entry);
		dnet_io_req_free(r);
	}
}

void dnet_state_destroy(struct dnet_net_state *st)
{
	dnet_state_remove(st);

	if (st->read_s >= 0) {
		dnet_sock_close(st->read_s);
		dnet_sock_close(st->write_s);
	}

	dnet_state_clean(st);

	dnet_state_send_clean(st);

	pthread_mutex_destroy(&st->send_lock);
	pthread_mutex_destroy(&st->trans_lock);

	dnet_log(st->n, DNET_LOG_NOTICE, "Freeing state %s, socket: %d/%d.\n",
		dnet_server_convert_dnet_addr(&st->addr), st->read_s, st->write_s);

	free(st);
}

int dnet_send_reply(void *state, struct dnet_cmd *cmd, void *odata, unsigned int size, int more)
{
	struct dnet_net_state *st = state;
	struct dnet_cmd *c;
	void *data;
	int err;

	if (st == st->n->st)
		return 0;

	c = malloc(sizeof(struct dnet_cmd) + size);
	if (!c)
		return -ENOMEM;

	memset(c, 0, sizeof(struct dnet_cmd) + size);

	data = c + 1;
	*c = *cmd;

	if ((cmd->flags & DNET_FLAGS_NEED_ACK) || more)
		c->flags |= DNET_FLAGS_MORE;

	c->size = size;
	c->trans |= DNET_TRANS_REPLY;

	if (size)
		memcpy(data, odata, size);

	dnet_log(st->n, DNET_LOG_NOTICE, "%s: %s: reply: size: %u, cflags: %llx.\n",
		dnet_dump_id(&cmd->id), dnet_cmd_string(cmd->cmd), size, (unsigned long long)c->flags);

	dnet_convert_cmd(c);

	err = dnet_send(st, c, sizeof(struct dnet_cmd) + size);
	free(c);

	return err;
}

int dnet_send_request(struct dnet_net_state *st, struct dnet_io_req *r)
{
	int cork;
	int err = 0;
	size_t offset = st->send_offset;

	/* Use TCP_CORK to send headers and packet body in one piece */
	cork = 1;
	setsockopt(st->write_s, IPPROTO_TCP, TCP_CORK, &cork, 4);

	if (r->hsize && r->header && st->send_offset < r->hsize) {
		err = dnet_send_nolock(st, r->header + offset, r->hsize - offset);
		if (err)
			goto err_out_exit;
	}

	if (r->dsize && r->data && st->send_offset < (r->dsize + r->hsize)) {
		offset = st->send_offset - r->hsize;
		err = dnet_send_nolock(st, r->data + offset, r->dsize - offset);
		if (err)
			goto err_out_exit;
	}

	if (r->fd >= 0 && r->fsize && st->send_offset < (r->dsize + r->hsize + r->fsize)) {
		offset = st->send_offset - r->dsize - r->hsize;
		err = dnet_send_fd_nolock(st, r->fd, r->local_offset + offset, r->fsize - offset);
		if (err)
			goto err_out_exit;
	}

	if (r->hsize > sizeof(struct dnet_cmd)) {
		struct dnet_cmd *cmd = r->header;
		int nonblocking = !!(cmd->flags & DNET_FLAGS_NOLOCK);

		dnet_log(st->n, DNET_LOG_DSA, "%s: %s: SENT %s cmd: %s: cmd-size: %llu, nonblocking: %d\n",
			dnet_state_dump_addr(st), dnet_dump_id(r->header),
			nonblocking ? "nonblocking" : "blocking",
			dnet_cmd_string(cmd->cmd),
			(unsigned long long)cmd->size, nonblocking);
	}

err_out_exit:
	if (st->send_offset == (r->dsize + r->hsize + r->fsize)) {
		pthread_mutex_lock(&st->send_lock);
		list_del(&r->req_entry);
		pthread_mutex_unlock(&st->send_lock);

		dnet_io_req_free(r);
		st->send_offset = 0;
	}

	if (err && err != -EAGAIN) {
		dnet_log(st->n, DNET_LOG_ERROR, "%s: setting send need_exit to %d\n", dnet_state_dump_addr(st), err);
		st->need_exit = err;
	}

	cork = 0;
	setsockopt(st->write_s, IPPROTO_TCP, TCP_CORK, &cork, 4);

	return err;
}

int dnet_parse_addr(char *addr, struct dnet_config *cfg)
{
	char *fam, *port;

	fam = strrchr(addr, DNET_CONF_ADDR_DELIM);
	if (!fam)
		goto err_out_print_wrong_param;
	*fam++ = 0;
	if (!fam)
		goto err_out_print_wrong_param;

	cfg->family = atoi(fam);

	port = strrchr(addr, DNET_CONF_ADDR_DELIM);
	if (!port)
		goto err_out_print_wrong_param;
	*port++ = 0;
	if (!port)
		goto err_out_print_wrong_param;

	memset(cfg->addr, 0, sizeof(cfg->addr));
	memset(cfg->port, 0, sizeof(cfg->port));

	snprintf(cfg->addr, sizeof(cfg->addr), "%s", addr);
	snprintf(cfg->port, sizeof(cfg->port), "%s", port);

	if (!strcmp(addr, "hostname")) {
		int err;

		err = gethostname(cfg->addr, sizeof(cfg->addr));
		if (err) {
			err = -errno;
			fprintf(stderr, "Could not get hostname: %s %d\n", strerror(-err), err);
			goto err_out_print_wrong_param;
		}
	}

	return 0;

err_out_print_wrong_param:
	fprintf(stderr, "Wrong address parameter '%s', should be 'addr%cport%cfamily'.\n",
				addr, DNET_CONF_ADDR_DELIM, DNET_CONF_ADDR_DELIM);
	return -EINVAL;
}
