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

#include "config.h"

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

static int dnet_socket_connect(struct dnet_node *n, int s, struct sockaddr *sa, unsigned int salen)
{
	int err;

	fcntl(s, F_SETFL, O_NONBLOCK);

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

		err = poll(&pfd, 1, 2000);
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

int dnet_socket_create(struct dnet_node *n, struct dnet_config *cfg,
		struct dnet_addr *addr, int listening)
{
	int s, err = -EINVAL;
	struct addrinfo *ai = NULL, hint;
	struct dnet_net_state *st;

	memset(&hint, 0, sizeof(struct addrinfo));

	if (cfg->family != n->family)
		cfg->family = n->family;
	if (cfg->sock_type != n->sock_type)
		cfg->sock_type = n->sock_type;
	if (cfg->proto != n->proto)
		cfg->proto = n->proto;

	hint.ai_family = cfg->family;
	hint.ai_socktype = cfg->sock_type;
	hint.ai_protocol = cfg->proto;

	err = getaddrinfo(cfg->addr, cfg->port, &hint, &ai);
	if (err || ai == NULL) {
		err = -errno;
		if (!err)
			err = -EINVAL;

		dnet_log(n, DNET_LOG_ERROR, "Failed to get address info for %s:%s, family: %d, err: %d: %s [%d].\n",
				cfg->addr, cfg->port, cfg->family, err, strerror(errno), errno);
		goto err_out_exit;
	}

	if (addr->addr_len >= ai->ai_addrlen)
		addr->addr_len = ai->ai_addrlen;
	else {
		dnet_log(n, DNET_LOG_ERROR, "Failed to copy address: size %u is too small (must be more than %u).\n",
				addr->addr_len, ai->ai_addrlen);
		err = -ENOBUFS;
		goto err_out_exit;
	}
	memcpy(addr->addr, ai->ai_addr, addr->addr_len);

	st = dnet_state_search_by_addr(n, addr);
	if (st) {
		dnet_log(n, DNET_LOG_ERROR, "Address %s:%s already exists in route table\n", cfg->addr, cfg->port);
		err = -EEXIST;
		dnet_state_put(st);
		goto err_out_free;
	}

	s = dnet_socket_create_addr(n, cfg->sock_type, cfg->proto, cfg->family,
			ai->ai_addr, ai->ai_addrlen, listening);
	if (s < 0) {
		err = s;
		goto err_out_free;
	}

	freeaddrinfo(ai);

	return s;

err_out_free:
	freeaddrinfo(ai);
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
		}
		pthread_mutex_unlock(&st->trans_lock);

		if (!t)
			break;

		dnet_trans_put(t);
		dnet_trans_put(t);
		num++;
	}

	dnet_log(st->n, DNET_LOG_INFO, "Cleaned state %s, transactions freed: %d\n", dnet_state_dump_addr(st), num);
}

/*
 * Eventually we may end up with proper reference counters here, but for now let's just copy the whole buf.
 * Large data blocks are being sent through sendfile anyway, so it should not be _that_ costly operation.
 */
static int dnet_send_req_queue(struct dnet_net_state *st, struct dnet_send_req *orig)
{
	void *buf;
	struct dnet_send_req *r;
	int offset = 0;
	int err;

	dnet_log(st->n, DNET_LOG_NOTICE, "%s: send queue: hsize: %zu, dsize: %zu, fsize: %zu\n",
			dnet_state_dump_addr(st), orig->hsize, orig->dsize, orig->fsize);

	buf = r = malloc(sizeof(struct dnet_send_req) + orig->dsize + orig->hsize);
	if (!r) {
		err = -ENOMEM;
		goto err_out_exit;
	}
	memset(r, 0, sizeof(struct dnet_send_req));
	r->fd = -1;

	if (orig->header && orig->hsize) {
		r->header = buf + sizeof(struct dnet_send_req);
		r->hsize = orig->hsize;

		offset = r->hsize;
		memcpy(r->header, orig->header, r->hsize);
	}

	if (orig->data && orig->dsize) {
		r->data = buf + sizeof(struct dnet_send_req) + offset;
		r->dsize = orig->dsize;
		
		offset += r->dsize;
		memcpy(r->data, orig->data, r->dsize);
	}

	if (orig->fd >= 0 && orig->fsize) {
		r->fd = dup(orig->fd);
		if (r->fd < 0) {
			err = -errno;
			dnet_log_err(st->n, "%s: failed to duplicate send fd(%d)", dnet_state_dump_addr(st), orig->fd);
			goto err_out_free;
		}

		r->local_offset = orig->local_offset;
		r->fsize = orig->fsize;
	}

	pthread_mutex_lock(&st->send_lock);
	list_add_tail(&r->req_entry, &st->send_list);
	pthread_cond_broadcast(&st->send_wait);
	pthread_mutex_unlock(&st->send_lock);

	return 0;

err_out_free:
	free(r);
err_out_exit:
	return err;
}

static void dnet_send_req_free(struct dnet_net_state *st, struct dnet_send_req *r)
{
	pthread_mutex_lock(&st->send_lock);
	list_del(&r->req_entry);
	pthread_mutex_unlock(&st->send_lock);

	if (r->fd >= 0 && r->fsize)
		close(r->fd);
	free(r);
}

static int dnet_wait(struct dnet_net_state *st, unsigned int events, long timeout)
{
	struct pollfd pfd;
	int err;

	pfd.fd = st->s;
	pfd.revents = 0;
	pfd.events = events;

	err = poll(&pfd, 1, timeout);
	if (err < 0) {
		if (errno == EAGAIN || errno == EINTR) {
			err = -EAGAIN;
			goto out_exit;
		}

		dnet_log(st->n, DNET_LOG_ERROR, "Failed to wait for descriptor: err: %d, socket: %d.\n",
				err, st->s);
		err = -errno;
		goto out_exit;
	}

	if (err == 0) {
		err = -EAGAIN;
		goto out_exit;
	}

	if (pfd.revents & (POLLRDHUP | POLLERR | POLLHUP | POLLNVAL)) {
		dnet_log(st->n, DNET_LOG_DSA, "Connection reset by peer: sock: %d, revents: %x.\n",
			st->s, pfd.revents);
		err = -ECONNRESET;
		goto out_exit;
	}

	if (pfd.revents & events) {
		err = 0;
		goto out_exit;
	}

	dnet_log(st->n, DNET_LOG_ERROR, "Socket reported error: sock: %d, revents: %x.\n",
			st->s, pfd.revents);
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
	struct timeval start, end;
	long diff;

	gettimeofday(&start, NULL);

	while (size) {
		err = dnet_wait(st, POLLOUT, 1000);

		gettimeofday(&end, NULL);
		diff = end.tv_sec - start.tv_sec;

		if ((err < 0) && (diff > n->check_timeout)) {
			dnet_log(n, DNET_LOG_ERROR, "%s: STATE TIMEOUT (send side)\n", dnet_state_dump_addr(st));
			err = -ETIMEDOUT;
			break;
		}

		if (err == -EAGAIN)
			continue;

		if (err < 0)
			break;

		err = send(st->s, data, size, 0);
		if (err < 0) {
			err = -errno;
			dnet_log_err(n, "Failed to send packet: size: %llu, socket: %d",
					(unsigned long long)size, st->s);
			break;
		}

		if (err == 0) {
			dnet_log(n, DNET_LOG_ERROR, "Peer %s has dropped the connection: socket: %d.\n", dnet_state_dump_addr(st), st->s);
			err = -ECONNRESET;
			break;
		}

		data += err;
		size -= err;

		err = 0;
		gettimeofday(&start, NULL);
	}

	if (err) {
		dnet_log(n, DNET_LOG_ERROR, "%s: setting need_exit to %d\n", dnet_state_dump_addr(st), err);
		st->need_exit = err;
	}
	return err;
}

ssize_t dnet_send(struct dnet_net_state *st, void *data, uint64_t size)
{
	struct dnet_send_req r;

	memset(&r, 0, sizeof(r));
	r.data = data;
	r.dsize = size;
	r.fd = -1;

	return dnet_send_req_queue(st, &r);
}

ssize_t dnet_send_data(struct dnet_net_state *st, void *header, uint64_t hsize, void *data, uint64_t dsize)
{
	struct dnet_send_req r;

	memset(&r, 0, sizeof(r));
	r.header = header;
	r.hsize = hsize;
	r.data = data;
	r.dsize = dsize;
	r.fd = -1;

	return dnet_send_req_queue(st, &r);
}

static ssize_t dnet_send_fd_nolock(struct dnet_net_state *st, int fd, uint64_t offset, uint64_t dsize)
{
	ssize_t err;
	unsigned long long orig_dsize = dsize;
	unsigned long long orig_offset = offset;
	struct timeval start, end;
	long diff;

	gettimeofday(&start, NULL);

	while (dsize) {
		err = dnet_wait(st, POLLOUT, 1000);

		gettimeofday(&end, NULL);
		diff = end.tv_sec - start.tv_sec;

		if ((err < 0) && (diff > st->n->check_timeout)) {
			dnet_log(st->n, DNET_LOG_ERROR, "%s: STATE TIMEOUT (sendfile side)\n", dnet_state_dump_addr(st));
			err = -ETIMEDOUT;
			break;
		}
		if (err == -EAGAIN)
			continue;

		if (err < 0)
			goto err_out_exit;

		err = dnet_sendfile(st, fd, &offset, dsize);
		if (err < 0)
			goto err_out_exit;
		if (err == 0) {
			dnet_log(st->n, DNET_LOG_ERROR, "Looks like truncated file: fd: %d, offset: %llu, size: %llu.\n",
					fd, (unsigned long long)offset, (unsigned long long)dsize);
			break;
		}

		dsize -= err;
		gettimeofday(&start, NULL);
	}

	if (dsize) {
		char buf[4096];
		unsigned int sz;

		memset(buf, 0, sizeof(buf));

		dnet_log(st->n, DNET_LOG_DSA, "Truncated file, orig: %llu, zeroes: %llu bytes.\n",
				(unsigned long long)dsize + err, (unsigned long long)dsize);

		while (dsize) {
			sz = dsize;
			if (sz > sizeof(buf))
				sz = sizeof(buf);

			err = dnet_send_nolock(st, buf, sz);
			if (err)
				goto err_out_exit;

			dsize -= sz;
		}
	}

	dnet_log(st->n, DNET_LOG_DSA, "Sent %llu data bytes from fd %d, offset %llu -> %llu.\n",
			orig_dsize, fd, orig_offset, (unsigned long long)offset);

	err = 0;

err_out_exit:
	if (err) {
		dnet_log(n, DNET_LOG_ERROR, "%s: setting sendfile need_exit to %d\n", dnet_state_dump_addr(st), err);
		st->need_exit = err;
	}

	return err;
}

ssize_t dnet_send_fd(struct dnet_net_state *st, void *header, uint64_t hsize, int fd, uint64_t offset, uint64_t dsize)
{
	struct dnet_send_req r;

	memset(&r, 0, sizeof(r));
	r.header = header;
	r.hsize = hsize;
	r.fd = fd;
	r.local_offset = offset;
	r.fsize = dsize;

	return dnet_send_req_queue(st, &r);
}

int dnet_trans_send(struct dnet_trans_send_ctl *ctl)
{
	struct dnet_net_state *st = ctl->st;
	struct dnet_send_req r;
	int err;

	dnet_trans_get(ctl->t);

	pthread_mutex_lock(&st->trans_lock);
	err = dnet_trans_insert_nolock(&st->trans_root, ctl->t);
	pthread_mutex_unlock(&st->trans_lock);
	if (err)
		goto err_out_put;

	memset(&r, 0, sizeof(r));
	r.header = ctl->header;
	r.hsize = ctl->hsize;

	r.data = ctl->data;
	r.dsize = ctl->dsize;

	r.fd = ctl->fd;
	r.local_offset = ctl->foffset;
	r.fsize = ctl->fsize;

	err = dnet_send_req_queue(st, &r);
	if (err)
		goto err_out_remove;

	dnet_trans_put(ctl->t);
	return 0;

err_out_remove:
	dnet_trans_remove(ctl->t);
err_out_put:
	dnet_trans_put(ctl->t);
	return err;
}

int dnet_recv(struct dnet_net_state *st, void *data, unsigned int size)
{
	int err;

	while (size) {
		err = dnet_wait(st, POLLIN, 1000);
		if (err < 0)
			return err;

		err = recv(st->s, data, size, 0);
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
	}

	return 0;
}

static int dnet_trans_exec(struct dnet_trans *t, struct dnet_net_state *st)
{
	dnet_log(t->st->n, DNET_LOG_NOTICE, "%s: executing trans: %llu, reply: %d.\n",
			dnet_dump_id(&st->rcv_cmd.id), st->rcv_cmd.trans & ~DNET_TRANS_REPLY,
			!!(st->rcv_cmd.trans & DNET_TRANS_REPLY));

	if (t->complete)
		t->complete(t->st, &st->rcv_cmd, st->rcv_data, t->priv);

	return 0;
}

static struct dnet_trans *dnet_trans_new(struct dnet_net_state *st)
{
	struct dnet_trans *t;

	t = dnet_trans_alloc(st->n, 0);
	if (!t)
		goto err_out_exit;

	memcpy(&t->cmd, &st->rcv_cmd, sizeof(struct dnet_cmd));
	dnet_convert_cmd(&t->cmd);

	t->trans = t->rcv_trans = st->rcv_cmd.trans;

	return t;

err_out_exit:
	return NULL;
}

int dnet_add_reconnect_state(struct dnet_node *n, struct dnet_addr *addr, unsigned int join_state)
{
	struct dnet_addr_storage *a, *it;
	int err = 0;

	if (!join_state || n->need_exit)
		goto out_exit;

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

static int dnet_trans_complete_forward(struct dnet_net_state *state __unused,
				struct dnet_cmd *cmd,
				struct dnet_attr *attr,
				void *priv)
{
	struct dnet_trans *t = priv;
	struct dnet_net_state *dst = t->st;
	int err = -EINVAL;

	if (!is_trans_destroyed(state, cmd, attr)) {
		uint64_t size = cmd->size;

		cmd->trans = t->rcv_trans | DNET_TRANS_REPLY;

		dnet_convert_cmd(cmd);
		dnet_convert_attr(attr);

		err = dnet_send_data(dst, cmd, sizeof(struct dnet_cmd), attr, size);
	}

	return err;
}

static int dnet_trans_forward(struct dnet_trans *t, struct dnet_net_state *orig, struct dnet_net_state *forward)
{
	struct dnet_trans_send_ctl sc;

	t->rcv_trans = t->cmd.trans;
	t->cmd.trans = t->trans = atomic_inc(&orig->n->trans);

	t->complete = dnet_trans_complete_forward;
	t->priv = t;

	t->st = dnet_state_get(orig);

	memset(&sc, 0, sizeof(sc));
	sc.t = t;
	sc.st = forward;
	sc.header = &t->cmd;
	sc.hsize = sizeof(struct dnet_cmd);
	sc.data = orig->rcv_data;
	sc.dsize = orig->rcv_cmd.size;

	dnet_log(orig->n, DNET_LOG_INFO, "%s: forwarding to %s, trans: %llu -> %llu\n",
			dnet_dump_id(&t->cmd.id), dnet_state_dump_addr(forward),
			(unsigned long long)t->rcv_trans, (unsigned long long)t->trans);

	return dnet_trans_send(&sc);
}

static int dnet_process_recv(struct dnet_net_state *st)
{
	int err;
	struct dnet_trans *t = NULL;
	struct dnet_node *n = st->n;
	struct dnet_net_state *forward_state;

	if (st->rcv_cmd.trans & DNET_TRANS_REPLY) {
		uint64_t tid = st->rcv_cmd.trans & ~DNET_TRANS_REPLY;

		pthread_mutex_lock(&st->trans_lock);
		t = dnet_trans_search(&st->trans_root, tid);
		if (t && !(st->rcv_cmd.flags & DNET_FLAGS_MORE)) {
			dnet_trans_remove_nolock(&st->trans_root, t);
		}
		pthread_mutex_unlock(&st->trans_lock);

		if (!t) {
			dnet_log(st->n, DNET_LOG_ERROR, "%s: could not find transaction for reply: trans %llu.\n",
				dnet_dump_id(&st->rcv_cmd.id), (unsigned long long)tid);
			err = 0;
			goto err_out_exit;
		}

		err = dnet_trans_exec(t, st);
		dnet_trans_put(t);
		if (!(st->rcv_cmd.flags & DNET_FLAGS_MORE))
			dnet_trans_put(t);
		goto out;
	}

	forward_state = dnet_state_get_first(n, &st->rcv_cmd.id);
	if (!forward_state || forward_state == st || forward_state == n->st ||
			(st->rcv_cmd.flags & DNET_FLAGS_DIRECT)) {
		dnet_state_put(forward_state);

		dnet_process_cmd(st);
		goto out;
	}

	t = dnet_trans_new(st);
	if (!t) {
		err = -ENOMEM;
		goto err_out_put_forward;
	}

	err = dnet_trans_forward(t, st, forward_state);
	if (err)
		goto err_out_destroy;

	dnet_state_put(forward_state);

out:
	return 0;

err_out_destroy:
	dnet_trans_put(t);
err_out_put_forward:
	dnet_state_put(forward_state);
err_out_exit:
	if (t)
		dnet_log(st->n, DNET_LOG_ERROR, "%s: error during received transaction processing: trans %llu, reply: %d, error: %d.\n",
			dnet_dump_id(&t->cmd.id), (t->cmd.trans & ~DNET_TRANS_REPLY),
			!!(t->cmd.trans & DNET_TRANS_REPLY), err);
	return err;
}

static void dnet_schedule_command(struct dnet_net_state *st)
{
	st->rcv_flags = DNET_IO_CMD;

	if (st->rcv_data) {
#if 0
		struct dnet_cmd *c = &st->rcv_cmd;
		unsigned long long tid = c->trans & ~DNET_TRANS_REPLY;
		dnet_log(st->n, DNET_LOG_DSA, "freed: size: %llu, trans: %llu, reply: %d, ptr: %p.\n",
						(unsigned long long)c->size, tid, tid != c->trans, st->rcv_data);
#endif
		free(st->rcv_data);
		st->rcv_data = NULL;
	}

	st->rcv_size = sizeof(struct dnet_cmd);
	st->rcv_offset = 0;
}

static int dnet_process_recv_single(struct dnet_net_state *st)
{
	struct dnet_node *n = st->n;
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
	size = st->rcv_size - st->rcv_offset;

	if (size) {
		err = recv(st->s, data, size, 0);
		if (err < 0) {
			err = -EAGAIN;
			if (errno != EAGAIN && errno != EINTR) {
				err = -errno;
				dnet_log_err(n, "failed to receive data, socket: %d", st->s);
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

	if (st->rcv_offset != st->rcv_size)
		goto again;

	if (st->rcv_flags & DNET_IO_CMD) {
		unsigned long long tid;
		struct dnet_cmd *c = &st->rcv_cmd;

		dnet_convert_cmd(c);

		tid = c->trans & ~DNET_TRANS_REPLY;

		dnet_log(n, DNET_LOG_DSA, "%s: received trans: %llu / %llx, reply: %d, size: %llu, flags: %x, status: %d.\n",
				dnet_dump_id(&c->id), tid, (unsigned long long)c->trans, !!(c->trans & DNET_TRANS_REPLY),
				(unsigned long long)c->size, c->flags, c->status);

		if (c->size) {
			st->rcv_data = malloc(c->size);
			if (!st->rcv_data) {
				err = -ENOMEM;
				goto out;
			}
#if 0
			dnet_log(n, DNET_LOG_DSA, "allocated: %llu, trans: %llu, reply: %d, ptr: %p.\n",
					(unsigned long long)c->size, tid, tid != c->trans, st->rcv_data);
#endif
		}

		st->rcv_flags &= ~DNET_IO_CMD;
		st->rcv_offset = 0;
		st->rcv_size = c->size;

		if (c->size) {
			/*
			 * We read the command header, now get the data.
			 */
			goto again;
		}
	}

	err = dnet_process_recv(st);
	if (err)
		goto out;

	dnet_schedule_command(st);

	return 0;

out:
	if (err == -EAGAIN || err == -EINTR) {
		err = 0;
	} else {
		dnet_schedule_command(st);
	}

	return err;
}

static void dnet_state_remove(struct dnet_net_state *st)
{
	struct dnet_node *n = st->n;

	pthread_mutex_lock(&n->state_lock);
	list_del_init(&st->state_entry);
	pthread_mutex_unlock(&n->state_lock);
}

void dnet_state_reset(struct dnet_net_state *st)
{
	dnet_state_remove(st);
	dnet_idc_destroy(st);

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

	fcntl(s, F_SETFL, O_NONBLOCK);
}

static void *dnet_accept_client(void *priv)
{
	struct dnet_net_state *orig = priv;
	struct dnet_node *n = orig->n;
	struct dnet_net_state *st;
	struct dnet_addr addr;
	int cs, err;

	dnet_set_name("acceptor");

	while (!n->need_exit) {
		err = dnet_wait(orig, POLLIN | POLLRDHUP | POLLERR | POLLHUP | POLLNVAL, 1000);
		if (err == -EAGAIN)
			continue;

		if (err < 0)
			break;

		addr.addr_len = sizeof(addr.addr);
		cs = accept(orig->s, (struct sockaddr *)&addr.addr, &addr.addr_len);
		if (cs <= 0) {
			err = -errno;
			dnet_log_err(n, "failed to accept new client at %s", dnet_state_dump_addr(orig));
			continue;
		}

		dnet_set_sockopt(cs);

		st = dnet_state_create(n, 0, NULL, 0, &addr, cs, &err);
		if (!st) {
			dnet_sock_close(cs);
			continue;
		}

		dnet_log(n, DNET_LOG_INFO, "Accepted client %s, socket: %d.\n",
				dnet_server_convert_dnet_addr(&addr), cs);
	}

	dnet_state_reset(orig);
	return NULL;
}

static void *dnet_state_processing(void *priv)
{
	struct dnet_net_state *st = priv;
	struct timeval start, end;
	char addr[64];
	long diff;
	int err;

	dnet_set_name(dnet_server_convert_dnet_addr_raw(&st->addr, addr, sizeof(addr)));
	dnet_schedule_command(st);

	gettimeofday(&start, NULL);

	while (!st->n->need_exit && !st->need_exit) {
		err = dnet_wait(st, POLLIN, 1000);

		gettimeofday(&end, NULL);
		diff = end.tv_sec - start.tv_sec;

		if (err == -EAGAIN) {
			if (!RB_EMPTY_ROOT(&st->trans_root) && (diff > st->n->check_timeout)) {
				err = -ETIMEDOUT;
				dnet_log(st->n, DNET_LOG_ERROR, "%s: STATE TIMEOUT (recv side)\n",
						dnet_state_dump_addr(st));
				goto out_exit;
			}

			if (RB_EMPTY_ROOT(&st->trans_root))
				gettimeofday(&start, NULL);
			continue;
		}

		if (err < 0) {
			dnet_log(st->n, DNET_LOG_ERROR, "%s: failed to process poll events: %s [%d]\n",
					dnet_state_dump_addr(st), strerror(-err), err);
			goto out_exit;
		}

		err = dnet_process_recv_single(st);
		if (err < 0)
			goto out_exit;

		gettimeofday(&start, NULL);
	}

out_exit:
	dnet_state_reset(st);
	return NULL;
}

struct dnet_net_state *dnet_state_create(struct dnet_node *n,
		int group_id, struct dnet_raw_id *ids, int id_num,
		struct dnet_addr *addr, int s, int *errp)
{
	int err = -ENOMEM;
	struct dnet_net_state *st;
	void * (* func)(void *);

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

	st->s = s;
	st->n = n;

	st->la = 1;

	INIT_LIST_HEAD(&st->send_list);

	INIT_LIST_HEAD(&st->state_entry);
	st->trans_root = RB_ROOT;

	func = dnet_state_processing;
	if (s == n->listen_socket)
		func = dnet_accept_client;

	err = pthread_cond_init(&st->send_wait, NULL);
	if (err) {
		err = -err;
		dnet_log(n, DNET_LOG_ERROR, "Failed to initialize send conditional: %s [%d]\n",
				strerror(err), err);
		goto err_out_free;
	}

	err = pthread_mutex_init(&st->trans_lock, NULL);
	if (err) {
		err = -err;
		dnet_log_err(n, "Failed to initialize transaction mutex: %d", err);
		goto err_out_send_cond_destroy;
	}

	err = pthread_mutex_init(&st->send_lock, NULL);
	if (err) {
		err = -err;
		dnet_log_err(n, "Failed to initialize send mutex: %d", err);
		goto err_out_trans_destroy;
	}

	atomic_init(&st->refcnt, 1);

	memcpy(&st->addr, addr, sizeof(struct dnet_addr));

	if (!ids || !id_num) {
		pthread_mutex_lock(&n->state_lock);
		list_add_tail(&st->state_entry, &n->empty_state_list);
		pthread_mutex_unlock(&n->state_lock);
	} else {
		err = dnet_idc_create(st, group_id, ids, id_num);
		if (err)
			goto err_out_send_destroy;
	}

	err = pthread_create(&st->send_tid, NULL, dnet_state_send, st);
	if (err) {
		dnet_log_err(n, "Failed to create new send state thread: %d", err);
		goto err_out_put;
	}

	err = pthread_create(&st->tid, &n->attr, func, st);
	if (err) {
		dnet_log_err(n, "Failed to create new recv state thread: %d", err);
		goto err_out_put;
	}

	return st;

err_out_put:
	dnet_state_reset(st);
	goto err_out_exit;

err_out_send_destroy:
	pthread_mutex_destroy(&st->send_lock);
err_out_trans_destroy:
	pthread_mutex_destroy(&st->trans_lock);
err_out_send_cond_destroy:
	pthread_cond_destroy(&st->send_wait);
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
	struct dnet_send_req *r, *tmp;

	list_for_each_entry_safe(r, tmp, &st->send_list, req_entry) {
		dnet_send_req_free(st, r);
	}
}

void dnet_state_destroy(struct dnet_net_state *st)
{
	dnet_state_remove(st);

	if (st->s >= 0) {
		dnet_sock_close(st->s);
	}

	dnet_idc_destroy(st);
	dnet_state_clean(st);

	if ((long)st->send_tid != 0) {
		pthread_join(st->send_tid, NULL);
		dnet_state_send_clean(st);
	}

	pthread_cond_destroy(&st->send_wait);
	pthread_mutex_destroy(&st->send_lock);
	pthread_mutex_destroy(&st->trans_lock);

	dnet_log(st->n, DNET_LOG_INFO, "Freeing state %s, socket: %d.\n",
		dnet_server_convert_dnet_addr(&st->addr), st->s);

	free(st);
}

int dnet_send_reply(void *state, struct dnet_cmd *cmd, struct dnet_attr *attr,
		void *odata, unsigned int size, int more)
{
	struct dnet_net_state *st = state;
	struct dnet_cmd *c;
	struct dnet_attr *a;
	void *data;
	int err;

	c = malloc(sizeof(struct dnet_cmd) + sizeof(struct dnet_attr) + size);
	if (!c)
		return -ENOMEM;

	memset(c, 0, sizeof(struct dnet_cmd) + sizeof(struct dnet_attr) + size);

	a = (struct dnet_attr *)(c + 1);
	data = a + 1;

	*c = *cmd;

	if ((cmd->flags & DNET_FLAGS_NEED_ACK) || more)
		c->flags = DNET_FLAGS_MORE;

	c->size = sizeof(struct dnet_attr) + size;
	c->trans |= DNET_TRANS_REPLY;

	a->size = size;
	a->flags = attr->flags;
	a->cmd = attr->cmd;

	if (size)
		memcpy(data, odata, size);

	dnet_log(st->n, DNET_LOG_NOTICE, "%s: sending reply: %u, size: %u, cflags: %x.\n",
		dnet_dump_id(&cmd->id), a->cmd, size, c->flags);

	dnet_convert_cmd(c);
	dnet_convert_attr(a);

	err = dnet_send(st, c, sizeof(struct dnet_cmd) + sizeof(struct dnet_attr) + size);
	free(c);

	return err;
}

static int dnet_send_request(struct dnet_net_state *st, struct dnet_send_req *r)
{
	int err = 0;

	if (r->hsize && r->header) {
		err = dnet_send_nolock(st, r->header, r->hsize);
		if (err)
			goto err_out_exit;
	}

	if (r->dsize && r->data) {
		err = dnet_send_nolock(st, r->data, r->dsize);
		if (err)
			goto err_out_exit;
	}

	if (r->fd >= 0 && r->fsize) {
		err = dnet_send_fd_nolock(st, r->fd, r->local_offset, r->dsize);
		if (err)
			goto err_out_exit;
	}

err_out_exit:
	dnet_log(st->n, DNET_LOG_NOTICE, "%s: sent: hsize: %zu, dsize: %zu, fsize: %zu, err: %d\n",
			dnet_state_dump_addr(st), r->hsize, r->dsize, r->fsize, err);


	dnet_send_req_free(st, r);
	return err;
}

void *dnet_state_send(void *_data)
{
	struct dnet_net_state *st = _data;
	struct dnet_node *n = st->n;
	struct timespec ts;
	struct timeval tv;
	struct dnet_send_req *r;
	int err;

	while (!n->need_exit && !st->need_exit) {
		r = NULL;
		err = 0;

		gettimeofday(&tv, NULL);
		ts.tv_sec = tv.tv_sec + 1; /* repeat check once per second */
		ts.tv_nsec = tv.tv_usec * 1000;

		pthread_mutex_lock(&st->send_lock);
		if (list_empty(&st->send_list))
			err = pthread_cond_timedwait(&st->send_wait, &st->send_lock, &ts);
		else
			r = list_first_entry(&st->send_list, struct dnet_send_req, req_entry);
		pthread_mutex_unlock(&st->send_lock);

		if (err) {
			if (err == ETIMEDOUT)
				continue;

			err = -err;
			dnet_log(n, DNET_LOG_ERROR, "%s: failed to wait for send condition: %s [%d]\n",
					dnet_state_dump_addr(st), strerror(err), err);

			st->need_exit = err;
			break;
		}

		if (!r)
			continue;

		err = dnet_send_request(st, r);
		if (err < 0) {
			st->need_exit = err;
			break;
		}

	}

	/* state will be deleted in receiving processing function */
	return NULL;
}
