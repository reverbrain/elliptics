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

#include "elliptics.h"
#include "elliptics/packet.h"
#include "elliptics/interface.h"

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

		err = listen(s, 1024);
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
	} else {
		err = connect(s, sa, salen);
		if (err) {
			err = -errno;
			dnet_log_err(n, "Failed to connect to %s:%d",
				dnet_server_convert_addr(sa, salen),
				dnet_server_convert_port(sa, salen));
			goto err_out_close;
		}

		dnet_log(n, DNET_LOG_INFO, "connected to %s:%d.\n",
			dnet_server_convert_addr(sa, salen),
			dnet_server_convert_port(sa, salen));
	}
	fcntl(s, F_SETFL, O_NONBLOCK);

	return s;

err_out_close:
	close(s);
err_out_exit:
	return err;
}

int dnet_socket_create(struct dnet_node *n, struct dnet_config *cfg,
		struct sockaddr *sa, unsigned int *addr_len, int listening)
{
	int s, err = -EINVAL;
	struct addrinfo *ai, hint;

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
	if (err) {
		err = -errno;
		dnet_log(n, DNET_LOG_ERROR, "Failed to get address info for %s:%s, family: %d, err: %d.\n",
				cfg->addr, cfg->port, cfg->family, err);
		goto err_out_exit;
	}

	s = dnet_socket_create_addr(n, cfg->sock_type, cfg->proto, cfg->family,
			ai->ai_addr, ai->ai_addrlen, listening);
	if (s < 0) {
		err = -errno;
		goto err_out_free;
	}

	if (*addr_len >= ai->ai_addrlen)
		*addr_len = ai->ai_addrlen;
	else {
		dnet_log(n, DNET_LOG_ERROR, "Failed to copy address: size %u is too small (must be more than %u).\n",
				*addr_len, ai->ai_addrlen);
		err = -ENOBUFS;
		goto err_out_close;
	}
	memcpy(sa, ai->ai_addr, *addr_len);

	freeaddrinfo(ai);

	return s;

err_out_close:
	close(s);
err_out_free:
	freeaddrinfo(ai);
err_out_exit:
	return err;
}

static int dnet_wait_fd(int s, unsigned int events, long timeout)
{
	struct pollfd pfd;
	int err;

	pfd.fd = s;
	pfd.revents = 0;
	pfd.events = events;

	err = poll(&pfd, 1, timeout);
	if (err < 0) {
		err = -errno;
		goto out_exit;
	}

	if (err == 0) {
		err = -EAGAIN;
		goto out_exit;
	}

	if (pfd.revents & events) {
		err = 0;
		goto out_exit;
	}

	err = -EINVAL;
out_exit:
	return err;
}

int dnet_send(struct dnet_net_state *st, void *data, unsigned int size)
{
	int err = 0;
	struct dnet_node *n = st->n;

	while (size) {
		err = dnet_wait_fd(st->s, POLLOUT, st->timeout);
		if (st->n->need_exit) {
			err = -EIO;
			break;
		}

		if (err == -EAGAIN || err == -EINTR)
			continue;

		if (err < 0) {
			dnet_log(n, DNET_LOG_ERROR, "Failed to wait for descriptor: err: %d, socket: %d.\n", err, st->s);
			break;
		}

		err = send(st->s, data, size, 0);
		if (err < 0) {
			err = -errno;
			dnet_log_err(n, "Failed to send packet: size: %u, socket: %d", size, st->s);
			break;
		}

		if (err == 0) {
			dnet_log(n, DNET_LOG_ERROR, "Peer has dropped the connection: socket: %d.\n", st->s);
			err = -ECONNRESET;
			break;
		}

		data += err;
		size -= err;

		err = 0;
	}

	return err;
}

int dnet_wait(struct dnet_net_state *st)
{
	return dnet_wait_fd(st->s, POLLIN, st->timeout);
}

int dnet_recv(struct dnet_net_state *st, void *data, unsigned int size)
{
	int err;

	while (size) {
		err = dnet_wait_fd(st->s, POLLIN, st->timeout);
		if (st->n->need_exit)
			return -EIO;
		if (err == -EAGAIN)
			continue;
		if (err < 0)
			return err;

		err = recv(st->s, data, size, 0);
		if (err < 0) {
			dnet_log_err(st->n, "Failed to recv packet: size: %u", size);
			return err;
		}

		if (err == 0) {
			dnet_log(st->n, DNET_LOG_ERROR, "Peer %s has disconnected.\n",
					dnet_server_convert_dnet_addr(&st->addr));
			return -ECONNRESET;
		}

		data += err;
		size -= err;
	}

	return 0;
}

/*
 * Schedule command receiving.
 */
static int dnet_schedule_command(struct dnet_net_state *st)
{
	st->rcv_flags = DNET_IO_CMD;
	st->rcv_size = sizeof(struct dnet_cmd);
	st->rcv_data = NULL;
	st->rcv_trans = NULL;
	st->rcv_offset = 0;
	return 0;
}

static int dnet_trans_forward(struct dnet_trans *t, struct dnet_net_state *st)
{
	int err;
	unsigned int size = t->cmd.size;
	struct dnet_node *n = st->n;

	err = dnet_wait_fd(st->s, POLLOUT, 0);
	if (err == -EINVAL)
		return err;

	dnet_convert_cmd(&t->cmd);

	dnet_req_set_header(&t->r, &t->cmd, sizeof(struct dnet_cmd), 0);
	dnet_req_set_data(&t->r, t->data, size, 0, 0);
	dnet_req_set_flags(&t->r, ~0, DNET_REQ_NO_DESTRUCT);

	dnet_log(n, DNET_LOG_INFO, "%s: forwarding to %s, trans: %llu.\n",
			dnet_dump_id(t->cmd.id),
			dnet_server_convert_dnet_addr(&st->addr),
			(unsigned long long)t->trans);

	return dnet_data_ready(st, &t->r);
}

void dnet_req_trans_destroy(struct dnet_data_req *r, int err __unused)
{
	struct dnet_trans *t = container_of(r, struct dnet_trans, r);

	if (!(t->cmd.flags & DNET_FLAGS_MORE))
		dnet_trans_put(t);
}

static void dnet_req_trans_destroy_forward(struct dnet_data_req *r, int err __unused)
{
	struct dnet_trans *t = container_of(r, struct dnet_trans, r);

	dnet_trans_put(t);
}

static int dnet_trans_exec(struct dnet_trans *t)
{
	int err = 0;

	if (t->cmd.flags & DNET_FLAGS_MORE) {
		struct timeval tv;

		gettimeofday(&tv, NULL);

		t->fire_time.tv_sec = tv.tv_sec;
		t->fire_time.tv_nsec = tv.tv_usec * 1000;
	}

	dnet_log(t->st->n, DNET_LOG_NOTICE, "%s: executing transaction %llu, reply: %d, complete: %p, r: %p.\n",
			dnet_dump_id(t->cmd.id), t->cmd.trans & ~DNET_TRANS_REPLY,
			!!(t->cmd.trans & DNET_TRANS_REPLY), t->complete, &t->r);

	if (t->complete) {
		t->complete(t->st, &t->cmd, t->data, t->priv);
		if (t->complete != (void *)dnet_req_trans_destroy_forward)
			t->st->rcv_flags |= DNET_IO_DROP;
	} else {
		dnet_req_set_complete(&t->r, dnet_req_trans_destroy_forward, NULL);
		err = dnet_trans_forward(t, t->st);
	}

	return err;
}

static struct dnet_trans *dnet_trans_new(struct dnet_net_state *st, uint64_t size)
{
	struct dnet_trans *t;

	t = dnet_trans_alloc(st->n, 0);
	if (!t)
		goto err_out_exit;

	if (size) {
		t->data = malloc(size);
		if (!t->data)
			goto err_out_free;
	}

	memcpy(&t->cmd, &st->rcv_cmd, sizeof(struct dnet_cmd));
	t->trans = t->recv_trans = t->cmd.trans;

	return t;

err_out_free:
	free(t);
err_out_exit:
	dnet_log(st->n, DNET_LOG_ERROR, "%s: failed to create new transaction, size: %llu.\n",
			dnet_dump_id(st->id), (unsigned long long)size);
	return NULL;
}

/*
 * We just have received a full command - schedule attached
 * data reading. First, we check if transaction is stored
 * for given command (it can only happen if command has
 * DNET_TRANS_REPLY bit set), in this case we try to reuse
 * its data buffer if it is big enough. If there is no
 * transaction or its buffer is too small, we allocate
 * a new one.
 */
static int dnet_schedule_data(struct dnet_net_state *st)
{
	struct dnet_node *n = st->n;
	struct dnet_trans *t = NULL;
	uint64_t size;
	int err;

	size = st->rcv_cmd.size;
	if (st->rcv_cmd.trans & DNET_TRANS_REPLY) {
		uint64_t tid = st->rcv_cmd.trans & ~DNET_TRANS_REPLY;

		dnet_lock_lock(&n->trans_lock);
		t = dnet_trans_search(&n->trans_root, tid);
		if (t && !(st->rcv_cmd.flags & DNET_FLAGS_MORE)) {
			dnet_trans_remove_nolock(&n->trans_root, t);
		}
		dnet_lock_unlock(&n->trans_lock);

		if (t) {
			uint64_t cmd_size = t->cmd.size;

			if (st->rcv_cmd.flags & DNET_FLAGS_MORE) {
				struct dnet_trans *nt;

				nt = dnet_trans_new(st, size);
				if (!nt) {
					err = -ENOMEM;
					goto err_out_put;
				}

				nt->cmd.trans = t->recv_trans | DNET_TRANS_REPLY;
				nt->trans = t->trans;
				nt->recv_trans = t->recv_trans;
				nt->priv = t->priv;
				nt->complete = t->complete;
				nt->st = dnet_state_get(t->st);

				dnet_trans_put(t);
				t = nt;
			} else {
				memcpy(&t->cmd, &st->rcv_cmd, sizeof(struct dnet_cmd));
				t->cmd.trans = t->recv_trans | DNET_TRANS_REPLY;

				/*
				 * This transaction can not be found in the node's tree anymore,
				 * so it can not be accessed through cleanup thread.
				 * Since we grabbed a reference to this transaction during search,
				 * it is safe to drop it here so that subsequent put will destroy
				 * this transaction.
				 */
				dnet_trans_put(t);

				if (!size) {
					err = dnet_trans_exec(t);
					if (err)
						goto err_out_put;

					if (st->rcv_flags & DNET_IO_DROP)
						dnet_trans_put(t);
					return dnet_schedule_command(st);
				}

				if (size > cmd_size) {
					free(t->data);
					t->data = malloc(size);
					if (!t->data) {
						err = -ENOMEM;
						goto err_out_put;
					}
				}
			}
		} else {
			dnet_log(n, DNET_LOG_ERROR, "%s: could not find transaction for "
					"the reply %llu, dropping.\n",
					dnet_dump_id(st->rcv_cmd.id), (unsigned long long)tid);
			st->rcv_flags |= DNET_IO_DROP;
		}
	}

	if (!t) {
		t = dnet_trans_new(st, size);
		if (!t) {
			err = -ENOMEM;
			goto err_out_exit;
		}
	}

	st->rcv_trans = t;
	st->rcv_flags &= ~DNET_IO_CMD;
	st->rcv_offset = 0;
	st->rcv_size = size;
	st->rcv_data = t->data;
	return 0;

err_out_put:
	dnet_trans_put(t);
err_out_exit:
	dnet_log(st->n, DNET_LOG_ERROR, "%s: schedule data size: %llu, error: %d.\n",
			dnet_dump_id(st->rcv_cmd.id),
			(unsigned long long)st->rcv_cmd.size, err);
	return err;
}

int dnet_add_reconnect_state(struct dnet_node *n, struct dnet_addr *addr, unsigned int join_state)
{
	struct dnet_addr_storage *a, *it;
	int err = 0;

	if (!join_state)
		goto out_exit;

	a = malloc(sizeof(struct dnet_addr_storage));
	if (!a) {
		err = -ENOMEM;
		goto out_exit;
	}

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

static int dnet_process_trans_new(struct dnet_trans *t, struct dnet_net_state *st)
{
	struct dnet_node *n = st->n;
	int err = 0;
	struct dnet_net_state *tmp;

	t->st = dnet_state_get_first(n, t->cmd.id, NULL);

	dnet_log(n, DNET_LOG_INFO, "%s: processing new transaction: st: %p, t_st: %p, n_st: %p, "
			"direct: %d, flags: %x/%x.\n",
			dnet_dump_id(st->rcv_cmd.id), st, t->st, n->st,
			(st->rcv_cmd.flags & DNET_FLAGS_DIRECT),
			st->rcv_cmd.flags, t->cmd.flags);

	if (!t->st || t->st == st || t->st == n->st ||
			(st->rcv_cmd.flags & DNET_FLAGS_DIRECT)) {
		dnet_state_put(t->st);
		t->st = dnet_state_get(st);

		dnet_process_cmd(t);
		return 0;
	}

	tmp = t->st;
	t->st = dnet_state_get(st);

	err = dnet_trans_insert(t);
	if (err)
		goto err_out_put;

	t->recv_trans = t->cmd.trans;
	t->cmd.trans = t->trans;

	err = dnet_trans_forward(t, tmp);
	if (err)
		goto err_out_put;

	dnet_state_put(tmp);
	return 0;

err_out_put:
	dnet_state_put(tmp);
	dnet_log(n, DNET_LOG_ERROR, "%s: failed to process new transaction %llu: %d.\n",
			dnet_dump_id(t->cmd.id), (unsigned long long)t->cmd.trans, err);
	return err;
}

static int dnet_process_recv_trans(struct dnet_trans *t, struct dnet_net_state *st)
{
	int err;

	if (!(st->rcv_flags & DNET_IO_DROP)) {
		if (t->cmd.trans & DNET_TRANS_REPLY) {
			err = dnet_trans_exec(t);
			if (err)
				goto err_out_destroy;
		} else {
			err = dnet_process_trans_new(t, st);
			if (err)
				goto err_out_destroy;
		}
	}

	if (st->rcv_flags & DNET_IO_DROP)
		dnet_trans_put(t);

	return 0;

err_out_destroy:
	dnet_log(st->n, DNET_LOG_ERROR, "%s: process recv trans %llu, reply: %d, error: %d.\n",
			dnet_dump_id(t->cmd.id), (t->cmd.trans & ~DNET_TRANS_REPLY),
			!!(t->cmd.trans & DNET_TRANS_REPLY), err);
	dnet_trans_put(t);
	return err;
}

static int dnet_process_recv_single(struct dnet_net_state *st)
{
	struct dnet_node *n = st->n;
	void *data;
	uint64_t size;
	struct dnet_trans *t;
	int err;

	dnet_log(n, DNET_LOG_DSA, "%s: receiving: cmd: %d, size: %llu, offset: %llu.\n",
		dnet_dump_id(st->id), !!(st->rcv_flags & DNET_IO_CMD),
		(unsigned long long)st->rcv_size, (unsigned long long)st->rcv_offset);

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

			dnet_log(n, DNET_LOG_DSA, "%s: no data.\n", dnet_dump_id(st->id));
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

	dnet_log(n, DNET_LOG_DSA, "%s: receiving: offset: %llu, size: %llu, flags: %x.\n",
			dnet_dump_id(st->id),
			(unsigned long long)st->rcv_offset, (unsigned long long)st->rcv_size,
			st->rcv_flags);

	if (st->rcv_offset != st->rcv_size)
		goto again;

	if (st->rcv_flags & DNET_IO_CMD) {
		unsigned long long tid;
		struct dnet_cmd *c = &st->rcv_cmd;

		dnet_convert_cmd(&st->rcv_cmd);

		tid = c->trans & ~DNET_TRANS_REPLY;

		dnet_log(n, DNET_LOG_NOTICE, "%s: received trans: %llu, reply: %d, size: %llu, "
				"flags: %u.\n",
				dnet_dump_id(c->id), tid, tid != c->trans,
				(unsigned long long)c->size, c->flags);
		err = dnet_schedule_data(st);
		if (err)
			goto out;

		/*
		 * We read the command header, now get the data.
		 */
		goto again;
	}

	t = st->rcv_trans;

	err = dnet_process_recv_trans(t, st);
	if (err)
		goto out;

	dnet_schedule_command(st);

out:
	return err;
}

static int dnet_process_send_single(struct dnet_net_state *st)
{
	struct dnet_node *n = st->n;
	struct dnet_data_req *r = NULL;
	struct dnet_trans *t = NULL;
	int err = 0;

	dnet_lock_lock(&n->trans_lock);
	if (!list_empty(&st->snd_list))
		r = list_first_entry(&st->snd_list, struct dnet_data_req, req_entry);

	if (!r) {
		err = -ENOENT;
		dnet_log(n, DNET_LOG_DSA, "%s: empty send queue.\n", dnet_dump_id(st->id));
		dnet_lock_unlock(&n->trans_lock);

		goto err_out_exit;
	}

	list_del_init(&r->req_entry);

	if (r->flags & DNET_REQ_NO_DESTRUCT) {
		t = container_of(r, struct dnet_trans, r);
		dnet_trans_get(t);
	}
	dnet_lock_unlock(&n->trans_lock);

	dnet_log(n, DNET_LOG_DSA, "%s: req: %p, hsize: %llu, dsize: %llu, fsize: %llu.\n",
			dnet_dump_id(st->id), r, (unsigned long long)r->hsize,
			(unsigned long long)r->dsize, (unsigned long long)r->size);

	if (!st->snd_size) {
		st->snd_offset = 0;
		st->snd_size = 0;

		st->hsize = st->dsize = st->fsize = st->foffset = 0;

		if (r->header) {
			st->snd_size += r->hsize;
			st->hsize = r->hsize;
		}
		if (r->data) {
			st->snd_size += r->dsize;
			st->dsize = r->dsize;
		}
		if (r->fd >= 0) {
			st->snd_size += r->size;
			st->fsize = r->size;
			st->foffset = r->offset;
		}
	}

	while (st->snd_size) {
		unsigned long long *size = NULL;
		void *data = NULL;
		err = -EINVAL;

		if (st->hsize) {
			size = &st->hsize;
			data = r->header;
		} else if (st->dsize) {
			size = &st->dsize;
			data = r->data + r->doff;
		} else if (st->fsize) {
			size = &st->fsize;
			data = NULL;
		}

		if (data)
			data += st->snd_offset;

		if (!size) {
			dnet_log(n, DNET_LOG_ERROR, "%s: snd_size: %llu, fd: %d.\n",
					dnet_dump_id(st->id),
					st->snd_size, r->fd);
		}

		if (data) {
			err = send(st->s, data, *size, 0);
		} else if (r->fd >= 0) {
			/*
			 * A little bit dirty, but we want to shut up 64bit compilers, which
			 * will not believe that long long is actually unt64_t there.
			 */
			err = dnet_sendfile(st, r->fd, (uint64_t *)(void *)&st->foffset, *size);
		}
		
		dnet_log(n, DNET_LOG_DSA, "%s: sent: data: %p, %d/%llu.\n",
				dnet_dump_id(st->id), data, err, *size);

		if (err < 0) {
			err = -EAGAIN;
			if (errno != EAGAIN && errno != EINTR) {
				err = -errno;
				dnet_log_err(n, "failed to send %llu bytes", *size);
				goto err_out_put_back;
			}

			dnet_log(n, DNET_LOG_DSA, "%s: again.\n", dnet_dump_id(st->id));
			goto err_out_put_back;
		}

		if (err == 0) {
			err = -ECONNRESET;
			dnet_log(n, DNET_LOG_ERROR, "%s: node dropped connection.\n",
					dnet_dump_id(st->id));
			goto err_out_put_back;
		}

		dnet_log(n, DNET_LOG_DSA, "%s: sent: %d/%llu.\n",
				dnet_dump_id(st->id), err, *size);

		*size -= err;
		if (data)
			data += err;
		st->snd_size -= err;
		st->snd_offset += err;

		if (*size == 0)
			st->snd_offset = 0;

		err = 0;
	}

	dnet_log(n, DNET_LOG_DSA, "%s: destroying send request: %p: "
			"flags: %x, hsize: %llu/%llu, dsize: %llu/%llu, fsize: %llu/%llu, complete: %p.\n",
			dnet_dump_id(st->id), r, r->flags,
			st->hsize, (unsigned long long)r->hsize,
			st->dsize, (unsigned long long)r->dsize,
			st->fsize, (unsigned long long)r->size, r->complete);

	dnet_req_destroy(r, 0);

	if (t)
		dnet_trans_put(t);
	return 0;

err_out_put_back:
	dnet_lock_lock(&n->trans_lock);
	list_add(&r->req_entry, &st->snd_list);
	dnet_lock_unlock(&n->trans_lock);

err_out_exit:
	if (t)
		dnet_trans_put(t);
	return err;
}

static void dnet_process_socket(int s __unused, short event, void *arg)
{
	struct dnet_net_state *st = arg;
	short mask = EV_READ;
	int err = -EINVAL, can_write, can_read;

	dnet_log(st->n, DNET_LOG_DSA, "%s: processing event: %p, mask: %x.\n",
			dnet_dump_id(st->id), &st->event, event);

	if (list_empty(&st->state_entry))
		goto err_out_destroy;

	do {
		can_write = can_read = 0;
		if (event & EV_WRITE) {
			err = dnet_process_send_single(st);
			switch (err) {
				case -ENOENT:
					break;
				case -EAGAIN:
					break;
				case 0:
					if (!list_empty(&st->snd_list))
						can_write = 1;
					break;
				default:
					goto err_out_destroy;
			}
		}

		if ((event & EV_READ) && (st->req_pending < st->n->max_pending)) {
			err = dnet_process_recv_single(st);
			switch (err) {
				case -EAGAIN:
					break;
				case 0:
					if (list_empty(&st->snd_list))
						can_read = 1;
					break;
				default:
					goto err_out_destroy;
			}
		}
	} while (can_write || can_read);

	if (!list_empty(&st->snd_list))
		mask |= EV_WRITE;

	dnet_event_schedule(st, mask);

	return;

err_out_destroy:
	event_del(&st->event);

	dnet_state_remove(st);

	dnet_add_reconnect_state(st->n, &st->addr, st->__join_state);
	while (!list_empty(&st->snd_list)) {
		struct dnet_data_req *r = NULL;

		dnet_lock_lock(&st->n->trans_lock);
		if (!list_empty(&st->snd_list)) {
			r = list_first_entry(&st->snd_list, struct dnet_data_req, req_entry);
			list_del_init(&r->req_entry);
		}
		dnet_lock_unlock(&st->n->trans_lock);

		if (!r)
			break;

		dnet_req_destroy(r, err);
	}
	dnet_log(st->n, DNET_LOG_NOTICE, "%s: refcnt: %d.\n", dnet_dump_id(st->id), atomic_read(&st->refcnt));
	dnet_state_put(st);
}

int dnet_event_schedule(struct dnet_net_state *st, short mask)
{
	void *base = st->event.ev_base;
	struct timeval tv;
	int err;

	tv.tv_sec = st->n->wait_ts.tv_sec;
	tv.tv_usec = st->n->wait_ts.tv_nsec * 1000;

	event_del(&st->event);

	event_set(&st->event, st->s, mask, dnet_process_socket, st);
	event_base_set(base, &st->event);
	err = event_add(&st->event, &tv);
	//err = event_add(&st->event, NULL);

	dnet_log(st->n, DNET_LOG_DSA, "%s: queued event: %p, mask: %x, err: %d, empty: %d.\n",
			dnet_dump_id(st->id), &st->event, mask, err,
			list_empty(&st->snd_list));

	return err;
}

static void dnet_accept_client(int s, short event __unused, void *arg)
{
	struct dnet_net_state *orig = arg;
	struct dnet_node *n = orig->n;
	struct dnet_net_state *st;
	struct dnet_addr addr;
	int cs, err;

	dnet_log(n, DNET_LOG_DSA, "%s: accepting client on event %x.\n", dnet_dump_id(orig->id), event);

	addr.addr_len = sizeof(addr.addr);
	cs = accept(s, (struct sockaddr *)&addr.addr, &addr.addr_len);
	if (cs <= 0) {
		err = -errno;
		dnet_log_err(n, "failed to accept new client");
		goto err_out_exit;
	}

	fcntl(cs, F_SETFL, O_NONBLOCK);
	
	st = dnet_state_create(n, NULL, &addr, cs);
	if (!st)
		goto err_out_close;

	dnet_log(n, DNET_LOG_INFO, "%s: accepted client %s, socket: %d.\n", dnet_dump_id(n->id),
			dnet_server_convert_dnet_addr(&addr), cs);

	return;

err_out_close:
	close(cs);
err_out_exit:
	return;
}

int dnet_schedule_socket(struct dnet_net_state *st)
{
	int err;
	struct dnet_node *n = st->n;

	if (st->s == n->listen_socket) {
		event_set(&st->event, st->s, EV_READ | EV_PERSIST, dnet_accept_client, st);
		event_base_set(st->th->base, &st->event);
		err = event_add(&st->event, NULL);
	} else {
		event_set(&st->event, st->s, EV_READ, dnet_process_socket, st);
		event_base_set(st->th->base, &st->event);
		err = dnet_event_schedule(st, EV_READ);
	}

	return err;
}

static int dnet_schedule_state(struct dnet_net_state *st)
{
	struct dnet_node *n = st->n;
	struct dnet_io_thread *t, *th = NULL;
	int pos = 0, err;

	pthread_rwlock_rdlock(&n->io_thread_lock);
	list_for_each_entry(t, &n->io_thread_list, thread_entry) {
		if (pos == n->io_thread_pos) {
			n->io_thread_pos++;
			if (n->io_thread_pos == n->io_thread_num)
				n->io_thread_pos = 0;
			th = t;
			break;
		}

		pos++;
		if (pos == n->io_thread_num)
			pos = 0;
	}
	pthread_rwlock_unlock(&n->io_thread_lock);

	if (!th) {
		dnet_log(n, DNET_LOG_ERROR, "%s: can not find IO thread.\n",
				dnet_dump_id(n->id));
		err = -ENOENT;
		goto err_out_exit;
	}

	/*
	 * Starting from reading a command.
	 */
	dnet_schedule_command(st);

	st->th = th;

	return 0;

err_out_exit:
	return err;
}

struct dnet_net_state *dnet_state_create(struct dnet_node *n, unsigned char *id,
		struct dnet_addr *addr, int s)
{
	int err = -ENOMEM;
	struct dnet_net_state *st;

	st = malloc(sizeof(struct dnet_net_state));
	if (!st)
		goto err_out_exit;

	memset(st, 0, sizeof(struct dnet_net_state));

	st->timeout = n->wait_ts.tv_sec * 1000;
	st->s = s;
	st->n = n;

	if (id)
		memcpy(st->id, id, DNET_ID_SIZE);

	atomic_init(&st->refcnt, 1);

	INIT_LIST_HEAD(&st->snd_list);

	memcpy(&st->addr, addr, sizeof(struct dnet_addr));

	err = dnet_schedule_state(st);
	if (err) {
		dnet_log_err(n, "%s: failed to schedule state: %d", dnet_dump_id(st->id), err);
		goto err_out_state_free;
	}

	if (!id) {
		pthread_rwlock_wrlock(&n->state_lock);
		list_add_tail(&st->state_entry, &n->empty_state_list);
		pthread_rwlock_unlock(&n->state_lock);
	} else {
		err = dnet_state_insert(st);
		if (err)
			goto err_out_state_free;
	}

	err = dnet_signal_thread(st, DNET_THREAD_SCHEDULE);
	if (err) {
		dnet_log_err(n, "%s: failed to signal thread: %d", dnet_dump_id(st->id), err);
		goto err_out_state_remove;
	}

	return st;

err_out_state_remove:
	dnet_state_remove(st);
err_out_state_free:
	free(st);
err_out_exit:
	return NULL;
}

int dnet_state_num(struct dnet_node *n)
{
	struct dnet_net_state *st;
	int num = 0;

	pthread_rwlock_rdlock(&n->state_lock);
	list_for_each_entry(st, &n->state_list, state_entry)
		num++;
	pthread_rwlock_unlock(&n->state_lock);

	return num;
}

int dnet_sendfile_data(struct dnet_net_state *st,
		int fd, uint64_t offset, uint64_t size,
		void *header, unsigned int hsize)
{
	int err;

	err = dnet_send(st, header, hsize);
	if (err)
		goto err_out_unlock;

	while (size) {
		err = dnet_wait_fd(st->s, POLLOUT, st->timeout);
		if (st->n->need_exit) {
			err = -EIO;
			break;
		}

		if (err == -EAGAIN || err == -EINTR)
			continue;

		if (err < 0) {
			dnet_log(st->n, DNET_LOG_ERROR, "Failed to wait for descriptor: "
					"err: %d, socket: %d.\n", err, st->s);
			break;
		}

		err = dnet_sendfile(st, fd, &offset, size);
		if (err < 0) {
			if (err == -EAGAIN)
				continue;
			dnet_log_err(st->n, "%s: failed to send file data, err: %d",
					dnet_dump_id(st->id), err);
			goto err_out_unlock;
		}

		if (err == 0) {
			dnet_log(st->n, DNET_LOG_INFO, "%s: looks like truncated file, "
					"size: %llu.\n", dnet_dump_id(st->id),
					(unsigned long long)size);
			break;
		}

		dnet_log(st->n, DNET_LOG_NOTICE, "%s: size: %llu, rest: %llu, offset: %llu, err: %d.\n",
				dnet_dump_id(st->id), (unsigned long long)size,
				(unsigned long long)size-err, (unsigned long long)offset, err);

		size -= err;
	}

	if (size) {
		char buf[4096];
		unsigned int sz;

		memset(buf, 0, sizeof(buf));

		dnet_log(st->n, DNET_LOG_INFO, "%s: truncated file, orig: %llu, zeroes: %llu bytes.\n",
				dnet_dump_id(st->id), (unsigned long long)size + err,
				(unsigned long long)size);

		while (size) {
			sz = size;
			if (sz > sizeof(buf))
				sz = sizeof(buf);

			err = dnet_send(st, buf, sz);
			if (err)
				goto err_out_unlock;

			size -= sz;
		}
	}

	return 0;

err_out_unlock:
	return err;
}

void dnet_state_destroy(struct dnet_net_state *st)
{
	dnet_state_remove(st);

	event_del(&st->event);

	if (st->s >= 0)
		close(st->s);

	dnet_log(st->n, DNET_LOG_NOTICE, "%s: freeing state %s, socket: %d.\n",
		dnet_dump_id(st->id), dnet_server_convert_dnet_addr(&st->addr), st->s);

	free(st);
}

int dnet_send_reply(void *state, struct dnet_cmd *cmd, struct dnet_attr *attr,
		void *odata, unsigned int size, int more)
{
	struct dnet_net_state *st = state;
	struct dnet_cmd *c;
	struct dnet_attr *a;
	struct dnet_data_req *r;
	void *data;

	r = dnet_req_alloc(st, sizeof(struct dnet_cmd) +
			sizeof(struct dnet_attr) + size);
	if (!r)
		return -ENOMEM;

	c = dnet_req_header(r);
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

	dnet_log(st->n, DNET_LOG_INFO, "%s: sending %u reply, size: %u, cflags: %x.\n",
		dnet_dump_id(cmd->id), a->cmd, size, c->flags);

	dnet_convert_cmd(c);
	dnet_convert_attr(a);

	return dnet_data_ready(st, r);
}
