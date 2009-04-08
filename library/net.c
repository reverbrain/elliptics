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
#include "dnet/packet.h"
#include "dnet/interface.h"

int dnet_socket_create_addr(struct dnet_node *n, int sock_type, int proto,
		struct sockaddr *sa, unsigned int salen, int listening)
{
	int s, err = -1;

	s = socket(sa->sa_family, sock_type, proto);
	if (s < 0) {
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
			dnet_log_err(n, "Failed to bind to %s:%d",
				dnet_server_convert_addr(sa, salen),
				dnet_server_convert_port(sa, salen));
			goto err_out_close;
		}

		err = listen(s, 1024);
		if (err) {
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
			dnet_log_err(n, "Failed to connect to %s:%d",
				dnet_server_convert_addr(sa, salen),
				dnet_server_convert_port(sa, salen));
			goto err_out_close;
		}

		dnet_log(n, DNET_LOG_INFO, "Connected to %s:%d.\n",
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

	hint.ai_flags = AI_NUMERICSERV;
	hint.ai_family = cfg->family;
	hint.ai_socktype = cfg->sock_type;
	hint.ai_protocol = cfg->proto;

	err = getaddrinfo(cfg->addr, cfg->port, &hint, &ai);
	if (err) {
		dnet_log(n, DNET_LOG_ERROR, "Failed to get address info for %s:%s, family: %d, err: %d.\n",
				cfg->addr, cfg->port, cfg->family, err);
		goto err_out_exit;
	}

	s = dnet_socket_create_addr(n, cfg->sock_type, cfg->proto,
			ai->ai_addr, ai->ai_addrlen, listening);
	if (s < 0) {
		err = -1;
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

static int dnet_net_reconnect(struct dnet_net_state *st)
{
	int err;

	if (st->join_state == DNET_CLIENT)
		return -EINVAL;

	err = dnet_socket_create_addr(st->n, st->n->sock_type, st->n->proto,
			(struct sockaddr *)&st->addr, st->addr.addr_len, 0);
	if (err < 0)
		return err;

	if (st->s > 0)
		close(st->s);
	st->s = err;

	st->join_state = DNET_REJOIN;
	st->n->join_state = DNET_REJOIN;

	return 0;
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
			dnet_log(st->n, DNET_LOG_NOTICE, "Peer has disconnected.\n");
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

	dnet_convert_cmd(&t->cmd);

	dnet_req_set_header(&t->r, &t->cmd, sizeof(struct dnet_cmd), 0);
	dnet_req_set_data(&t->r, t->data, size, 0);
	dnet_req_set_flags(&t->r, ~0, DNET_REQ_NO_DESTRUCT);

	dnet_log(n, DNET_LOG_INFO, "%s: forwarding to %s, trans: %llu.\n",
			dnet_dump_id(t->cmd.id),
			dnet_server_convert_dnet_addr(&st->addr),
			(unsigned long long)t->trans);

	err = dnet_data_ready(st, &t->r);

	return err;
}

static void dnet_req_trans_destroy(struct dnet_data_req *r)
{
	struct dnet_trans *t = container_of(r, struct dnet_trans, r);

	if (!(t->cmd.flags & DNET_FLAGS_MORE))
		dnet_trans_destroy(t);
}

static int dnet_trans_exec(struct dnet_trans *t)
{
	int err;

	if (t->complete) {
		err = t->complete(t->st, &t->cmd, t->data, t->priv);
	} else {
		t->r.complete = dnet_req_trans_destroy;
		err = dnet_trans_forward(t, t->st);
		if (!err)
			return 0;
	}

	if (!(t->cmd.flags & DNET_FLAGS_MORE))
		dnet_trans_destroy(t);

	return err;
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

		pthread_mutex_lock(&n->trans_lock);
		t = dnet_trans_search(&n->trans_root, tid);
		if (t && !(st->rcv_cmd.flags & DNET_FLAGS_MORE)) {
			dnet_trans_remove_nolock(&n->trans_root, t);
		}
		pthread_mutex_unlock(&n->trans_lock);

		if (t) {
			uint64_t cmd_size = t->cmd.size;

			memcpy(&t->cmd, &st->rcv_cmd, sizeof(struct dnet_cmd));
			t->cmd.trans = t->recv_trans | DNET_TRANS_REPLY;

			if (!size) {
				err = dnet_trans_exec(t);
				if (err)
					goto err_out_exit;

				return dnet_schedule_command(st);
			}

			if (size > cmd_size) {
				free(t->data);
				t->data = malloc(size);
				if (!t->data) {
					err = -ENOMEM;
					goto err_out_exit;
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
		t = dnet_trans_alloc(n, 0);
		if (!t) {
			err = -ENOMEM;
			goto err_out_exit;
		}
		memset(t, 0, sizeof(struct dnet_trans));

		if (size) {
			t->data = malloc(size);
			if (!t->data) {
				err = -ENOMEM;
				goto err_out_exit;
			}
		}

		memcpy(&t->cmd, &st->rcv_cmd, sizeof(struct dnet_cmd));
		t->trans = t->cmd.trans;
	}

	st->rcv_trans = t;
	st->rcv_flags &= ~DNET_IO_CMD;
	st->rcv_offset = 0;
	st->rcv_size = size;
	st->rcv_data = t->data;
	return 0;

err_out_exit:
	return err;
}

static int dnet_process_recv_trans(struct dnet_trans *t, struct dnet_net_state *st)
{
	int err;
	struct dnet_node *n = st->n;

	if (!(st->rcv_flags & DNET_IO_DROP)) {
		if (st->rcv_cmd.trans & DNET_TRANS_REPLY) {
			err = dnet_trans_exec(t);
			if (err)
				goto err_out_destroy;
		} else {
			t->st = dnet_state_search(n, st->rcv_cmd.id, NULL);

			if (!t->st || t->st == st || t->st == n->st) {
				dnet_state_put(t->st);
				t->st = dnet_state_get(st);

				dnet_process_cmd(t);
				st->rcv_flags |= DNET_IO_DROP;
			} else {
				struct dnet_net_state *tmp = t->st;

				t->st = dnet_state_get(st);

				err = dnet_trans_insert(t);
				if (err) {
					dnet_state_put(tmp);
					goto err_out_destroy;
				}

				t->recv_trans = t->cmd.trans;
				t->cmd.trans = t->trans;
				err = dnet_trans_forward(t, tmp);
				dnet_state_put(tmp);

				if (err)
					goto err_out_destroy;
			}
		}
	}
	
	if (st->rcv_flags & DNET_IO_DROP)
		dnet_trans_destroy(t);

	return 0;

err_out_destroy:
	dnet_trans_destroy(t);
	return err;
}

static int dnet_process_recv_single(struct dnet_net_state *st)
{
	struct dnet_node *n = st->n;
	void *data;
	size_t size;
	struct dnet_trans *t;
	int err;

	dnet_log(n, DNET_LOG_NOTICE, "%s: receiving: cmd: %d, size: %zu, offset: %zu.\n",
		dnet_dump_id(st->id), !!(st->rcv_flags & DNET_IO_CMD),
		st->rcv_size, (size_t)st->rcv_offset);

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
				dnet_log_err(n, "failed to receive data");
				goto out;
			}

			dnet_log(n, DNET_LOG_NOTICE, "%s: no data.\n", dnet_dump_id(st->id));
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

	dnet_log(n, DNET_LOG_NOTICE, "%s: receiving: offset: %zu, size: %zu, flags: %x.\n",
			dnet_dump_id(st->id), (size_t)st->rcv_offset, st->rcv_size, st->rcv_flags);

	/*
	 * Looks weird, but that's a reality - offset and size are very different types on some platforms.
	 */
	if ((ssize_t)st->rcv_offset != (ssize_t)st->rcv_size)
		goto again;

	if (st->rcv_flags & DNET_IO_CMD) {
		unsigned long long tid;
		struct dnet_cmd *c = &st->rcv_cmd;

		dnet_convert_cmd(&st->rcv_cmd);

		tid = c->trans & ~DNET_TRANS_REPLY;

		dnet_log(n, DNET_LOG_NOTICE, "%s: size: %llu, flags: %u, trans: %llu, reply: %d.\n",
				dnet_dump_id(c->id), (unsigned long long)c->size, c->flags,
				tid, !!(c->trans & DNET_TRANS_REPLY));
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
	int err = 0;

	if (!list_empty(&st->snd_list))
		r = list_first_entry(&st->snd_list, struct dnet_data_req, req_entry);

	if (!r) {
		err = -ENOENT;
		dnet_log(n, DNET_LOG_NOTICE, "%s: empty send queue.\n", dnet_dump_id(st->id));
		goto out;
	}
#if 1
	dnet_log(n, DNET_LOG_NOTICE, "%s: req: %p, hsize: %zu, dsize: %zu, fsize: %zu.\n",
			dnet_dump_id(st->id), r, r->hsize, r->dsize, r->size);
#endif
	if (!st->snd_size) {
		st->snd_offset = 0;
		st->snd_size = 0;

		if (r->header)
			st->snd_size += r->hsize;
		if (r->data)
			st->snd_size += r->dsize;
		if (r->fd >= 0)
			st->snd_size += r->size;
	}

	while (st->snd_size) {
		size_t *size = NULL;
		void *data = NULL;
		err = -EINVAL;

		if (r->hsize) {
			size = &r->hsize;
			data = r->header;
		} else if (r->dsize) {
			size = &r->dsize;
			data = r->data;
		} else if (r->fd >= 0) {
			size = &r->size;
			data = NULL;
		}

		if (data)
			data += st->snd_offset;

		if (!size) {
			dnet_log(n, DNET_LOG_ERROR, "%s: snd_size: %zu, fd: %d.\n",
					dnet_dump_id(st->id), st->snd_size, r->fd);
		}

		if (data) {
			err = send(st->s, data, *size, 0);
		} else if (r->fd >= 0) {
			err = dnet_sendfile(st, r->fd, &r->offset, *size);
		}

		if (err < 0) {
			err = -EAGAIN;
			if (errno != EAGAIN && errno != EINTR) {
				err = -errno;
				dnet_log_err(n, "failed to send %zu bytes", *size);
				goto out;
			}

			dnet_log(n, DNET_LOG_NOTICE, "%s: again.\n", dnet_dump_id(st->id));
			goto out;
		}

		if (err == 0) {
			err = -ECONNRESET;
			dnet_log(n, DNET_LOG_ERROR, "%s: node dropped connection.\n",
					dnet_dump_id(st->id));
			goto out;
		}

		dnet_log(n, DNET_LOG_NOTICE, "%s: sent: %d/%zu.\n", dnet_dump_id(st->id), err, *size);

		*size -= err;
		if (data)
			data += err;
		st->snd_size -= err;
		st->snd_offset += err;

		if (*size == 0)
			st->snd_offset = 0;

		err = 0;
	}

	pthread_mutex_lock(&st->snd_lock);
	list_del(&r->req_entry);
	pthread_mutex_unlock(&st->snd_lock);

	dnet_log(n, DNET_LOG_NOTICE, "%s: freeing send request: %p: "
			"flags: %x, hsize: %zu, dsize: %zu, fsize: %zu.\n",
			dnet_dump_id(st->id), r, r->flags, r->hsize, r->dsize, r->size);

	dnet_req_destroy(r);

out:
	return err;
}

static void dnet_process_socket(int s __unused, short event, void *arg)
{
	struct dnet_net_state *st = arg;
	short mask = EV_READ;
	int err, can_write, can_read;

	dnet_log(st->n, DNET_LOG_NOTICE, "%s: processing event: %p, mask: %x.\n",
			dnet_dump_id(st->id), &st->event, event);

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

	dnet_state_get(st);
	if (!list_empty(&st->state_entry)) {
		dnet_state_remove(st);
		dnet_state_put(st);
	}
	while (!list_empty(&st->snd_list)) {
		struct dnet_data_req *r = NULL;

		pthread_mutex_lock(&st->snd_lock);
		if (!list_empty(&st->snd_list)) {
			r = list_first_entry(&st->snd_list, struct dnet_data_req, req_entry);
			list_del(&r->req_entry);
		}
		pthread_mutex_unlock(&st->snd_lock);

		if (!r)
			break;

		/*
		 * Note, that this can kill the last reference to the state,
		 * so we increase state's reference counter above and drop it
		 * below, so that structure members access (like st->snd_list)
		 * would not fault.
		 */
		dnet_req_destroy(r);
	}
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

	dnet_log(st->n, DNET_LOG_NOTICE, "%s: queued event: %p, mask: %x, err: %d, empty: %d.\n",
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

	dnet_log(n, DNET_LOG_NOTICE, "%s: accepting client on event %x.\n", dnet_dump_id(orig->id), event);

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

	dnet_log(n, DNET_LOG_INFO, "%s: accepted client %s.\n", dnet_dump_id(n->id),
			dnet_server_convert_dnet_addr(&addr));

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

	pthread_mutex_lock(&n->io_thread_lock);
	list_for_each_entry(t, &n->io_thread_list, thread_entry) {
		if (pos == n->io_thread_pos) {
			n->io_thread_pos++;
			n->io_thread_pos %= n->io_thread_num;
			th = t;
			break;
		}

		pos++;
		pos %= n->io_thread_num;
	}
	pthread_mutex_unlock(&n->io_thread_lock);

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

	st->n = n;
	st->th = th;

	err = dnet_signal_thread(st, DNET_THREAD_SCHEDULE);
	if (err)
		goto err_out_exit;

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
	st->refcnt = 1;

	INIT_LIST_HEAD(&st->snd_list);

	memcpy(&st->addr, addr, sizeof(struct dnet_addr));
	
	err = pthread_mutex_init(&st->snd_lock, NULL);
	if (err) {
		dnet_log_err(n, "%s: failed to initialize sending queu: err: %d",
				dnet_dump_id(st->id), err);
		goto err_out_state_free;
	}

	err = pthread_mutex_init(&st->refcnt_lock, NULL);
	if (err) {
		dnet_log_err(n, "%s: failed to initialize state refcnt lock: err: %d",
				dnet_dump_id(st->id), err);
		goto err_out_snd_lock_destroy;
	}

	st->join_state = DNET_CLIENT;
	if (!id) {
		pthread_mutex_lock(&n->state_lock);
		list_add_tail(&st->state_entry, &n->empty_state_list);
		pthread_mutex_unlock(&n->state_lock);
	} else {
		memcpy(st->id, id, DNET_ID_SIZE);
		err = dnet_state_insert(st);
		if (err)
			goto err_out_refcnt_lock_destroy;
	}

	err = dnet_schedule_state(st);
	if (err)
		goto err_out_state_remove;

	return st;

err_out_state_remove:
	dnet_state_remove(st);
err_out_refcnt_lock_destroy:
	pthread_mutex_destroy(&st->refcnt_lock);
err_out_snd_lock_destroy:
	pthread_mutex_destroy(&st->snd_lock);
err_out_state_free:
	free(st);
err_out_exit:
	return NULL;
}

void dnet_state_put(struct dnet_net_state *st)
{
	int destroy = 0;

	if (!st)
		return;
	
	pthread_mutex_lock(&st->refcnt_lock);
	st->refcnt--;

	if (st->refcnt == 0)
		destroy = 1;
	pthread_mutex_unlock(&st->refcnt_lock);

	if (!destroy)
		return;

	dnet_state_remove(st);

	event_del(&st->event);

	if (st->s)
		close(st->s);

	pthread_mutex_destroy(&st->snd_lock);
	pthread_mutex_destroy(&st->refcnt_lock);

	dnet_log(st->n, DNET_LOG_ERROR, "%s: freeing state %s.\n", dnet_dump_id(st->id),
		dnet_server_convert_dnet_addr(&st->addr));

	free(st);
}

int dnet_sendfile_data(struct dnet_net_state *st,
		int fd, off_t offset, size_t size,
		void *header, unsigned int hsize)
{
	ssize_t err;

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
					"err: %zd, socket: %d.\n", err, st->s);
			break;
		}

		err = dnet_sendfile(st, fd, &offset, size);
		if (err < 0) {
			if (err == -EAGAIN)
				continue;
			dnet_log_err(st->n, "%s: failed to send file data, err: %zd",
					dnet_dump_id(st->id), err);
			goto err_out_unlock;
		}

		if (err == 0) {
			dnet_log(st->n, DNET_LOG_INFO, "%s: looks like truncated file, "
					"size: %zu.\n", dnet_dump_id(st->id), size);
			break;
		}

		dnet_log(st->n, DNET_LOG_NOTICE, "%s: size: %zu, rest: %zu, offset: %llu, err: %zd.\n",
				dnet_dump_id(st->id), size, size-err, (unsigned long long)offset, err);

		size -= err;
	}

	if (size) {
		char buf[4096];
		unsigned int sz;

		memset(buf, 0, sizeof(buf));

		dnet_log(st->n, DNET_LOG_INFO, "%s: truncated file, orig: %zu, zeroes: %zu bytes.\n",
				dnet_dump_id(st->id), size + err, size);

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

