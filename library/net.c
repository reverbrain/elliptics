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

#include <sys/epoll.h>
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

static int dnet_socket_connect(struct dnet_node *n, struct dnet_addr_socket *remote, int remote_num)
{
	long timeout;
	int err, i, epfd, good_num = 0, failed_num = 0;
	struct epoll_event ev;

	epfd = epoll_create(remote_num);
	if (epfd < 0) {
		err = -errno;
		dnet_log_err(n, "Could not create epoll handler");
		goto err_out_exit;
	}

	for (i = 0; i < remote_num; ++i) {
		struct dnet_addr_socket *rem = &remote[i];

		socklen_t salen = rem->addr.addr_len;
		struct sockaddr *sa = (struct sockaddr *)&rem->addr;

		if (rem->s < 0) {
			failed_num++;
			continue;
		}

		err = connect(rem->s, sa, salen);
		if (err < 0) {
			err = -errno;
			if (err != -EINPROGRESS) {
				dnet_log_err(n, "Failed to connect to %s",
					dnet_server_convert_dnet_addr(&rem->addr));
				failed_num++;
				close(rem->s);
				rem->s = err;
				continue;
			}
		}

		ev.events = EPOLLOUT;
		ev.data.u32 = i;

		err = epoll_ctl(epfd, EPOLL_CTL_ADD, rem->s, &ev);
		if (err < 0) {
			dnet_log_err(n, "Could not add %s address to epoll set",
				dnet_server_convert_dnet_addr(&rem->addr));
			failed_num++;
			close(rem->s);
			rem->s = err;
			continue;
		}
	}

	timeout = n->wait_ts.tv_sec * 1000 > 2000 ? n->wait_ts.tv_sec * 1000 : 2000;
	while (good_num + failed_num < remote_num) {
		int num = 10;
		int ready_num;
		struct epoll_event events[num];

		struct timeval start, end;

		gettimeofday(&start, NULL);

		err = epoll_wait(epfd, events, num, timeout);
		if (err < 0) {
			dnet_log_err(n, "Epoll error");
			goto err_out_close;
		}

		if (err == 0) {
			err = -ETIMEDOUT;
			break;
		}

		ready_num = err;
		
		for (i = 0; i < ready_num; ++i) {
			int status = 0;
			socklen_t slen = 4;

			struct dnet_addr_socket *rem = &remote[events[i].data.u32];
			epoll_ctl(epfd, EPOLL_CTL_DEL, rem->s, &events[i]);

			err = getsockopt(rem->s, SOL_SOCKET, SO_ERROR, &status, &slen);
			if (err || status) {
				if (status)
					err = -status;

				dnet_log(n, DNET_LOG_ERROR, "Failed to connect to %s: status: %d: %s [%d]\n",
					dnet_server_convert_dnet_addr(&rem->addr), status,
					strerror(-err), err);

				failed_num++;

				close(rem->s);
				rem->s = err;
				continue;
			}

			rem->ok = 1;
			dnet_set_sockopt(n, rem->s);

			dnet_log(n, DNET_LOG_INFO, "Connected to %s, socket: %d.\n",
				dnet_server_convert_dnet_addr(&rem->addr), rem->s);
			good_num++;
		}

		gettimeofday(&end, NULL);

		timeout -= (end.tv_sec - start.tv_sec) * 1000 + (end.tv_usec - start.tv_usec) / 1000;

		/*
		 * This is a small hack.
		 * When timeout is that small, epoll will either return ready events or quickly return 0,
		 * which means real timeout and we will drop out of the loop.
		 *
		 * It is needed to give a chance for events which are ready, but were not picked up
		 * by epoll_wait() because of small enough buffer size (see @num above).
		 * Even if that buffer is large enough, epoll_wait() may return just a single event
		 * every time it is invoked, and that will slowly eat original timeout (2 seconds or n->wait_ts)
		 *
		 * Eventually timeout becomes negative and we give the last chance of 10 msecs.
		 * If nothing fires, we break out of this loop.
		 */
		if (timeout < 0)
			timeout = 10;
	}

	err = -ETIMEDOUT;
	for (i = 0; i < remote_num; ++i) {
		struct dnet_addr_socket *rem = &remote[i];

		if (rem->s < 0)
			continue;

		if (!rem->ok) {
			close(rem->s);
			rem->s = -ETIMEDOUT;

			dnet_log(n, DNET_LOG_ERROR, "Could not connect to %s because of timeout",
				dnet_server_convert_dnet_addr(&rem->addr));

			continue;
		}
	}

	if (good_num)
		err = good_num;

err_out_close:
	close(epfd);
err_out_exit:
	return err;
}

/**
 * Creates sockets and connect/listen them to appropriate addresses.
 * Return number of successfully created and connected/made listen sockets.
 *
 * it is still required to run over @remote array to find out what exactly happend
 * for each socket. This is similar to poll() behaviour.
 *
 * Function only tries to connect to addresses which set its socket to -ENOENT
 */
static int dnet_socket_create_addr(struct dnet_node *n, struct dnet_addr_socket *remote, int remote_num, int listening)
{
	int err, i, tmp, good_num = 0;

	for (i = 0; i < remote_num; ++i) {
		struct dnet_addr_socket *rem = &remote[i];

		socklen_t salen = rem->addr.addr_len;
		struct sockaddr *sa = (struct sockaddr *)&rem->addr;

		sa->sa_family = rem->addr.family;

		if (rem->s != -ENOENT)
			continue;

		tmp = socket(sa->sa_family, SOCK_STREAM, IPPROTO_TCP);
		if (tmp < 0) {
			err = -errno;
			remote[i].s = err;
			dnet_log_err(n, "Failed to create socket for %s: family: %d",
					dnet_server_convert_dnet_addr(&remote[i].addr),
					sa->sa_family);
			continue;
		}

		remote[i].s = tmp;

		fcntl(tmp, F_SETFL, O_NONBLOCK);
		fcntl(tmp, F_SETFD, FD_CLOEXEC);

		if (listening) {
			err = 1;
			setsockopt(tmp, SOL_SOCKET, SO_REUSEADDR, &err, 4);

			err = bind(tmp, sa, salen);
			if (err) {
				err = -errno;
				dnet_log_err(n, "Failed to bind to %s",
					dnet_server_convert_dnet_addr(&remote[i].addr));
				close(tmp);
				remote[i].s = err;
				continue;
			}

			err = listen(tmp, 10240);
			if (err) {
				err = -errno;
				dnet_log_err(n, "Failed to listen at %s",
					dnet_server_convert_dnet_addr(&remote[i].addr));
				close(tmp);
				remote[i].s = err;
				continue;
			}

			dnet_log(n, DNET_LOG_INFO, "Server is now listening at %s.\n",
					dnet_server_convert_dnet_addr(&remote[i].addr));
			good_num++;
		}
	}

	if (!listening)
		return dnet_socket_connect(n, remote, remote_num);

	return good_num;
}

int dnet_fill_addr(struct dnet_addr *addr, const char *saddr, const int port, const int sock_type, const int proto)
{
	struct addrinfo *ai = NULL, hint;
	int err;
	char port_str[16];

	snprintf(port_str, sizeof(port_str), "%d", port);

	memset(&hint, 0, sizeof(struct addrinfo));

	hint.ai_family = addr->family;
	hint.ai_socktype = sock_type;
	hint.ai_protocol = proto;

	err = getaddrinfo(saddr, port_str, &hint, &ai);
	if (err || ai == NULL) {
		if (!err)
			err = -ENXIO;
		if (ai)
			goto err_out_free;

		goto err_out_exit;
	}

	if (addr->addr_len < ai->ai_addrlen) {
		err = -ENOBUFS;
		goto err_out_free;
	}

	addr->addr_len = ai->ai_addrlen;
	memcpy(addr->addr, ai->ai_addr, addr->addr_len);

err_out_free:
	freeaddrinfo(ai);
err_out_exit:
	return err;
}

/**
 * This function resolves DNS name or IP address and put end result into sockaddr structure
 * as well as fills dnet_add structure.
 */
int dnet_create_addr(struct dnet_addr *addr, const char *addr_str, int port, int family)
{
	memset(addr, 0, sizeof(struct dnet_addr));

	addr->addr_len = sizeof(addr->addr);
	addr->family = family;

	if (addr_str) {
		return dnet_fill_addr(addr, addr_str, port, SOCK_STREAM, IPPROTO_TCP);
	} else {
		if (addr->family != AF_INET6) {
			struct sockaddr_in *in = (struct sockaddr_in *)(addr->addr);
			in->sin_port = htons(port);
		} else {
			struct sockaddr_in6 *in6 = (struct sockaddr_in6 *)(addr->addr);
			in6->sin6_port = htons(port);
		}
	}

	return 0;
}

/**
 * Created array of dnet_addr_socket structures and tries to connect/listen as much sockets as possible.
 * Returns error if there is no memory or it failed to successfully create at least single socket.
 * Returns negative error value in this case.
 *
 * It is still required to run over @sockets array to find out which sockets were successfully created
 * and what errors happened to every address.
 */
int dnet_socket_create(struct dnet_node *n, struct dnet_addr *addr, struct dnet_addr_socket **sockets, int num, int listening)
{
	int err = -EINVAL, i;
	int good_num = 0;
	struct dnet_net_state *st;
	struct dnet_addr_socket *remote;

	*sockets = NULL;

	remote = calloc(num, sizeof(struct dnet_addr_socket));
	if (!remote) {
		err = -ENOMEM;
		goto err_out_exit;
	}

	*sockets = remote;

	for (i = 0; i < num; ++i) {
		struct dnet_addr_socket *rem = &remote[i];

		rem->addr = addr[i];
		rem->ok = 0;
		rem->s = -ENOENT;

		st = dnet_state_search_by_addr(n, &addr[i]);
		if (st) {
			dnet_log(n, DNET_LOG_NOTICE, "Address %s already exists in route table\n", dnet_server_convert_dnet_addr(&addr[i]));
			dnet_state_put(st);
			rem->s = -EEXIST;
		} else {
			good_num++;
		}
	}

	if (good_num == 0) {
		dnet_log(n, DNET_LOG_NOTICE, "All %d nodes are already exist in route table\n", num);
		err = -EEXIST;
		goto err_out_exit;
	}

	err = dnet_socket_create_addr(n, remote, num, listening);
	if (err < 0)
		goto err_out_exit;
	if (err == 0) {
		err = -ETIMEDOUT;
		goto err_out_exit;
	}

	*sockets = remote;
	return 0;

err_out_exit:
	return err;
}

void dnet_state_clean(struct dnet_net_state *st)
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

			dnet_trans_remove_nolock(st, t);
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
	int err = 0;

	buf = r = malloc(sizeof(struct dnet_io_req) + orig->dsize + orig->hsize);
	if (!r) {
		err = -ENOMEM;
		dnet_log(st->n, DNET_LOG_ERROR, "Not enough memory for io req queue fd: %d : %s %d\n", orig->fd, strerror(-err), err);

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
		r->on_exit = orig->on_exit;
		r->local_offset = orig->local_offset;
		r->fsize = orig->fsize;
	}

	pthread_mutex_lock(&st->send_lock);
	list_add_tail(&r->req_entry, &st->send_list);

	if (!st->__need_exit)
		dnet_schedule_send(st);
	pthread_mutex_unlock(&st->send_lock);

err_out_exit:
	return err;
}

void dnet_io_req_free(struct dnet_io_req *r)
{
	if (r->fd >= 0 && r->fsize) {
		if (r->on_exit & DNET_IO_REQ_FLAGS_CACHE_FORGET)
			posix_fadvise(r->fd, r->local_offset, r->fsize, POSIX_FADV_DONTNEED);
		if (r->on_exit & DNET_IO_REQ_FLAGS_CLOSE)
			close(r->fd);
	}
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
		dnet_log(st->n, DNET_LOG_ERROR, "Connection reset by peer: sock: %d, revents: 0x%x.\n",
			st->read_s, pfd.revents);
		err = -ECONNRESET;
		goto out_exit;
	}

	if (pfd.revents & events) {
		err = 0;
		goto out_exit;
	}

	dnet_log(st->n, DNET_LOG_ERROR, "Socket reported error: sock: %d, revents: 0x%x.\n",
			st->read_s, pfd.revents);
	err = -EINVAL;
out_exit:
	if (st->n->need_exit || st->__need_exit) {
		dnet_log(st->n, DNET_LOG_ERROR, "Need to exit: node: %d, state: %d.\n", st->n->need_exit, st->__need_exit);
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
		int fd, uint64_t offset, uint64_t fsize, int on_exit)
{
	struct dnet_io_req r;

	memset(&r, 0, sizeof(r));
	r.header = header;
	r.hsize = hsize;
	r.fd = fd;
	r.on_exit = on_exit;
	r.local_offset = offset;
	r.fsize = fsize;

	return dnet_io_req_queue(st, &r);
}

static void dnet_trans_timestamp(struct dnet_net_state *st, struct dnet_trans *t)
{
	struct timespec *wait_ts = t->wait_ts.tv_sec ? &t->wait_ts : &st->n->wait_ts;

	gettimeofday(&t->time, NULL);

	t->time.tv_sec += wait_ts->tv_sec;
	t->time.tv_usec += wait_ts->tv_nsec / 1000;

	dnet_trans_remove_timer_nolock(st, t);
	dnet_trans_insert_timer_nolock(st, t);
}

int dnet_trans_send(struct dnet_trans *t, struct dnet_io_req *req)
{
	struct dnet_net_state *st = req->st;
	int err;

	dnet_trans_get(t);

	pthread_mutex_lock(&st->trans_lock);
	err = dnet_trans_insert_nolock(st, t);
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

		err = recv(st->read_s, data, size, MSG_DONTWAIT);
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

int dnet_add_reconnect_state(struct dnet_node *n, struct dnet_addr *addr, unsigned int join_state)
{
	struct dnet_addr_storage *a, *it;
	int err = 0;

	if (!join_state || n->need_exit) {
		if (!join_state)
			dnet_log(n, DNET_LOG_INFO, "Do not add reconnection addr: %s, join state: 0x%x.\n",
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
			dnet_log(n, DNET_LOG_INFO, "Address already exists in reconnection array: addr: %s, join state: 0x%x.\n",
				dnet_server_convert_dnet_addr(&a->addr), join_state);
			err = -EEXIST;
			break;
		}
	}

	if (!err) {
		dnet_log(n, DNET_LOG_INFO, "Added reconnection addr: %s, join state: 0x%x.\n",
			dnet_server_convert_dnet_addr(&a->addr), join_state);
		list_add_tail(&a->reconnect_entry, &n->reconnect_list);
		n->reconnect_num++;
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
		t = dnet_trans_search(st, tid);
		if (t) {
			if (!(cmd->flags & DNET_FLAGS_MORE)) {
				dnet_trans_remove_nolock(st, t);
			} else {
				dnet_trans_timestamp(st, t);
			}

			/*
			 * Always remove transaction from 'timeout' list,
			 * thus it will not be found by checker thread and
			 * its callback will not be called under us
			 */
			list_del_init(&t->trans_list_entry);
		}
		pthread_mutex_unlock(&st->trans_lock);

		if (!t) {
			dnet_log(n, DNET_LOG_ERROR, "%s: could not find transaction for reply: trans %llu.\n",
				dnet_dump_id(&cmd->id), (unsigned long long)tid);
			err = 0;
			goto err_out_exit;
		}

		if (t->complete) {
			if (t->command == DNET_CMD_READ) {
				if ((cmd->size >= sizeof(struct dnet_io_attr)) && (t->alloc_size >= sizeof(struct dnet_cmd) + sizeof(struct dnet_io_attr))) {
					struct dnet_io_attr *recv_io = (struct dnet_io_attr *)(cmd + 1);

					struct dnet_cmd *local_cmd = (struct dnet_cmd *)(t + 1);
					struct dnet_io_attr *local_io = (struct dnet_io_attr *)(local_cmd + 1);

					local_io->flags = recv_io->flags;
					local_io->size = recv_io->size;
					local_io->offset = recv_io->offset;
					local_io->user_flags = recv_io->user_flags;
					local_io->total_size = recv_io->total_size;
					local_io->timestamp = recv_io->timestamp;

					dnet_convert_io_attr(local_io);
				}
			}
			t->complete(t->st, cmd, t->priv);
		}

		dnet_trans_put(t);
		if (!(cmd->flags & DNET_FLAGS_MORE)) {
			memcpy(&t->cmd, cmd, sizeof(struct dnet_cmd));
			dnet_trans_put(t);
		} else {
			/*
			 * Put transaction back into the end of 'timeout' list with updated timestamp
			 */

			pthread_mutex_lock(&st->trans_lock);
			dnet_trans_timestamp(st, t);
			pthread_mutex_unlock(&st->trans_lock);
		}

		goto out;
	}
#if 1
	forward_state = dnet_state_get_first(n, &cmd->id);
	if (!forward_state || forward_state == st || forward_state == n->st ||
			(st->rcv_cmd.flags & DNET_FLAGS_DIRECT)) {
		dnet_state_put(forward_state);

		err = dnet_process_cmd_raw(st, cmd, r->data, 0);
		goto out;
	}

	t = dnet_trans_alloc(st->n, 0);
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

static void dnet_state_remove_and_shutdown(struct dnet_net_state *st, int error)
{
	int level = DNET_LOG_NOTICE;

	if (error && (error != -EUCLEAN))
		level = DNET_LOG_ERROR;

	dnet_log(st->n, level, "%s: resetting state: %s [%d]\n",
			dnet_state_dump_addr(st), strerror(-error), error);

	pthread_mutex_lock(&st->send_lock);

	dnet_state_remove_nolock(st);

	if (!st->__need_exit) {
		if (!error)
			error = -123;

		st->__need_exit = error;

		shutdown(st->read_s, SHUT_RDWR);
		shutdown(st->write_s, SHUT_RDWR);

		//Wakes up sleeping threads and makes them exit because state is removed
		if ((atomic_read(&st->send_queue_size) > 0))
			pthread_cond_broadcast(&st->send_wait);
	}

	pthread_mutex_unlock(&st->send_lock);
}

int dnet_state_reset_nolock_noclean(struct dnet_net_state *st, int error, struct list_head *head)
{
	dnet_state_remove_and_shutdown(st, error);

	return dnet_trans_iterate_move_transaction(st, head);
}

void dnet_state_reset(struct dnet_net_state *st, int error)
{
	LIST_HEAD(head);

	/*
	 * Prevent route table access and update, check given state, move and then drop all its transactions
	 */
	pthread_mutex_lock(&st->n->state_lock);
	dnet_state_reset_nolock_noclean(st, error, &head);
	pthread_mutex_unlock(&st->n->state_lock);

	dnet_trans_clean_list(&head);
}


void dnet_sock_close(struct dnet_node *n, int s)
{
	char addr_str[128] = "no address";
	if (n->addr_num) {
		dnet_server_convert_dnet_addr_raw(&n->addrs[0], addr_str, sizeof(addr_str));
	}
	dnet_log(n, DNET_LOG_NOTICE, "%s: addr: %s, closing socket: %d\n", dnet_dump_id(&n->id), addr_str, s);

	shutdown(s, SHUT_RDWR);
	close(s);
}

void dnet_set_sockopt(struct dnet_node *n, int s)
{
	struct linger l;
	int opt;

	opt = 1;
	setsockopt(s, SOL_SOCKET, SO_KEEPALIVE, &opt, 4);

	setsockopt(s, IPPROTO_TCP, TCP_KEEPCNT, &n->keep_cnt, 4);
	opt = 10;
	setsockopt(s, IPPROTO_TCP, TCP_KEEPIDLE, &n->keep_idle, 4);
	opt = 10;
	setsockopt(s, IPPROTO_TCP, TCP_KEEPINTVL, &n->keep_interval, 4);

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

		pthread_mutex_lock(&st->send_lock);
		err = dnet_schedule_recv(st);
		if (err) {
			dnet_unschedule_send(st);
			dnet_unschedule_recv(st);
		}
		pthread_mutex_unlock(&st->send_lock);
		if (err)
			goto err_out_exit;
	}

	return 0;

err_out_exit:
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
			dnet_log(n, DNET_LOG_INFO, "%s: authentication request succeeded\n", dnet_state_dump_addr(state));
			return 0;
		}

		dnet_log(n, DNET_LOG_ERROR, "%s: authentication request failed: %d\n", dnet_state_dump_addr(state), cmd->status);

		state->__join_state = 0;
		dnet_state_reset(state, -ECONNRESET);
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

	return dnet_trans_alloc_send_state(NULL, st, &ctl);
}

int dnet_state_micro_init(struct dnet_net_state *st,
		struct dnet_node *n, struct dnet_addr *addr, int join,
		int (* process)(struct dnet_net_state *st, struct epoll_event *ev))
{
	int err = 0;

	st->n = n;

	st->process = process;

	st->la = 1;
	st->weight = DNET_STATE_DEFAULT_WEIGHT;

	INIT_LIST_HEAD(&st->state_entry);
	INIT_LIST_HEAD(&st->storage_state_entry);

	st->trans_root = RB_ROOT;
	st->timer_root = RB_ROOT;

	st->epoll_fd = -1;

	err = pthread_mutex_init(&st->trans_lock, NULL);
	if (err) {
		err = -err;
		dnet_log_err(n, "Failed to initialize transaction mutex: %d", err);
		goto err_out;
	}

	INIT_LIST_HEAD(&st->send_list);
	err = pthread_mutex_init(&st->send_lock, NULL);
	if (err) {
		err = -err;
		dnet_log_err(n, "Failed to initialize send mutex: %d", err);
		goto err_out_trans_destroy;
	}

	err = pthread_cond_init(&st->send_wait, NULL);
	if (err) {
		err = -err;
		dnet_log_err(n, "Failed to initialize send cond: %d", err);
		goto err_out_send_destroy;
	}

	atomic_init(&st->send_queue_size, 0);
	atomic_init(&st->refcnt, 1);

	memcpy(&st->addr, addr, sizeof(struct dnet_addr));

	dnet_schedule_command(st);
	st->__join_state = join;

	return 0;

err_out_send_destroy:
	pthread_mutex_destroy(&st->send_lock);
err_out_trans_destroy:
	pthread_mutex_destroy(&st->trans_lock);
err_out:
	return err;
}

struct dnet_net_state *dnet_state_create(struct dnet_node *n,
		int group_id, struct dnet_raw_id *ids, int id_num,
		struct dnet_addr *addr, int s, int *errp, int join, int idx,
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

	st->idx = idx;
	st->read_s = s;
	st->write_s = dup(s);
	if (st->write_s < 0) {
		err = -errno;
		dnet_log_err(n, "%s: failed to duplicate socket", dnet_server_convert_dnet_addr(addr));
		goto err_out_free;
	}

	fcntl(st->write_s, F_SETFD, FD_CLOEXEC);

	dnet_log(n, DNET_LOG_DEBUG, "%s: sockets: %d/%d\n", dnet_server_convert_dnet_addr(addr), st->read_s, st->write_s);

	err = dnet_state_micro_init(st, n, addr, join, process);
	if (err)
		goto err_out_dup_destroy;

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

		if ((st->__join_state == DNET_JOIN) && (process != dnet_state_accept_process)) {
			pthread_mutex_lock(&n->state_lock);
			err = dnet_state_join_nolock(st);
			pthread_mutex_unlock(&n->state_lock);

			err = dnet_auth_send(st);
		} else if (process == dnet_state_accept_process) {
			err = dnet_copy_addrs(st, n->addrs, n->addr_num);
			if (err)
				goto err_out_send_destroy;
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
		err = st->__need_exit;
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
	pthread_mutex_destroy(&st->trans_lock);
err_out_dup_destroy:
	dnet_sock_close(n, st->write_s);
err_out_free:
	free(st);
err_out_close:
	dnet_sock_close(n, s);

err_out_exit:
	if (err == -EEXIST)
		dnet_log(n, DNET_LOG_NOTICE, "%s: state already exists.\n", dnet_server_convert_dnet_addr(addr));
	*errp = err;
	return NULL;
}

int dnet_state_num(struct dnet_session *s)
{
	return dnet_node_state_num(s->node);
}

int dnet_node_state_num(struct dnet_node *n)
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
		dnet_sock_close(st->n, st->read_s);
		dnet_sock_close(st->n, st->write_s);
	}

	dnet_state_clean(st);

	dnet_state_send_clean(st);

	pthread_mutex_destroy(&st->send_lock);
	pthread_mutex_destroy(&st->trans_lock);

	dnet_log(st->n, DNET_LOG_NOTICE, "Freeing state %s, socket: %d/%d, addr-num: %d.\n",
		dnet_server_convert_dnet_addr(&st->addr), st->read_s, st->write_s, st->addr_num);

	free(st->addrs);

	memset(st, 0xff, sizeof(struct dnet_net_state));
	free(st);
}

/*
 * Queue replies to send queue wrt high and low watermark limits.
 * This is usefull to avoid memory bloat (and hence OOM) when data gets queued
 * into send queue faster than it could be send over wire.
 */
int dnet_send_reply_threshold(void *state, struct dnet_cmd *cmd,
		const void *odata, unsigned int size, int more)
{
	struct dnet_net_state *st = state;
	int err;

	if (st == st->n->st)
		return 0;

	/* Send reply */
	err = dnet_send_reply(state, cmd, odata, size, more);
	if (err == 0)
		/* If send succeeded then we should increase queue size */
		if (atomic_inc(&st->send_queue_size) > DNET_SEND_WATERMARK_HIGH) {
			/* If high watermark is reached we should sleep */
			dnet_log(st->n, DNET_LOG_DEBUG,
					"State high_watermark reached: %s: %d, sleeping\n",
					dnet_server_convert_dnet_addr(&st->addr),
					atomic_read(&st->send_queue_size));

			pthread_mutex_lock(&st->send_lock);
			// after successful dnet_send_reply the state can be removed from another thread
			// do not wait send_wait of removed state because no one broadcast it
			if (!st->__need_exit)
				pthread_cond_wait(&st->send_wait, &st->send_lock);
			else
				err = st->__need_exit;
			pthread_mutex_unlock(&st->send_lock);

			dnet_log(st->n, DNET_LOG_DEBUG, "State woken up: %s: %d",
					dnet_server_convert_dnet_addr(&st->addr),
					atomic_read(&st->send_queue_size));
		}

	return err;
}

int dnet_send_reply(void *state, struct dnet_cmd *cmd, const void *odata, unsigned int size, int more)
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

	dnet_log(st->n, DNET_LOG_NOTICE, "%s: %s: reply -> %s: trans: %lld, size: %u, cflags: 0x%llx.\n",
		dnet_dump_id(&cmd->id), dnet_cmd_string(cmd->cmd), dnet_server_convert_dnet_addr(&st->addr),
		(unsigned long long)(c->trans &~ DNET_TRANS_REPLY),
		size, (unsigned long long)c->flags);

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
	size_t total_size = r->dsize + r->hsize + r->fsize;

	if (total_size > sizeof(struct dnet_cmd)) {
		/* Use TCP_CORK to send headers and packet body in one piece */
		cork = 1;
		setsockopt(st->write_s, IPPROTO_TCP, TCP_CORK, &cork, 4);
	}

	if (1) {
		struct dnet_cmd *cmd = r->header;
		if (!cmd)
			cmd = r->data;
		dnet_log(st->n, DNET_LOG_DEBUG, "%s: %s: sending -> %s: trans: %lld, size: %llu, cflags: 0x%llx, start-sent: %zd/%zd.\n",
			dnet_dump_id(&cmd->id), dnet_cmd_string(cmd->cmd), dnet_server_convert_dnet_addr(&st->addr),
			(unsigned long long)(cmd->trans &~ DNET_TRANS_REPLY),
			(unsigned long long)cmd->size, (unsigned long long)cmd->flags,
			st->send_offset, r->dsize + r->hsize + r->fsize);
	}

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

		dnet_log(st->n, DNET_LOG_DEBUG, "%s: %s: SENT %s cmd: %s: cmd-size: %llu, nonblocking: %d\n",
			dnet_state_dump_addr(st), dnet_dump_id(r->header),
			nonblocking ? "nonblocking" : "blocking",
			dnet_cmd_string(cmd->cmd),
			(unsigned long long)cmd->size, nonblocking);
	}

err_out_exit:

	if (1) {
		struct dnet_cmd *cmd = r->header;
		if (!cmd)
			cmd = r->data;
		dnet_log(st->n, DNET_LOG_DEBUG, "%s: %s: sending -> %s: trans: %lld, size: %llu, cflags: 0x%llx, finish-sent: %zd/%zd.\n",
			dnet_dump_id(&cmd->id), dnet_cmd_string(cmd->cmd), dnet_server_convert_dnet_addr(&st->addr),
			(unsigned long long)(cmd->trans &~ DNET_TRANS_REPLY),
			(unsigned long long)cmd->size, (unsigned long long)cmd->flags,
			st->send_offset, r->dsize + r->hsize + r->fsize);
	}

	if (total_size > sizeof(struct dnet_cmd)) {
		cork = 0;
		setsockopt(st->write_s, IPPROTO_TCP, TCP_CORK, &cork, 4);
	}

	/*
	 * Flush TCP output pipeline if we've sent whole request.
	 *
	 * We do not destroy request here, it is postponed to caller.
	 * Function can be called without lock - default call path from network processing thread and dnet_process_send_single()
	 * or under st->send_lock, if queue was empty and dnet_send*() caller directly invoked this function from dnet_io_req_queue()
	 * instead of queueing.
	 */
	if (st->send_offset == r->dsize + r->hsize + r->fsize) {
		int nodelay = 1;
		setsockopt(st->write_s, IPPROTO_TCP, TCP_NODELAY, &nodelay, 4);
	}

	return err;
}

int dnet_parse_addr(char *addr, int *portp, int *familyp)
{
	char *fam, *port;

	fam = strrchr(addr, DNET_CONF_ADDR_DELIM);
	if (!fam)
		goto err_out_print_wrong_param;
	*fam++ = 0;
	if (!fam)
		goto err_out_print_wrong_param;

	port = strrchr(addr, DNET_CONF_ADDR_DELIM);
	if (!port)
		goto err_out_print_wrong_param;
	*port++ = 0;
	if (!port)
		goto err_out_print_wrong_param;

	*familyp = atoi(fam);
	*portp = atoi(port);

	return 0;

err_out_print_wrong_param:
	fprintf(stderr, "Wrong address parameter '%s', should be 'addr%cport%cfamily'.\n",
				addr, DNET_CONF_ADDR_DELIM, DNET_CONF_ADDR_DELIM);
	return -EINVAL;
}
