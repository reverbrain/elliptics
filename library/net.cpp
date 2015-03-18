/*
 * Copyright 2008+ Evgeniy Polyakov <zbr@ioremap.net>
 * Copyright 2014+ Ruslan Nigmatullin <euroelessar@yandex.ru>
 * Copyright 2015+ Yandex
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
#include <sys/eventfd.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <poll.h>
#include <fcntl.h>

#include <netinet/tcp.h>

#include "elliptics.h"
#include "elliptics/packet.h"
#include "elliptics/interface.h"

#undef dnet_log
#undef dnet_log_error

#define dnet_log(__node__, ...) \
	BH_LOG(*(__node__)->log, __VA_ARGS__)("source", "dnet_add_state")
#define dnet_log_error(...) \
	BH_LOG(__VA_ARGS__)("error", -errno)


enum dnet_socket_state {
	just_created = 0,
	trying_to_connect,
	started,
	send_reverse,
	recv_reverse,
	recv_reverse_data,
	recv_route_list,
	finished,
	failed
};

/*
 * This is internal structure used to help batch socket creation.
 * Socket @s will be set to negative value in case of error.
 * @ok will be set to 1 if given socket was successfully initialized (connected or made listened)
 */
struct dnet_addr_socket {
	dnet_addr addr;
	int s;
	int ok;
	dnet_socket_state state;
	dnet_cmd io_cmd;
	void *buffer;
	void *io_data;
	size_t io_size;
	int version[4];
	bool ask_route_list;
};

struct dnet_addr_socket_list
{
	list_head entry;
	size_t sockets_count;
	dnet_addr_socket sockets[0];
};

struct dnet_connect_state
{
	atomic_t refcnt;
	atomic_t route_list_count;
	pthread_mutex_t lock;
	bool lock_inited;
	dnet_node *node;
	int epollfd;
	int interruptfd;
	dnet_join_state join;
	size_t failed_count;
	size_t succeed_count;
	size_t total_count;
	list_head sockets_list;
	list_head sockets_queue;
	bool finished;
};

static inline bool operator <(const dnet_addr &first, const dnet_addr &second)
{
	return dnet_addr_cmp(&first, &second) < 0;
}

static inline bool operator ==(const dnet_addr &first, const dnet_addr &second)
{
	return dnet_addr_equal(&first, &second);
}

static inline bool operator <(const dnet_addr_socket &first, const dnet_addr_socket &second)
{
	return first.addr < second.addr;
}

/*!
 * Adds \a addr to reconnect list, so we will try to connect to it somewhere in the future.
 *
 * The \a addr will be really added to state only in case if it's error "is good enough",
 * we don't want to try to reconnect to nodes, to which we a hopeless to connect.
 */
static void dnet_add_to_reconnect_list(dnet_node *node, const dnet_addr &addr, int error, dnet_join_state join)
{
	if (error == -EEXIST) {
		return;
	}

	dnet_log(node, DNET_LOG_NOTICE, "%s: could not add state, its error: %d", dnet_addr_string(&addr), error);

	if ((error == -ENOMEM) ||
		(error == -EBADF)) {
		return;
	}

	dnet_add_reconnect_state(node, &addr, join);
}

/*!
 * Marks socket as failed one.
 *
 * This function removes it's socket from epoll, if needed, closes socket, if possible, and adds to reconnect list, also, if possible
 */
static void dnet_fail_socket(dnet_connect_state &state, dnet_addr_socket *socket, int error, bool remove_from_epoll = true)
{
	if (remove_from_epoll)
		epoll_ctl(state.epollfd, EPOLL_CTL_DEL, socket->s, NULL);

	state.failed_count++;
	if (socket->s >= 0)
		close(socket->s);
	socket->s = error;
	socket->state = failed;

	dnet_add_to_reconnect_list(state.node, socket->addr, error, state.join);
}

/*!
 * Adds new event for this socket to epoll, if failed - marks socket as failed one
 */
static bool dnet_epoll_ctl(dnet_connect_state &state, dnet_addr_socket *socket, uint32_t operation,  uint32_t events)
{
	epoll_event ev;
	ev.events = events;
	ev.data.ptr = socket;

	int err = epoll_ctl(state.epollfd, operation, socket->s, &ev);
	if (err < 0) {
		int err = -errno;
		dnet_log_err(state.node, "Could not add %s address to epoll set, operation: %u, events: %u",
			dnet_addr_string(&socket->addr), operation, events);
		dnet_fail_socket(state, socket, err, operation == EPOLL_CTL_ADD);
		return false;
	}

	return true;
}

/*!
 * Tryies to read as much as possible from socket's socket without blocking the thread, but not more than it's needed.
 *
 * On unrecoverable fail marks socket as failed.
 */
static bool dnet_recv_nolock(dnet_connect_state &state, dnet_addr_socket *socket)
{
	ssize_t err = recv(socket->s, socket->io_data, socket->io_size, 0);
	if (err < 0) {
		err = -EAGAIN;
		if (errno != EAGAIN && errno != EINTR) {
			err = -errno;
			dnet_log_err(state.node, "%s: failed to receive data, socket: %d",
					dnet_addr_string(&socket->addr), socket->s);
			dnet_fail_socket(state, socket, err);
			return false;
		}

		return false;
	}

	if (err == 0) {
		dnet_log(state.node, DNET_LOG_ERROR, "%s: peer has disconnected, socket: %d.",
			dnet_addr_string(&socket->addr), socket->s);
		err = -ECONNRESET;
		dnet_fail_socket(state, socket, err);
		return false;
	}

	socket->io_data = reinterpret_cast<char *>(socket->io_data) + err;
	socket->io_size -= err;

	if (socket->io_size == 0)
		return true;

	return false;
}

/*!
 * Tryies to write as much as possible to socket's socket without blocking the thread, but not more than it's needed.
 *
 * On unrecoverable fail marks socket as failed.
 */
static bool dnet_send_nolock(dnet_connect_state &state, dnet_addr_socket *socket)
{
	ssize_t err = send(socket->s, socket->io_data, socket->io_size, 0);
	if (err < 0) {
		err = -errno;
		if (err != -EAGAIN) {
			dnet_log_err(state.node, "%s: failed to send packet: size: %llu, socket: %d",
				dnet_addr_string(&socket->addr), (unsigned long long)socket->io_size, socket->s);
			dnet_fail_socket(state, socket, err);
			return false;
		}

		return false;
	}

	if (err == 0) {
		dnet_log(state.node, DNET_LOG_ERROR, "Peer %s has dropped the connection: socket: %d.",
			dnet_addr_string(&socket->addr), socket->s);
		err = -ECONNRESET;
		dnet_fail_socket(state, socket, err);
		return false;
	}

	socket->io_data = reinterpret_cast<char *>(socket->io_data) + err;
	socket->io_size -= err;

	if (socket->io_size == 0)
		return true;

	return false;
}

dnet_connect_state *dnet_connect_state_get(dnet_connect_state *state)
{
	atomic_add(&state->refcnt, 1);
	return state;
}

void dnet_connect_state_put(dnet_connect_state *state)
{
	if (atomic_dec_and_test(&state->refcnt)) {
		if (state->lock_inited)
			pthread_mutex_destroy(&state->lock);
		if (state->epollfd >= 0)
			close(state->epollfd);
		if (state->interruptfd >= 0)
			close(state->interruptfd);
		free(state);
	}
}

/*!
 * Initialize the socket, but don't connect to the address
 *
 * This function also checks if this socket already exists in route table
 */
static int dnet_socket_init(dnet_node *node, const dnet_addr *addr, dnet_addr_socket *result, int listening)
{
	socklen_t salen;
	sockaddr *sa;
	dnet_net_state *st;
	int err = 0;

	st = dnet_state_search_by_addr(node, addr);
	if (st) {
		err = -EEXIST;

		dnet_log(node, DNET_LOG_NOTICE, "Address %s already exists in route table",
			dnet_addr_string(addr));
		dnet_state_put(st);
		goto err_out_exit;
	}

	result->addr = *addr;
	result->ok = 0;
	result->state = just_created;

	salen = result->addr.addr_len;
	sa = (sockaddr *)&result->addr;

	sa->sa_family = result->addr.family;

	result->s = socket(sa->sa_family, SOCK_STREAM, IPPROTO_TCP);
	if (result->s < 0) {
		err = -errno;

		dnet_log_err(node, "Failed to create socket for %s: family: %d",
			dnet_addr_string(&result->addr), sa->sa_family);
		goto err_out_exit;
	}

	fcntl(result->s, F_SETFL, O_NONBLOCK);
	fcntl(result->s, F_SETFD, FD_CLOEXEC);

	if (listening) {
		err = 1;
		setsockopt(result->s, SOL_SOCKET, SO_REUSEADDR, &err, 4);

		err = bind(result->s, sa, salen);
		if (err) {
			err = -errno;
			dnet_log_err(node, "Failed to bind to %s",
				dnet_addr_string(addr));
			goto err_out_close;
		}

		err = listen(result->s, 10240);
		if (err) {
			err = -errno;
			dnet_log_err(node, "Failed to listen at %s",
				dnet_addr_string(addr));
			goto err_out_close;
		}

		dnet_log(node, DNET_LOG_INFO, "Server is now listening at %s.",
				dnet_addr_string(addr));
	} else {
		dnet_log(node, DNET_LOG_INFO, "Added %s to connect list",
			dnet_addr_string(addr));
	}

	return 0;

err_out_close:
	close(result->s);
err_out_exit:
	return err;
}

/*
 * Returns true if address @addr equals to one of the listening node's addresses.
 * In this case we should not try to connect to it - connection will be dropped with -EEXIST status later.
 */
static bool dnet_addr_is_local(dnet_node *n, const dnet_addr *addr)
{
	for (int i = 0; i < n->addr_num; ++i) {
		if (dnet_addr_equal(addr, &n->addrs[i]))
			return true;
	}

	return false;
}

/*!
 * \brief dnet_socket_create_addresses creates a socket per each passed address,
 * returnes array of allocated dnet_addr_sockets, their number is returned by addrs_count property.
 * If no sockets were created, NULL is returned, @at_least_one_exists is set if at least one address
 * already exists in local route table.
 *
 * This method actually doesn't connect to remote hosts or binds to local addresses.
 *
 * All sockets are sorted by their address, so we are able quickly to lookup if there are already such sockets.
 */
static dnet_addr_socket_list *dnet_socket_create_addresses(dnet_node *node, const dnet_addr *addrs, size_t addrs_count,
	bool ask_route_list, dnet_join_state join, bool *at_least_one_exist)
{
	*at_least_one_exist = false;

	if (addrs_count == 0) {
		return NULL;
	}

	dnet_addr_socket_list *result = reinterpret_cast<dnet_addr_socket_list *>(malloc(
		sizeof(dnet_addr_socket_list) + sizeof(dnet_addr_socket) * (addrs_count)));
	if (!result) {
		return NULL;
	}

	memset(result, 0, sizeof(dnet_addr_socket_list) + sizeof(dnet_addr_socket) * (addrs_count));

	INIT_LIST_HEAD(&result->entry);
	result->sockets_count = 0;

	for (size_t i = 0; i < addrs_count; ++i) {
		dnet_addr_socket *socket = &result->sockets[result->sockets_count];
		socket->ask_route_list = ask_route_list;

		if (dnet_addr_is_local(node, &addrs[i]))
			continue;

		int err = dnet_socket_init(node, &addrs[i], socket, 0);
		if (err == 0) {
			dnet_log(node, DNET_LOG_DEBUG, "dnet_socket_create_addresses: socket for state %s created successfully, socket: %d",
				dnet_addr_string(&addrs[i]), socket->s);
			++result->sockets_count;
		} else {
			if (err == -EEXIST) {
				*at_least_one_exist = true;
			} else {
				dnet_add_to_reconnect_list(node, addrs[i], err, join);

				dnet_log(node, DNET_LOG_ERROR, "dnet_socket_create_addresses: failed to create a socket for state %s, err: %d",
					dnet_addr_string(&addrs[i]), err);
			}
		}
	}

	if (result->sockets_count == 0) {
		free(result);
		return NULL;
	}

	std::sort(result->sockets, result->sockets + result->sockets_count);

	return result;
}

/*!
 * Iterrupts epoll, so it's possible to send data from 'some' thread to epoll's one
 */
static void dnet_interrupt_epoll(dnet_connect_state &state)
{
	uint64_t counter = 1;
	int err = ::write(state.interruptfd, &counter, sizeof(uint64_t));
	(void) err;
}

static int dnet_validate_route_list(const char *server_addr, dnet_node *node, struct dnet_cmd *cmd)
{
	dnet_addr_container *cnt;
	long size;
	int err, i;
	char rem_addr[128];

	err = cmd->status;
	if (!cmd->size || err)
		goto err_out_exit;

	size = cmd->size + sizeof(dnet_cmd);
	if (size < (signed)sizeof(dnet_addr_cmd)) {
		err = -EINVAL;
		goto err_out_exit;
	}

	cnt = (struct dnet_addr_container *)(cmd + 1);
	dnet_convert_addr_container(cnt);

	if (cmd->size != sizeof(dnet_addr) * cnt->addr_num + sizeof(dnet_addr_container)) {
		err = -EINVAL;
		goto err_out_exit;
	}

	/* only compare addr-num if we are server, i.e. joined node, clients do not have local addresses at all */
	if (node->addr_num && (cnt->node_addr_num != node->addr_num)) {
		dnet_log(node, DNET_LOG_ERROR, "%s: invalid route list reply: recv-addr-num: %d, local-addr-num: %d",
				server_addr, int(cnt->node_addr_num), node->addr_num);
		err = -EINVAL;
		goto err_out_exit;
	}

	if (cnt->node_addr_num == 0
		|| cnt->addr_num % cnt->node_addr_num != 0) {
		dnet_log(node, DNET_LOG_ERROR, "%s: invalid route list reply: recv-addr-num: %d, rec-node-addr-num: %d",
				server_addr, int(cnt->addr_num), int(cnt->node_addr_num));
		err = -EINVAL;
		goto err_out_exit;
	}

	for (i = 0; i < cnt->addr_num; ++i) {
		if (dnet_empty_addr(&cnt->addrs[i])) {
			dnet_log(node, DNET_LOG_ERROR, "%s: received zero address route reply, aborting route update",
				server_addr);
			err = -ENOTTY;
			goto err_out_exit;
		}

		dnet_log(node, DNET_LOG_DEBUG, "route-list: from: %s, node: %d, addr: %s",
			server_addr, i / cnt->node_addr_num, dnet_addr_string_raw(&cnt->addrs[i], rem_addr, sizeof(rem_addr)));
	}

err_out_exit:
	return err;
}

static int dnet_connect_route_list_complete(dnet_addr *addr, dnet_cmd *cmd, void *priv)
{
	dnet_connect_state *state = reinterpret_cast<dnet_connect_state *>(priv);
	dnet_node *node = state->node;

	char server_addr[128];
	dnet_addr_string_raw(addr, server_addr, sizeof(server_addr));

	int err;
	if (is_trans_destroyed(cmd)) {
		err = -EINVAL;
		if (cmd)
			err = cmd->status;

		atomic_dec(&state->route_list_count);
		dnet_interrupt_epoll(*state);

		dnet_log(node, DNET_LOG_NOTICE, "Received route-list reply from state: %s, route_list_count: %lld",
			server_addr, atomic_read(&state->route_list_count));

		dnet_connect_state_put(state);
		return err;
	}

	dnet_net_state *st = dnet_state_search_by_addr(node, addr);
	if (!st) {
		dnet_log(node, DNET_LOG_NOTICE, "Received route-list reply from unknown (destroyed?) state: %s", server_addr);
		return -EINVAL;
	}

	dnet_addr_container *cnt = reinterpret_cast<dnet_addr_container *>(cmd + 1);
	const size_t states_num = cnt->addr_num / cnt->node_addr_num;

	dnet_addr *addrs;
	dnet_addr_socket_list *sockets;
	size_t sockets_count;
	bool added_to_queue = false;
	bool all_exist = false;

	err = dnet_validate_route_list(server_addr, node, cmd);
	if (err) {
		goto err_out_exit;
	}

	addrs = reinterpret_cast<dnet_addr *>(malloc(states_num * sizeof(dnet_addr)));
	if (!addrs) {
		err = -ENOMEM;
		goto err_out_exit;
	}

	for (size_t i = 0; i < states_num; ++i) {
		dnet_addr *addr = &cnt->addrs[i * cnt->node_addr_num + st->idx];
		memcpy(&addrs[i], addr, sizeof(dnet_addr));
	}

	sockets = dnet_socket_create_addresses(node, addrs, states_num, false, state->join, &all_exist);
	if (!sockets) {
		err = -ENOMEM;
		goto err_out_free_addrs;
	}

	sockets_count = sockets->sockets_count;

	pthread_mutex_lock(&state->lock);

	if (!state->finished) {
		atomic_inc(&state->route_list_count);
		list_add(&sockets->entry, &state->sockets_queue);
		added_to_queue = true;
	}

	pthread_mutex_unlock(&state->lock);

	if (added_to_queue) {
		dnet_interrupt_epoll(*state);

		dnet_log(node, DNET_LOG_INFO, "Trying to connect to additional %llu states of %llu original from route_list_recv, state: %s, route_list_count: %lld",
			sockets_count, states_num, server_addr, atomic_read(&state->route_list_count));
	} else {
		dnet_log(node, DNET_LOG_ERROR, "Failed to connect to additional %llu states of %llu original from route_list_recv, state: %s, state is already desotryed, adding to reconnect list",
			sockets_count, states_num, server_addr);

		for (size_t i = 0; i < sockets->sockets_count; ++i) {
			dnet_addr_socket *socket = &sockets->sockets[i];

			if (socket->s >= 0)
				close(socket->s);

			dnet_add_to_reconnect_list(node, socket->addr, -ETIMEDOUT, state->join);
		}
		free(sockets);
	}

err_out_free_addrs:
	free(addrs);
err_out_exit:
	dnet_state_put(st);
	return err;
}

/*!
 * Requests route list, every unknown node from reply will be added to state's connection queue.
 */
void dnet_request_route_list(dnet_connect_state &state, dnet_net_state *st)
{
	int err = dnet_recv_route_list(st, dnet_connect_route_list_complete, dnet_connect_state_get(&state));
	if (!err) {
		atomic_inc(&state.route_list_count);
		dnet_log(state.node, DNET_LOG_NOTICE, "Sent route-list request to state: %s, route_list_count: %lld",
			dnet_state_dump_addr(st), atomic_read(&state.route_list_count));
	}
}

/*!
 * Adds new sockets from \a list to connection queue and add all of them to epoll.
 *
 * If some addresses are already in the queue - they are skipped
 */
static void dnet_socket_connect_new_sockets(dnet_connect_state &state, dnet_addr_socket_list *list)
{
	state.total_count += list->sockets_count;

	for (size_t i = 0; i < list->sockets_count; ++i) {
		dnet_addr_socket *socket = &list->sockets[i];
		bool already_exist = false;

		dnet_addr_socket_list *other;
		list_for_each_entry(other, &state.sockets_list, entry) {
			if (std::binary_search(other->sockets, other->sockets + other->sockets_count, *socket)) {
				already_exist = true;
				break;
			}
		}

		if (already_exist) {
			dnet_log(state.node, DNET_LOG_NOTICE, "we are already connecting to %s",
				dnet_addr_string(&socket->addr));

			dnet_fail_socket(state, socket, -EEXIST, false);
			continue;
		}

		socket->state = trying_to_connect;

		socklen_t salen = socket->addr.addr_len;
		sockaddr *sa = (sockaddr *)&socket->addr;

		if (socket->s < 0) {
			state.failed_count++;
			continue;
		}

		int err = connect(socket->s, sa, salen);
		if (err < 0) {
			err = -errno;
			if (err != -EINPROGRESS) {
				dnet_log_err(state.node, "Failed to connect to %s",
					dnet_addr_string(&socket->addr));
				dnet_fail_socket(state, socket, err, false);
				continue;
			}
		}

		dnet_epoll_ctl(state, socket, EPOLL_CTL_ADD, EPOLLOUT);
	}

	list_move_tail(&list->entry, &state.sockets_list);
}

/*!
 * This method is state machine for socket's processing, it's invoked on every epoll's event.
 *
 * It's implemented in synchornous-like way for easier understanding and developing.
 * It's always known that it's called from only one possible thread, so there are no locks around the state.
 *
 * All logic can be splitted to different big blocks with some io-operations between them,
 * each block has it's own equivalent in socket's state enum, so we are able to jump to
 * current block's code by simple switch.
 */
static void dnet_process_socket(dnet_connect_state &state, epoll_event &ev)
{
	if (ev.data.ptr == &state.interruptfd) {
		dnet_log(state.node, DNET_LOG_NOTICE, "Caught signal from interruptfd, list: %d", list_empty_careful(&state.sockets_queue));

		list_head local_queue;
		dnet_addr_socket_list *list, *tmp;
		INIT_LIST_HEAD(&local_queue);

		pthread_mutex_lock(&state.lock);
		list_splice_init(&state.sockets_queue, &local_queue);
		pthread_mutex_unlock(&state.lock);

		list_for_each_entry_safe(list, tmp, &local_queue, entry) {
			dnet_socket_connect_new_sockets(state, list);

			atomic_dec(&state.route_list_count);
			dnet_log(state.node, DNET_LOG_NOTICE, "Received route-list reply, count: %lld, route_list_count: %lld",
				list->sockets_count, atomic_read(&state.route_list_count));
		}

		return;
	}

	dnet_addr_socket *socket = reinterpret_cast<dnet_addr_socket *>(ev.data.ptr);
	dnet_cmd *cmd = &socket->io_cmd;

	dnet_log(state.node, DNET_LOG_DEBUG, "%s: socket: %d, state: %d", dnet_addr_string(&socket->addr), socket->s, socket->state);

	switch (socket->state) {
	case trying_to_connect: {
		int status, err;
		socklen_t slen = 4;

		err = getsockopt(socket->s, SOL_SOCKET, SO_ERROR, &status, &slen);
		if (err || status) {
			if (status)
				err = -status;

			dnet_log(state.node, DNET_LOG_ERROR, "%s: failed to connect, status: %d: %s [%d]",
				dnet_addr_string(&socket->addr), status,
				strerror(-err), err);

			dnet_fail_socket(state, socket, err);
			break;
		}

		dnet_log(state.node, DNET_LOG_NOTICE, "%s: successfully connected, sending reverse lookup command",
			dnet_addr_string(&socket->addr));

		socket->state = started;
		// Fall through
	}
	case started:
		memset(cmd, 0, sizeof(dnet_cmd));

		cmd->flags = DNET_FLAGS_DIRECT | DNET_FLAGS_NOLOCK;
		cmd->cmd = DNET_CMD_REVERSE_LOOKUP;

		dnet_version_encode(&cmd->id);
		dnet_indexes_shard_count_encode(&cmd->id, state.node->indexes_shard_count);
		dnet_convert_cmd(cmd);

		socket->state = send_reverse;
		socket->io_data = cmd;
		socket->io_size = sizeof(dnet_cmd);

		// Fall through
	case send_reverse:
		if (!dnet_send_nolock(state, socket))
			break;

		socket->io_data = cmd;
		socket->io_size = sizeof(dnet_cmd);

		if (!dnet_epoll_ctl(state, socket, EPOLL_CTL_MOD, EPOLLIN))
			break;

		socket->state = recv_reverse;
		// Fall through
	case recv_reverse: {
		if (!dnet_recv_nolock(state, socket))
			break;

		int (&version)[4] = socket->version;
		int indexes_shard_count = 0;
		int err;
		dnet_net_state dummy_state;

		memset(&dummy_state, 0, sizeof(dummy_state));
		dummy_state.addr = socket->addr;

		dummy_state.write_s = dummy_state.read_s = socket->state;
		dummy_state.n = state.node;

		dnet_convert_cmd(cmd);
		dnet_version_decode(&cmd->id, version);
		dnet_indexes_shard_count_decode(&cmd->id, &indexes_shard_count);

		if (cmd->status != 0) {
			err = cmd->status;

			dnet_log(state.node, DNET_LOG_ERROR, "%s: reverse lookup command failed: local version: %d.%d.%d.%d, "
					"remote version: %d.%d.%d.%d, error: %s [%d]",
					dnet_addr_string(&socket->addr),
					CONFIG_ELLIPTICS_VERSION_0, CONFIG_ELLIPTICS_VERSION_1,
					CONFIG_ELLIPTICS_VERSION_2, CONFIG_ELLIPTICS_VERSION_3,
					version[0], version[1], version[2], version[3],
					strerror(-err), err);
			dnet_fail_socket(state, socket, err);
			break;
		}

		err = dnet_version_check(&dummy_state, version);
		if (err) {
			dnet_fail_socket(state, socket, err);
			break;
		}

		dnet_log(state.node, DNET_LOG_NOTICE, "%s: received indexes shard count: local: %d, remote: %d, using server one",
				dnet_addr_string(&socket->addr), state.node->indexes_shard_count, indexes_shard_count);

		if (indexes_shard_count != state.node->indexes_shard_count && indexes_shard_count != 0) {
			dnet_log(state.node, DNET_LOG_INFO, "%s: local and remote indexes shard count are different: "
					"local: %d, remote: %d, using remote (%d) one",
					dnet_addr_string(&socket->addr),
					state.node->indexes_shard_count, indexes_shard_count, indexes_shard_count);

			state.node->indexes_shard_count = indexes_shard_count;
		}

		socket->buffer = malloc(cmd->size);
		socket->io_data = socket->buffer;
		socket->io_size = cmd->size;

		if (!socket->buffer) {
			err = -ENOMEM;
			dnet_log(state.node, DNET_LOG_ERROR, "%s: failed to allocate %llu bytes for reverse lookup data",
					dnet_addr_string(&socket->addr), (unsigned long long)cmd->size);
			dnet_fail_socket(state, socket, err);
			break;
		}
		socket->state = recv_reverse_data;
		// Fall through
	}
	case recv_reverse_data: {
		if (!dnet_recv_nolock(state, socket))
			break;

		dnet_addr_container *cnt = reinterpret_cast<dnet_addr_container *>(socket->buffer);
		int err;

		/* If we are server check that connected node has the same number of addresses.
		 * At the moment server nodes with different number of addresses can't be connected to each other.
		 */
		if (state.node->addr_num && (cnt->addr_num != state.node->addr_num)) {
			err = -EINVAL;
			dnet_log(state.node, DNET_LOG_ERROR, "%s: received dnet_addr_container "
				"is invalid, recv-addr-num: %d, local-addr-num: %d, err: %d",
				dnet_addr_string(&socket->addr),
				int(cnt->addr_num),
				state.node->addr_num,
				err);
			dnet_fail_socket(state, socket, err);
			break;
		}

		if (cmd->size < sizeof(dnet_addr_container) + cnt->addr_num * sizeof(dnet_addr) + sizeof(dnet_id_container)) {
			err = -EINVAL;
			dnet_log(state.node, DNET_LOG_ERROR, "%s: received dnet_addr_container "
				"is invalid, size: %lld, expected at least: %llu, err: %d",
				dnet_addr_string(&socket->addr),
				uint64_t(cmd->size),
				sizeof(dnet_addr_container) + cnt->addr_num * sizeof(dnet_addr) + sizeof(dnet_id_container),
				err);
			dnet_fail_socket(state, socket, err);
			break;
		}

		// This anyway doesn't work - there are issues with BE/LE conversion
		dnet_convert_addr_container(cnt);

		size_t size = cmd->size - sizeof(dnet_addr) * cnt->addr_num - sizeof(dnet_addr_container);
		dnet_id_container *id_container = reinterpret_cast<dnet_id_container *>(
			reinterpret_cast<char *>(socket->buffer) + sizeof(dnet_addr) * cnt->addr_num + sizeof(dnet_addr_container)
		);

		std::unique_ptr<dnet_backend_ids *[], free_destroyer> backends(reinterpret_cast<dnet_backend_ids **>(
			malloc(id_container->backends_count * sizeof(dnet_backend_ids *))
		));
		if (!backends) {
			dnet_log(state.node, DNET_LOG_ERROR, "%s: failed to allocate %llu bytes for dnet_backend_ids array from %s.",
				dnet_addr_string(&socket->addr),
				(unsigned long long)id_container->backends_count * sizeof(dnet_backend_ids *),
				dnet_addr_string(&socket->addr));
			dnet_fail_socket(state, socket, -ENOMEM);
			break;
		}

		err = dnet_validate_id_container(id_container, size, backends.get());
		if (err) {
			dnet_log(state.node, DNET_LOG_ERROR, "connected-to-addr: %s: failed to validate id container: %d",
					dnet_addr_string(&socket->addr), err);
			dnet_fail_socket(state, socket, err);
			break;
		}

		int idx = -1;
		for (int i = 0; i < cnt->addr_num; ++i) {
			if (dnet_empty_addr(&cnt->addrs[i])) {
				dnet_log(state.node, DNET_LOG_ERROR, "connected-to-addr: %s: received wildcard (like 0.0.0.0) addr: "
						"backends: %d, addr-num: %d, idx: %d.",
						dnet_addr_string(&socket->addr),
						int(id_container->backends_count), int(cnt->addr_num), idx);
				err = -EPROTO;
				dnet_fail_socket(state, socket, err);
				break;
			}

			if (dnet_addr_equal(&socket->addr, &cnt->addrs[i])) {
				idx = i;
				break;
			}
		}
		if (idx == -1) {
			err = -EPROTO;
			dnet_log(state.node, DNET_LOG_ERROR, "%s: there is no connected addr in received reverse lookup data",
					dnet_addr_string(&socket->addr));
			dnet_fail_socket(state, socket, err);
			break;
		}

		for (int i = 0; i < id_container->backends_count; ++i) {
			dnet_backend_ids *backend = backends[i];
			for (uint32_t j = 0; j < backend->ids_count; ++j) {
				dnet_log(state.node, DNET_LOG_NOTICE, "connected-to-addr: %s: received backends: %d/%d, "
						"ids: %d/%d, addr-num: %d, idx: %d, "
						"backend_id: %d, group_id: %d, id: %s.",
						dnet_addr_string(&socket->addr), i, int(id_container->backends_count),
						j, uint32_t(backend->ids_count), int(cnt->addr_num), idx,
						int(backend->backend_id), int(backend->group_id), dnet_dump_id_str(backend->ids[j].id));
			}
		}

		epoll_ctl(state.epollfd, EPOLL_CTL_DEL, socket->s, NULL);

		dnet_net_state *st = dnet_state_create(state.node, backends.get(),
			id_container->backends_count, &socket->addr, socket->s,
			&err, state.join, 1, idx, 0, cnt->addrs, cnt->addr_num);

		socket->s = -1;
		if (!st) {
			/* socket is already closed */
			dnet_fail_socket(state, socket, err, false);
			break;
		}

		memcpy(st->version, socket->version, sizeof(st->version));
		dnet_log(state.node, DNET_LOG_NOTICE, "%s: connected: backends-num: %d, addr-num: %d, idx: %d.",
				dnet_addr_string(&socket->addr), int(id_container->backends_count), int(cnt->addr_num), idx);

		free(socket->buffer);

		dnet_set_sockopt(state.node, socket->s);

		dnet_log(state.node, DNET_LOG_INFO, "Connected to %s, socket: %d.",
			dnet_addr_string(&socket->addr), socket->s);
		state.succeed_count++;

		socket->ok = 1;

		if (socket->ask_route_list) {
			dnet_request_route_list(state, st);
		}

		// @dnet_net_state() returns state with 2 reference counters
		dnet_state_put(st);
		socket->state = finished;
		break;
	}
	case just_created:
	case recv_route_list:
	case finished:
	case failed:
		dnet_log(state.node, DNET_LOG_ERROR, "Socket was epolled in state: %d, which is impossible, state: %s, socket: %d",
			int(socket->state), dnet_addr_string(&socket->addr), socket->s);
		break;
	}
}

struct net_state_list_destroyer
{
	net_state_list_destroyer() : count(0)
	{
	}

	net_state_list_destroyer(size_t count) : count(count)
	{
	}

	void operator ()(dnet_net_state **list)
	{
		if (!list) {
			return;
		}

		for (size_t i = 0; i < count; ++i) {
			if (list[i])
				dnet_state_put(list[i]);
		}

		free(list);
	}

	size_t count;
};

typedef std::unique_ptr<dnet_net_state *[], net_state_list_destroyer> net_state_list_ptr;
typedef std::unique_ptr<dnet_addr[], free_destroyer> net_addr_list_ptr;

/*!
 * Asynchornously connects to nodes from original_list, asks them route_list, if needed,
 * and continue to connecting to new nodes in addition to originally passed one.
 *
 * This function exits only if timeout is exceeded or if all connection operations are either failed or succeded.
 * It returns either negative error value or positive number of successfully connected sockets.
 *
 * \a original_list will be freed by call of this function
 *
 * @states_count contains number of already connected valid sockets in @states array.
 * This function sends route request to those sockets and resets the array.
 */
static int dnet_socket_connect(dnet_node *node, dnet_addr_socket_list *original_list, dnet_join_state join,
	net_state_list_ptr states, size_t states_count)
{
	int err;
	long timeout;
	epoll_event ev;

	dnet_connect_state *state_ptr = reinterpret_cast<dnet_connect_state *>(malloc(sizeof(dnet_connect_state)));
	if (!state_ptr) {
		err = -ENOMEM;
		return err;
	}

	memset(state_ptr, 0, sizeof(*state_ptr));

	dnet_connect_state &state = *state_ptr;
	state.node = node;
	state.failed_count = 0;
	state.succeed_count = 0;
	state.total_count = 0;
	state.join = join;
	state.finished = false;
	state.epollfd = -1;
	state.interruptfd = -1;

	INIT_LIST_HEAD(&state.sockets_list);
	INIT_LIST_HEAD(&state.sockets_queue);

	dnet_connect_state_get(&state);

	err = pthread_mutex_init(&state.lock, NULL);
	if (err) {
		dnet_log(state.node, DNET_LOG_ERROR, "Failed to initialize mutex: %d", err);
		goto err_out_put;
	}

	state.lock_inited = true;
	state.epollfd = epoll_create1(EPOLL_CLOEXEC);
	if (state.epollfd < 0) {
		err = -errno;
		dnet_log_err(state.node, "Could not create epoll handler");
		goto err_out_put;
	}

	// this file descriptor is used to pass information from io thread to current one
	// for example it's used to pass here replies from route-list requests
	state.interruptfd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
	if (state.interruptfd < 0) {
		err = -errno;
		dnet_log_err(state.node, "Could not create eventfd interrupter");
		close(state.epollfd);
		goto err_out_put;
	}

	ev.events = EPOLLIN | EPOLLET;
	ev.data.ptr = &state.interruptfd;
	err = epoll_ctl(state.epollfd, EPOLL_CTL_ADD, state.interruptfd, &ev);
	if (err) {
		err = -errno;
		dnet_log_err(state.node, "Could not epoll eventfd interrupter, fd: %d", state.interruptfd);
		goto err_out_put;
	}

	// send route request to already connected states
	if (!(state.node->flags & DNET_CFG_NO_ROUTE_LIST)) {
		for (size_t i = 0; i < states_count; ++i) {
			dnet_request_route_list(state, states[i]);
		}
	}

	states.reset();

	if (original_list)
		dnet_socket_connect_new_sockets(state, original_list);
	original_list = NULL;

	timeout = state.node->wait_ts.tv_sec * 1000 > 2000 ? state.node->wait_ts.tv_sec * 1000 : 2000;
	while (state.succeed_count + state.failed_count < state.total_count || atomic_read(&state.route_list_count) > 0) {
		const size_t num = 128;
		size_t ready_num;
		epoll_event events[num];

		timeval start, end;

		gettimeofday(&start, NULL);

		err = epoll_wait(state.epollfd, events, num, timeout);
		if (err < 0) {
			dnet_log_err(state.node, "Epoll error");
			goto err_out_put;
		}

		if (err == 0) {
			err = -ETIMEDOUT;
			break;
		}

		ready_num = err;

		for (size_t i = 0; i < ready_num; ++i) {
			dnet_process_socket(state, events[i]);
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
		 * every time it is invoked, and that will slowly eat original timeout (2 seconds or state.node->wait_ts)
		 *
		 * Eventually timeout becomes negative and we give the last chance of 10 msecs.
		 * If nothing fires, we break out of this loop.
		 */
		if (timeout < 0)
			timeout = 10;
	}

	pthread_mutex_lock(&state.lock);
	state.finished = true;

	list_splice_init(&state.sockets_queue, &state.sockets_list);

	pthread_mutex_unlock(&state.lock);

err_out_put:
	// Timeout! We need to close every socket where we have not connected yet.

	if (err == 0)
		err = -ECONNREFUSED;

	dnet_addr_socket_list *list;
	dnet_addr_socket_list *tmp;
	list_for_each_entry_safe(list, tmp, &state.sockets_list, entry) {
		for (size_t i = 0; i < list->sockets_count; ++i) {
			dnet_addr_socket *socket = &list->sockets[i];

			if (socket->s < 0)
				continue;

			if (!socket->ok) {
				close(socket->s);
				socket->s = -ETIMEDOUT;

				dnet_log(state.node, DNET_LOG_ERROR, "Could not connect to %s because of timeout",
					dnet_addr_string(&socket->addr));

				dnet_add_to_reconnect_list(state.node, socket->addr, -ETIMEDOUT, state.join);

				continue;
			}
		}

		list_del(&list->entry);
		free(list);
	}

	if (state.succeed_count) {
		err = state.succeed_count;
	} else if (err >= 0) {
		// this may happen when we have only one socket to connect and connect failed
		// epoll will return positive number (1), but @dnet_process_socket() will fail it,
		// yet error is not reset
		err = -ECONNREFUSED;
	}

	dnet_connect_state_put(&state);

	return err;
}

int dnet_socket_create_listening(dnet_node *node, const dnet_addr *addr)
{
	int err;
	dnet_addr_socket result;

	memset(&result, 0, sizeof(result));
	err = dnet_socket_init(node, addr, &result, 1);

	if (err) {
		return err;
	}

	return result.s;
}

static net_state_list_ptr dnet_check_route_table_victims(struct dnet_node *node, size_t *states_count)
{
	*states_count = 0;

	const size_t groups_count_limit = 4096;
	const size_t groups_count_random_limit = 5;

	std::unique_ptr<unsigned[], free_destroyer> groups(reinterpret_cast<unsigned *>(calloc(groups_count_limit, sizeof(unsigned))));
	if (!groups) {
		return net_state_list_ptr();
	}

	size_t groups_count = 0;
	pthread_mutex_lock(&node->state_lock);

	struct rb_node *it;
	struct dnet_group *g;
	for (it = rb_first(&node->group_root); it; it = rb_next(it)) {
		g = rb_entry(it, struct dnet_group, group_entry);
		groups[groups_count++] = g->group_id;

		if (groups_count >= groups_count_limit)
			break;
	}
	pthread_mutex_unlock(&node->state_lock);

	struct dnet_id id;
	memset(&id, 0, sizeof(id));
	const size_t route_addr_num = node->route_addr_num;
	const size_t total_states_count = route_addr_num + groups_count_random_limit;

	net_state_list_ptr route_list_states(
		reinterpret_cast<dnet_net_state **>(calloc(total_states_count, sizeof(dnet_net_state *))),
		net_state_list_destroyer(total_states_count)
	);

	if (!route_list_states) {
		return net_state_list_ptr();
	}

	pthread_mutex_lock(&node->reconnect_lock);
	for (size_t i = 0; i < std::min(groups_count, groups_count_random_limit); ++i) {
		int rnd = rand();
		id.group_id = groups[rnd % groups_count];

		memcpy(id.id, &rnd, sizeof(rnd));

		struct dnet_net_state *st = dnet_state_get_first(node, &id);
		if (st) {
			route_list_states[(*states_count)++] = st;
		}
	}

	dnet_log(node, DNET_LOG_INFO, "Requesting route address from %llu remote addresses", node->route_addr_num);

	for (size_t i = 0; i < node->route_addr_num; ++i) {
		struct dnet_net_state *st = dnet_state_search_by_addr(node, &node->route_addr[i]);
		if (st) {
			route_list_states[(*states_count)++] = st;
		}
	}
	pthread_mutex_unlock(&node->reconnect_lock);

	return route_list_states;
}

static net_addr_list_ptr dnet_reconnect_victims(struct dnet_node *node, size_t *addrs_count, int *flags)
{
	*addrs_count = 0;

	pthread_mutex_lock(&node->reconnect_lock);

	net_addr_list_ptr addrs(reinterpret_cast<dnet_addr *>(calloc(node->reconnect_num, sizeof(dnet_addr))));

	if (!addrs) {
		pthread_mutex_unlock(&node->reconnect_lock);
		return addrs;
	}

	struct dnet_addr_storage *ast, *tmp;
	list_for_each_entry_safe(ast, tmp, &node->reconnect_list, reconnect_entry) {
		list_del_init(&ast->reconnect_entry);
		addrs[(*addrs_count)++] = ast->addr;

		if (ast->__join_state == DNET_JOIN)
			(*flags) |= DNET_CFG_JOIN_NETWORK;

		free(ast);
	}


	pthread_mutex_unlock(&node->reconnect_lock);

	return addrs;
}

void dnet_reconnect_and_check_route_table(dnet_node *node)
{
	size_t states_count = 0;
	size_t addrs_count = 0;
	int flags = 0;

	net_state_list_ptr states = dnet_check_route_table_victims(node, &states_count);
	net_addr_list_ptr addrs = dnet_reconnect_victims(node, &addrs_count, &flags);

	dnet_join_state join = DNET_WANT_RECONNECT;
	if (node->flags & DNET_CFG_JOIN_NETWORK)
		join = DNET_JOIN;

	const bool ask_route_list = !((node->flags | flags) & DNET_CFG_NO_ROUTE_LIST);

	bool all_exist = false;
	dnet_addr_socket_list *sockets = dnet_socket_create_addresses(node, addrs.get(), addrs_count, ask_route_list, join, &all_exist);
	if (!sockets) {
		addrs.reset();
	}

	if (states_count > 0 || sockets) {
		dnet_socket_connect(node, sockets, join, std::move(states), states_count);
	}
}

/*!
 * Parallelly adds all nodes from \a addrs to own route table.
 *
 * Each addition is performed in several steps:
 * \li Connect to specified addr
 * \li Send reverse lookup request
 * \li Receive reverse lookup reply
 * \li Send route-table request if needed (both \a flags and node's flags does not contain  DNET_CFG_NO_ROUTE_LIST)
 * \li Add all new addresses from route-list reply to the same queue
 */
int dnet_add_state(dnet_node *node, const dnet_addr *addrs, int num, int flags)
{
	const bool ask_route_list = !((node->flags | flags) & DNET_CFG_NO_ROUTE_LIST);

	if (num <= 0)
		return -EINVAL;

	dnet_join_state join = DNET_WANT_RECONNECT;
	if (node->flags & DNET_CFG_JOIN_NETWORK)
		join = DNET_JOIN;

	const size_t addrs_count = num;
	bool at_least_one_exist = false;
	dnet_addr_socket_list *sockets = dnet_socket_create_addresses(node, addrs, addrs_count, ask_route_list, join, &at_least_one_exist);
	if (!sockets) {
		// return 0 if we failed to connect to any remote node, but there is at least one node in local route table
		return at_least_one_exist ? 0 : -ENOMEM;
	}

	dnet_log(node, DNET_LOG_INFO, "Trying to connect to %llu states of %llu original", sockets->sockets_count, addrs_count);

	// sockets are freed by dnet_socket_connect
	int err = dnet_socket_connect(node, sockets, join, net_state_list_ptr(), 0);

	if (ask_route_list) {
		pthread_mutex_lock(&node->reconnect_lock);

		dnet_addr *tmp = reinterpret_cast<dnet_addr *>(realloc(node->route_addr, (addrs_count + node->route_addr_num) * sizeof(dnet_addr)));
		if (tmp) {
			const size_t old_count = node->route_addr_num;

			// Copy all addrs to explicit route addrs list
			node->route_addr = tmp;
			memcpy(node->route_addr + node->route_addr_num, addrs, sizeof(dnet_addr) * addrs_count);
			node->route_addr_num += addrs_count;

			// Remove all duplicates
			std::sort(node->route_addr, node->route_addr + node->route_addr_num);
			auto it = std::unique(node->route_addr, node->route_addr + node->route_addr_num);
			node->route_addr_num = it - node->route_addr;

			size_t added_count = node->route_addr_num - old_count;

			dnet_log(node, DNET_LOG_INFO, "Added %llu states to explicit route list", added_count);
		} else {
			dnet_log(node, DNET_LOG_INFO, "Failed to add %llu states to explicit route list, err: %d", addrs_count, -ENOMEM);
		}

		pthread_mutex_unlock(&node->reconnect_lock);
	}

	return at_least_one_exist ? std::max(0, err) : err;
}
