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
#include <sys/mman.h>
#include <sys/wait.h>

#include <ctype.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "elliptics.h"

#include "elliptics/packet.h"
#include "elliptics/interface.h"

int dnet_transform(struct dnet_node *n, void *src, uint64_t size, struct dnet_id *id)
{
	unsigned int dsize = sizeof(id->id);
	struct dnet_transform *t = &n->transform;

	return t->transform(t->priv, src, size, id->id, &dsize, 0);
}

static int dnet_lookup_reply(struct dnet_net_state *st, struct dnet_id *id, uint64_t trans,
		unsigned int aflags, struct dnet_addr *addr, int status)
{
	struct dnet_addr_cmd *c;
	int err;

	c = malloc(sizeof(struct dnet_addr_cmd));
	if (!c)
		return -ENOMEM;

	memset(c, 0, sizeof(struct dnet_addr_cmd));

	memcpy(&c->cmd.id, id, sizeof(struct dnet_id));
	c->cmd.size = sizeof(struct dnet_addr_cmd) - sizeof(struct dnet_cmd);
	c->cmd.status = status;
	c->cmd.trans = trans | DNET_TRANS_REPLY;

	c->a.cmd = DNET_CMD_LOOKUP;
	c->a.size = sizeof(struct dnet_addr_cmd) - sizeof(struct dnet_cmd) - sizeof(struct dnet_attr);
	c->a.flags = aflags;

	memcpy(&c->addr.addr, addr, sizeof(struct dnet_addr));
	c->addr.family = st->n->family;
	c->addr.sock_type = st->n->sock_type;
	c->addr.proto = st->n->proto;

	dnet_log(st->n, DNET_LOG_DSA, "%s: sending address %s: trans: %llu, aflags: %x.\n",
			dnet_dump_id(id), dnet_server_convert_dnet_addr(addr),
			(unsigned long long)trans, aflags);

	dnet_convert_addr_cmd(c);

	err = dnet_send(st, c, sizeof(struct dnet_addr_cmd));
	free(c);

	return err;
}

static int dnet_stat_local(struct dnet_net_state *st, struct dnet_id *id, int history)
{
	struct dnet_node *n = st->n;
	int size, cmd_size;
	struct dnet_cmd *cmd;
	struct dnet_attr *attr;
	struct dnet_io_attr *io;
	int err;

	size = 1;
	cmd_size = size + sizeof(struct dnet_cmd) +
		sizeof(struct dnet_attr) + sizeof(struct dnet_io_attr);

	cmd = malloc(cmd_size);
	if (!cmd) {
		dnet_log(n, DNET_LOG_ERROR, "%s: failed to allocate %d bytes for local stat.\n",
				dnet_dump_id(id), cmd_size);
		err = -ENOMEM;
		goto err_out_exit;
	}

	memset(cmd, 0, cmd_size);

	attr = (struct dnet_attr *)(cmd + 1);
	io = (struct dnet_io_attr *)(attr + 1);

	memcpy(&cmd->id, id, sizeof(struct dnet_id));
	cmd->size = cmd_size - sizeof(struct dnet_cmd);
	
	attr->size = cmd->size - sizeof(struct dnet_attr);
	attr->cmd = DNET_CMD_READ;

	io->size = attr->size - sizeof(struct dnet_io_attr);
	io->offset = 0;
	io->flags = DNET_IO_FLAGS_NO_HISTORY_UPDATE;

	if (history)
		io->flags |= DNET_IO_FLAGS_HISTORY;

	memcpy(io->parent, id->id, DNET_ID_SIZE);
	memcpy(io->id, id->id, DNET_ID_SIZE);

	dnet_log(n, DNET_LOG_INFO, "%s: local stat: reading %llu byte(s).\n",
			dnet_dump_id(&cmd->id), (unsigned long long)io->size);

	dnet_convert_io_attr(io);

	err = n->command_handler(st, n->command_private, cmd, attr, io);
	dnet_log(n, DNET_LOG_INFO, "%s: local stat: io_size: %llu, err: %d.\n",
					dnet_dump_id(&cmd->id),
					(unsigned long long)io->size, err);

	free(cmd);

err_out_exit:
	return err;
}

static int dnet_cmd_lookup(struct dnet_net_state *orig, struct dnet_cmd *cmd,
		struct dnet_attr *attr, void *data __unused)
{
	struct dnet_node *n = orig->n;
	struct dnet_state_id sid;
	struct dnet_id raw;
	int err;
	unsigned int aflags = 0;
	struct dnet_addr addr;

	err = dnet_state_search_id(n, &cmd->id, &sid, &addr);
	if (!err) {
		if (attr->flags & DNET_ATTR_LOOKUP_STAT) {
			err = dnet_stat_local(orig, &cmd->id, !!(attr->flags & DNET_ATTR_LOOKUP_HISTORY));
			dnet_log(n, DNET_LOG_DSA, "%s: %s object is stored locally: %s.\n", dnet_dump_id(&cmd->id),
					!!(attr->flags & DNET_ATTR_LOOKUP_HISTORY) ? "history" : "plain",
					err ? "no" : "yes");
			if (!err)
				aflags = attr->flags;
		}
	} else {
		memset(sid.raw.id, 0, DNET_ID_SIZE);
	}

	dnet_setup_id(&raw, cmd->id.group_id, sid.raw.id);

	return dnet_lookup_reply(orig, &raw, cmd->trans, aflags, &addr, err);
}

static int dnet_send_idc(struct dnet_net_state *orig, struct dnet_net_state *send, struct dnet_id *id, uint64_t trans,
		unsigned int command, int reply, int direct, int more)
{
	struct dnet_node *n = orig->n;
	void *buf;
	struct dnet_cmd *cmd;
	struct dnet_attr *attr;
	struct dnet_raw_id *sid;
	struct dnet_addr_attr *addr;
	int size = sizeof(struct dnet_addr_cmd) + orig->idc->id_num * sizeof(struct dnet_raw_id);
	int err, i;

	buf = malloc(size);
	if (!buf) {
		err = -ENOMEM;
		goto err_out_exit;
	}
	memset(buf, 0, sizeof(struct dnet_addr_cmd));

	cmd = buf;
	attr = (struct dnet_attr *)(cmd + 1);
	addr = (struct dnet_addr_attr *)(attr + 1);
	sid = (struct dnet_raw_id *)(addr + 1);

	memcpy(&cmd->id, id, sizeof(struct dnet_id));
	cmd->size = size - sizeof(struct dnet_cmd);
	cmd->trans = trans;

	if (more)
		cmd->flags |= DNET_FLAGS_MORE;
	if (direct)
		cmd->flags |= DNET_FLAGS_DIRECT;
	if (reply)
		cmd->trans |= DNET_TRANS_REPLY;

	attr->size = cmd->size - sizeof(struct dnet_attr);
	attr->cmd = command;

	addr->sock_type = n->sock_type;
	addr->family = n->family;
	addr->proto = n->proto;
	memcpy(&addr->addr, &orig->addr, sizeof(struct dnet_addr));

	for (i=0; i<orig->idc->id_num; ++i) {
		memcpy(&sid[i], &orig->idc->ids[i].raw, sizeof(struct dnet_raw_id));
		dnet_convert_raw_id(&sid[i]);
	}

	dnet_log(n, DNET_LOG_DSA, "%s: sending address %s\n", dnet_dump_id(id), dnet_state_dump_addr(orig));

	dnet_convert_addr_cmd(buf);

	err = dnet_send(send, buf, size);

	free(buf);

err_out_exit:
	return err;
}

static int dnet_cmd_reverse_lookup(struct dnet_net_state *st, struct dnet_cmd *cmd,
		struct dnet_attr *attr __unused, void *data __unused)
{
	cmd->id.group_id = st->n->st->idc->group->group_id;
	return dnet_send_idc(st->n->st, st, &cmd->id, cmd->trans, DNET_CMD_REVERSE_LOOKUP, 1, 0, 0);
}

static int dnet_check_connection(struct dnet_node *n, struct dnet_addr_attr *a)
{
	int s;

	s = dnet_socket_create_addr(n, a->sock_type, a->proto, a->family,
			(struct sockaddr *)a->addr.addr, a->addr.addr_len, 0);
	if (s < 0)
		return s;

	close(s);
	return 0;
}

static int dnet_cmd_join_client(struct dnet_net_state *st, struct dnet_cmd *cmd,
		struct dnet_attr *attr, void *data)
{
	struct dnet_node *n = st->n;
	struct dnet_addr_attr *a = data;
	struct dnet_raw_id *ids;
	int num, i, err;

	dnet_convert_addr_attr(a);

	dnet_log(n, DNET_LOG_DSA, "%s: accepted joining client (%s), requesting statistics.\n",
			dnet_dump_id(&cmd->id), dnet_server_convert_dnet_addr(&a->addr));
	err = dnet_check_connection(n, a);
	if (err) {
		dnet_log(n, DNET_LOG_ERROR, "%s: failed to request statistics from joining client (%s), dropping connection.\n",
				dnet_dump_id(&cmd->id), dnet_server_convert_dnet_addr(&a->addr));
		return err;
	}

	num = (attr->size - sizeof(struct dnet_addr_attr)) / sizeof(struct dnet_raw_id);
	ids = (struct dnet_raw_id *)(a + 1);
	for (i=0; i<num; ++i)
		dnet_convert_raw_id(&ids[0]);

	pthread_rwlock_wrlock(&n->state_lock);
	list_del_init(&st->state_entry);
	pthread_rwlock_unlock(&n->state_lock);

	memcpy(&st->addr, &a->addr, sizeof(struct dnet_addr));
	err = dnet_idc_create(st, cmd->id.group_id, ids, num);

	dnet_log(n, DNET_LOG_INFO, "%s: accepted join request from state %s: %d.\n", dnet_dump_id(&cmd->id),
		dnet_server_convert_dnet_addr(&a->addr), err);

	return err;
}

static int dnet_cmd_route_list(struct dnet_net_state *orig, struct dnet_cmd *cmd)
{
	struct dnet_node *n = orig->n;
	struct dnet_net_state *st;
	struct dnet_group *g;
	int err;

	pthread_rwlock_rdlock(&n->state_lock);
	list_for_each_entry(g, &n->group_list, group_entry) {
		list_for_each_entry(st, &g->state_list, state_entry) {
			err = -1;

			if (!memcmp(&st->addr, &orig->addr, sizeof(struct dnet_addr)))
				continue;

			cmd->id.group_id = g->group_id;
			err = dnet_send_idc(st, orig, &cmd->id, cmd->trans, DNET_CMD_ROUTE_LIST, 1, 0, 1);
			if (err)
				goto err_out_unlock;
		}
	}
	pthread_rwlock_unlock(&n->state_lock);

	return 0;

err_out_unlock:
	pthread_rwlock_unlock(&n->state_lock);
	return err;
}

static int dnet_cmd_exec(struct dnet_net_state *st, struct dnet_cmd *cmd,
		struct dnet_attr *attr, void *data)
{
	char *command = data;
	pid_t pid;
	int err;
	struct dnet_node *n = st->n;

	if (!attr->size)
		return 0;

	dnet_log(n, DNET_LOG_DSA, "%s: command: '%s'.\n", dnet_dump_id(&cmd->id), command);

	pid = fork();
	if (pid < 0) {
		err = -errno;
		dnet_log_err(n, "%s: failed to fork a child process", dnet_dump_id(&cmd->id));
		goto out_exit;
	}

	if (pid == 0) {
		err = system(command);
		exit(err);
	} else {
		int status;

		err = waitpid(pid, &status, 0);
		if (err < 0) {
			err = -errno;
			dnet_log_err(n,	"%s: failed to wait for child (%d) process",
					dnet_dump_id(&cmd->id), (int)pid);
			goto out_exit;
		}

		if (WIFEXITED(status))
			err = WEXITSTATUS(status);
		else if (WIFSIGNALED(status))
			err = -EPIPE;
	}

out_exit:
	return err;
}

static int dnet_cmd_stat_count_single(struct dnet_net_state *orig, struct dnet_cmd *cmd, struct dnet_net_state *st, struct dnet_addr_stat *as)
{
	struct dnet_attr ca;
	struct dnet_node *n = orig->n;
	int i;

	ca.cmd = DNET_CMD_STAT_COUNT;
	ca.size = 0;
	ca.flags = 0;

	memcpy(&as->addr, &st->addr, sizeof(struct dnet_addr));
	as->num = __DNET_CMD_MAX;

	dnet_log(n, DNET_LOG_DSA, "addr: %s, ptr: %p, orig: %p.\n", dnet_server_convert_dnet_addr(&as->addr), st, orig);
	for (i=0; i<as->num; ++i) {
		as->count[i] = st->stat[i];
		dnet_log(n, DNET_LOG_DSA, "  cmd: %d, count: %llu, err: %llu\n",
			i, (unsigned long long)as->count[i].count, (unsigned long long)as->count[i].err);
	}

	dnet_convert_addr_stat(as, as->num);

	return dnet_send_reply(orig, cmd, &ca, as, sizeof(struct dnet_addr_stat) + __DNET_CMD_MAX * sizeof(struct dnet_stat_count), 1);
}

static int dnet_cmd_stat_count(struct dnet_net_state *orig, struct dnet_cmd *cmd)
{
	struct dnet_node *n = orig->n;
	struct dnet_net_state *st;
	struct dnet_addr_stat *as;
	int err = 0;

	as = alloca(sizeof(struct dnet_addr_stat) + __DNET_CMD_MAX * sizeof(struct dnet_stat_count));
	if (!as) {
		err = -ENOMEM;
		goto err_out_exit;
	}

	pthread_rwlock_rdlock(&n->state_lock);
#if 0
	list_for_each_entry(st, &n->state_list, state_entry) {
		err = dnet_cmd_stat_count_single(orig, cmd, st, as);
		if (err)
			goto err_out_unlock;
	}
#endif	
	list_for_each_entry(st, &n->empty_state_list, state_entry) {
		err = dnet_cmd_stat_count_single(orig, cmd, st, as);
		if (err)
			goto err_out_unlock;
	}

err_out_unlock:
	pthread_rwlock_unlock(&n->state_lock);
err_out_exit:
	return err;
}

int dnet_process_cmd(struct dnet_net_state *st)
{
	return dnet_process_cmd_raw(st, &st->rcv_cmd, st->rcv_data);
}

int dnet_process_cmd_raw(struct dnet_net_state *st, struct dnet_cmd *cmd, void *data)
{
	int err = 0;
	unsigned long long size = cmd->size;
	struct dnet_node *n = st->n;
	unsigned long long tid = cmd->trans & ~DNET_TRANS_REPLY;

	while (size) {
		struct dnet_attr *a = data;
		unsigned long long sz;

		if (size < sizeof(struct dnet_attr)) {
			dnet_log(st->n, DNET_LOG_ERROR, "%s: invalid size: cmd_size: %llu, rest_size: %llu.\n",
					dnet_dump_id(&cmd->id), (unsigned long long)cmd->size, size);
			err = -EINVAL;
			break;
		}

		dnet_convert_attr(a);
		sz = a->size;

		data += sizeof(struct dnet_attr);
		size -= sizeof(struct dnet_attr);

		if (size < a->size) {
			dnet_log(st->n, DNET_LOG_ERROR, "%s: invalid size: cmd: %u, cmd_size: %llu, rest_size: %llu, attr_size: %llu.\n",
				dnet_dump_id(&cmd->id), a->cmd, (unsigned long long)cmd->size, size, sz);
			err = -EINVAL;
			break;
		}

		if (a->cmd != DNET_CMD_STAT_COUNT && a->cmd != DNET_CMD_STAT)
			dnet_log(n, DNET_LOG_INFO, "%s: trans: %llu, transaction_size_left: %llu, "
					"starting cmd: %u, attribute_size: %llu, attribute_flags: %x.\n",
					dnet_dump_id(&cmd->id), tid, size, a->cmd, (unsigned long long)a->size, a->flags);

		switch (a->cmd) {
			case DNET_CMD_LOOKUP:
				err = dnet_cmd_lookup(st, cmd, a, data);
				break;
			case DNET_CMD_REVERSE_LOOKUP:
				err = dnet_cmd_reverse_lookup(st, cmd, a, data);
				break;
			case DNET_CMD_JOIN:
				err = dnet_cmd_join_client(st, cmd, a, data);
				break;
			case DNET_CMD_ROUTE_LIST:
				err = dnet_cmd_route_list(st, cmd);
				break;
			case DNET_CMD_EXEC:
				err = dnet_cmd_exec(st, cmd, a, data);
				break;
			case DNET_CMD_STAT_COUNT:
				err = dnet_cmd_stat_count(st, cmd);
				break;
			case DNET_CMD_NOTIFY:
				if (!a->flags) {
					err = dnet_notify_add(st, cmd);
					/*
					 * We drop 'need ack' flag, since notification
					 * transaction is a long-living one, since
					 * every notification will be sent as transaction
					 * completion.
					 *
					 * Transaction acknowledge will be sent when
					 * notification is removed.
					 */
					if (!err)
						cmd->flags &= ~DNET_FLAGS_NEED_ACK;
				} else
					err = dnet_notify_remove(st, cmd, a);
				break;
			case DNET_CMD_LIST:
				err = dnet_db_list(st, cmd, a);
				break;
			case DNET_CMD_READ:
			case DNET_CMD_WRITE:
			case DNET_CMD_DEL:
				if (a->cmd == DNET_CMD_DEL) {
					err = dnet_db_del(n, cmd, a);
					if (err < 0)
						break;

					if (err == 0)
						break;

					/* if positive value returned we will delete data object */
				} else {
					struct dnet_io_attr *io;

					if (a->size < sizeof(struct dnet_io_attr)) {
						dnet_log(n, DNET_LOG_ERROR,
							"%s: wrong read attribute, size does not match "
								"IO attribute size: size: %llu, must be: %zu.\n",
								dnet_dump_id(&cmd->id), (unsigned long long)a->size,
								sizeof(struct dnet_io_attr));
						err = -EINVAL;
						break;
					}

					io = data;
					dnet_convert_io_attr(io);

					if ((io->flags & DNET_IO_FLAGS_HISTORY) || (io->flags & DNET_IO_FLAGS_META)) {
						if (a->cmd == DNET_CMD_READ) {
							err = dnet_db_read(st, cmd, io);
						} else if (a->cmd == DNET_CMD_WRITE) {
							err = dnet_db_write(n, cmd, io);
						} else
							err = -EINVAL;
						break;
					}

					dnet_convert_io_attr(io);
				}
			default:
				err = n->command_handler(st, n->command_private, cmd, a, data);
				if (err || (a->cmd != DNET_CMD_WRITE))
					break;

				err = dnet_db_write(n, cmd, data);
				if (err)
					break;

#if 0
				dnet_update_notify(st, cmd, a, data);
#endif
				break;
		}

		if (a->cmd != DNET_CMD_STAT_COUNT && a->cmd != DNET_CMD_STAT)
			dnet_log(n, DNET_LOG_INFO, "%s: trans: %llu, completed cmd: %u, err: %d.\n",
				dnet_dump_id(&cmd->id), tid, a->cmd, err);

		dnet_stat_inc(st->stat, a->cmd, err);

		if (err)
			break;

		if (size < sz) {
			dnet_log(st->n, DNET_LOG_ERROR, "%s: invalid size 2: cmd: %u, cmd_size: %llu, rest_size: %llu, attr_size: %llu.\n",
				dnet_dump_id(&cmd->id), a->cmd, (unsigned long long)cmd->size, size, sz);
			err = -EINVAL;
			break;
		}

		data += sz;
		size -= sz;
	}

	if (cmd->flags & DNET_FLAGS_NEED_ACK) {
		struct dnet_cmd ack;

		memcpy(&ack.id, &cmd->id, sizeof(struct dnet_id));
		ack.trans = cmd->trans | DNET_TRANS_REPLY;
		ack.size = 0;
		ack.flags = cmd->flags & ~(DNET_FLAGS_NEED_ACK | DNET_FLAGS_MORE);
		ack.status = err;

		dnet_log(n, DNET_LOG_NOTICE, "%s: ack trans: %llu, flags: %x, status: %d.\n",
				dnet_dump_id(&cmd->id), tid,
				ack.flags, err);

		dnet_convert_cmd(&ack);
		err = dnet_send(st, &ack, sizeof(struct dnet_cmd));
	}

	return err;
}

static int dnet_state_join(struct dnet_net_state *st)
{
	int err;
	struct dnet_node *n = st->n;
	struct dnet_id id;

	dnet_setup_id(&id, n->st->idc->group->group_id, st->idc->ids[0].raw.id);

	err = dnet_send_idc(n->st, st, &id, 0, DNET_CMD_JOIN, 0, 1, 0);
	if (err) {
		dnet_log(n, DNET_LOG_ERROR, "%s: failed to send join request to %s.\n",
			dnet_dump_id(&id), dnet_server_convert_dnet_addr(&st->addr));
		goto out_exit;
	}

	st->__join_state = DNET_JOIN;
	dnet_log(n, DNET_LOG_INFO, "%s: successfully joined network, group %d.\n", dnet_dump_id(&id), id.group_id);

out_exit:
	return err;
}

static int dnet_add_received_state(struct dnet_node *n, struct dnet_addr_attr *a,
		int group_id, struct dnet_raw_id *ids, int id_num, int join)
{
	int s, err = 0;
	struct dnet_net_state *nst;
	struct dnet_state_id sid;
	struct dnet_id raw;

	dnet_setup_id(&raw, group_id, ids[0].id);

	err = dnet_state_search_id(n, &raw, &sid, NULL);
	if (!err && !memcmp(&sid.raw, &ids[0], sizeof(struct dnet_raw_id)))
		return 0;

	s = dnet_socket_create_addr(n, a->sock_type, a->proto, a->family,
			(struct sockaddr *)&a->addr.addr, a->addr.addr_len, 0);
	if (s < 0) {
		err = s;
		goto err_out_exit;
	}

	nst = dnet_state_create(n, group_id, ids, id_num, &a->addr, s);
	if (!nst) {
		err = -EINVAL;
		goto err_out_close;
	}

	nst->__join_state = DNET_WANT_RECONNECT;

	if (join) {
		err = dnet_state_join(nst);
		if (err)
			goto err_out_put;
	}

	dnet_log(n, DNET_LOG_INFO, "%d: added received state %s.\n",
			group_id, dnet_state_dump_addr(nst));

	return 0;

err_out_put:
	dnet_state_put(nst);
	return err;

err_out_close:
	close(s);
err_out_exit:
	return err;
}


static int dnet_recv_route_list_complete(struct dnet_net_state *st, struct dnet_cmd *cmd,
		struct dnet_attr *attr, void *priv __unused)
{
	struct dnet_addr_attr *a;
	struct dnet_node *n;
	struct dnet_raw_id *ids;
	int err, num, i;

	if (!st || !cmd || !attr) {
		err = -EINVAL;
		goto err_out_exit;
	}

	n = st->n;

	err = cmd->status;
	if (!cmd->size || err)
		goto err_out_exit;

	a = (struct dnet_addr_attr *)(attr + 1);
	dnet_convert_addr_attr(a);

	num = (attr->size - sizeof(struct dnet_addr_attr)) / sizeof(struct dnet_raw_id);
	dnet_log(n, DNET_LOG_DSA, "%s: route list: %d entries.\n", dnet_dump_id(&cmd->id), num);

	if (!num)
		goto err_out_exit;

	ids = (struct dnet_raw_id *)(a + 1);
	for (i=0; i<num; ++i)
		dnet_convert_raw_id(&ids[0]);

	err = dnet_add_received_state(n, a, cmd->id.group_id, ids, num, st->__join_state & DNET_JOIN);

err_out_exit:
	return err;
}

static int dnet_recv_route_list(struct dnet_net_state *st)
{
	struct dnet_node *n = st->n;
	struct dnet_trans *t;
	struct dnet_cmd *cmd;
	struct dnet_attr *a;
	int err;

	t = dnet_trans_alloc(n, sizeof(struct dnet_cmd) + sizeof(struct dnet_attr));
	if (!t) {
		err = -ENOMEM;
		goto err_out_exit;
	}

	t->complete = dnet_recv_route_list_complete;
	
	cmd = (struct dnet_cmd *)(t + 1);
	a = (struct dnet_attr *)(cmd + 1);

	dnet_setup_id(&cmd->id, st->idc->group->group_id, st->idc->ids[0].raw.id);
	cmd->size = sizeof(struct dnet_attr);
	cmd->flags = DNET_FLAGS_NEED_ACK | DNET_FLAGS_DIRECT;
	cmd->status = 0;

	memcpy(&t->cmd, cmd, sizeof(struct dnet_cmd));

	a->cmd = DNET_CMD_ROUTE_LIST;
	a->size = 0;
	a->flags = 0;

	t->st = dnet_state_get(st);

	err = dnet_trans_insert(t);
	if (err)
		goto err_out_destroy;

	cmd->trans = t->trans;
	dnet_convert_cmd(cmd);
	dnet_convert_attr(a);

	dnet_log(n, DNET_LOG_DSA, "%s: list route request to %s.\n", dnet_dump_id(&cmd->id),
		dnet_server_convert_dnet_addr(&st->addr));

	err = dnet_send(st, cmd, sizeof(struct dnet_attr) + sizeof(struct dnet_cmd));
	if (err)
		goto err_out_destroy;

	return 0;

err_out_destroy:
	dnet_trans_put(t);
err_out_exit:
	return err;
}

int dnet_join(struct dnet_node *n)
{
	int err = 0;
	struct dnet_net_state *st;
	struct dnet_group *g;

	if (!n->command_handler) {
		dnet_log(n, DNET_LOG_ERROR, "Can not join without command handler.\n");
		return -EINVAL;
	}

	pthread_rwlock_rdlock(&n->state_lock);
	list_for_each_entry(g, &n->group_list, group_entry) {
		list_for_each_entry(st, &g->state_list, state_entry) {
			if (st == n->st)
				continue;

			err = dnet_state_join(st);
		}
	}
	pthread_rwlock_unlock(&n->state_lock);

	return err;
}

static struct dnet_net_state *dnet_add_state_socket(struct dnet_node *n, struct dnet_addr *addr, int s)
{
	struct dnet_net_state *st, dummy;
	char buf[sizeof(struct dnet_addr_cmd)];
	struct dnet_cmd *cmd;
	struct dnet_attr *a;
	struct dnet_addr_attr *aa;
	int err, num, i, size;
	struct dnet_raw_id *ids;

	memset(buf, 0, sizeof(buf));

	cmd = (struct dnet_cmd *)(buf);
	a = (struct dnet_attr *)(cmd + 1);

	cmd->flags = DNET_FLAGS_DIRECT;
	cmd->size = sizeof(struct dnet_attr);
	a->cmd = DNET_CMD_REVERSE_LOOKUP;

	dnet_convert_cmd(cmd);
	dnet_convert_attr(a);

	st = &dummy;
	memset(st, 0, sizeof(struct dnet_net_state));

	st->s = s;
	st->n = n;
	st->timeout = n->wait_ts.tv_sec * 1000;

	err = dnet_send(st, buf, sizeof(struct dnet_cmd) + sizeof(struct dnet_attr));
	if (err) {
		dnet_log(n, DNET_LOG_ERROR, "Failed to send reverse "
				"lookup message to %s, err: %d.\n",
				dnet_server_convert_dnet_addr(addr), err);
		goto err_out_exit;
	}

	err = dnet_recv(st, buf, sizeof(buf));
	if (err) {
		dnet_log(n, DNET_LOG_ERROR, "Failed to receive reverse "
				"lookup headers from %s, err: %d.\n",
				dnet_server_convert_dnet_addr(addr), err);
		goto err_out_exit;
	}

	cmd = (struct dnet_cmd *)(buf);
	a = (struct dnet_attr *)(cmd + 1);
	aa = (struct dnet_addr_attr *)(a + 1);

	dnet_convert_addr_cmd((struct dnet_addr_cmd *)buf);

	size = a->size - sizeof(struct dnet_addr_attr);
	num = size / sizeof(struct dnet_raw_id);

	dnet_log(n, DNET_LOG_DSA, "%s: waiting for %d ids\n", dnet_dump_id(&cmd->id), num);

	ids = malloc(size);
	if (!ids) {
		err = -ENOMEM;
		goto err_out_exit;
	}

	err = dnet_recv(st, ids, size);
	if (err) {
		dnet_log(n, DNET_LOG_ERROR, "Failed to receive reverse "
				"lookup body (%llu bytes) from %s, err: %d.\n",
				(unsigned long long)a->size,
				dnet_server_convert_dnet_addr(addr), err);
		goto err_out_exit;
	}

	for (i=0; i<num; ++i)
		dnet_convert_raw_id(&ids[i]);

	st = dnet_state_create(n, cmd->id.group_id, ids, num, addr, s);
	if (!st) {
		err = -EINVAL;
		goto err_out_free;
	}
	free(ids);

	st->__join_state = DNET_WANT_RECONNECT;

	return st;

err_out_free:
	free(ids);
err_out_exit:
	return NULL;
}

int dnet_add_state(struct dnet_node *n, struct dnet_config *cfg)
{
	int s, err;
	struct dnet_addr addr;
	struct dnet_net_state *st;

	addr.addr_len = sizeof(addr.addr);
	s = dnet_socket_create(n, cfg, (struct sockaddr *)&addr.addr, &addr.addr_len, 0);
	if (s < 0) {
		err = s;
		goto err_out_reconnect;
	}

	st = dnet_add_state_socket(n, &addr, s);
	if (!st) {
		err = -EINVAL;
		goto err_out_sock_close;
	}

	if (!(cfg->join & DNET_NO_ROUTE_LIST))
		dnet_recv_route_list(st);

	return 0;

err_out_sock_close:
	close(s);
err_out_reconnect:
	if ((err == -EADDRINUSE) || (err == -ECONNREFUSED) ||
			(err == -EINPROGRESS) || (err == -EAGAIN))
		dnet_add_reconnect_state(n, &addr, cfg->join | DNET_WANT_RECONNECT);
	return err;
}

static void dnet_io_complete(struct dnet_wait *w, int status)
{
	if (status)
		w->status = status;
	w->cond++;
}

static int dnet_write_complete(struct dnet_net_state *st, struct dnet_cmd *cmd,
		struct dnet_attr *attr __unused, void *priv)
{
	int err = -EINVAL;

	if (!cmd || !cmd->status || cmd->size == 0) {
		struct dnet_wait *w = priv;

		if (cmd && st) {
			err = cmd->status;
			dnet_log(st->n, DNET_LOG_DSA, "%s: object write completed: trans: %llu, status: %d.\n",
				dnet_dump_id(&cmd->id), (unsigned long long)(cmd->trans & ~DNET_TRANS_REPLY),
				cmd->status);
		}

		dnet_wakeup(w, dnet_io_complete(w, err));
		dnet_wait_put(w);
	} else
		err = cmd->status;

	return 0;
}

static struct dnet_trans *dnet_io_trans_create(struct dnet_node *n, struct dnet_io_control *ctl)
{
	struct dnet_trans *t;
	int err;
	struct dnet_attr *a;
	struct dnet_io_attr *io;
	struct dnet_cmd *cmd;
	uint64_t size = ctl->io.size;
	uint64_t tsize = sizeof(struct dnet_attr) +
			sizeof(struct dnet_io_attr) +
			sizeof(struct dnet_cmd);

	if (ctl->cmd == DNET_CMD_READ)
		size = 0;

	if (ctl->asize && ctl->adata) {
		if (ctl->asize < sizeof(struct dnet_attr)) {
			dnet_log(n, DNET_LOG_ERROR, "%s: additional attribute size (%u) has to be "
					"larger or equal than %zu bytes (struct dnet_attr).\n",
					dnet_dump_id(&ctl->id), ctl->asize, sizeof(struct dnet_attr));
			err = -EINVAL;
			goto err_out_complete_destroy;
		}

		a = ctl->adata;

		if (a->size != ctl->asize - sizeof(struct dnet_attr)) {
			dnet_log(n, DNET_LOG_ERROR, "%s: additional attribute size (%llu) does not match "
					"structure's attribute size %llu.\n",
					dnet_dump_id(&ctl->id),
					(unsigned long long)ctl->asize - sizeof(struct dnet_attr),
					(unsigned long long)a->size);
			err = -EINVAL;
			goto err_out_complete_destroy;
		}

		tsize += ctl->asize;
	}

	if (ctl->fd < 0 && size < DNET_COPY_IO_SIZE)
		tsize += size;

	t = dnet_trans_alloc(n, tsize);
	if (!t) {
		err = -ENOMEM;
		goto err_out_complete_destroy;
	}
	t->complete = ctl->complete;
	t->priv = ctl->priv;

	cmd = (struct dnet_cmd *)(t + 1);
	a = (struct dnet_attr *)(cmd + 1);

	if (ctl->asize && ctl->adata) {
		memcpy(a, ctl->adata, ctl->asize);

		dnet_convert_attr(a);
		a = (struct dnet_attr *)(((void *)a) + ctl->asize);
	}

	io = (struct dnet_io_attr *)(a + 1);

	if (ctl->fd < 0 && size < DNET_COPY_IO_SIZE) {
		if (size) {
			void *data = io + 1;
			memcpy(data, ctl->data, size);
		}
	}

	memcpy(&cmd->id, &ctl->id, sizeof(struct dnet_id));
	cmd->size = sizeof(struct dnet_attr) + sizeof(struct dnet_io_attr) + size + ctl->asize;
	cmd->flags = ctl->cflags;
	cmd->status = 0;

	a->cmd = ctl->cmd;
	a->size = sizeof(struct dnet_io_attr) + size;
	a->flags = ctl->aflags;

	memcpy(io, &ctl->io, sizeof(struct dnet_io_attr));

	memcpy(&t->cmd, cmd, sizeof(struct dnet_cmd));

	t->st = dnet_state_get_first(n, &cmd->id);
	if (!t->st) {
		dnet_log(n, DNET_LOG_ERROR, "%s: failed to find a state.\n", dnet_dump_id(&cmd->id));
		goto err_out_destroy;
	}

	err = dnet_trans_insert(t);
	if (err)
		goto err_out_destroy;

	cmd->trans = t->trans;
	dnet_convert_cmd(cmd);
	dnet_convert_attr(a);
	dnet_convert_io_attr(io);

	dnet_log(n, DNET_LOG_INFO, "%s: created trans: %llu, cmd: %u, size: %llu, offset: %llu, fd: %d, local_offset: %llu -> %s.\n",
			dnet_dump_id(&ctl->id),
			(unsigned long long)t->trans, ctl->cmd,
			(unsigned long long)ctl->io.size, (unsigned long long)ctl->io.offset,
			ctl->fd,
			(unsigned long long)ctl->local_offset,
			dnet_server_convert_dnet_addr(&t->st->addr));

	if (ctl->fd >= 0) {
		err = dnet_send_fd(t->st, cmd, tsize, ctl->fd, ctl->local_offset, size);
	} else {
		if (size < DNET_COPY_IO_SIZE)
			err = dnet_send(t->st, cmd, tsize);
		else
			err = dnet_send_data(t->st, cmd, tsize, ctl->data, size);
	}

	return t;

err_out_complete_destroy:
	if (ctl->complete)
		ctl->complete(NULL, NULL, NULL, ctl->priv);
	goto err_out_exit;

err_out_destroy:
	dnet_trans_put(t);
err_out_exit:
	return NULL;
}

int dnet_trans_create_send_all(struct dnet_node *n, struct dnet_io_control *ctl)
{
	struct dnet_trans *t;
	int num = 0, i;

	pthread_mutex_lock(&n->group_lock);
	for (i=0; i<n->group_num; ++i) {
		ctl->id.group_id = n->groups[i];

		t = dnet_io_trans_create(n, ctl);
		if (!t) {
			dnet_log(n, DNET_LOG_ERROR, "%s: failed to create and send transaction.\n", dnet_dump_id(&ctl->id));
			continue;
		}

		num++;
	}
	pthread_mutex_unlock(&n->group_lock);

	if (!num) {
		t = dnet_io_trans_create(n, ctl);
		if (!t) {
			dnet_log(n, DNET_LOG_ERROR, "%s: failed to create and send transaction (after n->groups loop).\n", dnet_dump_id(&ctl->id));
		} else {
			num++;
		}
	}

	return num;
}

int dnet_write_object(struct dnet_node *n, struct dnet_io_control *ctl,
		void *remote, unsigned int len, struct dnet_id *id, int hupdate)
{
	struct dnet_io_control hctl;
	struct dnet_history_entry e;
	uint32_t flags = ctl->io.flags | DNET_IO_FLAGS_PARENT;
	struct dnet_id raw;
	int err, num;

	if (id) {
		memcpy(ctl->io.parent, id->id, DNET_ID_SIZE);
	} else {
		id = &raw;
		dnet_transform(n, remote, len, &raw);
		memcpy(ctl->io.parent, raw.id, DNET_ID_SIZE);
	}

	if (ctl->aflags & DNET_ATTR_DIRECT_TRANSACTION) {
		memcpy(ctl->io.id, ctl->io.parent, DNET_ID_SIZE);
	} else {
		dnet_transform(n, ctl->data, ctl->io.size, &raw);
		memcpy(ctl->io.id, raw.id, DNET_ID_SIZE);
	}
	memcpy(&ctl->id, id, sizeof(struct dnet_id));

	err = dnet_trans_create_send_all(n, ctl);
	if (err <= 0)
		goto err_out_exit;
	num = err;

	if (!hupdate || (ctl->aflags & DNET_ATTR_DIRECT_TRANSACTION))
		return num;

	memset(&hctl, 0, sizeof(hctl));

	dnet_setup_id(&hctl.id, id->group_id, ctl->io.parent);
	memcpy(hctl.io.parent, ctl->io.parent, DNET_ID_SIZE);
	memcpy(hctl.io.id, ctl->io.parent, DNET_ID_SIZE);

	dnet_setup_history_entry(&e, ctl->io.id, ctl->io.size, ctl->io.offset, NULL, flags);

	hctl.priv = ctl->priv;
	hctl.complete = ctl->complete;
	hctl.cmd = DNET_CMD_WRITE;
	hctl.aflags = 0;
	hctl.cflags = DNET_FLAGS_NEED_ACK;
	hctl.fd = -1;
	hctl.local_offset = 0;
	hctl.adata = NULL;
	hctl.asize = 0;

	hctl.data = &e;

	hctl.io.size = sizeof(struct dnet_history_entry);
	hctl.io.offset = 0;
	hctl.io.flags = flags | DNET_IO_FLAGS_HISTORY | DNET_IO_FLAGS_APPEND;

	err = dnet_trans_create_send_all(n, &hctl);
	if (err <= 0)
		goto err_out_exit;

	num += err;

	return num;

err_out_exit:
	return err;
}

int dnet_write_file_local_offset(struct dnet_node *n, char *file,
		void *remote, unsigned int remote_len, struct dnet_id *id,
		uint64_t local_offset, uint64_t offset, uint64_t size,
		unsigned int aflags, unsigned int ioflags)
{
	int fd, err, trans_num;
	struct stat stat;
	struct dnet_wait *w;
	struct dnet_io_control ctl;
	long page_size = sysconf(_SC_PAGE_SIZE);
	void *data;
	uint64_t off = 0;

	w = dnet_wait_alloc(0);
	if (!w) {
		err = -ENOMEM;
		dnet_log(n, DNET_LOG_ERROR, "Failed to allocate read waiting structure.\n");
		goto err_out_exit;
	}

	fd = open(file, O_RDONLY | O_LARGEFILE);
	if (fd < 0) {
		err = -errno;
		dnet_log_err(n, "Failed to open to be written file '%s'", file);
		goto err_out_put;
	}

	err = fstat(fd, &stat);
	if (err) {
		err = -errno;
		dnet_log_err(n, "Failed to stat to be written file '%s'", file);
		goto err_out_close;
	}

	if (local_offset >= (uint64_t)stat.st_size) {
		err = 0;
		goto err_out_close;
	}

	if (!size || size + local_offset >= (uint64_t)stat.st_size)
		size = stat.st_size - local_offset;

	memset(&ctl, 0, sizeof(struct dnet_io_control));

	off = local_offset & ~(page_size - 1);

	data = mmap(NULL, ALIGN(size + local_offset - off, page_size), PROT_READ, MAP_SHARED, fd, off);
	if (data == MAP_FAILED) {
		err = -errno;
		dnet_log_err(n, "Failed to map to be written file '%s', "
				"size: %llu, use: %llu, local offset: %llu, use: %llu",
				file, (unsigned long long)size,
				(unsigned long long)ALIGN(size + local_offset - off, page_size),
				(unsigned long long)local_offset, (unsigned long long)off);
		goto err_out_close;
	}

	atomic_set(&w->refcnt, INT_MAX);

	ctl.data = data + local_offset - off;
	ctl.fd = fd;
	ctl.local_offset = local_offset;

	dnet_log(n, DNET_LOG_DSA, "data: %p, ctl.data: %p, local offset: %llu/%llu, remote offset: %llu, size: %llu/%llu\n",
			data, ctl.data, (unsigned long long)local_offset, (unsigned long long)off,
			(unsigned long long)offset,
			(unsigned long long)size, (unsigned long long)ALIGN(size, page_size));

	ctl.complete = dnet_write_complete;
	ctl.priv = w;

	ctl.cflags = DNET_FLAGS_NEED_ACK;
	ctl.cmd = DNET_CMD_WRITE;
	ctl.aflags = aflags;

	ctl.io.flags = ioflags;
	ctl.io.size = size;
	ctl.io.offset = offset;

	trans_num = dnet_write_object(n, &ctl, remote, remote_len, id,
			!(ioflags & (DNET_IO_FLAGS_HISTORY | DNET_IO_FLAGS_NO_HISTORY_UPDATE | DNET_IO_FLAGS_META)));
	dnet_log(n, DNET_LOG_DSA, "%s: transactions sent: %d, err: %d.\n",
			dnet_dump_id(&ctl.id), trans_num, err);

	if (trans_num < 0)
		trans_num = 0;

	/*
	 * 1 - the first reference counter we grabbed at allocation time
	 */
	atomic_sub(&w->refcnt, INT_MAX - trans_num - 1);

	munmap(data, ALIGN(size, page_size));

	if ((trans_num > 0) && ((n->groups && n->group_num) || (remote_len && remote))) {
		err = dnet_create_write_metadata(n, &ctl.id, remote, remote_len, n->groups, n->group_num);
		if (err < 0) {
			dnet_log(n, DNET_LOG_ERROR, "Failed to write metadata for file '%s' into the storage, transactions: %d, err: %d.\n", file, trans_num, err);
			goto err_out_close;
		}

		if (trans_num > 1 && !(ioflags & (DNET_IO_FLAGS_HISTORY | DNET_IO_FLAGS_NO_HISTORY_UPDATE | DNET_IO_FLAGS_META))) {
			struct dnet_id raw;

			dnet_setup_id(&raw, ctl.id.group_id, ctl.io.parent);

			err = dnet_create_write_metadata(n, &raw, remote, remote_len, n->groups, n->group_num);
			if (err < 0) {
				dnet_log(n, DNET_LOG_ERROR, "Failed to write history metadata for file '%s' into the storage, transactions: %d, err: %d.\n", file, trans_num, err);
				goto err_out_close;
			}
		}
	}

	err = dnet_wait_event(w, w->cond == trans_num, &n->wait_ts);
	if (err || w->status) {
		if (!err)
			err = w->status;
	}

	if (!err && !trans_num)
		err = -EINVAL;

	if (err) {
		dnet_log(n, DNET_LOG_ERROR, "Failed to write file '%s' into the storage, transactions: %d, err: %d.\n", file, trans_num, err);
		goto err_out_close;
	}

	dnet_log(n, DNET_LOG_NOTICE, "Successfully wrote file: '%s' into the storage, size: %llu.\n",
			file, (unsigned long long)size);

	close(fd);
	dnet_wait_put(w);

	return 0;

err_out_close:
	close(fd);
err_out_put:
	dnet_wait_put(w);
err_out_exit:
	return err;
}

int dnet_write_file(struct dnet_node *n, char *file, void *remote, unsigned int len,
		struct dnet_id *id, uint64_t offset, uint64_t size, unsigned int aflags)
{
	return dnet_write_file_local_offset(n, file, remote, len, id, offset, offset, size, aflags, 0);
}

static int dnet_read_complete(struct dnet_net_state *st, struct dnet_cmd *cmd, struct dnet_attr *a, void *priv)
{
	int fd, err, freeing = 0;
	struct dnet_node *n;
	struct dnet_io_completion *c = priv;
	struct dnet_io_attr *io;
	void *data;

	if (!st || !cmd) {
		err = -ENOMEM;
		freeing = 1;
		goto err_out_exit;
	}

	n = st->n;

	freeing = !(cmd->flags & DNET_FLAGS_MORE);

	if (cmd->status != 0 || cmd->size == 0) {
		err = cmd->status;

		dnet_log(n, DNET_LOG_NOTICE, "%s: read completed: file: '%s', status: %d, freeing: %d.\n",
				dnet_dump_id(&cmd->id), c->file, cmd->status, freeing);
		goto err_out_exit;
	}

	if (cmd->size <= sizeof(struct dnet_attr) + sizeof(struct dnet_io_attr)) {
		dnet_log(n, DNET_LOG_ERROR, "%s: read completion error: wrong size: cmd_size: %llu, must be more than %zu.\n",
				dnet_dump_id(&cmd->id), (unsigned long long)cmd->size,
				sizeof(struct dnet_attr) + sizeof(struct dnet_io_attr));
		err = -EINVAL;
		goto err_out_exit;
	}

	if (!a) {
		dnet_log(n, DNET_LOG_ERROR, "%s: no attributes but command size is not null.\n", dnet_dump_id(&cmd->id));
		err = -EINVAL;
		goto err_out_exit;
	}

	io = (struct dnet_io_attr *)(a + 1);
	data = io + 1;

	dnet_convert_attr(a);
	dnet_convert_io_attr(io);

	fd = open(c->file, O_RDWR | O_CREAT, 0644);
	if (fd < 0) {
		err = -errno;
		dnet_log_err(n, "%s: failed to open read completion file '%s'", dnet_dump_id(&cmd->id), c->file);
		goto err_out_exit;
	}

	err = pwrite(fd, data, io->size, c->offset);
	if (err <= 0) {
		err = -errno;
		dnet_log_err(n, "%s: failed to write data into completion file '%s'", dnet_dump_id(&cmd->id), c->file);
		goto err_out_close;
	}

	close(fd);
	dnet_log(n, DNET_LOG_NOTICE, "%s: read completed: file: '%s', offset: %llu, size: %llu, status: %d.\n",
			dnet_dump_id(&cmd->id), c->file, (unsigned long long)c->offset,
			(unsigned long long)io->size, cmd->status);

	return cmd->status;

err_out_close:
	dnet_log(n, DNET_LOG_ERROR, "%s: read completed: file: '%s', offset: %llu, size: %llu, status: %d, err: %d.\n",
			dnet_dump_id(&cmd->id), c->file, (unsigned long long)io->offset,
			(unsigned long long)io->size, cmd->status, err);
	close(fd);
err_out_exit:
	if (freeing) {
		if (c->wait) {
			int destroy = atomic_dec_and_test(&c->wait->refcnt);

			dnet_wakeup(c->wait, c->wait->cond = err);

			if (destroy)
				dnet_wait_destroy(c->wait);
		}

		free(c);
	}
	return err;
}

int dnet_read_object(struct dnet_node *n, struct dnet_io_control *ctl)
{
	if (!dnet_io_trans_create(n, ctl)) {
		dnet_log(n, DNET_LOG_ERROR, "%s: failed to read object.\n",
				dnet_dump_id(&ctl->id));
		return -EINVAL;
	}

	return 0;
}

int dnet_read_file_id(struct dnet_node *n, char *file, unsigned int len,
		int direct, uint64_t write_offset, uint64_t io_offset, uint64_t io_size,
		struct dnet_id *id, struct dnet_wait *w, int hist, int wait)
{
	struct dnet_io_control ctl;
	struct dnet_io_completion *c;
	int err, wait_init = ~0;

	memset(&ctl, 0, sizeof(struct dnet_io_control));

	ctl.io.size = io_size;
	ctl.io.offset = io_offset;
	if (hist)
		ctl.io.flags = DNET_IO_FLAGS_HISTORY;

	memcpy(ctl.io.parent, id->id, DNET_ID_SIZE);
	memcpy(ctl.io.id, id->id, DNET_ID_SIZE);

	memcpy(&ctl.id, id, sizeof(struct dnet_id));

	ctl.fd = -1;
	ctl.complete = dnet_read_complete;
	ctl.cmd = DNET_CMD_READ;
	ctl.cflags = DNET_FLAGS_NEED_ACK;

	if (direct)
		ctl.cflags |= DNET_FLAGS_DIRECT;

	c = malloc(sizeof(struct dnet_io_completion) + len + 1 + sizeof(DNET_HISTORY_SUFFIX));
	if (!c) {
		dnet_log(n, DNET_LOG_ERROR, "%s: failed to allocate IO completion structure "
				"for '%s' file reading.\n",
				dnet_dump_id(&ctl.id), file);
		err = -ENOMEM;
		goto err_out_exit;
	}

	memset(c, 0, sizeof(struct dnet_io_completion) + len + 1 + sizeof(DNET_HISTORY_SUFFIX));

	c->wait = dnet_wait_get(w);
	c->offset = write_offset;
	c->file = (char *)(c + 1);

	if (hist)
		sprintf(c->file, "%s%s", file, DNET_HISTORY_SUFFIX);
	else
		sprintf(c->file, "%s", file);

	ctl.priv = c;

	w->cond = wait_init;
	err = dnet_read_object(n, &ctl);
	if (err)
		goto err_out_exit;

	if (wait) {
		err = dnet_wait_event(w, w->cond != wait_init, &n->wait_ts);
		if (err || (w->cond != 0 && w->cond != wait_init)) {
			if (!err)
				err = w->cond;
			dnet_log(n, DNET_LOG_ERROR, "%s: failed to wait for '%s' read completion, err: %d.\n",
					dnet_dump_id(&ctl.id), file, err);
			goto err_out_exit;
		}
	}

	return 0;

err_out_exit:
	return err;
}

struct dnet_map_private
{
	char				*file;
	int				len;

	int				direct;
	struct dnet_id			id;

	struct dnet_node		*node;

	struct dnet_wait		*wait;
};

static int dnet_trans_map_callback(void *priv, uint64_t offset, uint64_t size,
		struct dnet_history_entry *e)
{
	struct dnet_map_private *p = priv;
	int err;

	dnet_setup_id(&p->id, p->id.group_id, e->id);

	err = dnet_read_file_id(p->node, p->file, p->len, p->direct, offset, offset - e->offset, size, &p->id, p->wait, 0, 0);

	dnet_log(p->node, DNET_LOG_NOTICE, "%s: reading chunk into file '%s', direct: %d, write_offset: %llu, io_offset: %llu, io_size: %llu, err: %d.\n",
			dnet_dump_id(&p->id), p->file, p->direct,
			(unsigned long long)offset, (unsigned long long)offset - e->offset,
			(unsigned long long)size, err);

	return err;
}

struct dnet_map_entry
{
	struct rb_node			map_entry;
	uint64_t			offset, size;
};

struct dnet_map_root
{
	struct rb_root			root;

	uint64_t			offset, size;

	int				(* callback)(	void *priv,
							uint64_t moffset, uint64_t msize,
							struct dnet_history_entry *io);
	void				*priv;
};

static int dnet_trans_map_cmp(uint64_t old_offset, uint64_t old_size,
		uint64_t offset, uint64_t size)
{
	if (offset + size <= old_offset)
		return -1;

	if (offset >= old_offset + old_size)
		return 1;

	return 0;
}

static int dnet_trans_map_add_range_raw(struct rb_root *root, struct dnet_map_entry *new)
{
	struct rb_node **n = &root->rb_node, *parent = NULL;
	struct dnet_map_entry *m;
	int cmp;

	while (*n) {
		parent = *n;

		m = rb_entry(parent, struct dnet_map_entry, map_entry);

		cmp = dnet_trans_map_cmp(m->offset, m->size, new->offset, new->size);
		if (cmp < 0)
			n = &parent->rb_left;
		else if (cmp > 0)
			n = &parent->rb_right;
		else
			return -EEXIST;
	}

	rb_link_node(&new->map_entry, parent, n);
	rb_insert_color(&new->map_entry, root);
	return 0;	
}

static int dnet_trans_map_add_range(struct dnet_map_root *r, uint64_t offset, uint64_t size)
{
	struct rb_root *root = &r->root;
	struct dnet_map_entry *m;
	int err = -ENOMEM;

	m = malloc(sizeof(struct dnet_map_entry));
	if (!m)
		goto err_out_exit;

	m->offset = offset;
	m->size = size;

	err = dnet_trans_map_add_range_raw(root, m);
	if (err)
		goto err_out_free;

	return 0;

err_out_free:
	free(m);
err_out_exit:
	return err;
}

static void dnet_trans_map_free(struct dnet_map_root *r)
{
	struct rb_node *n;
	struct dnet_map_entry *m;

	for (n = rb_first(&r->root); n; ) {
		m = rb_entry(n, struct dnet_map_entry, map_entry);

		n = rb_next(n);

		free(m);
	}
}

static int dnet_trans_map_match(struct dnet_node *node, struct dnet_map_root *r, struct dnet_history_entry *a)
{
	struct rb_root *root = &r->root;
	struct rb_node *n;
	struct dnet_map_entry *m;
	int cmp, err;

again:
	n = root->rb_node;
	cmp = 1;

	while (n) {
		m = rb_entry(n, struct dnet_map_entry, map_entry);

		cmp = dnet_trans_map_cmp(m->offset, m->size, a->offset, a->size);
		if (cmp < 0)
			n = n->rb_left;
		else if (cmp > 0)
			n = n->rb_right;

		dnet_log(node, DNET_LOG_NOTICE, "map: %llu/%llu, history: %llu/%llu, cmp: %d, n: %p.\n",
				(unsigned long long)m->offset, (unsigned long long)m->size,
				(unsigned long long)a->offset, (unsigned long long)a->size,
				cmp, n);
		if (!cmp)
			break;
	}

	if (cmp)
		return -ENOENT;

	/*
	 *                         a->offset+a->size   m->offset+m->size
	 * |------------------|==========|--------------------|
	 * m->offset      a->offset
	 *
	 * split into two ranges
	 *
	 * |------------------|          |--------------------|
	 *
	 */
	if (m->offset < a->offset && m->offset + m->size > a->offset + a->size) {
		uint64_t right_size = m->offset + m->size - (a->offset + a->size);

		err = r->callback(r->priv, a->offset, a->size, a);
		if (err)
			return err;

		m->size = a->offset - m->offset;

		err = dnet_trans_map_add_range(r, a->offset + a->size, right_size);
		if (err)
			return err;

		r->size -= a->size;
		goto again;
	}

	/*
	 *         a->offset
	 *           |====================
	 * |--------------------------|
	 * m->offset             m->offset+m->size
	 *
	 * truncated to
	 *
	 * |---------|
	 *
	 */
	if (m->offset < a->offset) {
		err = r->callback(r->priv, a->offset, m->offset + m->size - a->offset, a);
		if (err)
			return err;

		m->size = a->offset - m->offset;
		r->size -= m->offset + m->size - a->offset;
		goto again;
	}
	
	/*
	 *            a->offset + a->size
	 * ==================|
	 * |-------------------------------------|
	 * m->offset                    m->offset+m->size
	 *
	 * changed to
	 *
	 *                   |-------------------|
	 *
	 */

	if (m->offset + m->size > a->offset + a->size) {
		err = r->callback(r->priv, m->offset, a->offset + a->size - m->offset, a);
		if (err)
			return err;

		m->offset = a->offset + a->size;
		r->size -= a->offset + a->size - m->offset;
		goto again;
	}


	/*
	 *                               a->offset + a->size
	 * =====================================|
	 * |----------------------|
	 * m->offset      m->offset+m->size
	 *
	 * removed
	 *
	 */

	if (m->offset + m->size <= a->offset + a->size) {
		err = r->callback(r->priv, m->offset, m->size, a);
		if (err)
			return err;

		rb_erase(&m->map_entry, root);
		r->size -= m->size;
		free(m);
		goto again;
	}

	/*
	 * Should not be here.
	 */
	return -EINVAL;
}

#define dnet_map_log(n, mask, fmt, a...) do { if ((n)) dnet_log((n), mask, fmt, ##a); else fprintf(stderr, fmt, ##a); } while (0)

int dnet_map_history(struct dnet_node *n, char *file, struct dnet_history_map *map)
{
	int err;
	struct stat st;

	map->fd = open(file, O_RDWR);
	if (map->fd < 0) {
		err = -errno;
		dnet_map_log(n, DNET_LOG_ERROR, "Failed to open history file '%s': %s [%d].\n",
				file, strerror(errno), errno);
		goto err_out_exit;
	}

	err = fstat(map->fd, &st);
	if (err) {
		err = -errno;
		dnet_map_log(n, DNET_LOG_ERROR, "Failed to stat history file '%s': %s [%d].\n",
				file, strerror(errno), errno);
		goto err_out_close;
	}

	if (st.st_size % (int)sizeof(struct dnet_history_entry)) {
		dnet_map_log(n, DNET_LOG_ERROR, "Corrupted history file '%s', "
				"its size %llu must be multiple of %zu.\n",
				file, (unsigned long long)st.st_size,
				sizeof(struct dnet_history_entry));
		err = -EINVAL;
		goto err_out_close;
	}
	map->size = st.st_size;

	map->ent = mmap(NULL, map->size, PROT_READ | PROT_WRITE, MAP_SHARED, map->fd, 0);
	if (map->ent == MAP_FAILED) {
		err = -errno;
		dnet_map_log(n, DNET_LOG_ERROR, "Failed to mmap history file '%s': %s [%d].\n",
				file, strerror(errno), errno);
		goto err_out_close;
	}

	map->num = map->size / sizeof(struct dnet_history_entry);

	dnet_map_log(n, DNET_LOG_NOTICE, "Mapped %ld entries in '%s'.\n", map->num, file);

	return 0;

err_out_close:
	close(map->fd);
err_out_exit:
	return err;
}

void dnet_unmap_history(struct dnet_node *n __unused, struct dnet_history_map *map)
{
	munmap(map->ent, map->size);
	close(map->fd);
}

static int dnet_trans_map(struct dnet_node *n, char *main_file, uint64_t offset, uint64_t size,
		struct dnet_id *id, int (*callback)(void *priv, uint64_t offset, uint64_t size,
			struct dnet_history_entry *io), void *priv)
{
	struct dnet_map_root r;
	char file[strlen(main_file) + 1 + sizeof(DNET_HISTORY_SUFFIX)];
	struct dnet_history_entry e;
	struct dnet_history_map map;
	struct dnet_id raw;
	long i;
	int err;

	if (!callback)
		return 0;

	sprintf(file, "%s%s", main_file, DNET_HISTORY_SUFFIX);

	err = dnet_map_history(n, file, &map);
	if (err)
		goto err_out_exit;

	r.root = RB_ROOT;
	r.callback = callback;
	r.priv = priv;
	r.offset = offset;
	r.size = size;

	dnet_log(n, DNET_LOG_NOTICE, "%s: objects: %ld, range: %llu-%llu, "
			"counting from the most recent.\n",
			file, map.num, (unsigned long long)offset,
			(unsigned long long)offset+r.size);

	err = dnet_trans_map_add_range(&r, offset, size);
	if (err) {
		dnet_log(n, DNET_LOG_ERROR, "Failed to add range: offset: %llu, size: %llu, err: %d.\n",
			(unsigned long long)offset, (unsigned long long)size, err);
		goto err_out_unmap;
	}

	for (i=map.num-1; i>=0; --i) {
		e = map.ent[i];

		dnet_convert_history_entry(&e);

		err = dnet_trans_map_match(n, &r, &e);

		dnet_setup_id(&raw, id->group_id, e.id);

		dnet_log(n, DNET_LOG_NOTICE, "%s: flags: %08x, offset: %8llu, size: %8llu: match: %d, rest: %llu\n",
			dnet_dump_id(&raw), e.flags,
			(unsigned long long)e.offset, (unsigned long long)e.size,
			err, (unsigned long long)r.size);

		if (err < 0 && err != -ENOENT)
			goto err_out_free;

		if (!r.size)
			break;
	}

	dnet_trans_map_free(&r);
	dnet_unmap_history(n, &map);

	return 0;

err_out_free:
	dnet_trans_map_free(&r);
err_out_unmap:
	dnet_unmap_history(n, &map);
err_out_exit:
	return err;
}

static int dnet_read_file_raw(struct dnet_node *n, char *file, void *remote, unsigned int remote_len,
		struct dnet_id *id, int direct, uint64_t offset, uint64_t size, int hist)
{
	int err, len = strlen(file), error = 0, i;
	struct dnet_wait *w;
	struct dnet_id raw;

	w = dnet_wait_alloc(~0);
	if (!w) {
		err = -ENOMEM;
		dnet_log(n, DNET_LOG_ERROR, "Failed to allocate read waiting.\n");
		goto err_out_exit;
	}

	if (id) {
		err = dnet_read_file_id(n, file, len, direct, 0, 0, 0, id, w, 1, 1);
		if (err)
			goto err_out_put;
	} else {
		id = &raw;

		dnet_transform(n, remote, remote_len, id);
		pthread_mutex_lock(&n->group_lock);
		for (i=0; i<n->group_num; ++i) {
			id->group_id = n->groups[i];

			err = dnet_read_file_id(n, file, len, direct, 0, 0, 0, id, w, 1, 1);
			if (err) {
				error = err;
				continue;
			}

			error = 0;
			break;
		}
		pthread_mutex_unlock(&n->group_lock);

		if (error) {
			err = error;
			goto err_out_put;
		}
	}

	if (!hist) {
		struct dnet_map_private p;

		p.file = file;
		p.len = len;
		p.node = n;
		p.wait = w;
		p.direct = direct;
		memcpy(&p.id, id, sizeof(struct dnet_id));

		if (!size)
			size = ~0ULL;

		err = dnet_trans_map(n, file, offset, size, id, dnet_trans_map_callback, &p);
		if (err)
			goto err_out_put;

		/*
		 * Waiting for all readers to complete the transactions.
		 */
		err = dnet_wait_event(w, atomic_read(&w->refcnt) == 1, &n->wait_ts);
		if (err || (w->cond < 0 && w->cond != ~0)) {
			if (w->cond < 0 && w->cond != ~0)
				err = w->cond;
			dnet_log(n, DNET_LOG_ERROR, "%s: failed to read file '%s', offset: %llu, size: %llu, err: %d.\n",
					dnet_dump_id(id), file, (unsigned long long)offset,
					(unsigned long long)size, err);
			goto err_out_put;
		}
	}

	dnet_wait_put(w);

	return 0;

err_out_put:
	dnet_wait_put(w);
err_out_exit:
	return err;
}

int dnet_read_file(struct dnet_node *n, char *file, void *remote, unsigned int remote_len,
		struct dnet_id *id, uint64_t offset, uint64_t size, int hist)
{
	return dnet_read_file_raw(n, file, remote, remote_len, id, 0, offset, size, hist);
}

int dnet_read_file_direct(struct dnet_node *n, char *file, void *remote, unsigned int remote_len,
		struct dnet_id *id, uint64_t offset, uint64_t size, int hist)
{
	return dnet_read_file_raw(n, file, remote, remote_len, id, 1, offset, size, hist);
}

struct dnet_wait *dnet_wait_alloc(int cond)
{
	int err;
	struct dnet_wait *w;

	w = malloc(sizeof(struct dnet_wait));
	if (!w) {
		err = -ENOMEM;
		goto err_out_exit;
	}

	memset(w, 0, sizeof(struct dnet_wait));

	err = pthread_cond_init(&w->wait, NULL);
	if (err)
		goto err_out_exit;

	err = pthread_mutex_init(&w->wait_lock, NULL);
	if (err)
		goto err_out_destroy;

	w->cond = cond;
	atomic_init(&w->refcnt, 1);

	return w;

err_out_destroy:
	pthread_mutex_destroy(&w->wait_lock);
err_out_exit:
	return NULL;
}

void dnet_wait_destroy(struct dnet_wait *w)
{
	pthread_mutex_destroy(&w->wait_lock);
	pthread_cond_destroy(&w->wait);
}

static void __dnet_send_cmd_complete(struct dnet_wait *w, int status)
{
	w->status = status;
	w->cond++;
}

static int dnet_send_cmd_complete(struct dnet_net_state *st, struct dnet_cmd *cmd,
			struct dnet_attr *attr __unused, void *priv)
{
	int err = -EINVAL;
	struct dnet_wait *w = priv;

	if (!cmd)
		goto err_out_complete;

	err = cmd->status;
	if (cmd->status != 0)
		goto err_out_complete;

	if (cmd->flags & DNET_FLAGS_MORE)
		return 0;

err_out_complete:
	if (st && cmd)
		dnet_log(st->n, DNET_LOG_DSA, "%s: completed command, err: %d.\n", dnet_dump_id(&cmd->id), err);

	dnet_wakeup(w, __dnet_send_cmd_complete(w, err));
	dnet_wait_put(w);
	return err;
}

static int dnet_send_cmd_single(struct dnet_net_state *st, struct dnet_wait *w, char *command)
{
	struct dnet_trans_control ctl;

	memset(&ctl, 0, sizeof(struct dnet_trans_control));

	memcpy(&ctl.id, &st->idc->ids[0], sizeof(struct dnet_id));
	ctl.cmd = DNET_CMD_EXEC;
	ctl.complete = dnet_send_cmd_complete;
	ctl.priv = w;
	ctl.cflags = DNET_FLAGS_NEED_ACK;
	ctl.size = strlen(command) + 1;
	ctl.data = command;

	return dnet_trans_alloc_send_state(st, &ctl);
}

int dnet_send_cmd(struct dnet_node *n, struct dnet_id *id, char *cmd)
{
	struct dnet_net_state *st;
	int err = -ENOENT, num = 0;
	struct dnet_wait *w;

	w = dnet_wait_alloc(0);
	if (!w) {
		err = -ENOMEM;
		goto err_out_exit;
	}

	if (id) {
		dnet_wait_get(w);
		st = dnet_state_get_first(n, id);
		if (!st)
			goto err_out_put;
		err = dnet_send_cmd_single(st, w, cmd);
		num = 1;
	} else {
		struct dnet_group *g;

		pthread_rwlock_rdlock(&n->state_lock);
		list_for_each_entry(g, &n->group_list, group_entry) {
			list_for_each_entry(st, &g->state_list, state_entry) {
				if (st == n->st)
					continue;

				dnet_wait_get(w);

				dnet_send_cmd_single(st, w, cmd);
				num++;
			}
		}
		pthread_rwlock_unlock(&n->state_lock);
	}

	err = dnet_wait_event(w, w->cond == num, &n->wait_ts);
	if (err)
		goto err_out_put;

	dnet_wait_put(w);

	return num;

err_out_put:
	dnet_wait_put(w);
err_out_exit:
	return err;
}

int dnet_try_reconnect(struct dnet_node *n)
{
	struct dnet_addr_storage *ast, *tmp;
	struct dnet_net_state *st;
	int s, err;

	if (list_empty(&n->reconnect_list))
		return 0;

	pthread_mutex_lock(&n->reconnect_lock);
	list_for_each_entry_safe(ast, tmp, &n->reconnect_list, reconnect_entry) {
		ast->reconnect_num += n->check_timeout;
		if (ast->reconnect_num < ast->reconnect_num_max)
			continue;

		ast->reconnect_num = 0;
		ast->reconnect_num_max += 60;

		if (ast->reconnect_num_max > ast->reconnect_num_limit) {
			dnet_log(n, DNET_LOG_ERROR, "Reconnect num %d reached limit %d, will not try to reconnect anymore.\n",
					ast->reconnect_num_max, ast->reconnect_num_limit);
			goto out_remove;
		}

		s = dnet_socket_create_addr(n, n->sock_type, n->proto, n->family,
				(struct sockaddr *)ast->addr.addr, ast->addr.addr_len, 0);
		if (s < 0)
			continue;

		st = dnet_add_state_socket(n, &ast->addr, s);
		if (!st) {
			close(s);

			st = dnet_state_search_by_addr(n, &ast->addr);
			if (st) {
				dnet_state_put(st);
				goto out_remove;
			}
			continue;
		}

		st->__join_state = DNET_WANT_RECONNECT;

		if (ast->__join_state == DNET_JOIN) {
			err = dnet_state_join(st);
			if (err) {
				dnet_state_put(st);
				continue;
			}
		}

out_remove:
		list_del(&ast->reconnect_entry);
		free(ast);
	}
	pthread_mutex_unlock(&n->reconnect_lock);

	return 0;
}

int dnet_lookup_object(struct dnet_node *n, struct dnet_id *id, unsigned int aflags,
	int (* complete)(struct dnet_net_state *, struct dnet_cmd *, struct dnet_attr *, void *),
	void *priv)
{
	struct dnet_trans *t;
	struct dnet_attr *a;
	struct dnet_cmd *cmd;
	struct dnet_net_state *st;
	int err;

	t = dnet_trans_alloc(n, sizeof(struct dnet_attr) +
			sizeof(struct dnet_cmd));
	if (!t) {
		err = -ENOMEM;
		goto err_out_complete_destroy;
	}
	t->complete = complete;
	t->priv = priv;

	cmd = (struct dnet_cmd *)(t + 1);
	a = (struct dnet_attr *)(cmd + 1);

	memcpy(&cmd->id, id, sizeof(struct dnet_id));
	cmd->size = sizeof(struct dnet_attr);
	cmd->status = 0;

	memcpy(&t->cmd, cmd, sizeof(struct dnet_cmd));

	a->cmd = DNET_CMD_LOOKUP;
	a->size = 0;
	a->flags = aflags;

	t->st = dnet_state_get_first(n, &cmd->id);
	if (!t->st) {
		err = -ENOENT;
		dnet_log(n, DNET_LOG_ERROR, "%s: failed to find a state.\n", dnet_dump_id(&cmd->id));
		goto err_out_destroy;
	}

	err = dnet_trans_insert(t);
	if (err)
		goto err_out_destroy;

	cmd->trans = t->trans;
	dnet_convert_cmd(cmd);
	dnet_convert_attr(a);

	st = t->st;

	dnet_log(n, DNET_LOG_NOTICE, "%s: %s lookup to %s.\n", dnet_dump_id(id),
		(a->flags) ? "stat" : "plain", dnet_server_convert_dnet_addr(&st->addr));

	err = dnet_send(st, cmd, sizeof(struct dnet_attr) + sizeof(struct dnet_cmd));
	if (err)
		goto err_out_destroy;

	return 0;

err_out_complete_destroy:
	if (complete)
		complete(NULL, NULL, NULL, priv);
	goto err_out_exit;

err_out_destroy:
	dnet_trans_put(t);
err_out_exit:
	return err;
}

int dnet_lookup_complete(struct dnet_net_state *st, struct dnet_cmd *cmd,
		struct dnet_attr *attr, void *priv)
{
	struct dnet_wait *w = priv;
	struct dnet_node *n = NULL;
	struct dnet_addr_attr *a;
	struct dnet_net_state *other;
	int err;

	if (!cmd || !st) {
		err = -EINVAL;
		goto err_out_exit;
	}
	n = st->n;

	err = cmd->status;
	if (err || !cmd->size)
		goto err_out_exit;

	if (attr->size != sizeof(struct dnet_addr_attr)) {
		dnet_log(st->n, DNET_LOG_ERROR, "%s: wrong dnet_addr attribute size %llu, must be %zu.\n",
				dnet_dump_id(&cmd->id), (unsigned long long)attr->size, sizeof(struct dnet_addr_attr));
		err = -EINVAL;
		goto err_out_exit;
	}

	a = (struct dnet_addr_attr *)(attr + 1);

	dnet_convert_addr_attr(a);

	other = dnet_state_search_by_addr(n, &a->addr);
	if (other) {
		dnet_state_put(other);
	} else {
		dnet_recv_route_list(st);
	}

	if (!(cmd->flags & DNET_FLAGS_MORE))
		goto out;

	return 0;

err_out_exit:
	if (n)
		dnet_log(n, DNET_LOG_ERROR, "%s: lookup completion status: %d, err: %d.\n", dnet_dump_id(&cmd->id), cmd->status, err);
out:
	if (w) {
		dnet_wakeup(w, w->cond = 1);
		dnet_wait_put(w);
	}
	return err;
}

int dnet_lookup(struct dnet_node *n, char *file)
{
	int err, error = 0, i;
	struct dnet_wait *w;
	struct dnet_id raw;

	w = dnet_wait_alloc(0);
	if (!w) {
		err = -ENOMEM;
		goto err_out_exit;
	}

	dnet_transform(n, file, strlen(file), &raw);

	pthread_mutex_lock(&n->group_lock);
	for (i=0; i<n->group_num; ++i) {
		raw.group_id = n->groups[i];

		err = dnet_lookup_object(n, &raw, 0, dnet_lookup_complete, dnet_wait_get(w));
		if (err) {
			error = err;
			continue;
		}

		err = dnet_wait_event(w, w->cond == 1, &n->wait_ts);
		if (err || w->status) {
			if (!err)
				err = w->status;
			error = err;
			continue;
		}

		error = 0;
		break;
	}
	pthread_mutex_unlock(&n->group_lock);

	dnet_wait_put(w);
	return error;

err_out_exit:
	return err;
}

struct dnet_addr *dnet_state_addr(struct dnet_net_state *st)
{
	return &st->addr;
}

static int dnet_stat_complete(struct dnet_net_state *state, struct dnet_cmd *cmd,
	struct dnet_attr *attr, void *priv)
{
	struct dnet_wait *w = priv;
	float la[3];
	struct dnet_stat *st;
	int err = -EINVAL;

	if (!state || !cmd || !attr) {
		dnet_wakeup(w, w->cond++);
		dnet_wait_put(w);
		return 0;
	}

	if (attr->cmd == DNET_CMD_STAT && attr->size == sizeof(struct dnet_stat)) {
		st = (struct dnet_stat *)(attr + 1);

		dnet_convert_stat(st);

		la[0] = (float)st->la[0] / 100.0;
		la[1] = (float)st->la[1] / 100.0;
		la[2] = (float)st->la[2] / 100.0;

		dnet_log(state->n, DNET_LOG_INFO, "%s: %s: la: %.2f %.2f %.2f.\n",
				dnet_dump_id(&cmd->id), dnet_state_dump_addr(state),
				la[0], la[1], la[2]);
		dnet_log(state->n, DNET_LOG_INFO, "%s: %s: mem: "
				"total: %llu kB, free: %llu kB, cache: %llu kB.\n",
				dnet_dump_id(&cmd->id), dnet_state_dump_addr(state),
				(unsigned long long)st->vm_total,
				(unsigned long long)st->vm_free,
				(unsigned long long)st->vm_cached);
		dnet_log(state->n, DNET_LOG_INFO, "%s: %s: fs: "
				"total: %llu mB, avail: %llu mB, files: %llu, fsid: %llx.\n",
				dnet_dump_id(&cmd->id), dnet_state_dump_addr(state),
				(unsigned long long)(st->frsize * st->blocks / 1024 / 1024),
				(unsigned long long)(st->bavail * st->bsize / 1024 / 1024),
				(unsigned long long)st->files, (unsigned long long)st->fsid);
		err = 0;
	} else if (attr->size >= sizeof(struct dnet_addr_stat) && attr->cmd == DNET_CMD_STAT_COUNT) {
		struct dnet_addr_stat *as = (struct dnet_addr_stat *)(attr + 1);
		char addr[128];
		int i;

		dnet_convert_addr_stat(as, 0);

		dnet_log(state->n, DNET_LOG_DSA, "%s: per-cmd operation counters:\n",
			dnet_server_convert_dnet_addr_raw(&as->addr, addr, sizeof(addr)));
		for (i=0; i<as->num; ++i)
			dnet_log(state->n, DNET_LOG_DSA, "    cmd: %d, count: %llu, err: %llu\n", i,
					(unsigned long long)as->count[i].count, (unsigned long long)as->count[i].err);
	}

	if (!(cmd->flags & DNET_FLAGS_MORE)) {
		dnet_wakeup(w, w->cond++);
		dnet_wait_put(w);
	}

	return err;
}

int dnet_request_cmd_single(struct dnet_node *n,
	struct dnet_net_state *st, struct dnet_id *id,
	unsigned int cmd, unsigned int aflags,
	int (* complete)(struct dnet_net_state *state,
			struct dnet_cmd *cmd,
			struct dnet_attr *attr,
			void *priv),
	void *priv)
{
	struct dnet_trans_control ctl;

	memset(&ctl, 0, sizeof(struct dnet_trans_control));

	memcpy(&ctl.id, id, sizeof(struct dnet_id));
	ctl.cmd = cmd;
	ctl.complete = complete;
	ctl.priv = priv;
	ctl.cflags = DNET_FLAGS_NEED_ACK;
	ctl.aflags = aflags;

	if (st)
		return dnet_trans_alloc_send_state(st, &ctl);
	else
		return dnet_trans_alloc_send(n, &ctl);
}

int dnet_request_stat(struct dnet_node *n, struct dnet_id *id, unsigned int cmd,
	int (* complete)(struct dnet_net_state *state,
			struct dnet_cmd *cmd,
			struct dnet_attr *attr,
			void *priv),
	void *priv)
{
	struct dnet_wait *w = NULL;
	int err, num = 0;

	if (!complete) {
		w = dnet_wait_alloc(0);
		if (!w) {
			err = -ENOMEM;
			goto err_out_exit;
		}

		complete = dnet_stat_complete;
		priv = w;
	}
	if (id) {
		if (w)
			dnet_wait_get(w);
		err = dnet_request_cmd_single(n, NULL, id, cmd, 0, complete, priv);
		num = 1;
	} else {
		struct dnet_net_state *st;
		struct dnet_group *g;

		pthread_rwlock_rdlock(&n->state_lock);
		list_for_each_entry(g, &n->group_list, group_entry) {
			list_for_each_entry(st, &g->state_list, state_entry) {
				struct dnet_id raw;

				if (st == n->st)
					continue;

				if (w)
					dnet_wait_get(w);

				dnet_setup_id(&raw, st->idc->group->group_id, st->idc->ids[0].raw.id);
				dnet_request_cmd_single(n, st, &raw, cmd, 0, complete, priv);
				num++;
			}
		}
		pthread_rwlock_unlock(&n->state_lock);
	}

	if (!w)
		return num;

	err = dnet_wait_event(w, w->cond == num, &n->wait_ts);
	if (err)
		goto err_out_put;

	dnet_wait_put(w);

	return num;

err_out_put:
	dnet_wait_put(w);
err_out_exit:
	return err;
}

static int dnet_remove_object_raw(struct dnet_node *n,
	unsigned char *parent, struct dnet_id *id,
	int (* complete)(struct dnet_net_state *state,
			struct dnet_cmd *cmd,
			struct dnet_attr *attr,
			void *priv),
	void *priv,
	int direct)
{
	struct dnet_trans_control ctl;
	char data[sizeof(struct dnet_io_attr) + sizeof(struct dnet_history_entry)];
	struct dnet_io_attr *io = (struct dnet_io_attr *)data;
	struct dnet_history_entry *e = (struct dnet_history_entry *)(io + 1);

	memset(&ctl, 0, sizeof(struct dnet_trans_control));

	memcpy(&ctl.id, id, sizeof(struct dnet_id));

	memset(data, 0, sizeof(data));

	memcpy(io->id, id->id, DNET_ID_SIZE);
	memcpy(io->parent, parent, DNET_ID_SIZE);
	io->size = sizeof(struct dnet_history_entry);
	io->flags = DNET_IO_FLAGS_APPEND | DNET_IO_FLAGS_HISTORY;

	dnet_convert_io_attr(io);

	dnet_setup_history_entry(e, id->id, 0, 0, NULL, DNET_IO_FLAGS_REMOVED);

	ctl.cmd = DNET_CMD_WRITE;
	ctl.complete = complete;
	ctl.priv = priv;
	ctl.cflags = DNET_FLAGS_NEED_ACK;
	if (direct)
		ctl.cflags |= DNET_FLAGS_DIRECT;
	ctl.data = data;
	ctl.size = sizeof(data);

	return dnet_trans_alloc_send(n, &ctl);
}

static int dnet_remove_complete(struct dnet_net_state *state,
			struct dnet_cmd *cmd,
			struct dnet_attr *attr __unused,
			void *priv)
{
	struct dnet_wait *w = priv;
	int err = 0;

	if (!state || !cmd) {
		err = -EINVAL;
		goto out_put;
	}

	if (cmd) {
		err = cmd->status;
		if (cmd->flags & DNET_FLAGS_MORE)
			return 0;
	}

out_put:
	if (state)
		dnet_log(state->n, DNET_LOG_NOTICE, "%s: removing completion: %d.\n",
				dnet_dump_id(&cmd->id), err);

	dnet_wakeup(w, dnet_io_complete(w, err));
	dnet_wait_put(w);
	return 0;
}

int dnet_remove_object(struct dnet_node *n,
	unsigned char *parent, struct dnet_id *id,
	int (* complete)(struct dnet_net_state *state,
			struct dnet_cmd *cmd,
			struct dnet_attr *attr,
			void *priv),
	void *priv,
	int direct)
{
	struct dnet_wait *w = NULL;
	int err;

	if (!complete) {
		w = dnet_wait_alloc(0);
		if (!w) {
			err = -ENOMEM;
			goto err_out_exit;
		}

		complete = dnet_remove_complete;
		priv = w;
		dnet_wait_get(w);
	}

	err = dnet_remove_object_raw(n, parent, id,
			complete, priv, direct);
	if (err)
		goto err_out_put;

	if (w) {
		err = dnet_wait_event(w, w->cond != 0, &n->wait_ts);
		if (err)
			goto err_out_put;

		dnet_wait_put(w);
	}
	return 0;

err_out_put:
	if (w)
		dnet_wait_put(w);
err_out_exit:
	return err;
}

int dnet_remove_object_now(struct dnet_node *n, struct dnet_id *id, int direct)
{
	struct dnet_wait *w = NULL;
	struct dnet_trans_control ctl;
	int err;

	w = dnet_wait_alloc(0);
	if (!w) {
		err = -ENOMEM;
		goto err_out_exit;
	}

	dnet_wait_get(w);

	memset(&ctl, 0, sizeof(struct dnet_trans_control));

	memcpy(&ctl.id, id, sizeof(struct dnet_id));
	ctl.cmd = DNET_CMD_DEL;
	ctl.complete = dnet_remove_complete;
	ctl.priv = w;
	ctl.cflags = DNET_FLAGS_NEED_ACK;
	ctl.aflags = DNET_ATTR_DIRECT_TRANSACTION;

	if (direct)
		ctl.cflags |= DNET_FLAGS_DIRECT;

	err = dnet_trans_alloc_send(n, &ctl);
	if (err)
		goto err_out_put;

	err = dnet_wait_event(w, w->cond != 0, &n->wait_ts);
	if (err)
		goto err_out_put;

err_out_put:
	dnet_wait_put(w);
err_out_exit:
	return err;
}

static int dnet_remove_file_raw(struct dnet_node *n, struct dnet_id *id)
{
	struct dnet_wait *w;
	int err;

	w = dnet_wait_alloc(0);
	if (!w) {
		err = -ENOMEM;
		goto err_out_exit;
	}

	dnet_wait_get(w);
	err = dnet_remove_object_raw(n, id->id, id, dnet_remove_complete, w, 0);
	if (err)
		goto err_out_put;

	err = dnet_wait_event(w, w->cond == 1, &n->wait_ts);
	if (err)
		goto err_out_put;

	dnet_wait_put(w);

	return 0;

err_out_put:
	dnet_wait_put(w);
err_out_exit:
	return err;
}

int dnet_remove_file(struct dnet_node *n, char *remote, int remote_len, struct dnet_id *id)
{
	struct dnet_id raw;
	int err, error = 0, i;

	if (id)
		 return dnet_remove_file_raw(n, id);

	dnet_transform(n, remote, remote_len, &raw);

	pthread_mutex_lock(&n->group_lock);
	for (i=0; i<n->group_num; ++i) {
		raw.group_id = n->groups[i];
		err = dnet_remove_file_raw(n, &raw);
		if (err)
			error = err;
	}
	pthread_mutex_unlock(&n->group_lock);

	return error;
}

int dnet_request_ids(struct dnet_node *n, struct dnet_id *id, unsigned int aflags,
	int (* complete)(struct dnet_net_state *state,
			struct dnet_cmd *cmd,
			struct dnet_attr *attr,
			void *priv),
	void *priv)
{
	struct dnet_trans_control ctl;

	dnet_log_raw(n, DNET_LOG_ERROR, "Temporarily unsupported operation.\n");
	exit(-1);

	memset(&ctl, 0, sizeof(struct dnet_trans_control));

	memcpy(&ctl.id, id, sizeof(struct dnet_id));
	ctl.cmd = DNET_CMD_LIST;
	ctl.complete = complete;
	ctl.priv = priv;
	ctl.cflags = DNET_FLAGS_NEED_ACK;
	ctl.aflags = aflags;

	return dnet_trans_alloc_send(n, &ctl);
}

struct dnet_node *dnet_get_node_from_state(void *state)
{
	struct dnet_net_state *st = state;
	return st->n;
}

struct dnet_read_data_completion {
	struct dnet_wait		*w;
	void				*data;
	uint64_t			size;
};

static int dnet_read_data_complete(struct dnet_net_state *st, struct dnet_cmd *cmd, struct dnet_attr *attr, void *priv)
{
	struct dnet_read_data_completion *c = priv;
	int last = (!cmd || !(cmd->flags & DNET_FLAGS_MORE));
	int err = -EINVAL;

	if (!cmd || !attr || !st) {
		if (cmd)
			err = cmd->status;
		goto err_out_exit;
	}

	err = cmd->status;

	if (attr->size > sizeof(struct dnet_io_attr)) {
		struct dnet_io_attr *io = (struct dnet_io_attr *)(attr + 1);
		void *data;
		uint64_t sz = c->size;

		data = io + 1;

		dnet_convert_io_attr(io);

		sz += io->size;
		c->data = realloc(c->data, sz);
		if (!c->data) {
			err = -ENOMEM;
			goto err_out_exit;
		}

		memcpy(c->data + c->size, data, io->size);
		c->size += io->size;
	}

	dnet_log(st->n, DNET_LOG_NOTICE, "%s: object read completed: trans: %llu, status: %d, last: %d.\n",
		dnet_dump_id(&cmd->id), (unsigned long long)(cmd->trans & ~DNET_TRANS_REPLY),
		cmd->status, last);

err_out_exit:
	if (last) {
		dnet_wakeup(c->w, dnet_io_complete(c->w, err));
		dnet_wait_put(c->w);
	}

	return err;
}

void *dnet_read_data_wait(struct dnet_node *n, struct dnet_id *id, uint64_t *size)
{
	struct dnet_io_control ctl;
	ssize_t err;
	struct dnet_wait *w;
	struct dnet_read_data_completion c;
	void *data = NULL;

	w = dnet_wait_alloc(0);
	if (!w) {
		err = -ENOMEM;
		goto err_out_exit;
	}

	c.w = w;
	c.size = 0;
	c.data = NULL;

	memset(&ctl, 0, sizeof(struct dnet_io_control));

	ctl.fd = -1;

	ctl.priv = &c;
	ctl.complete = dnet_read_data_complete;

	ctl.cmd = DNET_CMD_READ;
	ctl.cflags = DNET_FLAGS_NEED_ACK;

	memcpy(ctl.io.id, id->id, DNET_ID_SIZE);
	memcpy(ctl.io.parent, id->id, DNET_ID_SIZE);

	memcpy(&ctl.id, id, sizeof(struct dnet_id));
	
	ctl.io.flags = 0;
	ctl.io.size = *size;
	ctl.io.offset = 0;

	dnet_wait_get(w);
	err = dnet_read_object(n, &ctl);
	if (err)
		goto err_out_put;

	err = dnet_wait_event(w, w->cond, &n->wait_ts);
	if (err || w->status) {
		if (!err)
			err = w->status;
		dnet_log(n, DNET_LOG_ERROR, "%s: failed to wait for IO read completion, err: %zd, status: %d.\n",
				dnet_dump_id(&ctl.id), err, w->status);
		goto err_out_put;
	}
	*size = c.size;
	data = c.data;

err_out_put:
	dnet_wait_get(w);
err_out_exit:
	return data;
}

int dnet_write_data_wait(struct dnet_node *n, void *remote, unsigned int len,
		struct dnet_id *id, void *data, int fd, uint64_t local_offset,
		uint64_t offset, uint64_t size,
		struct timespec *ts, unsigned int aflags, unsigned int ioflags)
{
	struct dnet_io_control ctl;
	int err, trans_num = 0;
	struct dnet_wait *w;

	w = dnet_wait_alloc(0);
	if (!w) {
		err = -ENOMEM;
		goto err_out_exit;
	}

	memset(&ctl, 0, sizeof(struct dnet_io_control));

	ctl.data = data;
	ctl.fd = fd;
	ctl.local_offset = local_offset;
	ctl.aflags = aflags;

	if (ts)
		ctl.ts = *ts;

	ctl.priv = w;
	ctl.complete = dnet_write_complete;

	ctl.cmd = DNET_CMD_WRITE;
	ctl.cflags = DNET_FLAGS_NEED_ACK;

	ctl.io.flags = ioflags;
	ctl.io.size = size;
	ctl.io.offset = offset;

	atomic_set(&w->refcnt, INT_MAX);
	trans_num = dnet_write_object(n, &ctl, remote, len, id, !(ioflags & (DNET_IO_FLAGS_HISTORY | DNET_IO_FLAGS_NO_HISTORY_UPDATE | DNET_IO_FLAGS_META)));
	if (trans_num < 0)
		trans_num = 0;

	/*
	 * 1 - the first reference counter we grabbed at allocation time
	 */
	atomic_sub(&w->refcnt, INT_MAX - trans_num - 1);

	err = dnet_wait_event(w, w->cond == trans_num, &n->wait_ts);
	if (err || w->status) {
		if (!err)
			err = w->status;
		dnet_log(n, DNET_LOG_ERROR, "%s: failed to wait for IO write completion, err: %d.\n",
				dnet_dump_id(&ctl.id), err);
		goto err_out_put;
	}

	if (!err && !trans_num) {
		err = -EINVAL;
		dnet_log(n, DNET_LOG_ERROR, "Failed to write data into the storage, err: %d, trans_num: %d.\n", err, trans_num);
		goto err_out_put;
	}

	if (trans_num)
		dnet_log(n, DNET_LOG_NOTICE, "Successfully wrote %llu bytes into the storage.\n", (unsigned long long)size);
	err = trans_num;

err_out_put:
	dnet_wait_get(w);
err_out_exit:
	return err;
}

int64_t dnet_get_param(struct dnet_node *n, struct dnet_id *id, enum id_params param)
{
	struct dnet_net_state *st;
	int64_t ret = 1;

	st = dnet_state_get_first(n, id);
	if (!st)
		return -ENOENT;

	switch (param) {
		case DNET_ID_PARAM_LA:
			ret = st->la;
			break;
		case DNET_ID_PARAM_FREE_SPACE:
			ret = st->free;
			break;
		default:
			break;
	}
	dnet_state_put(st);

	return ret;
}

static int dnet_compare_by_param(const void *id1, const void *id2)
{
	const struct dnet_id_param *l1 = id1;
	const struct dnet_id_param *l2 = id2;

	if (l1->param == l2->param)
		return l1->param_reserved - l2->param_reserved;

	return l1->param - l2->param;
}

static int dnet_compare_by_param_reverse(const void *id1, const void *id2)
{
	const struct dnet_id_param *l2 = id1;
	const struct dnet_id_param *l1 = id2;

	if (l1->param == l2->param)
		return l1->param_reserved - l2->param_reserved;

	return l1->param - l2->param;
}

int dnet_generate_ids_by_param(struct dnet_node *n, struct dnet_id *id, enum id_params param, struct dnet_id_param **dst)
{
	int i, err = 0, group_num = 0;
	struct dnet_id_param *ids;
	struct dnet_group *g;

	if (n->group_num) {
		pthread_mutex_lock(&n->group_lock);
		if (n->group_num) {
			group_num = n->group_num;

			ids = malloc(group_num * sizeof(struct dnet_id_param));
			if (!ids) {
				err = -ENOMEM;
				goto err_out_unlock_group;
			}
			for (i=0; i<group_num; ++i)
				ids[i].group_id = n->groups[i];
		}
err_out_unlock_group:
		pthread_mutex_unlock(&n->group_lock);
		if (err)
			goto err_out_exit;
	}

	if (!group_num) {
		int pos = 0;

		pthread_rwlock_rdlock(&n->state_lock);
		list_for_each_entry(g, &n->group_list, group_entry)
			group_num++;

		ids = malloc(group_num * sizeof(struct dnet_id_param));
		if (!ids) {
			err = -ENOMEM;
			goto err_out_unlock_state;
		}

		list_for_each_entry(g, &n->group_list, group_entry) {
			ids[pos].group_id = g->group_id;
			pos++;
		}
err_out_unlock_state:
		pthread_rwlock_unlock(&n->state_lock);
		if (err)
			goto err_out_exit;
	}

	for (i=0; i<group_num; ++i) {
		id->group_id = ids[i].group_id;
		ids[i].param = dnet_get_param(n, id, param);
	}

	qsort(ids, group_num, sizeof(struct dnet_id_param), dnet_compare_by_param);
	*dst = ids;

	for (i=0; i<group_num; ++i) {
		id->group_id = ids[i].group_id;

		dnet_log(n, DNET_LOG_DSA, "%s: requested param: %d, group: %u, param: %llu\n",
				dnet_dump_id(id), param,
				ids[i].group_id, (unsigned long long)ids[i].param);
	}

	err = group_num;

err_out_exit:
	return err;
}

int dnet_send_read_data(void *state, struct dnet_cmd *cmd, struct dnet_io_attr *io, void *data, int fd, uint64_t offset)
{
	struct dnet_net_state *st = state;
	struct dnet_cmd *c;
	struct dnet_attr *a;
	struct dnet_io_attr *rio;
	int hsize = sizeof(struct dnet_cmd) + sizeof(struct dnet_attr) + sizeof(struct dnet_io_attr);
	int err;

	/*
	 * A simple hack to forbid read reply sending.
	 * It is used in local stat - we do not want to send stat data
	 * back to parental client, instead server will wrap data into
	 * proper transaction reply next to this obscure packet.
	 */
	if (io->flags & DNET_IO_FLAGS_NO_HISTORY_UPDATE)
		return 0;

	c = malloc(hsize);
	if (!c) {
		err = -ENOMEM;
		goto err_out_exit;
	}

	a = (struct dnet_attr *)(c + 1);
	rio = (struct dnet_io_attr *)(a + 1);

	dnet_setup_id(&c->id, cmd->id.group_id, io->parent);
	memcpy(rio->parent, io->parent, DNET_ID_SIZE);

	dnet_log_raw(st->n, DNET_LOG_NOTICE, "%s: read reply offset: %llu, size: %llu.\n",
			dnet_dump_id(&c->id), (unsigned long long)io->offset,
			(unsigned long long)io->size);

	if (cmd->flags & DNET_FLAGS_NEED_ACK)
		c->flags = DNET_FLAGS_MORE;

	c->status = 0;
	c->size = sizeof(struct dnet_attr) + sizeof(struct dnet_io_attr) + io->size;
	c->trans = cmd->trans | DNET_TRANS_REPLY;

	a->cmd = DNET_CMD_READ;
	a->size = sizeof(struct dnet_io_attr) + io->size;
	a->flags = 0;

	rio->size = io->size;
	rio->offset = io->offset;
	rio->flags = io->flags;

	dnet_convert_cmd(c);
	dnet_convert_attr(a);
	dnet_convert_io_attr(rio);

	if (data)
		err = dnet_send_data(st, c, hsize, data, io->size);
	else
		err = dnet_send_fd(st, c, hsize, fd, offset, io->size);

err_out_exit:
	return err;
}

struct dnet_read_multiple {
	struct dnet_wait		*w;
	struct dnet_id_param		*ids;
	int				num;

	int				wait_error;
	int				wait_num;
};

static int dnet_read_multiple_complete(struct dnet_net_state *state,
		struct dnet_cmd *cmd, struct dnet_attr *attr, void *priv)
{
	struct dnet_read_multiple *m = priv;
	struct dnet_node *n;
	struct dnet_io_attr *io;
	struct dnet_history_entry *he;
	int err = 0, last, i, num;

	if (!state || !cmd) {
		err = -EINVAL;
		goto out_wakeup;
	}

	n = state->n;
	err = cmd->status;
	last = !(cmd->flags & DNET_FLAGS_MORE);
	dnet_log_raw(n, DNET_LOG_DSA, "%s: read multiple status: %d, last: %d.\n",
			dnet_dump_id(&cmd->id), cmd->status, last);

	if (err)
		goto out_check;

	if (attr && attr->size) {
		if (cmd->size <= sizeof(struct dnet_attr) + sizeof(struct dnet_io_attr)) {
			dnet_log_raw(n, DNET_LOG_ERROR, "%s: read multiple completion error: wrong size: cmd_size: %llu, must be more than %zu.\n",
					dnet_dump_id(&cmd->id), (unsigned long long)cmd->size,
					sizeof(struct dnet_attr) + sizeof(struct dnet_io_attr));
			err = -EINVAL;
			goto out_check;
		}

		if (!attr) {
			dnet_log_raw(n, DNET_LOG_ERROR, "%s: read multiple: no attributes but command size is not null.\n", dnet_dump_id(&cmd->id));
			err = -EINVAL;
			goto out_check;
		}

		io = (struct dnet_io_attr *)(attr + 1);
		he = (struct dnet_history_entry *)(io + 1);

		dnet_convert_attr(attr);
		dnet_convert_io_attr(io);

		if (io->size < sizeof(struct dnet_history_entry)) {
			dnet_log_raw(n, DNET_LOG_ERROR, "%s: read multiple: invalid io size %llu.\n", dnet_dump_id(&cmd->id), (unsigned long long)io->size);
			err = -EINVAL;
			goto out_check;
		}

		num = io->size / sizeof(struct dnet_history_entry);
		he = &he[num - 1];

		dnet_convert_history_entry(he);

		for (i=0; i<m->num; ++i) {
			if (m->ids[i].group_id == cmd->id.group_id) {
				m->ids[i].param = he->tsec;
				m->ids[i].param_reserved = he->tnsec;
				dnet_log(n, DNET_LOG_DSA, "%s: multiple read reply: i: %d, ts: %llu.%llu\n",
						dnet_dump_id(&cmd->id), i, (unsigned long long)he->tsec, (unsigned long long)he->tnsec);
				break;
			}
		}
	}

out_check:
	if (last)
		goto out_wakeup;

	return err;

out_wakeup:
	dnet_wakeup(m->w, { do { if (err) m->wait_error = err; m->wait_num++; } while (0); 0;} );
	dnet_wait_put(m->w);
	return err;
}

int dnet_read_multiple(struct dnet_node *n, struct dnet_id *id, int num, struct dnet_id_param **dst)
{
	int err, i;
	struct dnet_id_param *ids;
	struct dnet_wait *w;
	struct dnet_read_multiple mult;
	struct dnet_io_control ctl;

	err = dnet_generate_ids_by_param(n, id, DNET_ID_PARAM_LA, &ids);
	if (err <= 0)
		goto err_out_exit;

	memset(&mult, 0, sizeof(struct dnet_read_multiple));

	if (err < num)
		num = err;

	w = dnet_wait_alloc(0);
	if (!w) {
		err = -ENOMEM;
		goto err_out_free;
	}

	mult.ids = ids;
	mult.num = err;
	mult.w = w;

	memset(&ctl, 0, sizeof(struct dnet_io_control));

	ctl.fd = -1;
	ctl.complete = dnet_read_multiple_complete;
	ctl.priv = &mult;
	ctl.cmd = DNET_CMD_READ;
	ctl.cflags = DNET_FLAGS_NEED_ACK;

	ctl.io.flags = DNET_IO_FLAGS_HISTORY;
	ctl.io.offset = 0;
	ctl.io.size = 0;

	memcpy(ctl.io.parent, id->id, DNET_ID_SIZE);
	memcpy(ctl.io.id, id->id, DNET_ID_SIZE);
	memcpy(&ctl.id, id, sizeof(struct dnet_id));

	for (i=0; i<num; ++i) {
		dnet_wait_get(w);

		ids[i].param = ids[i].param_reserved = -1ULL;
		ctl.id.group_id = ids[i].group_id;
		dnet_read_object(n, &ctl);
	}

	err = dnet_wait_event(w, mult.wait_num == num, &n->wait_ts);
	if (!err)
		err = mult.wait_error;
	if (err)
		goto err_out_put;

	qsort(ids, num, sizeof(struct dnet_id_param), dnet_compare_by_param_reverse);
	*dst = ids;

	for (i=0; i<num; ++i) {
		id->group_id = ids[i].group_id;

		dnet_log(n, DNET_LOG_DSA, "%s: read multiple: group: %u, tsec: %lld.%lld\n",
				dnet_dump_id(id), ids[i].group_id,
				(long long)ids[i].param,
				(long long)ids[i].param_reserved);
	}

	dnet_wait_put(w);
	return num;

err_out_put:
	dnet_wait_put(w);
err_out_free:
	free(ids);
err_out_exit:
	return err;
}
