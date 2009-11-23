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

#include "dnet/packet.h"
#include "dnet/interface.h"

int dnet_transform(struct dnet_node *n, void *src, uint64_t size, void *dst, void *addr,
		unsigned int *dsize, int *ppos)
{
	int pos = 0;
	int err = 1;
	struct dnet_transform *t;

	pthread_rwlock_rdlock(&n->transform_lock);
	list_for_each_entry(t, &n->transform_list, tentry) {
		if (pos++ == *ppos) {
			*ppos = pos;
			err = t->init(t->priv, n);
			if (err)
				continue;

			err = t->update(t->priv, src, size, dst, dsize, 0);
			if (err)
				continue;

			err = t->final(t->priv, dst, addr, dsize, 0);
			if (!err)
				break;
		}
	}
	pthread_rwlock_unlock(&n->transform_lock);

	return err;
}

static int dnet_send_address(struct dnet_net_state *st, unsigned char *id, uint64_t trans,
		unsigned int cmd, unsigned int aflags, struct dnet_addr *addr, int reply, int direct)
{
	struct dnet_data_req *r;
	struct dnet_addr_cmd *c;

	r = dnet_req_alloc(st, sizeof(struct dnet_addr_cmd));
	if (!r)
		return -ENOMEM;

	c = dnet_req_header(r);

	memcpy(c->cmd.id, id, DNET_ID_SIZE);
	c->cmd.size = sizeof(struct dnet_addr_cmd) - sizeof(struct dnet_cmd);
	c->cmd.trans = trans;
	if (reply)
		c->cmd.trans |= DNET_TRANS_REPLY;

	if (direct)
		c->cmd.flags |= DNET_FLAGS_DIRECT;

	c->a.cmd = cmd;
	c->a.size = sizeof(struct dnet_addr_cmd) -
		sizeof(struct dnet_cmd) - sizeof(struct dnet_attr);
	c->a.flags = aflags;

	memcpy(&c->addr.addr, addr, sizeof(struct dnet_addr));
	c->addr.family = st->n->family;
	c->addr.sock_type = st->n->sock_type;
	c->addr.proto = st->n->proto;

	dnet_log(st->n, DNET_LOG_INFO, "%s: sending address command: trans: %llu, reply: %d, cmd: %u, aflags: %x.\n",
			dnet_dump_id(id), (unsigned long long)trans, reply, cmd, aflags);

	dnet_convert_addr_cmd(c);

	return dnet_data_ready(st, r);
}

static int dnet_stat_local(struct dnet_net_state *st, unsigned char *id)
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

	memcpy(cmd->id, id, DNET_ID_SIZE);
	cmd->size = cmd_size - sizeof(struct dnet_cmd);
	
	attr->size = cmd->size - sizeof(struct dnet_attr);
	attr->cmd = DNET_CMD_READ;

	io->size = attr->size - sizeof(struct dnet_io_attr);
	io->offset = 0;
	io->flags = 0;

	memcpy(io->origin, id, DNET_ID_SIZE);
	memcpy(io->id, id, DNET_ID_SIZE);

	dnet_log(n, DNET_LOG_INFO, "%s: local stat: reading %llu byte(s).\n",
			dnet_dump_id(cmd->id), (unsigned long long)io->size);

	dnet_convert_io_attr(io);

	err = n->command_handler(st, n->command_private, cmd, attr, io);
	dnet_log(n, DNET_LOG_INFO, "%s: local stat: io_size: %llu, err: %d.\n",
					dnet_dump_id(cmd->id),
					(unsigned long long)io->size, err);

	free(cmd);

err_out_exit:
	return err;
}

static int dnet_cmd_lookup(struct dnet_net_state *orig, struct dnet_cmd *cmd,
		struct dnet_attr *attr, void *data __unused)
{
	struct dnet_node *n = orig->n;
	struct dnet_net_state *st;
	int err;
	unsigned int aflags = 0;

	st = dnet_state_search(n, cmd->id, NULL);
	if (!st)
		st = dnet_state_get(orig->n->st);

	if (attr->flags) {
		err = dnet_stat_local(orig, cmd->id);
		dnet_log(n, DNET_LOG_NOTICE, "%s: object is stored locally: %d.\n",
				dnet_dump_id(cmd->id), !err);
		if (!err)
			aflags = 1;
	}

	err = dnet_send_address(orig, st->id, cmd->trans, DNET_CMD_LOOKUP, aflags, &st->addr, 1, 0);
	dnet_state_put(st);
	return err;
}

static int dnet_cmd_reverse_lookup(struct dnet_net_state *st, struct dnet_cmd *cmd __unused,
		struct dnet_attr *attr __unused, void *data __unused)
{
	struct dnet_node *n = st->n;

	return dnet_send_address(st, n->id, cmd->trans, DNET_CMD_REVERSE_LOOKUP, 0,
			&n->addr, 1, 0);
}

static int dnet_cmd_join_client(struct dnet_net_state *orig, struct dnet_cmd *cmd,
		struct dnet_attr *attr __unused, void *data)
{
	struct dnet_node *n = orig->n;
	struct dnet_addr_attr *a = data;
	int err;

	if (!(cmd->flags & DNET_FLAGS_DIRECT)) {
		int s;
		struct dnet_net_state *st = NULL;

		dnet_convert_addr_attr(a);

		s = dnet_socket_create_addr(n, a->sock_type, a->proto, a->family,
				(struct sockaddr *)&a->addr, a->addr.addr_len, 0);
		if (s < 0) {
			err = s;
			goto err_out_exit;
		}

		st = dnet_state_create(n, cmd->id, &a->addr, s);
		if (!st) {
			err = -EINVAL;
			close(s);
			goto err_out_exit;
		}
	} else {
		dnet_convert_addr_attr(a);

		orig->join_state = DNET_CLIENT_JOINED;
		memcpy(&orig->addr, &a->addr, sizeof(struct dnet_addr));
		memcpy(orig->id, cmd->id, DNET_ID_SIZE);

		err = dnet_state_move(orig);
		if (err)
			goto err_out_exit;
	}

	dnet_log(n, DNET_LOG_INFO, "%s: state %s.\n", dnet_dump_id(cmd->id),
		dnet_server_convert_dnet_addr(&a->addr));

	return 0;

err_out_exit:
	dnet_log(n, DNET_LOG_ERROR, "%s: failed to join to state %s.\n",
		dnet_dump_id(cmd->id), dnet_server_convert_dnet_addr(&orig->addr));
	return err;
}

static int dnet_cmd_route_list(struct dnet_net_state *orig, struct dnet_cmd *req)
{
	struct dnet_node *n = orig->n;
	struct dnet_net_state *st;
	int def_num = 1024, err, idx = 0;
	struct dnet_attr ca;
	struct dnet_route_attr attr[def_num], *a;

	ca.cmd = DNET_CMD_ROUTE_LIST;
	ca.size = 0;
	ca.flags = 0;

	dnet_log(n, DNET_LOG_INFO, "%s: route request from %s.\n",
			dnet_dump_id(orig->id), dnet_state_dump_addr(orig));

	pthread_rwlock_rdlock(&n->state_lock);
	list_for_each_entry(st, &n->state_list, state_entry) {
		err = -1;

		if (!memcmp(&st->addr, &orig->addr, sizeof(struct dnet_addr)))
			goto out_continue;

		if (!memcmp(st->id, n->id, DNET_ID_SIZE))
			goto out_continue;

		err = 0;
		if (idx == def_num) {
			err = dnet_send_reply(orig, req, &ca, attr,
				idx * sizeof(struct dnet_route_attr), 1);
			if (err)
				goto err_out_unlock;

			idx = 0;
		}

		a = &attr[idx];

		memcpy(a->id, st->id, DNET_ID_SIZE);
		memcpy(&a->addr.addr, &st->addr, sizeof(struct dnet_addr));
		a->addr.family = n->family;
		a->addr.sock_type = n->sock_type;
		a->addr.proto = n->proto;

		dnet_convert_addr_attr(&a->addr);
		idx++;

out_continue:
		dnet_log(n, DNET_LOG_INFO, "%s: route to %s [%c].\n",
			dnet_dump_id(st->id), dnet_state_dump_addr(st),
			(err) ? '-' : '+');
	}

	if (idx) {
		err = dnet_send_reply(orig, req, &ca, attr,
			idx * sizeof(struct dnet_route_attr), 1);
		if (err)
			goto err_out_unlock;
	}
	pthread_rwlock_unlock(&n->state_lock);

	return 0;

err_out_unlock:
	pthread_rwlock_unlock(&n->state_lock);
	return err;
}

static int dnet_cmd_transform_list(struct dnet_net_state *orig, struct dnet_cmd *req)
{
	struct dnet_node *n = orig->n;
	struct dnet_cmd *cmd;
	struct dnet_attr *attr;
	struct dnet_transform *t;
	struct dnet_data_req *r;
	int num = n->transform_num;
	char *data;
	int sz;

	if (!num)
		return 0;

	sz = sizeof(struct dnet_cmd) + sizeof(struct dnet_attr) + num * DNET_MAX_NAME_LEN;

	r = dnet_req_alloc(orig, sz);
	if (!r)
		return -ENOMEM;

	cmd = dnet_req_header(r);
	attr = (struct dnet_attr *)(cmd + 1);
	data = (char *)(attr + 1);

	memcpy(cmd->id, req->id, DNET_ID_SIZE);
	cmd->size = sizeof(struct dnet_attr);
	cmd->trans = req->trans | DNET_TRANS_REPLY;
	if (req->flags & DNET_FLAGS_NEED_ACK)
		cmd->flags = DNET_FLAGS_MORE;

	attr->size = 0;
	attr->cmd = DNET_CMD_TRANSFORM_LIST;

	pthread_rwlock_rdlock(&n->transform_lock);
	list_for_each_entry(t, &n->transform_list, tentry) {
		if (num > 0) {
			snprintf(data, DNET_MAX_NAME_LEN - 1, "%s", t->name);

			data += DNET_MAX_NAME_LEN;
			cmd->size += DNET_MAX_NAME_LEN;
			attr->size += DNET_MAX_NAME_LEN;
			num--;
		}
	}
	pthread_rwlock_unlock(&n->transform_lock);

	if (!attr->size) {
		dnet_req_destroy(r, 0);
		return 0;
	}

	dnet_convert_cmd(cmd);
	dnet_convert_attr(attr);

	return dnet_data_ready(orig, r);
}

static int dnet_local_transform_complete(struct dnet_net_state *st, struct dnet_cmd *cmd,
					struct dnet_attr *attr __unused, void *priv)
{
	if (!st || !cmd || !(cmd->flags & DNET_FLAGS_MORE))
		free(priv);
	return 0;
}

static int dnet_local_transform(struct dnet_net_state *orig, struct dnet_cmd *cmd,
		struct dnet_attr *attr, void *odata)
{
	struct dnet_node *n = orig->n;
	struct dnet_io_control ctl;
	int err;
	void *data;

	if (!n->transform_num)
		return 0;

	if (attr->size <= sizeof(struct dnet_io_attr)) {
		dnet_log(n, DNET_LOG_ERROR, "%s: wrong write attribute, size does not match "
				"IO attribute size: size: %llu, must be more than %zu.\n",
				dnet_dump_id(cmd->id), (unsigned long long)attr->size,
				sizeof(struct dnet_io_attr));
		err = -EINVAL;
		goto err_out_exit;
	}

	memset(&ctl, 0, sizeof(struct dnet_io_control));
	memcpy(&ctl.io, odata, sizeof(struct dnet_io_attr));
	odata += sizeof(struct dnet_io_attr);

	dnet_convert_io_attr(&ctl.io);

	if (attr->size != sizeof(struct dnet_io_attr) + ctl.io.size) {
		dnet_log(n, DNET_LOG_ERROR, "%s: IO attribute size (%llu) plus header (%zu)"
				" does not match write size (must be %llu).\n",
				dnet_dump_id(cmd->id), (unsigned long long)ctl.io.size,
				sizeof(struct dnet_io_attr), (unsigned long long)attr->size);
		err = -EINVAL;
		goto err_out_exit;
	}

	data = malloc(ctl.io.size);
	if (!data) {
		dnet_log(n, DNET_LOG_ERROR, "%s: failed to clone data (%llu bytes) for replication.\n",
				dnet_dump_id(cmd->id), (unsigned long long)ctl.io.size);
		err = -ENOMEM;
		goto err_out_exit;
	}

	memcpy(data, odata, ctl.io.size);

	ctl.aflags = attr->flags;
	ctl.cmd = DNET_CMD_WRITE;
	ctl.cflags = DNET_FLAGS_NEED_ACK | DNET_FLAGS_NO_LOCAL_TRANSFORM;

	ctl.complete = dnet_local_transform_complete;
	ctl.priv = data;

	ctl.data = data;
	ctl.fd = -1;

	return dnet_write_object(n, &ctl, NULL, 0, 0, 0, &err);

err_out_exit:
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

	dnet_log(n, DNET_LOG_NOTICE, "%s: command: '%s'.\n", dnet_dump_id(cmd->id), command);

	pid = fork();
	if (pid < 0) {
		err = -errno;
		dnet_log_err(n, "%s: failed to fork a child process", dnet_dump_id(cmd->id));
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
					dnet_dump_id(cmd->id), (int)pid);
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

static int dnet_data_sync(struct dnet_net_state *st, struct dnet_cmd *cmd,
		struct dnet_attr *attr, void *data)
{
	struct dnet_node *n = st->n;
	uint64_t num;

	if (!attr->size || (attr->size % DNET_ID_SIZE)) {
		dnet_log(n, DNET_LOG_ERROR, "%s: attribute size %llu "
				"is not multiple of DNET_ID_SIZE(%u).\n",
				dnet_dump_id(cmd->id),
				(unsigned long long)attr->size, DNET_ID_SIZE);
		return -EINVAL;
	}

	num = attr->size / DNET_ID_SIZE;

	return dnet_fetch_objects(st, data, num, NULL);
}

int dnet_process_cmd(struct dnet_trans *t)
{
	struct dnet_net_state *st = t->st;
	struct dnet_cmd *cmd = &t->cmd;
	void *data = t->data;
	int err = 0;
	unsigned long long size = cmd->size;
	struct dnet_node *n = st->n;
	unsigned long long tid = cmd->trans & ~DNET_TRANS_REPLY;

	dnet_log(n, DNET_LOG_INFO, "%s: processing local cmd: size: %llu, trans: %llu, flags: %x.\n",
			dnet_dump_id(cmd->id), size, tid, cmd->flags);

	while (size) {
		struct dnet_attr *a = data;
		unsigned long long sz;

		dnet_convert_attr(a);
		sz = a->size;

		if (size < sizeof(struct dnet_attr)) {
			dnet_log(st->n, DNET_LOG_ERROR, "%s: 1 wrong cmd: size: %llu/%llu, "
					"attr_size: %llu.\n",
					dnet_dump_id(st->id), (unsigned long long)cmd->size,
					size, sz);
			err = -EINVAL;
			break;
		}

		data += sizeof(struct dnet_attr);
		size -= sizeof(struct dnet_attr);

		if (size < a->size) {
			dnet_log(n, DNET_LOG_ERROR, "%s: 2 wrong cmd: size: %llu/%llu, "
					"attr_size: %llu.\n",
				dnet_dump_id(st->id), (unsigned long long)cmd->size, size, sz);
			err = -EINVAL;
			break;
		}

		dnet_log(n, DNET_LOG_INFO, "%s: trans: %llu, transaction_size_left: %llu, "
				"starting cmd: %u, attribute_size: %llu, attribute_flags: %x.\n",
			dnet_dump_id(cmd->id), tid,
			size, a->cmd, (unsigned long long)a->size, a->flags);

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
			case DNET_CMD_TRANSFORM_LIST:
				err = dnet_cmd_transform_list(st, cmd);
				break;
			case DNET_CMD_EXEC:
				err = dnet_cmd_exec(st, cmd, a, data);
				break;
			case DNET_CMD_NOTIFY:
				if (!a->flags) {
					err = dnet_notify_add(st, cmd);
					/*
					 * We drop need ack flag, since notification
					 * transaction is a long-standing one, since
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
			case DNET_CMD_SYNC:
				err = dnet_data_sync(st, cmd, a, data);
				break;
			case DNET_CMD_WRITE:
				if (!(cmd->flags & DNET_FLAGS_NO_LOCAL_TRANSFORM))
					err = dnet_local_transform(st, cmd, a, data);
			default:
				if (!n->command_handler)
					err = -EINVAL;
				else {
					err = n->command_handler(st, n->command_private, cmd, a, data);
					if (a->cmd == DNET_CMD_LIST && !err &&
							(st->join_state != DNET_JOINED)) {
						/*
						 * This should be only invoked for the accepted connections which can
						 * only be in DNET_CLIENT state. When connection drops, accepted state
						 * is destroyed.
						 *
						 * All states used by client to connect to remote servers are in
						 * DNET_JOINED state, so there will be no list command recursion.
						 */

						//err = dnet_recv_list(n, st);
					}
				}
				if (a->cmd == DNET_CMD_WRITE && !err)
					dnet_update_notify(st, cmd, a, data);
				break;
		}

		dnet_log(n, DNET_LOG_INFO, "%s: trans: %llu, transaction_size_left: %llu, "
				"starting cmd: %u, attribute_size: %llu, err: %d.\n",
			dnet_dump_id(cmd->id), tid, size,
			a->cmd, (unsigned long long)a->size, err);

		if (err)
			break;

		if (size < sz) {
			dnet_log(n, DNET_LOG_ERROR, "%s: 3 wrong cmd: size: %llu/%llu, "
					"attr_size: %llu.\n",
				dnet_dump_id(st->id), (unsigned long long)cmd->size, size, sz);
			err = -EINVAL;
			break;
		}

		data += sz;
		size -= sz;
	}

	if (cmd->flags & DNET_FLAGS_NEED_ACK) {
		struct dnet_cmd *ack;

		dnet_req_set_complete(&t->r, dnet_req_trans_destroy, NULL);

		dnet_req_set_header(&t->r, cmd, sizeof(struct dnet_cmd), 0);
		dnet_req_set_flags(&t->r, ~0, DNET_REQ_NO_DESTRUCT);
		ack = dnet_req_header(&t->r);

		memcpy(ack->id, cmd->id, DNET_ID_SIZE);
		ack->trans = cmd->trans | DNET_TRANS_REPLY;
		ack->size = 0;
		ack->flags = cmd->flags & ~(DNET_FLAGS_NEED_ACK | DNET_FLAGS_MORE);
		ack->status = err;

		dnet_log(n, DNET_LOG_NOTICE, "%s: ack trans: %llu, flags: %x, status: %d.\n",
				dnet_dump_id(cmd->id), tid,
				ack->flags, err);

		dnet_convert_cmd(ack);
		dnet_data_ready(st, &t->r);
	}

	return err;
}

static struct dnet_net_state *dnet_add_state_socket(struct dnet_node *n, struct dnet_addr *addr, int s)
{
	struct dnet_net_state *st, dummy;
	char buf[sizeof(struct dnet_cmd) + sizeof(struct dnet_attr)];
	struct dnet_addr_cmd acmd;
	struct dnet_cmd *cmd;
	struct dnet_attr *a;
	int err;

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

	err = dnet_send(st, buf, sizeof(buf));
	if (err) {
		dnet_log(n, DNET_LOG_ERROR, "%s: failed to send reverse "
				"lookup message to %s, err: %d.\n",
				dnet_dump_id(n->id),
				dnet_server_convert_dnet_addr(addr), err);
		goto err_out_exit;
	}

	err = dnet_recv(st, &acmd, sizeof(acmd));
	if (err < 0) {
		dnet_log(n, DNET_LOG_ERROR, "%s: failed to receive reverse "
				"lookup response from %s, err: %d.\n",
				dnet_dump_id(n->id),
				dnet_server_convert_dnet_addr(addr), err);
		goto err_out_exit;
	}

	dnet_convert_addr_cmd(&acmd);

	dnet_log(n, DNET_LOG_NOTICE, "%s reverse lookup -> %s.\n", dnet_dump_id(acmd.cmd.id),
		dnet_server_convert_dnet_addr(&acmd.addr.addr));

	st = dnet_state_create(n, acmd.cmd.id, &acmd.addr.addr, s);
	if (!st) {
		err = -EINVAL;
		goto err_out_exit;
	}

	return st;

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
	if (s < 0)
		return s;

	st = dnet_add_state_socket(n, &addr, s);
	if (!st) {
		err = -EINVAL;
		goto err_out_sock_close;
	}

	return 0;

err_out_sock_close:
	close(s);
	return err;
}

static int dnet_add_received_state(struct dnet_node *n, unsigned char *id,
		struct dnet_attr *attr, struct dnet_addr_attr *a)
{
	int s, err = 0;
	struct dnet_net_state *nst;

	nst = dnet_state_search(n, id, NULL);
	if (nst) {
		if (!dnet_id_cmp(id, nst->id))
			err = -EEXIST;
		dnet_state_put(nst);
		if (err)
			goto err_out_exit;
	}

	s = dnet_socket_create_addr(n, a->sock_type, a->proto, a->family,
			(struct sockaddr *)&a->addr.addr, a->addr.addr_len, 0);
	if (s < 0) {
		err = s;
		goto err_out_exit;
	}

	nst = dnet_state_create(n, id, &a->addr, s);
	if (!nst) {
		err = -EINVAL;
		goto err_out_close;
	}

	if (!attr->flags) {
		err = dnet_send_address(nst, n->id, 0, DNET_CMD_JOIN, 0, &n->addr, 0, 1);
		if (err) {
			dnet_log(n, DNET_LOG_ERROR, "%s: failed to join to state %s.\n",
				dnet_dump_id(nst->id), dnet_state_dump_addr(nst));
			goto err_out_put;
		}
	}

	dnet_log(n, DNET_LOG_INFO, "%s: added state %s.\n", dnet_dump_id(id),
		dnet_state_dump_addr(nst));

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
	struct dnet_route_attr *attrs, *a;
	struct dnet_node *n;
	int err, num, i;

	if (!st || !cmd || !attr) {
		err = -EINVAL;
		goto err_out_exit;
	}

	if (!cmd->size || cmd->status) {
		err = cmd->status;
		goto err_out_exit;
	}

	n = st->n;

	if (attr->size % sizeof(struct dnet_route_attr)) {
		dnet_log(n, DNET_LOG_ERROR, "%s: wrong attribute size in route list reply %llu, must be modulo of %zu.\n",
				dnet_dump_id(cmd->id), (unsigned long long)attr->size, sizeof(struct dnet_route_attr));
		err = -EINVAL;
		goto err_out_exit;
	}

	attrs = (struct dnet_route_attr *)(attr + 1);

	num = attr->size / sizeof(struct dnet_route_attr);
	dnet_log(n, DNET_LOG_INFO, "%s: route list: %d entries.\n", dnet_dump_id(cmd->id), num);
	i = 0;
	while (i < num) {
		a = &attrs[i];

		dnet_convert_addr_attr(&a->addr);

		err = dnet_add_received_state(n, a->id, attr, &a->addr);
		
		dnet_log(n, DNET_LOG_INFO, " %2d/%d   %s - %s, added error: %d.\n",
				i, num, dnet_dump_id(a->id),
				dnet_server_convert_dnet_addr(&a->addr.addr), err);

		if (num < 10 || !i)
			i++;
		else
			i <<= 1;
	}

	return 0;

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

	memcpy(cmd->id, st->id, DNET_ID_SIZE);
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

	dnet_log(n, DNET_LOG_NOTICE, "%s: list route request to %s.\n", dnet_dump_id(st->id),
		dnet_server_convert_dnet_addr(&st->addr));

	dnet_req_set_header(&t->r, t+1, sizeof(struct dnet_attr) +
			sizeof(struct dnet_cmd), 0);
	dnet_req_set_flags(&t->r, ~0, DNET_REQ_NO_DESTRUCT);

	err = dnet_data_ready(st, &t->r);
	if (err)
		goto err_out_destroy;

	return 0;

err_out_destroy:
	dnet_trans_put(t);
err_out_exit:
	return err;
}

int dnet_rejoin(struct dnet_node *n, int all)
{
	int err = 0;
	struct dnet_net_state *st, *prev;

	if (!n->command_handler) {
		dnet_log(n, DNET_LOG_ERROR, "%s: can not join without command handler.\n",
				dnet_dump_id(n->id));
		return -EINVAL;
	}

	/*
	 * Need to sync local content.
	 */
	err = dnet_recv_list(n, NULL);
	if (err) {
		dnet_log(n, DNET_LOG_ERROR, "%s: content sync failed, error: %d.\n",
				dnet_dump_id(n->id), err);
		if (err != -ENOENT)
			return err;

		err = 0;
	}

	pthread_rwlock_rdlock(&n->state_lock);
	list_for_each_entry(st, &n->state_list, state_entry) {
		if (st == n->st)
			continue;

		dnet_log(n, DNET_LOG_NOTICE, "%s: sending join: all: %d, state: %x.\n",
				dnet_dump_id(st->id), all, st->join_state);

		if (!all && st->join_state != DNET_REJOIN)
			continue;

		err = dnet_send_address(st, n->id, 0, DNET_CMD_JOIN, 0, &n->addr, 0, 1);
		if (err) {
			dnet_log(n, DNET_LOG_ERROR, "%s: failed to rejoin to state %s.\n",
				dnet_dump_id(st->id), dnet_server_convert_dnet_addr(&st->addr));
			break;
		}

		err = dnet_recv_route_list(st);
		if (err) {
			dnet_log(n, DNET_LOG_ERROR, "%s: failed to send route list request to %s.\n",
				dnet_dump_id(st->id), dnet_server_convert_dnet_addr(&st->addr));
			break;
		}

		st->join_state = DNET_JOINED;
	}
	pthread_rwlock_unlock(&n->state_lock);

	prev = dnet_state_get_prev(n->st);
	if (prev) {
		if (prev != n->st)
			dnet_request_sync(prev, n->id);
		dnet_state_put(prev);
	}

	return err;
}

int dnet_join(struct dnet_node *n)
{
	int err;

	err = dnet_rejoin(n, 1);
	if (err)
		return err;

	n->join_state = DNET_JOINED;
	return 0;
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
			dnet_log(st->n, DNET_LOG_INFO, "%s: object write completed: trans: %llu, status: %d.\n",
				dnet_dump_id(cmd->id), (unsigned long long)(cmd->trans & ~DNET_TRANS_REPLY),
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
					dnet_dump_id(ctl->addr), ctl->asize, sizeof(struct dnet_attr));
			err = -EINVAL;
			goto err_out_exit;
		}

		a = ctl->adata;

		if (a->size != ctl->asize - sizeof(struct dnet_attr)) {
			dnet_log(n, DNET_LOG_ERROR, "%s: additional attribute size (%llu) does not match "
					"structure's attribute size %llu.\n",
					dnet_dump_id(ctl->addr),
					(unsigned long long)ctl->asize - sizeof(struct dnet_attr),
					(unsigned long long)a->size);
			err = -EINVAL;
			goto err_out_exit;
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

	dnet_req_set_header(&t->r, t+1, tsize, 0);
	dnet_req_set_fd(&t->r, ctl->fd, ctl->io.offset, size, 0);
	dnet_req_set_flags(&t->r, ~0, DNET_REQ_NO_DESTRUCT);

	if (ctl->fd < 0 && size < DNET_COPY_IO_SIZE) {
		if (size) {
			void *data = io + 1;
			memcpy(data, ctl->data, size);
		}
	} else if (ctl->fd < 0 && size && ctl->data) {
		dnet_req_set_data(&t->r, ctl->data, size, 0, 0);
	}

	memcpy(cmd->id, ctl->addr, DNET_ID_SIZE);
	cmd->size = sizeof(struct dnet_attr) + sizeof(struct dnet_io_attr) + size + ctl->asize;
	cmd->flags = ctl->cflags;
	cmd->status = 0;

	a->cmd = ctl->cmd;
	a->size = sizeof(struct dnet_io_attr) + size;
	a->flags = ctl->aflags;

	memcpy(io, &ctl->io, sizeof(struct dnet_io_attr));

	memcpy(&t->cmd, cmd, sizeof(struct dnet_cmd));

	t->st = dnet_state_get_first(n, cmd->id, n->st);
	if (!t->st) {
		dnet_log(n, DNET_LOG_ERROR, "%s: failed to find a state.\n", dnet_dump_id(cmd->id));
		goto err_out_destroy;
	}

	err = dnet_trans_insert(t);
	if (err)
		goto err_out_destroy;

	cmd->trans = t->trans;
	dnet_convert_cmd(cmd);
	dnet_convert_attr(a);
	dnet_convert_io_attr(io);

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

int dnet_trans_create_send(struct dnet_node *n, struct dnet_io_control *ctl)
{
	struct dnet_trans *t;
	struct dnet_net_state *st;
	int err;

	if (ctl->cflags & DNET_FLAGS_NO_LOCAL_TRANSFORM) {
		int local;

		st = dnet_state_get_first(n, ctl->addr, NULL);

		local = (!st || st == n->st);

		dnet_log(n, DNET_LOG_INFO, "%s: server-side replica -> %s.\n",
				dnet_dump_id(ctl->addr),
				(!local) ? dnet_server_convert_dnet_addr(&st->addr) : "local");
		dnet_state_put(st);
		if (local)
			return 0;
	}

	t = dnet_io_trans_create(n, ctl);
	if (!t) {
		err = -ENOMEM;
		dnet_log(n, DNET_LOG_ERROR, "%s: failed to create transaction.\n", dnet_dump_id(ctl->addr));
		goto err_out_exit;
	}
	st = t->st;

	dnet_log(n, DNET_LOG_INFO, "%s: created trans: %llu, cmd: %u, size: %llu, offset: %llu -> %s.\n",
			dnet_dump_id(ctl->addr),
			(unsigned long long)t->trans, ctl->cmd,
			(unsigned long long)ctl->io.size, (unsigned long long)ctl->io.offset,
			dnet_server_convert_dnet_addr(&st->addr));

	err = dnet_data_ready(st, &t->r);
	if (err)
		goto err_out_destroy;

	return 0;

err_out_destroy:
	dnet_trans_put(t);
err_out_exit:
	return err;
}

static int dnet_write_object_raw(struct dnet_node *n, struct dnet_io_control *ctl,
		void *remote, unsigned int len, unsigned char *id, int hupdate, int *pos)
{
	unsigned int rsize;
	int err;
	unsigned char addr[DNET_ID_SIZE];
	struct dnet_io_control hctl;
	struct dnet_history_entry e;

	if (!(ctl->aflags & DNET_ATTR_DIRECT_TRANSACTION)) {
		rsize = DNET_ID_SIZE;
		err = dnet_transform(n, ctl->data, ctl->io.size, ctl->io.origin, ctl->addr, &rsize, pos);
		if (err) {
			if (err > 0)
				return err;
			goto err_out_complete;
		}

		if (!id && remote && len)
			*pos = *pos - 1;
	}

	if (id) {
		memcpy(ctl->io.id, id, DNET_ID_SIZE);
		memcpy(addr, id, DNET_ID_SIZE);
	} else {
		/*
		 * Copy origin ID in case transformation function wants to work with it.
		 */
		memcpy(ctl->io.id, ctl->io.origin, DNET_ID_SIZE);

		if (remote && len) {
			rsize = DNET_ID_SIZE;
			err = dnet_transform(n, remote, len, ctl->io.id, addr, &rsize, pos);
			if (err) {
				if (err > 0)
					return err;
				goto err_out_complete;
			}
		}
	}

	if (ctl->aflags & DNET_ATTR_DIRECT_TRANSACTION) {
		memcpy(ctl->io.origin, ctl->io.id, DNET_ID_SIZE);
		memcpy(ctl->addr, ctl->io.id, DNET_ID_SIZE);
	}

	err = dnet_trans_create_send(n, ctl);
	if (err)
		goto err_out_exit;

	if (!hupdate)
		return 0;

	if (!id && (!remote || !len))
		return 0;

	memcpy(hctl.addr, addr, DNET_ID_SIZE);
	memcpy(hctl.io.origin, ctl->io.id, DNET_ID_SIZE);
	memcpy(hctl.io.id, addr, DNET_ID_SIZE);

	dnet_setup_history_entry(&e, ctl->io.origin, ctl->io.size, ctl->io.offset, 0);

	hctl.priv = ctl->priv;
	hctl.complete = ctl->complete;
	hctl.cmd = DNET_CMD_WRITE;
	hctl.aflags = 0;
	hctl.cflags = DNET_FLAGS_NEED_ACK;
	hctl.fd = -1;
	hctl.adata = NULL;
	hctl.asize = 0;

	hctl.data = &e;

	hctl.io.size = sizeof(struct dnet_history_entry);
	hctl.io.offset = 0;
	hctl.io.flags = DNET_IO_FLAGS_HISTORY | DNET_IO_FLAGS_APPEND;

	err = dnet_trans_create_send(n, &hctl);
	if (err)
		goto err_out_exit;

	return 0;

err_out_complete:
	if (ctl->complete)
		ctl->complete(NULL, NULL, NULL, ctl->priv);
err_out_exit:
	return err;
}

int dnet_write_object(struct dnet_node *n, struct dnet_io_control *ctl,
		void *remote, unsigned int len,
		unsigned char *id, int hupdate, int *trans_nump)
{
	int pos = 0, err = 0, num = 0;
	int error = 0;
	void *data = ctl->data;
	struct dnet_io_attr tmp = ctl->io;

	while (1) {
		uint64_t sz, size = tmp.size;

		ctl->data = data;

		ctl->io = tmp;
		while (size) {
			sz = size;
			if (!(ctl->aflags & DNET_ATTR_NO_TRANSACTION_SPLIT) &&
					sz > DNET_MAX_TRANS_SIZE)
				sz = DNET_MAX_TRANS_SIZE;

			ctl->io.size = sz;
			err = dnet_write_object_raw(n, ctl, remote, len, id, hupdate, &pos);
			if (err) {
				if (err > 0)
					break;
				error = err;
				break;
			}

			ctl->data += sz;
			ctl->io.offset += sz;
			size -= sz;

			error = 0;
			if (size)
				pos--;

			num++;
			if (hupdate)
				num++;
		}

		if (err > 0 || pos == 0)
			break;
	}

	*trans_nump = num;

	if (error < 0)
		return error;

	return 0;
}

int dnet_write_file(struct dnet_node *n, char *file, unsigned char *id, uint64_t offset, uint64_t size, unsigned int aflags)
{
	int fd, err, trans_num, error;
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

	if (offset >= (uint64_t)stat.st_size) {
		err = 0;
		goto err_out_close;
	}

	if (!size || size + offset >= (uint64_t)stat.st_size)
		size = stat.st_size - offset;

	memset(&ctl, 0, sizeof(struct dnet_io_control));

	off = offset & ~(page_size - 1);

	data = mmap(NULL, ALIGN(size + offset - off, page_size), PROT_READ, MAP_SHARED, fd, off);
	if (data == MAP_FAILED) {
		err = -errno;
		dnet_log_err(n, "Failed to map to be written file '%s', "
				"size: %llu, use: %llu, offset: %llu, use: %llu",
				file, size, ALIGN(size + offset - off, page_size),
				offset, off);
		goto err_out_close;
	}

	atomic_set(&w->refcnt, INT_MAX);

	ctl.data = data + offset - off;
	ctl.fd = fd;

	dnet_log(n, DNET_LOG_NOTICE, "data: %p, ctl.data: %p, offset: %llu/%llu, size: %llu/%llu\n",
			data, ctl.data, offset, off, size, ALIGN(size, page_size));

	ctl.complete = dnet_write_complete;
	ctl.priv = w;

	ctl.cflags = DNET_FLAGS_NEED_ACK;
	ctl.cmd = DNET_CMD_WRITE;
	ctl.aflags = aflags;

	ctl.io.flags = 0;
	ctl.io.size = size;
	ctl.io.offset = offset;

	error = dnet_write_object(n, &ctl, file, strlen(file), id, 1, &trans_num);

	dnet_log(n, DNET_LOG_INFO, "%s: transactions sent: %d, error: %d.\n",
			dnet_dump_id(ctl.addr), trans_num, error);

	/*
	 * 1 - the first reference counter we grabbed at allocation time
	 */
	atomic_sub(&w->refcnt, INT_MAX - trans_num - 1);

	munmap(data, ALIGN(size, page_size));

	err = dnet_wait_event(w, w->cond == trans_num, &n->wait_ts);
	if (err || w->status) {
		if (!err)
			err = w->status;
	}

	if (!err && error)
		err = error;

	if (err)
		dnet_log(n, DNET_LOG_ERROR, "Failed to write file '%s' into the storage, err: %d.\n", file, err);
	else
		dnet_log(n, DNET_LOG_INFO, "Successfully wrote file: '%s' into the storage, size: %llu.\n",
				file, (unsigned long long)size);

	close(fd);
	dnet_wait_put(w);

	return err;

err_out_close:
	close(fd);
err_out_put:
	dnet_wait_put(w);
err_out_exit:
	return err;
}

static int dnet_read_complete(struct dnet_net_state *st, struct dnet_cmd *cmd, struct dnet_attr *a, void *priv)
{
	int fd, err, freeing = 0;
	struct dnet_node *n = st->n;
	struct dnet_io_completion *c = priv;
	struct dnet_io_attr *io;
	void *data;

	if (!st || !cmd) {
		err = -ENOMEM;
		freeing = 1;
		goto err_out_exit;
	}

	freeing = !(cmd->flags & DNET_FLAGS_MORE);

	if (cmd->status != 0 || cmd->size == 0) {
		err = cmd->status;

		dnet_log(n, DNET_LOG_INFO, "%s: read completed: file: '%s', status: %d, freeing: %d.\n",
				dnet_dump_id(cmd->id), c->file, cmd->status, freeing);
		goto err_out_exit;
	}

	if (cmd->size <= sizeof(struct dnet_attr) + sizeof(struct dnet_io_attr)) {
		dnet_log(n, DNET_LOG_ERROR, "%s: read completion error: wrong size: cmd_size: %llu, must be more than %zu.\n",
				dnet_dump_id(cmd->id), (unsigned long long)cmd->size,
				sizeof(struct dnet_attr) + sizeof(struct dnet_io_attr));
		err = -EINVAL;
		goto err_out_exit;
	}

	if (!a) {
		dnet_log(n, DNET_LOG_ERROR, "%s: no attributes but command size is not null.\n", dnet_dump_id(cmd->id));
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
		dnet_log_err(n, "%s: failed to open read completion file '%s'", dnet_dump_id(cmd->id), c->file);
		goto err_out_exit;
	}

	err = pwrite(fd, data, io->size, c->offset);
	if (err <= 0) {
		err = -errno;
		dnet_log_err(n, "%s: failed to write data into completion file '%s'", dnet_dump_id(cmd->id), c->file);
		goto err_out_close;
	}

	fsync(fd);
	close(fd);
	dnet_log(n, DNET_LOG_INFO, "%s: read completed: file: '%s', offset: %llu, size: %llu, status: %d.\n",
			dnet_dump_id(cmd->id), c->file, (unsigned long long)c->offset,
			(unsigned long long)io->size, cmd->status);

	return cmd->status;

err_out_close:
	dnet_log(n, DNET_LOG_ERROR, "%s: read completed: file: '%s', offset: %llu, size: %llu, status: %d, err: %d.\n",
			dnet_dump_id(cmd->id), c->file, (unsigned long long)io->offset,
			(unsigned long long)io->size, cmd->status, err);
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
	int err;

	err = dnet_trans_create_send(n, ctl);
	if (err) {
		dnet_log(n, DNET_LOG_ERROR, "Failed to read object %s, err: %d.\n",
				dnet_dump_id(ctl->addr), err);
		return err;
	}

	return 0;
}

static int dnet_read_file_id(struct dnet_node *n, char *file, int len,
		uint64_t write_offset,
		struct dnet_io_attr *io,
		struct dnet_wait *w, int hist, int wait)
{
	struct dnet_io_control ctl;
	struct dnet_io_completion *c;
	int err, wait_init = ~0;

	memset(&ctl, 0, sizeof(struct dnet_io_control));

	memcpy(&ctl.io, io, sizeof(struct dnet_io_attr));
	memcpy(ctl.addr, io->origin, DNET_ID_SIZE);

	ctl.fd = -1;
	ctl.complete = dnet_read_complete;
	ctl.cmd = DNET_CMD_READ;
	ctl.cflags = DNET_FLAGS_NEED_ACK;

	c = malloc(sizeof(struct dnet_io_completion) + len + 1 + sizeof(DNET_HISTORY_SUFFIX));
	if (!c) {
		dnet_log(n, DNET_LOG_ERROR, "%s: failed to allocate IO completion structure "
				"for '%s' file reading.\n",
				dnet_dump_id(ctl.io.id), file);
		err = -ENOMEM;
		goto err_out_exit;
	}

	memset(c, 0, sizeof(struct dnet_io_completion) + len + 1 + sizeof(DNET_HISTORY_SUFFIX));

	c->wait = dnet_wait_get(w);
	c->offset = write_offset;
	c->size = io->size;
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
					dnet_dump_id(ctl.addr), file, err);
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

	struct dnet_node		*node;

	struct dnet_wait		*wait;
};

static int dnet_trans_map_callback(void *priv, uint64_t offset, uint64_t size,
		struct dnet_history_entry *e)
{
	struct dnet_map_private *p = priv;
	struct dnet_io_attr io;
	int err;

	memcpy(io.origin, e->id, DNET_ID_SIZE);
	io.offset = offset - e->offset;
	io.size = size;
	io.flags = 0;

	err = dnet_read_file_id(p->node, p->file, p->len, offset, &io, p->wait, 0, 0);

	dnet_log(p->node, DNET_LOG_INFO, "%s: reading chunk into file '%s', offset: %llu/%llu, size: %llu, err: %d.\n",
			dnet_dump_id(e->id), p->file, (unsigned long long)io.offset,
			(unsigned long long)offset,
			(unsigned long long)io.size, err);

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

static int dnet_trans_map_match(struct dnet_map_root *r, struct dnet_history_entry *a)
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
		else
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

static int dnet_trans_map(struct dnet_node *n, char *main_file, uint64_t offset, uint64_t size,
		int (*callback)(void *priv, uint64_t offset, uint64_t size,
			struct dnet_history_entry *io), void *priv)
{
	int fd, err;
	struct stat st;
	struct dnet_map_root r;
	unsigned int isize = sizeof(struct dnet_history_entry);
	struct dnet_history_entry *entries, e;
	long i, num;
	char file[strlen(main_file) + 1 + sizeof(DNET_HISTORY_SUFFIX)];

	if (!callback)
		return 0;

	sprintf(file, "%s%s", main_file, DNET_HISTORY_SUFFIX);

	fd = open(file, O_RDONLY);
	if (fd < 0) {
		err = -errno;
		dnet_log_err(n, "Failed to open history file '%s'", file);
		goto err_out_exit;
	}

	err = fstat(fd, &st);
	if (err) {
		err = -errno;
		dnet_log_err(n, "Failed to stat history file '%s'", file);
		goto err_out_close;
	}

	if (!st.st_size || (st.st_size % isize)) {
		dnet_log(n, DNET_LOG_ERROR, "%s: Corrupted history file '%s', "
				"its size %llu has to be modulo of %u.\n",
				dnet_dump_id(n->id), file,
				(unsigned long long)st.st_size, isize);
		err = -EINVAL;
		goto err_out_close;
	}

	entries = mmap(NULL, st.st_size, PROT_READ, MAP_SHARED, fd, 0);
	if (entries == MAP_FAILED) {
		err = -errno;
		dnet_log_err(n, "Failed to mmap history file '%s'", file);
		goto err_out_close;
	}

	num = st.st_size / isize;

	r.root = RB_ROOT;
	r.callback = callback;
	r.priv = priv;
	r.offset = offset;

	if (!size) {
		e = entries[0];
		dnet_convert_history_entry(&e);
		size = e.size;
	}
	r.size = size;

	dnet_log(n, DNET_LOG_INFO, "%s: objects: %ld, range: %llu-%llu, "
			"counting from the most recent.\n",
			file, num, (unsigned long long)offset,
			(unsigned long long)offset+r.size);

	err = dnet_trans_map_add_range(&r, offset, size);
	if (err) {
		dnet_log(n, DNET_LOG_ERROR, "Failed to add range: offset: %llu, size: %llu, err: %d.\n",
			(unsigned long long)offset, (unsigned long long)size, err);
		goto err_out_unmap;
	}

	for (i=num-1; i>=1; --i) {
		e = entries[i];

		dnet_convert_history_entry(&e);

		err = dnet_trans_map_match(&r, &e);

		dnet_log(n, DNET_LOG_INFO, "%s: flags: %08x, offset: %8llu, size: %8llu: match: %d, rest: %llu\n",
			dnet_dump_id(e.id), e.flags,
			(unsigned long long)e.offset, (unsigned long long)e.size,
			err, (unsigned long long)r.size);

		if (err) {
			if (err < 0 && err != -ENOENT)
				goto err_out_free;
			continue;
		}

		if (!r.size)
			break;
	}

	dnet_trans_map_free(&r);
	munmap(entries, st.st_size);
	close(fd);

	return 0;

err_out_free:
	dnet_trans_map_free(&r);
err_out_unmap:
	munmap(entries, st.st_size);
err_out_close:
	close(fd);
err_out_exit:
	return err;

}

int dnet_read_file(struct dnet_node *n, char *file, unsigned char *id, uint64_t offset, uint64_t size, int hist)
{
	int err, len = strlen(file), pos = 0, error = 0;
	struct dnet_wait *w;
	struct dnet_io_attr io;

	w = dnet_wait_alloc(~0);
	if (!w) {
		err = -ENOMEM;
		dnet_log(n, DNET_LOG_ERROR, "Failed to allocate read waiting.\n");
		goto err_out_exit;
	}

	io.size = 0;
	io.offset = 0;
	io.flags = 0;
	io.flags = DNET_IO_FLAGS_HISTORY;

	if (id) {
		memcpy(io.origin, id, DNET_ID_SIZE);
		memcpy(io.id, id, DNET_ID_SIZE);

		err = dnet_read_file_id(n, file, len, 0, &io, w, 1, 1);
		if (err)
			goto err_out_put;
	} else {
		while (1) {
			unsigned int rsize = DNET_ID_SIZE;

			err = dnet_transform(n, file, len, io.origin, io.id, &rsize, &pos);
			if (err) {
				if (err > 0)
					break;
				if (!error)
					error = err;
				continue;
			}

			err = dnet_read_file_id(n, file, len, 0, &io, w, 1, 1);
			if (err) {
				error = err;
				continue;
			}

			error = 0;
			break;
		}

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

		err = dnet_trans_map(n, file, offset, size, dnet_trans_map_callback, &p);
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
					dnet_dump_id(n->id), file, (unsigned long long)offset,
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

int dnet_add_transform(struct dnet_node *n, void *priv, char *name,
	int (* init)(void *priv, struct dnet_node *n),
	int (* update)(void *priv, void *src, uint64_t size,
		void *dst, unsigned int *dsize, unsigned int flags),
	int (* final)(void *priv, void *dst, void *addr,
		unsigned int *dsize, unsigned int flags))
{
	struct dnet_transform *t;
	int err = 0;

	if (!n || !init || !update || !final || !name) {
		err = -EINVAL;
		goto err_out_exit;
	}

	pthread_rwlock_wrlock(&n->transform_lock);
	list_for_each_entry(t, &n->transform_list, tentry) {
		if (!strncmp(name, t->name, DNET_MAX_NAME_LEN)) {
			err = -EEXIST;
			goto err_out_unlock;
		}
	}

	t = malloc(sizeof(struct dnet_transform));
	if (!t) {
		err = -ENOMEM;
		goto err_out_unlock;
	}

	memset(t, 0, sizeof(struct dnet_transform));

	snprintf(t->name, sizeof(t->name), "%s", name);
	t->init = init;
	t->update = update;
	t->final = final;
	t->priv = priv;

	list_add_tail(&t->tentry, &n->transform_list);
	n->transform_num++;

	pthread_rwlock_unlock(&n->transform_lock);

	return 0;

err_out_unlock:
	pthread_rwlock_unlock(&n->transform_lock);
err_out_exit:
	return err;
}

int dnet_remove_transform(struct dnet_node *n, char *name)
{
	struct dnet_transform *t, *tmp;
	int err = -ENOENT;

	if (!n)
		return -EINVAL;

	pthread_rwlock_wrlock(&n->transform_lock);
	list_for_each_entry_safe(t, tmp, &n->transform_list, tentry) {
		if (!strncmp(name, t->name, DNET_MAX_NAME_LEN)) {
			err = 0;
			break;
		}
	}

	if (!err) {
		n->transform_num--;
		list_del(&t->tentry);
		free(t);
	}
	pthread_rwlock_unlock(&n->transform_lock);

	return err;
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
	w->cond = 1;
}

static int dnet_send_cmd_complete(struct dnet_net_state *st, struct dnet_cmd *cmd,
			struct dnet_attr *attr __unused, void *priv)
{
	int err = -EINVAL;

	if (!cmd || cmd->size == 0 || !cmd->status) {
		struct dnet_wait *w = priv;

		if (cmd) {
			dnet_log(st->n, DNET_LOG_INFO, "%s: completed command, err: %d.\n",
				dnet_dump_id(cmd->id), cmd->status);
			err = cmd->status;
		}

		dnet_wakeup(w, __dnet_send_cmd_complete(w, err));
		dnet_wait_put(w);
	} else
		err = cmd->status;

	return err;
}

int dnet_send_cmd(struct dnet_node *n, unsigned char *id, char *command)
{
	struct dnet_trans *t;
	struct dnet_net_state *st;
	int err, len = strlen(command) + 1;
	struct dnet_attr *a;
	struct dnet_cmd *cmd;
	struct dnet_wait *w;

	w = dnet_wait_alloc(0);
	if (!w) {
		err = -ENOMEM;
		goto err_out_exit;
	}

	t = dnet_trans_alloc(n,	sizeof(struct dnet_cmd) +
			sizeof(struct dnet_attr) + len);
	if (!t) {
		err = -ENOMEM;
		goto err_out_put;
	}

	t->complete = dnet_send_cmd_complete;
	t->priv = dnet_wait_get(w);

	cmd = (struct dnet_cmd *)(t + 1);
	a = (struct dnet_attr *)(cmd + 1);

	memcpy(cmd->id, id, DNET_ID_SIZE);
	cmd->size = sizeof(struct dnet_attr) + len;
	cmd->flags = DNET_FLAGS_NEED_ACK;
	cmd->status = 0;

	memcpy(&t->cmd, cmd, sizeof(struct dnet_cmd));

	a->cmd = DNET_CMD_EXEC;
	a->size = len;
	a->flags = 0;

	sprintf((char *)(a+1), "%s", command);

	st = t->st = dnet_state_get_first(n, cmd->id, n->st);
	if (!t->st) {
		err = -ENOENT;
		dnet_log(n, DNET_LOG_ERROR, "%s: failed to find a state.\n", dnet_dump_id(cmd->id));
		goto err_out_destroy;
	}

	err = dnet_trans_insert(t);
	if (err)
		goto err_out_destroy;

	cmd->trans = t->trans;

	dnet_convert_cmd(cmd);
	dnet_convert_attr(a);

	dnet_req_set_header(&t->r, t+1, sizeof(struct dnet_attr) +
			sizeof(struct dnet_cmd), 0);
	dnet_req_set_flags(&t->r, ~0, DNET_REQ_NO_DESTRUCT);

	err = dnet_data_ready(st, &t->r);
	if (err)
		goto err_out_destroy;

	err = dnet_wait_event(w, w->cond == 1, &n->wait_ts);
	if (err || w->status) {
		if (!err)
			err = w->status;

		dnet_log(n, DNET_LOG_ERROR, "%s: failed to execute command '%s', err: %d.\n",
				dnet_dump_id(id), command, err);
		goto err_out_put;
	}

	dnet_wait_put(w);

	dnet_log(n, DNET_LOG_INFO, "%s: successfully executed command '%s'.\n", dnet_dump_id(id), command);
	return 0;

err_out_destroy:
	dnet_trans_put(t);
err_out_put:
	dnet_wait_put(w);
err_out_exit:
	return err;
}

int dnet_try_reconnect(struct dnet_node *n)
{
	struct dnet_addr_storage *ast, *tmp;
	struct dnet_net_state *st;
	int s, rejoin;

	if (list_empty(&n->reconnect_list))
		return 0;

	rejoin = 0;
	pthread_mutex_lock(&n->reconnect_lock);
	list_for_each_entry_safe(ast, tmp, &n->reconnect_list, reconnect_entry) {
		s = dnet_socket_create_addr(n, n->sock_type, n->proto, n->family,
				(struct sockaddr *)ast->addr.addr, ast->addr.addr_len, 0);
		if (s < 0)
			continue;

		st = dnet_add_state_socket(n, &ast->addr, s);
		if (!st) {
			close(s);
			continue;
		}

		st->join_state = DNET_REJOIN;
		rejoin = 1;

		list_del(&ast->reconnect_entry);
		free(ast);
	}
	pthread_mutex_unlock(&n->reconnect_lock);

	if (rejoin)
		dnet_rejoin(n, 0);

	return 0;
}

int dnet_lookup_object(struct dnet_node *n, unsigned char *id, unsigned int aflags,
	int (* complete)(struct dnet_net_state *, struct dnet_cmd *, struct dnet_attr *, void *),
	void *priv)
{
	struct dnet_trans *t;
	struct dnet_attr *a;
	struct dnet_cmd *cmd;
	struct dnet_net_state *st;
	int err;

	if (!aflags)
		dnet_recv_transform_list(n, id, NULL);

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

	memcpy(cmd->id, id, DNET_ID_SIZE);
	cmd->size = sizeof(struct dnet_attr);
	//cmd->flags = DNET_FLAGS_DIRECT;
	cmd->status = 0;

	memcpy(&t->cmd, cmd, sizeof(struct dnet_cmd));

	a->cmd = DNET_CMD_LOOKUP;
	a->size = 0;
	a->flags = aflags;

	t->st = dnet_state_get_first(n, cmd->id, n->st);
	if (!t->st) {
		err = -ENOENT;
		dnet_log(n, DNET_LOG_ERROR, "%s: failed to find a state.\n", dnet_dump_id(cmd->id));
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

	dnet_req_set_header(&t->r, t+1, sizeof(struct dnet_attr) +
			sizeof(struct dnet_cmd), 0);
	dnet_req_set_flags(&t->r, ~0, DNET_REQ_NO_DESTRUCT);

	err = dnet_data_ready(st, &t->r);
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
	int err;

	if (!cmd || !st) {
		err = -EINVAL;
		goto err_out_exit;
	}
	n = st->n;

	if (cmd->status || !cmd->size) {
		err = cmd->status;
		goto err_out_exit;
	}

	if (attr->size != sizeof(struct dnet_addr_attr)) {
		dnet_log(st->n, DNET_LOG_ERROR, "%s: wrong dnet_addr attribute size %llu, must be %zu.\n",
				dnet_dump_id(cmd->id), (unsigned long long)attr->size, sizeof(struct dnet_addr_attr));
		err = -EINVAL;
		goto err_out_exit;
	}

	a = (struct dnet_addr_attr *)(attr + 1);

	dnet_convert_addr_attr(a);

	err = dnet_add_received_state(n, cmd->id, attr, a);

	if (!err)
		dnet_log(n, DNET_LOG_INFO, "%s: lookup returned address %s.\n",
			dnet_dump_id(cmd->id), dnet_server_convert_dnet_addr(&a->addr));

	if (!(cmd->flags & DNET_FLAGS_MORE))
		goto out;

	return 0;

err_out_exit:
	if (n)
		dnet_log(n, DNET_LOG_ERROR, "%s: status: %d, err: %d.\n", dnet_dump_id(cmd->id), cmd->status, err);
out:
	if (w) {
		dnet_wakeup(w, w->cond = 1);
		dnet_wait_put(w);
	}
	return err;
}

int dnet_lookup(struct dnet_node *n, char *file)
{
	int err, pos = 0, len = strlen(file), error = 0;
	struct dnet_wait *w;
	unsigned char origin[DNET_ID_SIZE], addr[DNET_ID_SIZE];

	w = dnet_wait_alloc(0);
	if (!w) {
		err = -ENOMEM;
		goto err_out_exit;
	}

	while (1) {
		unsigned int rsize = DNET_ID_SIZE;

		err = dnet_transform(n, file, len, origin, addr, &rsize, &pos);
		if (err) {
			if (err > 0)
				break;
			continue;
		}

		err = dnet_lookup_object(n, origin, 0, dnet_lookup_complete, dnet_wait_get(w));
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

	dnet_wait_put(w);
	return error;

err_out_exit:
	return err;
}

int dnet_signal_thread_raw(struct dnet_io_thread *t, struct dnet_net_state *st, unsigned int cmd)
{
	struct dnet_thread_signal ts;
	int err;

	ts.cmd = cmd;
	ts.state = st;

	err = write(t->pipe[1], &ts, sizeof(struct dnet_thread_signal));
	if (err <= 0) {
		err = -errno;
		return err;
	}

	if (st)
		dnet_log(st->n, DNET_LOG_DSA, "%s: signaled thread %lu, cmd %u.\n",
			dnet_dump_id(st->id), (unsigned long)t->tid, cmd);

	return 0;
}

int dnet_signal_thread(struct dnet_net_state *st, unsigned int cmd)
{
	int err;

	/*
	 * I hate libevent.
	 * It is not designed for multi-threaded usage.
	 * But anything which was made by a man, can be broken by another.
	 * So we have this hack to signal given IO thread which event it should check.
	 */
	dnet_state_get(st);

	err = dnet_signal_thread_raw(st->th, st, cmd);
	if (err)
		dnet_state_put(st);

	return err;
}

int dnet_data_ready(struct dnet_net_state *st, struct dnet_data_req *r)
{
	int err = 0, add;

	dnet_lock_lock(&st->snd_lock);
	add = list_empty(&st->snd_list);
	list_add_tail(&r->req_entry, &st->snd_list);

	if (add)
		err = dnet_signal_thread(st, DNET_THREAD_DATA_READY);
	dnet_lock_unlock(&st->snd_lock);

	return err;
}

void *dnet_req_header(struct dnet_data_req *r)
{
	return r->header;
}

void *dnet_req_data(struct dnet_data_req *r)
{
	return r->data;
}

void *dnet_req_private(struct dnet_data_req *r)
{
	return r->priv;
}

struct dnet_data_req *dnet_req_alloc(struct dnet_net_state *st, uint64_t hsize)
{
	struct dnet_data_req *r;

	r = malloc(sizeof(struct dnet_data_req) + hsize);
	if (!r)
		return NULL;
	memset(r, 0, sizeof(struct dnet_data_req) + hsize);

	r->header = r + 1;
	r->hsize = hsize;
	r->fd = -1;
	r->size = 0;
	r->offset = 0;
	r->data = NULL;
	r->dsize = 0;

	if (st) {
		r->st = dnet_state_get(st);
		st->req_pending++;
	}

	return r;
}

void dnet_req_set_complete(struct dnet_data_req *r,
		void (* complete)(struct dnet_data_req *r, int err), void *priv)
{
	r->priv = priv;
	r->complete = complete;
}

void dnet_req_set_header(struct dnet_data_req *r, void *header, uint64_t hsize, int free)
{
	if (free)
		r->flags |= DNET_REQ_FREE_HEADER;
	r->header = header;
	r->hsize = hsize;
}

void dnet_req_set_data(struct dnet_data_req *r, void *data, uint64_t size, uint64_t offset, int free)
{
	if (free)
		r->flags |= DNET_REQ_FREE_DATA;
	r->data = data;
	r->dsize = size;
	r->doff = offset;
}

void dnet_req_set_fd(struct dnet_data_req *r, int fd, uint64_t offset, uint64_t size, int close)
{
	if (close)
		r->flags |= DNET_REQ_CLOSE_FD;
	r->fd = fd;
	r->offset = offset;
	r->size = size;
}

void dnet_req_set_flags(struct dnet_data_req *r, unsigned int mask, unsigned int flags)
{
	r->flags |= flags;
	r->flags &= mask;
}

void dnet_req_destroy(struct dnet_data_req *r, int err)
{
	if (r->flags & DNET_REQ_CLOSE_FD)
		close(r->fd);
	if (r->flags & DNET_REQ_FREE_DATA)
		free(r->data);
	if (r->flags & DNET_REQ_FREE_HEADER)
		free(r->header);

	if (r->st) {
		r->st->req_pending--;
		dnet_state_put(r->st);
	}

	if (!(r->flags & DNET_REQ_NO_DESTRUCT) && !r->complete) {
		free(r);
		return;
	}
	if (r->complete)
		r->complete(r, err);
}

struct dnet_addr *dnet_state_addr(struct dnet_net_state *st)
{
	return &st->addr;
}

static int dnet_recv_transform_complete(struct dnet_net_state *st, struct dnet_cmd *cmd,
					struct dnet_attr *attr, void *priv)
{
	char *data;
	unsigned int i;
	struct dnet_transform_complete *tc = priv;

	if (!st || !cmd || !attr)
		return 0;

	if (!cmd->size || !(cmd->flags & DNET_FLAGS_MORE)) {
		free(priv);
		return 0;
	}

	if (attr->size % DNET_MAX_NAME_LEN)
		return 0;

	data = (char *)(attr + 1);
	for (i=0; i<attr->size / DNET_MAX_NAME_LEN; ++i) {
		dnet_log(st->n, DNET_LOG_INFO, "%s: server-side transform function: %s\n",
				dnet_dump_id(cmd->id), data);

		if (tc && tc->callback)
			tc->callback(tc, data);
		data += DNET_MAX_NAME_LEN;
	}

	return 0;
}

int dnet_recv_transform_list(struct dnet_node *n, unsigned char *id,
		struct dnet_transform_complete *tc)
{
	struct dnet_net_state *st;
	struct dnet_cmd *cmd;
	struct dnet_attr *a;
	struct dnet_trans *t;
	int err;

	t = dnet_trans_alloc(n, sizeof(struct dnet_cmd) + sizeof(struct dnet_attr));
	if (!t) {
		err = -ENOMEM;
		goto err_out_exit;
	}

	t->complete = dnet_recv_transform_complete;
	t->priv = tc;

	cmd = (struct dnet_cmd *)(t + 1);
	a = (struct dnet_attr *)(cmd + 1);

	memcpy(cmd->id, id, DNET_ID_SIZE);
	cmd->flags = DNET_FLAGS_NEED_ACK;
	cmd->size = sizeof(struct dnet_attr);

	memcpy(&t->cmd, cmd, sizeof(struct dnet_cmd));

	a->cmd = DNET_CMD_TRANSFORM_LIST;

	st = dnet_state_get_first(n, cmd->id, n->st);
	if (!st) {
		err = -ENOENT;
		dnet_log(n, DNET_LOG_ERROR, "%s: can not get output state.\n", dnet_dump_id(n->id));
		goto err_out_destroy;
	}

	t->st = st;

	err = dnet_trans_insert(t);
	if (err)
		goto err_out_destroy;

	cmd->trans = t->trans;

	dnet_convert_cmd(cmd);
	dnet_convert_attr(a);

	t->r.header = cmd;
	t->r.hsize = sizeof(struct dnet_cmd) + sizeof(struct dnet_attr);
	t->r.fd = -1;
	t->r.offset = 0;
	t->r.size = 0;

	dnet_req_set_flags(&t->r, ~0, DNET_REQ_NO_DESTRUCT);

	err = dnet_data_ready(st, &t->r);
	if (err)
		goto err_out_destroy;

	return 0;

err_out_destroy:
	dnet_trans_put(t);
err_out_exit:
	return err;
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

	if (attr->size == sizeof(struct dnet_stat)) {
		st = (struct dnet_stat *)(attr + 1);

		dnet_convert_stat(st);

		la[0] = (float)st->la[0] / 100.0;
		la[1] = (float)st->la[1] / 100.0;
		la[2] = (float)st->la[2] / 100.0;

		dnet_log(state->n, DNET_LOG_INFO, "%s: %s: la: %.2f %.2f %.2f.\n",
				dnet_dump_id(cmd->id), dnet_state_dump_addr(state),
				la[0], la[1], la[2]);
		dnet_log(state->n, DNET_LOG_INFO, "%s: %s: mem: "
				"total: %llu kB, free: %llu kB, cache: %llu kB.\n",
				dnet_dump_id(cmd->id), dnet_state_dump_addr(state),
				(unsigned long long)st->vm_total,
				(unsigned long long)st->vm_free,
				(unsigned long long)st->vm_cached);
		dnet_log(state->n, DNET_LOG_INFO, "%s: %s: fs: "
				"total: %llu mB, avail: %llu mB, files: %llu, fsid: %llx.\n",
				dnet_dump_id(cmd->id), dnet_state_dump_addr(state),
				(unsigned long long)(st->frsize * st->blocks / 1024 / 1024),
				(unsigned long long)(st->bavail * st->bsize / 1024 / 1024),
				(unsigned long long)st->files, (unsigned long long)st->fsid);
		err = 0;
	}

	if (!(cmd->flags & DNET_FLAGS_MORE)) {
		dnet_wakeup(w, w->cond++);
		dnet_wait_put(w);
	}

	return err;
}

static int dnet_request_stat_single(struct dnet_node *n,
	unsigned char *id,
	int (* complete)(struct dnet_net_state *state,
			struct dnet_cmd *cmd,
			struct dnet_attr *attr,
			void *priv),
	void *priv)
{
	struct dnet_trans_control ctl;

	memset(&ctl, 0, sizeof(struct dnet_trans_control));

	memcpy(ctl.id, id, DNET_ID_SIZE);
	ctl.cmd = DNET_CMD_STAT;
	ctl.complete = complete;
	ctl.priv = priv;
	ctl.cflags = DNET_FLAGS_NEED_ACK;

	return dnet_trans_alloc_send(n, &ctl);
}

int dnet_request_stat(struct dnet_node *n, unsigned char *id,
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
		err = dnet_request_stat_single(n, id, complete, priv);
		num = 1;
	} else {
		struct dnet_net_state *st;

		pthread_rwlock_rdlock(&n->state_lock);
		list_for_each_entry(st, &n->state_list, state_entry) {
			if (w)
				dnet_wait_get(w);
			dnet_request_stat_single(n, st->id, complete, priv);
			num++;
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

int dnet_request_sync(struct dnet_net_state *st, unsigned char *id)
{
	struct dnet_node *n = st->n;
	char buf[sizeof(struct dnet_attr) + sizeof(struct dnet_cmd)];
	struct dnet_attr *attr;
	struct dnet_cmd *cmd;
	char prev_id[DNET_ID_SIZE * 2 + 1];
	char cur_id[DNET_ID_SIZE * 2 + 1];

	cmd = (struct dnet_cmd *)buf;
	attr = (struct dnet_attr *)(cmd + 1);

	memcpy(cmd->id, id, DNET_ID_SIZE);
	cmd->size = sizeof(struct dnet_attr);
	cmd->flags = 0;
	cmd->trans = 0;
	cmd->status = 0;

	attr->size = 0;
	attr->flags = 1;
	attr->cmd = DNET_CMD_LIST;

	snprintf(prev_id, sizeof(prev_id), "%s", dnet_dump_id(st->id));
	snprintf(cur_id, sizeof(cur_id), "%s", dnet_dump_id(id));

	dnet_log(n, DNET_LOG_INFO, "Syncing %s - %s range to %s.\n",
			prev_id, cur_id, dnet_state_dump_addr(st));

	return n->command_handler(st, n->command_private, cmd, attr, NULL);
}

static int dnet_remove_object_raw(struct dnet_node *n,
	unsigned char *origin, unsigned char *id,
	int (* complete)(struct dnet_net_state *state,
			struct dnet_cmd *cmd,
			struct dnet_attr *attr,
			void *priv),
	void *priv)
{
	struct dnet_trans_control ctl;
	struct dnet_io_attr io;

	memset(&ctl, 0, sizeof(struct dnet_trans_control));

	memcpy(ctl.id, id, DNET_ID_SIZE);

	memcpy(io.id, id, DNET_ID_SIZE);
	memcpy(io.origin, origin, DNET_ID_SIZE);

	ctl.cmd = DNET_CMD_DEL;
	ctl.complete = complete;
	ctl.priv = priv;
	ctl.cflags = DNET_FLAGS_NEED_ACK;
	ctl.data = &io;
	ctl.size = sizeof(struct dnet_io_attr);

	{
		char id_str[DNET_ID_SIZE * 2 + 1];
		snprintf(id_str, sizeof(id_str), "%s", dnet_dump_id(id));
		dnet_log(n, DNET_LOG_NOTICE, "%s: removing object %s.\n",
				dnet_dump_id(origin), id_str);
	}

	return dnet_trans_alloc_send(n, &ctl);
}

static int dnet_remove_complete(struct dnet_net_state *state,
			struct dnet_cmd *cmd,
			struct dnet_attr *attr __unused,
			void *priv)
{
	struct dnet_wait *w = priv;

	if (!state || !cmd)
		return 0;

	if (cmd && (cmd->flags && DNET_FLAGS_MORE))
		return 0;

	dnet_wakeup(w, dnet_io_complete(w, 0));
	dnet_wait_put(w);
	return 0;
}

int dnet_remove_object(struct dnet_node *n,
	unsigned char *origin, unsigned char *id,
	int (* complete)(struct dnet_net_state *state,
			struct dnet_cmd *cmd,
			struct dnet_attr *attr,
			void *priv),
	void *priv)
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

	err = dnet_remove_object_raw(n, origin, id,
			complete, priv);
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

static int dnet_remove_file_raw(struct dnet_node *n, char *base, unsigned char *id)
{
	char file[strlen(base) + 3 + sizeof(DNET_HISTORY_SUFFIX)];
	int fd, err;
	struct dnet_history_entry *e;
	uint64_t i, num;
	struct stat st;
	struct dnet_wait *w;

	err = dnet_read_file(n, base, id, 0, 0, 1);
	if (err)
		goto err_out_exit;

	snprintf(file, sizeof(file), "%s%s", base, DNET_HISTORY_SUFFIX);

	fd = open(file, O_RDONLY);
	if (fd < 0) {
		err = -errno;
		dnet_log_err(n,	"%s: failed to open history of deleted object '%s'",
				dnet_dump_id(id), file);
		goto err_out_exit;
	}

	err = fstat(fd, &st);
	if (err) {
		err = -errno;
		dnet_log_err(n, "%s: failed to stat history of deleted object '%s'",
				dnet_dump_id(id), file);
		goto err_out_close;
	}

	if (st.st_size % sizeof(struct dnet_history_entry)) {
		err = -EINVAL;
		dnet_log(n, DNET_LOG_ERROR, "%s: corrupted history object '%s'.\n",
				dnet_dump_id(id), file);
		goto err_out_close;
	}

	e = mmap(NULL, st.st_size, PROT_READ, MAP_SHARED, fd, 0);
	if (e == MAP_FAILED) {
		err = -errno;
		dnet_log_err(n, "%s: failed to mmap history of deleted object '%s'",
				dnet_dump_id(id), file);
		goto err_out_close;
	}

	num = st.st_size / sizeof(struct dnet_history_entry);

	w = dnet_wait_alloc(0);
	if (!w) {
		err = -ENOMEM;
		goto err_out_unmap;
	}

	for (i=1; i<num; ++i) {
		dnet_wait_get(w);
		dnet_remove_object_raw(n, id, e[i].id, dnet_remove_complete, w);
	}

	dnet_wait_get(w);
	dnet_remove_object_raw(n, e[0].id, id, dnet_remove_complete, w);
	dnet_wait_get(w);
	dnet_remove_object_raw(n, e[0].id, id, dnet_remove_complete, w);

	err = dnet_wait_event(w, w->cond == (int)(num+1), &n->wait_ts);
	if (err)
		goto err_out_put;

	dnet_wait_put(w);
	munmap(e, st.st_size);
	close(fd);

	remove(file);

	return 0;

err_out_put:
	dnet_wait_put(w);
err_out_unmap:
	munmap(e, st.st_size);
err_out_close:
	close(fd);
	remove(file);
err_out_exit:
	return err;
}

int dnet_remove_file(struct dnet_node *n, char *file, unsigned char *file_id)
{
	unsigned char id[DNET_ID_SIZE], origin[DNET_ID_SIZE];
	unsigned int len = strlen(file);
	int pos = 0;
	int err, error = 0;

	if (file_id)
		return dnet_remove_file_raw(n, file, file_id);

	while (1) {
		unsigned int rsize = DNET_ID_SIZE;

		err = dnet_transform(n, file, len, origin, id, &rsize, &pos);
		if (err) {
			if (err > 0)
				break;
			if (!error)
				error = err;
			continue;
		}

		dnet_remove_file_raw(n, file, origin);
	}

	if (error) {
		err = error;
		goto err_out_exit;
	}

	return 0;

err_out_exit:
	return err;
}
