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
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "elliptics.h"

#include "dnet/packet.h"
#include "dnet/interface.h"

static int dnet_transform(struct dnet_node *n, void *src, uint64_t size, void *dst, void *addr,
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
		unsigned int cmd, struct dnet_addr *addr, int reply)
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

	c->a.cmd = cmd;
	c->a.size = sizeof(struct dnet_addr_cmd) -
		sizeof(struct dnet_cmd) - sizeof(struct dnet_attr);

	memcpy(&c->addr.addr, addr, sizeof(struct dnet_addr));
	c->addr.family = st->n->family;
	c->addr.sock_type = st->n->sock_type;
	c->addr.proto = st->n->proto;

	dnet_log(st->n, DNET_LOG_INFO, "%s: sending address command: trans: %llu, reply: %d, cmd: %u.\n",
			dnet_dump_id(id), (unsigned long long)trans, reply, cmd);

	dnet_convert_addr_cmd(c);

	return dnet_data_ready(st, r);
}

static int dnet_cmd_lookup(struct dnet_net_state *orig, struct dnet_cmd *cmd,
		struct dnet_attr *attr __unused, void *data __unused)
{
	struct dnet_node *n = orig->n;
	struct dnet_net_state *st;
	int err;

	st = dnet_state_search(n, cmd->id, NULL);
	if (!st)
		st = dnet_state_get(orig->n->st);

	err = dnet_send_address(orig, st->id, cmd->trans, DNET_CMD_LOOKUP, &st->addr, 1);
	dnet_state_put(st);
	return err;
}

static int dnet_cmd_reverse_lookup(struct dnet_net_state *st, struct dnet_cmd *cmd __unused,
		struct dnet_attr *attr __unused, void *data __unused)
{
	struct dnet_node *n = st->n;

	return dnet_send_address(st, n->id, cmd->trans, DNET_CMD_REVERSE_LOOKUP,
			&n->addr, 1);
}

static int dnet_cmd_join_client(struct dnet_net_state *orig, struct dnet_cmd *cmd,
		struct dnet_attr *attr __unused, void *data)
{
	int err, s;
	struct dnet_net_state *st = NULL;
	struct dnet_node *n = orig->n;
	struct dnet_addr_attr *a = data;

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
		goto err_out_close;
	}

	dnet_log(n, DNET_LOG_INFO, "%s: state %s.\n", dnet_dump_id(cmd->id),
		dnet_server_convert_dnet_addr(&a->addr));

	return 0;

err_out_close:
	close(s);
err_out_exit:
	dnet_log(n, DNET_LOG_ERROR, "%s: failed to join to state %s.\n", dnet_dump_id(cmd->id),
		(st) ? dnet_server_convert_dnet_addr(&st->addr) : "undefined");
	return err;
}

static int dnet_cmd_route_list(struct dnet_net_state *orig, struct dnet_cmd *req)
{
	struct dnet_node *n = orig->n;
	struct dnet_net_state *st;
	int def_num = 1024, space = 0, err;
	struct dnet_data_req *r = NULL;
	/*
	 * Shut up a compiler. Neither of below variables
	 * can be used uninitialized, since they are defined
	 * in the blocks which depend on above variables
	 * @r and @space to be non-null.
	 */
	struct dnet_route_attr *a = NULL;
	struct dnet_cmd *cmd = NULL;
	struct dnet_attr *attr = NULL;

	pthread_rwlock_rdlock(&n->state_lock);
	list_for_each_entry(st, &n->state_list, state_entry) {
		if (!space) {
			unsigned int sz;

			if (r) {
				dnet_convert_cmd(cmd);
				dnet_convert_attr(attr);

				err = dnet_data_ready(orig, r);
				if (err)
					goto err_out_unlock;
			}

			space = def_num;
			sz = space * sizeof(struct dnet_route_attr);
			sz += sizeof(struct dnet_attr) + sizeof(struct dnet_cmd);

			r = dnet_req_alloc(orig, sz);
			if (!r) {
				err = -ENOMEM;
				goto err_out_unlock;
			}

			cmd = dnet_req_header(r);
			attr = (struct dnet_attr *)(cmd + 1);
			a = (struct dnet_route_attr *)(attr + 1);

			memcpy(cmd->id, req->id, DNET_ID_SIZE);
			cmd->size = sizeof(struct dnet_attr);
			cmd->trans = req->trans | DNET_TRANS_REPLY;
			cmd->flags |= DNET_FLAGS_MORE;

			attr->size = 0;
			attr->cmd = DNET_CMD_ROUTE_LIST;

			r->hsize = sizeof(struct dnet_cmd) + sizeof(struct dnet_attr);
		}

		if (!memcmp(st->id, orig->id, DNET_ID_SIZE))
			continue;

		if (!memcmp(st->id, n->id, DNET_ID_SIZE))
			continue;

		memcpy(a->id, st->id, DNET_ID_SIZE);
		memcpy(&a->addr.addr, &st->addr, sizeof(struct dnet_addr));
		a->addr.family = n->family;
		a->addr.sock_type = n->sock_type;
		a->addr.proto = n->proto;

		cmd->size += sizeof(struct dnet_route_attr);
		attr->size += sizeof(struct dnet_route_attr);
		r->hsize += sizeof(struct dnet_route_attr);

		dnet_log(n, DNET_LOG_INFO, "%s: route to %s\n", dnet_dump_id(a->id),
				dnet_server_convert_dnet_addr(&a->addr.addr));

		dnet_convert_addr_attr(&a->addr);
		a++;
		space--;
	}

	if (r) {
		err = dnet_data_ready(orig, r);
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
		dnet_req_destroy(r);
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
				dnet_dump_id(cmd->id), (unsigned long)ctl.io.size,
				sizeof(struct dnet_io_attr), (unsigned long long)attr->size);
		err = -EINVAL;
		goto err_out_exit;
	}

	data = malloc(ctl.io.size);
	if (!data) {
		dnet_log(n, DNET_LOG_ERROR, "%s: failed to clone data (%llu bytes) for replication.\n",
				dnet_dump_id(cmd->id), ctl.io.size);
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

	return dnet_write_object(n, &ctl, NULL, 0, 0);

err_out_exit:
	return err;
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

		dnet_log(n, DNET_LOG_NOTICE, "%s: start: size: %llu/%llu, asize: %llu\n",
				dnet_dump_id(cmd->id), size, (unsigned long long)cmd->size,
				(unsigned long long)a->size);

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

		dnet_log(n, DNET_LOG_INFO, "%s: trans: %llu, size_left: %llu, "
				"starting cmd: %u, asize: %llu.\n",
			dnet_dump_id(cmd->id), tid,
			size, a->cmd, (unsigned long long)a->size);

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
				break;
		}

		dnet_log(n, DNET_LOG_INFO, "%s: trans: %llu, size_left: %llu, "
				"completed cmd: %u, asize: %llu, err: %d.\n",
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

		t->r.complete = dnet_req_trans_destroy;

		dnet_req_set_header(&t->r, cmd, sizeof(struct dnet_cmd), 0);
		dnet_req_set_flags(&t->r, ~0, DNET_REQ_NO_DESTRUCT);
		ack = dnet_req_header(&t->r);

		memcpy(ack->id, cmd->id, DNET_ID_SIZE);
		ack->trans = cmd->trans | DNET_TRANS_REPLY;
		ack->size = 0;
		ack->flags = cmd->flags & ~DNET_FLAGS_NEED_ACK;
		ack->status = err;

		dnet_log(n, DNET_LOG_NOTICE, "%s: ack trans: %llu, flags: %x, status: %d.\n",
				dnet_dump_id(cmd->id), tid,
				ack->flags, err);

		dnet_convert_cmd(ack);
		dnet_data_ready(st, &t->r);
	}

	return err;
}

int dnet_add_state(struct dnet_node *n, struct dnet_config *cfg)
{
	int s, err;
	struct dnet_net_state *st, dummy;
	char buf[sizeof(struct dnet_cmd) + sizeof(struct dnet_attr)];
	struct dnet_addr addr;
	struct dnet_addr_cmd acmd;
	struct dnet_cmd *cmd;
	struct dnet_attr *a;

	addr.addr_len = sizeof(addr.addr);
	s = dnet_socket_create(n, cfg, (struct sockaddr *)&addr.addr, &addr.addr_len, 0);
	if (s < 0) {
		err = s;
		goto err_out_exit;
	}

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
				dnet_server_convert_dnet_addr(&addr), err);
		goto err_out_sock_close;
	}

	err = dnet_recv(st, &acmd, sizeof(acmd));
	if (err < 0) {
		dnet_log(n, DNET_LOG_ERROR, "%s: failed to receive reverse "
				"lookup response from %s, err: %d.\n",
				dnet_dump_id(n->id),
				dnet_server_convert_dnet_addr(&addr), err);
		goto err_out_sock_close;
	}

	dnet_convert_addr_cmd(&acmd);

	dnet_log(n, DNET_LOG_NOTICE, "%s reverse lookup -> %s.\n", dnet_dump_id(acmd.cmd.id),
		dnet_server_convert_dnet_addr(&acmd.addr.addr));

	st = dnet_state_create(n, acmd.cmd.id, &acmd.addr.addr, s);
	if (!st) {
		err = -EINVAL;
		goto err_out_sock_close;
	}

	return 0;

err_out_sock_close:
	close(s);
err_out_exit:
	return err;
}

static int dnet_add_received_state(struct dnet_node *n, unsigned char *id, struct dnet_addr_attr *a)
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

	dnet_log(n, DNET_LOG_NOTICE, "%s: added state %s.\n", dnet_dump_id(id),
		dnet_server_convert_dnet_addr(&a->addr));

	return 0;

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
	while (1) {
		if (num < 10 || !i)
			i++;
		else
			i <<= 1;

		if (i >= num)
			break;

		a = &attrs[i];

		dnet_convert_addr_attr(&a->addr);

		err = dnet_add_received_state(n, a->id, &a->addr);
		
		dnet_log(n, DNET_LOG_INFO, " %2d   %s - %s, added error: %d.\n", i, dnet_dump_id(a->id),
				dnet_server_convert_dnet_addr(&a->addr.addr), err);
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
	dnet_trans_destroy(t);
err_out_exit:
	return err;
}

int dnet_rejoin(struct dnet_node *n, int all)
{
	int err = 0;
	struct dnet_net_state *st;

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
		if (err == -ENOENT)
			err = 0;
		return err;
	}

	pthread_rwlock_rdlock(&n->state_lock);
	list_for_each_entry(st, &n->state_list, state_entry) {
		if (st == n->st)
			continue;

		dnet_log(n, DNET_LOG_NOTICE, "%s: sending join: all: %d, state: %x.\n",
				dnet_dump_id(st->id), all, st->join_state);

		if (!all && st->join_state != DNET_REJOIN)
			continue;

		err = dnet_recv_route_list(st);
		if (err) {
			dnet_log(n, DNET_LOG_ERROR, "%s: failed to send route list request to %s.\n",
				dnet_dump_id(st->id), dnet_server_convert_dnet_addr(&st->addr));
			break;
		}

		err = dnet_send_address(st, n->id, 0, DNET_CMD_JOIN, &n->addr, 0);
		if (err) {
			dnet_log(n, DNET_LOG_ERROR, "%s: failed to rejoin to state %s.\n",
				dnet_dump_id(st->id), dnet_server_convert_dnet_addr(&st->addr));
			break;
		}

		st->join_state = DNET_JOINED;
	}
	pthread_rwlock_unlock(&n->state_lock);

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
	w->cond--;
}

static int dnet_write_complete(struct dnet_net_state *st, struct dnet_cmd *cmd,
		struct dnet_attr *attr __unused, void *priv)
{
	int err = -EINVAL;

	if (!cmd || !cmd->status || cmd->size == 0) {
		struct dnet_wait *w = priv;

		if (cmd && st) {
			err = cmd->status;
			dnet_log(st->n, DNET_LOG_INFO, "%s: object write completed: status: %d.\n",
				dnet_dump_id(cmd->id), cmd->status);
		}

		dnet_wakeup(w, dnet_io_complete(w, err));
		dnet_wait_put(w);
	} else
		err = cmd->status;

	return err;
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
			dnet_log(n, DNET_LOG_ERROR, "%s: additional attribute size (%u) does not match "
					"structure's attribute size %llu.\n",
					dnet_dump_id(ctl->addr), ctl->asize - sizeof(struct dnet_attr),
					a->size);
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
	dnet_trans_destroy(t);
err_out_exit:
	return NULL;
}

static int dnet_trans_create_send(struct dnet_node *n, struct dnet_io_control *ctl)
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
	dnet_trans_destroy(t);
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

	rsize = DNET_ID_SIZE;
	err = dnet_transform(n, ctl->data, ctl->io.size, ctl->io.origin, ctl->addr, &rsize, pos);
	if (err) {
		if (err > 0)
			return err;
		goto err_out_complete;
	}

	if (id) {
		memcpy(ctl->io.id, id, DNET_ID_SIZE);
		memcpy(addr, id, DNET_ID_SIZE);
	} else if (remote && len) {
		*pos = *pos - 1;
		rsize = DNET_ID_SIZE;
		err = dnet_transform(n, remote, len, ctl->io.id, addr, &rsize, pos);
		if (err) {
			if (err > 0)
				return err;
			goto err_out_complete;
		}
	} else {
		memcpy(ctl->io.id, ctl->io.origin, DNET_ID_SIZE);
	}

	err = dnet_trans_create_send(n, ctl);
	if (err)
		goto err_out_exit;

	if (!hupdate || !remote || !len || !id)
		return 0;

	memcpy(hctl.addr, addr, DNET_ID_SIZE);
	memcpy(hctl.io.origin, ctl->io.id, DNET_ID_SIZE);
	memcpy(hctl.io.id, addr, DNET_ID_SIZE);

	memcpy(e.id, ctl->io.origin, DNET_ID_SIZE);
	e.offset = ctl->io.offset;
	e.size = ctl->io.size;
	e.flags = 0;

	dnet_convert_history_entry(&e);

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
	hctl.io.flags |= DNET_IO_FLAGS_HISTORY | DNET_IO_FLAGS_APPEND;

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

int dnet_write_object(struct dnet_node *n, struct dnet_io_control *ctl, void *remote,
		unsigned char *id, int hupdate)
{
	unsigned int len = 0;
	int pos = 0, err = 0;
	int error = 0;
	void *data = ctl->data;
	uint64_t total_size = ctl->io.size;

	if (remote)
		len = strlen(remote);

	while (1) {
		uint64_t sz, size = total_size;

		ctl->data = data;
		while (size) {
			sz = size;
			if (!ctl->aflags && sz > DNET_MAX_TRANS_SIZE)
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
			size -= sz;

			error = 0;
			if (size)
				pos--;
		}

		if (err > 0)
			break;
	}

	if (error < 0)
		return error;

	if (hupdate)
		pos *= 2;
	return pos;
}

int dnet_write_file(struct dnet_node *n, char *file, unsigned char *id, uint64_t offset, uint64_t size, unsigned int aflags)
{
	int fd, err, i, tnum = n->transform_num*2;
	struct stat stat;
	struct dnet_wait *w;
	struct dnet_io_control ctl;

	w = dnet_wait_alloc(1);
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

	if (!size) {
		err = fstat(fd, &stat);
		if (err) {
			err = -errno;
			dnet_log_err(n, "Failed to stat to be written file '%s'", file);
			goto err_out_close;
		}

		size = stat.st_size;
	}

	memset(&ctl, 0, sizeof(struct dnet_io_control));

	ctl.data = mmap(NULL, size, PROT_READ, MAP_SHARED, fd, offset);
	if (ctl.data == MAP_FAILED) {
		err = -errno;
		dnet_log_err(n, "Failed to map to be written file '%s'", file);
		goto err_out_close;
	}

	for (i=0; i<tnum; ++i)
		dnet_wait_get(w);

	w->cond += tnum;

	ctl.fd = fd;

	ctl.complete = dnet_write_complete;
	ctl.priv = w;

	ctl.cflags = DNET_FLAGS_NEED_ACK;
	ctl.cmd = DNET_CMD_WRITE;
	ctl.aflags = aflags;

	ctl.io.flags = 0;
	ctl.io.size = size;
	ctl.io.offset = offset;

	err = dnet_write_object(n, &ctl, file, id, 1);
	if (err <= 0)
		goto err_out_unmap;

	munmap(ctl.data, size);

	dnet_wakeup(w, w->cond -= tnum - err + 1);

	err = dnet_wait_event(w, w->cond == 0, &n->wait_ts);
	if (err || w->status) {
		if (!err)
			err = w->status;

		dnet_log(n, DNET_LOG_ERROR, "Failed to write file '%s' into the storage, err: %d.\n", file, err);
		goto err_out_close;
	}

	dnet_log(n, DNET_LOG_INFO, "Successfully wrote file: '%s' into the storage, size: %zu.\n", file, size);

	close(fd);
	dnet_wait_put(w);

	return 0;

err_out_unmap:
	munmap(ctl.data, size);
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
			dnet_dump_id(cmd->id), c->file, (unsigned long long)io->offset,
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

	dnet_log(p->node, DNET_LOG_INFO, "%s: reading chunk of file: '%s', offset: %llu, size: %llu, err: %d.\n",
			dnet_dump_id(e->id), p->file, (unsigned long long)io.offset,
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
	printf("%s: old: %llu %llu, new: %llu %llu.\n",
			__func__, old_offset, old_size, offset, size);
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
				"its size %llu has to be modulo of %zu.\n",
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

	dnet_log(n, DNET_LOG_INFO, "%s: objects: %zd, range: %llu-%llu, "
			"counting from the most recent.\n",
			file, num, offset, offset+r.size);

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
	dnet_trans_destroy(t);
err_out_put:
	dnet_wait_put(w);
err_out_exit:
	return err;
}

int dnet_give_up_control(struct dnet_node *n)
{
	while (!n->need_exit) {
		if (n->join_state == DNET_REJOIN) {
			dnet_rejoin(n, 0);
			n->join_state = DNET_JOINED;
		}
		sleep(1);
	}

	return 0;
}

int dnet_lookup_object(struct dnet_node *n, unsigned char *id,
	int (* complete)(struct dnet_net_state *, struct dnet_cmd *, struct dnet_attr *, void *),
	void *priv)
{
	struct dnet_trans *t;
	struct dnet_attr *a;
	struct dnet_cmd *cmd;
	struct dnet_net_state *st;
	int err;

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

	a->cmd = DNET_CMD_LOOKUP;
	a->size = 0;
	a->flags = 0;

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

	dnet_log(n, DNET_LOG_NOTICE, "%s: lookup to %s.\n", dnet_dump_id(id),
		dnet_server_convert_dnet_addr(&st->addr));

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
	dnet_trans_destroy(t);
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

	err = dnet_add_received_state(n, cmd->id, a);

	if (!err)
		dnet_log(n, DNET_LOG_INFO, "%s: lookup returned address %s.\n",
			dnet_dump_id(cmd->id), dnet_server_convert_dnet_addr(&a->addr));


	return err;

err_out_exit:
	if (n)
		dnet_log(n, DNET_LOG_ERROR, "%s: status: %d, err: %d.\n", dnet_dump_id(cmd->id), cmd->status, err);
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

		err = dnet_lookup_object(n, origin, dnet_lookup_complete, dnet_wait_get(w));
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

int dnet_signal_thread(struct dnet_net_state *st, unsigned int cmd)
{
	struct dnet_thread_signal ts;
	int err;

	ts.cmd = cmd;
	ts.state = st;

	/*
	 * I hate libevent.
	 * It is not designed for multi-threaded usage.
	 * But anything which was made by a man, can be broken by another.
	 * So we have this hack to signal given IO thread which event it should check.
	 */
	dnet_state_get(st);

	err = write(st->th->pipe[1], &ts, sizeof(struct dnet_thread_signal));
	if (err <= 0) {
		err = -errno;
		dnet_state_put(st);
		return err;
	}

	dnet_log(st->n, DNET_LOG_NOTICE, "%s: signaled thread %lu, cmd %u.\n",
			dnet_dump_id(st->id), (unsigned long)st->th->tid, cmd);

	return 0;
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
		void (* complete)(struct dnet_data_req *r), void *priv)
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

void dnet_req_destroy(struct dnet_data_req *r)
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
		r->complete(r);
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
	dnet_trans_destroy(t);
err_out_exit:
	return err;
}
