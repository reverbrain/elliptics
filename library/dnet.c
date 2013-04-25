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

#define _XOPEN_SOURCE 500

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <sys/wait.h>

#include <alloca.h>
#include <ctype.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "elliptics.h"

#include "elliptics/packet.h"
#include "elliptics/interface.h"


int dnet_stat_local(struct dnet_net_state *st, struct dnet_id *id)
{
	struct dnet_node *n = st->n;
	int size, cmd_size;
	struct dnet_cmd *cmd;
	struct dnet_io_attr *io;
	int err;

	size = 1;
	cmd_size = size + sizeof(struct dnet_cmd) + sizeof(struct dnet_io_attr);

	cmd = malloc(cmd_size);
	if (!cmd) {
		dnet_log(n, DNET_LOG_ERROR, "%s: failed to allocate %d bytes for local stat.\n",
				dnet_dump_id(id), cmd_size);
		err = -ENOMEM;
		goto err_out_exit;
	}

	memset(cmd, 0, cmd_size);

	io = (struct dnet_io_attr *)(cmd + 1);

	memcpy(&cmd->id, id, sizeof(struct dnet_id));
	cmd->size = cmd_size - sizeof(struct dnet_cmd);
	cmd->flags = DNET_FLAGS_NOLOCK;
	cmd->cmd = DNET_CMD_READ;

	io->size = cmd->size - sizeof(struct dnet_io_attr);
	io->offset = 0;
	io->flags = DNET_IO_FLAGS_SKIP_SENDING;

	memcpy(io->parent, id->id, DNET_ID_SIZE);
	memcpy(io->id, id->id, DNET_ID_SIZE);

	dnet_convert_io_attr(io);

	err = n->cb->command_handler(st, n->cb->command_private, cmd, io);
	dnet_log(n, DNET_LOG_INFO, "%s: local stat: io_size: %llu, err: %d.\n", dnet_dump_id(&cmd->id), (unsigned long long)io->size, err);

	free(cmd);

err_out_exit:
	return err;
}

int dnet_remove_local(struct dnet_node *n, struct dnet_id *id)
{
	int cmd_size;
	struct dnet_cmd *cmd;
	struct dnet_io_attr *io;
	int err;

	cmd_size = sizeof(struct dnet_cmd) + sizeof(struct dnet_io_attr);

	cmd = malloc(cmd_size);
	if (!cmd) {
		dnet_log(n, DNET_LOG_ERROR, "%s: failed to allocate %d bytes for local remove.\n",
				dnet_dump_id(id), cmd_size);
		err = -ENOMEM;
		goto err_out_exit;
	}

	memset(cmd, 0, cmd_size);

	io = (struct dnet_io_attr *)(cmd + 1);

	cmd->id = *id;
	cmd->size = cmd_size - sizeof(struct dnet_cmd);
	cmd->flags = DNET_FLAGS_NOLOCK;
	cmd->cmd = DNET_CMD_DEL;

	io->flags = DNET_IO_FLAGS_SKIP_SENDING;

	memcpy(io->parent, id->id, DNET_ID_SIZE);
	memcpy(io->id, id->id, DNET_ID_SIZE);

	dnet_convert_io_attr(io);

	err = n->cb->command_handler(n->st, n->cb->command_private, cmd, io);
	dnet_log(n, DNET_LOG_NOTICE, "%s: local remove: err: %d.\n", dnet_dump_id(&cmd->id), err);

	free(cmd);

err_out_exit:
	return err;

}

static void dnet_send_idc_fill(struct dnet_net_state *st, struct dnet_addr_cmd *acmd, int total_size,
		struct dnet_id *id, uint64_t trans, unsigned int command, int reply, int direct, int more)
{
	struct dnet_node *n = st->n;
	struct dnet_cmd *cmd = &acmd->cmd;
	struct dnet_raw_id *sid;
	int i;

	acmd->cnt.addr_num = n->addr_num;
	if (!st->addrs)
		memcpy(acmd->cnt.addrs, n->addrs, n->addr_num * sizeof(struct dnet_addr));
	else
		memcpy(acmd->cnt.addrs, st->addrs, n->addr_num * sizeof(struct dnet_addr));

	sid = (struct dnet_raw_id *)(acmd->cnt.addrs + n->addr_num);

	memcpy(&cmd->id, id, sizeof(struct dnet_id));
	cmd->size = total_size - sizeof(struct dnet_cmd);
	cmd->trans = trans;

	cmd->flags = DNET_FLAGS_NOLOCK;
	if (more)
		cmd->flags |= DNET_FLAGS_MORE;
	if (direct)
		cmd->flags |= DNET_FLAGS_DIRECT;
	if (reply)
		cmd->trans |= DNET_TRANS_REPLY;

	cmd->cmd = command;

	for (i = 0; i < st->idc->id_num; ++i) {
		memcpy(&sid[i], &st->idc->ids[i].raw, sizeof(struct dnet_raw_id));
		dnet_convert_raw_id(&sid[i]);
	}

	dnet_convert_addr_cmd(acmd);
}

static int dnet_send_idc(struct dnet_net_state *lstate, struct dnet_net_state *send, struct dnet_id *id, uint64_t trans,
		unsigned int command, int reply, int direct, int more)
{
	struct dnet_node *n = lstate->n;
	int size = sizeof(struct dnet_addr_cmd) + sizeof(struct dnet_addr) * n->addr_num + lstate->idc->id_num * sizeof(struct dnet_raw_id);
	void *buf;
	int err;
	struct dnet_addr laddr;
	char server_addr[128], client_addr[128];
	struct timeval start, end;
	long diff;

	gettimeofday(&start, NULL);

	buf = malloc(size);
	if (!buf) {
		err = -ENOMEM;
		goto err_out_exit;
	}
	memset(buf, 0, size);

	dnet_send_idc_fill(lstate, buf, size, id, trans, command, reply, direct, more);
	dnet_socket_local_addr(send->read_s, &laddr);

	gettimeofday(&end, NULL);
	diff = (end.tv_sec - start.tv_sec) * 1000000 + end.tv_usec - start.tv_usec;
	dnet_log(n, DNET_LOG_INFO, "%s: sending address %s -> %s, addr_num: %d, time-took: %ld\n",
			dnet_dump_id(id),
			dnet_server_convert_dnet_addr_raw(&laddr, server_addr, sizeof(server_addr)),
			dnet_server_convert_dnet_addr_raw(dnet_state_addr(send), client_addr, sizeof(client_addr)),
			n->addr_num, diff);

	err = dnet_send(send, buf, size);

	free(buf);

err_out_exit:
	return err;
}

static int dnet_cmd_reverse_lookup(struct dnet_net_state *st, struct dnet_cmd *cmd, void *data __unused)
{
	struct dnet_node *n = st->n;
	struct dnet_net_state *base;
	int err = -ENXIO;

	cmd->id.group_id = n->id.group_id;
	base = dnet_node_state(n);
	if (base) {
		err = dnet_send_idc(base, st, &cmd->id, cmd->trans, DNET_CMD_REVERSE_LOOKUP, 1, 0, 0);
		dnet_state_put(base);
	}

	return err;
}

static int dnet_check_connection(struct dnet_node *n, struct dnet_addr *addr)
{
	int s;

	s = dnet_socket_create_addr(n, addr, 0);
	if (s < 0)
		return s;

	dnet_sock_close(s);
	return 0;
}

static int dnet_cmd_join_client(struct dnet_net_state *st, struct dnet_cmd *cmd, void *data)
{
	struct dnet_node *n = st->n;
	struct dnet_addr_container *cnt = data;
	struct dnet_addr laddr;
	struct dnet_raw_id *ids;
	char client_addr[128], server_addr[128];
	int ids_num, i, err, idx;

	dnet_socket_local_addr(st->read_s, &laddr);
	idx = dnet_local_addr_index(n, &laddr);

	dnet_server_convert_dnet_addr_raw(&st->addr, client_addr, sizeof(client_addr));
	dnet_server_convert_dnet_addr_raw(&laddr, server_addr, sizeof(server_addr));

	if (cmd->size < sizeof(struct dnet_addr_container)) {
		dnet_log(n, DNET_LOG_ERROR, "%s: invalid join request: client: %s -> %s, "
				"cmd-size: %llu, must be more than addr_container: %zd\n",
				dnet_dump_id(&cmd->id), client_addr, server_addr,
				(unsigned long long)cmd->size, sizeof(struct dnet_addr_container));
		err = -EINVAL;
		goto err_out_exit;
	}

	dnet_convert_addr_container(cnt);

	if (cmd->size < sizeof(struct dnet_addr_container) + cnt->addr_num * sizeof(struct dnet_addr)) {
		dnet_log(n, DNET_LOG_ERROR, "%s: invalid join request: client: %s -> %s, "
				"cmd-size: %llu, must be more than addr_container+addrs: %zd, addr_num: %d\n",
				dnet_dump_id(&cmd->id), client_addr, server_addr,
				(unsigned long long)cmd->size, sizeof(struct dnet_addr_container) + cnt->addr_num * sizeof(struct dnet_addr),
				cnt->addr_num);
		err = -EINVAL;
		goto err_out_exit;
	}

	ids_num = (cmd->size - sizeof(struct dnet_addr) * cnt->addr_num - sizeof(struct dnet_addr_container)) / sizeof(struct dnet_raw_id);

	if (idx < 0 || idx >= cnt->addr_num || cnt->addr_num != n->addr_num) {
		dnet_log(n, DNET_LOG_ERROR, "%s: invalid join request: client: %s -> %s, "
				"address idx: %d, received addr-num: %d, local addr-num: %d, ids-num: %d\n",
				dnet_dump_id(&cmd->id), client_addr, server_addr,
				idx, cnt->addr_num, n->addr_num, ids_num);
		err = -EINVAL;
		goto err_out_exit;
	}

	dnet_log(n, DNET_LOG_NOTICE, "%s: join request: client: %s -> %s, "
			"address idx: %d, received addr-num: %d, local addr-num: %d, ids-num: %d\n",
			dnet_dump_id(&cmd->id), client_addr, server_addr,
			idx, cnt->addr_num, n->addr_num, ids_num);

	err = dnet_check_connection(n, &cnt->addrs[idx]);
	if (err) {
		dnet_log(n, DNET_LOG_ERROR, "%s: failed to request statistics from joining client (%s), dropping connection.\n",
				dnet_dump_id(&cmd->id), dnet_server_convert_dnet_addr(&cnt->addrs[idx]));
		goto err_out_exit;
	}

	ids = (struct dnet_raw_id *)(data + sizeof(struct dnet_addr_container) + cnt->addr_num * sizeof(struct dnet_addr));
	for (i = 0; i < ids_num; ++i)
		dnet_convert_raw_id(&ids[0]);

	list_del_init(&st->state_entry);
	list_del_init(&st->storage_state_entry);

	memcpy(&st->addr, &cnt->addrs[idx], sizeof(struct dnet_addr));

	err = dnet_copy_addrs(st, cnt->addrs, cnt->addr_num);
	if (err)
		goto err_out_exit;

	err = dnet_idc_create(st, cmd->id.group_id, ids, ids_num);

	dnet_log(n, DNET_LOG_INFO, "%s: join request completed: client: %s -> %s, "
			"address idx: %d, received addr-num: %d, local addr-num: %d, ids-num: %d, err: %d\n",
			dnet_dump_id(&cmd->id), client_addr, server_addr,
			idx, cnt->addr_num, n->addr_num, ids_num, err);

err_out_exit:
	return err;
}

static int dnet_cmd_route_list(struct dnet_net_state *orig, struct dnet_cmd *cmd)
{
	struct dnet_node *n = orig->n;
	struct dnet_net_state *st;
	struct dnet_group *g;
	void *buf = NULL;
	size_t size, orig_size = 0;
	int err;

	pthread_mutex_lock(&n->state_lock);
	list_for_each_entry(g, &n->group_list, group_entry) {
		list_for_each_entry(st, &g->state_list, state_entry) {
			if (dnet_addr_equal(&st->addr, &orig->addr) || !st->addrs)
				continue;

			size = st->idc->id_num * sizeof(struct dnet_raw_id) +
				sizeof(struct dnet_addr_cmd) + n->addr_num * sizeof(struct dnet_addr);

			if (size > orig_size) {
				buf = realloc(buf, size);
				if (!buf) {
					err = -ENOMEM;
					goto err_out_unlock;
				}

				orig_size = size;
			}

			dnet_log(n, DNET_LOG_INFO, "%s: %d %s, id_num: %d, addr_num: %d\n",
					dnet_server_convert_dnet_addr(&st->addrs[0]),
					g->group_id, dnet_dump_id_str(st->idc->ids[0].raw.id),
					st->idc->id_num, n->addr_num);

			memset(buf, 0, size);
			cmd->id.group_id = g->group_id;
			dnet_send_idc_fill(st, buf, size, &cmd->id, cmd->trans, DNET_CMD_ROUTE_LIST, 1, 0, 1);

			err = dnet_send(orig, buf, size);
			if (err)
				goto err_out_unlock;
		}
	}

	err = 0;

err_out_unlock:
	pthread_mutex_unlock(&n->state_lock);
	free(buf);
	return err;
}

static int dnet_cmd_exec(struct dnet_net_state *st, struct dnet_cmd *cmd, void *data)
{
	struct dnet_node *n = st->n;
	struct sph *e = data;
	int err = -ENOTSUP;

	data += sizeof(struct sph);

	dnet_convert_sph(e);

	if (e->event_size + e->data_size + sizeof(struct sph) != cmd->size) {
		err = -E2BIG;
		dnet_log(n, DNET_LOG_ERROR, "%s: invalid size: event-size %d, data-size %llu must be: %llu\n",
				dnet_dump_id(&cmd->id),
				e->event_size,
				(unsigned long long)e->data_size,
				(unsigned long long)cmd->size);
		goto err_out_exit;
	}

	err = dnet_cmd_exec_raw(st, cmd, e, data);

err_out_exit:
	return err;
}

static int dnet_cmd_stat_count_single(struct dnet_net_state *orig, struct dnet_cmd *cmd, struct dnet_net_state *st, struct dnet_addr_stat *as)
{
	int i;

	cmd->cmd = DNET_CMD_STAT_COUNT;

	memcpy(&as->addr, &st->addr, sizeof(struct dnet_addr));
	as->num = __DNET_CMD_MAX;
	as->cmd_num = __DNET_CMD_MAX;

	for (i=0; i<as->num; ++i) {
		as->count[i] = st->stat[i];
	}

	dnet_convert_addr_stat(as, as->num);

	return dnet_send_reply(orig, cmd, as, sizeof(struct dnet_addr_stat) + __DNET_CMD_MAX * sizeof(struct dnet_stat_count), 1);
}

static int dnet_cmd_stat_count_global(struct dnet_net_state *orig, struct dnet_cmd *cmd,
		struct dnet_node *n, struct dnet_addr_stat *as)
{
	struct dnet_stat st;
	int err = 0;

	cmd->cmd = DNET_CMD_STAT_COUNT;

	memcpy(&as->addr, &orig->addr, sizeof(struct dnet_addr));
	as->num = __DNET_CNTR_MAX;
	as->cmd_num = __DNET_CMD_MAX;

	memcpy(as->count, n->counters, sizeof(struct dnet_stat_count) * __DNET_CNTR_MAX);

	if (n->cb->storage_stat) {
		err = n->cb->storage_stat(n->cb->command_private, &st);
		if (err)
			return err;

		as->count[DNET_CNTR_LA1].count = st.la[0];
		as->count[DNET_CNTR_LA5].count = st.la[1];
		as->count[DNET_CNTR_LA15].count = st.la[2];
		as->count[DNET_CNTR_BSIZE].count = st.bsize;
		as->count[DNET_CNTR_FRSIZE].count = st.frsize;
		as->count[DNET_CNTR_BLOCKS].count = st.blocks;
		as->count[DNET_CNTR_BFREE].count = st.bfree;
		as->count[DNET_CNTR_BAVAIL].count = st.bavail;
		as->count[DNET_CNTR_FILES].count = st.files;
		as->count[DNET_CNTR_FFREE].count = st.ffree;
		as->count[DNET_CNTR_FAVAIL].count = st.favail;
		as->count[DNET_CNTR_FSID].count = st.fsid;
		as->count[DNET_CNTR_VM_ACTIVE].count = st.vm_active;
		as->count[DNET_CNTR_VM_INACTIVE].count = st.vm_inactive;
		as->count[DNET_CNTR_VM_TOTAL].count = st.vm_total;
		as->count[DNET_CNTR_VM_FREE].count = st.vm_free;
		as->count[DNET_CNTR_VM_CACHED].count = st.vm_cached;
		as->count[DNET_CNTR_VM_BUFFERS].count = st.vm_buffers;
	}
	as->count[DNET_CNTR_NODE_FILES].count = n->cb->meta_total_elements(n->cb->command_private);

	dnet_convert_addr_stat(as, as->num);

	return dnet_send_reply(orig, cmd, as, sizeof(struct dnet_addr_stat) + __DNET_CNTR_MAX * sizeof(struct dnet_stat_count), 1);
}

static int dnet_cmd_stat_count(struct dnet_net_state *orig, struct dnet_cmd *cmd, void *data __unused)
{
	struct dnet_node *n = orig->n;
	struct dnet_net_state *st;
	struct dnet_addr_stat *as;
	int err = 0;

	as = alloca(sizeof(struct dnet_addr_stat) + __DNET_CNTR_MAX * sizeof(struct dnet_stat_count));
	if (!as) {
		err = -ENOMEM;
		goto err_out_exit;
	}

	if (cmd->flags & DNET_ATTR_CNTR_GLOBAL) {
		err = dnet_cmd_stat_count_global(orig, cmd, orig->n, as);
	} else {
		pthread_mutex_lock(&n->state_lock);
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
		pthread_mutex_unlock(&n->state_lock);
	}

err_out_exit:
	return err;
}

static int dnet_cmd_status(struct dnet_net_state *orig, struct dnet_cmd *cmd __unused, void *data)
{
	struct dnet_node *n = orig->n;
	struct dnet_node_status *st = data;

	dnet_convert_node_status(st);

	dnet_log(n, DNET_LOG_INFO, "%s: status-change: nflags: %x->%x, log_level: %d->%d, "
			"status_flags: EXIT: %d, RO: %d\n",
			dnet_dump_id(&cmd->id), n->flags, st->nflags, n->log->log_level, st->log_level,
			!!(st->status_flags & DNET_STATUS_EXIT), !!(st->status_flags & DNET_STATUS_RO));

	if (st->status_flags != -1) {
		if (st->status_flags & DNET_STATUS_EXIT) {
			dnet_set_need_exit(n);
		}

		if (st->status_flags & DNET_STATUS_RO) {
			n->ro = 1;
		} else {
			n->ro = 0;
		}
	}

	if (st->nflags != -1)
		n->flags = st->nflags;

	if (st->log_level != ~0U)
		n->log->log_level = st->log_level;

	st->nflags = n->flags;
	st->log_level = n->log->log_level;
	st->status_flags = 0;

	if (n->need_exit)
		st->status_flags |= DNET_STATUS_EXIT;

	if (n->ro)
		st->status_flags |= DNET_STATUS_RO;

	dnet_convert_node_status(st);

	return dnet_send_reply(orig, cmd, st, sizeof(struct dnet_node_status), 1);
}

static int dnet_cmd_auth(struct dnet_net_state *orig, struct dnet_cmd *cmd __unused, void *data)
{
	struct dnet_node *n = orig->n;
	struct dnet_auth *a = data;
	int err = 0;

	if (cmd->size != sizeof(struct dnet_auth)) {
		err = -EINVAL;
		goto err_out_exit;
	}

	dnet_convert_auth(a);
	if (memcmp(n->cookie, a->cookie, DNET_AUTH_COOKIE_SIZE)) {
		err = -EPERM;
		dnet_log(n, DNET_LOG_ERROR, "%s: auth cookies do not match\n", dnet_state_dump_addr(orig));
	} else {
		dnet_log(n, DNET_LOG_INFO, "%s: authentication succeeded\n", dnet_state_dump_addr(orig));
	}

err_out_exit:
	return err;
}

int dnet_send_ack(struct dnet_net_state *st, struct dnet_cmd *cmd, int err)
{
	if (st && cmd && (cmd->flags & DNET_FLAGS_NEED_ACK)) {
		struct dnet_node *n = st->n;
		unsigned long long tid = cmd->trans & ~DNET_TRANS_REPLY;
		struct dnet_cmd ack;

		memcpy(&ack.id, &cmd->id, sizeof(struct dnet_id));
		ack.cmd = cmd->cmd;
		ack.trans = cmd->trans | DNET_TRANS_REPLY;
		ack.size = 0;
		ack.flags = cmd->flags & ~(DNET_FLAGS_NEED_ACK | DNET_FLAGS_MORE);
		ack.status = err;

		dnet_log(n, DNET_LOG_NOTICE, "%s: %s: ack -> %s: trans: %llu, flags: %llx, status: %d.\n",
				dnet_dump_id(&cmd->id), dnet_cmd_string(cmd->cmd), dnet_server_convert_dnet_addr(&st->addr),
				tid, (unsigned long long)ack.flags, err);

		dnet_convert_cmd(&ack);
		err = dnet_send(st, &ack, sizeof(struct dnet_cmd));
	}

	return err;
}

/*!
 * Internal callback that writes result to \a fd opened in append mode
 */
static int dnet_iterator_callback_file(void *priv, void *data, uint64_t dsize)
{
	struct dnet_iterator_file_private *file = priv;
	ssize_t err;

	err = write(file->fd, data, dsize);
	if (err == -1)
		return -errno;
	if (err != (ssize_t)dsize)
		return -EINTR;
	return 0;
}

/*!
 * Internal callback that sends result to state \a st
 * TODO: Send data in chunks.
 */
static int dnet_iterator_callback_send(void *priv, void *data, uint64_t dsize)
{
	struct dnet_iterator_send_private *send = priv;

	return dnet_send_reply(send->st, send->cmd, data, dsize, 1);
}

static int dnet_iterator_callback_common(void *priv, struct dnet_raw_id *key,
		void *data, uint64_t dsize, struct dnet_ext_list *elist)
{
	struct dnet_iterator_common_private *ipriv = priv;
	struct dnet_iterator_response *response;
	static const uint64_t response_size = sizeof(struct dnet_iterator_response);
	uint64_t size;
	unsigned char *combined, *position;
	int err = 0;

	/* If DNET_IFLAGS_KEY_RANGE is set... */
	if (ipriv->req->flags & DNET_IFLAGS_KEY_RANGE)
		/* ...skip keys not in key range */
			if (dnet_id_cmp_str(key->id, ipriv->req->key_begin.id) < 0
					|| dnet_id_cmp_str(key->id, ipriv->req->key_end.id) > 0)
				goto err_out_exit;

	/* If DNET_IFLAGS_TS_RANGE is set... */
	if (ipriv->req->flags & DNET_IFLAGS_TS_RANGE)
		/* ...skip ts not in ts range */
			if (dnet_time_cmp(&elist->timestamp, &ipriv->req->time_begin) < 0
					|| dnet_time_cmp(&elist->timestamp, &ipriv->req->time_end) > 0)
				goto err_out_exit;

	/* Set data to NULL in case it's not requested */
	if (!(ipriv->req->flags & DNET_IFLAGS_DATA)) {
		data = NULL;
		dsize = 0;
	}
	size = response_size + dsize;

	/*
	 * Prepare combined buffer.
	 * XXX: Remove memcpy.
	 */
	position = combined = malloc(size);
	if (combined == NULL) {
		err = -ENOMEM;
		goto err_out_exit;
	}

	/* Response */
	response = (struct dnet_iterator_response *)combined;
	memset(response, 0, response_size);
	response->key = *key;
	response->timestamp = elist->timestamp;
	response->user_flags = elist->flags;
	dnet_convert_iterator_response(response);

	/* Data */
	if (data) {
		position += response_size;
		memcpy(position, data, dsize);
	}

	/*
	 * XXX: Check that we allowed to run
	 *
	 * If state is 'paused' - sleep on condition variable.
	 * If state is 'canceled' - exit with error.
	 */

	/* Finally run next callback */
	err = ipriv->next_callback(ipriv->next_private, combined, size);

	/* Pass to next callback */
	free(combined);

err_out_exit:
	return err;
}

/*!
 * Starts low-level backend iterator and passes data to network or file
 */
static int dnet_cmd_iterator(struct dnet_net_state *st, struct dnet_cmd *cmd, void *data)
{
	struct dnet_iterator_request *ireq = data;
	struct dnet_iterator_common_private cpriv = {
		.req = ireq,
	};
	struct dnet_iterator_ctl ictl = {
		.iterate_private = st->n->cb->command_private,
		.callback = dnet_iterator_callback_common,
		.callback_private = &cpriv,
	};
	struct dnet_iterator_send_private spriv;
	struct dnet_iterator_file_private fpriv;
	static const int mode = O_WRONLY|O_APPEND|O_CLOEXEC|O_CREAT|O_TRUNC;
	int err = 0;
	char iter_path[PATH_MAX];

	/*
	 * Sanity
	 */
	if (ireq == NULL || st == NULL || cmd == NULL)
		return -EINVAL;
	dnet_convert_iterator_request(ireq);

	/*
	 * XXX:
	 * Check iterator action start/pause/cont
	 * On pause, find in list and mark as stopped
	 * On cont, find in list and mark as running, broadcast condition variable.
	 * On start, all following code.....
	 */

	/* Check for rouge flags */
	if ((ireq->flags & ~DNET_IFLAGS_ALL) != 0) {
		err = -ENOTSUP;
		goto err_out_exit;
	}
	/* Check for valid callback */
	if (ireq->itype <= DNET_ITYPE_FIRST || ireq->itype >= DNET_ITYPE_LAST) {
		err = -ENOTSUP;
		goto err_out_exit;
	}

	/*
	 * Range checks
	 */

	if (ireq->flags & DNET_IFLAGS_KEY_RANGE) {
		struct dnet_raw_id empty_key;
		memset(&empty_key, 0, sizeof(struct dnet_raw_id));
		/* Unset DNET_IFLAGS_KEY_RANGE if both keys are empty */
		if (memcmp(&empty_key, &ireq->key_begin, sizeof(struct dnet_raw_id)) == 0
				&& memcmp(&empty_key, &ireq->key_end, sizeof(struct dnet_raw_id)) == 0) {
			dnet_log(st->n, DNET_LOG_NOTICE, "%s: both keys are zero: cmd: %u\n",
				dnet_dump_id(&cmd->id), cmd->cmd);
			ireq->flags &= ~DNET_IFLAGS_KEY_RANGE;
		}
		/* Check that range is valid */
		if (dnet_id_cmp_str(ireq->key_begin.id, ireq->key_end.id) > 0) {
			dnet_log(st->n, DNET_LOG_ERROR, "%s: key_start > key_begin: cmd: %u\n",
				dnet_dump_id(&cmd->id), cmd->cmd);
			err = -ERANGE;
			goto err_out_exit;
		}
	}
	if (ireq->flags & DNET_IFLAGS_TS_RANGE) {
		struct dnet_time empty_time;
		memset(&empty_time, 0, sizeof(struct dnet_time));
		/* Unset DNET_IFLAGS_KEY_RANGE if both times are empty */
		if (memcmp(&empty_time, &ireq->time_begin, sizeof(struct dnet_time)) == 0
				&& memcmp(&empty_time, &ireq->time_end, sizeof(struct dnet_time) == 0)) {
			dnet_log(st->n, DNET_LOG_NOTICE, "%s: both times are zero: cmd: %u\n",
				dnet_dump_id(&cmd->id), cmd->cmd);
			ireq->flags &= ~DNET_IFLAGS_TS_RANGE;
		}
		/* Check that range is valid */
		if (dnet_time_cmp(&ireq->time_begin, &ireq->time_end) > 0) {
			dnet_log(st->n, DNET_LOG_ERROR, "%s: time_begin > time_begin: cmd: %u\n",
				dnet_dump_id(&cmd->id), cmd->cmd);
			err = -ERANGE;
			goto err_out_exit;
		}
	}

	switch (ireq->itype) {
	case DNET_ITYPE_NETWORK:
		memset(&spriv, 0, sizeof(struct dnet_iterator_send_private));

		spriv.st = st;
		spriv.cmd = cmd;

		cpriv.next_callback = dnet_iterator_callback_send;
		cpriv.next_private = &spriv;
		break;
	case DNET_ITYPE_DISK:
		memset(&fpriv, 0, sizeof(struct dnet_iterator_file_private));

		/* XXX: Use history, Use iterator id! */
		snprintf(iter_path, PATH_MAX, "iter/%s", dnet_dump_id(&cmd->id));
		if ((fpriv.fd = open(iter_path, mode, 0644)) == -1) {
			dnet_log(st->n, DNET_LOG_INFO, "%s: cmd: %u, can't open: %s: err: %d\n",
				dnet_dump_id(&cmd->id), cmd->cmd, iter_path, err);
			err = -errno;
			goto err_out_exit;
		}

		cpriv.next_callback = dnet_iterator_callback_file;
		cpriv.next_private = &fpriv;
		break;
	default:
		err = -EINVAL;
		goto err_out_exit;
	}

	/* XXX: Add iterator to the list of running */
	err = st->n->cb->iterator(&ictl);
	/* XXX: Remove iterator */

err_out_exit:
	dnet_log(st->n, DNET_LOG_INFO, "%s: iteration finished: cmd: %u, err: %d\n",
		dnet_dump_id(&cmd->id), cmd->cmd, err);
	return err;
}

int dnet_process_cmd_raw(struct dnet_net_state *st, struct dnet_cmd *cmd, void *data)
{
	int err = 0;
	unsigned long long size = cmd->size;
	struct dnet_node *n = st->n;
	unsigned long long tid = cmd->trans & ~DNET_TRANS_REPLY;
	struct dnet_io_attr *io;
	struct timeval start, end;
	long diff;

	if (!(cmd->flags & DNET_FLAGS_NOLOCK)) {
		dnet_oplock(n, &cmd->id);
	}

	gettimeofday(&start, NULL);

	switch (cmd->cmd) {
		case DNET_CMD_AUTH:
			err = dnet_cmd_auth(st, cmd, data);
			break;
		case DNET_CMD_STATUS:
			err = dnet_cmd_status(st, cmd, data);
			break;
		case DNET_CMD_REVERSE_LOOKUP:
			err = dnet_cmd_reverse_lookup(st, cmd, data);
			break;
		case DNET_CMD_JOIN:
			err = dnet_cmd_join_client(st, cmd, data);
			break;
		case DNET_CMD_ROUTE_LIST:
			err = dnet_cmd_route_list(st, cmd);
			break;
		case DNET_CMD_EXEC:
			err = dnet_cmd_exec(st, cmd, data);
			break;
		case DNET_CMD_ITERATOR:
			err = dnet_cmd_iterator(st, cmd, data);
			break;
		case DNET_CMD_STAT_COUNT:
			err = dnet_cmd_stat_count(st, cmd, data);
			break;
		case DNET_CMD_NOTIFY:
			if (!(cmd->flags & DNET_ATTR_DROP_NOTIFICATION)) {
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
				err = dnet_notify_remove(st, cmd);
			break;
		case DNET_CMD_LIST:
			if (n->ro) {
				err = -EROFS;
			} else {
				if (cmd->flags & DNET_ATTR_BULK_CHECK)
					err = dnet_cmd_bulk_check(st, cmd, data);
				else
					err = dnet_db_list(st, cmd);
			}
			break;
		case DNET_CMD_READ:
		case DNET_CMD_WRITE:
		case DNET_CMD_DEL:
			if (n->ro && ((cmd->cmd == DNET_CMD_DEL) || (cmd->cmd == DNET_CMD_WRITE))) {
				err = -EROFS;
				break;
			}

			io = NULL;
			if (size < sizeof(struct dnet_io_attr)) {
				dnet_log(st->n, DNET_LOG_ERROR, "%s: invalid size: cmd: %u, rest_size: %llu\n",
					dnet_dump_id(&cmd->id), cmd->cmd, size);
				err = -EINVAL;
				break;
			}
			io = data;
			dnet_convert_io_attr(io);

			dnet_log(n, DNET_LOG_INFO, "%s: %s io command, offset: %llu, size: %llu, ioflags: %x, cflags: %llx, "
					"node-flags: %x, type: %d\n",
					dnet_dump_id_str(io->id), dnet_cmd_string(cmd->cmd),
					(unsigned long long)io->offset, (unsigned long long)io->size,
					io->flags, (unsigned long long)cmd->flags,
					n->flags, io->type);

			if (n->flags & DNET_CFG_NO_CSUM)
				io->flags |= DNET_IO_FLAGS_NOCSUM;

			/* do not write metadata for cache-only writes */
			if ((io->flags & DNET_IO_FLAGS_CACHE_ONLY) && (io->type == EBLOB_TYPE_META)) {
				err = -EINVAL;
				break;
			}

			/*
			 * Only allow cache for column 0
			 * In the next life (2012 I really expect) there will be no columns at all
			 */
			if (io->type == 0) {
				/*
				 * Always check cache when reading!
				 */
				if ((io->flags & DNET_IO_FLAGS_CACHE) || (cmd->cmd != DNET_CMD_WRITE)) {
					err = dnet_cmd_cache_io(st, cmd, io, data + sizeof(struct dnet_io_attr));

					if (io->flags & DNET_IO_FLAGS_CACHE_ONLY) {
						if ((cmd->cmd == DNET_CMD_WRITE) && !err) {
							cmd->flags &= ~DNET_FLAGS_NEED_ACK;
							err = dnet_send_file_info_without_fd(st, cmd, 0, io->size);
						}
						break;
					}

					/*
					 * We successfully read data from cache, do not sink to disk for it
					 */
					if ((cmd->cmd == DNET_CMD_READ) && !err)
						break;
				}
			}

			if ((io->flags & DNET_IO_FLAGS_COMPARE_AND_SWAP) && (cmd->cmd == DNET_CMD_WRITE)) {
				char csum[DNET_ID_SIZE];
				int csize = DNET_ID_SIZE;

				if (!n->cb->checksum) {
					err = -ENOTSUP;
					dnet_log(n, DNET_LOG_ERROR, "%s: cas: checksum operation is not supported in backend\n",
							dnet_dump_id(&cmd->id));
					break;
				}

				err = n->cb->checksum(n, n->cb->command_private, &cmd->id, csum, &csize);
				if (err < 0 && err != -ENOENT) {
					dnet_log(n, DNET_LOG_ERROR, "%s: cas: checksum operation failed\n", dnet_dump_id(&cmd->id));
					break;
				}

				/*
				 * If err == -ENOENT then there is no data to checksum, and CAS should succeed
				 * This is not 'client-safe' since two or more clients with unlocked CAS write
				 * may find out that there is no data and try to write their data, but we do not
				 * case about parallel writes being made without locks.
				 */

				if (err == 0) {
					if (memcmp(csum, io->parent, DNET_ID_SIZE)) {
						char disk_csum[DNET_ID_SIZE * 2 + 1];
						char recv_csum[DNET_ID_SIZE * 2 + 1];

						dnet_dump_id_len_raw((const unsigned char *)csum, DNET_ID_SIZE, disk_csum);
						dnet_dump_id_len_raw(io->parent, DNET_ID_SIZE, recv_csum);
						dnet_log(n, DNET_LOG_ERROR, "%s: cas: checksum mismatch: disk-csum: %s, recv-csum: %s\n",
								dnet_dump_id(&cmd->id), disk_csum, recv_csum);
						err = -EBADFD;
						break;
					} else if (n->log->log_level >= DNET_LOG_NOTICE) {
						char recv_csum[DNET_ID_SIZE * 2 + 1];

						dnet_dump_id_len_raw(io->parent, DNET_ID_SIZE, recv_csum);
						dnet_log(n, DNET_LOG_NOTICE, "%s: cas: checksum; %s\n",
								dnet_dump_id(&cmd->id), recv_csum);
					}
				}
			}

			if ((cmd->cmd == DNET_CMD_DEL) || (io->flags & DNET_IO_FLAGS_META)) {
				err = dnet_process_meta(st, cmd, data);
				break;
			}

			dnet_convert_io_attr(io);
		default:
			/* Remove DNET_FLAGS_NEED_ACK flags for WRITE command 
			   to eliminate double reply packets 
			   (the first one with dnet_file_info structure,
			   the second to destroy transaction on client side) */
			if ((cmd->cmd == DNET_CMD_WRITE) || (cmd->cmd == DNET_CMD_READ)) {
				cmd->flags &= ~DNET_FLAGS_NEED_ACK;
			}
			err = n->cb->command_handler(st, n->cb->command_private, cmd, data);

			/* If there was error in WRITE command - send empty reply
			   to notify client with error code and destroy transaction */
			if (err && ((cmd->cmd == DNET_CMD_WRITE) || (cmd->cmd == DNET_CMD_READ))) {
				cmd->flags |= DNET_FLAGS_NEED_ACK;
			}

			if (!err && (cmd->cmd == DNET_CMD_WRITE)) {
				dnet_update_notify(st, cmd, data);
			}
			break;
	}

	dnet_stat_inc(st->stat, cmd->cmd, err);
	if (st->__join_state == DNET_JOIN)
		dnet_counter_inc(n, cmd->cmd, err);
	else
		dnet_counter_inc(n, cmd->cmd + __DNET_CMD_MAX, err);

	gettimeofday(&end, NULL);

	diff = (end.tv_sec - start.tv_sec) * 1000000 + (end.tv_usec - start.tv_usec);
	dnet_log(n, DNET_LOG_INFO, "%s: %s: trans: %llu, cflags: %llx, time: %ld usecs, err: %d.\n",
			dnet_dump_id(&cmd->id), dnet_cmd_string(cmd->cmd), tid,
			(unsigned long long)cmd->flags, diff, err);

	err = dnet_send_ack(st, cmd, err);

	if (!(cmd->flags & DNET_FLAGS_NOLOCK))
		dnet_opunlock(n, &cmd->id);

	return err;
}

int dnet_state_join_nolock(struct dnet_net_state *st)
{
	int err;
	struct dnet_node *n = st->n;
	struct dnet_net_state *base;
	struct dnet_id id;

	base = dnet_state_search_nolock(n, &n->id);
	if (!base) {
		err = -ENXIO;
		goto err_out_exit;
	}

	/* we do not care about group_id actually, since use direct send */
	memcpy(&id, &n->id, sizeof(id));

	err = dnet_send_idc(base, st, &id, 0, DNET_CMD_JOIN, 0, 1, 0);
	if (err) {
		dnet_log(n, DNET_LOG_ERROR, "%s: failed to send join request to %s.\n",
			dnet_dump_id(&id), dnet_server_convert_dnet_addr(&st->addr));
		goto err_out_put;
	}

	st->__join_state = DNET_JOIN;
	dnet_log(n, DNET_LOG_INFO, "%s: successfully joined network, group %d.\n", dnet_dump_id(&id), id.group_id);

err_out_put:
	/* this is dangerous, since base can go away and we will destroy it here,
	 * which in turn will call dnet_state_remove(), which will deadlock with n->state_lock already being held
	 *
	 * FIXME
	 */
	dnet_state_put(base);
err_out_exit:
	return err;
}

/*
int64_t dnet_get_param(struct dnet_node *n, struct dnet_id *id, enum id_params param)
{
	struct dnet_net_state *st;
	int64_t ret = 1;

	st = dnet_state_get_first(n, id);
	if (!st)
		return -ENXIO;

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
*/
/* TODO: remove this function
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

		pthread_mutex_lock(&n->state_lock);
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
		pthread_mutex_unlock(&n->state_lock);
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
	}

	err = group_num;

err_out_exit:
	return err;
}
*/

static int dnet_populate_cache(struct dnet_node *n, struct dnet_cmd *cmd, struct dnet_io_attr *io,
		void *data, int fd, size_t fd_offset, size_t size)
{
	void *orig_data = data;
	ssize_t err;

	if (!data && fd >= 0) {
		ssize_t tmp_size = size;

		if (size >= n->cache_size)
			return -ENOMEM;

		orig_data = data = malloc(size);
		if (!data)
			return -ENOMEM;

		while (tmp_size > 0) {
			err = pread(fd, data, tmp_size, fd_offset);
			if (err <= 0) {
				dnet_log_err(n, "%s: failed to populate cache: pread: offset: %zd, size: %zd",
						dnet_dump_id(&cmd->id), fd_offset, size);
				goto err_out_free;
			}

			data += err;
			tmp_size -= err;
			fd_offset += err;
		}
	}

	cmd->cmd = DNET_CMD_WRITE;
	err = dnet_cmd_cache_io(n->st, cmd, io, orig_data);
	cmd->cmd = DNET_CMD_READ;

err_out_free:
	if (data != orig_data)
		free(orig_data);

	return err;
}

int dnet_send_read_data(void *state, struct dnet_cmd *cmd, struct dnet_io_attr *io, void *data,
		int fd, uint64_t offset, int on_exit)
{
	struct dnet_net_state *st = state;
	struct dnet_node *n = st->n;
	struct dnet_cmd *c;
	struct dnet_io_attr *rio;
	int hsize = sizeof(struct dnet_cmd) + sizeof(struct dnet_io_attr);
	int err;

	/*
	 * A simple hack to forbid read reply sending.
	 * It is used in local stat - we do not want to send stat data
	 * back to parental client, instead server will wrap data into
	 * proper transaction reply next to this obscure packet.
	 */
	if (io->flags & DNET_IO_FLAGS_SKIP_SENDING)
		return 0;

	c = malloc(hsize);
	if (!c) {
		err = -ENOMEM;
		goto err_out_exit;
	}

	memset(c, 0, hsize);

	rio = (struct dnet_io_attr *)(c + 1);

	dnet_setup_id(&c->id, cmd->id.group_id, io->id);

	c->flags = cmd->flags & ~(DNET_FLAGS_NEED_ACK | DNET_FLAGS_MORE);
	if (cmd->flags & DNET_FLAGS_NEED_ACK)
		c->flags |= DNET_FLAGS_MORE;

	c->size = sizeof(struct dnet_io_attr) + io->size;
	c->trans = cmd->trans | DNET_TRANS_REPLY;
	c->cmd = DNET_CMD_READ;

	memcpy(rio, io, sizeof(struct dnet_io_attr));

	dnet_log_raw(n, DNET_LOG_NOTICE, "%s: %s: reply: offset: %llu, size: %llu.\n",
			dnet_dump_id(&c->id), dnet_cmd_string(c->cmd),
			(unsigned long long)io->offset,	(unsigned long long)io->size);

	/* only populate data which has zero offset and from column 0 */
	if ((io->flags & DNET_IO_FLAGS_CACHE) && !io->offset && (io->type == 0)) {
		err = dnet_populate_cache(st->n, c, rio, data, fd, offset, io->size);
	}

	dnet_convert_cmd(c);
	dnet_convert_io_attr(rio);

	if (io->flags & DNET_IO_FLAGS_CHECKSUM) {
		if (data) {
			err = dnet_checksum_data(n, data, rio->size, rio->parent, sizeof(rio->parent));
		} else {
			err = dnet_checksum_fd(n, fd, offset, rio->size, rio->parent, sizeof(rio->parent));
		}

		if (err)
			goto err_out_free;
	}

	if (data)
		err = dnet_send_data(st, c, hsize, data, rio->size);
	else
		err = dnet_send_fd(st, c, hsize, fd, offset, rio->size, on_exit);

err_out_free:
	free(c);
err_out_exit:
	return err;
}

static void dnet_fill_state_addr(void *state, struct dnet_addr *addr)
{
	struct dnet_net_state *st = state;
	struct dnet_node *n = st->n;

	memcpy(addr, &n->addrs[0], sizeof(struct dnet_addr));
}

int dnet_read_file_info(struct dnet_node *n, struct dnet_id *id, struct dnet_file_info *info)
{
	struct dnet_meta *m;
	struct dnet_meta_update *mu;
	struct dnet_meta_container mc;
	struct dnet_raw_id raw;
	int err;

	memcpy(raw.id, id->id, DNET_ID_SIZE);

	err = n->cb->meta_read(n->cb->command_private, &raw, &mc.data);
	if (err < 0) {
		goto err_out_exit;
	}
	mc.size = err;

	m = dnet_meta_search(n, &mc, DNET_META_UPDATE);
	if (!m) {
		dnet_log(n, DNET_LOG_ERROR, "%s: dnet_read_file_info_verify_csum: no DNET_META_UPDATE tag in metadata\n",
				dnet_dump_id(id));
		err = -ENODATA;
		goto err_out_free;
	}

	mu = (struct dnet_meta_update *)m->data;
	dnet_convert_meta_update(mu);

	info->mtime = mu->tm;
	err = 0;

err_out_free:
	free(mc.data);
err_out_exit:
	return err;
}

static int dnet_fd_readlink(int fd, char **datap)
{
	char *dst, src[64];
	int dsize = 4096;
	int err;

	snprintf(src, sizeof(src), "/proc/self/fd/%d", fd);

	dst = malloc(dsize);
	if (!dst) {
		err = -ENOMEM;
		goto err_out_exit;
	}

	err = readlink(src, dst, dsize);
	if (err < 0)
		goto err_out_free;

	dst[err] = '\0';
	*datap = dst;

	return err + 1; /* including 0-byte */

err_out_free:
	free(dst);
err_out_exit:
	return err;
}

int dnet_send_file_info(void *state, struct dnet_cmd *cmd, int fd, uint64_t offset, int64_t size)
{
	struct dnet_node *n = dnet_get_node_from_state(state);
	struct dnet_file_info *info;
	struct dnet_addr *addr;
	int flen, err;
	char *file;
	struct stat st;

	err = dnet_fd_readlink(fd, &file);
	if (err < 0)
		goto err_out_exit;

	flen = err;

	addr = malloc(sizeof(struct dnet_addr) + sizeof(struct dnet_file_info) + flen);
	if (!addr) {
		err = -ENOMEM;
		goto err_out_free_file;
	}
	info = (struct dnet_file_info *)(addr + 1);

	dnet_fill_state_addr(state, addr);
	dnet_convert_addr(addr);

	err = fstat(fd, &st);
	if (err) {
		err = -errno;
		dnet_log(n, DNET_LOG_ERROR, "%s: file-info: %s: info-stat: %d: %s.\n",
				dnet_dump_id(&cmd->id), file, err, strerror(-err));
		goto err_out_free;
	}

	dnet_info_from_stat(info, &st);
	/* this is not valid data from raw blob file stat */
	info->mtime.tsec = 0;

	if (cmd->flags & DNET_ATTR_META_TIMES) {
		err = dnet_read_file_info(n, &cmd->id, info);
		if (((err == -ENOENT) || (err == -ENXIO)) && (cmd->flags & DNET_ATTR_META_TIMES))
			err = 0;
		if (err)
			goto err_out_free;
	}

	if (size >= 0)
		info->size = size;
	if (offset)
		info->offset = offset;

	if (cmd->flags & DNET_FLAGS_CHECKSUM) {
		err = dnet_checksum_fd(n, fd, info->offset, info->size, info->checksum, sizeof(info->checksum));
		if (err) {
			dnet_log(n, DNET_LOG_ERROR, "%s: file-info: %s: checksum: %d: %s.\n",
					dnet_dump_id(&cmd->id), file, err, strerror(-err));
			goto err_out_free;
		}
	}

	if (info->size == 0) {
		err = -EINVAL;
		dnet_log(n, DNET_LOG_NOTICE, "%s: EBLOB: %s: info-stat: ZERO-FILE-SIZE, fd: %d.\n",
				dnet_dump_id(&cmd->id), file, fd);
		goto err_out_free;
	}

	info->flen = flen;
	memcpy(info + 1, file, flen);

	dnet_convert_file_info(info);

	err = dnet_send_reply(state, cmd, addr, sizeof(struct dnet_addr) + sizeof(struct dnet_file_info) + flen, 0);

err_out_free:
	free(addr);
err_out_free_file:
	free(file);
err_out_exit:
	return err;
}

int dnet_send_file_info_without_fd(void *state, struct dnet_cmd *cmd, void *data, int64_t size)
{
	struct dnet_net_state *st = state;
	struct dnet_file_info *info;
	struct dnet_addr *a;
	int err;
	const char file[] = "";
	const size_t flen = sizeof(file) - 1;

	a = malloc(sizeof(struct dnet_addr) + sizeof(struct dnet_file_info) + flen);
	if (!a) {
		err = -ENOMEM;
		goto err_out_exit;
	}
	info = (struct dnet_file_info *)(a + 1);

	dnet_fill_state_addr(state, a);
	dnet_convert_addr(a);

	memset(info, 0, sizeof(struct dnet_file_info));

	if (size >= 0)
		info->size = size;

	if (flen > 0) {
		info->flen = flen;
		memcpy(info + 1, file, flen);
	}

	if (cmd->flags & DNET_FLAGS_CHECKSUM)
		dnet_checksum_data(st->n, data, size, info->checksum, sizeof(info->checksum));

	dnet_convert_file_info(info);

	err = dnet_send_reply(state, cmd, a, sizeof(struct dnet_addr) + sizeof(struct dnet_file_info) + flen, 0);

	free(a);
err_out_exit:
	return err;
}

int dnet_checksum_data(struct dnet_node *n, const void *data, uint64_t size, unsigned char *csum, int csize)
{
	return dnet_transform_node(n, data, size, csum, csize);
}

int dnet_checksum_file(struct dnet_node *n, const char *file, uint64_t offset, uint64_t size, void *csum, int csize)
{
	int fd, err;

	err = open(file, O_RDONLY);

	if (err < 0) {
		err = -errno;
		dnet_log_err(n, "failed to open to be csummed file '%s'", file);
		goto err_out_exit;
	}
	fd = err;
	err = dnet_checksum_fd(n, fd, offset, size, csum, csize);
	close(fd);

err_out_exit:
	return err;
}

int dnet_checksum_fd(struct dnet_node *n, int fd, uint64_t offset, uint64_t size, void *csum, int csize)
{
	int err;
	struct dnet_map_fd m;

	if (!size) {
		struct stat st;

		err = fstat(fd, &st);
		if (err < 0) {
			err = -errno;
			dnet_log_err(n, "CSUM: fd: %d", fd);
			goto err_out_exit;
		}

		size = st.st_size;
	}

	m.fd = fd;
	m.size = size;
	m.offset = offset;

	err = dnet_data_map(&m);
	if (err)
		goto err_out_exit;

	err = dnet_checksum_data(n, m.data, size, csum, csize);
	dnet_data_unmap(&m);

err_out_exit:
	return err;
}

/* Allocate and init iterator */
struct dnet_iterator *dnet_iterator_alloc(uint64_t id)
{
	struct dnet_iterator *it;
	int err;

	it = calloc(1, sizeof(struct dnet_iterator));
	if (it == NULL)
		goto err_out_exit;

	it->id = id;
	it->state = DNET_ITERATOR_CMD_START;
	INIT_LIST_HEAD(&it->list);
	err = pthread_cond_init(&it->wait, NULL);
	if (err != 0)
		goto err_out_free;
	err = pthread_mutex_init(&it->lock, NULL);
	if (err != 0)
		goto err_out_destroy_cond;

	return it;

err_out_destroy_cond:
	pthread_cond_destroy(&it->wait);
err_out_free:
	free(it);
err_out_exit:
	return NULL;
}

/* Destroy previously allocated iterator */
void dnet_iterator_destroy(struct dnet_iterator *it)
{
	if (it == NULL)
		return;
	pthread_cond_destroy(&it->wait);
	pthread_mutex_destroy(&it->lock);
}

/* Adds iterator to the list of running iterators if it's not already there */
int dnet_iterator_list_insert(struct dnet_node *n, struct dnet_iterator *it)
{
	struct dnet_iterator *pos;

	/* Sanity */
	if (n == NULL || it == NULL)
		return -EINVAL;

	/* Check that iterator not already in list */
	pthread_mutex_lock(&n->iterator_lock);
	list_for_each_entry(pos, &n->iterator_list, list) {
		if (pos->id == it->id) {
			pthread_mutex_unlock(&n->iterator_lock);
			return -EEXIST;
		}
	}
	/* Add to list */
	list_add(&it->list, &n->iterator_list);
	pthread_mutex_unlock(&n->iterator_lock);

	return 0;
}

/* Looks up iterator in list by id */
struct dnet_iterator *dnet_iterator_list_lookup_nolock(struct dnet_node *n, uint64_t id)
{
	struct dnet_iterator *pos;

	/* Sanity */
	if (n == NULL)
		return NULL;

	/* Lookup iterator by id and return pointer */
	list_for_each_entry(pos, &n->iterator_list, list) {
		if (pos->id == id) {
			return pos;
		}
	}

	return NULL;
}

/* Removes iterator from list by id */
int dnet_iterator_list_remove(struct dnet_node *n, uint64_t id)
{
	struct dnet_iterator *pos;

	/* Sanity */
	if (n == NULL)
		return -EINVAL;

	/* Lookup iterator by id and remove */
	pthread_mutex_lock(&n->iterator_lock);
	list_for_each_entry(pos, &n->iterator_list, list) {
		if (pos->id == id) {
			list_del_init(&pos->list);
			pthread_mutex_unlock(&n->iterator_lock);
			return 0;
		}
	}
	pthread_mutex_unlock(&n->iterator_lock);

	return -ENOENT;
}
