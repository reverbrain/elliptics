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

#define _XOPEN_SOURCE 600

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <sys/wait.h>

#include <alloca.h>
#include <assert.h>
#include <ctype.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "elliptics.h"
#include "../monitor/monitor.h"

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
	const size_t cmd_size = sizeof(struct dnet_cmd) + sizeof(struct dnet_io_attr);
	int err;
	char buffer[cmd_size];
	struct dnet_cmd *cmd = (struct dnet_cmd *)buffer;
	struct dnet_io_attr *io = (struct dnet_io_attr *)(cmd + 1);

	memset(buffer, 0, cmd_size);

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

	return err;

}

static void dnet_send_idc_fill(struct dnet_net_state *st, struct dnet_addr_cmd *acmd, int total_size,
		struct dnet_id *id, uint64_t trans, unsigned int command, int reply, int direct, int more)
{
	struct dnet_node *n = st->n;
	struct dnet_cmd *cmd = &acmd->cmd;
	struct dnet_raw_id *sid;
	char parsed_addr_str[128];
	char state_addr_str[128];
	int i;

	acmd->cnt.addr_num = n->addr_num;
	if (!st->addrs)
		memcpy(acmd->cnt.addrs, n->addrs, n->addr_num * sizeof(struct dnet_addr));
	else
		memcpy(acmd->cnt.addrs, st->addrs, n->addr_num * sizeof(struct dnet_addr));

	dnet_server_convert_dnet_addr_raw(&st->addr, state_addr_str, sizeof(state_addr_str));
	for (i = 0; i < acmd->cnt.addr_num; ++i) {
		dnet_log(n, DNET_LOG_NOTICE, "%s: filling route table: addr-to-be-sent: %s, st->addrs: %p\n", state_addr_str,
			dnet_server_convert_dnet_addr_raw(&acmd->cnt.addrs[i], parsed_addr_str, sizeof(parsed_addr_str)),
			st->addrs);
	}

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
	int version[4] = {0, 0, 0, 0};
	int indexes_shard_count = 0;

	dnet_version_decode(&cmd->id, version);
	dnet_indexes_shard_count_decode(&cmd->id, &indexes_shard_count);
	memcpy(st->version, version, sizeof(st->version));

	dnet_version_encode(&cmd->id);
	dnet_indexes_shard_count_encode(&cmd->id, n->indexes_shard_count);

	err = dnet_version_check(st, version);
	if (err)
		goto err_out_exit;

	dnet_log(n, DNET_LOG_INFO, "%s: reverse lookup command: client indexes shard count: %d, server indexes shard count: %d\n",
			dnet_state_dump_addr(st),
			indexes_shard_count,
			n->indexes_shard_count);

	cmd->id.group_id = n->id.group_id;
	base = dnet_node_state(n);
	if (base) {
		err = dnet_send_idc(base, st, &cmd->id, cmd->trans, DNET_CMD_REVERSE_LOOKUP, 1, 0, 0);
		dnet_state_put(base);
	}

err_out_exit:
	if (err) {
		cmd->flags |= DNET_FLAGS_NEED_ACK;
		dnet_state_reset(st, err);
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

			dnet_log(n, DNET_LOG_NOTICE, "%s: %d %s, id_num: %d, addr_num: %d\n",
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
		as->count[DNET_CNTR_NODE_FILES].count = st.node_files;
		as->count[DNET_CNTR_NODE_FILES_REMOVED].count = st.node_files_removed;
	}

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

	dnet_log(n, DNET_LOG_INFO, "%s: status-change: nflags: 0x%x->0x%x, log_level: %d->%d, "
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

int dnet_send_ack(struct dnet_net_state *st, struct dnet_cmd *cmd, int err, int recursive)
{
	if (st && cmd && (cmd->flags & DNET_FLAGS_NEED_ACK)) {
		struct dnet_node *n = st->n;
		unsigned long long tid = cmd->trans & ~DNET_TRANS_REPLY;
		struct dnet_cmd ack;

		memcpy(&ack.id, &cmd->id, sizeof(struct dnet_id));
		ack.cmd = cmd->cmd;
		ack.trans = cmd->trans | DNET_TRANS_REPLY;
		ack.size = 0;
		// In recursive mode keep DNET_FLAGS_MORE flag
		if (recursive)
			ack.flags = cmd->flags & ~(DNET_FLAGS_NEED_ACK);
		else
			ack.flags = cmd->flags & ~(DNET_FLAGS_NEED_ACK | DNET_FLAGS_MORE);
		ack.status = err;

		dnet_log(n, DNET_LOG_NOTICE, "%s: %s: ack -> %s: trans: %llu, flags: 0x%llx, status: %d.\n",
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
 */
static int dnet_iterator_callback_send(void *priv, void *data, uint64_t dsize)
{
	struct dnet_iterator_send_private *send = priv;

	/*
	 * If need_exit is set - skips sending reply and return -EINTR to
	 * interrupt execution of current iterator
	 */
	if (send->st->__need_exit) {
		dnet_log(send->st->n, DNET_LOG_ERROR,
				"%s: Interrupting iterator because peer has been disconnected\n",
				dnet_dump_id(&send->cmd->id));
		return -EINTR;
	}

	return dnet_send_reply_threshold(send->st, send->cmd, data, dsize, 1);
}

/*!
 * This routine decides whenever it's time for iterator to pause/cancel.
 *
 * While state is 'paused' - wait on condition variable.
 * If state is 'canceled' - exit with error.
 */
static int dnet_iterator_flow_control(struct dnet_iterator_common_private *ipriv)
{
	int err = 0;

	pthread_mutex_lock(&ipriv->it->lock);
	while (ipriv->it->state == DNET_ITERATOR_ACTION_PAUSE)
		err = pthread_cond_wait(&ipriv->it->wait, &ipriv->it->lock);
	if (ipriv->it->state == DNET_ITERATOR_ACTION_CANCEL)
		err = -ENOEXEC;
	pthread_mutex_unlock(&ipriv->it->lock);

	return err;
}

/*!
 * Common callback part that is run by all iterator types.
 * It's responsible for sanity checks and flow control.
 *
 * Also now it "prepares" data for next callback by combining data itself with
 * fixed-size response header.
 */
static int dnet_iterator_callback_common(void *priv, struct dnet_raw_id *key,
		void *data, uint64_t dsize, struct dnet_ext_list *elist)
{
	struct dnet_iterator_common_private *ipriv = priv;
	struct dnet_iterator_response *response;
	static const uint64_t response_size = sizeof(struct dnet_iterator_response);
	uint64_t size;
	const uint64_t fsize = dsize;
	unsigned char *combined = NULL, *position;
	int err = 0;

	/* Sanity */
	if (ipriv == NULL || key == NULL || data == NULL || elist == NULL)
		return -EINVAL;

	/* If DNET_IFLAGS_KEY_RANGE is set... */
	if (ipriv->req->flags & DNET_IFLAGS_KEY_RANGE) {
		/* ...skip keys not in key ranges */
		struct dnet_iterator_range *curr = ipriv->range;
		struct dnet_iterator_range *end = curr + ipriv->req->range_num;
		for (; curr < end; ++curr) {
			if (dnet_id_cmp_str(key->id, curr->key_begin.id) >= 0
					&& dnet_id_cmp_str(key->id, curr->key_end.id) < 0)
				goto key_range_found;
		}
		/* no range contains the key */
		goto err_out_exit;
	}

key_range_found:

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

	/* Prepare combined buffer */
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
	response->size = fsize;
	dnet_convert_iterator_response(response);

	/* Data */
	if (data) {
		position += response_size;
		memcpy(position, data, dsize);
	}

	/* Finally run next callback */
	err = ipriv->next_callback(ipriv->next_private, combined, size);
	if (err)
		goto err_out_exit;

	/* Check that we are allowed to run */
	err = dnet_iterator_flow_control(ipriv);

err_out_exit:
	free(combined);
	return err;
}

static int dnet_iterator_check_key_range(struct dnet_net_state *st, struct dnet_cmd *cmd,
		struct dnet_iterator_request *ireq,
		struct dnet_iterator_range *irange)
{
	struct dnet_iterator_range *i = NULL;
	struct dnet_iterator_range *end = irange + ireq->range_num;

	if (ireq->flags & DNET_IFLAGS_KEY_RANGE) {
		struct dnet_raw_id empty_key = { .id = {} };

		/* Unset DNET_IFLAGS_KEY_RANGE if all keys are empty */
		for (i = irange; i < end; ++i) {
			if (memcmp(&empty_key, &i->key_begin, sizeof(struct dnet_raw_id)) != 0
					|| memcmp(&empty_key, &i->key_end, sizeof(struct dnet_raw_id)) != 0) {
				break;
			}
		}
		if (i == end) {
			dnet_log(st->n, DNET_LOG_ERROR, "%s: all keys in all ranges are 0\n",
				dnet_dump_id(&cmd->id));
			ireq->flags &= ~DNET_IFLAGS_KEY_RANGE;
		}

		/* Check that each range is valid */
		for (i = irange; i < end; ++i) {
			if (dnet_id_cmp_str(i->key_begin.id, i->key_end.id) > 0) {
				dnet_log(st->n, DNET_LOG_ERROR, "%s: %tu: key_start > key_begin: cmd: %u\n",
					dnet_dump_id(&cmd->id), i - irange, cmd->cmd);
				return -ERANGE;
			}
		}
	}
	if (ireq->flags & DNET_IFLAGS_KEY_RANGE) {
		const short id_len = 6, buf_sz = id_len * 2 + 1;
		char buf1[buf_sz], buf2[buf_sz];

		for (i = irange; i < end; ++i) {
			dnet_log(st->n, DNET_LOG_NOTICE, "%s: using key range: %s...%s\n",
					dnet_dump_id(&cmd->id),
					dnet_dump_id_len_raw(i->key_begin.id, id_len, buf1),
					dnet_dump_id_len_raw(i->key_end.id, id_len, buf2));
		}
	}
	return 0;
}

static int dnet_iterator_check_ts_range(struct dnet_net_state *st, struct dnet_cmd *cmd,
		struct dnet_iterator_request *ireq)
{
	if (ireq->flags & DNET_IFLAGS_TS_RANGE) {
		struct dnet_time empty_time = {0, 0};
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
			return -ERANGE;
		}
	}
	if (ireq->flags & DNET_IFLAGS_TS_RANGE)
		dnet_log(st->n, DNET_LOG_NOTICE, "%s: using ts range: "
				"%" PRIu64 ":%" PRIu64 "...%" PRIu64 ":%" PRIu64 "\n",
				dnet_dump_id(&cmd->id),
				ireq->time_begin.tsec, ireq->time_begin.tnsec,
				ireq->time_end.tsec, ireq->time_end.tnsec);
	return 0;
}

static int dnet_iterator_start(struct dnet_net_state *st, struct dnet_cmd *cmd,
		struct dnet_iterator_request *ireq,
		struct dnet_iterator_range *irange)
{
	struct dnet_iterator_common_private cpriv = {
		.req = ireq,
		.range = irange,
	};
	struct dnet_iterator_ctl ictl = {
		.iterate_private = st->n->cb->command_private,
		.callback = dnet_iterator_callback_common,
		.callback_private = &cpriv,
	};
	struct dnet_iterator_send_private spriv;
	struct dnet_iterator_file_private fpriv;
	int err;

	/* Check flags */
	if ((ireq->flags & ~DNET_IFLAGS_ALL) != 0) {
		err = -ENOTSUP;
		goto err_out_exit;
	}
	/* Check callback type */
	if (ireq->itype <= DNET_ITYPE_FIRST || ireq->itype >= DNET_ITYPE_LAST) {
		err = -ENOTSUP;
		goto err_out_exit;
	}
	/* Check ranges */
	if ((err = dnet_iterator_check_key_range(st, cmd, ireq, irange)) ||
			(err = dnet_iterator_check_ts_range(st, cmd, ireq)))
		goto err_out_exit;

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
		cpriv.next_callback = dnet_iterator_callback_file;
		cpriv.next_private = &fpriv;
		/* TODO: Implement local file-based iterators */
		err = -ENOTSUP;
		goto err_out_exit;
	default:
		err = -EINVAL;
		goto err_out_exit;
	}

	/* Create iterator */
	cpriv.it = dnet_iterator_create(st->n);
	if (cpriv.it == NULL) {
		err = -ENOMEM;
		goto err_out_exit;
	}

	/* Run iterator */
	err = st->n->cb->iterator(&ictl);

	/* Remove iterator */
	dnet_iterator_destroy(st->n, cpriv.it);

err_out_exit:
	dnet_log(st->n, DNET_LOG_NOTICE, "%s: %s: iteration finished: err: %d\n",
			__func__, dnet_dump_id(&cmd->id), err);
	return err;
}

/*!
 * Starts low-level backend iterator and passes data to network or file
 */
static int dnet_cmd_iterator(struct dnet_net_state *st, struct dnet_cmd *cmd, void *data)
{
	struct dnet_iterator_request *ireq = data;
	struct dnet_iterator_range *irange = data + sizeof(struct dnet_iterator_request);
	int err = 0;

	/*
	 * Sanity
	 */
	if (ireq == NULL || st == NULL || cmd == NULL)
		return -EINVAL;
	dnet_convert_iterator_request(ireq);

	dnet_log(st->n, DNET_LOG_NOTICE,
			"%s: started: %s: id: %" PRIu64 ", action: %d\n",
			__func__, dnet_dump_id(&cmd->id), ireq->id, ireq->action);

	/*
	 * Check iterator action start/pause/cont
	 * On pause, find in list and mark as stopped
	 * On cont, find in list and mark as running, broadcast condition variable.
	 * On start, (surprise!) create and start iterator.
	 */
	switch (ireq->action) {
	case DNET_ITERATOR_ACTION_START:
		err = dnet_iterator_start(st, cmd, ireq, irange);
		break;
	case DNET_ITERATOR_ACTION_PAUSE:
	case DNET_ITERATOR_ACTION_CONTINUE:
	case DNET_ITERATOR_ACTION_CANCEL:
		err = dnet_iterator_set_state(st->n, ireq->action, ireq->id);
		break;
	default:
		err = -EINVAL;
		goto err_out_exit;
	}

err_out_exit:
	dnet_log(st->n, DNET_LOG_NOTICE,
			"%s: finished: %s: id: %" PRIu64 ", action: %d, err: %d\n",
			__func__, dnet_dump_id(&cmd->id), ireq->id, ireq->action, err);
	return err;
}

static int dnet_cmd_bulk_read(struct dnet_net_state *st, struct dnet_cmd *cmd, void *data)
{
	int err = -1, ret;
	struct dnet_io_attr *io = data;
	struct dnet_io_attr *ios = io + 1;
	uint64_t count = 0;
	uint64_t i;

	struct dnet_cmd read_cmd = *cmd;
	read_cmd.size = sizeof(struct dnet_io_attr);
	read_cmd.cmd = DNET_CMD_READ;
	read_cmd.flags |= DNET_FLAGS_MORE;

	dnet_convert_io_attr(io);
	count = io->size / sizeof(struct dnet_io_attr);

	if (count > 0) {
		cmd->flags &= ~DNET_FLAGS_NEED_ACK;
	}

	/*
	 * we have to drop io lock, otherwise it will be grabbed again in dnet_process_cmd_raw() being recursively called
	 * Lock will be taken again after loop has been finished
	 */
	if (!(cmd->flags & DNET_FLAGS_NOLOCK)) {
		dnet_opunlock(st->n, &cmd->id);
	}

	dnet_log(st->n, DNET_LOG_NOTICE, "%s: starting BULK_READ for %d commands\n",
		dnet_dump_id(&cmd->id), (int) count);

	for (i = 0; i < count; i++) {
		ret = dnet_process_cmd_raw(st, &read_cmd, &ios[i], 1);
		dnet_log(st->n, DNET_LOG_NOTICE, "%s: processing BULK_READ.READ for %d/%d command, err: %d\n",
			dnet_dump_id(&cmd->id), (int) i, (int) count, ret);

		if (i + 1 == count)
			cmd->flags |= DNET_FLAGS_NEED_ACK;

		if (!ret)
			err = 0;
		else if (err == -1)
			err = ret;
	}

	if (!(cmd->flags & DNET_FLAGS_NOLOCK)) {
		dnet_oplock(st->n, &cmd->id);
	}

	return err;
}

int dnet_cas_local(struct dnet_node *n, struct dnet_id *id, void *remote_csum, int csize)
{
	char csum[DNET_ID_SIZE];
	int err = 0;

	if (!n->cb->checksum) {
		dnet_log(n, DNET_LOG_ERROR, "%s: cas: checksum operation is not supported in backend\n",
				dnet_dump_id(id));
		return -ENOTSUP;
	}

	err = n->cb->checksum(n, n->cb->command_private, id, csum, &csize);
	if (err != 0 && err != -ENOENT) {
		dnet_log(n, DNET_LOG_ERROR, "%s: cas: checksum operation failed\n", dnet_dump_id(id));
		return err;
	}

	/*
	 * If err == -ENOENT then there is no data to checksum, and CAS should succeed
	 * This is not 'client-safe' since two or more clients with unlocked CAS write
	 * may find out that there is no data and try to write their data, but we do not
	 * case about parallel writes being made without locks.
	 */

	if (err == 0) {
		if (memcmp(csum, remote_csum, DNET_ID_SIZE)) {
			char disk_csum[DNET_ID_SIZE * 2 + 1];
			char recv_csum[DNET_ID_SIZE * 2 + 1];

			dnet_dump_id_len_raw((const unsigned char *)csum, DNET_ID_SIZE, disk_csum);
			dnet_dump_id_len_raw(remote_csum, DNET_ID_SIZE, recv_csum);
			dnet_log(n, DNET_LOG_ERROR, "%s: cas: checksum mismatch: disk-csum: %s, recv-csum: %s\n",
					dnet_dump_id(id), disk_csum, recv_csum);
			return -EBADFD;
		} else if (n->log->log_level >= DNET_LOG_NOTICE) {
			char recv_csum[DNET_ID_SIZE * 2 + 1];

			dnet_dump_id_len_raw(remote_csum, DNET_ID_SIZE, recv_csum);
			dnet_log(n, DNET_LOG_NOTICE, "%s: cas: checksum; %s\n",
					dnet_dump_id(id), recv_csum);
		}
	}

	return err;
}

int dnet_process_cmd_raw(struct dnet_net_state *st, struct dnet_cmd *cmd, void *data, int recursive)
{
	int err = 0;
	unsigned long long size = cmd->size;
	struct dnet_node *n = st->n;
	unsigned long long tid = cmd->trans & ~DNET_TRANS_REPLY;
	struct dnet_io_attr *io = NULL;
#if 0
	struct dnet_indexes_request *indexes_request;
#endif
	struct timeval start, end;
	char time_str[64];
	struct tm io_tm;
	struct timeval io_tv;

#define DIFF(s, e) ((e).tv_sec - (s).tv_sec) * 1000000 + ((e).tv_usec - (s).tv_usec)

	long diff;
	int handled_in_cache = 0;

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
		case DNET_CMD_INDEXES_UPDATE:
		case DNET_CMD_INDEXES_INTERNAL:
		case DNET_CMD_INDEXES_FIND:
#if 0 // We don't want specially process this commands yet
			indexes_request = (struct dnet_indexes_request*)data;
			if (!(indexes_request->flags & DNET_IO_FLAGS_NOCACHE)) {
				err = dnet_cmd_cache_indexes(st, cmd, indexes_request);

				if (err != -ENOTSUP)
					return err;
			}
#endif

			err = dnet_process_indexes(st, cmd, data);
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
		case DNET_CMD_BULK_READ:
			err = n->cb->command_handler(st, n->cb->command_private, cmd, data);

			if (err == -ENOTSUP) {
				err = dnet_cmd_bulk_read(st, cmd, data);
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

			io_tv.tv_sec = io->timestamp.tsec;
			io_tv.tv_usec = io->timestamp.tnsec / 1000;

			if (cmd->cmd == DNET_CMD_READ) {
				dnet_log(n, DNET_LOG_INFO, "%s: %s io command, offset: %llu, size: %llu, ioflags: 0x%x, cflags: 0x%llx, "
						"node-flags: 0x%x\n",
						dnet_dump_id_str(io->id), dnet_cmd_string(cmd->cmd),
						(unsigned long long)io->offset, (unsigned long long)io->size,
						io->flags, (unsigned long long)cmd->flags,
						n->flags);
			} else {
				localtime_r((time_t *)&io_tv.tv_sec, &io_tm);
				strftime(time_str, sizeof(time_str), "%F %R:%S", &io_tm);

				dnet_log(n, DNET_LOG_INFO, "%s: %s io command, offset: %llu, size: %llu, ioflags: 0x%x, cflags: 0x%llx, "
						"node-flags: 0x%x, ts: %ld.%06ld '%s'\n",
						dnet_dump_id_str(io->id), dnet_cmd_string(cmd->cmd),
						(unsigned long long)io->offset, (unsigned long long)io->size,
						io->flags, (unsigned long long)cmd->flags,
						n->flags, io_tv.tv_sec, io_tv.tv_usec, time_str);
			}

			if (n->flags & DNET_CFG_NO_CSUM)
				io->flags |= DNET_IO_FLAGS_NOCSUM;

			if (!(io->flags & DNET_IO_FLAGS_NOCACHE)) {
				err = dnet_cmd_cache_io(st, cmd, io, data + sizeof(struct dnet_io_attr));

				if (err != -ENOTSUP) {
					handled_in_cache = 1;
					break;
				}
			}

			if ((io->flags & DNET_IO_FLAGS_COMPARE_AND_SWAP) && (cmd->cmd == DNET_CMD_WRITE)) {
				err = dnet_cas_local(n, &cmd->id, io->parent, DNET_ID_SIZE);

				if (err != 0 && err != -ENOENT)
					break;
			}

			dnet_convert_io_attr(io);
		default:
			if (cmd->cmd == DNET_CMD_LOOKUP && !(cmd->flags & DNET_FLAGS_NOCACHE)) {
				err = dnet_cmd_cache_lookup(st, cmd);

				if (err != -ENOTSUP) {
					handled_in_cache = 1;
					break;
				}
			}

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

	diff = DIFF(start, end);
	monitor_command_counter(n, cmd->cmd, tid, err, handled_in_cache, io ? io->size : 0, diff);
	dnet_log(n, DNET_LOG_INFO, "%s: %s: trans: %llu, cflags: 0x%llx, time: %ld usecs, err: %d.\n",
			dnet_dump_id(&cmd->id), dnet_cmd_string(cmd->cmd), tid,
			(unsigned long long)cmd->flags, diff, err);

	err = dnet_send_ack(st, cmd, err, recursive);

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

int dnet_send_read_data(void *state, struct dnet_cmd *cmd, struct dnet_io_attr *io, void *data,
		int fd, uint64_t offset, int on_exit)
{
	struct dnet_net_state *st = state;
	struct dnet_node *n = st->n;
	struct dnet_cmd *c;
	struct dnet_io_attr *rio;
	int hsize = sizeof(struct dnet_cmd) + sizeof(struct dnet_io_attr);
	int err;
	long csum_time, send_time, total_time;
	struct timeval start_tv, csum_tv, send_tv;

	/*
	 * A simple hack to forbid read reply sending.
	 * It is used in local stat - we do not want to send stat data
	 * back to parental client, instead server will wrap data into
	 * proper transaction reply next to this obscure packet.
	 */
	if (io->flags & DNET_IO_FLAGS_SKIP_SENDING)
		return 0;

	gettimeofday(&start_tv, NULL);

	c = malloc(hsize);
	if (!c) {
		err = -ENOMEM;
		goto err_out_exit;
	}

	memset(c, 0, hsize);

	rio = (struct dnet_io_attr *)(c + 1);

	dnet_setup_id(&c->id, cmd->id.group_id, io->id);

	c->flags = cmd->flags & ~(DNET_FLAGS_NEED_ACK);
	if (cmd->flags & DNET_FLAGS_NEED_ACK)
		c->flags |= DNET_FLAGS_MORE;

	c->size = sizeof(struct dnet_io_attr) + io->size;
	c->trans = cmd->trans | DNET_TRANS_REPLY;
	c->cmd = DNET_CMD_READ;

	memcpy(rio, io, sizeof(struct dnet_io_attr));

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

	gettimeofday(&csum_tv, NULL);

	if (data)
		err = dnet_send_data(st, c, hsize, data, rio->size);
	else
		err = dnet_send_fd(st, c, hsize, fd, offset, rio->size, on_exit);

	gettimeofday(&send_tv, NULL);

#define DIFF(s, e) ((e).tv_sec - (s).tv_sec) * 1000000 + ((e).tv_usec - (s).tv_usec)

	csum_time = DIFF(start_tv, csum_tv);
	send_time = DIFF(csum_tv, send_tv);
	total_time = DIFF(start_tv, send_tv);

	dnet_log_raw(n, DNET_LOG_INFO, "%s: %s: reply: cflags: 0x%llx, ioflags: 0x%llx, offset: %llu, size: %llu, csum-time: %ld, send-time: %ld, total-time: %ld usecs.\n",
			dnet_dump_id(&c->id), dnet_cmd_string(c->cmd),
			(unsigned long long)cmd->flags, (unsigned long long)io->flags,
			(unsigned long long)io->offset,	(unsigned long long)io->size,
			csum_time, send_time, total_time);


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

/*
 * @offset should be set not to offset within given record,
 * but offset within file descriptor
 */
int dnet_send_file_info_ts(void *state, struct dnet_cmd *cmd, int fd,
		uint64_t offset, int64_t size, struct dnet_time *timestamp)
{
	struct dnet_net_state *st = state;
	struct dnet_file_info *info;
	struct dnet_addr *a;
	size_t a_size = 0;
	int err, flen;
	char *file;

	/* Sanity */
	if (state == NULL || cmd == NULL || timestamp == NULL)
		return -EINVAL;
	if (size < 0 || fd < 0)
		return -EINVAL;

	flen = dnet_fd_readlink(fd, &file);
	if (flen < 0) {
		err = flen;
		goto err_out_exit;
	}

	a_size = sizeof(struct dnet_addr) + sizeof(struct dnet_file_info) + flen;
	a = calloc(1, a_size);
	if (a == NULL) {
		err = -ENOMEM;
		goto err_out_free_file;
	}

	info = (struct dnet_file_info *)(a + 1);

	dnet_fill_state_addr(state, a);
	dnet_convert_addr(a);

	info->offset = offset;
	info->size = size;
	info->mtime = *timestamp;
	info->flen = flen;
	memcpy(info + 1, file, flen);

	if (cmd->flags & DNET_FLAGS_CHECKSUM)
		dnet_checksum_fd(st->n, fd, info->offset,
				info->size, info->checksum, sizeof(info->checksum));

	dnet_convert_file_info(info);
	err = dnet_send_reply(state, cmd, a, a_size, 0);
	free(a);

err_out_free_file:
	free(file);
err_out_exit:
	return err;
}

int dnet_send_file_info_without_fd(void *state, struct dnet_cmd *cmd, const void *data, int64_t size)
{
	return dnet_send_file_info_ts_without_fd(state, cmd, data, size, NULL);
}

int dnet_send_file_info_ts_without_fd(void *state, struct dnet_cmd *cmd, const void *data, int64_t size, struct dnet_time *timestamp)
{
	struct dnet_net_state *st = state;
	struct dnet_file_info *info;
	struct dnet_addr *a;
	const size_t a_size = sizeof(struct dnet_addr) + sizeof(struct dnet_file_info) + 1;

	a = alloca(a_size);
	memset(a, 0, a_size);

	info = (struct dnet_file_info *)(a + 1);

	dnet_fill_state_addr(state, a);
	dnet_convert_addr(a);

	if (size >= 0)
		info->size = size;

	if (cmd->flags & DNET_FLAGS_CHECKSUM)
		dnet_checksum_data(st->n, data, size, info->checksum, sizeof(info->checksum));

	if (timestamp)
		info->mtime = *timestamp;

	dnet_convert_file_info(info);
	return dnet_send_reply(state, cmd, a, a_size, 0);
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
