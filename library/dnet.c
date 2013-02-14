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


int dnet_transform(struct dnet_node *n, const void *src, uint64_t size, struct dnet_id *id)
{
	struct dnet_transform *t = &n->transform;
	unsigned int csize = sizeof(id->id);

	return t->transform(t->priv, src, size, id->id, &csize, 0);
}

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

static void dnet_send_idc_fill(struct dnet_net_state *st, void *buf, int size,
		struct dnet_id *id, uint64_t trans, unsigned int command, int reply, int direct, int more)
{
	struct dnet_cmd *cmd;
	struct dnet_raw_id *sid;
	struct dnet_addr *addr;
	int i;

	memset(buf, 0, sizeof(*cmd) + sizeof(*addr));

	cmd = buf;
	addr = (struct dnet_addr *)(cmd + 1);
	sid = (struct dnet_raw_id *)(addr + 1);

	memcpy(&cmd->id, id, sizeof(struct dnet_id));
	cmd->size = size - sizeof(struct dnet_cmd);
	cmd->trans = trans;

	cmd->flags = DNET_FLAGS_NOLOCK;
	if (more)
		cmd->flags |= DNET_FLAGS_MORE;
	if (direct)
		cmd->flags |= DNET_FLAGS_DIRECT;
	if (reply)
		cmd->trans |= DNET_TRANS_REPLY;

	cmd->cmd = command;

	memcpy(&addr->addr, &st->addr, sizeof(struct dnet_addr));

	for (i=0; i<st->idc->id_num; ++i) {
		memcpy(&sid[i], &st->idc->ids[i].raw, sizeof(struct dnet_raw_id));
		dnet_convert_raw_id(&sid[i]);
	}

	dnet_convert_addr_cmd(buf);
}

static int dnet_send_idc(struct dnet_net_state *orig, struct dnet_net_state *send, struct dnet_id *id, uint64_t trans,
		unsigned int command, int reply, int direct, int more)
{
	struct dnet_node *n = orig->n;
	int size = sizeof(struct dnet_addr_cmd) + orig->idc->id_num * sizeof(struct dnet_raw_id);
	void *buf;
	int err;
	struct timeval start, end;
	long diff;

	gettimeofday(&start, NULL);

	buf = malloc(size);
	if (!buf) {
		err = -ENOMEM;
		goto err_out_exit;
	}
	memset(buf, 0, sizeof(struct dnet_addr_cmd));

	dnet_send_idc_fill(orig, buf, size, id, trans, command, reply, direct, more);

	gettimeofday(&end, NULL);
	diff = (end.tv_sec - start.tv_sec) * 1000000 + end.tv_usec - start.tv_usec;
	dnet_log(n, DNET_LOG_INFO, "%s: sending address %s: %ld\n", dnet_dump_id(id), dnet_state_dump_addr(orig), diff);

	err = dnet_send(send, buf, size);

	free(buf);

err_out_exit:
	return err;
}

static int dnet_cmd_reverse_lookup(struct dnet_net_state *st, struct dnet_cmd *cmd, void *data __unused)
{
	struct dnet_node *n = st->n;
	struct dnet_net_state *base;
	int err = -ENOENT;

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
	struct dnet_addr *addr = data;
	struct dnet_raw_id *ids;
	int num, i, err;

	dnet_convert_addr(addr);

	dnet_log(n, DNET_LOG_DEBUG, "%s: accepted joining client (%s), requesting statistics.\n",
			dnet_dump_id(&cmd->id), dnet_server_convert_dnet_addr(addr));
	err = dnet_check_connection(n, addr);
	if (err) {
		dnet_log(n, DNET_LOG_ERROR, "%s: failed to request statistics from joining client (%s), dropping connection.\n",
				dnet_dump_id(&cmd->id), dnet_server_convert_dnet_addr(addr));
		return err;
	}

	num = (cmd->size - sizeof(struct dnet_addr)) / sizeof(struct dnet_raw_id);
	ids = (struct dnet_raw_id *)(addr + 1);
	for (i = 0; i < num; ++i)
		dnet_convert_raw_id(&ids[0]);

	pthread_mutex_lock(&n->state_lock);
	list_del_init(&st->state_entry);
	list_del_init(&st->storage_state_entry);
	pthread_mutex_unlock(&n->state_lock);

	memcpy(&st->addr, addr, sizeof(struct dnet_addr));
	err = dnet_idc_create(st, cmd->id.group_id, ids, num);

	dnet_log(n, DNET_LOG_INFO, "%s: accepted join request from state %s: %d.\n", dnet_dump_id(&cmd->id),
		dnet_server_convert_dnet_addr(addr), err);

	return err;
}

static int dnet_cmd_route_list(struct dnet_net_state *orig, struct dnet_cmd *cmd)
{
	struct dnet_node *n = orig->n;
	struct dnet_net_state *st;
	struct dnet_group *g;
	void *buf, *orig_buf;
	size_t size = 0, send_size = 0, sz;
	int err;

	pthread_mutex_lock(&n->state_lock);
	list_for_each_entry(g, &n->group_list, group_entry) {
		list_for_each_entry(st, &g->state_list, state_entry) {
			if (!memcmp(&st->addr, &orig->addr, sizeof(struct dnet_addr)))
				continue;

			size += st->idc->id_num * sizeof(struct dnet_raw_id) + sizeof(struct dnet_addr_cmd);
		}
	}
	pthread_mutex_unlock(&n->state_lock);

	orig_buf = buf = malloc(size);
	if (!buf) {
		err = -ENOMEM;
		goto err_out_exit;
	}

	pthread_mutex_lock(&n->state_lock);
	list_for_each_entry(g, &n->group_list, group_entry) {
		list_for_each_entry(st, &g->state_list, state_entry) {
			if (!memcmp(&st->addr, &orig->addr, sizeof(struct dnet_addr)))
				continue;

			sz = st->idc->id_num * sizeof(struct dnet_raw_id) + sizeof(struct dnet_addr_cmd);
			if (sz <= size) {
				cmd->id.group_id = g->group_id;
				dnet_send_idc_fill(st, buf, sz, &cmd->id, cmd->trans, DNET_CMD_ROUTE_LIST, 1, 0, 1);

				size -= sz;
				buf += sz;

				send_size += sz;
			}
		}
	}
	pthread_mutex_unlock(&n->state_lock);

	err = dnet_send(orig, orig_buf, send_size);
	if (err)
		goto err_out_free;

err_out_free:
	free(orig_buf);
err_out_exit:
	return err;
}

static int dnet_cmd_exec(struct dnet_net_state *st, struct dnet_cmd *cmd, void *data)
{
	struct dnet_node *n = st->n;
	struct sph *e = data;
	int err = -ENOTSUP;

	data += sizeof(struct sph);

	dnet_convert_sph(e);

	if (e->event_size + e->data_size + e->binary_size + sizeof(struct sph) != cmd->size) {
		err = -E2BIG;
		dnet_log(n, DNET_LOG_ERROR, "%s: invalid size: event-size %d, data-size %llu, binary-size %llu must be: %llu\n",
				dnet_dump_id(&cmd->id),
				e->event_size,
				(unsigned long long)e->data_size,
				(unsigned long long)e->binary_size,
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

					if (io->flags & DNET_IO_FLAGS_CACHE_ONLY)
						break;

					/*
					 * We successfully read data from cache, do not sink to disk for it
					 */
					if ((cmd->cmd == DNET_CMD_READ) && !err)
						break;
				}
			}

			if (io->flags & DNET_IO_FLAGS_COMPARE_AND_SWAP) {
				char csum[DNET_ID_SIZE];
				int csize = DNET_ID_SIZE;

				err = n->cb->checksum(n, n->cb->command_private, &cmd->id, csum, &csize);
				if (err < 0) {
					dnet_log(n, DNET_LOG_ERROR, "%s: cas: checksum operation failed\n", dnet_dump_id(&cmd->id));
					err = 0;
				} else {
					if (memcmp(csum, io->parent, DNET_ID_SIZE)) {
						dnet_log(n, DNET_LOG_ERROR, "%s: cas: checksum mismatch\n", dnet_dump_id(&cmd->id));
						err = -EINVAL;
						break;
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
		err = -ENOENT;
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
		int fd, uint64_t offset, int close_on_exit)
{
	struct dnet_net_state *st = state;
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

	dnet_log_raw(st->n, DNET_LOG_NOTICE, "%s: %s: reply: offset: %llu, size: %llu.\n",
			dnet_dump_id(&c->id), dnet_cmd_string(c->cmd),
			(unsigned long long)io->offset,	(unsigned long long)io->size);

	/* only populate data which has zero offset and from column 0 */
	if ((io->flags & DNET_IO_FLAGS_CACHE) && !io->offset && (io->type == 0)) {
		err = dnet_populate_cache(st->n, c, rio, data, fd, offset, io->size);
	}

	dnet_convert_cmd(c);
	dnet_convert_io_attr(rio);

	if (data)
		err = dnet_send_data(st, c, hsize, data, io->size);
	else
		err = dnet_send_fd(st, c, hsize, fd, offset, io->size, close_on_exit);

	free(c);

err_out_exit:
	return err;
}

void dnet_fill_state_addr(void *state, struct dnet_addr *addr)
{
	struct dnet_net_state *st = state;

	memcpy(addr, &st->addr, sizeof(struct dnet_addr));
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

	info->ctime = info->mtime = mu->tm;
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
		dnet_log(n, DNET_LOG_ERROR, "%s: EBLOB: %s: info-stat: %d: %s.\n",
				dnet_dump_id(&cmd->id), file, err, strerror(-err));
		goto err_out_free;
	}

	dnet_info_from_stat(info, &st);
	/* this is not valid data from raw blob file stat */
	info->ctime.tsec = info->mtime.tsec = 0;

	if (cmd->flags & DNET_ATTR_META_TIMES) {
		err = dnet_read_file_info(n, &cmd->id, info);
		if ((err == -ENOENT) && (cmd->flags & DNET_ATTR_META_TIMES))
			err = 0;
		if (err)
			goto err_out_free;
	}

	if (size >= 0)
		info->size = size;
	if (offset)
		info->offset = offset;

	if (info->size == 0) {
		err = -ENOENT;
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

int dnet_checksum_data(struct dnet_node *n, void *csum, int *csize, const void *data, uint64_t size)
{
	struct dnet_transform *t = &n->transform;

	return t->transform(t->priv, data, size, csum, (unsigned int *)csize, 0);
}

int dnet_checksum_file(struct dnet_node *n, void *csum, int *csize, const char *file, uint64_t offset, uint64_t size)
{
	int fd, err;

	err = open(file, O_RDONLY);

	if (err < 0) {
		err = -errno;
		dnet_log_err(n, "failed to open to be csummed file '%s'", file);
		goto err_out_exit;
	}
	fd = err;
	err = dnet_checksum_fd(n, csum, csize, fd, offset, size);
	close(fd);

err_out_exit:
	return err;
}

int dnet_checksum_fd(struct dnet_node *n, void *csum, int *csize, int fd, uint64_t offset, uint64_t size)
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

	err = dnet_checksum_data(n, csum, csize, m.data, size);
	dnet_data_unmap(&m);

err_out_exit:
	return err;
}
