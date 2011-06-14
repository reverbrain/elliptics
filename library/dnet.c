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

int dnet_checksum_data(struct dnet_node *n, void *csum, int *csize, void *data, uint64_t size)
{
	struct dnet_transform *t = &n->transform;

	return t->transform(t->priv, data, size, csum, (unsigned int *)csize, 0);
}

int dnet_transform(struct dnet_node *n, void *src, uint64_t size, struct dnet_id *id)
{
	int dsize = sizeof(id->id);

	return dnet_checksum_data(n, id->id, &dsize, src, size);
}

int dnet_stat_local(struct dnet_net_state *st, struct dnet_id *id)
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

static void dnet_send_idc_fill(struct dnet_net_state *st, void *buf, int size,
		struct dnet_id *id, uint64_t trans, unsigned int command, int reply, int direct, int more)
{
	struct dnet_node *n = st->n;
	struct dnet_cmd *cmd;
	struct dnet_attr *attr;
	struct dnet_raw_id *sid;
	struct dnet_addr_attr *addr;
	int i;

	memset(buf, 0, sizeof(*cmd) + sizeof(*attr) + sizeof(*addr));

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

static int dnet_cmd_reverse_lookup(struct dnet_net_state *st, struct dnet_cmd *cmd,
		struct dnet_attr *attr __unused, void *data __unused)
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

static int dnet_check_connection(struct dnet_node *n, struct dnet_addr_attr *a)
{
	int s;

	s = dnet_socket_create_addr(n, a->sock_type, a->proto, a->family,
			(struct sockaddr *)a->addr.addr, a->addr.addr_len, 0);
	if (s < 0)
		return s;

	dnet_sock_close(s);
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

	pthread_mutex_lock(&n->state_lock);
	list_del_init(&st->state_entry);
	list_del_init(&st->storage_state_entry);
	pthread_mutex_unlock(&n->state_lock);

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
	as->cmd_num = __DNET_CMD_MAX;

	dnet_log(n, DNET_LOG_DSA, "addr: %s, ptr: %p, orig: %p.\n", dnet_server_convert_dnet_addr(&as->addr), st, orig);
	dnet_log(n, DNET_LOG_DSA, "as->num = %d, as->cmd_num = %d\n", as->num, as->cmd_num);
	for (i=0; i<as->num; ++i) {
		as->count[i] = st->stat[i];
		dnet_log(n, DNET_LOG_DSA, "  cmd: %d, count: %llu, err: %llu\n",
			i, (unsigned long long)as->count[i].count, (unsigned long long)as->count[i].err);
	}

	dnet_convert_addr_stat(as, as->num);

	return dnet_send_reply(orig, cmd, &ca, as, sizeof(struct dnet_addr_stat) + __DNET_CMD_MAX * sizeof(struct dnet_stat_count), 1);
}

static int dnet_cmd_stat_count_global(struct dnet_net_state *orig, struct dnet_cmd *cmd,
		struct dnet_node *n, struct dnet_addr_stat *as)
{
	struct dnet_attr ca;
	struct dnet_stat st;
	int i;
	int err = 0;

	ca.cmd = DNET_CMD_STAT_COUNT;
	ca.size = 0;
	ca.flags = 0;

	memcpy(&as->addr, &n->addr, sizeof(struct dnet_addr));
	as->num = __DNET_CNTR_MAX;
	as->cmd_num = __DNET_CMD_MAX;

	dnet_log(n, DNET_LOG_DSA, "storage_stat = %p\n, command_private = %p\n",
			n->storage_stat, n->command_private);

	memcpy(as->count, n->counters, sizeof(struct dnet_stat_count) * __DNET_CNTR_MAX);

	if (n->storage_stat) {
		err = n->storage_stat(n->command_private, &st);
		dnet_log(n, DNET_LOG_DSA, "storage_stat returns %d\n", err);
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
	as->count[DNET_CNTR_NODE_FILES].count = kcdbcount(n->meta);

	dnet_log(n, DNET_LOG_DSA, "as->num = %d, as->cmd_num = %d\n", as->num, as->cmd_num);

	for (i=0; i<as->num && (n->log->log_mask & DNET_LOG_DSA); ++i) {
		dnet_log(n, DNET_LOG_DSA, "  counter: %d, count: %llu, err: %llu\n",
			i, (unsigned long long)as->count[i].count, (unsigned long long)as->count[i].err);
	}

	dnet_convert_addr_stat(as, as->num);

	return dnet_send_reply(orig, cmd, &ca, as, sizeof(struct dnet_addr_stat) + __DNET_CNTR_MAX * sizeof(struct dnet_stat_count), 1);
}

static int dnet_cmd_stat_count(struct dnet_net_state *orig, struct dnet_cmd *cmd,
		struct dnet_attr *attr, void *data __unused)
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

	if (attr->flags & DNET_ATTR_CNTR_GLOBAL) {
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

static char *dnet_cmd_strings[] = {
	[DNET_CMD_LOOKUP] = "LOOKUP",
	[DNET_CMD_REVERSE_LOOKUP] = "REVERSE_LOOKUP",
	[DNET_CMD_JOIN] = "JOIN",
	[DNET_CMD_WRITE] = "WRITE",
	[DNET_CMD_READ] = "READ",
	[DNET_CMD_LIST] = "CHECK",
	[DNET_CMD_EXEC] = "EXEC",
	[DNET_CMD_ROUTE_LIST] = "ROUTE_LIST",
	[DNET_CMD_STAT] = "STAT",
	[DNET_CMD_NOTIFY] = "NOTIFY",
	[DNET_CMD_DEL] = "REMOVE",
	[DNET_CMD_STAT_COUNT] = "STAT_COUNT",
	[DNET_CMD_UNKNOWN] = "UNKNOWN",
};

static char *dnet_counter_strings[] = {
	[DNET_CNTR_LA1] = "DNET_CNTR_LA1",
	[DNET_CNTR_LA5] = "DNET_CNTR_LA5",
	[DNET_CNTR_LA15] = "DNET_CNTR_LA15",
	[DNET_CNTR_BSIZE] = "DNET_CNTR_BSIZE",
	[DNET_CNTR_FRSIZE] = "DNET_CNTR_FRSIZE",
	[DNET_CNTR_BLOCKS] = "DNET_CNTR_BLOCKS",
	[DNET_CNTR_BFREE] = "DNET_CNTR_BFREE",
	[DNET_CNTR_BAVAIL] = "DNET_CNTR_BAVAIL",
	[DNET_CNTR_FILES] = "DNET_CNTR_FILES",
	[DNET_CNTR_FFREE] = "DNET_CNTR_FFREE",
	[DNET_CNTR_FAVAIL] = "DNET_CNTR_FAVAIL",
	[DNET_CNTR_FSID] = "DNET_CNTR_FSID",
	[DNET_CNTR_VM_ACTIVE] = "DNET_CNTR_VM_ACTIVE",
	[DNET_CNTR_VM_INACTIVE] = "DNET_CNTR_VM_INACTIVE",
	[DNET_CNTR_VM_TOTAL] = "DNET_CNTR_VM_TOTAL",
	[DNET_CNTR_VM_FREE] = "DNET_CNTR_VM_FREE",
	[DNET_CNTR_VM_CACHED] = "DNET_CNTR_VM_CACHED",
	[DNET_CNTR_VM_BUFFERS] = "DNET_CNTR_VM_BUFFERS",
	[DNET_CNTR_NODE_FILES] = "DNET_CNTR_NODE_FILES",
	[DNET_CNTR_NODE_LAST_MERGE] = "DNET_CNTR_NODE_LAST_MERGE",
	[DNET_CNTR_NODE_CHECK_COPY] = "DNET_CNTR_NODE_CHECK_COPY",
	[DNET_CNTR_DBR_NOREC] = "DNET_CNTR_DBR_NOREC",
	[DNET_CNTR_DBR_SYSTEM] = "DNET_CNTR_DBR_SYSTEM",
	[DNET_CNTR_DBR_ERROR] = "DNET_CNTR_DBR_ERROR",
	[DNET_CNTR_DBW_SYSTEM] = "DNET_CNTR_DBW_SYSTEM",
	[DNET_CNTR_DBW_ERROR] = "DNET_CNTR_DBW_ERROR",
	[DNET_CNTR_UNKNOWN] = "UNKNOWN",
};

char *dnet_cmd_string(int cmd)
{
	if (cmd == 0 || cmd >= __DNET_CMD_MAX)
		cmd = DNET_CMD_UNKNOWN;

	return dnet_cmd_strings[cmd];
}

static char *dnet_counter_string(int cntr, int cmd_num)
{
	if (cntr == 0 || cntr >= __DNET_CNTR_MAX)
		cntr = DNET_CNTR_UNKNOWN;

	if (cntr < cmd_num)
		return dnet_cmd_string(cntr);

	if (cntr >= cmd_num && cntr < (cmd_num * 2))
		return dnet_cmd_string(cntr - cmd_num);

	return dnet_counter_strings[cntr];
}

static int dnet_cmd_status(struct dnet_net_state *orig, struct dnet_cmd *cmd __unused, struct dnet_attr *attr)
{
	struct dnet_node *n = orig->n;

	if (attr->flags & DNET_STATUS_EXIT) {
		dnet_set_need_exit(n);
		return 0;
	}

	if (attr->flags & DNET_STATUS_RO) {
		n->ro = 1;
		return 0;
	}

	if (attr->flags & DNET_STATUS_RW) {
		n->ro = 0;
		return 0;
	}

	return -ENOTSUP;
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

	while (size) {
		struct dnet_attr *a = data;
		unsigned long long sz;

		gettimeofday(&start, NULL);

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

		switch (a->cmd) {
			case DNET_CMD_STATUS:
				err = dnet_cmd_status(st, cmd, a);
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
				err = dnet_cmd_stat_count(st, cmd, a, data);
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
				if (n->ro) {
					err = -EROFS;
				} else {
					if (a->flags & DNET_ATTR_BULK_CHECK)
						err = dnet_cmd_bulk_check(st, cmd, a, data);
					else
						err = dnet_db_list(st, cmd, a);
				}
				break;
			case DNET_CMD_READ:
			case DNET_CMD_WRITE:
			case DNET_CMD_DEL:
				if (n->ro && ((a->cmd == DNET_CMD_DEL) || (a->cmd == DNET_CMD_WRITE))) {
					err = -EROFS;
					break;
				}

				if (a->cmd == DNET_CMD_DEL) {
					err = dnet_db_del(n, cmd, a);
					dnet_log(n, DNET_LOG_DSA, "after dnet_db_del err=%d\n", err);
					if (err <= 0)
						break;

					/* if positive value returned we will delete data object */
				} else {
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

					if (io->flags & DNET_IO_FLAGS_META) {
						if (a->cmd == DNET_CMD_READ) {
							err = dnet_db_read(st, cmd, io);
						} else if (a->cmd == DNET_CMD_WRITE) {
							if (n->flags & DNET_CFG_NO_META) {
								err = 0;
								break;
							}

							err = dnet_db_write(n, cmd, io);
							if (!err && !(a->flags & DNET_ATTR_NOCSUM) && !(n->flags & DNET_CFG_NO_CSUM)) {
								struct dnet_id raw;
								dnet_setup_id(&raw, cmd->id.group_id, io->id);

								err = dnet_meta_update_checksum(n, &raw);
							}
						} else
							err = -EINVAL;
						break;
					}

					dnet_convert_io_attr(io);
				}
			default:
				if (a->cmd == DNET_CMD_READ) {
					if (!(a->flags & DNET_ATTR_NOCSUM) && !(n->flags & DNET_CFG_NO_CSUM)) {
						io = data;

						err = dnet_verify_checksum_io(n, io->id, NULL, NULL);
						if (err && (err != -ENODATA))
							break;
					}
				}

				if (n->flags & DNET_CFG_NO_CSUM)
					a->flags |= DNET_ATTR_NOCSUM;

				err = n->command_handler(st, n->command_private, cmd, a, data);
				if (err || (a->cmd != DNET_CMD_WRITE))
					break;

				if (!(n->flags & DNET_CFG_NO_META)) {
					err = dnet_db_write(n, cmd, data);
					if (err)
						break;
				}

#if 0
				dnet_update_notify(st, cmd, a, data);
#endif
				break;
		}



		dnet_stat_inc(st->stat, a->cmd, err);
		if (st->__join_state == DNET_JOIN)
			dnet_counter_inc(n, a->cmd, err);
		else
			dnet_counter_inc(n, a->cmd + __DNET_CMD_MAX, err);

		gettimeofday(&end, NULL);

		diff = (end.tv_sec - start.tv_sec) * 1000000 + (end.tv_usec - start.tv_usec);
		dnet_log(n, DNET_LOG_INFO, "%s: %s: trans: %llu, cflags: %x, aflags: %x, time: %ld usecs, err: %d.\n",
				dnet_dump_id(&cmd->id), dnet_cmd_string(a->cmd), tid,
				cmd->flags, a->flags, diff, err);
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

		dnet_log(n, DNET_LOG_DSA, "%s: ack trans: %llu, flags: %x, status: %d.\n",
				dnet_dump_id(&cmd->id), tid,
				ack.flags, err);

		dnet_convert_cmd(&ack);
		err = dnet_send(st, &ack, sizeof(struct dnet_cmd));
	}

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

static int dnet_add_received_state(struct dnet_node *n, struct dnet_addr_attr *a,
		int group_id, struct dnet_raw_id *ids, int id_num)
{
	int s, err = 0;
	struct dnet_net_state *nst;
	struct dnet_id raw;
	int join;

	dnet_setup_id(&raw, group_id, ids[0].id);

	nst = dnet_state_search_by_addr(n, &a->addr);
	if (nst) {
		err = -EEXIST;
		dnet_state_put(nst);
		goto err_out_exit;
	}

	s = dnet_socket_create_addr(n, a->sock_type, a->proto, a->family,
			(struct sockaddr *)&a->addr.addr, a->addr.addr_len, 0);
	if (s < 0) {
		err = s;
		goto err_out_exit;
	}

	join = DNET_WANT_RECONNECT;
	if (n->flags & DNET_CFG_JOIN_NETWORK)
		join = DNET_JOIN;

	nst = dnet_state_create(n, group_id, ids, id_num, &a->addr, s, &err, join, dnet_state_net_process);
	if (!nst)
		goto err_out_close;

	dnet_log(n, DNET_LOG_NOTICE, "%d: added received state %s.\n",
			group_id, dnet_state_dump_addr(nst));

	return 0;

err_out_close:
	dnet_sock_close(s);
err_out_exit:
	return err;
}

static int dnet_process_addr_attr(struct dnet_net_state *st, struct dnet_attr *attr, struct dnet_addr_attr *a, int group_id)
{
	struct dnet_node *n = st->n;
	struct dnet_raw_id *ids;
	int num, i, err;

	num = (attr->size - sizeof(struct dnet_addr_attr)) / sizeof(struct dnet_raw_id);
	if (!num)
		return -EINVAL;

	ids = (struct dnet_raw_id *)(a + 1);
	for (i=0; i<num; ++i)
		dnet_convert_raw_id(&ids[0]);

	err = dnet_add_received_state(n, a, group_id, ids, num);
	dnet_log(n, DNET_LOG_DSA, "%s: route list: %d entries: %d.\n", dnet_server_convert_dnet_addr(&a->addr), num, err);

	return err;
}

static int dnet_recv_route_list_complete(struct dnet_net_state *st, struct dnet_cmd *cmd,
		struct dnet_attr *attr, void *priv)
{
	struct dnet_wait *w = priv;
	struct dnet_addr_attr *a;
	struct dnet_node *n;
	long size;
	int err;

	if (is_trans_destroyed(st, cmd, attr)) {
		err = -EINVAL;
		if (cmd)
			err = cmd->status;

		w->status = err;
		dnet_wakeup(w, w->cond = 1);
		dnet_wait_put(w);
		goto err_out_exit;
	}

	n = st->n;

	err = cmd->status;
	if (!cmd->size || err || !attr)
		goto err_out_exit;

	size = cmd->size + sizeof(struct dnet_cmd);
	if (size < (signed)sizeof(struct dnet_addr_cmd)) {
		err = -EINVAL;
		goto err_out_exit;
	}

	a = (struct dnet_addr_attr *)(attr + 1);
	dnet_convert_addr_attr(a);

	err = dnet_process_addr_attr(st, attr, a, cmd->id.group_id);

err_out_exit:
	return err;
}

int dnet_recv_route_list(struct dnet_net_state *st)
{
	struct dnet_io_req req;
	struct dnet_node *n = st->n;
	struct dnet_trans *t;
	struct dnet_cmd *cmd;
	struct dnet_attr *a;
	struct dnet_wait *w;
	int err;

	w = dnet_wait_alloc(0);
	if (!w) {
		err = -ENOMEM;
		goto err_out_exit;
	}

	t = dnet_trans_alloc(n, sizeof(struct dnet_cmd) + sizeof(struct dnet_attr));
	if (!t) {
		err = -ENOMEM;
		goto err_out_wait_put;
	}

	t->complete = dnet_recv_route_list_complete;
	t->priv = w;

	cmd = (struct dnet_cmd *)(t + 1);
	a = (struct dnet_attr *)(cmd + 1);

	cmd->size = sizeof(struct dnet_attr);
	cmd->flags = DNET_FLAGS_NEED_ACK | DNET_FLAGS_DIRECT;
	cmd->status = 0;

	memcpy(&t->cmd, cmd, sizeof(struct dnet_cmd));

	a->cmd = t->command = DNET_CMD_ROUTE_LIST;
	a->size = 0;
	a->flags = 0;

	t->st = dnet_state_get(st);
	cmd->trans = t->rcv_trans = t->trans = atomic_inc(&n->trans);

	dnet_convert_cmd(cmd);
	dnet_convert_attr(a);

	dnet_log(n, DNET_LOG_DSA, "%s: list route request to %s.\n", dnet_dump_id(&cmd->id),
		dnet_server_convert_dnet_addr(&st->addr));

	memset(&req, 0, sizeof(req));
	req.st = st;
	req.header = cmd;
	req.hsize = sizeof(struct dnet_attr) + sizeof(struct dnet_cmd);

	dnet_wait_get(w);
	err = dnet_trans_send(t, &req);
	if (err)
		goto err_out_destroy;

	err = dnet_wait_event(w, w->cond != 1, &n->wait_ts);
	dnet_wait_put(w);

	return 0;

err_out_destroy:
	dnet_trans_put(t);
err_out_wait_put:
	dnet_wait_put(w);
err_out_exit:
	return err;
}

static struct dnet_net_state *dnet_add_state_socket(struct dnet_node *n, struct dnet_addr *addr, int s, int *errp, int join)
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

	st->write_s = st->read_s = s;
	st->n = n;

	err = dnet_send_nolock(st, buf, sizeof(struct dnet_cmd) + sizeof(struct dnet_attr));
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

	st = dnet_state_create(n, cmd->id.group_id, ids, num, addr, s, &err, join, dnet_state_net_process);
	if (!st) {
		/* socket is already closed */
		s = -1;
		goto err_out_free;
	}
	free(ids);

	st->__join_state = DNET_WANT_RECONNECT;

	return st;

err_out_free:
	free(ids);
err_out_exit:
	*errp = err;
	if (s >= 0)
		dnet_sock_close(s);
	return NULL;
}

int dnet_add_state(struct dnet_node *n, struct dnet_config *cfg)
{
	int s, err, join = DNET_WANT_RECONNECT;
	struct dnet_addr addr;
	struct dnet_net_state *st;

	memset(&addr, 0, sizeof(addr));

	addr.addr_len = sizeof(addr.addr);
	s = dnet_socket_create(n, cfg, &addr, 0);
	if (s < 0) {
		err = s;
		goto err_out_reconnect;
	}

	if (n->flags & DNET_CFG_JOIN_NETWORK)
		join = DNET_JOIN;

	/* will close socket on error */
	st = dnet_add_state_socket(n, &addr, s, &err, join);
	if (!st)
		goto err_out_reconnect;

	if (!(cfg->flags & DNET_CFG_NO_ROUTE_LIST))
		dnet_recv_route_list(st);

	return 0;

err_out_reconnect:
	if ((err == -EADDRINUSE) || (err == -ECONNREFUSED) || (err == -ECONNRESET) ||
			(err == -EINPROGRESS) || (err == -EAGAIN))
		dnet_add_reconnect_state(n, &addr, join);
	return err;
}

static int dnet_write_complete(struct dnet_net_state *st, struct dnet_cmd *cmd,
		struct dnet_attr *attr, void *priv)
{
	int err = -EINVAL;
	struct dnet_wait *w = priv;

	if (is_trans_destroyed(st, cmd, attr)) {
		dnet_wakeup(w, w->cond++);
		dnet_wait_put(w);
		return 0;
	}

	err = cmd->status;
	dnet_log(st->n, DNET_LOG_DSA, "%s: object write completed: trans: %llu, status: %d.\n",
		dnet_dump_id(&cmd->id), (unsigned long long)(cmd->trans & ~DNET_TRANS_REPLY),
		cmd->status);

	pthread_mutex_lock(&w->wait_lock);
	if (w->status < 0)
		w->status = err;
	pthread_mutex_unlock(&w->wait_lock);

	return 0;
}

static struct dnet_trans *dnet_io_trans_create(struct dnet_node *n, struct dnet_io_control *ctl, int *errp)
{
	struct dnet_io_req req;
	struct dnet_trans *t = NULL;
	struct dnet_attr *a;
	struct dnet_io_attr *io;
	struct dnet_cmd *cmd;
	uint64_t size = ctl->io.size;
	uint64_t tsize = sizeof(struct dnet_attr) +
			sizeof(struct dnet_io_attr) +
			sizeof(struct dnet_cmd);
	int err;

	if (ctl->cmd == DNET_CMD_READ)
		size = 0;

	if (ctl->asize && ctl->adata) {
		if (ctl->asize < sizeof(struct dnet_attr)) {
			dnet_log(n, DNET_LOG_ERROR, "%s: additional attribute size (%u) has to be "
					"larger or equal than %zu bytes (struct dnet_attr).\n",
					dnet_dump_id(&ctl->id), ctl->asize, sizeof(struct dnet_attr));
			err = -EINVAL;
			goto err_out_complete;
		}

		a = ctl->adata;

		if (a->size != ctl->asize - sizeof(struct dnet_attr)) {
			dnet_log(n, DNET_LOG_ERROR, "%s: additional attribute size (%llu) does not match "
					"structure's attribute size %llu.\n",
					dnet_dump_id(&ctl->id),
					(unsigned long long)ctl->asize - sizeof(struct dnet_attr),
					(unsigned long long)a->size);
			err = -EINVAL;
			goto err_out_complete;
		}

		tsize += ctl->asize;
	}

	if (ctl->fd < 0 && size < DNET_COPY_IO_SIZE)
		tsize += size;

	t = dnet_trans_alloc(n, tsize);
	if (!t) {
		err = -ENOMEM;
		goto err_out_complete;
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

	a->cmd = t->command = ctl->cmd;
	a->size = sizeof(struct dnet_io_attr) + size;
	a->flags = ctl->aflags;

	memcpy(io, &ctl->io, sizeof(struct dnet_io_attr));

	memcpy(&t->cmd, cmd, sizeof(struct dnet_cmd));

	t->st = dnet_state_get_first(n, &cmd->id);
	if (!t->st) {
		err = -ENOENT;
		dnet_log(n, DNET_LOG_ERROR, "%s: failed to find a state.\n", dnet_dump_id(&cmd->id));
		goto err_out_destroy;
	}

	cmd->trans = t->rcv_trans = t->trans = atomic_inc(&n->trans);
	dnet_convert_cmd(cmd);
	dnet_convert_attr(a);
	dnet_convert_io_attr(io);

	dnet_log(n, DNET_LOG_INFO, "%s: created trans: %llu, cmd: %s, size: %llu, offset: %llu, fd: %d, local_offset: %llu -> %s weight: %f, mrt: %ld.\n",
			dnet_dump_id(&ctl->id),
			(unsigned long long)t->trans,
			dnet_cmd_string(ctl->cmd),
			(unsigned long long)ctl->io.size, (unsigned long long)ctl->io.offset,
			ctl->fd,
			(unsigned long long)ctl->local_offset,
			dnet_server_convert_dnet_addr(&t->st->addr), t->st->weight, t->st->median_read_time);

	memset(&req, 0, sizeof(req));
	req.st = t->st;
	req.header = cmd;
	req.hsize = tsize;
	req.fd = ctl->fd;
	req.local_offset = ctl->local_offset;
	req.fsize = size;

	if ((ctl->fd == -1) && (size >= DNET_COPY_IO_SIZE)) {
		req.data = ctl->data;
		req.dsize = size;
	}

	err = dnet_trans_send(t, &req);
	if (err)
		goto err_out_destroy;

	return t;

err_out_complete:
	if (ctl->complete)
		ctl->complete(NULL, NULL, NULL, ctl->priv);
	*errp = err;
	return NULL;

err_out_destroy:
	dnet_trans_put(t);
	*errp = err;
	return NULL;
}

int dnet_trans_create_send_all(struct dnet_node *n, struct dnet_io_control *ctl)
{
	struct dnet_trans *t;
	int num = 0, i, err;

	pthread_mutex_lock(&n->group_lock);
	for (i=0; i<n->group_num; ++i) {
		ctl->id.group_id = n->groups[i];

		t = dnet_io_trans_create(n, ctl, &err);
		num++;
	}
	pthread_mutex_unlock(&n->group_lock);

	if (!num) {
		t = dnet_io_trans_create(n, ctl, &err);
		num++;
	}

	return num;
}

int dnet_write_object(struct dnet_node *n, struct dnet_io_control *ctl,
		void *remote, unsigned int remote_len, struct dnet_id *id)
{
	struct dnet_id raw;
	int num;

	memset(&raw, 0, sizeof(struct dnet_id));

	if (id) {
		memcpy(ctl->io.parent, id->id, DNET_ID_SIZE);
	} else {
		id = &raw;
		dnet_transform(n, remote, remote_len, &raw);
		memcpy(ctl->io.parent, raw.id, DNET_ID_SIZE);
	}

	memcpy(ctl->io.id, ctl->io.parent, DNET_ID_SIZE);
	dnet_log(n, DNET_LOG_DSA, "Remote = %.*s, Generated id: %s\n", remote_len, (char *)remote, dnet_dump_id(&raw));
	memcpy(&ctl->id, id, sizeof(struct dnet_id));

	num = dnet_trans_create_send_all(n, ctl);

	return num;
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

	w->status = -ENOENT;
	ctl.complete = dnet_write_complete;
	ctl.priv = w;

	ctl.cflags = DNET_FLAGS_NEED_ACK;
	ctl.cmd = DNET_CMD_WRITE;
	ctl.aflags = aflags;

	ctl.io.flags = ioflags;
	ctl.io.size = size;
	ctl.io.offset = offset;

	dnet_log(n, DNET_LOG_DSA, "data: %p, ctl.data: %p, local offset: %llu/%llu, remote offset: %llu, size: %llu/%llu\n",
			data, ctl.data, (unsigned long long)local_offset, (unsigned long long)off,
			(unsigned long long)offset,
			(unsigned long long)size, (unsigned long long)ALIGN(size, page_size));

	trans_num = dnet_write_object(n, &ctl, remote, remote_len, id);
	dnet_log(n, DNET_LOG_DSA, "%s: transactions sent: %d, err: %d.\n",
			dnet_dump_id(&ctl.id), trans_num, err);

	if (trans_num < 0)
		trans_num = 0;
	else
		dnet_create_write_metadata_strings(n, remote, remote_len, &ctl.id, NULL);

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

static int dnet_read_complete(struct dnet_net_state *st, struct dnet_cmd *cmd, struct dnet_attr *attr, void *priv)
{
	int fd, err;
	struct dnet_node *n;
	struct dnet_io_completion *c = priv;
	struct dnet_io_attr *io;
	void *data;

	if (is_trans_destroyed(st, cmd, attr)) {
		if (c->wait) {
			if (cmd && cmd->status)
				c->wait->cond = cmd->status;
			dnet_wakeup(c->wait, );
			dnet_wait_put(c->wait);
		}

		free(c);
		return 0;
	}

	n = st->n;

	if (cmd->status != 0 || cmd->size == 0 || !attr) {
		err = cmd->status;
		goto err_out_exit_no_log;
	}

	if (cmd->size <= sizeof(struct dnet_attr) + sizeof(struct dnet_io_attr)) {
		dnet_log(n, DNET_LOG_ERROR, "%s: read completion error: wrong size: cmd_size: %llu, must be more than %zu.\n",
				dnet_dump_id(&cmd->id), (unsigned long long)cmd->size,
				sizeof(struct dnet_attr) + sizeof(struct dnet_io_attr));
		err = -EINVAL;
		goto err_out_exit_no_log;
	}

	io = (struct dnet_io_attr *)(attr + 1);
	data = io + 1;

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
	close(fd);
err_out_exit:
	dnet_log(n, DNET_LOG_ERROR, "%s: read completed: file: '%s', offset: %llu, size: %llu, status: %d, err: %d.\n",
			dnet_dump_id(&cmd->id), c->file, (unsigned long long)io->offset,
			(unsigned long long)io->size, cmd->status, err);
err_out_exit_no_log:
	c->wait->cond = err;
	return err;
}

int dnet_read_object(struct dnet_node *n, struct dnet_io_control *ctl)
{
	int err;

	if (!dnet_io_trans_create(n, ctl, &err))
		return err;

	return 0;
}

int dnet_read_file_id(struct dnet_node *n, char *file, unsigned int len,
		int direct, uint64_t write_offset, uint64_t io_offset, uint64_t io_size,
		struct dnet_id *id, struct dnet_wait *w, int wait)
{
	struct dnet_io_control ctl;
	struct dnet_io_completion *c;
	int err, wait_init = ~0;

	memset(&ctl, 0, sizeof(struct dnet_io_control));

	ctl.io.size = io_size;
	ctl.io.offset = io_offset;

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

	sprintf(c->file, "%s", file);

	ctl.priv = c;

	w->cond = wait_init;
	err = dnet_read_object(n, &ctl);
	if (err)
		goto err_out_exit;

	if (wait) {
		err = dnet_wait_event(w, w->cond != wait_init, &n->wait_ts);
		if (err || (w->cond != 0 && w->cond != wait_init)) {
			char id_str[2*DNET_ID_SIZE + 1];
			if (!err)
				err = w->cond;
			dnet_log(n, DNET_LOG_ERROR, "%d:%s '%s' : failed to read data: %d\n",
				ctl.id.group_id, dnet_dump_id_len_raw(ctl.id.id, DNET_ID_SIZE, id_str),
				file, err);
			goto err_out_exit;
		}
	}

	return 0;

err_out_exit:
	return err;
}

static int dnet_read_file_raw(struct dnet_node *n, char *file, void *remote, unsigned int remote_len,
		struct dnet_id *id, int direct, uint64_t offset, uint64_t size)
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

	if (!size)
		size = ~0ULL;

	if (id) {
		err = dnet_read_file_id(n, file, len, direct, 0, offset, size, id, w, 1);
		if (err)
			goto err_out_put;
	} else {
		id = &raw;

		dnet_transform(n, remote, remote_len, id);
		pthread_mutex_lock(&n->group_lock);
		for (i=0; i<n->group_num; ++i) {
			id->group_id = n->groups[i];

			err = dnet_read_file_id(n, file, len, direct, 0, offset, size, id, w, 1);
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

	dnet_wait_put(w);

	return 0;

err_out_put:
	dnet_wait_put(w);
err_out_exit:
	return err;
}

int dnet_read_file(struct dnet_node *n, char *file, void *remote, unsigned int remote_len,
		struct dnet_id *id, uint64_t offset, uint64_t size)
{
	return dnet_read_file_raw(n, file, remote, remote_len, id, 0, offset, size);
}

int dnet_read_file_direct(struct dnet_node *n, char *file, void *remote, unsigned int remote_len,
		struct dnet_id *id, uint64_t offset, uint64_t size)
{
	return dnet_read_file_raw(n, file, remote, remote_len, id, 1, offset, size);
}

struct dnet_read_meta_control
{
	struct dnet_wait		*wait;
	struct dnet_meta_container	*mc;
};

static int dnet_read_meta_complete(struct dnet_net_state *st, struct dnet_cmd *cmd, struct dnet_attr *attr, void *priv)
{
	int err;
	struct dnet_node *n;
	struct dnet_read_meta_control *c = priv;
	struct dnet_io_attr *io;
	void *data;

	if (is_trans_destroyed(st, cmd, attr)) {
		if (c->wait) {
			if (cmd && cmd->status)
				c->wait->cond = cmd->status;
			dnet_wakeup(c->wait, );
			dnet_wait_put(c->wait);
		}

		free(c);
		return 0;
	}

	n = st->n;

	if (cmd->status != 0 || cmd->size == 0 || !attr) {
		err = cmd->status;
		goto err_out_exit_no_log;
	}

	if (cmd->size <= sizeof(struct dnet_attr) + sizeof(struct dnet_io_attr)) {
		dnet_log(n, DNET_LOG_ERROR, "%s: read completion error: wrong size: cmd_size: %llu, must be more than %zu.\n",
				dnet_dump_id(&cmd->id), (unsigned long long)cmd->size,
				sizeof(struct dnet_attr) + sizeof(struct dnet_io_attr));
		err = -EINVAL;
		goto err_out_exit_no_log;
	}

	io = (struct dnet_io_attr *)(attr + 1);
	data = io + 1;

	dnet_convert_io_attr(io);

	c->mc->data = malloc(io->size);
	if (!c->mc->data) {
		dnet_log(n, DNET_LOG_ERROR, "%s: failed to allocate meta data\n",
				dnet_dump_id(&cmd->id));
		err = -ENOMEM;
		goto err_out_exit;
	}
	c->mc->size = io->size;
	memcpy(c->mc->data, data, io->size);

	dnet_log(n, DNET_LOG_NOTICE, "%s: meta read completed: size: %llu, status: %d.\n",
			dnet_dump_id(&cmd->id), (unsigned long long)io->size, cmd->status);

	return cmd->status;

err_out_exit:
	dnet_log(n, DNET_LOG_ERROR, "%s: read failed: size: %llu, status: %d, err: %d.\n",
			dnet_dump_id(&cmd->id), (unsigned long long)io->size, cmd->status, err);
err_out_exit_no_log:
	c->wait->cond = err;
	return err;
}

int dnet_read_meta_id(struct dnet_node *n, struct dnet_meta_container *mc, struct dnet_id *id, struct dnet_wait *w, int wait)
{
	struct dnet_io_control ctl;
	struct dnet_read_meta_control *c;
	int err, wait_init = ~0;

	memset(&ctl, 0, sizeof(struct dnet_io_control));

	ctl.io.flags = DNET_IO_FLAGS_META;
	memcpy(ctl.io.parent, id->id, DNET_ID_SIZE);
	memcpy(ctl.io.id, id->id, DNET_ID_SIZE);

	memcpy(&ctl.id, id, sizeof(struct dnet_id));

	ctl.fd = -1;
	ctl.complete = dnet_read_meta_complete;
	ctl.cmd = DNET_CMD_READ;
	ctl.cflags = DNET_FLAGS_NEED_ACK;

	c = malloc(sizeof(struct dnet_read_meta_control));
	if (!c) {
		dnet_log(n, DNET_LOG_ERROR, "%s: failed to allocate read meta control structure\n",
				dnet_dump_id(&ctl.id));
		err = -ENOMEM;
		goto err_out_exit;
	}

	memset(c, 0, sizeof(struct dnet_read_meta_control));

	c->wait = dnet_wait_get(w);
	c->mc = mc;

	ctl.priv = c;

	w->cond = wait_init;
	err = dnet_read_object(n, &ctl);
	if (err)
		goto err_out_exit;

	if (wait) {
		err = dnet_wait_event(w, w->cond != wait_init, &n->wait_ts);
		if (err || (w->cond != 0 && w->cond != wait_init)) {
			char id_str[2*DNET_ID_SIZE + 1];
			if (!err)
				err = w->cond;
			dnet_log(n, DNET_LOG_ERROR, "%d:%s failed to read meta: %d\n",
				ctl.id.group_id, dnet_dump_id_len_raw(ctl.id.id, DNET_ID_SIZE, id_str), err);
			goto err_out_exit;
		}
	}

	return 0;

err_out_exit:
	return err;
}

int dnet_read_meta(struct dnet_node *n, struct dnet_meta_container *mc, void *remote, unsigned int remote_len, struct dnet_id *id)
{
	int err, error = 0, i;
	struct dnet_wait *w;
	struct dnet_id raw;

	if (!mc)
		return -EINVAL;

	w = dnet_wait_alloc(~0);
	if (!w) {
		err = -ENOMEM;
		dnet_log(n, DNET_LOG_ERROR, "Failed to allocate read waiting.\n");
		goto err_out_exit;
	}

	if (id) {
		err = dnet_read_meta_id(n, mc, id, w, 1);
		if (err)
			goto err_out_put;
	} else {
		id = &raw;

		dnet_transform(n, remote, remote_len, id);
		pthread_mutex_lock(&n->group_lock);
		for (i=0; i<n->group_num; ++i) {
			id->group_id = n->groups[i];

			err = dnet_read_meta_id(n, mc, id, w, 1);
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

	dnet_wait_put(w);

	return 0;

err_out_put:
	dnet_wait_put(w);
err_out_exit:
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
	free(w);
}

static int dnet_send_cmd_complete(struct dnet_net_state *st, struct dnet_cmd *cmd,
			struct dnet_attr *attr, void *priv)
{
	int err;
	struct dnet_wait *w = priv;

	if (is_trans_destroyed(st, cmd, attr)) {
		dnet_wakeup(w, w->cond++);
		dnet_wait_put(w);
		return 0;
	}

	err = cmd->status;
	w->status = err;
	return err;
}

static int dnet_send_cmd_single(struct dnet_net_state *st, struct dnet_wait *w, char *command)
{
	struct dnet_trans_control ctl;

	memset(&ctl, 0, sizeof(struct dnet_trans_control));

	dnet_setup_id(&ctl.id, st->idc->group->group_id, st->idc->ids[0].raw.id);
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
		struct timeval start, end;
		long diff;

		gettimeofday(&start, NULL);
		pthread_mutex_lock(&n->state_lock);
		list_for_each_entry(g, &n->group_list, group_entry) {
			list_for_each_entry(st, &g->state_list, state_entry) {
				if (st == n->st)
					continue;

				dnet_wait_get(w);

				dnet_send_cmd_single(st, w, cmd);
				num++;
			}
		}
		pthread_mutex_unlock(&n->state_lock);

		gettimeofday(&end, NULL);
		diff = (end.tv_sec - start.tv_sec) * 1000000 + end.tv_usec - start.tv_usec;
		dnet_log(n, DNET_LOG_ERROR, "%s: cmd %s: %ld usecs.\n", dnet_dump_id(id), cmd, diff);
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
	LIST_HEAD(list);
	int s, err, join;

	if (list_empty(&n->reconnect_list))
		return 0;

	pthread_mutex_lock(&n->reconnect_lock);
	list_for_each_entry_safe(ast, tmp, &n->reconnect_list, reconnect_entry) {
		list_move(&ast->reconnect_entry, &list);
	}
	pthread_mutex_unlock(&n->reconnect_lock);

	list_for_each_entry_safe(ast, tmp, &list, reconnect_entry) {
		s = dnet_socket_create_addr(n, n->sock_type, n->proto, n->family,
				(struct sockaddr *)ast->addr.addr, ast->addr.addr_len, 0);
		if (s < 0)
			goto out_add;

		join = DNET_WANT_RECONNECT;
		if (ast->__join_state == DNET_JOIN)
			join = DNET_JOIN;

		st = dnet_add_state_socket(n, &ast->addr, s, &err, join);
		if (st)
			goto out_remove;

		dnet_sock_close(s);

		if (err == -EEXIST || err == -EINVAL)
			goto out_remove;

out_add:
		dnet_add_reconnect_state(n, &ast->addr, ast->__join_state);
out_remove:
		list_del(&ast->reconnect_entry);
		free(ast);
	}

	return 0;
}

int dnet_lookup_object(struct dnet_node *n, struct dnet_id *id, unsigned int aflags,
	int (* complete)(struct dnet_net_state *, struct dnet_cmd *, struct dnet_attr *, void *),
	void *priv)
{
	struct dnet_io_req req;
	struct dnet_trans *t;
	struct dnet_attr *a;
	struct dnet_cmd *cmd;
	int err;

	t = dnet_trans_alloc(n, sizeof(struct dnet_attr) +
			sizeof(struct dnet_cmd));
	if (!t) {
		err = -ENOMEM;
		goto err_out_complete;
	}
	t->complete = complete;
	t->priv = priv;

	cmd = (struct dnet_cmd *)(t + 1);
	a = (struct dnet_attr *)(cmd + 1);

	memcpy(&cmd->id, id, sizeof(struct dnet_id));
	cmd->size = sizeof(struct dnet_attr);
	cmd->status = 0;
	cmd->flags = DNET_FLAGS_NEED_ACK;

	memcpy(&t->cmd, cmd, sizeof(struct dnet_cmd));

	a->cmd = t->command = DNET_CMD_LOOKUP;
	a->size = 0;
	a->flags = aflags;

	t->st = dnet_state_get_first(n, &cmd->id);
	if (!t->st) {
		err = -ENOENT;
		dnet_log(n, DNET_LOG_ERROR, "%s: failed to find a state.\n", dnet_dump_id(&cmd->id));
		goto err_out_destroy;
	}

	cmd->trans = t->rcv_trans = t->trans = atomic_inc(&n->trans);
	dnet_convert_cmd(cmd);
	dnet_convert_attr(a);

	dnet_log(n, DNET_LOG_NOTICE, "%s: lookup to %s.\n", dnet_dump_id(id), dnet_server_convert_dnet_addr(&t->st->addr));

	memset(&req, 0, sizeof(req));
	req.st = t->st;
	req.header = cmd;
	req.hsize = sizeof(struct dnet_attr) + sizeof(struct dnet_cmd);

	err = dnet_trans_send(t, &req);
	if (err)
		goto err_out_destroy;

	return 0;

err_out_complete:
	if (complete)
		complete(NULL, NULL, NULL, priv);
	return err;

err_out_destroy:
	dnet_trans_put(t);
	return err;
}

int dnet_lookup_complete(struct dnet_net_state *st, struct dnet_cmd *cmd,
		struct dnet_attr *attr, void *priv)
{
	struct dnet_wait *w = priv;
	struct dnet_node *n = NULL;
	struct dnet_addr_attr *a;
	struct dnet_net_state *other;
	char addr_str[128] = "no-address";
	int err;

	if (is_trans_destroyed(st, cmd, attr)) {
		dnet_wakeup(w, w->cond = 1);
		dnet_wait_put(w);
		return 0;
	}
	n = st->n;

	err = cmd->status;
	if (err || !cmd->size || !attr)
		goto err_out_exit;

	if (attr->size < sizeof(struct dnet_addr_attr)) {
		dnet_log(st->n, DNET_LOG_ERROR, "%s: wrong dnet_addr attribute size %llu, must be at least %zu.\n",
				dnet_dump_id(&cmd->id), (unsigned long long)attr->size, sizeof(struct dnet_addr_attr));
		err = -EINVAL;
		goto err_out_exit;
	}

	a = (struct dnet_addr_attr *)(attr + 1);

	dnet_convert_addr_attr(a);
	dnet_server_convert_dnet_addr_raw(&a->addr, addr_str, sizeof(addr_str));

	if (attr->size > sizeof(struct dnet_addr_attr) + sizeof(struct dnet_file_info)) {
		struct dnet_file_info *info = (struct dnet_file_info *)(a + 1);

		dnet_convert_file_info(info);

		dnet_log_raw(n, DNET_LOG_NOTICE, "%s: lookup object: %s: "
				"offset: %llu, size: %llu, mode: %llo, path: %s\n",
			dnet_dump_id(&cmd->id), addr_str,
			(unsigned long long)info->offset, (unsigned long long)info->size,
			(unsigned long long)info->mode, (char *)(info + 1));
	} else {
		dnet_log_raw(n, DNET_LOG_INFO, "%s: lookup object: %s\n",
			dnet_dump_id(&cmd->id), addr_str);
	}


	other = dnet_state_search_by_addr(n, &a->addr);
	if (other) {
		dnet_state_put(other);
	} else {
		dnet_recv_route_list(st);
	}

	return 0;

err_out_exit:
	if (n)
		dnet_log(n, DNET_LOG_ERROR, "%s: lookup completion status: %d, err: %d.\n", dnet_dump_id(&cmd->id), cmd->status, err);

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

	if (is_trans_destroyed(state, cmd, attr)) {
		dnet_wakeup(w, w->cond++);
		dnet_wait_put(w);
		return 0;
	}

	if (!attr)
		return cmd->status;

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

		dnet_log(state->n, DNET_LOG_DSA, "as->num = %d, as->cmd_num = %d\n", as->num, as->cmd_num);

		for (i=0; i<as->num; ++i) {
			if (as->num > as->cmd_num) {
				if (i == 0)
					dnet_log(state->n, DNET_LOG_INFO, "%s: %s: Storage commands\n",
						dnet_dump_id(&cmd->id), dnet_state_dump_addr(state));
				if (i == as->cmd_num)
					dnet_log(state->n, DNET_LOG_INFO, "%s: %s: Proxy commands\n",
						dnet_dump_id(&cmd->id), dnet_state_dump_addr(state));
				if (i == as->cmd_num * 2)
					dnet_log(state->n, DNET_LOG_INFO, "%s: %s: Counters\n",
						dnet_dump_id(&cmd->id), dnet_state_dump_addr(state));
			}	
			dnet_log(state->n, DNET_LOG_INFO, "%s: %s:    cmd: %s, count: %llu, err: %llu\n",
					dnet_dump_id(&cmd->id), dnet_state_dump_addr(state),
					dnet_counter_string(i, as->cmd_num),
					(unsigned long long)as->count[i].count, (unsigned long long)as->count[i].err);
		}
	}

	return err;
}

static int dnet_request_cmd_single(struct dnet_node *n, struct dnet_net_state *st, struct dnet_trans_control *ctl)
{
	if (st)
		return dnet_trans_alloc_send_state(st, ctl);
	else
		return dnet_trans_alloc_send(n, ctl);
}

int dnet_request_stat(struct dnet_node *n, struct dnet_id *id,
	unsigned int cmd, unsigned int aflags,
	int (* complete)(struct dnet_net_state *state,
			struct dnet_cmd *cmd,
			struct dnet_attr *attr,
			void *priv),
	void *priv)
{
	struct dnet_trans_control ctl;
	struct dnet_wait *w = NULL;
	int err, num = 0;
	struct timeval start, end;
	long diff;

	gettimeofday(&start, NULL);

	if (!complete) {
		w = dnet_wait_alloc(0);
		if (!w) {
			err = -ENOMEM;
			goto err_out_exit;
		}

		complete = dnet_stat_complete;
		priv = w;
	}

	memset(&ctl, 0, sizeof(struct dnet_trans_control));

	ctl.cmd = cmd;
	ctl.complete = complete;
	ctl.priv = priv;
	ctl.cflags = DNET_FLAGS_NEED_ACK;
	ctl.aflags = aflags;

	if (id) {
		if (w)
			dnet_wait_get(w);

		memcpy(&ctl.id, id, sizeof(struct dnet_id));

		err = dnet_request_cmd_single(n, NULL, &ctl);
		num = 1;
	} else {
		struct dnet_net_state *st;
		struct dnet_group *g;


		pthread_mutex_lock(&n->state_lock);
		list_for_each_entry(g, &n->group_list, group_entry) {
			list_for_each_entry(st, &g->state_list, state_entry) {
				if (st == n->st)
					continue;

				if (w)
					dnet_wait_get(w);

				dnet_setup_id(&ctl.id, st->idc->group->group_id, st->idc->ids[0].raw.id);
				dnet_request_cmd_single(n, st, &ctl);
				num++;
			}
		}
		pthread_mutex_unlock(&n->state_lock);
	}

	if (!w) {
		gettimeofday(&end, NULL);
		diff = (end.tv_sec - start.tv_sec) * 1000000 + end.tv_usec - start.tv_usec;
		dnet_log(n, DNET_LOG_NOTICE, "stat cmd: %s: %ld usecs, num: %d.\n", dnet_cmd_string(cmd), diff, num);

		return num;
	}

	err = dnet_wait_event(w, w->cond == num, &n->wait_ts);

	gettimeofday(&end, NULL);
	diff = (end.tv_sec - start.tv_sec) * 1000000 + end.tv_usec - start.tv_usec;
	dnet_log(n, DNET_LOG_NOTICE, "stat cmd: %s: %ld usecs, wait_error: %d, num: %d.\n", dnet_cmd_string(cmd), diff, err, num);

	if (err)
		goto err_out_put;

	dnet_wait_put(w);

	return num;

err_out_put:
	dnet_wait_put(w);
err_out_exit:
	return err;
}

struct dnet_request_cmd_priv {
	struct dnet_wait	*w;

	int 			(* complete)(struct dnet_net_state *state,
					struct dnet_cmd *cmd,
					struct dnet_attr *attr,
					void *priv);
	void			*priv;
};

static int dnet_request_cmd_complete(struct dnet_net_state *state,
		struct dnet_cmd *cmd, struct dnet_attr *attr, void *priv)
{
	struct dnet_request_cmd_priv *p = priv;
	int err = p->complete(state, cmd, attr, p->priv);

	if (is_trans_destroyed(state, cmd, attr)) {
		struct dnet_wait *w = p->w;

		dnet_wakeup(w, w->cond++);
		if (atomic_read(&w->refcnt) == 1)
			free(p);
		dnet_wait_put(w);
	}

	return err;
}

int dnet_request_cmd(struct dnet_node *n, struct dnet_trans_control *ctl)
{
	int err, num = 0;
	struct dnet_request_cmd_priv *p;
	struct dnet_wait *w;
	struct dnet_net_state *st;
	struct dnet_group *g;
	struct timeval start, end;
	long diff;

	gettimeofday(&start, NULL);

	p = malloc(sizeof(*p));
	if (!p) {
		err = -ENOMEM;
		goto err_out_exit;
	}

	w = dnet_wait_alloc(0);
	if (!w) {
		err = -ENOMEM;
		goto err_out_free;
	}

	p->w = w;
	p->complete = ctl->complete;
	p->priv = ctl->priv;

	ctl->complete = dnet_request_cmd_complete;
	ctl->priv = p;

	pthread_mutex_lock(&n->state_lock);
	list_for_each_entry(g, &n->group_list, group_entry) {
		list_for_each_entry(st, &g->state_list, state_entry) {
			if (st == n->st)
				continue;

			dnet_wait_get(w);

			ctl->id.group_id = g->group_id;

			if (!(ctl->cflags & DNET_FLAGS_DIRECT))
				dnet_setup_id(&ctl->id, st->idc->group->group_id, st->idc->ids[0].raw.id);
			dnet_request_cmd_single(n, st, ctl);
			num++;
		}
	}
	pthread_mutex_unlock(&n->state_lock);

	err = dnet_wait_event(w, w->cond == num, &n->wait_ts);

	gettimeofday(&end, NULL);
	diff = (end.tv_sec - start.tv_sec) * 1000000 + end.tv_usec - start.tv_usec;
	dnet_log(n, DNET_LOG_NOTICE, "request cmd: %s: %ld usecs, wait_error: %d, num: %d.\n", dnet_cmd_string(ctl->cmd), diff, err, num);

	if (!err)
		err = num;

	if (atomic_read(&w->refcnt) == 1)
		free(p);
	dnet_wait_put(w);

	return err;

err_out_free:
	free(p);
err_out_exit:
	return err;
}

static int dnet_update_status_complete(struct dnet_net_state *state,
		struct dnet_cmd *cmd, struct dnet_attr *attr, void *priv)
{
	struct dnet_wait *w = priv;

	if (is_trans_destroyed(state, cmd, attr)) {
		dnet_wakeup(w, w->cond++);
		dnet_wait_put(w);
	}

	return 0;
}

int dnet_update_status(struct dnet_node *n, struct dnet_addr *addr, struct dnet_id *id, unsigned int status)
{
	int err;
	struct dnet_wait *w;
	struct dnet_trans_control ctl;

	if (!id && !addr) {
		err = -EINVAL;
		goto err_out_exit;
	}

	memset(&ctl, 0, sizeof(ctl));

	if (id) {
		memcpy(&ctl.id, id, sizeof(struct dnet_id));
	} else {
		struct dnet_net_state *st;

		st = dnet_state_search_by_addr(n, addr);
		if (!st) {
			err = -ENOENT;
			goto err_out_exit;
		}

		dnet_setup_id(&ctl.id, st->idc->group->group_id, st->idc->ids[0].raw.id);
		dnet_state_put(st);
	}

	w = dnet_wait_alloc(0);
	if (!w) {
		err = -ENOMEM;
		goto err_out_exit;
	}

	ctl.complete = dnet_update_status_complete;
	ctl.priv = w;
	ctl.cmd = DNET_CMD_STATUS;
	ctl.cflags = DNET_FLAGS_NEED_ACK;
	ctl.aflags = status;

	dnet_wait_get(w);
	dnet_request_cmd_single(n, NULL, &ctl);

	err = dnet_wait_event(w, w->cond == 1, &n->wait_ts);
	dnet_wait_put(w);

err_out_exit:
	return err;
}

static int dnet_remove_object_raw(struct dnet_node *n,
	unsigned char *parent __unused, struct dnet_id *id,
	int (* complete)(struct dnet_net_state *state,
			struct dnet_cmd *cmd,
			struct dnet_attr *attr,
			void *priv),
	void *priv,
	int direct)
{
	struct dnet_trans_control ctl;

	memset(&ctl, 0, sizeof(struct dnet_trans_control));

	memcpy(&ctl.id, id, sizeof(struct dnet_id));

	ctl.cmd = DNET_CMD_DEL;
	ctl.complete = complete;
	ctl.priv = priv;
	ctl.cflags = DNET_FLAGS_NEED_ACK;
	if (direct)
		ctl.cflags |= DNET_FLAGS_DIRECT;

	return dnet_trans_alloc_send(n, &ctl);
}

static int dnet_remove_complete(struct dnet_net_state *state,
			struct dnet_cmd *cmd,
			struct dnet_attr *attr,
			void *priv)
{
	struct dnet_wait *w = priv;

	if (is_trans_destroyed(state, cmd, attr)) {
		dnet_wakeup(w, w->cond++);
		dnet_wait_put(w);
		return 0;
	}

	if (cmd->status)
		w->status = cmd->status;
	return cmd->status;
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
	ctl.aflags = DNET_ATTR_DELETE_HISTORY;

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

	if (!st)
		return NULL;
	return st->n;
}

struct dnet_read_data_completion {
	struct dnet_wait		*w;
	void				*data;
	uint64_t			size;
	atomic_t			refcnt;
};

static int dnet_read_data_complete(struct dnet_net_state *st, struct dnet_cmd *cmd, struct dnet_attr *attr, void *priv)
{
	struct dnet_read_data_completion *c = priv;
	struct dnet_wait *w = c->w;
	int last = (!cmd || !(cmd->flags & DNET_FLAGS_MORE));
	int err = -EINVAL;

	if (is_trans_destroyed(st, cmd, attr)) {
		dnet_wakeup(w, w->cond++);
		dnet_wait_put(w);
		if (atomic_dec_and_test(&c->refcnt))
			free(c);
		return err;
	}

	err = cmd->status;
	if (err)
		w->status = err;

	if (!attr)
		return err;

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

err_out_exit:
	dnet_log(st->n, DNET_LOG_NOTICE, "%s: object read completed: trans: %llu, status: %d, last: %d, err: %d.\n",
		dnet_dump_id(&cmd->id), (unsigned long long)(cmd->trans & ~DNET_TRANS_REPLY),
		cmd->status, last, err);

	return err;
}

void *dnet_read_data_wait(struct dnet_node *n, struct dnet_id *id, uint64_t *size, uint64_t offset, uint32_t aflags, uint32_t ioflags)
{
	struct dnet_io_control ctl;
	ssize_t err;
	struct dnet_wait *w;
	struct dnet_read_data_completion *c;
	void *data = NULL;

	w = dnet_wait_alloc(0);
	if (!w) {
		err = -ENOMEM;
		goto err_out_exit;
	}

	c = malloc(sizeof(*c));
	if (!c) {
		err = -ENOMEM;
		goto err_out_put;
	}

	c->w = w;
	c->size = 0;
	c->data = NULL;
	/* one for completion callback, another for this function */
	atomic_init(&c->refcnt, 2);

	memset(&ctl, 0, sizeof(struct dnet_io_control));

	ctl.fd = -1;

	ctl.priv = c;
	ctl.complete = dnet_read_data_complete;

	ctl.cmd = DNET_CMD_READ;
	ctl.cflags = DNET_FLAGS_NEED_ACK;

	ctl.aflags = aflags;

	memcpy(ctl.io.id, id->id, DNET_ID_SIZE);
	memcpy(ctl.io.parent, id->id, DNET_ID_SIZE);

	memcpy(&ctl.id, id, sizeof(struct dnet_id));

	ctl.io.flags = ioflags;
	ctl.io.size = *size;
	ctl.io.offset = offset;

	dnet_wait_get(w);
	err = dnet_read_object(n, &ctl);
	if (err)
		goto err_out_put_complete;

	err = dnet_wait_event(w, w->cond, &n->wait_ts);
	if (err || w->status) {
		char id_str[2*DNET_ID_SIZE + 1];
		if (!err)
			err = w->status;
		dnet_log(n, DNET_LOG_ERROR, "%d:%s : failed to read data: %zd\n",
			ctl.id.group_id, dnet_dump_id_len_raw(ctl.id.id, DNET_ID_SIZE, id_str), err);
		goto err_out_put_complete;
	}
	*size = c->size;
	data = c->data;

err_out_put_complete:
	if (atomic_dec_and_test(&c->refcnt))
		free(c);
err_out_put:
	dnet_wait_put(w);
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

	w->status = -ENOENT;
	ctl.priv = w;
	ctl.complete = dnet_write_complete;

	ctl.cmd = DNET_CMD_WRITE;
	ctl.cflags = DNET_FLAGS_NEED_ACK;

	ctl.io.flags = ioflags;
	ctl.io.size = size;
	ctl.io.offset = offset;

	atomic_set(&w->refcnt, INT_MAX);
	trans_num = dnet_write_object(n, &ctl, remote, len, id);
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
		dnet_log(n, DNET_LOG_NOTICE, "%s: failed to wait for IO write completion, err: %d, status: %d.\n",
				dnet_dump_id(&ctl.id), err, w->status);
	}

	if (err || !trans_num) {
		if (!err)
			err = -EINVAL;
		dnet_log(n, DNET_LOG_ERROR, "Failed to write data into the storage, err: %d, trans_num: %d.\n", err, trans_num);
		goto err_out_put;
	}

	if (trans_num)
		dnet_log(n, DNET_LOG_NOTICE, "Successfully wrote %llu bytes into the storage (%d groups).\n",
				(unsigned long long)size, trans_num);
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

/*static int dnet_compare_by_param_reverse(const void *id1, const void *id2)
{
	const struct dnet_id_param *l2 = id1;
	const struct dnet_id_param *l1 = id2;

	if (l1->param == l2->param)
		return l1->param_reserved - l2->param_reserved;

	return l1->param - l2->param;
}*/

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

	free(c);

err_out_exit:
	return err;
}

/*
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
	struct dnet_wait *w = m->w;
	struct dnet_node *n;
	struct dnet_io_attr *io;
	struct dnet_history_entry *he;
	int err = 0, last, i, num;

	if (is_trans_destroyed(state, cmd, attr)) {
		dnet_wakeup(w, m->wait_num++);
		dnet_wait_put(w);
		return 0;
	}

	n = state->n;
	err = cmd->status;

	last = !(cmd->flags & DNET_FLAGS_MORE);
	dnet_log_raw(n, DNET_LOG_DSA, "%s: read multiple status: %d, last: %d.\n",
			dnet_dump_id(&cmd->id), cmd->status, last);

	if (err || !attr)
		goto err_out_exit;

	if (attr->size) {
		if (cmd->size <= sizeof(struct dnet_attr) + sizeof(struct dnet_io_attr)) {
			dnet_log_raw(n, DNET_LOG_ERROR, "%s: read multiple completion error: wrong size: cmd_size: %llu, must be more than %zu.\n",
					dnet_dump_id(&cmd->id), (unsigned long long)cmd->size,
					sizeof(struct dnet_attr) + sizeof(struct dnet_io_attr));
			err = -EINVAL;
			goto err_out_exit;
		}

		if (!attr) {
			dnet_log_raw(n, DNET_LOG_ERROR, "%s: read multiple: no attributes but command size is not null.\n", dnet_dump_id(&cmd->id));
			err = -EINVAL;
			goto err_out_exit;
		}

		io = (struct dnet_io_attr *)(attr + 1);
		he = (struct dnet_history_entry *)(io + 1);

		dnet_convert_attr(attr);
		dnet_convert_io_attr(io);

		if (io->size < sizeof(struct dnet_history_entry)) {
			dnet_log_raw(n, DNET_LOG_ERROR, "%s: read multiple: invalid io size %llu.\n", dnet_dump_id(&cmd->id), (unsigned long long)io->size);
			err = -EINVAL;
			goto err_out_exit;
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

err_out_exit:
	if (err)
		m->wait_error = err;
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
*/

int dnet_lookup_addr(struct dnet_node *n, void *remote, int len, struct dnet_id *id, int group_id, char *dst, int dlen)
{
	struct dnet_id raw;
	struct dnet_net_state *st;
	int err = -ENOENT;

	if (!id) {
		dnet_transform(n, remote, len, &raw);
		id = &raw;
	}
	id->group_id = group_id;

	st = dnet_state_get_first(n, id);
	if (!st)
		goto err_out_exit;

	dnet_server_convert_dnet_addr_raw(dnet_state_addr(st), dst, dlen);
	dnet_state_put(st);
	err = 0;

err_out_exit:
	return err;
}

struct dnet_weight {
	int			weight;
	int			group_id;
};

static int dnet_weight_compare(const void *v1, const void *v2)
{
	const struct dnet_weight *w1 = v1;
	const struct dnet_weight *w2 = v2;

	return w1->weight - w2->weight;
}

int dnet_mix_states(struct dnet_node *n, struct dnet_id *id, int **groupsp)
{
	struct dnet_weight *weights;
	int *groups;
	int group_num, i, num;
	struct dnet_net_state *st;

	pthread_mutex_lock(&n->group_lock);
	group_num = n->group_num;

	weights = alloca(n->group_num * sizeof(*weights));
	groups = malloc(n->group_num * sizeof(*groups));
	if (groups)
		memcpy(groups, n->groups, n->group_num * sizeof(*groups));
	pthread_mutex_unlock(&n->group_lock);

	if (!groups) {
		*groupsp = NULL;
		return -ENOMEM;
	}

	if (!(n->flags & DNET_CFG_MIX_STATES)) {
		*groupsp = groups;
		return group_num;
	}

	memset(weights, 0, group_num * sizeof(*weights));

	for (i=0, num=0; i<group_num; ++i) {
		id->group_id = groups[i];

		st = dnet_state_get_first(n, id);
		if (st) {
			weights[num].weight = (int)st->weight;
			weights[num].group_id = id->group_id;

			dnet_state_put(st);

			num++;
		}
	}

	group_num = num;
	if (group_num) {
		int have_equal = 0;

		qsort(weights, group_num, sizeof(struct dnet_weight), dnet_weight_compare);

		/* if we have equal weights, add random salt to them and rerun */
		for (i=1; i<group_num; ++i) {
			if (weights[i].weight == weights[i - 1].weight) {
				float r = rand();

				r /= (float)RAND_MAX;

				weights[i].weight += (r > 0.5) ? +r : -r;
				weights[i - 1].weight -= (r > 0.5) ? +r : -r;

				have_equal = 1;
			}
		}

		if (have_equal)
			qsort(weights, group_num, sizeof(struct dnet_weight), dnet_weight_compare);

		/* weights are sorted in ascending order */
		for (i=0; i<group_num; ++i) {
			groups[i] = weights[num - i - 1].group_id;
		}
	}

	dnet_node_set_groups(n, groups, group_num);

	*groupsp = groups;
	return group_num;
}

void dnet_fill_addr_attr(struct dnet_node *n, struct dnet_addr_attr *attr)
{
	memcpy(&attr->addr, &n->addr, sizeof(struct dnet_addr));

	attr->sock_type = n->sock_type;
	attr->family = n->family;
	attr->proto = n->proto;
}

int dnet_checksum_fd(struct dnet_node *n, void *csum, int *csize, int fd, uint64_t offset, uint64_t size)
{
	void *data, *csum_data;
	uint64_t off, sz;
	long page_size = sysconf(_SC_PAGE_SIZE);
	int err;

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


	off = offset & ~(page_size - 1);
	sz = ALIGN(size + offset - off, page_size);

	data = mmap(NULL, sz, PROT_READ, MAP_SHARED, fd, off);
	if (data == MAP_FAILED) {
		err = -errno;
		dnet_log_err(n, "Failed to map to be csummed file: size: %llu, use: %llu, local offset: %llu, use: %llu",
				(unsigned long long)size, (unsigned long long)sz,
				(unsigned long long)offset, (unsigned long long)off);
		goto err_out_exit;
	}

	csum_data = data + offset - off;

	err = dnet_checksum_data(n, csum, csize, csum_data, size);

	munmap(data, sz);

err_out_exit:
	return err;
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

int dnet_verify_checksum_io(struct dnet_node *n, unsigned char *id, unsigned char *result, int *res_len)
{
	struct dnet_id raw;
	int csize = DNET_CSUM_SIZE;
	unsigned char csum[csize];
	struct dnet_meta_checksum mc;
	char str[csize*2+1];
	int err;

	dnet_setup_id(&raw, n->id.group_id, id);

	err = dnet_meta_read_checksum(n, &raw, &mc);
	if (err) {
		err = -ENODATA;
		goto err_out_exit;
	}

	err = n->checksum(n, n->command_private, &raw, csum, &csize);
	if (err)
		goto err_out_exit;

	dnet_log(n, DNET_LOG_DSA, "%s: calculated csum: %s\n", dnet_dump_id(&raw), dnet_dump_id_len_raw(csum, csize, str));
	dnet_log(n, DNET_LOG_DSA, "%s: stored     csum: %s\n", dnet_dump_id(&raw), dnet_dump_id_len_raw(mc.checksum, csize, str));

	if (memcmp(mc.checksum, csum, csize)) {
		err = -EBADFD;
		goto err_out_exit;
	}

	if (result) {
		if (*res_len > csize)
			*res_len = csize;

		memcpy(result, csum, *res_len);
	}

err_out_exit:
	if (err)
		dnet_log(n, DNET_LOG_ERROR, "%s: CSUM: verification: failed: %d: %s\n", dnet_dump_id(&raw), err, strerror(-err));
	return err;
}
