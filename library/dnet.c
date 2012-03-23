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
	cmd->flags = DNET_FLAGS_NOLOCK;

	attr->size = cmd->size - sizeof(struct dnet_attr);
	attr->cmd = DNET_CMD_READ;

	io->size = attr->size - sizeof(struct dnet_io_attr);
	io->offset = 0;
	io->flags = DNET_IO_FLAGS_SKIP_SENDING;

	memcpy(io->parent, id->id, DNET_ID_SIZE);
	memcpy(io->id, id->id, DNET_ID_SIZE);

	dnet_convert_io_attr(io);

	err = n->cb->command_handler(st, n->cb->command_private, cmd, attr, io);
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

	cmd->flags = DNET_FLAGS_NOLOCK;
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

static int dnet_cmd_exec_shell(struct dnet_node *n, struct dnet_cmd *cmd, struct dnet_exec *e)
{
	pid_t pid;
	int err;
	char *command;

	command = malloc(e->script_size + 1);
	if (!command) {
		err = -ENOMEM;
		goto err_out_exit;
	}

	memcpy(command, e->data, e->script_size);
	command[e->script_size] = '\0';

	pid = fork();
	if (pid < 0) {
		err = -errno;
		dnet_log_err(n, "%s: failed to fork a child process", dnet_dump_id(&cmd->id));
		goto err_out_free;
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
			goto err_out_exit;
		}

		if (WIFEXITED(status))
			err = WEXITSTATUS(status);
		else if (WIFSIGNALED(status))
			err = -EPIPE;
	}

err_out_free:
	free(command);
err_out_exit:
	return err;
}

static int dnet_cmd_exec(struct dnet_net_state *st, struct dnet_cmd *cmd,
		struct dnet_attr *attr, void *data)
{
	struct dnet_node *n = st->n;
	struct dnet_exec *e = data;
	int err = -ENOTSUP;

	if (!attr->size)
		return 0;

	dnet_convert_exec(e);

	dnet_log(n, DNET_LOG_NOTICE, "%s: type: %d, command: '%.*s'.\n",
			dnet_dump_id(&cmd->id), e->type, (int)e->script_size + (int)e->name_size, e->data);

	if (e->script_size + e->name_size + e->binary_size + sizeof(struct dnet_exec) != attr->size) {
		err = -E2BIG;
		dnet_log(n, DNET_LOG_ERROR, "%s: invalid: name size %llu, script size %llu, binary size %llu must be: %llu\n",
				dnet_dump_id(&cmd->id),
				(unsigned long long)e->name_size,
				(unsigned long long)e->script_size,
				(unsigned long long)e->binary_size,
				(unsigned long long)attr->size);
		goto err_out_exit;
	}


	switch (e->type) {
		case DNET_EXEC_SHELL:
			err = dnet_cmd_exec_shell(n, cmd, e);
			break;
		case DNET_EXEC_PYTHON_SCRIPT_NAME:
			err = dnet_cmd_exec_python_script(st, cmd, attr, e);
			break;
		case DNET_EXEC_PYTHON:
			err = dnet_cmd_exec_python(st, cmd, attr, e);
			break;
	}

err_out_exit:
	return err;
}

static int dnet_cmd_stat_count_single(struct dnet_net_state *orig, struct dnet_cmd *cmd, struct dnet_net_state *st, struct dnet_addr_stat *as)
{
	struct dnet_attr ca;
	int i;

	ca.cmd = DNET_CMD_STAT_COUNT;
	ca.size = 0;
	ca.flags = 0;

	memcpy(&as->addr, &st->addr, sizeof(struct dnet_addr));
	as->num = __DNET_CMD_MAX;
	as->cmd_num = __DNET_CMD_MAX;

	for (i=0; i<as->num; ++i) {
		as->count[i] = st->stat[i];
	}

	dnet_convert_addr_stat(as, as->num);

	return dnet_send_reply(orig, cmd, &ca, as, sizeof(struct dnet_addr_stat) + __DNET_CMD_MAX * sizeof(struct dnet_stat_count), 1);
}

static int dnet_cmd_stat_count_global(struct dnet_net_state *orig, struct dnet_cmd *cmd,
		struct dnet_node *n, struct dnet_addr_stat *as)
{
	struct dnet_attr ca;
	struct dnet_stat st;
	int err = 0;

	ca.cmd = DNET_CMD_STAT_COUNT;
	ca.size = 0;
	ca.flags = 0;

	memcpy(&as->addr, &n->addr, sizeof(struct dnet_addr));
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
	[DNET_CMD_STATUS] = "STATUS",
	[DNET_CMD_READ_RANGE] = "READ_RANGE",
	[DNET_CMD_DEL_RANGE] = "DEL_RANGE",
	[DNET_CMD_AUTH] = "AUTH",
	[DNET_CMD_BULK_READ] = "BULK_READ",
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
	if (cmd <= 0 || cmd >= __DNET_CMD_MAX)
		cmd = DNET_CMD_UNKNOWN;

	return dnet_cmd_strings[cmd];
}

char *dnet_counter_string(int cntr, int cmd_num)
{
	if (cntr <= 0 || cntr >= __DNET_CNTR_MAX)
		cntr = DNET_CNTR_UNKNOWN;

	if (cntr < cmd_num)
		return dnet_cmd_string(cntr);

	if (cntr >= cmd_num && cntr < (cmd_num * 2))
		return dnet_cmd_string(cntr - cmd_num);

	return dnet_counter_strings[cntr];
}

static int dnet_cmd_status(struct dnet_net_state *orig, struct dnet_cmd *cmd __unused, struct dnet_attr *attr, void *data)
{
	struct dnet_node *n = orig->n;
	struct dnet_node_status *st = data;
	struct dnet_attr ca;
	
	dnet_convert_node_status(st);

	if (attr->flags & DNET_ATTR_STATUS_CHANGE) {
		dnet_log(n, DNET_LOG_INFO, "%s: status-change: nflags: %x->%x, log_mask: %x->%x, "
				"status_flags: EXIT: %d, RO: %d\n",
				dnet_dump_id(&cmd->id), n->flags, st->nflags, n->log->log_mask, st->log_mask,
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

		if (st->log_mask != ~0U)
			n->log->log_mask = st->log_mask;
	}

	st->nflags = n->flags;
	st->log_mask = n->log->log_mask;
	st->status_flags = 0;

	if (n->need_exit)
		st->status_flags |= DNET_STATUS_EXIT;

	if (n->ro)
		st->status_flags |= DNET_STATUS_RO;

	dnet_convert_node_status(st);

	ca.cmd = DNET_CMD_STATUS;
	ca.size = 0;
	ca.flags = 0;

	return dnet_send_reply(orig, cmd, &ca, st, sizeof(struct dnet_node_status), 1);
}

static int dnet_cmd_auth(struct dnet_net_state *orig, struct dnet_cmd *cmd __unused, struct dnet_attr *attr, void *data)
{
	struct dnet_node *n = orig->n;
	struct dnet_auth *a = data;
	int err = 0;

	if (attr->size != sizeof(struct dnet_auth)) {
		err = -EINVAL;
		goto err_out_exit;
	}

	dnet_convert_auth(a);
	if (memcmp(n->cookie, a->cookie, DNET_AUTH_COOKIE_SIZE)) {
		err = -EPERM;
		dnet_log(n, DNET_LOG_ERROR, "%s: auth cookies do not match\n", dnet_state_dump_addr(orig));
	} else {
		dnet_log(n, DNET_LOG_INFO, "%s: authentification succeeded\n", dnet_state_dump_addr(orig));
	}

err_out_exit:
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
			case DNET_CMD_AUTH:
				err = dnet_cmd_auth(st, cmd, a, data);
				break;
			case DNET_CMD_STATUS:
				err = dnet_cmd_status(st, cmd, a, data);
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

				io = NULL;
				if ((a->cmd == DNET_CMD_READ) || (a->cmd == DNET_CMD_WRITE)) {
					if (size < sizeof(struct dnet_io_attr)) {
						dnet_log(st->n, DNET_LOG_ERROR, "%s: invalid size: cmd: %u, rest_size: %llu\n",
							dnet_dump_id(&cmd->id), a->cmd, size);
						err = -EINVAL;
						break;
					}
					io = data;
					dnet_convert_io_attr(io);

					if (io->flags & DNET_IO_FLAGS_NOCSUM)
						a->flags |= DNET_ATTR_NOCSUM;

					if ((n->flags & DNET_CFG_NO_CSUM) || (a->flags & DNET_ATTR_NOCSUM)) {
						io->flags |= DNET_IO_FLAGS_NOCSUM;
						a->flags |= DNET_ATTR_NOCSUM;
					}
				}

				if (a->cmd == DNET_CMD_DEL || io->flags & DNET_IO_FLAGS_META) {
					err = dnet_process_meta(st, cmd, a, data);
					break;
				}

				dnet_convert_io_attr(io);
			default:
				if (n->flags & DNET_CFG_NO_CSUM)
					a->flags |= DNET_ATTR_NOCSUM;

				/* Remove DNET_FLAGS_NEED_ACK flags for WRITE command 
				   to eliminate double reply packets 
				   (the first one with dnet_file_info structure,
				   the second to destroy transaction on client side) */
				if (a->cmd == DNET_CMD_WRITE) {
					cmd->flags &= ~DNET_FLAGS_NEED_ACK;
				}
				err = n->cb->command_handler(st, n->cb->command_private, cmd, a, data);

				/* If there was error in WRITE command - send empty reply
				   to notify client with error code and destroy transaction */
				if (err && (a->cmd == DNET_CMD_WRITE)) {
					cmd->flags |= DNET_FLAGS_NEED_ACK;
				}
				if (err || (a->cmd != DNET_CMD_WRITE))
					break;
#if 0
				if (!(n->flags & DNET_CFG_NO_META)) {
					err = dnet_db_write(n, cmd, data);
					if (err)
						break;
				}
#endif
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
	cmd->flags = DNET_FLAGS_NEED_ACK | DNET_FLAGS_DIRECT | DNET_FLAGS_NOLOCK;
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

	err = dnet_wait_event(w, w->cond != 0, &n->wait_ts);
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
	int err, num, i, size;
	struct dnet_raw_id *ids;

	memset(buf, 0, sizeof(buf));

	cmd = (struct dnet_cmd *)(buf);
	a = (struct dnet_attr *)(cmd + 1);

	cmd->flags = DNET_FLAGS_DIRECT | DNET_FLAGS_NOLOCK;
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

struct dnet_write_completion {
	void			*reply;
	int			size;
	struct dnet_wait	*wait;
};

static void dnet_write_complete_free(struct dnet_write_completion *wc)
{
	if (atomic_dec_and_test(&wc->wait->refcnt)) {
		dnet_wait_destroy(wc->wait);
		free(wc->reply);
		free(wc);
	}
}

static int dnet_write_complete(struct dnet_net_state *st, struct dnet_cmd *cmd,
		struct dnet_attr *attr, void *priv)
{
	int err = -EINVAL;
	struct dnet_write_completion *wc = priv;
	struct dnet_wait *w = wc->wait;

	if (!st || !cmd) {
		dnet_wakeup(w, w->cond++);
		dnet_write_complete_free(wc);
		return 0;
	}

	err = cmd->status;
	if (!err && st && attr && (attr->size > sizeof(struct dnet_addr_attr) + sizeof(struct dnet_file_info))) {
		int old_size = wc->size;
		void *data;

		wc->size += cmd->size + sizeof(struct dnet_cmd) + sizeof(struct dnet_addr);
		wc->reply = realloc(wc->reply, wc->size);
		if (!wc->reply) {
			err = -ENOMEM;
			goto err_out_exit;
		}

		data = wc->reply + old_size;

		memcpy(data, &st->addr, sizeof(struct dnet_addr));
		memcpy(data + sizeof(struct dnet_addr), cmd, sizeof(struct dnet_cmd));
		memcpy(data + sizeof(struct dnet_addr) + sizeof(struct dnet_cmd), attr, cmd->size);
	}

err_out_exit:
	pthread_mutex_lock(&w->wait_lock);
	if (w->status < 0)
		w->status = err;
	pthread_mutex_unlock(&w->wait_lock);

	if (is_trans_destroyed(st, cmd, attr)) {
		dnet_wakeup(w, w->cond++);
		dnet_write_complete_free(wc);
		return 0;
	}

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
	if (ctl->aflags & DNET_ATTR_NOLOCK)
		cmd->flags |= DNET_FLAGS_NOLOCK;
	cmd->status = 0;

	a->cmd = t->command = ctl->cmd;
	a->size = sizeof(struct dnet_io_attr) + size;
	a->flags = ctl->aflags;

	memcpy(io, &ctl->io, sizeof(struct dnet_io_attr));

	memcpy(&t->cmd, cmd, sizeof(struct dnet_cmd));

	t->st = dnet_state_get_first(n, &cmd->id);
	if (!t->st) {
		err = -ENOENT;
		goto err_out_destroy;
	}

	cmd->trans = t->rcv_trans = t->trans = atomic_inc(&n->trans);

	dnet_log(n, DNET_LOG_INFO, "%s: created trans: %llu, cmd: %s, cflags: %x, size: %llu, offset: %llu, "
			"fd: %d, local_offset: %llu -> %s weight: %f, mrt: %ld.\n",
			dnet_dump_id(&ctl->id),
			(unsigned long long)t->trans,
			dnet_cmd_string(ctl->cmd), cmd->flags,
			(unsigned long long)ctl->io.size, (unsigned long long)ctl->io.offset,
			ctl->fd,
			(unsigned long long)ctl->local_offset,
			dnet_server_convert_dnet_addr(&t->st->addr), t->st->weight, t->st->median_read_time);

	dnet_convert_cmd(cmd);
	dnet_convert_attr(a);
	dnet_convert_io_attr(io);


	memset(&req, 0, sizeof(req));
	req.st = t->st;
	req.header = cmd;
	req.hsize = tsize;

	req.fd = ctl->fd;

	if (ctl->fd >= 0) {
		req.local_offset = ctl->local_offset;
		req.fsize = size;
	} else if (size >= DNET_COPY_IO_SIZE) {
		req.data = (void *)ctl->data;
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
	int num = 0, i, err;

	pthread_mutex_lock(&n->group_lock);
	for (i=0; i<n->group_num; ++i) {
		ctl->id.group_id = n->groups[i];

		dnet_io_trans_create(n, ctl, &err);
		num++;
	}
	pthread_mutex_unlock(&n->group_lock);

	if (!num) {
		dnet_io_trans_create(n, ctl, &err);
		num++;
	}

	return num;
}

int dnet_write_object(struct dnet_node *n, struct dnet_io_control *ctl)
{
	return dnet_trans_create_send_all(n, ctl);
}

static int dnet_write_file_id_raw(struct dnet_node *n, const char *file, struct dnet_id *id,
		uint64_t local_offset, uint64_t remote_offset, uint64_t size,
		unsigned int aflags, unsigned int ioflags)
{
	int fd, err, trans_num;
	struct stat stat;
	struct dnet_wait *w;
	struct dnet_io_control ctl;
	struct dnet_write_completion *wc;

	wc = malloc(sizeof(struct dnet_write_completion));
	if (!wc) {
		err = -ENOMEM;
		goto err_out_exit;
	}
	memset(wc, 0, sizeof(struct dnet_write_completion));

	w = dnet_wait_alloc(0);
	if (!w) {
		free(wc);
		err = -ENOMEM;
		dnet_log(n, DNET_LOG_ERROR, "Failed to allocate read waiting structure.\n");
		goto err_out_exit;
	}

	wc->wait = w;

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

	atomic_set(&w->refcnt, INT_MAX);

	ctl.data = NULL;
	ctl.fd = fd;
	ctl.local_offset = local_offset;

	w->status = -ENOENT;
	ctl.complete = dnet_write_complete;
	ctl.priv = wc;

	ctl.cflags = DNET_FLAGS_NEED_ACK;
	ctl.cmd = DNET_CMD_WRITE;
	ctl.aflags = aflags;
	if (ctl.aflags & DNET_ATTR_NOLOCK)
		ctl.cflags |= DNET_FLAGS_NOLOCK;

	memcpy(ctl.io.id, id->id, DNET_ID_SIZE);
	memcpy(ctl.io.parent, id->id, DNET_ID_SIZE);

	ctl.io.flags = ioflags;
	ctl.io.size = size;
	ctl.io.offset = remote_offset;
	ctl.io.type = id->type;

	memcpy(&ctl.id, id, sizeof(struct dnet_id));

	trans_num = dnet_write_object(n, &ctl);
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
	dnet_write_complete_free(wc);

	return 0;

err_out_close:
	close(fd);
err_out_put:
	dnet_write_complete_free(wc);
err_out_exit:
	return err;
}

int dnet_write_file_id(struct dnet_node *n, const char *file, struct dnet_id *id, uint64_t local_offset,
		uint64_t remote_offset, uint64_t size, unsigned int aflags, unsigned int ioflags)
{
	int err = dnet_write_file_id_raw(n, file, id, local_offset, remote_offset, size, aflags, ioflags);

	if (!err)
		err = dnet_create_write_metadata_strings(n, NULL, 0, id, NULL, aflags);

	return err;
}

int dnet_write_file(struct dnet_node *n, const char *file, const void *remote, int remote_len,
		uint64_t local_offset, uint64_t remote_offset, uint64_t size,
		unsigned int aflags, unsigned int ioflags, int type)
{
	int err;
	struct dnet_id id;

	dnet_transform(n, remote, remote_len, &id);
	id.type = type;

	err = dnet_write_file_id_raw(n, file, &id, local_offset, remote_offset, size, aflags, ioflags);
	if (!err)
		err = dnet_create_write_metadata_strings(n, remote, remote_len, &id, NULL, aflags);

	return err;
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

static int dnet_read_file_raw_exec(struct dnet_node *n, const char *file, unsigned int len,
		int direct, uint64_t write_offset, uint64_t io_offset, uint64_t io_size,
		struct dnet_id *id, struct dnet_wait *w)
{
	struct dnet_io_control ctl;
	struct dnet_io_completion *c;
	int err, wait_init = ~0;

	memset(&ctl, 0, sizeof(struct dnet_io_control));

	ctl.io.size = io_size;
	ctl.io.offset = io_offset;

	ctl.io.type = id->type;

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

	return 0;

err_out_exit:
	return err;
}

static int dnet_read_file_raw(struct dnet_node *n, const char *file, struct dnet_id *id,
		int direct, uint64_t offset, uint64_t size)
{
	int err = -ENOENT, len = strlen(file), i;
	struct dnet_wait *w;
	int *g, num;

	w = dnet_wait_alloc(~0);
	if (!w) {
		err = -ENOMEM;
		dnet_log(n, DNET_LOG_ERROR, "Failed to allocate read waiting.\n");
		goto err_out_exit;
	}

	if (!size)
		size = ~0ULL;

	num = dnet_mix_states(n, id, &g);
	if (num < 0) {
		err = num;
		goto err_out_exit;
	}

	for (i=0; i<num; ++i) {
		id->group_id = g[i];

		err = dnet_read_file_raw_exec(n, file, len, direct, 0, offset, size, id, w);
		if (err)
			continue;

		break;
	}

	dnet_wait_put(w);
	free(g);

err_out_exit:
	return err;
}

int dnet_read_file_id(struct dnet_node *n, const char *file, struct dnet_id *id, uint64_t offset, uint64_t size)
{
	return dnet_read_file_raw(n, file, id, 0, offset, size);
}

int dnet_read_file(struct dnet_node *n, const char *file, const void *remote, int remote_size,
		uint64_t offset, uint64_t size, int type)
{
	struct dnet_id id;

	dnet_transform(n, remote, remote_size, &id);
	id.type = type;

	return dnet_read_file_raw(n, file, &id, 0, offset, size);
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
	free(w->ret);
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

	w->status = cmd->status;

	if (attr && attr->size) {
		void *old = w->ret;
		void *data = attr + 1;

		w->ret = realloc(w->ret, w->size + attr->size);
		if (!w->ret) {
			w->ret = old;
			w->status = -ENOMEM;
		} else {
			memcpy(w->ret + w->size, data, attr->size);
			w->size += attr->size;
		}
	}

	err = w->status;

	return err;
}

static int dnet_send_cmd_single(struct dnet_net_state *st, struct dnet_wait *w, struct dnet_exec *e)
{
	struct dnet_trans_control ctl;

	memset(&ctl, 0, sizeof(struct dnet_trans_control));

	dnet_setup_id(&ctl.id, st->idc->group->group_id, st->idc->ids[0].raw.id);
	ctl.cmd = DNET_CMD_EXEC;
	ctl.complete = dnet_send_cmd_complete;
	ctl.priv = w;
	ctl.cflags = DNET_FLAGS_NEED_ACK;
	ctl.size = sizeof(struct dnet_exec) + e->script_size + e->name_size + e->binary_size;

	dnet_convert_exec(e);

	ctl.data = e;

	return dnet_trans_alloc_send_state(st, &ctl);
}

int dnet_send_cmd(struct dnet_node *n, struct dnet_id *id,
		struct dnet_exec *e, void **ret)
{
	struct dnet_net_state *st;
	int err = -ENOENT, num = 0;
	struct dnet_wait *w;
	struct dnet_group *g;

	w = dnet_wait_alloc(0);
	if (!w) {
		err = -ENOMEM;
		goto err_out_exit;
	}

	if (id && id->group_id != 0) {
		dnet_wait_get(w);
		st = dnet_state_get_first(n, id);
		if (!st)
			goto err_out_put;
		err = dnet_send_cmd_single(st, w, e);
		dnet_state_put(st);
		num = 1;
	} else if (id && id->group_id == 0) {
		pthread_mutex_lock(&n->state_lock);
		list_for_each_entry(g, &n->group_list, group_entry) {
			dnet_wait_get(w);

			id->group_id = g->group_id;

			st = dnet_state_search_nolock(n, id);
			if (st) {
				if (st != n->st) {
					err = dnet_send_cmd_single(st, w, e);
					num++;
				}
				dnet_state_put(st);
			}
		}
		pthread_mutex_unlock(&n->state_lock);
	} else {
		pthread_mutex_lock(&n->state_lock);
		list_for_each_entry(g, &n->group_list, group_entry) {
			list_for_each_entry(st, &g->state_list, state_entry) {
				if (st == n->st)
					continue;

				dnet_wait_get(w);

				err = dnet_send_cmd_single(st, w, e);
				num++;
			}
		}
		pthread_mutex_unlock(&n->state_lock);
	}

	err = dnet_wait_event(w, w->cond == num, &n->wait_ts);
	if (err)
		goto err_out_put;

	if (w->ret) {
		*ret = w->ret;
		w->ret = NULL;

		err = w->size;
	}

	dnet_wait_put(w);

	return err;

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
	if (aflags & DNET_ATTR_NOLOCK)
		cmd->flags |= DNET_FLAGS_NOLOCK;

	t->st = dnet_state_get_first(n, &cmd->id);
	if (!t->st) {
		err = -ENOENT;
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
		dnet_wakeup(w, w->cond++);
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

int dnet_lookup(struct dnet_node *n, const char *file)
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

		dnet_log(state->n, DNET_LOG_DATA, "%s: %s: la: %.2f %.2f %.2f.\n",
				dnet_dump_id(&cmd->id), dnet_state_dump_addr(state),
				la[0], la[1], la[2]);
		dnet_log(state->n, DNET_LOG_DATA, "%s: %s: mem: "
				"total: %llu kB, free: %llu kB, cache: %llu kB.\n",
				dnet_dump_id(&cmd->id), dnet_state_dump_addr(state),
				(unsigned long long)st->vm_total,
				(unsigned long long)st->vm_free,
				(unsigned long long)st->vm_cached);
		dnet_log(state->n, DNET_LOG_DATA, "%s: %s: fs: "
				"total: %llu mB, avail: %llu mB, files: %llu, fsid: %llx.\n",
				dnet_dump_id(&cmd->id), dnet_state_dump_addr(state),
				(unsigned long long)(st->frsize * st->blocks / 1024 / 1024),
				(unsigned long long)(st->bavail * st->bsize / 1024 / 1024),
				(unsigned long long)st->files, (unsigned long long)st->fsid);
		err = 0;
	} else if (attr->size >= sizeof(struct dnet_addr_stat) && attr->cmd == DNET_CMD_STAT_COUNT) {
		struct dnet_addr_stat *as = (struct dnet_addr_stat *)(attr + 1);
		int i;

		dnet_convert_addr_stat(as, 0);
		
		for (i=0; i<as->num; ++i) {
			if (as->num > as->cmd_num) {
				if (i == 0)
					dnet_log(state->n, DNET_LOG_DATA, "%s: %s: Storage commands\n",
						dnet_dump_id(&cmd->id), dnet_state_dump_addr(state));
				if (i == as->cmd_num)
					dnet_log(state->n, DNET_LOG_DATA, "%s: %s: Proxy commands\n",
						dnet_dump_id(&cmd->id), dnet_state_dump_addr(state));
				if (i == as->cmd_num * 2)
					dnet_log(state->n, DNET_LOG_DATA, "%s: %s: Counters\n",
						dnet_dump_id(&cmd->id), dnet_state_dump_addr(state));
			}	
			dnet_log(state->n, DNET_LOG_DATA, "%s: %s:    cmd: %s, count: %llu, err: %llu\n",
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
	ctl.cflags = DNET_FLAGS_NEED_ACK | DNET_ATTR_NOLOCK;
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

struct dnet_update_status_priv {
	struct dnet_wait *w;
	struct dnet_node_status status;
	atomic_t refcnt;
};

static int dnet_update_status_complete(struct dnet_net_state *state,
		struct dnet_cmd *cmd, struct dnet_attr *attr, void *priv)
{
	struct dnet_update_status_priv *p = priv;

	if (is_trans_destroyed(state, cmd, attr)) {
		dnet_wakeup(p->w, p->w->cond++);
		dnet_wait_put(p->w);
		if (atomic_dec_and_test(&p->refcnt))
			free(p);
	}

	if (!attr)
		return cmd->status;

	if (attr->size == sizeof(struct dnet_node_status)) {
		memcpy(&p->status, attr+1, sizeof(struct dnet_node_status));
		return 0;
	}

	return -ENOENT;
}

int dnet_update_status(struct dnet_node *n, struct dnet_addr *addr, struct dnet_id *id,
			struct dnet_node_status *status, int update)
{
	int err;
	struct dnet_update_status_priv *priv;
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

	priv = malloc(sizeof(struct dnet_update_status_priv));
	if (!priv) {
		err = -ENOMEM;
		goto err_out_exit;
	}

	priv->w = dnet_wait_alloc(0);
	if (!priv->w) {
		err = -ENOMEM;
		goto err_out_exit;
	}

	ctl.complete = dnet_update_status_complete;
	ctl.priv = priv;
	ctl.cmd = DNET_CMD_STATUS;
	ctl.cflags = DNET_FLAGS_NEED_ACK;
	if (update)
		ctl.aflags = DNET_ATTR_STATUS_CHANGE;
	ctl.size = sizeof(struct dnet_node_status);
	ctl.data = status;

	dnet_wait_get(priv->w);
	dnet_request_cmd_single(n, NULL, &ctl);

	err = dnet_wait_event(priv->w, priv->w->cond == 1, &n->wait_ts);
	dnet_wait_put(priv->w);
	if (!err && priv) {
		memcpy(status, &priv->status, sizeof(struct dnet_node_status));
	}
	if (atomic_dec_and_test(&priv->refcnt))
		free(priv);

err_out_exit:
	return err;
}

static int dnet_remove_object_raw(struct dnet_node *n, struct dnet_id *id,
	int (* complete)(struct dnet_net_state *state,
			struct dnet_cmd *cmd,
			struct dnet_attr *attr,
			void *priv),
	void *priv,
	int direct, int aflags)
{
	struct dnet_trans_control ctl;

	memset(&ctl, 0, sizeof(struct dnet_trans_control));

	memcpy(&ctl.id, id, sizeof(struct dnet_id));

	ctl.cmd = DNET_CMD_DEL;
	ctl.complete = complete;
	ctl.priv = priv;
	ctl.cflags = DNET_FLAGS_NEED_ACK;
	ctl.aflags = aflags;
	if (ctl.aflags & DNET_ATTR_NOLOCK)
		ctl.cflags |= DNET_FLAGS_NOLOCK;
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

int dnet_remove_object(struct dnet_node *n, struct dnet_id *id,
	int (* complete)(struct dnet_net_state *state,
			struct dnet_cmd *cmd,
			struct dnet_attr *attr,
			void *priv),
	void *priv,
	int direct, int aflags)
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

	err = dnet_remove_object_raw(n, id, complete, priv, direct, aflags);
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

int dnet_remove_object_now(struct dnet_node *n, struct dnet_id *id, int direct, int aflags)
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
	ctl.aflags = DNET_ATTR_DELETE_HISTORY | aflags;
	if (ctl.aflags & DNET_ATTR_NOLOCK)
		ctl.cflags |= DNET_FLAGS_NOLOCK;

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

static int dnet_remove_file_raw(struct dnet_node *n, struct dnet_id *id, int aflags)
{
	struct dnet_wait *w;
	int err;

	w = dnet_wait_alloc(0);
	if (!w) {
		err = -ENOMEM;
		goto err_out_exit;
	}

	dnet_wait_get(w);
	err = dnet_remove_object_raw(n, id, dnet_remove_complete, w, 0, aflags);
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

int dnet_remove_file(struct dnet_node *n, char *remote, int remote_len, struct dnet_id *id, int aflags)
{
	struct dnet_id raw;
	int err, error = 0, i;

	if (id)
		 return dnet_remove_file_raw(n, id, aflags);

	dnet_transform(n, remote, remote_len, &raw);

	pthread_mutex_lock(&n->group_lock);
	for (i=0; i<n->group_num; ++i) {
		raw.group_id = n->groups[i];
		err = dnet_remove_file_raw(n, &raw, aflags);
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
	if (ctl.aflags & DNET_ATTR_NOLOCK)
		ctl.cflags |= DNET_FLAGS_NOLOCK;

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

	if (attr->size >= sizeof(struct dnet_io_attr)) {
		struct dnet_io_attr *io = (struct dnet_io_attr *)(attr + 1);
		uint64_t sz = c->size;

		dnet_convert_io_attr(io);

		sz += io->size + sizeof(struct dnet_io_attr);
		c->data = realloc(c->data, sz);
		if (!c->data) {
			err = -ENOMEM;
			goto err_out_exit;
		}

		memcpy(c->data + c->size, io, sizeof(struct dnet_io_attr) + io->size);
		c->size = sz;
	}

err_out_exit:
	dnet_log(st->n, DNET_LOG_NOTICE, "%s: object read completed: trans: %llu, status: %d, err: %d.\n",
		dnet_dump_id(&cmd->id), (unsigned long long)(cmd->trans & ~DNET_TRANS_REPLY),
		cmd->status, err);

	return err;
}

void *dnet_read_data_wait_raw(struct dnet_node *n, struct dnet_id *id, struct dnet_io_attr *io,
		int cmd, uint32_t aflags, int *errp)
{
	struct dnet_io_control ctl;
	struct dnet_wait *w;
	struct dnet_read_data_completion *c;
	void *data = NULL;
	int err;

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

	ctl.cmd = cmd;
	ctl.cflags = DNET_FLAGS_NEED_ACK;
	if (aflags & DNET_ATTR_NOLOCK)
		ctl.cflags |= DNET_FLAGS_NOLOCK;

	ctl.aflags = aflags;

	memcpy(&ctl.io, io, sizeof(struct dnet_io_attr));
	memcpy(&ctl.id, id, sizeof(struct dnet_id));

	ctl.id.type = io->type;

	dnet_wait_get(w);
	err = dnet_read_object(n, &ctl);
	if (err)
		goto err_out_put_complete;

	err = dnet_wait_event(w, w->cond, &n->wait_ts);
	if (err || w->status) {
		char id_str[2*DNET_ID_SIZE + 1];
		if (!err)
			err = w->status;
		if ((cmd != DNET_CMD_READ_RANGE) || (err != -ENOENT))
			dnet_log(n, DNET_LOG_ERROR, "%d:%s : failed to read data: %d\n",
				ctl.id.group_id, dnet_dump_id_len_raw(ctl.id.id, DNET_ID_SIZE, id_str), err);
		goto err_out_put_complete;
	}
	io->size = c->size;
	data = c->data;
	err = 0;

err_out_put_complete:
	if (atomic_dec_and_test(&c->refcnt))
		free(c);
err_out_put:
	dnet_wait_put(w);
err_out_exit:
	*errp = err;
	return data;
}

void *dnet_read_data_wait_groups(struct dnet_node *n, struct dnet_id *id, int *groups, int num,
		struct dnet_io_attr *io, uint32_t aflags, int *errp)
{
	int i;
	void *data;

	for (i = 0; i < num; ++i) {
		id->group_id = groups[i];

		data = dnet_read_data_wait_raw(n, id, io, DNET_CMD_READ, aflags, errp);
		if (data) {
			*errp = 0;
			return data;
		}
	}

	return NULL;
}

void *dnet_read_data_wait(struct dnet_node *n, struct dnet_id *id, struct dnet_io_attr *io,
		uint32_t aflags, int *errp)
{
	int num, *g, err;
	void *data = NULL;

	num = dnet_mix_states(n, id, &g);
	if (num < 0) {
		err = num;
		goto err_out_exit;
	}

	data = dnet_read_data_wait_groups(n, id, g, num, io, aflags, &err);
	if (!data)
		goto err_out_free;

err_out_free:
	free(g);
err_out_exit:
	*errp = err;
	return data;
}

int dnet_write_data_wait(struct dnet_node *n, struct dnet_io_control *ctl)
{
	int err, trans_num = 0;
	struct dnet_wait *w;
	struct dnet_write_completion *wc;

	wc = malloc(sizeof(struct dnet_write_completion));
	if (!wc) {
		err = -ENOMEM;
		goto err_out_exit;
	}
	memset(wc, 0, sizeof(struct dnet_write_completion));

	w = dnet_wait_alloc(0);
	if (!w) {
		err = -ENOMEM;
		free(wc);
		goto err_out_exit;
	}
	wc->wait = w;

	w->status = -ENOENT;
	ctl->priv = wc;
	ctl->complete = dnet_write_complete;

	ctl->cmd = DNET_CMD_WRITE;
	ctl->cflags = DNET_FLAGS_NEED_ACK;
	if (ctl->aflags & DNET_ATTR_NOLOCK)
		ctl->cflags |= DNET_FLAGS_NOLOCK;

	memcpy(ctl->io.id, ctl->id.id, DNET_ID_SIZE);
	memcpy(ctl->io.parent, ctl->id.id, DNET_ID_SIZE);

	atomic_set(&w->refcnt, INT_MAX);
	trans_num = dnet_write_object(n, ctl);
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
				dnet_dump_id(&ctl->id), err, w->status);
	}

	if (err || !trans_num) {
		if (!err)
			err = -EINVAL;
		dnet_log(n, DNET_LOG_ERROR, "Failed to write data into the storage, err: %d, trans_num: %d.\n", err, trans_num);
		goto err_out_put;
	}

	if (trans_num)
		dnet_log(n, DNET_LOG_NOTICE, "%s: wrote: %llu bytes, type: %d, reply size: %d.\n",
				dnet_dump_id(&ctl->id), (unsigned long long)ctl->io.size, ctl->io.type, wc->size);
	err = trans_num;

	ctl->adata = wc->reply;
	ctl->asize = wc->size;

	wc->reply = NULL;

err_out_put:
	dnet_write_complete_free(wc);
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
	}

	err = group_num;

err_out_exit:
	return err;
}

int dnet_send_read_data(void *state, struct dnet_cmd *cmd, struct dnet_io_attr *io, void *data,
		int fd, uint64_t offset, int close_on_exit)
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
	if (io->flags & DNET_IO_FLAGS_SKIP_SENDING)
		return 0;

	c = malloc(hsize);
	if (!c) {
		err = -ENOMEM;
		goto err_out_exit;
	}

	a = (struct dnet_attr *)(c + 1);
	rio = (struct dnet_io_attr *)(a + 1);

	dnet_setup_id(&c->id, cmd->id.group_id, io->id);

	c->flags = cmd->flags & ~(DNET_FLAGS_NEED_ACK | DNET_FLAGS_MORE);
	if (cmd->flags & DNET_FLAGS_NEED_ACK)
		c->flags |= DNET_FLAGS_MORE;

	c->status = 0;
	c->size = sizeof(struct dnet_attr) + sizeof(struct dnet_io_attr) + io->size;
	c->trans = cmd->trans | DNET_TRANS_REPLY;

	a->cmd = DNET_CMD_READ;
	a->size = sizeof(struct dnet_io_attr) + io->size;
	a->flags = 0;

	memcpy(rio, io, sizeof(struct dnet_io_attr));

	dnet_log_raw(st->n, DNET_LOG_NOTICE, "%s: %s: reply: offset: %llu, size: %llu.\n",
			dnet_dump_id(&c->id), dnet_cmd_string(a->cmd),
			(unsigned long long)io->offset,	(unsigned long long)io->size);

	dnet_convert_cmd(c);
	dnet_convert_attr(a);
	dnet_convert_io_attr(rio);

	if (data)
		err = dnet_send_data(st, c, hsize, data, io->size);
	else
		err = dnet_send_fd(st, c, hsize, fd, offset, io->size, close_on_exit);

	free(c);

err_out_exit:
	return err;
}

int dnet_lookup_addr(struct dnet_node *n, const void *remote, int len, struct dnet_id *id, int group_id, char *dst, int dlen)
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

	return w2->weight - w1->weight;
}

static int dnet_weight_get_winner(struct dnet_weight *w, int num)
{
	long sum = 0, pos;
	float r;
	int i;

	for (i = 0; i < num; ++i)
		sum += w[i].weight;

	r = (float)rand() / (float)RAND_MAX;
	pos = r * sum;

	for (i = 0; i < num; ++i) {
		pos -= w[i].weight;
		if (pos <= 0)
			return i;
	}

	return num - 1;
}

int dnet_mix_states(struct dnet_node *n, struct dnet_id *id, int **groupsp)
{
	struct dnet_weight *weights;
	int *groups;
	int group_num, i, num;
	struct dnet_net_state *st;

	if (!n->group_num)
		return -ENOENT;

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

	if (n->flags & DNET_CFG_RANDOMIZE_STATES) {
		for (i = 0; i < group_num; ++i) {
			weights[i].weight = rand();
			weights[i].group_id = groups[i];
		}
		num = group_num;
	} else {
		if (!(n->flags & DNET_CFG_MIX_STATES)) {
			*groupsp = groups;
			return group_num;
		}

		memset(weights, 0, group_num * sizeof(*weights));

		for (i = 0, num = 0; i < group_num; ++i) {
			id->group_id = groups[i];

			st = dnet_state_get_first(n, id);
			if (st) {
				weights[num].weight = (int)st->weight;
				weights[num].group_id = id->group_id;

				dnet_state_put(st);

				num++;
			}
		}
	}

	group_num = num;
	if (group_num) {
		qsort(weights, group_num, sizeof(struct dnet_weight), dnet_weight_compare);

		for (i = 0; i < group_num; ++i) {
			int pos = dnet_weight_get_winner(weights, group_num - i);
			groups[i] = weights[pos].group_id;

			if (pos < group_num - 1)
				memmove(&weights[pos], &weights[pos + 1], (group_num - 1 - pos) * sizeof(struct dnet_weight));
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

int dnet_data_map(struct dnet_map_fd *map)
{
	uint64_t off;
	long page_size = sysconf(_SC_PAGE_SIZE);
	int err = 0;

	off = map->offset & ~(page_size - 1);
	map->mapped_size = ALIGN(map->size + map->offset - off, page_size);

	map->mapped_data = mmap(NULL, map->mapped_size, PROT_READ, MAP_SHARED, map->fd, off);
	if (map->mapped_data == MAP_FAILED) {
		err = -errno;
		goto err_out_exit;
	}

	map->data = map->mapped_data + map->offset - off;

err_out_exit:
	return err;
}

void dnet_data_unmap(struct dnet_map_fd *map)
{
	munmap(map->mapped_data, map->mapped_size);
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

struct dnet_io_attr *dnet_remove_range(struct dnet_node *n, struct dnet_io_attr *io, int group_id, uint32_t aflags, int *ret_num, int *errp)
{
	struct dnet_id id;
	struct dnet_io_attr *ret, *new_ret;
	struct dnet_raw_id start, next;
	struct dnet_raw_id end;
	uint64_t size = io->size;
	void *data;
	int err, need_exit = 0;

	memcpy(end.id, io->parent, DNET_ID_SIZE);

	dnet_setup_id(&id, group_id, io->id);
	id.type = io->type;

	ret = NULL;
	*ret_num = 0;
	while (!need_exit) {
		err = dnet_search_range(n, &id, &start, &next);
		if (err)
			goto err_out_exit;

		if ((dnet_id_cmp_str(id.id, next.id) > 0) ||
				!memcmp(start.id, next.id, DNET_ID_SIZE) ||
				(dnet_id_cmp_str(next.id, end.id) > 0)) {
			memcpy(next.id, end.id, DNET_ID_SIZE);
			need_exit = 1;
		}

		if (n->log->log_mask & DNET_LOG_NOTICE) {
			int len = 6;
			char start_id[2*len + 1];
			char next_id[2*len + 1];
			char end_id[2*len + 1];
			char id_str[2*len + 1];

			dnet_log(n, DNET_LOG_NOTICE, "id: %s, start: %s: next: %s, end: %s, size: %llu, cmp: %d\n",
					dnet_dump_id_len_raw(id.id, len, id_str),
					dnet_dump_id_len_raw(start.id, len, start_id),
					dnet_dump_id_len_raw(next.id, len, next_id),
					dnet_dump_id_len_raw(end.id, len, end_id),
					(unsigned long long)size, dnet_id_cmp_str(next.id, end.id));
		}

		memcpy(io->id, id.id, DNET_ID_SIZE);
		memcpy(io->parent, next.id, DNET_ID_SIZE);

		io->size = size;

		data = dnet_read_data_wait_raw(n, &id, io, DNET_CMD_DEL_RANGE, aflags, &err);
		if (io->size != sizeof(struct dnet_io_attr)) {
			err = -ENOENT;
			goto err_out_exit;
		}

		if (data) {
			struct dnet_io_attr *rep = (struct dnet_io_attr*)data;

			dnet_convert_io_attr(rep);

			dnet_log(n, DNET_LOG_NOTICE, "%s: rep_num: %llu, io_start: %llu, io_num: %llu, io_size: %llu\n",
					dnet_dump_id(&id), (unsigned long long)rep->num, (unsigned long long)io->start,
					(unsigned long long)io->num, (unsigned long long)io->size);

			(*ret_num)++;

			new_ret = realloc(ret, *ret_num * sizeof(struct dnet_io_attr));
			if (!new_ret) {
				err = -ENOMEM;
				goto err_out_exit;
			}

			ret = new_ret;
			ret[*ret_num - 1] = *rep;

			free(data);
		}

		memcpy(id.id, next.id, DNET_ID_SIZE);
	}

err_out_exit:
	*errp = err;

	return ret;
}

struct dnet_range_data *dnet_read_range(struct dnet_node *n, struct dnet_io_attr *io, int group_id, uint32_t aflags, int *errp)
{
	struct dnet_id id;
	int ret_num;
	struct dnet_range_data *ret;
	struct dnet_raw_id start, next;
	struct dnet_raw_id end;
	uint64_t size = io->size;
	void *data;
	int err, need_exit = 0;

	memcpy(end.id, io->parent, DNET_ID_SIZE);

	dnet_setup_id(&id, group_id, io->id);
	id.type = io->type;

	ret = NULL;
	ret_num = 0;
	while (!need_exit) {
		err = dnet_search_range(n, &id, &start, &next);
		if (err)
			goto err_out_exit;

		if ((dnet_id_cmp_str(id.id, next.id) > 0) ||
				!memcmp(start.id, next.id, DNET_ID_SIZE) ||
				(dnet_id_cmp_str(next.id, end.id) > 0)) {
			memcpy(next.id, end.id, DNET_ID_SIZE);
			need_exit = 1;
		}

		if (n->log->log_mask & DNET_LOG_NOTICE) {
			int len = 6;
			char start_id[2*len + 1];
			char next_id[2*len + 1];
			char end_id[2*len + 1];
			char id_str[2*len + 1];

			dnet_log(n, DNET_LOG_NOTICE, "id: %s, start: %s: next: %s, end: %s, size: %llu, cmp: %d\n",
					dnet_dump_id_len_raw(id.id, len, id_str),
					dnet_dump_id_len_raw(start.id, len, start_id),
					dnet_dump_id_len_raw(next.id, len, next_id),
					dnet_dump_id_len_raw(end.id, len, end_id),
					(unsigned long long)size, dnet_id_cmp_str(next.id, end.id));
		}

		memcpy(io->id, id.id, DNET_ID_SIZE);
		memcpy(io->parent, next.id, DNET_ID_SIZE);

		io->size = size;

		data = dnet_read_data_wait_raw(n, &id, io, DNET_CMD_READ_RANGE, aflags, &err);
		if (data) {
			struct dnet_io_attr *rep = data + io->size - sizeof(struct dnet_io_attr);

			/* If DNET_IO_FLAGS_NODATA is set do not decrement size as 'rep' is the only structure in output */
			if (!(io->flags & DNET_IO_FLAGS_NODATA))
				io->size -= sizeof(struct dnet_io_attr);
			dnet_convert_io_attr(rep);

			dnet_log(n, DNET_LOG_NOTICE, "%s: rep_num: %llu, io_start: %llu, io_num: %llu, io_size: %llu\n",
					dnet_dump_id(&id), (unsigned long long)rep->num, (unsigned long long)io->start,
					(unsigned long long)io->num, (unsigned long long)io->size);

			if (io->start < rep->num) {
				rep->num -= io->start;
				io->start = 0;
				io->num -= rep->num;

				if (!io->size && !(io->flags & DNET_IO_FLAGS_NODATA)) {
					free(data);
				} else {
					struct dnet_range_data *new_ret;

					ret_num++;

					new_ret = realloc(ret, ret_num * sizeof(struct dnet_range_data));
					if (!new_ret) {
						goto err_out_exit;
					}

					ret = new_ret;

					ret[ret_num - 1].data = data;
					ret[ret_num - 1].size = io->size;
				}

				err = 0;
				if (!io->num)
					break;
			} else {
				io->start -= rep->num;
			}
		}

		memcpy(id.id, next.id, DNET_ID_SIZE);
	}

err_out_exit:
	if (ret) {
		*errp = ret_num;
	} else {
		*errp = err;
	}
	return ret;
}

struct dnet_read_latest_id {
	struct dnet_id			id;
	struct dnet_file_info		fi;
};

struct dnet_read_latest_ctl {
	struct dnet_wait		*w;
	int				num, pos;
	pthread_mutex_t			lock;

	struct dnet_read_latest_id	ids[0];
};

static void dnet_read_latest_ctl_put(struct dnet_read_latest_ctl *ctl)
{
	dnet_wakeup(ctl->w, ctl->w->cond++);
	if (atomic_dec_and_test(&ctl->w->refcnt)) {
		dnet_wait_destroy(ctl->w);
		pthread_mutex_destroy(&ctl->lock);
		free(ctl);
	}
}

static int dnet_read_latest_complete(struct dnet_net_state *st, struct dnet_cmd *cmd,
		struct dnet_attr *attr, void *priv)
{
	struct dnet_read_latest_ctl *ctl = priv;
	struct dnet_node *n;
	struct dnet_addr_attr *a;
	struct dnet_file_info *fi;
	int pos, err;

	if (is_trans_destroyed(st, cmd, attr)) {
		dnet_read_latest_ctl_put(ctl);
		return 0;
	}

	n = st->n;

	err = cmd->status;
	if (err || !cmd->size || !attr)
		goto err_out_exit;

	if (attr->size < sizeof(struct dnet_addr_attr) + sizeof(struct dnet_file_info)) {
		dnet_log(n, DNET_LOG_ERROR, "%s: wrong dnet_addr attribute size %llu, must be at least %zu.\n",
				dnet_dump_id(&cmd->id), (unsigned long long)attr->size,
				sizeof(struct dnet_addr_attr) + sizeof(struct dnet_file_info));
		err = -EINVAL;
		goto err_out_exit;
	}
	a = (struct dnet_addr_attr *)(attr + 1);
	fi = (struct dnet_file_info *)(a + 1);

	dnet_convert_addr_attr(a);
	dnet_convert_file_info(fi);

	pthread_mutex_lock(&ctl->lock);
	pos = ctl->pos++;
	pthread_mutex_unlock(&ctl->lock);

	/* we do not care about filename */
	memcpy(&ctl->ids[pos].fi, fi, sizeof(struct dnet_file_info));
	memcpy(&ctl->ids[pos].id, &cmd->id, sizeof(struct dnet_id));

err_out_exit:
	return err;
}

static int dnet_file_read_latest_cmp(const void *p1, const void *p2)
{
	const struct dnet_read_latest_id *id1 = p1;
	const struct dnet_read_latest_id *id2 = p2;

	int ret = (int)(id2->fi.mtime.tsec - id1->fi.mtime.tsec);

	if (!ret)
		ret = (int)(id2->fi.mtime.tnsec - id1->fi.mtime.tnsec);

	return ret;
}

int dnet_read_latest_prepare(struct dnet_read_latest_prepare *pr)
{
	struct dnet_read_latest_ctl *ctl;
	int group_id = pr->id.group_id;
	int err, i;

	ctl = malloc(sizeof(struct dnet_read_latest_ctl) + sizeof(struct dnet_read_latest_id) * pr->group_num);
	if (!ctl) {
		err = -ENOMEM;
		goto err_out_exit;
	}
	memset(ctl, 0, sizeof(struct dnet_read_latest_ctl));

	ctl->w = dnet_wait_alloc(0);
	if (!ctl->w) {
		err = -ENOMEM;
		goto err_out_free;
	}

	err = pthread_mutex_init(&ctl->lock, NULL);
	if (err)
		goto err_out_put_wait;

	ctl->num = pr->group_num;
	ctl->pos = 0;

	for (i = 0; i < pr->group_num; ++i) {
		pr->id.group_id = pr->group[i];

		dnet_wait_get(ctl->w);
		dnet_lookup_object(pr->n, &pr->id, DNET_ATTR_META_TIMES | pr->aflags, dnet_read_latest_complete, ctl);
	}

	err = dnet_wait_event(ctl->w, ctl->w->cond == pr->group_num, &pr->n->wait_ts);
	if (err)
		goto err_out_put;

	pr->group_num = ctl->pos;

	qsort(ctl->ids, pr->group_num, sizeof(struct dnet_read_latest_id), dnet_file_read_latest_cmp);

	for (i = 0; i < pr->group_num; ++i) {
		pr->group[i] = ctl->ids[i].id.group_id;

		if (group_id == pr->group[i]) {
			const struct dnet_read_latest_id *id0 = &ctl->ids[0];
			const struct dnet_read_latest_id *id1 = &ctl->ids[i];

			if (!dnet_file_read_latest_cmp(id0, id1)) {
				int tmp_group = pr->group[0];
				pr->group[0] = pr->group[i];
				pr->group[i] = tmp_group;
			}
		}
	}

err_out_put:
	dnet_read_latest_ctl_put(ctl);
	goto err_out_exit;

err_out_put_wait:
	dnet_wait_put(ctl->w);
err_out_free:
	free(ctl);
err_out_exit:
	return err;
}

int dnet_read_latest(struct dnet_node *n, struct dnet_id *id, struct dnet_io_attr *io, uint32_t aflags, void **datap)
{
	struct dnet_read_latest_prepare pr;
	int *g, num, err, i;

	if ((int)io->num > n->group_num) {
		err = -E2BIG;
		goto err_out_exit;
	}

	err = dnet_mix_states(n, id, &g);
	if (err < 0)
		goto err_out_exit;

	num = err;

	if ((int)io->num > num) {
		err = -E2BIG;
		goto err_out_free;
	}

	memset(&pr, 0, sizeof(struct dnet_read_latest_prepare));

	pr.n = n;
	pr.id = *id;
	pr.group = g;
	pr.group_num = num;
	pr.aflags = aflags;

	err = dnet_read_latest_prepare(&pr);
	if (err)
		goto err_out_free;

	err = -ENODATA;
	for (i = 0; i < pr.group_num; ++i) {
		void *data;
		
		id->group_id = pr.group[i];
		data = dnet_read_data_wait_raw(n, id, io, DNET_CMD_READ, aflags, &err);
		if (data) {
			*datap = data;
			err = 0;
			break;
		}
	}

err_out_free:
	free(g);
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

int dnet_send_file_info(void *state, struct dnet_cmd *cmd, struct dnet_attr *attr,
		int fd, uint64_t offset, uint64_t size)
{
	struct dnet_node *n = dnet_get_node_from_state(state);
	struct dnet_file_info *info;
	struct dnet_addr_attr *a;
	int flen, err;
	char *file;
	struct stat st;

	err = dnet_fd_readlink(fd, &file);
	if (err < 0)
		goto err_out_exit;

	flen = err;

	a = malloc(sizeof(struct dnet_addr_attr) + sizeof(struct dnet_file_info) + flen);
	if (!a) {
		err = -ENOMEM;
		goto err_out_free_file;
	}
	info = (struct dnet_file_info *)(a + 1);

	dnet_fill_addr_attr(n, a);

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

	if (attr->flags & DNET_ATTR_META_TIMES) {
		err = dnet_read_file_info(n, &cmd->id, info);
		if ((err == -ENOENT) && (attr->flags & DNET_ATTR_META_TIMES))
			err = 0;
		if (err)
			goto err_out_free;
	}

	if (size)
		info->size = size;
	if (offset)
		info->offset = offset;

	info->flen = flen;
	memcpy(info + 1, file, flen);

	dnet_convert_file_info(info);

	err = dnet_send_reply(state, cmd, attr, a, sizeof(struct dnet_addr_attr) + sizeof(struct dnet_file_info) + flen, 0);

err_out_free:
	free(a);
err_out_free_file:
	free(file);
err_out_exit:
	return err;
}

int dnet_get_routes(struct dnet_node *n, struct dnet_id **ids, struct dnet_addr **addrs) {

	struct dnet_net_state *st;
	struct dnet_group *g;
	struct dnet_addr *tmp_addrs;
	struct dnet_id *tmp_ids;
	int size = 0, count = 0;
	int i;

	*ids = NULL;
	*addrs = NULL;

	pthread_mutex_lock(&n->state_lock);
	list_for_each_entry(g, &n->group_list, group_entry) {
		list_for_each_entry(st, &g->state_list, state_entry) {

			size += st->idc->id_num;

			tmp_ids = (struct dnet_id *)realloc(*ids, size * sizeof(struct dnet_id));
			if (!tmp_ids) {
				count = -ENOMEM;
				goto err_out_free;
			}
			*ids = tmp_ids;

			tmp_addrs = (struct dnet_addr *)realloc(*addrs, size * sizeof(struct dnet_addr));
			if (!tmp_addrs) {
				count = -ENOMEM;
				goto err_out_free;
			}
			*addrs = tmp_addrs;

			for (i = 0; i < st->idc->id_num; ++i) {
				dnet_setup_id(&(*ids)[count], g->group_id, st->idc->ids[i].raw.id);
				memcpy(&(*addrs)[count], dnet_state_addr(st), sizeof(struct dnet_addr));
				count++;
				//fprintf(stderr, "%d: %s -> %s\n", g->group_id, dnet_dump_id_str(st->idc->ids[i].raw.id), dnet_state_dump_addr(st));
			}
		}
	}
	pthread_mutex_unlock(&n->state_lock);

	return count;

err_out_free:
	if (ids)
		free(*ids);
	if (addrs)
		free(*addrs);

	return count;

}

void *dnet_bulk_read_wait_raw(struct dnet_node *n, struct dnet_id *id, struct dnet_io_attr *ios,
		uint32_t io_num, int cmd, uint32_t aflags, int *errp)
{
	struct dnet_io_control ctl;
	struct dnet_io_attr io;
	struct dnet_wait *w;
	struct dnet_read_data_completion *c;
	void *data = NULL;
	int err;

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

	ctl.cmd = cmd;
	ctl.cflags = DNET_FLAGS_NEED_ACK;

	ctl.aflags = aflags;
	if (ctl.aflags & DNET_ATTR_NOLOCK)
		ctl.cflags |= DNET_FLAGS_NOLOCK;

	memcpy(&ctl.id, id, sizeof(struct dnet_id));

	memset(&ctl.io, 0, sizeof(struct dnet_io_attr));

	memcpy(io.id, id->id, DNET_ID_SIZE);
	memcpy(io.parent, id->id, DNET_ID_SIZE);

	ctl.io.size = io_num * sizeof(struct dnet_io_attr);
	ctl.data = ios;

	dnet_wait_get(w);
	err = dnet_read_object(n, &ctl);
	if (err)
		goto err_out_put_complete;

	err = dnet_wait_event(w, w->cond, &n->wait_ts);
	if (err || w->status) {
		char id_str[2*DNET_ID_SIZE + 1];
		if (!err)
			err = w->status;
		if ((cmd != DNET_CMD_READ_RANGE) || (err != -ENOENT))
			dnet_log(n, DNET_LOG_ERROR, "%d:%s : failed to read data: %d\n",
				ctl.id.group_id, dnet_dump_id_len_raw(ctl.id.id, DNET_ID_SIZE, id_str), err);
		goto err_out_put_complete;
	}
	err = c->size;
	data = c->data;

err_out_put_complete:
	if (atomic_dec_and_test(&c->refcnt))
		free(c);
err_out_put:
	dnet_wait_put(w);
err_out_exit:
	*errp = err;
	return data;
}


static int dnet_io_attr_cmp(const void *d1, const void *d2)
{
	const struct dnet_io_attr *io1 = d1;
	const struct dnet_io_attr *io2 = d2;

	return memcmp(io1->id, io2->id, DNET_ID_SIZE);
} 

struct dnet_range_data *dnet_bulk_read(struct dnet_node *n, struct dnet_io_attr *ios, uint32_t io_num, int group_id, uint32_t aflags, int *errp)
{
	struct dnet_id id, next_id;
	int ret_num;
	struct dnet_range_data *ret;
	struct dnet_net_state *cur, *next = NULL;
	uint64_t size = 0;
	void *data;
	int err;
	uint32_t i, start = -1;

	if (io_num <= 0) {
		return 0;
	}

	qsort(ios, io_num, sizeof(struct dnet_io_attr), dnet_io_attr_cmp);

	ret = NULL;
	ret_num = 0;
	size = 0;

	dnet_setup_id(&id, group_id, ios[0].id);
	id.type = ios[0].type;

	cur = dnet_state_get_first(n, &id);
	if (!cur) {
		dnet_log(n, DNET_LOG_ERROR, "%s: Can't get state for id\n", dnet_dump_id(&id));
		err = -ENOENT;
		goto err_out_exit;
	}

	for (i = 0; i < io_num; ++i) {
		if ((i + 1) < io_num) {
			dnet_setup_id(&next_id, group_id, ios[i+1].id);
			next_id.type = ios[i+1].type;

			next = dnet_state_get_first(n, &next_id);
			if (!next) {
				dnet_log(n, DNET_LOG_ERROR, "%s: Can't get state for id\n", dnet_dump_id(&next_id));
				err = -ENOENT;
				goto err_out_put;
			}

			/* Send command only if state changes or it's a last id */
			if ((cur == next)) {
				dnet_state_put(next);
				next = NULL;
				continue;
			}
		}

		dnet_log(n, DNET_LOG_NOTICE, "start: %s: end: %s, count: %llu, addr: %s\n",
					dnet_dump_id(&id),
					dnet_dump_id(&next_id),
					(unsigned long long)(i - start),
					dnet_state_dump_addr(cur));

		data = dnet_bulk_read_wait_raw(n, &id, ios, i - start, DNET_CMD_BULK_READ, aflags, &err);
		if (data) {
			size = err;
			err = 0;

				if (!size) {
					free(data);
				} else {
					struct dnet_range_data *new_ret;

					ret_num++;

					new_ret = realloc(ret, ret_num * sizeof(struct dnet_range_data));
					if (!new_ret) {
						goto err_out_put;
					}

					ret = new_ret;

					ret[ret_num - 1].data = data;
					ret[ret_num - 1].size = size;
				}

				err = 0;
		}

		dnet_state_put(cur);
		cur = next;
		next = NULL;
		memcpy(&id, &next_id, sizeof(struct dnet_id));
	}

err_out_put:
	if (next)
		dnet_state_put(next);
	dnet_state_put(cur);
err_out_exit:
	if (ret) {
		*errp = ret_num;
	} else {
		*errp = err;
	}
	return ret;
}

struct dnet_range_data dnet_bulk_write(struct dnet_node *n, struct dnet_io_control *ctl, int ctl_num, int *errp)
{
	int err, i, trans_num = 0, local_trans_num;
	struct dnet_wait *w;
	struct dnet_write_completion *wc;
	struct dnet_range_data ret;
	struct dnet_metadata_control mcl;
	struct dnet_meta_container mc;
	struct dnet_io_control meta_ctl;
	struct timeval tv;
	int *groups = NULL;
	int group_num = 0;

	memset(&ret, 0, sizeof(ret));

	wc = malloc(sizeof(struct dnet_write_completion));
	if (!wc) {
		err = -ENOMEM;
		goto err_out_exit;
	}
	memset(wc, 0, sizeof(struct dnet_write_completion));

	w = dnet_wait_alloc(0);
	if (!w) {
		err = -ENOMEM;
		free(wc);
		goto err_out_exit;
	}
	wc->wait = w;

	atomic_set(&w->refcnt, INT_MAX);
	w->status = -ENOENT;

	for (i = 0; i < ctl_num; ++i) {
		ctl[i].priv = wc;
		ctl[i].complete = dnet_write_complete;
	
		ctl[i].cmd = DNET_CMD_WRITE;
		ctl[i].cflags = DNET_FLAGS_NEED_ACK;
		if (ctl[i].aflags & DNET_ATTR_NOLOCK)
			ctl[i].cflags |= DNET_FLAGS_NOLOCK;
	
		memcpy(ctl[i].io.id, ctl[i].id.id, DNET_ID_SIZE);
		memcpy(ctl[i].io.parent, ctl[i].id.id, DNET_ID_SIZE);
	
		local_trans_num = dnet_write_object(n, &ctl[i]);
		if (local_trans_num < 0)
			local_trans_num = 0;

		trans_num += local_trans_num;

		/* Prepare and send metadata */
		memset(&mcl, 0, sizeof(mcl));

		pthread_mutex_lock(&n->group_lock);
		group_num = n->group_num;
		groups = alloca(group_num * sizeof(int));

		memcpy(groups, n->groups, group_num * sizeof(int));
		pthread_mutex_unlock(&n->group_lock);

		mcl.groups = groups;
		mcl.group_num = group_num;
		mcl.id = ctl[i].id;
		mcl.aflags = ctl[i].aflags;

		gettimeofday(&tv, NULL);
		mcl.ts.tv_sec = tv.tv_sec;
		mcl.ts.tv_nsec = tv.tv_usec * 1000;

		memset(&mc, 0, sizeof(mc));

		err = dnet_create_metadata(n, &mcl, &mc);
		dnet_log(n, DNET_LOG_DSA, "Creating metadata: err: %d", err);
		if (!err) {
			dnet_convert_metadata(n, mc.data, mc.size);

			memset(&meta_ctl, 0, sizeof(struct dnet_io_control));

			meta_ctl.priv = wc;
			meta_ctl.complete = dnet_write_complete;
			meta_ctl.cmd = DNET_CMD_WRITE;
			meta_ctl.fd = -1;

			meta_ctl.aflags = ctl[i].aflags;
			meta_ctl.cflags = ctl[i].cflags;

			memcpy(&meta_ctl.id, &ctl[i].id, sizeof(struct dnet_id));
			memcpy(meta_ctl.io.id, ctl[i].id.id, DNET_ID_SIZE);
			memcpy(meta_ctl.io.parent, ctl[i].id.id, DNET_ID_SIZE);
			meta_ctl.id.type = meta_ctl.io.type = EBLOB_TYPE_META;
		
			meta_ctl.io.flags |= DNET_IO_FLAGS_META;
			meta_ctl.io.offset = 0;
			meta_ctl.io.size = mc.size;
			meta_ctl.data = mc.data;

			local_trans_num = dnet_write_object(n, &meta_ctl);
			if (local_trans_num < 0)
				local_trans_num = 0;

			trans_num += local_trans_num;
		}
	}

	/*
	 * 1 - the first reference counter we grabbed at allocation time
	 */
	atomic_sub(&w->refcnt, INT_MAX - trans_num - 1);

	err = dnet_wait_event(w, w->cond == trans_num, &n->wait_ts);
	if (err || w->status) {
		if (!err)
			err = w->status;
		dnet_log(n, DNET_LOG_NOTICE, "%s: failed to wait for IO write completion, err: %d, status: %d.\n",
				dnet_dump_id(&ctl->id), err, w->status);
	}

	if (err || !trans_num) {
		if (!err)
			err = -EINVAL;
		dnet_log(n, DNET_LOG_ERROR, "Failed to write data into the storage, err: %d, trans_num: %d.\n", err, trans_num);
		goto err_out_put;
	}

	if (trans_num)
		dnet_log(n, DNET_LOG_NOTICE, "%s: successfully wrote %llu bytes into the storage, reply size: %d.\n",
				dnet_dump_id(&ctl->id), (unsigned long long)ctl->io.size, wc->size);
	err = trans_num;

	ret.data = wc->reply;
	ret.size = wc->size;

	wc->reply = NULL;

err_out_put:
	dnet_write_complete_free(wc);
err_out_exit:
	*errp = err;
	return ret;
}
