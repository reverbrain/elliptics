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
#define __STDC_FORMAT_MACROS

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <sys/wait.h>

#include <alloca.h>
#include <assert.h>
#include <ctype.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <unistd.h>

#include "elliptics.h"

#include "elliptics/packet.h"
#include "elliptics/interface.h"

int dnet_transform_node(struct dnet_node *n, const void *src, uint64_t size, unsigned char *csum, int csize)
{
	struct dnet_transform *t = &n->transform;

	return t->transform(t->priv, NULL, src, size, csum, (unsigned int *)&csize, 0);
}

int dnet_transform_file(struct dnet_node *n, int fd, uint64_t offset, uint64_t size, char *csum, unsigned int csize)
{
	struct dnet_transform *t = &n->transform;

	return t->transform_file(t->priv, NULL, fd, offset, size, csum, (unsigned int *)&csize, 0);
}

int dnet_transform_raw(struct dnet_session *s, const void *src, uint64_t size, char *csum, unsigned int csize)
{
	struct dnet_node *n = s->node;
	struct dnet_transform *t = &n->transform;

	return t->transform(t->priv, s, src, size, csum, &csize, 0);
}

int dnet_transform(struct dnet_session *s, const void *src, uint64_t size, struct dnet_id *id)
{
	return dnet_transform_raw(s, src, size, (char *)id->id, sizeof(id->id));
}

static void dnet_indexes_transform_id(struct dnet_node *node, const uint8_t *src, uint8_t *id,
				      const char *suffix, int suffix_len)
{
	const size_t buffer_size = DNET_ID_SIZE + 32;
	char buffer[buffer_size];

	memcpy(buffer, src, DNET_ID_SIZE);
	memcpy(buffer + DNET_ID_SIZE, suffix, suffix_len);

	dnet_transform_node(node, buffer, DNET_ID_SIZE + suffix_len, id, DNET_ID_SIZE);
}

void dnet_indexes_transform_object_id(struct dnet_node *node, const struct dnet_id *src, struct dnet_id *id)
{
	char suffix[] = "\0object_table";

	dnet_indexes_transform_id(node, src->id, id->id, suffix, sizeof(suffix));
}

#ifdef WORDS_BIGENDIAN
#define dnet_swap32_to_be(x)
#else
#define dnet_swap32_to_be(x) \
     ((((x) & 0xff000000) >> 24) | (((x) & 0x00ff0000) >>  8) |		      \
      (((x) & 0x0000ff00) <<  8) | (((x) & 0x000000ff) << 24))
#endif

void dnet_indexes_transform_index_prepare(struct dnet_node *node, const struct dnet_raw_id *src, struct dnet_raw_id *id)
{
	char suffix[] = "\0index_table";

	dnet_indexes_transform_id(node, src->id, id->id, suffix, sizeof(suffix));

	memset(id->id, 0, DNET_ID_SIZE / 2);
}

void dnet_indexes_transform_index_id_raw(struct dnet_node *node, struct dnet_raw_id *id, int shard_id)
{
	unsigned shard_int = (1ull << 32) * shard_id / node->indexes_shard_count;

	// Convert to Big-Endian to set less-significant bytes to the begin
	*(unsigned *)id->id = dnet_swap32_to_be(shard_int);
}

void dnet_indexes_transform_index_id(struct dnet_node *node, const struct dnet_raw_id *src, struct dnet_raw_id *id, int shard_id)
{
	dnet_indexes_transform_index_prepare(node, src, id);
	dnet_indexes_transform_index_id_raw(node, id, shard_id);
}

int dnet_indexes_get_shard_id(struct dnet_node *node, const struct dnet_raw_id *object_id)
{
	int indexes_shard_count = node->indexes_shard_count;
	int i;
	int result = 0;

	for (i = 0; i < DNET_ID_SIZE; ++i) {
		result = (result * 256 + object_id->id[i]) % indexes_shard_count;
	}

	return result;
}

int dnet_node_get_indexes_shard_count(struct dnet_node *node)
{
	return node->indexes_shard_count;
}

static char *dnet_cmd_strings[] = {
	[DNET_CMD_LOOKUP] = "LOOKUP",
	[DNET_CMD_REVERSE_LOOKUP] = "REVERSE_LOOKUP",
	[DNET_CMD_JOIN] = "JOIN",
	[DNET_CMD_WRITE] = "WRITE",
	[DNET_CMD_READ] = "READ",
	[DNET_CMD_LIST_DEPRECATED] = "CHECK",
	[DNET_CMD_EXEC] = "EXEC",
	[DNET_CMD_ROUTE_LIST] = "ROUTE_LIST",
	[DNET_CMD_STAT_DEPRECATED] = "STAT",
	[DNET_CMD_NOTIFY] = "NOTIFY",
	[DNET_CMD_DEL] = "REMOVE",
	[DNET_CMD_STAT_COUNT_DEPRECATED] = "STAT_COUNT",
	[DNET_CMD_STATUS] = "STATUS",
	[DNET_CMD_READ_RANGE] = "READ_RANGE",
	[DNET_CMD_DEL_RANGE] = "DEL_RANGE",
	[DNET_CMD_AUTH] = "AUTH",
	[DNET_CMD_BULK_READ] = "BULK_READ",
	[DNET_CMD_DEFRAG_DEPRECATED] = "DEFRAG_DEPRECATED",
	[DNET_CMD_ITERATOR] = "ITERATOR",
	[DNET_CMD_INDEXES_UPDATE] = "INDEXES_UPDATE",
	[DNET_CMD_INDEXES_INTERNAL] = "INDEXES_INTERNAL",
	[DNET_CMD_INDEXES_FIND] = "INDEXES_FIND",
	[DNET_CMD_MONITOR_STAT] = "MONITOR_STAT",
	[DNET_CMD_UPDATE_IDS] = "UPDATE_IDS",
	[DNET_CMD_BACKEND_CONTROL] = "BACKEND_CONTROL",
	[DNET_CMD_BACKEND_STATUS] = "BACKEND_STATUS",
	[DNET_CMD_UNKNOWN] = "UNKNOWN",
};

char *dnet_cmd_string(int cmd)
{
	if (cmd <= 0 || cmd >= __DNET_CMD_MAX || cmd >= DNET_CMD_UNKNOWN)
		cmd = DNET_CMD_UNKNOWN;

	return dnet_cmd_strings[cmd];
}

const char *dnet_backend_state_string(uint32_t state)
{
	switch ((enum dnet_backend_state)state) {
		case DNET_BACKEND_ENABLED:
			return "enabled";
		case DNET_BACKEND_DISABLED:
			return "disabled";
		case DNET_BACKEND_ACTIVATING:
			return "activating";
		case DNET_BACKEND_DEACTIVATING:
			return "deactivating";
		default:
			return "unknown";
	}
}

const char *dnet_backend_defrag_state_string(uint32_t state)
{
	switch ((enum dnet_backend_defrag_state)state) {
		case DNET_BACKEND_DEFRAG_IN_PROGRESS:
			return "in-progress";
		case DNET_BACKEND_DEFRAG_NOT_STARTED:
			return "not-started";
		default:
			return "unknown";
	}
}

int dnet_copy_addrs_nolock(struct dnet_net_state *nst, struct dnet_addr *addrs, int addr_num)
{
	char addr_str[128];
	struct dnet_node *n = nst->n;
	int err = 0, i;

	if (nst->addrs) {
		// idx = -1 for just created server node, which can not have ->addrs yet
		dnet_log(n, DNET_LOG_NOTICE, "%s: do not copy %d addrs, already have %d, idx: %d",
				dnet_addr_string(&nst->addrs[nst->idx]),
				addr_num, nst->addr_num, nst->idx);
		goto err_out_exit;
	}

	nst->addrs = malloc(sizeof(struct dnet_addr) * addr_num);
	if (!nst->addrs) {
		err = -ENOMEM;
		goto err_out_exit;
	}

	nst->addr_num = addr_num;
	memcpy(nst->addrs, addrs, addr_num * sizeof(struct dnet_addr));

	dnet_addr_string_raw(dnet_state_addr(nst), addr_str, sizeof(addr_str));
	for (i = 0; i < addr_num; ++i) {
		dnet_log(n, DNET_LOG_NOTICE, "%s: copy addr: %s, idx: %d",
				addr_str,
				dnet_addr_string(&nst->addrs[i]),
				nst->idx);
	}

err_out_exit:
	return err;
}

struct dnet_route_list_control
{
	struct dnet_wait *w;
	struct dnet_addr *addrs;
	int addrs_num;
};

static inline void dnet_route_list_control_put(struct dnet_route_list_control *control)
{
	if (atomic_dec_and_test(&control->w->refcnt)) {
		free(control->addrs);
		dnet_wait_destroy(control->w);
		free(control);
	}
}

int dnet_recv_route_list(struct dnet_net_state *st, int (*complete)(struct dnet_addr *addr, struct dnet_cmd *cmd, void *priv), void *priv)
{
	struct dnet_io_req req;
	struct dnet_node *n = st->n;
	struct dnet_trans *t;
	struct dnet_cmd *cmd;
	int err;

	t = dnet_trans_alloc(n, sizeof(struct dnet_cmd));
	if (!t) {
		err = -ENOMEM;
		goto err_out_exit;
	}

	t->complete = complete;
	t->priv = priv;

	cmd = (struct dnet_cmd *)(t + 1);

	cmd->flags = DNET_FLAGS_NEED_ACK | DNET_FLAGS_DIRECT | DNET_FLAGS_NOLOCK;
	cmd->status = 0;

	memcpy(&t->cmd, cmd, sizeof(struct dnet_cmd));

	cmd->cmd = t->command = DNET_CMD_ROUTE_LIST;

	t->st = dnet_state_get(st);
	cmd->trans = t->rcv_trans = t->trans = atomic_inc(&n->trans);

	dnet_convert_cmd(cmd);

	dnet_log(n, DNET_LOG_DEBUG, "%s: list route request to %s.", dnet_dump_id(&cmd->id),
		dnet_addr_string(&st->addr));

	memset(&req, 0, sizeof(req));
	req.st = st;
	req.header = cmd;
	req.hsize = sizeof(struct dnet_cmd);

	err = dnet_trans_send(t, &req);
	if (err)
		goto err_out_destroy;

	return 0;

err_out_destroy:
	dnet_trans_put(t);
err_out_exit:
	return err;
}

static void dnet_io_trans_control_fill_cmd(struct dnet_session *s, const struct dnet_io_control *ctl, struct dnet_cmd *cmd)
{
	memcpy(&cmd->id, &ctl->id, sizeof(struct dnet_id));
	cmd->cmd = ctl->cmd;
	cmd->flags = ctl->cflags | dnet_session_get_cflags(s);
	cmd->trace_id = dnet_session_get_trace_id(s);
	cmd->status = 0;

	if (cmd->flags & DNET_FLAGS_DIRECT_BACKEND)
		cmd->backend_id = dnet_session_get_direct_backend(s);
}

static int dnet_io_trans_send_fail(struct dnet_session *s, struct dnet_addr *addr, struct dnet_io_control *ctl, int err, int destroy)
{
	struct dnet_cmd cmd;
	memset(&cmd, 0, sizeof(cmd));
	dnet_io_trans_control_fill_cmd(s, ctl, &cmd);

	cmd.status = err;
	cmd.size = 0;

	if (ctl->complete) {
		cmd.flags &= ~DNET_FLAGS_REPLY;

		ctl->complete(addr, &cmd, ctl->priv);

		if (destroy) {
			cmd.flags |= DNET_FLAGS_DESTROY;
			ctl->complete(addr, &cmd, ctl->priv);
		}
	}

	return 0;
}

void dnet_io_trans_alloc_send(struct dnet_session *s, struct dnet_io_control *ctl)
{
	struct dnet_node *n = s->node;
	struct dnet_io_req req;
	struct dnet_trans *t = NULL;
	struct dnet_io_attr *io;
	struct dnet_cmd *cmd;
	struct dnet_addr *request_addr = NULL;
	uint64_t size = ctl->io.size;
	uint64_t tsize = sizeof(struct dnet_io_attr) + sizeof(struct dnet_cmd);
	int err;

	if (ctl->cmd == DNET_CMD_READ)
		size = 0;

	t = dnet_trans_alloc(n, tsize);
	t->wait_ts = *dnet_session_get_timeout(s);
	if (!t) {
		err = -ENOMEM;
		goto err_out_complete;
	}
	t->complete = ctl->complete;
	t->priv = ctl->priv;

	cmd = (struct dnet_cmd *)(t + 1);
	io = (struct dnet_io_attr *)(cmd + 1);

	dnet_io_trans_control_fill_cmd(s, ctl, cmd);
	cmd->size = sizeof(struct dnet_io_attr) + size;

	t->command = cmd->cmd;

	memcpy(io, &ctl->io, sizeof(struct dnet_io_attr));
	memcpy(&t->cmd, cmd, sizeof(struct dnet_cmd));

	if ((s->cflags & DNET_FLAGS_DIRECT) == 0) {
		t->st = dnet_state_get_first(n, &cmd->id);
	} else {
		/* We're requested to execute request on particular node */
		request_addr = &s->direct_addr;
		t->st = dnet_state_search_by_addr(n, &s->direct_addr);
		if (!t->st) {
			dnet_log(n, DNET_LOG_ERROR, "%s: %s: io_trans_send: could not find network state for address",
				dnet_dump_id(&cmd->id), dnet_addr_string(&s->direct_addr));
		}
	}

	if (!t->st) {
		err = -ENXIO;
		goto err_out_destroy;
	}

	cmd->trans = t->rcv_trans = t->trans = atomic_inc(&n->trans);
	request_addr = dnet_state_addr(t->st);

	dnet_log(n, DNET_LOG_INFO, "%s: created trans: %llu, cmd: %s, cflags: %s, size: %llu, offset: %llu, "
			"fd: %d, local_offset: %llu -> %s weight: %f, wait-ts: %ld.",
			dnet_dump_id(&ctl->id),
			(unsigned long long)t->trans,
			dnet_cmd_string(ctl->cmd), dnet_flags_dump_cflags(cmd->flags),
			(unsigned long long)ctl->io.size, (unsigned long long)ctl->io.offset,
			ctl->fd,
			(unsigned long long)ctl->local_offset,
			dnet_addr_string(&t->st->addr), t->st->weight,
			t->wait_ts.tv_sec);

	dnet_convert_cmd(cmd);
	dnet_convert_io_attr(io);


	memset(&req, 0, sizeof(req));
	req.st = t->st;
	req.header = cmd;
	req.hsize = tsize;

	req.fd = ctl->fd;

	if (ctl->fd >= 0) {
		req.local_offset = ctl->local_offset;
		req.fsize = size;
	} else {
		req.data = (void *)ctl->data;
		req.dsize = size;
	}

	err = dnet_trans_send(t, &req);
	if (err)
		goto err_out_destroy;
	return;

err_out_complete:
	dnet_io_trans_send_fail(s, request_addr, ctl, err, 1);

err_out_destroy:
	dnet_io_trans_send_fail(s, request_addr, ctl, err, 0);
	dnet_trans_put(t);
}

int dnet_trans_create_send_all(struct dnet_session *s, struct dnet_io_control *ctl)
{
	int num = 0, i;

	for (i=0; i<s->group_num; ++i) {
		ctl->id.group_id = s->groups[i];

		dnet_io_trans_alloc_send(s, ctl);
		num++;
	}

	if (!num) {
		dnet_io_trans_alloc_send(s, ctl);
		num++;
	}

	return num;
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
	free(w);
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

int dnet_send_cmd(struct dnet_session *s,
	struct dnet_id *id,
	int (* complete)(struct dnet_addr *addr,
			struct dnet_cmd *cmd,
			void *priv),
	void *priv,
	struct sph *e)
{
	struct dnet_node *n = s->node;
	struct dnet_net_state *st;
	struct dnet_idc *idc;
	int num = 0, i, found_group;
	struct dnet_group *g;
	struct dnet_trans_control ctl;

	dnet_convert_sph(e);

	memset(&ctl, 0, sizeof(struct dnet_trans_control));

	ctl.size = sizeof(struct sph) + e->event_size + e->data_size;
	ctl.cmd = DNET_CMD_EXEC;
	ctl.complete = complete;
	ctl.priv = priv;
	ctl.cflags = DNET_FLAGS_NEED_ACK;
	ctl.data = e;

	/*
	 * FIXME
	 * We should iterate not over whole routing table and all groups ever received
	 * but only on those which are present in provided dnet_session
	 *
	 * This also concerns stat request and other broadcasting operations
	 */
	if (id && id->group_id != 0) {
		ctl.id = *id;

		st = dnet_state_get_first(n, &ctl.id);
		if (st) {
			e->addr = *dnet_state_addr(st);
			dnet_trans_alloc_send_state(s, st, &ctl);
			dnet_state_put(st);
			num = 1;
		} else {
			dnet_trans_send_fail(s, NULL, &ctl, -ENXIO, 1);
			num = 1;
		}
	} else if (id && id->group_id == 0) {
		ctl.id = *id;

		pthread_mutex_lock(&n->state_lock);
		for (i = 0; i < s->group_num; ++i) {
			ctl.id.group_id = s->groups[i];

			st = dnet_state_search_nolock(n, &ctl.id, NULL);
			if (st) {
				if (st != n->st) {
					e->addr = *dnet_state_addr(st);
					dnet_trans_alloc_send_state(s, st, &ctl);
					num++;
				}
				dnet_state_put(st);
			} else {
				dnet_trans_send_fail(s, NULL, &ctl, -ENXIO, 1);
				num++;
			}
		}
		pthread_mutex_unlock(&n->state_lock);
	} else {
		pthread_mutex_lock(&n->state_lock);
		list_for_each_entry(st, &n->dht_state_list, node_entry) {
			if (st == n->st)
				continue;

			list_for_each_entry(idc, &st->idc_list, state_entry) {
				g = idc->group;

				found_group = 0;
				for (i = 0; i < s->group_num; ++i) {
					found_group |= ((unsigned)s->groups[i] == g->group_id);
				}
				if (!found_group)
					continue;

				dnet_setup_id(&ctl.id, g->group_id, idc->ids[0].raw.id);
				memcpy(e->src.id, idc->ids[0].raw.id, DNET_ID_SIZE);
				e->addr = *dnet_state_addr(st);
				dnet_trans_alloc_send_state(s, st, &ctl);
				num++;

				break;
			}
		}
		pthread_mutex_unlock(&n->state_lock);
	}

	return num;
}

struct dnet_addr *dnet_state_addr(struct dnet_net_state *st)
{
	return &st->addr;
}

int dnet_version_compare(struct dnet_net_state *st, int *version)
{
	size_t i;

	for (i = 0; i < 4; ++i) {
		if (st->version[i] != version[i]) {
			return st->version[i] - version[i];
		}
	}

	return 0;
}

static int dnet_request_cmd_single(struct dnet_session *s, struct dnet_net_state *st, struct dnet_trans_control *ctl)
{
	if (st)
		return dnet_trans_alloc_send_state(s, st, ctl);
	else
		return dnet_trans_alloc_send(s, ctl);
}

int dnet_request_cmd(struct dnet_session *s, struct dnet_trans_control *ctl)
{
	struct dnet_node *n = s->node;
	int num = 0;
	struct dnet_net_state *st;
	struct dnet_idc *idc;
	struct rb_node *it;
	struct dnet_group *g;
	struct timeval start, end;
	long diff;

	gettimeofday(&start, NULL);

	pthread_mutex_lock(&n->state_lock);
	for (it = rb_first(&n->group_root); it; it = rb_next(it)) {
		g = rb_entry(it, struct dnet_group, group_entry);
		list_for_each_entry(idc, &g->idc_list, group_entry) {
			st = idc->st;
			if (st == n->st)
				continue;

			ctl->id.group_id = g->group_id;

			if (!(ctl->cflags & DNET_FLAGS_DIRECT))
				dnet_setup_id(&ctl->id, idc->group->group_id, idc->ids[0].raw.id);
			if (ctl->cflags & DNET_FLAGS_DIRECT_BACKEND)
				dnet_session_set_direct_backend(s, idc->backend_id);

			dnet_request_cmd_single(s, st, ctl);
			num++;
		}
	}
	pthread_mutex_unlock(&n->state_lock);

	gettimeofday(&end, NULL);
	diff = (end.tv_sec - start.tv_sec) * 1000000 + end.tv_usec - start.tv_usec;
	dnet_log(n, DNET_LOG_NOTICE, "request cmd: %s: %ld usecs, num: %d.", dnet_cmd_string(ctl->cmd), diff, num);

	return num;
}

struct dnet_update_status_priv {
	struct dnet_wait *w;
	struct dnet_node_status status;
	atomic_t refcnt;
};

int dnet_request_cmd_addr(struct dnet_session *s, struct dnet_addr *addr, struct dnet_trans_control *ctl)
{
	struct dnet_net_state *st;
	int err;

	st = dnet_state_search_by_addr(s->node, addr);
	if (!st) {
		dnet_log(s->node, DNET_LOG_ERROR, "%s: %s: request_cmd_addr: could not find network state for address",
			dnet_dump_id(&ctl->id), dnet_addr_string(addr));
		return -ENXIO;
	}

	err = dnet_request_cmd_single(s, st, ctl);

	dnet_state_put(st);

	if (err)
		return err;
	else
		return 1;
}

static int dnet_update_status_complete(struct dnet_addr *addr __unused, struct dnet_cmd *cmd, void *priv)
{
	struct dnet_update_status_priv *p = priv;

	if (is_trans_destroyed(cmd)) {
		int err = -ENOENT;
		if (cmd)
			err = cmd->status;

		dnet_wakeup(p->w, p->w->cond++);
		dnet_wait_put(p->w);
		if (atomic_dec_and_test(&p->refcnt)) {
			free(p);
		}

		return err;
	}

	if (cmd->size == sizeof(struct dnet_node_status)) {
		memcpy(&p->status, cmd + 1, sizeof(struct dnet_node_status));
		return 0;
	}

	return -ENOENT;
}

int dnet_update_status(struct dnet_session *s, const struct dnet_addr *addr, struct dnet_id *id, struct dnet_node_status *status)
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
		struct dnet_idc *idc;

		st = dnet_state_search_by_addr(s->node, addr);
		if (!st) {
			err = -ENXIO;
			dnet_log(s->node, DNET_LOG_ERROR, "%s: %s: update_state: could not find network state for address",
				dnet_dump_id(&ctl.id), dnet_addr_string(addr));
		}

		pthread_mutex_lock(&st->n->state_lock);

		if (list_empty(&st->idc_list)) {
			pthread_mutex_unlock(&st->n->state_lock);

			err = -ENXIO;
			goto err_out_exit;
		}

		idc = list_first_entry(&st->idc_list, struct dnet_idc, state_entry);
		dnet_setup_id(&ctl.id, idc->group->group_id, idc->ids[0].raw.id);

		pthread_mutex_unlock(&st->n->state_lock);

		dnet_state_put(st);
	}

	priv = malloc(sizeof(struct dnet_update_status_priv));
	if (!priv) {
		err = -ENOMEM;
		goto err_out_exit;
	}

	atomic_init(&priv->refcnt, 1);

	priv->w = dnet_wait_alloc(0);
	if (!priv->w) {
		err = -ENOMEM;
		goto err_out_free;
	}

	ctl.complete = dnet_update_status_complete;
	ctl.priv = priv;
	ctl.cmd = DNET_CMD_STATUS;
	ctl.cflags = DNET_FLAGS_NEED_ACK;
	ctl.size = sizeof(struct dnet_node_status);
	ctl.data = status;

	dnet_wait_get(priv->w);
	atomic_inc(&priv->refcnt);

	dnet_request_cmd_single(s, NULL, &ctl);

	err = dnet_wait_event(priv->w, priv->w->cond == 1, dnet_session_get_timeout(s));
	dnet_wait_put(priv->w);
	if (!err && priv) {
		memcpy(status, &priv->status, sizeof(struct dnet_node_status));
	}

err_out_free:
	if (atomic_dec_and_test(&priv->refcnt))
		free(priv);

err_out_exit:
	return err;
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

int dnet_lookup_addr(struct dnet_session *s, const void *remote, int len, const struct dnet_id *id, int group_id,
		struct dnet_addr *addr, int *backend_id)
{
	struct dnet_node *n = s->node;
	struct dnet_id raw;
	struct dnet_net_state *st;
	int err = -ENXIO;

	if (!id) {
		dnet_transform(s, remote, len, &raw);
	} else {
		raw = *id;
	}
	raw.group_id = group_id;

	st = dnet_state_get_first_with_backend(n, &raw, backend_id);
	if (!st)
		goto err_out_exit;

	*addr = *dnet_state_addr(st);
	dnet_state_put(st);
	err = 0;

err_out_exit:
	return err;

}

struct dnet_weight {
	double			weight;
	int			group_id;
};

static int dnet_weight_compare(const void *v1, const void *v2)
{
	const struct dnet_weight *w1 = v1;
	const struct dnet_weight *w2 = v2;

	if (w2->weight > w1->weight)
		return 1;
	if (w2->weight < w1->weight)
		return -1;

	return 0;
}

static int dnet_weight_get_winner(struct dnet_weight *w, int num)
{
	double r, pos, sum = 0;
	int i;

	for (i = 0; i < num; ++i)
		sum += w[i].weight;

	/*
	 * Small state weights will be summed into quite small value,
	 * random generator will not be able to produce a value
	 * with enough bits of entropy. In some cases @pos below
	 * will always be zero ending up always selecting the first node.
	 *
	 * This simple algorithm increases all weights until they sum up
	 * to the large enough range.
	 */
	while (sum && sum < 1000) {
		double mult = 10.0;

		sum *= mult;
		for (i = 0; i < num; ++i)
			w[i].weight *= mult;
	}

	r = (double)rand() / (double)RAND_MAX;
	pos = r * sum;

	for (i = 0; i < num; ++i) {
		pos -= w[i].weight;
		if (pos <= 0)
			return i;
	}

	return num - 1;
}

int dnet_mix_states(struct dnet_session *s, struct dnet_id *id, int **groupsp)
{
	struct dnet_node *n = s->node;
	struct dnet_weight *weights;
	int *groups;
	int group_num, i, num;
	struct dnet_net_state *st;

	if (!s->group_num)
		return -ENXIO;

	group_num = s->group_num;

	weights = alloca(s->group_num * sizeof(*weights));
	groups = malloc(s->group_num * sizeof(*groups));
	if (groups)
		memcpy(groups, s->groups, s->group_num * sizeof(*groups));

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
		if (!(n->flags & DNET_CFG_MIX_STATES) || !id) {
			*groupsp = groups;
			return group_num;
		}

		memset(weights, 0, group_num * sizeof(*weights));

		for (i = 0, num = 0; i < group_num; ++i) {
			id->group_id = groups[i];

			st = dnet_state_get_first(n, id);
			if (st) {
				weights[num].weight = st->weight;
				weights[num].group_id = id->group_id;

				dnet_state_put(st);

				num++;
			}
		}
	}

	if (num == 0) {
		free(groups);
		return -ENXIO;
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

	*groupsp = groups;
	return group_num;
}

static int dnet_data_map_ll(struct dnet_map_fd *map, int prot)
{
	uint64_t off;
	long page_size = sysconf(_SC_PAGE_SIZE);
	int err = 0;

	if (map == NULL || prot == 0)
		return -EINVAL;

	off = map->offset & ~(page_size - 1);
	map->mapped_size = ALIGN(map->size + map->offset - off, page_size);

	map->mapped_data = mmap(NULL, map->mapped_size, prot, MAP_SHARED, map->fd, off);
	if (map->mapped_data == MAP_FAILED) {
		err = -errno;
		goto err_out_exit;
	}

	map->data = map->mapped_data + map->offset - off;

err_out_exit:
	return err;
}

int dnet_data_map_rw(struct dnet_map_fd *map)
{
	return dnet_data_map_ll(map, PROT_READ|PROT_WRITE);
}

int dnet_data_map(struct dnet_map_fd *map)
{
	return dnet_data_map_ll(map, PROT_READ);
}

void dnet_data_unmap(struct dnet_map_fd *map)
{
	munmap(map->mapped_data, map->mapped_size);
}

int dnet_get_routes(struct dnet_session *s, struct dnet_route_entry **entries) {

	struct dnet_node *n = s->node;
	struct dnet_net_state *st;
	struct dnet_idc *idc;
	struct dnet_route_entry *tmp_entries;
	struct dnet_route_entry *entry;
	int size = 0, count = 0, err = 0;
	int i;

	*entries = NULL;

	pthread_mutex_lock(&n->state_lock);
	list_for_each_entry(st, &n->dht_state_list, node_entry) {
		list_for_each_entry(idc, &st->idc_list, state_entry) {

			size += idc->id_num;

			tmp_entries = (struct dnet_route_entry *)realloc(*entries, size * sizeof(struct dnet_route_entry));
			if (!tmp_entries) {
				err = -ENOMEM;
				goto err_out_free;
			}
			*entries = tmp_entries;

			for (i = 0; i < idc->id_num; ++i) {
				entry = &(*entries)[count++];

				memcpy(entry->id.id, idc->ids[i].raw.id, DNET_ID_SIZE);
				memcpy(&entry->addr, dnet_state_addr(st), sizeof(struct dnet_addr));
				entry->group_id = idc->group->group_id;
				entry->backend_id = idc->backend_id;
			}
			dnet_log(n, DNET_LOG_INFO, "%s: %s, group: %d, backend: %d, idc: %p",
				dnet_state_dump_addr(st), dnet_dump_id_str(idc->ids[0].raw.id),
				idc->group->group_id, idc->backend_id, idc);
		}
	}
	pthread_mutex_unlock(&n->state_lock);

	return count;

err_out_free:
	if (entries)
		free(*entries);

	return err;

}

int dnet_flags(struct dnet_node *n)
{
	return n->flags;
}

/*!
 * Compares responses firt by key, then by timestamp
 */
static int dnet_iterator_response_cmp(const void *r1, const void *r2)
{
	const struct dnet_iterator_response *a = r1, *b = r2;
	int diff = dnet_id_cmp_str(a->key.id, b->key.id);

	if (diff == 0) {
		diff = dnet_time_cmp(&b->timestamp, &a->timestamp);
		if (diff == 0) {
			if (a->size > b->size)
				diff = -1;
			if(a->size < b->size)
				diff = 1;
		}
	}

	return diff;
}

/*!
 * Sort responses using \fn dnet_iterator_response_cmp
 */
int dnet_iterator_response_container_sort(int fd, size_t size)
{
	struct dnet_map_fd map = { .fd = fd, .size = size };
	const ssize_t resp_size = sizeof(struct dnet_iterator_response);
	const size_t nel = size / resp_size;
	int err;

	/* Sanity */
	if (fd < 0)
		return -EINVAL;
	if (size % resp_size != 0)
		return -EINVAL;

	/* If size is zero - it's already sorted */
	if (size == 0)
		return 0;

	posix_fadvise(fd, 0, 0, POSIX_FADV_WILLNEED);

	if ((err = dnet_data_map_rw(&map)) != 0)
		return err;
	qsort(map.data, nel, resp_size, dnet_iterator_response_cmp);
	dnet_data_unmap(&map);

	posix_fadvise(fd, 0, 0, POSIX_FADV_SEQUENTIAL);

	return 0;
}

/*!
 * Appends one dnet_iterator_response to fd
 */
int dnet_iterator_response_container_append(const struct dnet_iterator_response *response,
		int fd, uint64_t pos)
{
	struct dnet_iterator_response copy;
	const ssize_t resp_size = sizeof(struct dnet_iterator_response);
	ssize_t err;

	/* Sanity */
	if (pos % resp_size != 0)
		return -EINVAL;
	if (response == NULL)
		return -EINVAL;

	copy = *response;
	dnet_convert_iterator_response(&copy);
	if ((err = pwrite(fd, &copy, resp_size, pos)) != resp_size)
		return (err == -1) ? -errno : -EINTR;

	return 0;
}

/*!
 * Reads one dnet_iterator_response from \a fd at position \a pos and stores it
 * in \a response
 */
int dnet_iterator_response_container_read(int fd, uint64_t pos,
		struct dnet_iterator_response *response)
{
	const ssize_t resp_size = sizeof(struct dnet_iterator_response);
	ssize_t err;

	/* Sanity */
	if (fd < 0 || response == NULL)
		return -EINVAL;
	if (pos % resp_size != 0)
		return -EINVAL;

	if ((err = pread(fd, response, resp_size, pos)) != resp_size)
		return (err == -1) ? -errno : -EINTR;
	dnet_convert_iterator_response(response);

	return 0;
}

/*!
 * Shifts offset and skips response with equal keys.
 */
static inline void dnet_iterator_response_skip_equal_keys(const struct dnet_iterator_response *resp,
		uint64_t *offset, uint64_t size)
{
	const ssize_t resp_size = sizeof(struct dnet_iterator_response);
	uint64_t next_offset = *offset + resp_size;

	while (next_offset < size) {
		const uint64_t current_pos = *offset / resp_size;
		const uint64_t next_pos = next_offset / resp_size;
		const struct dnet_iterator_response *curr = resp + current_pos;
		const struct dnet_iterator_response *next = resp + next_pos;

		if (dnet_id_cmp_str(curr->key.id, next->key.id))
			break;

		*offset += resp_size;
		next_offset += resp_size;
	}

	*offset += resp_size;
}

/*!
 * Computes difference for two containers and writes it to diff_fd.
 * Returns size of new container.
 *
 * NB! For now only right outer difference is supported, so returned container
 * has only items that exist only in right, or exist in both but right one is
 * newer (w.r.t. timestamp).
 */
int64_t dnet_iterator_response_container_diff(int diff_fd, int left_fd, uint64_t left_size,
		int right_fd, uint64_t right_size)
{
	struct dnet_map_fd left_map = { .fd = left_fd, .size = left_size };
	struct dnet_map_fd right_map = { .fd = right_fd, .size = right_size };
	const ssize_t resp_size = sizeof(struct dnet_iterator_response);
	uint64_t left_offset = 0, right_offset = 0;
	int64_t diff_offset = 0, err = 0;

	/* Sanity */
	if (diff_fd < 0 || left_fd < 0 || right_fd < 0)
		return -EINVAL;
	if (left_size % resp_size != 0)
		return -EINVAL;
	if (right_size % resp_size != 0)
		return -EINVAL;

	/* mmap both containers */
	if ((err = dnet_data_map(&left_map)) != 0)
		goto err;
	if ((err = dnet_data_map(&right_map)) != 0)
		goto err_unmap_left;

	/*
	 * Compute difference between two sorted lists.
	 * - We add elements from right list to diff until they are than
	 *   current element in left list;
	 * - We skip elements in left list until they are ge then current
	 * element in right one;
	 * - In case elements are equal skip both.
	 */
	while (right_offset < right_size) {
		const uint64_t left_pos = left_offset / resp_size;
		const uint64_t right_pos = right_offset / resp_size;
		const struct dnet_iterator_response *left =
			(struct dnet_iterator_response *)left_map.data + left_pos;
		const struct dnet_iterator_response *right =
			(struct dnet_iterator_response *)right_map.data + right_pos;
		const int cmp_id = dnet_id_cmp_str(left->key.id, right->key.id);
		const int cmp = dnet_iterator_response_cmp(left, right);

		if (left_offset < left_size && cmp <= 0) {
			/*
			 * If we can move left pointer and left key is less or
			 * same but with lesser timestamp we skip record.
			 */
			dnet_iterator_response_skip_equal_keys(left_map.data, &left_offset, left_size);

			/* For same key we move both pointers */
			if (cmp_id == 0)
				dnet_iterator_response_skip_equal_keys(right_map.data, &right_offset, right_size);
		} else {
			/*
			 * If we can move left pointer or left key is greater
			 * or same but less timestamp we add record to
			 * differene because it should be recovered.
			 */
			err = dnet_iterator_response_container_append(right, diff_fd, diff_offset);
			if (err != 0)
				goto err_unmap_right;
			diff_offset += resp_size;

			dnet_iterator_response_skip_equal_keys(right_map.data, &right_offset, right_size);

			/* For same key we move both pointers */
			if (cmp_id == 0 && left_offset < left_size)
				dnet_iterator_response_skip_equal_keys(left_map.data, &left_offset, left_size);
		}
		assert(left_offset <= left_size);
		assert(diff_offset <= (int64_t)right_size);
	}
	assert(right_offset == right_size);

err_unmap_right:
	dnet_data_unmap(&right_map);
err_unmap_left:
	dnet_data_unmap(&left_map);
err:
	return err ? err : diff_offset;
}

int dnet_parse_numeric_id(const char *value, unsigned char *id)
{
	unsigned char ch[5];
	unsigned int i, len = strlen(value);

	memset(id, 0, DNET_ID_SIZE);

	if (len/2 > DNET_ID_SIZE)
		len = DNET_ID_SIZE * 2;

	ch[0] = '0';
	ch[1] = 'x';
	ch[4] = '\0';
	for (i=0; i<len / 2; i++) {
		ch[2] = value[2*i + 0];
		ch[3] = value[2*i + 1];

		id[i] = (unsigned char)strtol((const char *)ch, NULL, 16);
	}

	if (len & 1) {
		ch[2] = value[2*i + 0];
		ch[3] = '0';

		id[i] = (unsigned char)strtol((const char *)ch, NULL, 16);
	}

	return 0;
}

/* Verify that this state transition is valid */
static int dnet_iterator_verify_state(enum dnet_iterator_action from,
		enum dnet_iterator_action to)
{
	/*
	 * Allowed transitions:
	 *	started	-> paused
	 *	started -> canceled
	 *	paused	-> started
	 *	paused	-> canceled
	 */
	if (from == DNET_ITERATOR_ACTION_START &&
			to == DNET_ITERATOR_ACTION_PAUSE)
		return 0;
	if (from == DNET_ITERATOR_ACTION_START &&
			to == DNET_ITERATOR_ACTION_CANCEL)
		return 0;
	if (from == DNET_ITERATOR_ACTION_PAUSE &&
			to == DNET_ITERATOR_ACTION_START)
		return 0;
	if (from == DNET_ITERATOR_ACTION_PAUSE &&
			to == DNET_ITERATOR_ACTION_CANCEL)
		return 0;
	return 1;
}

/* Sets state of iterator given it's id */
static int dnet_iterator_set_state_nolock(struct dnet_node *n,
		enum dnet_iterator_action action, uint64_t id)
{
	struct dnet_iterator *it;
	int err;

	it = dnet_iterator_list_lookup_nolock(n, id);
	if (it == NULL) {
		err = -ENOENT;
		goto err_out_exit;
	}

	pthread_mutex_lock(&it->lock);

	/* We don't want to have two different names for the same thing */
	if (action == DNET_ITERATOR_ACTION_CONTINUE)
		action = DNET_ITERATOR_ACTION_START;

	/* Check that transition is valid */
	if ((err = dnet_iterator_verify_state(it->state, action)) != 0)
		goto err_out_unlock_it;

	/* Wake up iterator thread */
	if (it->state == DNET_ITERATOR_ACTION_PAUSE)
		if ((err = pthread_cond_broadcast(&it->wait)) != 0)
			goto err_out_unlock_it;

	/* Set iterator desired state */
	it->state = action;

	pthread_mutex_unlock(&it->lock);

	return 0;

err_out_unlock_it:
	pthread_mutex_unlock(&it->lock);
err_out_exit:
	return err;
}

/* Sets state of iterator given it's id */
int dnet_iterator_set_state(struct dnet_node *n,
		enum dnet_iterator_action action, uint64_t id)
{
	int err;

	/* Sanity */
	if (n == NULL)
		return -EINVAL;
	if (action <= DNET_ITERATOR_ACTION_FIRST
			|| action >= DNET_ITERATOR_ACTION_LAST)
		return -EINVAL;

	pthread_mutex_lock(&n->iterator_lock);
	err = dnet_iterator_set_state_nolock(n, action, id);
	pthread_mutex_unlock(&n->iterator_lock);

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
	it->state = DNET_ITERATOR_ACTION_START;
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
void dnet_iterator_free(struct dnet_iterator *it)
{
	/* Sanity */
	if (it == NULL)
		return;

	pthread_cond_destroy(&it->wait);
	pthread_mutex_destroy(&it->lock);
	free(it);
}

/* Adds iterator to the list of running iterators if it's not already there */
int dnet_iterator_list_insert_nolock(struct dnet_node *n, struct dnet_iterator *it)
{
	/* Sanity */
	if (n == NULL || it == NULL)
		return -EINVAL;

	/* Check that iterator not already in list */
	if (dnet_iterator_list_lookup_nolock(n, it->id) != NULL)
		return -EEXIST;

	/* Add to list */
	list_add(&it->list, &n->iterator_list);

	return 0;
}

/* Looks up iterator in list by id */
struct dnet_iterator *dnet_iterator_list_lookup_nolock(struct dnet_node *n, uint64_t id)
{
	struct dnet_iterator *it;

	/* Sanity */
	if (n == NULL)
		return NULL;

	/* Lookup iterator by id and return pointer */
	list_for_each_entry(it, &n->iterator_list, list)
		if (it->id == id)
			return it;

	return NULL;
}

/* Removes iterator from list by id */
int dnet_iterator_list_remove(struct dnet_node *n, uint64_t id)
{
	struct dnet_iterator *it;

	/* Sanity */
	if (n == NULL)
		return -EINVAL;

	pthread_mutex_lock(&n->iterator_lock);

	/* Lookup iterator by id and remove */
	it = dnet_iterator_list_lookup_nolock(n, id);
	if (it != NULL) {
		list_del_init(&it->list);
		pthread_mutex_unlock(&n->iterator_lock);
		return 0;
	}

	pthread_mutex_unlock(&n->iterator_lock);

	return -ENOENT;
}

/* Find next free id */
uint64_t dnet_iterator_list_next_id_nolock(struct dnet_node *n)
{
	uint64_t next;

	assert(n != NULL);
	for (next = 0; next != -1ULL; ++next)
		if (dnet_iterator_list_lookup_nolock(n, next) == NULL)
			return next;
	return -1ULL;
}

/* Creates iterator and adds it to list */
struct dnet_iterator *dnet_iterator_create(struct dnet_node *n)
{
	struct dnet_iterator *it;
	uint64_t id;
	int err;

	/* Sanity */
	if (n == NULL)
		goto err;

	pthread_mutex_lock(&n->iterator_lock);

	/* Create new iterator and add it to list */
	id = dnet_iterator_list_next_id_nolock(n);
	if (id == -1ULL)
		goto err_unlock;
	it = dnet_iterator_alloc(id);
	if (it == NULL)
		goto err_unlock;
	err = dnet_iterator_list_insert_nolock(n, it);
	if (err)
		goto err_free;

	pthread_mutex_unlock(&n->iterator_lock);

	return it;

err_free:
	dnet_iterator_free(it);
err_unlock:
	pthread_mutex_unlock(&n->iterator_lock);
err:
	return NULL;
}

/* Remove iterator from list and free resources */
void dnet_iterator_destroy(struct dnet_node *n, struct dnet_iterator *it)
{
	/* Sanity */
	if (n == NULL || it == NULL)
		return;

	(void)dnet_iterator_list_remove(n, it->id);
	dnet_iterator_free(it);
}

/* Async cancel all iterators */
void dnet_iterator_cancel_all(struct dnet_node *n)
{
	struct dnet_iterator *it;

	/* Sanity */
	if (n == NULL)
		return;

	pthread_mutex_lock(&n->iterator_lock);
	list_for_each_entry(it, &n->iterator_list, list)
		dnet_iterator_set_state_nolock(n, DNET_ITERATOR_ACTION_CANCEL, it->id);
	pthread_mutex_unlock(&n->iterator_lock);

}

int *dnet_version(struct dnet_net_state *state)
{
	return state->version;
}

int dnet_version_check(struct dnet_net_state *st, int *version)
{
	struct dnet_node *n = st->n;
	int err = 0;

	if ((version[0] == CONFIG_ELLIPTICS_VERSION_0) && (version[1] == CONFIG_ELLIPTICS_VERSION_1)) {
		dnet_log(n, DNET_LOG_INFO, "%s: reverse lookup command: network version: %d.%d.%d.%d, local version: %d.%d.%d.%d",
				dnet_state_dump_addr(st),
				version[0], version[1], version[2], version[3],
				CONFIG_ELLIPTICS_VERSION_0, CONFIG_ELLIPTICS_VERSION_1,
				CONFIG_ELLIPTICS_VERSION_2, CONFIG_ELLIPTICS_VERSION_3);
	} else {
		dnet_log(n, DNET_LOG_ERROR, "%s: reverse lookup command: VERSION MISMATCH: "
				"network version: %d.%d.%d.%d, local version: %d.%d.%d.%d",
				dnet_state_dump_addr(st),
				version[0], version[1], version[2], version[3],
				CONFIG_ELLIPTICS_VERSION_0, CONFIG_ELLIPTICS_VERSION_1,
				CONFIG_ELLIPTICS_VERSION_2, CONFIG_ELLIPTICS_VERSION_3);
		err = -EPROTO;
	}

	return err;
}

#if defined HAVE_PROC_STAT
int dnet_get_vm_stat(dnet_logger *l, struct dnet_vm_stat *st) {
	int err;
	FILE *f;
	float la[3];
	unsigned long long stub;

	memset(st, 0, sizeof(struct dnet_vm_stat));

	f = fopen("/proc/loadavg", "r");
	if (!f) {
		err = -errno;
		dnet_log_only_log(l, DNET_LOG_ERROR, "Failed to open '/proc/loadavg': %s [%d].",
		                 strerror(errno), errno);
		goto err_out_exit;
	}

	err = fscanf(f, "%f %f %f", &la[0], &la[1], &la[2]);
	if (err != 3) {
		err = -errno;
		if (!err)
			err = -EINVAL;

		dnet_log_only_log(l, DNET_LOG_ERROR, "Failed to read load average data: %s [%d].",
		                 strerror(errno), errno);
		goto err_out_close;
	}

	st->la[0] = la[0] * 100;
	st->la[1] = la[1] * 100;
	st->la[2] = la[2] * 100;

	fclose(f);

	f = fopen("/proc/meminfo", "r");
	if (!f) {
		err = -errno;
		dnet_log_only_log(l, DNET_LOG_ERROR, "Failed to open '/proc/meminfo': %s [%d].",
		                 strerror(errno), errno);
		goto err_out_exit;
	}

	err = fscanf(f, "MemTotal:%llu kB\n", (unsigned long long *)&st->vm_total);
	err = fscanf(f, "MemFree:%llu kB\n", (unsigned long long *)&st->vm_free);
	err = fscanf(f, "Buffers:%llu kB\n", (unsigned long long *)&st->vm_buffers);
	err = fscanf(f, "Cached:%llu kB\n", (unsigned long long *)&st->vm_cached);
	err = fscanf(f, "SwapCached:%llu kB\n", (unsigned long long *)&stub);
	err = fscanf(f, "Active:%llu kB\n", (unsigned long long *)&st->vm_active);
	err = fscanf(f, "Inactive:%llu kB\n", (unsigned long long *)&st->vm_inactive);

	fclose(f);
	return 0;

err_out_close:
	fclose(f);
err_out_exit:
	return err;
}
#elif defined HAVE_SYSCTL_STAT
#include <sys/sysctl.h>
#include <sys/resource.h>

int dnet_get_vm_stat(dnet_logger *l, struct dnet_vm_stat *st) {
	int err;
	struct loadavg la;
	long page_size = 0;
	size_t sz = sizeof(la);

	memset(st, 0, sizeof(struct dnet_vm_stat));

	err = sysctlbyname("vm.loadavg", &la, &sz, NULL, 0);
	if (err) {
		err = -errno;
		dnet_log_only_log(l, DNET_LOG_ERROR, "Failed to get load average data: %s [%d].",
				strerror(errno), errno);
		return err;
	}

	st->la[0] = (double)la.ldavg[0] / la.fscale * 100;
	st->la[1] = (double)la.ldavg[1] / la.fscale * 100;
	st->la[2] = (double)la.ldavg[2] / la.fscale * 100;

	sz = sizeof(uint64_t);
	sysctlbyname("vm.stats.vm.v_active_count", &st->vm_active, &sz, NULL, 0);
	sz = sizeof(uint64_t);
	sysctlbyname("vm.stats.vm.v_inactive_count", &st->vm_inactive, &sz, NULL, 0);
	sz = sizeof(uint64_t);
	sysctlbyname("vm.stats.vm.v_cache_count", &st->vm_cached, &sz, NULL, 0);
	sz = sizeof(uint64_t);
	sysctlbyname("vm.stats.vm.v_free_count", &st->vm_free, &sz, NULL, 0);
	sz = sizeof(uint64_t);
	sysctlbyname("vm.stats.vm.v_wire_count", &st->vm_buffers, &sz, NULL, 0);
	sz = sizeof(uint64_t);
	sysctlbyname("vm.stats.vm.v_page_count", &st->vm_total, &sz, NULL, 0);
	sz = sizeof(page_size);
	sysctlbyname("vm.stats.vm.v_page_size", &page_size, &sz, NULL, 0);

	page_size /= 1024;

	st->vm_total *= page_size;
	st->vm_active *= page_size;
	st->vm_inactive *= page_size;
	st->vm_free *= page_size;
	st->vm_cached *= page_size;
	st->vm_buffers *= page_size;

	return 0;
}
#else
int dnet_get_vm_stat(dnet_logger *l __unused, struct dnet_vm_stat *st) {
	memset(st, 0, sizeof(struct dnet_vm_stat));
	return 0;
}
#endif
