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

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "elliptics.h"
#include "elliptics/packet.h"
#include "elliptics/interface.h"

static inline int dnet_trans_cmp(uint64_t old, uint64_t new)
{
	if (old > new)
		return 1;
	if (old < new)
		return -1;
	return 0;
}

struct dnet_trans *dnet_trans_search(struct rb_root *root, uint64_t trans)
{
	struct rb_node *n = root->rb_node;
	struct dnet_trans *t = NULL;
	int cmp = 1;

	while (n) {
		t = rb_entry(n, struct dnet_trans, trans_entry);

		cmp = dnet_trans_cmp(t->trans, trans);
		if (cmp < 0)
			n = n->rb_left;
		else if (cmp > 0)
			n = n->rb_right;
		else
			return dnet_trans_get(t);
	}

	return NULL;
}

static int dnet_trans_insert_raw(struct rb_root *root, struct dnet_trans *a)
{
	struct rb_node **n = &root->rb_node, *parent = NULL;
	struct dnet_trans *t;
	int cmp;

	while (*n) {
		parent = *n;

		t = rb_entry(parent, struct dnet_trans, trans_entry);

		cmp = dnet_trans_cmp(t->trans, a->trans);
		if (cmp < 0)
			n = &parent->rb_left;
		else if (cmp > 0)
			n = &parent->rb_right;
		else
			return -EEXIST;
	}

	if (a->st && a->st->n)
		dnet_log(a->st->n, DNET_LOG_NOTICE, "%s: added transaction: %llu -> %s.\n",
			dnet_dump_id(&a->cmd.id), (unsigned long long)a->trans,
			dnet_server_convert_dnet_addr(&a->st->addr));

	rb_link_node(&a->trans_entry, parent, n);
	rb_insert_color(&a->trans_entry, root);
	return 0;
}

int dnet_trans_insert(struct dnet_trans *t)
{
	struct dnet_node *n = t->st->n;
	int err;

	dnet_lock_lock(&n->trans_lock);
	t->rcv_trans = t->trans = (n->trans++) & ~DNET_TRANS_REPLY;
	err = dnet_trans_insert_raw(&n->trans_root, t);
	dnet_lock_unlock(&n->trans_lock);

	return err;
}

void dnet_trans_remove_nolock(struct rb_root *root, struct dnet_trans *t)
{
	if (!t->trans_entry.rb_parent_color) {
		if (t->st && t->st->n)
			dnet_log(t->st->n, DNET_LOG_ERROR, "%s: trying to remove standalone transaction %llu.\n",
				dnet_dump_id(&t->cmd.id), (unsigned long long)t->trans);
		return;
	}

	if (t) {
		rb_erase(&t->trans_entry, root);
		t->trans_entry.rb_parent_color = 0;
	}
}

void dnet_trans_remove(struct dnet_trans *t)
{
	struct dnet_node *n = t->st->n;

	dnet_lock_lock(&n->trans_lock);
	dnet_trans_remove_nolock(&n->trans_root, t);
	dnet_lock_unlock(&n->trans_lock);
}

struct dnet_trans *dnet_trans_alloc(struct dnet_node *n, uint64_t size)
{
	struct dnet_trans *t;
	struct timeval tv;

	t = malloc(sizeof(struct dnet_trans) + size);
	if (!t)
		return NULL;
	memset(t, 0, sizeof(struct dnet_trans) + size);

	gettimeofday(&tv, NULL);

	atomic_set(&t->refcnt, 1);

	t->fire_time.tv_sec = tv.tv_sec + n->check_timeout;
	t->fire_time.tv_nsec = tv.tv_usec * 1000;

	return t;
}

void dnet_trans_destroy(struct dnet_trans *t)
{
	if (t) {
		if (t->st && t->st->n)
			dnet_log(t->st->n, DNET_LOG_NOTICE, "%s: destruction trans: %llu, reply: %d, st: %p, data: %p.\n",
				dnet_dump_id(&t->cmd.id),
				(unsigned long long)(t->trans & ~DNET_TRANS_REPLY),
				!!(t->trans & ~DNET_TRANS_REPLY),
				t->st, t->data);

		if (t->trans_entry.rb_parent_color && t->st && t->st->n)
			dnet_trans_remove(t);

		dnet_state_put(t->st);
		free(t->data);

		free(t);
	}
}

int dnet_trans_alloc_send_state(struct dnet_net_state *st, struct dnet_trans_control *ctl)
{
	struct dnet_node *n = st->n;
	struct dnet_cmd *cmd;
	struct dnet_attr *a;
	struct dnet_trans *t;
	int err;

	t = dnet_trans_alloc(n, sizeof(struct dnet_cmd) + sizeof(struct dnet_attr) + ctl->size);
	if (!t) {
		err = -ENOMEM;
		if (ctl->complete)
			ctl->complete(NULL, NULL, NULL, ctl->priv);
		goto err_out_exit;
	}

	t->complete = ctl->complete;
	t->priv = ctl->priv;

	cmd = (struct dnet_cmd *)(t + 1);
	a = (struct dnet_attr *)(cmd + 1);

	memcpy(&cmd->id, &ctl->id, sizeof(struct dnet_id));
	cmd->flags = ctl->cflags;
	cmd->size = sizeof(struct dnet_attr) + ctl->size;

	memcpy(&t->cmd, cmd, sizeof(struct dnet_cmd));

	a->cmd = ctl->cmd;
	a->size = ctl->size;
	a->flags = ctl->aflags;

	if (ctl->size && ctl->data)
		memcpy(a + 1, ctl->data, ctl->size);

	t->st = dnet_state_get(st);

	err = dnet_trans_insert(t);
	if (err)
		goto err_out_destroy;

	cmd->trans = t->trans;

	dnet_convert_cmd(cmd);
	dnet_convert_attr(a);

	err = dnet_send(t->st, cmd, sizeof(struct dnet_cmd) + sizeof(struct dnet_attr) + ctl->size);
	if (err)
		goto err_out_destroy;

	return 0;

err_out_destroy:
	if (ctl->complete)
		ctl->complete(NULL, NULL, NULL, ctl->priv);
	dnet_trans_put(t);
err_out_exit:
	return err;
}

int dnet_trans_alloc_send(struct dnet_node *n, struct dnet_trans_control *ctl)
{
	struct dnet_net_state *st;
	int err;

	st = dnet_state_get_first(n, &ctl->id);
	if (!st) {
		err = -ENOENT;
		goto err_out_exit;
	}

	err = dnet_trans_alloc_send_state(st, ctl);
	dnet_state_put(st);

err_out_exit:
	return err;
}

void dnet_check_tree(struct dnet_node *n, int kill)
{
	struct dnet_trans *t;
	struct timespec ts;
	struct timeval tv;
	struct rb_node *node, *next;
	int total = 0;

	dnet_try_reconnect(n);

	gettimeofday(&tv, NULL);

	ts.tv_sec = tv.tv_sec;
	ts.tv_nsec = tv.tv_usec * 1000;

	dnet_lock_lock(&n->trans_lock);
	node = rb_first(&n->trans_root);

	while (node) {
		int err = 0;

		next = rb_next(node);
		t = rb_entry(node, struct dnet_trans, trans_entry);

		if (kill)
			err = -EIO;

		if (!err && !dnet_time_after(&ts, &t->fire_time))
			break;

		if (dnet_time_after(&ts, &t->fire_time))
			err = -ETIMEDOUT;
		dnet_trans_remove_nolock(&n->trans_root, t);

		dnet_log(n, DNET_LOG_ERROR, "%s: %ld.%ld: freeing trans: %llu: fire_time: %ld.%ld, err: %d.\n",
				dnet_dump_id(&t->cmd.id), ts.tv_sec, ts.tv_nsec,	(unsigned long long)t->trans,
				t->fire_time.tv_sec, t->fire_time.tv_nsec, err);

		t->cmd.status = err;
		t->cmd.size = 0;

		if (t->complete)
			t->complete(n->st, &t->cmd, NULL, t->priv);

		if (t->st) {
			dnet_log(n, DNET_LOG_ERROR, "Removing state %s on check error: %d\n",
					dnet_state_dump_addr(t->st), err);
			dnet_state_get(t->st);
			dnet_state_reset(t->st);
		}

		dnet_trans_put(t);

		total++;
		node = next;
	}
	dnet_lock_unlock(&n->trans_lock);

	if (total)
		dnet_log(n, DNET_LOG_DSA, "Checked %d transactions.\n", total);
}

static int dnet_check_stat_complete(struct dnet_net_state *orig, struct dnet_cmd *cmd,
		struct dnet_attr *attr, void *priv __unused)
{
	struct dnet_node *n;
	struct dnet_net_state *st;

	if (!orig || !cmd)
		return -EINVAL;

	n = orig->n;

	if (cmd->status) {
		st = dnet_state_search(n, &cmd->id);
		if (!st) {
			dnet_log(n, DNET_LOG_ERROR, "%s: failed to find matching state to free on stat check error: %d.\n", dnet_dump_id(&cmd->id), cmd->status);
			return cmd->status;
		}

		dnet_log(n, DNET_LOG_ERROR, "%s: removing state %s on stat check error: %d\n",
				dnet_dump_id(&cmd->id), dnet_state_dump_addr(st), cmd->status);

		dnet_state_reset(st);
		return cmd->status;
	}

	if (attr && (attr->size == sizeof(struct dnet_stat))) {
		struct dnet_stat *stat = (struct dnet_stat *)(attr + 1);
		dnet_convert_stat(stat);

		orig->la = (int)stat->la[0];
		orig->free = stat->bsize * stat->bavail;

		dnet_log(n, DNET_LOG_DSA, "%s: la: %d, free: %llu\n", dnet_dump_id(&cmd->id), orig->la, orig->free);
	}

	return 0;
}

static void *dnet_check_tree_from_thread(void *data)
{
	struct dnet_node *n = data;
	long i, timeout;
	struct timeval tv1, tv2;

	if (!n->check_timeout)
		n->check_timeout = 10;

	dnet_log(n, DNET_LOG_INFO, "Started checking thread. Timeout: %lu seconds.\n",
			n->check_timeout);

	while (!n->need_exit) {
		gettimeofday(&tv1, NULL);
		dnet_check_tree(n, 0);

		dnet_request_stat(n, NULL, DNET_CMD_STAT, dnet_check_stat_complete, NULL);

		gettimeofday(&tv2, NULL);

		timeout = n->check_timeout - (tv2.tv_sec - tv1.tv_sec);

		for (i=0; i<timeout; ++i) {
			if (n->need_exit)
				break;
			sleep(1);
		}
	}

	return NULL;
}

int dnet_check_thread_start(struct dnet_node *n)
{
	int err;

	err = pthread_create(&n->check_tid, &n->attr, dnet_check_tree_from_thread, n);
	if (err) {
		dnet_log(n, DNET_LOG_ERROR, "Failed to start tree checking thread: err: %d.\n",
				err);
		return -err;
	}

	return 0;
}

void dnet_check_thread_stop(struct dnet_node *n)
{
	pthread_join(n->check_tid, NULL);
	dnet_log(n, DNET_LOG_NOTICE, "Checking thread stopped.\n");
}
