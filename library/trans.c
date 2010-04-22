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
#include "dnet/packet.h"
#include "dnet/interface.h"

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
			dnet_dump_id(a->cmd.id), (unsigned long long)a->trans,
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
	t->recv_trans = t->trans = (n->trans++) & ~DNET_TRANS_REPLY;
	err = dnet_trans_insert_raw(&n->trans_root, t);
	dnet_lock_unlock(&n->trans_lock);

	return err;
}

void dnet_trans_remove_nolock(struct rb_root *root, struct dnet_trans *t)
{
	if (!t->trans_entry.rb_parent_color) {
		if (t->st && t->st->n)
			dnet_log(t->st->n, DNET_LOG_ERROR, "%s: trying to remove standalone transaction %llu.\n",
				dnet_dump_id(t->cmd.id), (unsigned long long)t->trans);
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

	t->resend_count = n->resend_count;
	t->fire_time.tv_sec = tv.tv_sec + n->resend_timeout.tv_sec;
	t->fire_time.tv_nsec = tv.tv_usec * 1000 + n->resend_timeout.tv_nsec;

	return t;
}

void dnet_trans_destroy(struct dnet_trans *t)
{
	if (t) {
		if (t->st && t->st->n)
			dnet_log(t->st->n, DNET_LOG_NOTICE, "%s: destruction trans: %llu, reply: %d, r: %p.\n",
				dnet_dump_id(t->cmd.id),
				(unsigned long long)(t->trans & ~DNET_TRANS_REPLY),
				!!(t->trans & ~DNET_TRANS_REPLY), &t->r);

		if (t->trans_entry.rb_parent_color && t->st && t->st->n)
			dnet_trans_remove(t);

		dnet_state_put(t->st);
		free(t->data);

		free(t);
	}
}

int dnet_trans_alloc_send(struct dnet_node *n, struct dnet_trans_control *ctl)
{
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

	memcpy(cmd->id, ctl->id, DNET_ID_SIZE);
	cmd->flags = ctl->cflags;
	cmd->size = sizeof(struct dnet_attr) + ctl->size;

	memcpy(&t->cmd, cmd, sizeof(struct dnet_cmd));

	a->cmd = ctl->cmd;
	a->size = ctl->size;
	a->flags = ctl->aflags;

	if (ctl->size && ctl->data)
		memcpy(a + 1, ctl->data, ctl->size);

	t->st = dnet_state_get_first(n, cmd->id, n->st);
	if (!t->st) {
		err = -ENOENT;
		goto err_out_destroy;
	}

	err = dnet_trans_insert(t);
	if (err)
		goto err_out_destroy;

	cmd->trans = t->trans;

	dnet_convert_cmd(cmd);
	dnet_convert_attr(a);

	dnet_req_set_header(&t->r, cmd, sizeof(struct dnet_cmd) +
			sizeof(struct dnet_attr) + ctl->size, 0);
	dnet_req_set_fd(&t->r, -1, 0, 0, 0);
	dnet_req_set_flags(&t->r, ~0, DNET_REQ_NO_DESTRUCT);

	err = dnet_data_ready(t->st, &t->r);
	if (err)
		goto err_out_destroy;

	return 0;

err_out_destroy:
	dnet_trans_put(t);
err_out_exit:
	return err;
}

static int dnet_trans_resend(struct dnet_trans *t)
{
	struct dnet_net_state *st = t->st;
	struct dnet_node *n = t->st->n;
	int empty = 1;

	dnet_lock_lock(&st->snd_lock);
	if (!list_empty(&t->r.req_entry))
		empty = 0;
	dnet_lock_unlock(&st->snd_lock);

	if (!empty)
		return 0;

	st = dnet_state_get_first(n, t->cmd.id, n->st);
	if (!st) {
		dnet_log(n, DNET_LOG_ERROR, "%s: failed to find a state.\n",
				dnet_dump_id(t->cmd.id));
		return -ENODEV;
	}

	dnet_state_put(t->st);
	t->st = st;

	dnet_log(n, DNET_LOG_INFO, "%s: resending transaction %llu -> %s.\n",
			dnet_dump_id(t->cmd.id), (unsigned long long)t->trans,
			dnet_state_dump_addr(st));

	dnet_data_ready(t->st, &t->r);
	return 1;
}

void dnet_check_tree(struct dnet_node *n, int kill)
{
	struct dnet_trans *t;
	struct timespec ts;
	struct timeval tv;
	struct rb_node *node, *next;
	int resent = 0, total = 0;

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
		if (dnet_time_after(&ts, &t->fire_time)) {
			err = -ETIMEDOUT;

			if (--t->resend_count > 0) {
				err = dnet_trans_resend(t);
				if (!err)
					t->resend_count++;

				if (err > 0) {
					t->fire_time.tv_sec = ts.tv_sec + n->resend_timeout.tv_sec;
					t->fire_time.tv_nsec = ts.tv_nsec + n->resend_timeout.tv_nsec;
				}

				resent++;
			}
		}
		if (err < 0) {
			dnet_trans_remove_nolock(&n->trans_root, t);
			dnet_trans_put(t);
		}

		total++;
		node = next;
	}
	dnet_lock_unlock(&n->trans_lock);

	if (resent || total)
		dnet_log(n, DNET_LOG_NOTICE, "%s: resent/checked %d transactions, total: %d.\n",
			dnet_dump_id(n->id), resent, total);
}

static void *dnet_check_tree_from_thread(void *data)
{
	struct dnet_node *n = data;
	unsigned long i, timeout = n->resend_timeout.tv_sec;

	if (!timeout)
		timeout = 1;

	dnet_log(n, DNET_LOG_INFO, "%s: started resending thread. Timeout: %lu seconds.\n",
			dnet_dump_id(n->id), timeout);

	while (!n->need_exit) {
		dnet_check_tree(n, 0);

		for (i=0; i<timeout; ++i) {
			if (n->need_exit)
				break;
			sleep(1);
		}
	}

	return NULL;
}

int dnet_resend_thread_start(struct dnet_node *n)
{
	int err;

	err = pthread_create(&n->resend_tid, NULL, dnet_check_tree_from_thread, n);
	if (err) {
		dnet_log(n, DNET_LOG_ERROR, "%s: failed to start tree checking thread: err: %d.\n",
				dnet_dump_id(n->id), err);
		return -err;
	}

	return 0;
}

void dnet_resend_thread_stop(struct dnet_node *n)
{
	pthread_join(n->resend_tid, NULL);
	dnet_log(n, DNET_LOG_NOTICE, "%s: resend thread stopped.\n", dnet_dump_id(n->id));
}
