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

int dnet_trans_insert_nolock(struct rb_root *root, struct dnet_trans *a)
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
	struct dnet_net_state *st = t->st;

	pthread_mutex_lock(&st->trans_lock);
	dnet_trans_remove_nolock(&st->trans_root, t);
	pthread_mutex_unlock(&st->trans_lock);
}

struct dnet_trans *dnet_trans_alloc(struct dnet_node *n __unused, uint64_t size)
{
	struct dnet_trans *t;
	int err;

	t = malloc(sizeof(struct dnet_trans) + size);
	if (!t) {
		err = -ENOMEM;
		goto err_out_exit;
	}

	memset(t, 0, sizeof(struct dnet_trans) + size);

	atomic_init(&t->refcnt, 1);

	return t;

err_out_exit:
	return NULL;
}

void dnet_trans_destroy(struct dnet_trans *t)
{
	if (!t)
		return;

	if (t->st && t->st->n)
		dnet_log(t->st->n, DNET_LOG_NOTICE, "%s: destruction trans: %llu, reply: %d, st: %s.\n",
			dnet_dump_id(&t->cmd.id),
			(unsigned long long)(t->trans & ~DNET_TRANS_REPLY),
			!!(t->trans & ~DNET_TRANS_REPLY),
			dnet_state_dump_addr(t->st));

	if (t->trans_entry.rb_parent_color && t->st && t->st->n)
		dnet_trans_remove(t);

	if (t->complete) {
		t->cmd.flags |= DNET_FLAGS_DESTROY;
		t->complete(t->st, &t->cmd, NULL, t->priv);
	}

	dnet_state_put(t->st);

	free(t);
}

int dnet_trans_alloc_send_state(struct dnet_net_state *st, struct dnet_trans_control *ctl)
{
	struct dnet_io_req req;
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

	cmd->trans = t->rcv_trans = t->trans = atomic_inc(&n->trans);

	dnet_convert_cmd(cmd);
	dnet_convert_attr(a);

	t->st = dnet_state_get(st);

	memset(&req, 0, sizeof(req));
	req.st = st;
	req.header = cmd;
	req.hsize = sizeof(struct dnet_cmd) + sizeof(struct dnet_attr) + ctl->size;

	err = dnet_trans_send(t, &req);
	if (err)
		goto err_out_put;

	return 0;

err_out_put:
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
		if (ctl->complete)
			ctl->complete(NULL, NULL, NULL, ctl->priv);
		goto err_out_exit;
	}

	err = dnet_trans_alloc_send_state(st, ctl);
	dnet_state_put(st);

err_out_exit:
	return err;
}

static void *dnet_check_tree_from_thread(void *data)
{
	struct dnet_node *n = data;
	long i, timeout;
	struct timeval tv1, tv2;

	dnet_set_name("check");

	if (!n->check_timeout)
		n->check_timeout = 10;

	dnet_log(n, DNET_LOG_INFO, "Started checking thread. Timeout: %lu seconds.\n",
			n->check_timeout);

	while (!n->need_exit) {
		gettimeofday(&tv1, NULL);

		dnet_try_reconnect(n);

		gettimeofday(&tv2, NULL);

		timeout = n->check_timeout - (tv2.tv_sec - tv1.tv_sec);

		for (i=0; i<timeout; ++i) {
			if (n->need_exit)
				break;
			sleep(1);
		}

		dnet_db_sync(n);
	}

	return NULL;
}

int dnet_check_thread_start(struct dnet_node *n)
{
	int err;

	err = pthread_create(&n->check_tid, NULL, dnet_check_tree_from_thread, n);
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
