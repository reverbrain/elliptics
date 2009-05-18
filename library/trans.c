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
			return t;
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

struct dnet_trans *dnet_trans_alloc(struct dnet_node *n __unused, uint64_t size)
{
	struct dnet_trans *t;

	t = malloc(sizeof(struct dnet_trans) + size);
	if (!t)
		return NULL;
	memset(t, 0, sizeof(struct dnet_trans) + size);

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
#if 0
		if (t->complete) {
			t->cmd.flags |= DNET_FLAGS_DESTROY;
			t->complete(t, NULL);
		}
#endif
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
	dnet_trans_destroy(t);
err_out_exit:
	return err;
}
