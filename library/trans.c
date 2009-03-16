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

	pthread_mutex_lock(&n->trans_lock);
	t->trans = (n->trans++) & ~DNET_TRANS_REPLY;
	err = dnet_trans_insert_raw(&n->trans_root, t);
	pthread_mutex_unlock(&n->trans_lock);

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

	pthread_mutex_lock(&n->trans_lock);
	dnet_trans_remove_nolock(&n->trans_root, t);
	pthread_mutex_unlock(&n->trans_lock);
}

static int dnet_trans_forward(struct dnet_trans *t, struct dnet_net_state *st)
{
	int err;
	unsigned int size = t->cmd.size;
	struct dnet_node *n = st->n;

	dnet_convert_cmd(&t->cmd);

	pthread_mutex_lock(&st->lock);
	err = dnet_send(st, &t->cmd, sizeof(struct dnet_cmd));
	if (!err)
		err = dnet_send(st, t->data, size);
	pthread_mutex_unlock(&st->lock);

	dnet_log(n, DNET_LOG_INFO, "%s: ", dnet_dump_id(t->cmd.id));
	dnet_log_append(n, DNET_LOG_INFO, "forwarded to %s (%s:%d), trans: %llu, err: %d.\n", dnet_dump_id(st->id),
		dnet_server_convert_dnet_addr(&st->addr),
		(unsigned long long)t->trans, err);

	return err;
}

int dnet_trans_process(struct dnet_net_state *st)
{
	struct dnet_node *n = st->n;
	struct dnet_trans *t = NULL;
	struct dnet_cmd cmd;
	int err, need_drop = 0;

	err = dnet_wait(st);
	if (err)
		return err;

	pthread_mutex_lock(&st->lock);

	err = dnet_recv(st, &cmd, sizeof(struct dnet_cmd));
	if (err < 0) {
		memset(&cmd, 0, sizeof(struct dnet_cmd));
		goto err_out_unlock;
	}

	dnet_convert_cmd(&cmd);

	dnet_log(n, DNET_LOG_INFO, "%s: size: %llu, trans: %llu, reply: %d, flags: 0x%x, status: %d.\n",
			dnet_dump_id(cmd.id), (unsigned long long)cmd.size,
			(unsigned long long)(cmd.trans & ~DNET_TRANS_REPLY),
			!!(cmd.trans & DNET_TRANS_REPLY),
			cmd.flags, cmd.status);

	if (cmd.trans & DNET_TRANS_REPLY) {
		uint64_t tid = cmd.trans & ~DNET_TRANS_REPLY;

		pthread_mutex_lock(&n->trans_lock);
		t = dnet_trans_search(&n->trans_root, tid);
		if (t && !(cmd.flags & DNET_FLAGS_MORE))
			dnet_trans_remove_nolock(&n->trans_root, t);
		pthread_mutex_unlock(&n->trans_lock);

		if (t) {
			int err;

			if (cmd.size) {
				free(t->data);
				t->data = malloc(cmd.size);
				if (!t->data) {
					err = -ENOMEM;
					goto err_out_unlock;
				}

				err = dnet_recv(st, t->data, cmd.size);
				if (err < 0)
					goto err_out_unlock;
			}
			pthread_mutex_unlock(&st->lock);

			memcpy(&t->cmd, &cmd, sizeof(struct dnet_cmd));
			t->cmd.trans = t->recv_trans | DNET_TRANS_REPLY;

			if (t->complete) {
				err = t->complete(t->st, &t->cmd, t->data, t->priv);
			} else {
				err = dnet_trans_forward(t, t->st);
			}

			if (!(cmd.flags & DNET_FLAGS_MORE))
				dnet_trans_destroy(t);
			goto out;
		}

		dnet_log(n, DNET_LOG_ERROR, "%s: could not find transaction for the reply %llu, dropping.\n",
				dnet_dump_id(cmd.id), (unsigned long long)tid);
		need_drop = 1;
	}

	t = malloc(sizeof(struct dnet_trans));
	if (!t) {
		err = -ENOMEM;
		goto err_out_unlock;
	}

	memset(t, 0, sizeof(struct dnet_trans));

	if (cmd.size) {
		t->data = malloc(cmd.size);
		if (!t->data) {
			err = -ENOMEM;
			goto err_out_unlock;
		}

		err = dnet_recv(st, t->data, cmd.size);
		if (err < 0)
			goto err_out_unlock;
	}

	pthread_mutex_unlock(&st->lock);

	if (need_drop) {
		dnet_trans_destroy(t);
		t = NULL;
	} else {
		t->st = dnet_state_search(n, cmd.id, NULL);

		memcpy(&t->cmd, &cmd, sizeof(struct dnet_cmd));

		if (!t->st || t->st == st || t->st == n->st) {
			err = dnet_process_cmd(st, &t->cmd, t->data);
			if (err) {
				err = 0;
				goto err_out_destroy;
			}

			dnet_trans_destroy(t);
			t = NULL;
		} else {
			struct dnet_net_state *tmp = t->st;

			t->st = dnet_state_get(st);

			err = dnet_trans_insert(t);
			if (err) {
				dnet_state_put(tmp);
				goto err_out_destroy;
			}

			t->recv_trans = t->cmd.trans;
			t->cmd.trans = t->trans;
			err = dnet_trans_forward(t, tmp);
			dnet_state_put(tmp);

			if (err)
				goto err_out_destroy;
		}
	}

out:
	dnet_log(n, DNET_LOG_INFO, "%s: completed size: %llu, trans: %llu, reply: %d",
			dnet_dump_id(cmd.id), (unsigned long long)cmd.size,
			(unsigned long long)(cmd.trans & ~DNET_TRANS_REPLY),
			!!(cmd.trans & DNET_TRANS_REPLY));
	if (!need_drop && !t)
		dnet_log_append(n, DNET_LOG_INFO, " (local)");
	dnet_log_append(n, DNET_LOG_INFO, "\n");

	return 0;

err_out_unlock:
	pthread_mutex_unlock(&st->lock);
err_out_destroy:
	dnet_log(n, DNET_LOG_ERROR, "%s: failed cmd: size: %llu, trans: %llu, reply: %d, err: %d",
			dnet_dump_id(cmd.id), (unsigned long long)cmd.size,
			(unsigned long long)(cmd.trans & ~DNET_TRANS_REPLY),
			!!(cmd.trans & DNET_TRANS_REPLY), err);
	dnet_log_append(n, DNET_LOG_ERROR, ", st: %s", dnet_dump_id(st->id));
	if (t && t->st) {
		if (st == t->st)
			dnet_log_append(n, DNET_LOG_ERROR, " (local)");
		else
			dnet_log_append(n, DNET_LOG_ERROR, ", trans_st: %s", dnet_dump_id(t->st->id));
	}
	dnet_log_append(n, DNET_LOG_ERROR, "\n");
	dnet_trans_destroy(t);
	return err;
}

void dnet_trans_destroy(struct dnet_trans *t)
{
	if (t) {
		if (t->st && t->st->n)
			dnet_log(t->st->n, DNET_LOG_NOTICE, "%s: destruction trans: %llu.\n",
				dnet_dump_id(t->cmd.id), (unsigned long long)(t->trans & ~DNET_TRANS_REPLY));
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
		free(t->priv);

		free(t);
	}
}
