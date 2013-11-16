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

#include <sys/stat.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>

#include "elliptics.h"

void dnet_locks_destroy(struct dnet_node *n)
{
	struct dnet_locks_entry *r, *tmp;

	if (n->locks) {

		list_for_each_entry_safe(r, tmp, &n->locks->lock_list, lock_list_entry) {
			list_del(&r->lock_list_entry);
			pthread_mutex_destroy(&r->lock);
			pthread_cond_destroy(&r->wait);

			if (r->lock_tree_entry.rb_parent_color) {
				rb_erase(&r->lock_tree_entry, &n->locks->lock_tree);
			}
		}

		free(n->locks);
		n->locks = NULL;
	}
}

int dnet_locks_init(struct dnet_node *n, int num)
{
	int err, i;
	struct dnet_locks_entry *entry;

	n->locks = malloc(sizeof(struct dnet_locks) + num * sizeof(struct dnet_locks_entry));
	if (!n->locks) {
		err = -ENOMEM;
		goto err_out_exit;
	}

	INIT_LIST_HEAD(&n->locks->lock_list);
	n->locks->lock_tree = RB_ROOT;

	err = pthread_mutex_init(&n->locks->lock, NULL);
	if (err) {
		err = -err;
		dnet_log(n, DNET_LOG_ERROR, "Could not create lock: %s [%d]\n", strerror(-err), err);

		goto err_out_destroy;
	}

	entry = (struct dnet_locks_entry *) (n->locks + 1);

	for (i = 0; i < num; ++i, ++entry) {
		entry->locked = 0;

		err = pthread_mutex_init(&entry->lock, NULL);
		if (err) {
			err = -err;
			dnet_log(n, DNET_LOG_ERROR, "Could not create lock %d/%d: %s [%d]\n", i, num, strerror(-err), err);

			goto err_out_destroy;
		}
		err = pthread_cond_init(&entry->wait, NULL);
		if (err) {
			err = -err;
			dnet_log(n, DNET_LOG_ERROR, "Could not create cond %d/%d: %s [%d]\n", i, num, strerror(-err), err);

			pthread_mutex_destroy(&entry->lock);
			goto err_out_destroy;
		}

		memset(&entry->lock_tree_entry, 0, sizeof(struct rb_node));
		list_add_tail(&entry->lock_list_entry, &n->locks->lock_list);
	}

	return 0;

err_out_destroy:
	dnet_locks_destroy(n);
err_out_exit:
	return err;
}

static struct dnet_locks_entry *dnet_oplock_search_nolock(struct dnet_node *n, struct dnet_id *id)
{
	struct rb_root *root = &n->locks->lock_tree;
	struct rb_node *node = root->rb_node;
	struct dnet_locks_entry *entry = NULL;
	int cmp = 1;

	while (node) {
		entry = rb_entry(node, struct dnet_locks_entry, lock_tree_entry);

		cmp = memcmp(entry->id.id, id->id, DNET_ID_SIZE);
		if (cmp < 0)
			node = node->rb_left;
		else if (cmp > 0)
			node = node->rb_right;
		else
			return entry;
	}

	return NULL;
}

static int dnet_oplock_insert_nolock(struct dnet_node *n, struct dnet_locks_entry *a)
{
	struct rb_root *root = &n->locks->lock_tree;
	struct rb_node **node = &root->rb_node, *parent = NULL;
	struct dnet_locks_entry *t;
	int cmp;

	while (*node) {
		parent = *node;

		t = rb_entry(parent, struct dnet_locks_entry, lock_tree_entry);

		cmp = memcmp(t->id.id, a->id.id, DNET_ID_SIZE);
		if (cmp < 0)
			node = &parent->rb_left;
		else if (cmp > 0)
			node = &parent->rb_right;
		else
			return -EEXIST;
	}

	rb_link_node(&a->lock_tree_entry, parent, node);
	rb_insert_color(&a->lock_tree_entry, root);
	return 0;
}

static void dnet_oplock_remove_nolock(struct dnet_node *n, struct dnet_locks_entry *entry)
{
	struct rb_root *root = &n->locks->lock_tree;

	if (!entry->lock_tree_entry.rb_parent_color) {
		dnet_log(n, DNET_LOG_ERROR, "%s: trying to remove non-existen oplock.\n",
			dnet_dump_id_str(entry->id.id));
		return;
	}

	if (entry) {
		rb_erase(&entry->lock_tree_entry, root);
		entry->lock_tree_entry.rb_parent_color = 0;
	}
}

static struct dnet_locks_entry *dnet_oplock_ensure(struct dnet_node *n, struct dnet_id *id)
{
	struct dnet_locks_entry *entry = NULL;

	pthread_mutex_lock(&n->locks->lock);

	entry = dnet_oplock_search_nolock(n, id);

	if (entry) {
		atomic_inc(&entry->refcnt);
	} else if (!list_empty(&n->locks->lock_list)) {
		entry = list_first_entry(&n->locks->lock_list, struct dnet_locks_entry, lock_list_entry);
		list_del(&entry->lock_list_entry);

		entry->locked = 0;
		atomic_init(&entry->refcnt, 1);

		memcpy(entry->id.id, id->id, sizeof(entry->id.id));

		dnet_oplock_insert_nolock(n, entry);
	} else {
		dnet_log(n, DNET_LOG_ERROR, "%s: oplock list is empty.\n", dnet_dump_id(id));
	}

	pthread_mutex_unlock(&n->locks->lock);

	return entry;
}

static struct dnet_locks_entry *dnet_oplock_take(struct dnet_node *n, struct dnet_id *id)
{
	struct dnet_locks_entry *entry = NULL;

	pthread_mutex_lock(&n->locks->lock);

	entry = dnet_oplock_search_nolock(n, id);

	if (!entry) {
		dnet_log(n, DNET_LOG_ERROR, "%s: lock not found.\n", dnet_dump_id(id));
		goto err_out_complete;
	}

	if (entry && atomic_dec_and_test(&entry->refcnt)) {
		dnet_oplock_remove_nolock(n, entry);
		list_add_tail(&entry->lock_list_entry, &n->locks->lock_list);

		entry = NULL;
		goto err_out_complete;
	}

err_out_complete:
	pthread_mutex_unlock(&n->locks->lock);

	return entry;
}

void dnet_oplock(struct dnet_node *n, struct dnet_id *key)
{
	struct dnet_locks_entry *entry = dnet_oplock_ensure(n, key);

	if (!entry) {
		return;
	}

	pthread_mutex_lock(&entry->lock);

	while (entry->locked) {
		pthread_cond_wait(&entry->wait, &entry->lock);
	}

	entry->locked = 1;

	pthread_mutex_unlock(&entry->lock);
}

void dnet_opunlock(struct dnet_node *n, struct dnet_id *key)
{
	struct dnet_locks_entry *entry = dnet_oplock_take(n, key);

	if (!entry) {
		return;
	}

	pthread_mutex_lock(&entry->lock);

	entry->locked = 0;

	pthread_cond_signal(&entry->wait);

	pthread_mutex_unlock(&entry->lock);
}

int dnet_optrylock(struct dnet_node *n, struct dnet_id *key)
{
	struct dnet_locks_entry *entry = dnet_oplock_ensure(n, key);
	int err = 0;

	if (!entry) {
		return -ENOENT;
	}

	pthread_mutex_lock(&entry->lock);

	if (entry->locked)
		err = -EBUSY;
	else
		entry->locked = 1;

	pthread_mutex_unlock(&entry->lock);

	return err;
}

