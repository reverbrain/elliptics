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

#include <errno.h>
#include <ctype.h>
#include <dirent.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "atomic.h"
#include "elliptics.h"
#include "lock.h"
#include "list.h"

#ifndef __unused
#define __unused	__attribute__ ((unused))
#endif

struct dnet_hash_entry {
	struct list_head	list_entry;
	unsigned int		dsize, ksize;
	void			*data;

	atomic_t		refcnt;
	void			(* cleanup)(void *key, unsigned int ksize, void *data, unsigned int dsize);

	unsigned char		key[];
};

struct dnet_hash_head {
	struct list_head	list;
	struct dnet_lock	lock;
};

static inline unsigned int dnet_hash_data(void *data, unsigned int size, unsigned int limit)
{
	unsigned int hval = 1313131313;
	unsigned int i;

	while (size >= 4) {
		uint32_t *p = data;

		hval ^= *p;
		hval += 0x80808080;

		size -= 4;
		data += 4;
	}

	for (i=0; i<size; ++i) {
		unsigned char *p = data;

		hval ^= *p;
		hval += 0x80808080;

		hval += hval << size;
	}

	return hval % limit;
}

static void dnet_hash_entry_free(struct dnet_hash *h, struct dnet_hash_entry *e)
{
	if (h->flags & DNET_HASH_MLOCK)
		munlock(e, e->dsize + e->ksize + sizeof(struct dnet_hash_entry));
	free(e);
}


static inline void dnet_hash_entry_get(struct dnet_hash_entry *e)
{
	atomic_inc(&e->refcnt);
}

static inline void dnet_hash_entry_put(struct dnet_hash *h, struct dnet_hash_entry *e)
{
	if (atomic_dec_and_test(&e->refcnt)) {
		if (e->cleanup)
			e->cleanup(e->key, e->ksize, e->data, e->dsize);

		list_del_init(&e->list_entry);

		dnet_hash_entry_free(h, e);
	}
}

struct dnet_hash *dnet_hash_init(unsigned int num, unsigned int flags)
{
	struct dnet_hash *h;
	int err;
	unsigned int i;
	unsigned int size = sizeof(struct dnet_hash) + sizeof(struct dnet_hash_head) * num;

	h = malloc(size);
	if (!h)
		goto err_out_exit;

	h->heads = (struct dnet_hash_head *)(h + 1);
	h->flags = flags;
	h->num = num;

	if (flags & DNET_HASH_MLOCK) {
		err = mlock(h, size);
		if (err) {
			err = -errno;
			goto err_out_free;
		}
	}

	for (i=0; i<num; ++i) {
		struct dnet_hash_head *head = &h->heads[i];

		INIT_LIST_HEAD(&head->list);
		dnet_lock_init(&head->lock);
	}

	return h;

err_out_free:
	free(h);
err_out_exit:
	return h;
}

void dnet_hash_exit(struct dnet_hash *h)
{
	unsigned int i;
	struct dnet_hash_head *head;
	struct dnet_hash_entry *e, *tmp;

	for (i=0; i<h->num; ++i) {
		head = &h->heads[i];

		list_for_each_entry_safe(e, tmp, &head->list, list_entry) {
			list_del_init(&e->list_entry);

			dnet_hash_entry_put(h, e);
		}

		dnet_lock_destroy(&head->lock);
	}

	if (h->flags & DNET_HASH_MLOCK)
		munlock(h, sizeof(struct dnet_hash) + sizeof(struct dnet_hash_head) * h->num);

	free(h);
}

static int dnet_hash_insert_raw(struct dnet_hash *h, void *key, unsigned int ksize, void *data, unsigned int dsize, int replace)
{
	unsigned int idx;
	struct dnet_hash_entry *e, *tmp, *next, *found = NULL;
	struct dnet_hash_head *head;
	unsigned int size = sizeof(struct dnet_hash_entry) + dsize + ksize;
	int err;

	e = malloc(size);
	if (!e) {
		err = -ENOMEM;
		goto err_out_exit;
	}

	if (dsize) {
		e->data = e->key + ksize;
		memcpy(e->data, data, dsize);
	} else {
		e->data = data;
	}

	e->dsize = dsize;
	e->ksize = ksize;

	memcpy(e->key, key, ksize);

	e->cleanup = NULL;
	atomic_set(&e->refcnt, 1);

	if (h->flags & DNET_HASH_MLOCK) {
		err = mlock(e, size);
		if (err) {
			err = -errno;
			goto err_out_free;
		}
	}

	idx = dnet_hash_data(key, ksize, h->num);
	head = &h->heads[idx];

	dnet_lock_lock(&head->lock);

	list_for_each_entry_safe(tmp, next, &head->list, list_entry) {
		if ((tmp->ksize == e->ksize) && !memcmp(tmp->key, e->key, ksize)) {
			if (replace) {
				list_del_init(&tmp->list_entry);
				found = tmp;
				break;
			}
			err = -EEXIST;
			goto err_out_unlock;
		}
	}

	list_add_tail(&e->list_entry, &head->list);

	dnet_lock_unlock(&head->lock);

	if (found)
		dnet_hash_entry_put(h, found);

	return 0;

err_out_unlock:
	dnet_lock_unlock(&head->lock);
err_out_free:
	dnet_hash_entry_free(h, e);
err_out_exit:
	return err;
}

int dnet_hash_insert(struct dnet_hash *h, void *key, unsigned int ksize, void *data, unsigned int dsize)
{
	return dnet_hash_insert_raw(h, key, ksize, data, dsize, 0);
}

int dnet_hash_replace(struct dnet_hash *h, void *key, unsigned int ksize, void *data, unsigned int dsize)
{
	return dnet_hash_insert_raw(h, key, ksize, data, dsize, 1);
}

int dnet_hash_remove(struct dnet_hash *h, void *key, unsigned int ksize)
{
	unsigned int idx = dnet_hash_data(key, ksize, h->num);
	struct dnet_hash_head *head = &h->heads[idx];
	struct dnet_hash_entry *e, *tmp, *found = NULL;
	int err = -ENOENT;

	dnet_lock_lock(&head->lock);
	list_for_each_entry_safe(e, tmp, &head->list, list_entry) {
		if ((e->ksize == ksize) && !memcmp(key, e->key, ksize)) {
			list_del_init(&e->list_entry);
			found = e;
			err = 0;
			break;
		}
	}

	dnet_lock_unlock(&head->lock);

	if (found)
		dnet_hash_entry_put(h, found);

	return err;
}

int dnet_hash_lookup(struct dnet_hash *h, void *key, unsigned int ksize, void *data, unsigned int *dsize)
{
	unsigned int idx = dnet_hash_data(key, ksize, h->num);
	struct dnet_hash_head *head = &h->heads[idx];
	struct dnet_hash_entry *e;
	int err = -ENOENT;

	dnet_lock_lock(&head->lock);
	list_for_each_entry_reverse(e, &head->list, list_entry) {
		if ((e->ksize == ksize) && !memcmp(key, e->key, ksize)) {
			unsigned int size = *dsize;

			if (size > e->dsize)
				size = e->dsize;

			memcpy(data, e->data, size);
			*dsize = size;
			err = 0;
			break;
		}
	}

	dnet_lock_unlock(&head->lock);

	return err;
}
