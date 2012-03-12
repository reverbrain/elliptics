/*
 * 2011+ Copyright (c) Evgeniy Polyakov <zbr@ioremap.net>
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

#include <sys/stat.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>

#include "elliptics.h"

void dnet_locks_destroy(struct dnet_node *n)
{
	int i;

	if (n->locks) {
		for (i = 0; i < n->locks->num; ++i) {
			pthread_mutex_destroy(&n->locks->lock[i]);
		}

		free(n->locks);
		n->locks = NULL;
	}
}

int dnet_locks_init(struct dnet_node *n, int num)
{
	int err, i;

	n->locks = malloc(sizeof(struct dnet_locks) + num * sizeof(pthread_mutex_t));
	if (!n->locks) {
		err = -ENOMEM;
		goto err_out_exit;
	}

	n->locks->num = num;

	for (i = 0; i < num; ++i) {
		err = pthread_mutex_init(&n->locks->lock[i], NULL);
		if (err) {
			err = -err;
			dnet_log(n, DNET_LOG_ERROR, "Could not create lock %d/%d: %s [%d]\n", i, num, strerror(-err), err);

			n->locks->num = i;
			goto err_out_destroy;
		}
	}

	return 0;

err_out_destroy:
	dnet_locks_destroy(n);
err_out_exit:
	return err;
}

static unsigned int dnet_ophash_index(struct dnet_node *n, struct dnet_id *key)
{
	unsigned int *ptr = (unsigned int *)key->id;
	unsigned int h = 0;
	unsigned int i;

	for (i = 0; i < sizeof(key->id) / sizeof(unsigned int); ++i) {
		h ^= ptr[i];
	}

	return h % n->locks->num;
}

void dnet_oplock(struct dnet_node *n, struct dnet_id *key)
{
	unsigned int idx = dnet_ophash_index(n, key);

	pthread_mutex_lock(&n->locks->lock[idx]);
}

void dnet_opunlock(struct dnet_node *n, struct dnet_id *key)
{
	unsigned int idx = dnet_ophash_index(n, key);

	pthread_mutex_unlock(&n->locks->lock[idx]);
}

int dnet_optrylock(struct dnet_node *n, struct dnet_id *key)
{
	unsigned int idx = dnet_ophash_index(n, key);
	int err;

	err = pthread_mutex_trylock(&n->locks->lock[idx]);
	return err;
}

