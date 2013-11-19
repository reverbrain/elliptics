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

struct dnet_notify_entry
{
	struct list_head		notify_entry;
	struct dnet_cmd			cmd;
	struct dnet_net_state		*state;
};

static unsigned int dnet_notify_hash(struct dnet_id *id, unsigned int hash_size)
{
	unsigned int hash = 0xbb40e64d; /* 3.141592653 */
	unsigned int i;
	unsigned int *int_id = (unsigned int *)id->id;

	for (i=0; i<DNET_ID_SIZE / 4; ++i)
		hash ^= int_id[i];

	hash %= hash_size;
	return hash;
}

int dnet_update_notify(struct dnet_net_state *st, struct dnet_cmd *cmd, void *data)
{
	struct dnet_node *n = st->n;
	unsigned int hash = dnet_notify_hash(&cmd->id, n->notify_hash_size);
	struct dnet_notify_bucket *b = &n->notify_hash[hash];
	struct dnet_notify_entry *nt;
	struct dnet_io_attr *io = data;
	struct dnet_io_notification notif;

	memcpy(&notif.io, io, sizeof(struct dnet_io_attr));
	dnet_convert_io_attr(&notif.io);

	pthread_rwlock_rdlock(&b->notify_lock);
	list_for_each_entry(nt, &b->notify_list, notify_entry) {
		if (dnet_id_cmp(&cmd->id, &nt->cmd.id))
			continue;

		memcpy(&notif.addr, &st->addr, sizeof(struct dnet_addr));

		dnet_log(n, DNET_LOG_NOTICE, "%s: sending notification.\n", dnet_dump_id(&cmd->id));
		dnet_send_reply(nt->state, &nt->cmd, &notif, sizeof(struct dnet_io_notification), 1);
	}
	pthread_rwlock_unlock(&b->notify_lock);

	return 0;
}

static void dnet_notify_entry_destroy(struct dnet_notify_entry *e)
{
	dnet_state_put(e->state);
	free(e);
}

int dnet_notify_add(struct dnet_net_state *st, struct dnet_cmd *cmd)
{
	struct dnet_node *n = st->n;
	struct dnet_notify_entry *e;
	unsigned int hash = dnet_notify_hash(&cmd->id, n->notify_hash_size);
	struct dnet_notify_bucket *b = &n->notify_hash[hash];

	e = malloc(sizeof(struct dnet_notify_entry));
	if (!e)
		return -ENOMEM;

	e->state = dnet_state_get(st);
	memcpy(&e->cmd, cmd, sizeof(struct dnet_cmd));

	pthread_rwlock_wrlock(&b->notify_lock);
	list_add_tail(&e->notify_entry, &b->notify_list);
	pthread_rwlock_unlock(&b->notify_lock);

	dnet_log(n, DNET_LOG_INFO, "%s: added notification, hash: 0x%x.\n", dnet_dump_id(&cmd->id), hash);

	return 0;
}

int dnet_notify_remove(struct dnet_net_state *st, struct dnet_cmd *cmd)
{
	struct dnet_node *n = st->n;
	struct dnet_notify_entry *e, *tmp;
	unsigned int hash = dnet_notify_hash(&cmd->id, n->notify_hash_size);
	struct dnet_notify_bucket *b = &n->notify_hash[hash];
	int err = -ENXIO;

	pthread_rwlock_wrlock(&b->notify_lock);
	list_for_each_entry_safe(e, tmp, &b->notify_list, notify_entry) {
		if (dnet_id_cmp(&e->cmd.id, &cmd->id))
			continue;

		e->cmd.flags = 0;
		err = dnet_send_reply(e->state, &e->cmd, NULL, 0, 0);

		list_del(&e->notify_entry);
		dnet_notify_entry_destroy(e);
		
		dnet_log(n, DNET_LOG_INFO, "%s: removed notification.\n", dnet_dump_id(&cmd->id));
		break;
	}
	pthread_rwlock_unlock(&b->notify_lock);

	return err;
}

int dnet_notify_init(struct dnet_node *n)
{
	unsigned int i;
	struct dnet_notify_bucket *b;
	int err;

	n->notify_hash = malloc(sizeof(struct dnet_notify_bucket) * n->notify_hash_size);
	if (!n->notify_hash) {
		errno = ENOMEM; /* Linux does not set errno when malloc fails */
		dnet_log_err(n, "Failed to allocate %u notify hash buckets", n->notify_hash_size);
		err = -ENOMEM;
		goto err_out_exit;
	}

	for (i=0; i<n->notify_hash_size; ++i) {
		b = &n->notify_hash[i];

		INIT_LIST_HEAD(&b->notify_list);
		err = pthread_rwlock_init(&b->notify_lock, NULL);
		if (err) {
			err = -err;
			dnet_log_err(n, "Failed to initialize %d'th bucket lock: err: %d", i, err);
			goto err_out_free;
		}
	}

	dnet_log(n, DNET_LOG_INFO, "Successfully initialized notify hash table (%u entries).\n",
			n->notify_hash_size);

	return 0;

err_out_free:
	n->notify_hash_size = i;
	for (i=0; i<n->notify_hash_size; ++i) {
		b = &n->notify_hash[i];
		pthread_rwlock_destroy(&b->notify_lock);
	}
	free(n->notify_hash);
err_out_exit:
	return err;
}

void dnet_notify_exit(struct dnet_node *n)
{
	unsigned int i;
	struct dnet_notify_bucket *b;
	struct dnet_notify_entry *e, *tmp;

	for (i=0; i<n->notify_hash_size; ++i) {
		b = &n->notify_hash[i];

		pthread_rwlock_wrlock(&b->notify_lock);
		list_for_each_entry_safe(e, tmp, &b->notify_list, notify_entry) {
			list_del(&e->notify_entry);

			dnet_notify_entry_destroy(e);
		}
		pthread_rwlock_unlock(&b->notify_lock);

		pthread_rwlock_destroy(&b->notify_lock);
	}
	free(n->notify_hash);
}
