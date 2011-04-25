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

#include <ctype.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "elliptics.h"

#include "elliptics/packet.h"
#include "elliptics/interface.h"

#define dnet_map_log(n, mask, fmt, a...) do { if ((n)) dnet_log((n), mask, fmt, ##a); else fprintf(stderr, fmt, ##a); } while (0)

static int dnet_update_ts_metadata_raw(struct dnet_node *n, struct dnet_meta_container *mc, int group_id, uint64_t flags_set, uint64_t flags_clear)
{
	struct dnet_meta m;
	void *data = mc->data;
	uint32_t size = mc->size;
	struct dnet_meta_update *mu;
	int mu_group_id;
	struct timeval tv;

	while (size) {
		if (size < sizeof(struct dnet_meta)) {
			dnet_log(n, DNET_LOG_ERROR, "Metadata size %u is too small, min %zu, searching for type 0x%x.\n",
					size, sizeof(struct dnet_meta), DNET_META_UPDATE);
			return -1;
		}

		m = *(struct dnet_meta *)data;
		dnet_convert_meta(&m);

		if (m.size + sizeof(struct dnet_meta) > size) {
			dnet_log(n, DNET_LOG_ERROR, "Metadata entry broken: entry size %u, type: 0x%x, struct size: %zu, "
					"total size left: %u, searching for type: 0x%x.\n",
					m.size, m.type, sizeof(struct dnet_meta), size, DNET_META_UPDATE);
			return -1;
		}

		if (m.type == DNET_META_UPDATE) {
			mu = (struct dnet_meta_update *)(data + sizeof(struct dnet_meta));
			mu_group_id = dnet_bswap32(mu->group_id);
			if (mu_group_id != group_id)
				continue;

			mu = (struct dnet_meta_update *)(data + sizeof(struct dnet_meta));
			dnet_convert_meta_update(mu);
			gettimeofday(&tv, NULL);

			mu->tsec = tv.tv_sec;
			mu->tnsec = tv.tv_usec * 1000;
			mu->flags |= flags_set;
			mu->flags &= ~flags_clear;

			dnet_convert_meta_update(mu);
			return 0;
		}

		data += m.size + sizeof(struct dnet_meta);
		size -= m.size + sizeof(struct dnet_meta);
	}
	return -ENOENT;
}

int dnet_update_ts_metadata(struct dnet_node *n, struct dnet_id *id, uint64_t flags_set, uint64_t flags_clear)
{
	int err = 0;
	struct dnet_meta_container mc;
	struct dnet_meta *m;
	struct dnet_meta_update *mu;
	struct timeval tv;

	memset(&mc, 0, sizeof(struct dnet_meta_container));

	err = kcdbbegintran(n->meta, 1);
	if (!err) {
		err = -kcdbecode(n->meta);
		dnet_log_raw(n, DNET_LOG_ERROR, "%s: failed to start meta deletion transaction, err: %d: %s.\n",
			dnet_dump_id(id), err, kcecodename(-err));
		goto err_out_exit;
	}

	mc.data = (unsigned char *)kcdbget(n->meta, (void *)id->id, DNET_ID_SIZE, &mc.size);
	if (!mc.data) {
		err = -kcdbecode(n->meta);
		dnet_log_raw(n, DNET_LOG_ERROR, "%s: failed to read meta of to be deleted object, err: %d: %s.\n",
			dnet_dump_id(id), err, kcecodename(-err));

		m = (struct dnet_meta *)malloc(sizeof(struct dnet_meta) + sizeof(struct dnet_meta_update));
		m->size = sizeof(struct dnet_meta_update);
		m->type = DNET_META_UPDATE;
		mu = (struct dnet_meta_update *)m->data;

		gettimeofday(&tv, NULL);

		mu->tsec = tv.tv_sec;
		mu->tnsec = tv.tv_usec * 1000;
		mu->flags |= flags_set;
		mu->flags &= ~flags_clear;

		dnet_convert_meta_update(mu);
		dnet_convert_meta(m);

		err = kcdbset(n->meta, (void *)id->id, DNET_ID_SIZE, (void *)m, m->size + sizeof(struct dnet_meta));
		free(m);
		if (!err) {
			err = -kcdbecode(n->history);
			dnet_log_raw(n, DNET_LOG_ERROR, "%s: failed to store updated meta, err: %d: %s.\n",
				dnet_dump_id(id), err, kcecodename(-err));
		}

		goto err_out_txn_end;
	}

	err = dnet_update_ts_metadata_raw(n, &mc, id->group_id, flags_set, flags_clear);
	if (err) {
		m = (struct dnet_meta *)malloc(sizeof(struct dnet_meta) + sizeof(struct dnet_meta_update));
		m->size = sizeof(struct dnet_meta_update);
		m->type = DNET_META_UPDATE;
		mu = (struct dnet_meta_update *)m->data;

		gettimeofday(&tv, NULL);

		mu->tsec = tv.tv_sec;
		mu->tnsec = tv.tv_usec * 1000;
		mu->flags |= flags_set;
		mu->flags &= ~flags_clear;

		dnet_convert_meta_update(mu);
		dnet_convert_meta(m);

		err = kcdbappend(n->meta, (void *)id->id, DNET_ID_SIZE, (void *)m, m->size + sizeof(struct dnet_meta));
		free(m);
		if (!err) {
			err = -kcdbecode(n->meta);
			dnet_log_raw(n, DNET_LOG_ERROR, "%s: failed to store updated meta, err: %d: %s.\n",
				dnet_dump_id(id), err, kcecodename(-err));

			goto err_out_free;
		}
	} else {
		err = kcdbset(n->meta, (void *)id->id, DNET_ID_SIZE, (void *)mc.data, mc.size);
		if (!err) {
			err = -kcdbecode(n->meta);
			dnet_log_raw(n, DNET_LOG_ERROR, "%s: failed to store updated meta, err: %d: %s.\n",
				dnet_dump_id(id), err, kcecodename(-err));

			goto err_out_free;
		}
	}


	kcfree(mc.data);
	kcdbendtran(n->history, 1);

	return err;
err_out_free:
	kcfree(mc.data);
err_out_txn_end:
	kcdbendtran(n->meta, 0);
err_out_exit:
	return err;
}

struct dnet_meta_update *dnet_get_meta_update(struct dnet_node *n, struct dnet_meta_container *mc, int group_id, struct dnet_meta_update *meta_update)
{
	struct dnet_meta m;
	void *data = mc->data;
	uint32_t size = mc->size;
	struct dnet_meta_update *mu;
	int mu_group_id;
	struct timeval tv;

	while (size) {
		if (size < sizeof(struct dnet_meta)) {
			dnet_log(n, DNET_LOG_ERROR, "Metadata size %u is too small, min %zu, searching for type 0x%x.\n",
					size, sizeof(struct dnet_meta), DNET_META_UPDATE);
			return NULL;
		}

		m = *(struct dnet_meta *)data;
		dnet_convert_meta(&m);

		if (m.size + sizeof(struct dnet_meta) > size) {
			dnet_log(n, DNET_LOG_ERROR, "Metadata entry broken: entry size %u, type: 0x%x, struct size: %zu, "
					"total size left: %u, searching for type: 0x%x.\n",
					m.size, m.type, sizeof(struct dnet_meta), size, DNET_META_UPDATE);
			return NULL;
		}

		if (m.type == DNET_META_UPDATE) {
			mu = (struct dnet_meta_update *)(data + sizeof(struct dnet_meta));
			mu_group_id = dnet_bswap32(mu->group_id);
			if (mu_group_id != group_id)
				continue;

			if (meta_update)
				memcpy(meta_update, mu, sizeof(struct dnet_meta_update));
			dnet_convert_meta_update(meta_update);
			return mu;
		}

		data += m.size + sizeof(struct dnet_meta);
		size -= m.size + sizeof(struct dnet_meta);
	}
	return NULL;
}

struct dnet_meta *dnet_meta_search(struct dnet_node *n, struct dnet_meta_container *mc, uint32_t type)
{
	void *data = mc->data;
	uint32_t size = mc->size;

	struct dnet_meta m, *found = NULL;

	while (size) {
		if (size < sizeof(struct dnet_meta)) {
			dnet_map_log(n, DNET_LOG_ERROR, "Metadata size %u is too small, min %zu, searching for type 0x%x.\n",
					size, sizeof(struct dnet_meta), type);
			break;
		}

		m = *(struct dnet_meta *)data;
		dnet_convert_meta(&m);

		if (m.size + sizeof(struct dnet_meta) > size) {
			dnet_map_log(n, DNET_LOG_ERROR, "Metadata entry broken: entry size %u, type: 0x%x, struct size: %zu, "
					"total size left: %u, searching for type: 0x%x.\n",
					m.size, m.type, sizeof(struct dnet_meta), size, type);
			break;
		}

		if (m.type == type) {
			found = data;
			break;
		}

		data += m.size + sizeof(struct dnet_meta);
		size -= m.size + sizeof(struct dnet_meta);
	}

	return found;
}

void dnet_update_check_metadata_raw(struct dnet_node *n, void *data, int size)
{
	void *ptr = data;
	struct dnet_meta *m;

	while (size) {
		m = ptr;

		ptr += sizeof(struct dnet_meta) + m->size;
		size -= sizeof(struct dnet_meta) + m->size;

		if (m->type == DNET_META_CHECK_STATUS) {
			struct timeval tv;
			struct dnet_meta_check_status *c = (struct dnet_meta_check_status *)m->data;

			gettimeofday(&tv, NULL);

			c->tsec = tv.tv_sec;
			c->tnsec = tv.tv_usec * 1000;
			c->status = 0;

			dnet_convert_meta_check_status(c);
			dnet_log(n, DNET_LOG_DSA, "Metadata updated\n");
		}

		dnet_convert_meta(m);
	}
}

int dnet_write_metadata(struct dnet_node *n, struct dnet_meta_container *mc, int convert)
{
	if (convert) {
		dnet_update_check_metadata_raw(n, mc->data, mc->size);
	}

	dnet_log(n, DNET_LOG_DSA, "%s: writing metadata (%u bytes)\n", dnet_dump_id(&mc->id), mc->size);
	return dnet_write_data_wait(n, NULL, 0, &mc->id, mc->data, -1, 0, 0, mc->size, NULL, 0, DNET_IO_FLAGS_META);
}

int dnet_create_write_metadata_strings(struct dnet_node *n, void *remote, unsigned int remote_len, struct dnet_id *id, struct timespec *ts)
{
	struct dnet_metadata_control mc;
	int *groups = NULL;
	int group_num = 0;
	int err;

	pthread_mutex_lock(&n->group_lock);
	group_num = n->group_num;
	groups = alloca(group_num * sizeof(int));

	memcpy(groups, n->groups, group_num * sizeof(int));
	pthread_mutex_unlock(&n->group_lock);

	memset(&mc, 0, sizeof(mc));
	mc.obj = remote;
	mc.len = remote_len;
	mc.groups = groups;
	mc.group_num = group_num;
	mc.id = *id;

	if (ts)
		mc.ts = *ts;

	err = dnet_create_write_metadata(n, &mc);
	if (err < 0) {
		dnet_log(n, DNET_LOG_ERROR, "%s: failed to write metadata: %d\n", dnet_dump_id(id), err);
	}

	return err;
}

int dnet_create_write_metadata(struct dnet_node *n, struct dnet_metadata_control *ctl)
{
	struct dnet_meta_container mc;
	struct dnet_meta_check_status *c;
	struct dnet_meta_update *mu;
	struct dnet_meta *m;
	int size = 0, err, nsize = 0, groups_in_meta = 1, i;
	void *ns;

	size += sizeof(struct dnet_meta_check_status) + sizeof(struct dnet_meta);

	if (ctl->obj && ctl->len)
		size += ctl->len + sizeof(struct dnet_meta);

	if (ctl->groups && ctl->group_num) {
		size += ctl->group_num * sizeof(int) + sizeof(struct dnet_meta);
		groups_in_meta = ctl->group_num;
	}

	size += sizeof(struct dnet_meta_update)*groups_in_meta + sizeof(struct dnet_meta);

	ns = dnet_node_get_ns(n, &nsize);
	if (ns && nsize)
		size += nsize + sizeof(struct dnet_meta);

	if (!size) {
		err = -EINVAL;
		goto err_out_exit;
	}

	memset(&mc, 0, sizeof(struct dnet_meta_container));
	mc.data = malloc(size);
	if (mc.data) {
		err = -ENOMEM;
		goto err_out_exit;
	}
	memset(mc.data, 0, size);

	m = (struct dnet_meta *)(mc.data);

	c = (struct dnet_meta_check_status *)m->data;
	m->size = sizeof(struct dnet_meta_check_status);
	m->type = DNET_META_CHECK_STATUS;

	/* Check status is undefined for now, it will be filled during actual check */
	memset(c, 0, sizeof(struct dnet_meta_check_status));

	m = (struct dnet_meta *)(m->data + m->size);
	m->size = sizeof(*mu) * groups_in_meta;
	m->type = DNET_META_UPDATE;
	if (!ctl->ts.tv_sec) {
		struct timeval tv;

		gettimeofday(&tv, NULL);
		ctl->ts.tv_sec = tv.tv_sec;
		ctl->ts.tv_nsec = tv.tv_usec * 1000;
	}
	for (i=0; i<groups_in_meta; ++i) {
		mu = (struct dnet_meta_update *)(m->data + i*sizeof(struct dnet_meta_update));

		mu->group_id = (ctl->groups) ? ctl->groups[i] : 0;
		mu->flags = ctl->update_flags;
		mu->tsec = ctl->ts.tv_sec;
		mu->tnsec = ctl->ts.tv_nsec;

		dnet_convert_meta_update(mu);
	}

	m = (struct dnet_meta *)(m->data + m->size);

	if (ctl->obj && ctl->len) {
		m->size = ctl->len;
		m->type = DNET_META_PARENT_OBJECT;
		memcpy(m->data, ctl->obj, ctl->len);

		m = (struct dnet_meta *)(m->data + m->size);
	}

	if (ctl->groups && ctl->group_num) {
		m->size = ctl->group_num * sizeof(int);
		m->type = DNET_META_GROUPS;
		memcpy(m->data, ctl->groups, ctl->group_num * sizeof(int));

		m = (struct dnet_meta *)(m->data + m->size);
	}

	if (ns && nsize) {
		m->size = nsize;
		m->type = DNET_META_NAMESPACE;
		memcpy(m->data, ns, nsize);

		m = (struct dnet_meta *)(m->data + m->size);
	}

	mc.size = size;
	memcpy(&mc.id, &ctl->id, sizeof(struct dnet_id));

	err = dnet_write_metadata(n, &mc, 1);

	free(mc.data);
err_out_exit:
	return err;
}

