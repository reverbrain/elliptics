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

struct dnet_meta *dnet_meta_search(struct dnet_node *n, void *data, uint32_t size, uint32_t type)
{
	struct dnet_meta m, *found = NULL;

	while (size) {
		if (size < sizeof(struct dnet_meta)) {
			dnet_map_log(n, DNET_LOG_ERROR, "Metadata size %u is too small, min %zu, searching for type 0x%x.\n",
					size, sizeof(struct dnet_meta), type);
			break;
		}

		m = *(struct dnet_meta *)data;
		//dnet_convert_meta(&m);

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

void dnet_convert_metadata(void *data, int size, int use_size_before_convert)
{
	struct dnet_meta *m;
	int sz;

	while (size > 0) {
		m = data;

		if (use_size_before_convert)
			sz = m->size;

		dnet_convert_meta(m);

		if (!use_size_before_convert)
			sz = m->size;

		sz += sizeof(struct dnet_meta);
		
		size -= sz;
		data += sz;
	}
}

int dnet_write_metadata(struct dnet_node *n, struct dnet_meta_container *mc, int convert)
{
	if (convert) {
		void *ptr = mc->data;
		int size = mc->size;
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
			}

			dnet_convert_meta(m);
		}
	}

	dnet_log(n, DNET_LOG_DSA, "%s: writing metadata (%u bytes)\n", dnet_dump_id(&mc->id), mc->size);
	return dnet_write_data_wait(n, NULL, 0, &mc->id, mc->data, -1, 0, 0, mc->size, NULL, DNET_ATTR_DIRECT_TRANSACTION, DNET_IO_FLAGS_META);
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
	struct dnet_meta_container *mc;
	struct dnet_meta_check_status *c;
	struct dnet_meta_update *mu;
	struct dnet_meta_checksum *csum;
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

	size += sizeof(struct dnet_meta_checksum) + sizeof(struct dnet_meta);

	size += sizeof(struct dnet_meta_update)*groups_in_meta + sizeof(struct dnet_meta);

	ns = dnet_node_get_ns(n, &nsize);
	if (ns && nsize)
		size += nsize + sizeof(struct dnet_meta);

	if (!size) {
		err = -EINVAL;
		goto err_out_exit;
	}

	mc = malloc(sizeof(struct dnet_meta_container) + size);
	if (!mc) {
		err = -ENOMEM;
		goto err_out_exit;
	}
	memset(mc, 0, sizeof(struct dnet_meta_container) + size);

	m = (struct dnet_meta *)(mc + 1);

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

	csum = (struct dnet_meta_checksum *)m->data;
	csum->tsec = ctl->ts.tv_sec;
	csum->tnsec = ctl->ts.tv_nsec;
	dnet_convert_meta_checksum(csum);
	m->size = sizeof(struct dnet_meta_checksum);
	m->type = DNET_META_CHECKSUM;
	m = (struct dnet_meta *)(m->data + m->size);

	mc->size = size;
	memcpy(&mc->id, &ctl->id, sizeof(struct dnet_id));

	err = dnet_write_metadata(n, mc, 1);

	free(mc);
err_out_exit:
	return err;
}

int dnet_meta_update_checksum(struct dnet_node *n, struct dnet_id *id)
{
	struct dnet_meta *m;
	struct dnet_meta_checksum *csum;
	void *meta, *new_meta = NULL;
	ssize_t size, new_size = 0;
	struct dnet_cmd cmd;
	struct dnet_io_attr io;
	int err, csize;

	size = dnet_db_read_raw(n, 1, id->id, &meta);
	if (size < 0) {
		err = size;
		goto err_out_exit;
	}

	dnet_convert_metadata(meta, size, 0);

	m = dnet_meta_search(n, meta, size, DNET_META_CHECKSUM);
	if (!m) {
		new_size = size + sizeof(struct dnet_meta) + sizeof(struct dnet_meta_checksum);
		new_meta = malloc(new_size);
		if (!new_meta) {
			err = -ENOMEM;
			goto err_out_kcfree;
		}

		memcpy(new_meta, meta, size);
		m = new_meta + size;

		m->type = DNET_META_CHECKSUM;
		m->size = sizeof(struct dnet_meta_checksum);
	}

	csum = (struct dnet_meta_checksum *)m->data;
	csize = sizeof(csum->checksum);
	err = n->checksum(n, n->command_private, id, csum->checksum, &csize);
	if (err)
		goto err_out_free_new_meta;

	memset(&cmd, 0, sizeof(struct dnet_cmd));
	memcpy(&cmd.id, id, sizeof(struct dnet_id));

	memset(&io, 0, sizeof(struct dnet_io_attr));
	memcpy(io.id, id->id, DNET_ID_SIZE);
	io.flags = DNET_IO_FLAGS_META;

	if (new_meta) {
		dnet_convert_metadata(new_meta, new_size, 1);
		err = db_put_data(n, &cmd, &io, new_meta, new_size);
	} else {
		dnet_convert_metadata(meta, size, 1);
		err = db_put_data(n, &cmd, &io, meta, size);
	}

err_out_free_new_meta:
	free(new_meta);
err_out_kcfree:
	kcfree(meta);
err_out_exit:
	dnet_log(n, DNET_LOG_INFO, "%s: meta: CHECKSUM: result: %d\n", dnet_dump_id(id), err);
	return err;
}

int dnet_meta_read_checksum(struct dnet_node *n, struct dnet_id *id, struct dnet_meta_checksum *csum)
{
	struct dnet_meta *m;
	void *meta;
	ssize_t size;
	int err;

	size = dnet_db_read_raw(n, 1, id->id, &meta);
	if (size < 0) {
		err = size;
		goto err_out_exit;
	}

	dnet_convert_metadata(meta, size, 0);

	m = dnet_meta_search(n, meta, size, DNET_META_CHECKSUM);
	if (!m) {
		err = -ENOENT;
		goto err_out_kcfree;
	}

	if (m->size != sizeof(struct dnet_meta_checksum)) {
		err = -EINVAL;
		goto err_out_kcfree;
	}

	memcpy(csum, m->data, sizeof(struct dnet_meta_checksum));
	err = 0;

err_out_kcfree:
	kcfree(meta);
err_out_exit:
	return err;
}
