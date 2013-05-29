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

#define dnet_map_log(n, level, fmt, a...) do { if ((n)) dnet_log((n), level, fmt, ##a); else fprintf(stderr, fmt, ##a); } while (0)

int dnet_update_ts_metadata_raw(struct dnet_meta_container *mc, uint64_t flags_set, uint64_t flags_clear)
{
	struct dnet_meta m;
	void *data = mc->data;
	uint32_t size = mc->size;
	struct dnet_meta_update *mu;

	while (size) {
		if (size < sizeof(struct dnet_meta)) {
			return -1;
		}

		m = *(struct dnet_meta *)data;
		dnet_convert_meta(&m);

		if (m.size + sizeof(struct dnet_meta) > size) {
			return -1;
		}

		if (m.type == DNET_META_UPDATE) {
			mu = (struct dnet_meta_update *)(data + sizeof(struct dnet_meta));

			dnet_convert_meta_update(mu);

			dnet_current_time(&mu->tm);
			mu->flags |= flags_set;
			mu->flags &= ~flags_clear;

			dnet_convert_meta_update(mu);
		}

		data += m.size + sizeof(struct dnet_meta);
		size -= m.size + sizeof(struct dnet_meta);
	}

	return -ENOENT;
}

void dnet_create_meta_update(struct dnet_meta *m, struct timespec *ts, uint64_t flags_set, uint64_t flags_clear)
{
	struct dnet_meta_update *mu = (struct dnet_meta_update *)m->data;

	m->size = sizeof(struct dnet_meta_update);
	m->type = DNET_META_UPDATE;

	if (!ts) {
		dnet_current_time(&mu->tm);
	} else {
		mu->tm.tsec = ts->tv_sec;
		mu->tm.tnsec = ts->tv_nsec;
	}

	mu->flags = 0;
	mu->flags |= flags_set;
	mu->flags &= ~flags_clear;

	dnet_convert_meta_update(mu);
	dnet_convert_meta(m);
}

struct dnet_meta_update *dnet_get_meta_update(struct dnet_node *n, struct dnet_meta_container *mc,
		struct dnet_meta_update *meta_update)
{
	struct dnet_meta m;
	void *data = mc->data;
	uint32_t size = mc->size;
	struct dnet_meta_update *mu;
	int num;

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

			num = m.size / sizeof(struct dnet_meta_update);
			if (num >= 0) {
				if (meta_update) {
					memcpy(meta_update, &mu[0], sizeof(struct dnet_meta_update));
					dnet_convert_meta_update(meta_update);
				}
				return &mu[0];
			}
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

void dnet_convert_metadata(struct dnet_node *n __unused, void *data, int size)
{
	void *ptr = data;
	struct dnet_meta *m;

	while (size) {
		m = ptr;

		ptr += sizeof(struct dnet_meta) + m->size;
		size -= sizeof(struct dnet_meta) + m->size;

		dnet_convert_meta(m);
	}
}

int dnet_write_metadata(struct dnet_session *s, struct dnet_meta_container *mc, int convert)
{
	struct dnet_node *n = s->node;
	struct dnet_io_control ctl;
	void *result;
	int err;

	if (n->flags & DNET_CFG_NO_META)
		return 0;

	if (convert)
		dnet_convert_metadata(n, mc->data, mc->size);

	memset(&ctl, 0, sizeof(ctl));

	ctl.fd = -1;

	ctl.data = mc->data;
	ctl.io.size = mc->size;
	ctl.io.flags = DNET_IO_FLAGS_META;
	ctl.cflags = dnet_session_get_cflags(s);

	memcpy(&ctl.id, &mc->id, sizeof(struct dnet_id));
	ctl.id.type = ctl.io.type = EBLOB_TYPE_META;

	err = dnet_write_data_wait(s, &ctl, &result);
	if (err < 0)
		return err;

	free(result);

	return 0;
}

int dnet_create_write_metadata_strings(struct dnet_session *s, const void *remote, unsigned int remote_len,
		struct dnet_id *id, struct timespec *ts)
{
	struct dnet_node *n = s->node;
	struct dnet_metadata_control mc;
	int *groups = NULL;
	int group_num = 0;
	int err;

	group_num = s->group_num;
	groups = alloca(group_num * sizeof(int));

	memcpy(groups, s->groups, group_num * sizeof(int));

	memset(&mc, 0, sizeof(mc));
	mc.obj = remote;
	mc.len = remote_len;
	mc.groups = groups;
	mc.group_num = group_num;
	mc.id = *id;

	if (ts) {
		mc.ts = *ts;
	} else {
		struct timeval tv;

		gettimeofday(&tv, NULL);
		mc.ts.tv_sec = tv.tv_sec;
		mc.ts.tv_nsec = tv.tv_usec * 1000;
	}

	err = dnet_create_write_metadata(s, &mc);
	if (err < 0) {
		dnet_log(n, DNET_LOG_ERROR, "%s: failed to write metadata: %d\n", dnet_dump_id(id), err);
	}

	return 0;
}

int dnet_create_metadata(struct dnet_session *s __unused, struct dnet_metadata_control *ctl, struct dnet_meta_container *mc)
{
	struct dnet_meta_check_status *c;
	struct dnet_meta *m;
	int size = 0, err;

	size += sizeof(struct dnet_meta_check_status) + sizeof(struct dnet_meta);

	if (ctl->obj && ctl->len)
		size += ctl->len + sizeof(struct dnet_meta);

	if (ctl->groups && ctl->group_num)
		size += ctl->group_num * sizeof(int) + sizeof(struct dnet_meta);

	size += sizeof(struct dnet_meta_update) + sizeof(struct dnet_meta);

	if (!size) {
		err = -EINVAL;
		goto err_out_exit;
	}

	mc->data = malloc(size);
	if (!mc->data) {
		err = -ENOMEM;
		goto err_out_exit;
	}
	memset(mc->data, 0, size);

	m = (struct dnet_meta *)(mc->data);

	c = (struct dnet_meta_check_status *)m->data;
	m->size = sizeof(struct dnet_meta_check_status);
	m->type = DNET_META_CHECK_STATUS;

	/* Check status is undefined for now, it will be filled during actual check */
	memset(c, 0, sizeof(struct dnet_meta_check_status));

	m = (struct dnet_meta *)(m->data + m->size);
	dnet_create_meta_update(m, ctl->ts.tv_sec ? &ctl->ts : NULL, 0, 0);

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

	mc->size = size;
	memcpy(&mc->id, &ctl->id, sizeof(struct dnet_id));
	err = 0;

err_out_exit:
	return err;
}

int dnet_create_write_metadata(struct dnet_session *s, struct dnet_metadata_control *ctl)
{
	struct dnet_meta_container mc;
	int err;

	memset(&mc, 0, sizeof(struct dnet_meta_container));

	err = dnet_create_metadata(s, ctl, &mc);
	if (err)
		goto err_out_exit;

	err = dnet_write_metadata(s, &mc, 1);
	if (err)
		goto err_out_free;

err_out_free:
	free(mc.data);
err_out_exit:
	return err;
}

static char *dnet_meta_types[__DNET_META_MAX] = {
	[DNET_META_PARENT_OBJECT] = "DNET_META_PARENT_OBJECT",
	[DNET_META_GROUPS] = "DNET_META_GROUPS",
	[DNET_META_CHECK_STATUS] = "DNET_META_CHECK_STATUS",
	[DNET_META_NAMESPACE] = "DNET_META_NAMESPACE",
	[DNET_META_UPDATE] = "DNET_META_UPDATE",
	[DNET_META_CHECKSUM] = "DNET_META_CHECKSUM",
};

void dnet_meta_print(struct dnet_session *s, struct dnet_meta_container *mc)
{
	struct dnet_node *n = s->node;
	void *data;
	int size, err;
	struct dnet_meta *m;
	char tstr[64];
	struct tm tm;

	data = mc->data;
	size = mc->size;

	dnet_log(n, DNET_LOG_DATA, "%s: size: %u\n", dnet_dump_id_len(&mc->id, DNET_ID_SIZE), mc->size);

	while (size) {
		m = data;

		dnet_convert_meta(m);

		if (m->type >= __DNET_META_MAX || m->type < DNET_META_PARENT_OBJECT) {
			dnet_log(n, DNET_LOG_ERROR, "%s: incorrect meta type %d\n", dnet_dump_id(&mc->id), m->type);
			return;
		}

		if (m->type == DNET_META_PARENT_OBJECT) {
			char name[m->size + 1];

			memcpy(name, m->data, m->size);
			name[m->size] = '\0';
			dnet_log(n, DNET_LOG_DATA, "%s: type: %u, size: %u, name: '%s'\n",
					dnet_meta_types[m->type], m->type, m->size, name);
		} else if (m->type == DNET_META_GROUPS) {
			int *groups = (int *)m->data;
			int gnum = m->size / sizeof(int);
			char str[gnum * 36 + 1], *ptr;
			int i, rest;

			memset(str, 0, sizeof(str));

			ptr = str;
			rest = sizeof(str);
			for (i=0; i<gnum; ++i) {
				err = snprintf(ptr, rest, "%d:", groups[i]);
				if (err > rest)
					break;

				rest -= err;
				ptr += err;

				if (i == gnum - 1)
					*(--ptr) = '\0';
			}

			dnet_log(n, DNET_LOG_DATA, "%s: type: %u, size: %u, groups: %s\n",
					dnet_meta_types[m->type], m->type, m->size, str);
		} else if (m->type == DNET_META_CHECK_STATUS) {
			struct dnet_meta_check_status *s = (struct dnet_meta_check_status *)m->data;

			dnet_convert_meta_check_status(s);

			localtime_r((time_t *)&s->tm.tsec, &tm);
			strftime(tstr, sizeof(tstr), "%F %R:%S %Z", &tm);

			dnet_log(n, DNET_LOG_DATA, "%s: type: %u, size: %u, check status: %d, ts: %s: %lld.%lld\n",
					dnet_meta_types[m->type],
					m->type, m->size, s->status, tstr,
					(unsigned long long)s->tm.tsec,
					(unsigned long long)s->tm.tnsec);
		} else if (m->type == DNET_META_UPDATE) {
			struct dnet_meta_update *mu = (struct dnet_meta_update *)m->data;

			dnet_convert_meta_update(mu);

			localtime_r((time_t *)&mu->tm.tsec, &tm);
			strftime(tstr, sizeof(tstr), "%F %R:%S %Z", &tm);

			dnet_log(n, DNET_LOG_DATA, "%s: type: %u, size: %u, flags: %llx, ts: %s %lld.%lld\n",
					dnet_meta_types[m->type], m->type, m->size,
					(unsigned long long)mu->flags, tstr,
					(unsigned long long)mu->tm.tsec, (unsigned long long)mu->tm.tnsec);
		} else if (m->type == DNET_META_NAMESPACE) {
			char str[m->size + 1];
			memcpy(str, m->data, m->size);
			str[m->size] = '\0';

			dnet_log(n, DNET_LOG_DATA, "%s: type: %u, size: %u, namespace: %s\n",
					dnet_meta_types[m->type], m->type, m->size, str);
		} else if (m->type == DNET_META_CHECKSUM) {
			struct dnet_meta_checksum *cs = (struct dnet_meta_checksum *)m->data;
			char str[2*DNET_CSUM_SIZE+1];

			localtime_r((time_t *)&cs->tm.tsec, &tm);
			strftime(tstr, sizeof(tstr), "%F %R:%S %Z", &tm);

			dnet_dump_id_len_raw(cs->checksum, DNET_CSUM_SIZE, str);
			dnet_log(n, DNET_LOG_DATA, "%s: type: %u, size: %u, csum: %s, ts: %s %lld.%lld\n",
					dnet_meta_types[m->type], m->type, m->size, str, tstr,
					(unsigned long long)cs->tm.tsec, (unsigned long long)cs->tm.tnsec);
		} else {
			dnet_log(n, DNET_LOG_DATA, "%s: type: %u, size: %u\n",
					dnet_meta_types[m->type], m->type, m->size);
		}

		data += m->size + sizeof(*m);
		size -= m->size + sizeof(*m);
	}
}

int dnet_read_meta(struct dnet_session *s, struct dnet_meta_container *mc,
		const void *remote, unsigned int remote_len, struct dnet_id *id)
{
	struct dnet_io_attr io;
	struct dnet_id raw;
	void *data;
	int err;

	io.flags = DNET_IO_FLAGS_META;
	io.size = 0;
	io.offset = 0;
	io.type = 0;
	io.start = io.num = 0;

	if (!id) {
		if (!remote) {
			err = -EINVAL;
			goto err_out_exit;
		}

		dnet_transform(s, remote, remote_len, &raw);
		id = &raw;

		id->type = 0;

		memcpy(io.id, id->id, DNET_ID_SIZE);
		memcpy(io.parent, id->id, DNET_ID_SIZE);

		data = dnet_read_data_wait(s, id, &io, &err);
	} else {
		id->type = 0;

		memcpy(io.id, id->id, DNET_ID_SIZE);
		memcpy(io.parent, id->id, DNET_ID_SIZE);

		data = dnet_read_data_wait_raw(s, id, &io, DNET_CMD_READ, &err);
	}

	if (data) {
		io.size -= sizeof(struct dnet_io_attr);

		mc->data = malloc(io.size);
		if (!mc->data) {
			err = -ENOMEM;
			goto err_out_free;
		}

		memcpy(mc->data, data + sizeof(struct dnet_io_attr), io.size);

		memcpy(&mc->id, id, sizeof(struct dnet_id));
		mc->size = io.size;
	}

err_out_free:
	free(data);
err_out_exit:
	return err;
}

int dnet_meta_update_check_status_raw(struct dnet_node *n, struct dnet_meta_container *mc)
{
	struct dnet_meta *m = NULL;
	struct dnet_meta_check_status *meta_check;
	int err = 0;

	m = dnet_meta_search(n, mc, DNET_META_CHECK_STATUS);

	if (!m) {
		mc->data = realloc(mc->data, mc->size + sizeof(struct dnet_meta) + sizeof(struct dnet_meta_check_status));
		if (!mc->data) {
			err = -ENOMEM;
			goto err_out_free;
		}

		m = mc->data + mc->size;
		mc->size += sizeof(struct dnet_meta) + sizeof(struct dnet_meta_check_status);

		m->type = DNET_META_CHECK_STATUS;
		m->size = sizeof(struct dnet_meta_check_status);
		dnet_convert_meta(m);
	}

	meta_check = (struct dnet_meta_check_status *)m->data;
	meta_check->status = 0;

	dnet_current_time(&meta_check->tm);

	dnet_convert_meta_check_status(meta_check);

	return err;

err_out_free:
	free(mc->data);
	return err;
}

int dnet_meta_update_check_status(struct dnet_node *n, struct dnet_meta_container *mc)
{
	struct dnet_raw_id id;
	int err;

	err = dnet_meta_update_check_status_raw(n, mc);

	if (err) {
		dnet_log(n, DNET_LOG_ERROR, "%s: failed to update DNET_META_CHECK_STATUS, err=%d\n",
				dnet_dump_id(&mc->id), err);
		return err;
	} else {
		memcpy(&id.id, &mc->id.id, DNET_ID_SIZE);
		err = n->cb->meta_write(n->cb->command_private, &id, mc->data, mc->size);
		if (err) {
			dnet_log(n, DNET_LOG_ERROR, "%s: failed to write meta, err=%d\n",
					dnet_dump_id(&mc->id), err);
		}
	}

	return err;
}

