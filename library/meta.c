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
	int i, num;

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
			num = m.size / sizeof(struct dnet_meta_update);
			for (i = 0; i < num; ++i) {
				mu_group_id = dnet_bswap32(mu[i].group_id);
				if (mu_group_id != group_id)
					continue;

				dnet_convert_meta_update(&mu[i]);
				gettimeofday(&tv, NULL);

				mu[i].tsec = tv.tv_sec;
				mu[i].tnsec = tv.tv_usec * 1000;
				mu[i].flags |= flags_set;
				mu[i].flags &= ~flags_clear;

				dnet_convert_meta_update(&mu[i]);
				return 0;
			}
		}

		data += m.size + sizeof(struct dnet_meta);
		size -= m.size + sizeof(struct dnet_meta);
	}
	return -ENOENT;
}

static void dnet_create_meta_update(struct dnet_meta *m, struct timespec *ts, int group_id, uint64_t flags_set, uint64_t flags_clear)
{
	struct dnet_meta_update *mu = (struct dnet_meta_update *)m->data;
	struct timespec raw_ts;

	m->size = sizeof(struct dnet_meta_update);
	m->type = DNET_META_UPDATE;

	if (!ts) {
		struct timeval tv;

		gettimeofday(&tv, NULL);
		raw_ts.tv_sec = tv.tv_sec;
		raw_ts.tv_nsec = tv.tv_usec * 1000;
		ts = &raw_ts;
	}

	mu->group_id = group_id;
	mu->tsec = ts->tv_sec;
	mu->tnsec = ts->tv_nsec;

	mu->flags = 0;
	mu->flags |= flags_set;
	mu->flags &= ~flags_clear;

	dnet_convert_meta_update(mu);
	dnet_convert_meta(m);
}

int dnet_update_ts_metadata(struct dnet_node *n, struct dnet_id *id, uint64_t flags_set, uint64_t flags_clear)
{
	int err = 0;
	struct dnet_meta_container mc;
	struct dnet_meta *m;
	struct eblob_key key;

	memset(&mc, 0, sizeof(struct dnet_meta_container));

	memcpy(key.id, id->id, DNET_ID_SIZE);

	err = dnet_db_read_raw(n, key.id, &mc.data);
	if (err < 0) {
		dnet_log(n, DNET_LOG_ERROR, "%s: META: update-ts-read-failed: %d: %s.\n",
			dnet_dump_id(id), err, strerror(-err));
		if (err == -ENOENT) 
			dnet_counter_inc(n, DNET_CNTR_DBR_NOREC, err);
		else
			dnet_counter_inc(n, DNET_CNTR_DBR_ERROR, err);

		m = malloc(sizeof(struct dnet_meta) + sizeof(struct dnet_meta_update));
		if (!m) {
			err = -ENOMEM;
			goto err_out_exit;
		}
		dnet_create_meta_update(m, NULL, id->group_id, flags_set, flags_clear);

		mc.data = m;
		mc.size = sizeof(struct dnet_meta_update) + sizeof(struct dnet_meta);

		dnet_log(n, DNET_LOG_DSA, "%s: created meta-update metadata\n", dnet_dump_id(id));
	} else {
		err = dnet_update_ts_metadata_raw(n, &mc, id->group_id, flags_set, flags_clear);
		if (err) {
			/* broken metadata, rewrite it */
			if (err != -ENOENT) {
				free(mc.data);

				mc.data = NULL;
				mc.size = 0;

				dnet_log(n, DNET_LOG_ERROR, "%s: META: broken-metadata: rewrite it\n", dnet_dump_id(id));
			}

			mc.data = realloc(mc.data, mc.size + sizeof(struct dnet_meta) + sizeof(struct dnet_meta_update));
			if (!mc.data) {
				err = -ENOMEM;
				goto err_out_exit;
			}

			m = mc.data + mc.size;
			mc.size += sizeof(struct dnet_meta) + sizeof(struct dnet_meta_update);

			dnet_create_meta_update(m, NULL, id->group_id, flags_set, flags_clear);

			dnet_log(n, DNET_LOG_DSA, "%s: appended meta-update metadata\n", dnet_dump_id(id));
		}
	}

	err = eblob_write(n->meta, &key, mc.data, mc.size, BLOB_DISK_CTL_NOCSUM, EBLOB_TYPE_META);
	if (err) {
		dnet_log(n, DNET_LOG_ERROR, "%s: META: update-ts-write: %d: %s.\n",
			dnet_dump_id(id), err, strerror(-err));
		dnet_counter_inc(n, DNET_CNTR_DBW_ERROR, err);
		goto err_out_free;
	}

err_out_free:
	free(mc.data);
err_out_exit:
	return err;
}

struct dnet_meta_update *dnet_get_meta_update(struct dnet_node *n, struct dnet_meta_container *mc,
		int group_id __attribute__ ((unused)), struct dnet_meta_update *meta_update)
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

static void dnet_update_check_metadata_raw(struct dnet_node *n __unused, void *data, int size)
{
	void *ptr = data;
	struct dnet_meta *m;

	while (size) {
		m = ptr;

		ptr += sizeof(struct dnet_meta) + m->size;
		size -= sizeof(struct dnet_meta) + m->size;
#if 0
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
#endif
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

	if (ts) {
		mc.ts = *ts;
	} else {
		struct timeval tv;

		gettimeofday(&tv, NULL);
		mc.ts.tv_sec = tv.tv_sec;
		mc.ts.tv_nsec = tv.tv_usec * 1000;
	}

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
	struct dnet_meta_checksum *csum;
	struct dnet_meta *m;
	int size = 0, err, nsize = 0;
	void *ns;

	size += sizeof(struct dnet_meta_check_status) + sizeof(struct dnet_meta);

	if (ctl->obj && ctl->len)
		size += ctl->len + sizeof(struct dnet_meta);

	if (ctl->groups && ctl->group_num)
		size += ctl->group_num * sizeof(int) + sizeof(struct dnet_meta);

	size += sizeof(struct dnet_meta_checksum) + sizeof(struct dnet_meta);

	size += sizeof(struct dnet_meta_update) + sizeof(struct dnet_meta);

	ns = dnet_node_get_ns(n, &nsize);
	if (ns && nsize)
		size += nsize + sizeof(struct dnet_meta);

	if (!size) {
		err = -EINVAL;
		goto err_out_exit;
	}

	memset(&mc, 0, sizeof(struct dnet_meta_container));
	mc.data = malloc(size);
	if (!mc.data) {
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
	dnet_create_meta_update(m, ctl->ts.tv_sec ? &ctl->ts : NULL, n->id.group_id, 0, 0);

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

	mc.size = size;
	memcpy(&mc.id, &ctl->id, sizeof(struct dnet_id));

	err = dnet_write_metadata(n, &mc, 1);

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

void dnet_meta_print(struct dnet_node *n, struct dnet_meta_container *mc)
{
	void *data;
	int size, err;
	struct dnet_meta *m;
	char tstr[64];
	struct tm tm;

	data = mc->data;
	size = mc->size;

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
			dnet_log(n, DNET_LOG_INFO, "%s: type: %u, size: %u, name: '%s'\n",
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

			dnet_log(n, DNET_LOG_INFO, "%s: type: %u, size: %u, groups: %s\n",
					dnet_meta_types[m->type], m->type, m->size, str);
		} else if (m->type == DNET_META_CHECK_STATUS) {
			struct dnet_meta_check_status *s = (struct dnet_meta_check_status *)m->data;

			dnet_convert_meta_check_status(s);

			localtime_r((time_t *)&s->tsec, &tm);
			strftime(tstr, sizeof(tstr), "%F %R:%S %Z", &tm);

			dnet_log(n, DNET_LOG_INFO, "%s: type: %u, size: %u, check status: %d, ts: %s: %lld.%lld\n",
					dnet_meta_types[m->type],
					m->type, m->size, s->status, tstr,
					(unsigned long long)s->tsec,
					(unsigned long long)s->tnsec);
		} else if (m->type == DNET_META_UPDATE) {
			struct dnet_meta_update *mu = (struct dnet_meta_update *)m->data;

			dnet_convert_meta_update(mu);

			localtime_r((time_t *)&mu->tsec, &tm);
			strftime(tstr, sizeof(tstr), "%F %R:%S %Z", &tm);

			dnet_log(n, DNET_LOG_INFO, "%s: type: %u, size: %u, group: %d, flags: %llx, ts: %s %lld.%lld\n",
					dnet_meta_types[m->type], m->type, m->size,
					mu->group_id, (unsigned long long)mu->flags, tstr,
					(unsigned long long)mu->tsec, (unsigned long long)mu->tnsec);
		} else if (m->type == DNET_META_NAMESPACE) {
			char str[m->size + 1];
			memcpy(str, m->data, m->size);
			str[m->size] = '\0';

			dnet_log(n, DNET_LOG_INFO, "%s: type: %u, size: %u, namespace: %s\n",
					dnet_meta_types[m->type], m->type, m->size, str);
		} else if (m->type == DNET_META_CHECKSUM) {
			struct dnet_meta_checksum *cs = (struct dnet_meta_checksum *)m->data;
			char str[2*DNET_CSUM_SIZE+1];

			localtime_r((time_t *)&cs->tsec, &tm);
			strftime(tstr, sizeof(tstr), "%F %R:%S %Z", &tm);

			dnet_dump_id_len_raw(cs->checksum, DNET_CSUM_SIZE, str);
			dnet_log(n, DNET_LOG_INFO, "%s: type: %u, size: %u, csum: %s, ts: %s %lld.%lld\n",
					dnet_meta_types[m->type], m->type, m->size, str, tstr,
					(unsigned long long)cs->tsec, (unsigned long long)cs->tnsec);
		} else {
			dnet_log(n, DNET_LOG_INFO, "%s: type: %u, size: %u\n",
					dnet_meta_types[m->type], m->type, m->size);
		}

		data += m->size + sizeof(*m);
		size -= m->size + sizeof(*m);
	}
}

int dnet_meta_update_checksum(struct dnet_node *n, struct dnet_id *id)
{
	struct dnet_meta *m;
	struct dnet_meta_container mc;
	struct dnet_meta_checksum *csum;
	int err, csize;

	err = dnet_db_read_raw(n, id->id, &mc.data);
	if (err < 0) {
		goto err_out_exit;
	}
	mc.size = err;

	m = dnet_meta_search(n, &mc, DNET_META_CHECKSUM);
	if (!m) {
		mc.data = realloc(mc.data, mc.size + sizeof(struct dnet_meta) + sizeof(struct dnet_meta_checksum));
		if (!mc.data) {
			err = -ENOMEM;
			goto err_out_free;
		}

		m = mc.data + mc.size;
		mc.size += sizeof(struct dnet_meta) + sizeof(struct dnet_meta_checksum);

		m->type = DNET_META_CHECKSUM;
		m->size = sizeof(struct dnet_meta_checksum);
		dnet_convert_meta(m);
	}

	csum = (struct dnet_meta_checksum *)m->data;
	csize = sizeof(csum->checksum);
	err = n->cb->checksum(n, n->cb->command_private, id, csum->checksum, &csize);
	if (err)
		goto err_out_free;

	err = dnet_db_write_raw(n, id->id, mc.data, mc.size);

err_out_free:
	free(mc.data);
err_out_exit:
	dnet_log(n, DNET_LOG_INFO, "%s: meta: CHECKSUM: result: %d\n", dnet_dump_id(id), err);
	return err;
}

int dnet_meta_read_checksum(struct dnet_node *n, struct dnet_id *id, struct dnet_meta_checksum *csum)
{
	struct dnet_meta *m;
	struct dnet_meta_container mc;
	int err;

	err = dnet_db_read_raw(n, id->id, &mc.data);
	if (err < 0) {
		goto err_out_exit;
	}
	mc.size = err;

	m = dnet_meta_search(n, &mc, DNET_META_CHECKSUM);
	if (!m) {
		err = -ENOENT;
		goto err_out_free;
	}

	if (m->size != sizeof(struct dnet_meta_checksum)) {
		err = -EINVAL;
		goto err_out_free;
	}

	memcpy(csum, m->data, sizeof(struct dnet_meta_checksum));
	err = 0;

err_out_free:
	free(mc.data);
err_out_exit:
	return err;
}
