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

#include "dnet/packet.h"
#include "dnet/interface.h"

#define dnet_map_log(n, mask, fmt, a...) do { if ((n)) dnet_log((n), mask, fmt, ##a); else fprintf(stderr, fmt, ##a); } while (0)

struct dnet_meta *dnet_meta_search(struct dnet_node *n, void *data, uint32_t size, uint32_t type)
{
	struct dnet_meta m, *found = NULL;

	while (size) {
		if (size < sizeof(struct dnet_meta)) {
			dnet_map_log(n, DNET_LOG_ERROR, "%s: metadata size %u is too small, min %zu, searching for type 0x%x.\n",
					(n) ? dnet_dump_id(n->id) : "NULL", size, sizeof(struct dnet_meta), type);
			break;
		}

		m = *(struct dnet_meta *)data;
		dnet_convert_meta(&m);

		if (m.size + sizeof(struct dnet_meta) > size) {
			dnet_map_log(n, DNET_LOG_ERROR, "%s: metadata entry broken: entry size %u, type: 0x%x, struct size: %zu, "
					"total size left: %u, searching for type: 0x%x.\n",
					(n) ? dnet_dump_id(n->id) : "NULL", m.size, m.type, sizeof(struct dnet_meta), size, type);
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

int dnet_meta_remove(struct dnet_node *n, void *data, uint32_t *size, struct dnet_meta *m)
{
	int err = 0;
	void *ptr = m;
	struct dnet_meta tmp = *m;
	uint32_t copy;

	dnet_convert_meta(&tmp);

	ptr += tmp.size + sizeof(struct dnet_meta);

	if (*size < (uint32_t)(ptr - data)) {
		dnet_map_log(n, DNET_LOG_ERROR, "%s: broken metadata object (too large size), nothing was changed: "
				"total size: %u, meta: %u, ptr-data: %u.\n",
				(n) ? dnet_dump_id(n->id) : "NULL", *size, tmp.size, (uint32_t)(ptr - data));
		err = -EINVAL;
		goto out_exit;
	}
	copy = *size - (uint32_t)(ptr - data);

	if (copy)
		memmove(m, ptr, copy);
	*size = *size - tmp.size - sizeof(struct dnet_meta);

out_exit:
	return err;
}

struct dnet_meta *dnet_meta_add(struct dnet_node *n, void *data, uint32_t *size, struct dnet_meta *add, void *add_data)
{
	void *ptr;

	data = realloc(data, *size + sizeof(struct dnet_meta) + add->size);
	if (!data) {
		dnet_map_log(n, DNET_LOG_ERROR, "%s: failed to reallocate buffer: old size: %u, addon: %zu.\n",
				(n) ? dnet_dump_id(n->id) : "NULL", *size, sizeof(struct dnet_meta) + add->size);
		goto out_exit;
	}

	ptr = data + *size;

	memcpy(ptr, add, sizeof(struct dnet_meta));
	dnet_convert_meta(ptr);

	if (add->size)
		memcpy(ptr + sizeof(struct dnet_meta), add_data, add->size);

	*size = *size + sizeof(struct dnet_meta) + add->size;

out_exit:
	return data;
}

struct dnet_meta *dnet_meta_replace(struct dnet_node *n, void *data, uint32_t *size, struct dnet_meta *rep, void *rep_data)
{
	struct dnet_meta *m, tmp;
	int err = 0;

	m = dnet_meta_search(n, data, *size, rep->type);
	if (m) {
		tmp = *m;

		dnet_convert_meta(&tmp);

		if (tmp.size == rep->size) {
			memcpy(m->data, rep_data, tmp.size);
			return data;
		}

		err = dnet_meta_remove(n, data, size, m);
		if (err)
			goto err_out_exit;
	}

	data = dnet_meta_add(n, data, size, rep, rep_data);
	if (!data) {
		err = -ENOMEM;
		goto err_out_exit;
	}

	return data;

err_out_exit:
	return NULL;
}

int dnet_meta_read_object_id(struct dnet_node *n, unsigned char *id, char *file)
{
	int err, len;
	struct dnet_io_attr io;
	struct dnet_wait *w;
	char id_str[DNET_ID_SIZE*2+1];
	char tmp[256];

	memset(&io, 0, sizeof(struct dnet_io_attr));
	memcpy(io.id, id, DNET_ID_SIZE);
	memcpy(io.origin, id, DNET_ID_SIZE);

	io.flags = DNET_IO_FLAGS_HISTORY;

	len = snprintf(tmp, sizeof(tmp), "/tmp/meta-hist-%s", dnet_dump_id_len_raw(id, DNET_ID_SIZE, id_str));

	w = dnet_wait_alloc(~0);
	if (!w) {
		err = -ENOMEM;
		dnet_map_log(n, DNET_LOG_ERROR, "Failed to allocate read waiting.\n");
		goto err_out_exit;
	}

	err = dnet_read_file_id(n, tmp, len, 0, 0, &io, w, 1, 1);
	dnet_map_log(n, DNET_LOG_NOTICE, "%s: metadata reading history: %d.\n", dnet_dump_id(io.origin), err);
	if (err)
		goto err_out_put;

	len = snprintf(tmp, sizeof(tmp), "/tmp/meta-hist-%s%s", id_str, DNET_HISTORY_SUFFIX);

	err = rename(tmp, file);
	if (err) {
		err = -errno;
		dnet_map_log(n, DNET_LOG_ERROR, "Failed to rename tmp files: %s -> %s: %d.\n", tmp, file, err);
		goto err_out_put;
	}

err_out_put:
	dnet_wait_put(w);
err_out_exit:
	return err;
}
