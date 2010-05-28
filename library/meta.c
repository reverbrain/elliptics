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

int dnet_meta_create_file(struct dnet_node *n, char *metafile, struct dnet_meta *m, void *mdata)
{
	int fd, err, size;
	struct dnet_meta *meta;
	struct stat st;
	void *data;

	fd = open(metafile, O_RDWR | O_CREAT, 0644);
	if (fd < 0) {
		err = -errno;
		dnet_map_log(n, DNET_LOG_ERROR, "Failed to open metadata file '%s'", metafile);
		goto err_out_exit;
	}

	err = fstat(fd, &st);
	if (err) {
		err = -errno;
		dnet_map_log(n, DNET_LOG_ERROR, "Failed to stat metadata file '%s'", metafile);
		goto err_out_close;
	}
	size = st.st_size;

	data = meta = malloc(size);
	if (!meta) {
		err = -errno;
		dnet_map_log(n, DNET_LOG_ERROR, "Failed to allocate %d bytes for metadata file '%s'", size, metafile);
		goto err_out_close;
	}

	err = read(fd, meta, size);
	if (err != size) {
		err = -errno;
		dnet_map_log(n, DNET_LOG_ERROR, "Failed to read %d bytes from metadata file '%s'", size, metafile);
		goto err_out_free;
	}

	dnet_map_log(n, DNET_LOG_INFO, "%s: meta: %d, meta_size: %d, size: %d.\n", metafile, m->type, m->size, size);

	meta = dnet_meta_replace(n, meta, (uint32_t *)&size, m, mdata);
	if (!meta) {
		err = -ENOMEM;
		dnet_map_log(n, DNET_LOG_ERROR, "Failed to replace metadata in file '%s'", metafile);
		goto err_out_free;
	}

	data = meta;

	err = pwrite(fd, meta, size, 0);
	if (err != size) {
		err = -ENOMEM;
		dnet_map_log(n, DNET_LOG_ERROR, "Failed to write metadata in file '%s'", metafile);
		goto err_out_free;
	}
	err = 0;

err_out_free:
	free(data);
err_out_close:
	close(fd);
err_out_exit:
	return err;
}

int dnet_meta_read_object_id(struct dnet_node *n, unsigned char *id, char *file)
{
	int err, len;
	struct dnet_io_attr io;
	struct dnet_history_map m;
	struct dnet_wait *w;
	char tmp[32];

	memset(&io, 0, sizeof(struct dnet_io_attr));
	memcpy(io.id, id, DNET_ID_SIZE);
	memcpy(io.origin, id, DNET_ID_SIZE);

	io.flags = DNET_IO_FLAGS_HISTORY;

	len = snprintf(tmp, sizeof(tmp), "/tmp/meta-hist-%d", getpid());

	w = dnet_wait_alloc(~0);
	if (!w) {
		err = -ENOMEM;
		dnet_map_log(n, DNET_LOG_ERROR, "Failed to allocate read waiting.\n");
		goto err_out_exit;
	}

	err = dnet_read_file_id(n, tmp, len, 0, 0, &io, w, 1, 1);
	dnet_map_log(n, DNET_LOG_INFO, "%s: metadata reading history: %d.\n", dnet_dump_id(io.origin), err);
	if (err)
		goto err_out_put;

	snprintf(tmp, sizeof(tmp), "/tmp/meta-hist-%d%s", getpid(), DNET_HISTORY_SUFFIX);

	err = dnet_map_history(n, tmp, &m);
	if (err)
		goto err_out_unlink;

	io.flags = 0;
	memcpy(io.id, m.ent[m.num - 1].id, DNET_ID_SIZE);
	memcpy(io.origin, io.id, DNET_ID_SIZE);

	err = dnet_read_file_id(n, file, strlen(file), 0, 0, &io, w, 0, 1);
	dnet_map_log(n, DNET_LOG_INFO, "%s: metadata reading transaction: %d.\n", dnet_dump_id(io.origin), err);
	if (err)
		goto err_out_unmap;

err_out_unmap:
	dnet_unmap_history(n, &m);
err_out_unlink:
	unlink(tmp);
err_out_put:
	dnet_wait_put(w);
err_out_exit:
	return err;
}

static int dnet_meta_read_object(struct dnet_node *n, char *meta_object, int meta_len, char *metafile)
{
	int err, pos = 0, error = 0;
	unsigned char id[DNET_ID_SIZE];
	unsigned char addr[DNET_ID_SIZE];

	while (1) {
		unsigned int rsize = DNET_ID_SIZE;

		err = dnet_transform(n, meta_object, meta_len, id, addr, &rsize, &pos);
		if (err) {
			if (err > 0)
				break;
			if (!error)
				error = err;
			continue;
		}

		err = dnet_meta_read_object_id(n, id, metafile);
		if (err) {
			error = err;
			continue;
		}

		error = 0;
		break;
	}

	return error;
}

int dnet_meta_read(struct dnet_node *n, char *obj, int len, char *metafile)
{
	char meta_object[len + sizeof(DNET_META_SUFFIX) + 1];

	snprintf(meta_object, len, "%s", obj);
	memcpy(meta_object + len, DNET_META_SUFFIX, sizeof(DNET_META_SUFFIX));
	meta_object[sizeof(meta_object) - 1] = '\0';

	return dnet_meta_read_object(n, meta_object, sizeof(meta_object), metafile);
}

int dnet_meta_write(struct dnet_node *n, struct dnet_meta *m, void *mdata,
		char *obj, int len, char *metafile)
{
	char meta_object[len + sizeof(DNET_META_SUFFIX) + 1];
	int err, meta_unlink = 0;
	char file[64];

	snprintf(meta_object, len, "%s", obj);
	memcpy(meta_object + len, DNET_META_SUFFIX, sizeof(DNET_META_SUFFIX));
	meta_object[sizeof(meta_object) - 1] = '\0';

	if (!metafile) {
		snprintf(file, sizeof(file), "/tmp/meta-%d", getpid());
		err = dnet_meta_read_object(n, meta_object, sizeof(meta_object), file);
		if (err) {
			if (err != -ENOENT)
				goto err_out_exit;
		}

		err = open(file, O_RDWR | O_CREAT | O_TRUNC, 0644);
		if (err < 0) {
			err = -errno;
			dnet_map_log(n, DNET_LOG_ERROR, "Failed to create empty metadata file '%s'", file);
			goto err_out_exit;
		}
		close(err);

		metafile = file;
		meta_unlink = 1;
	}

	err = dnet_meta_create_file(n, metafile, m, mdata);
	if (err)
		goto err_out_unlink;

	err = dnet_write_file_local_offset(n, metafile, meta_object, sizeof(meta_object),
			NULL, 0, 0, 0, 0, DNET_IO_FLAGS_META | DNET_IO_FLAGS_ID_CONTENT);

err_out_unlink:
	if (meta_unlink)
		unlink(metafile);
err_out_exit:
	return err;
}
