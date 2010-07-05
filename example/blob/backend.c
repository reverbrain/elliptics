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
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "elliptics/packet.h"
#include "elliptics/interface.h"

#include "backends.h"

#ifndef __unused
#define __unused	__attribute__ ((unused))
#endif

#define DNET_BLOB_DEFAULT_HASH_SIZE		1024*1024*10

struct blob_backend
{
	unsigned int		hash_size;
	unsigned int		hash_flags;
	unsigned int		bsize;
	int			sync;

	int			datafd, historyfd;

	pthread_mutex_t		lock;
	off_t			data_offset, history_offset;
	struct dnet_hash	*hash;
};

struct blob_disk_control {
	unsigned char		id[DNET_ID_SIZE];
	uint64_t		flags;
	uint64_t		size;
} __attribute__ ((packed));

#define BLOB_DISK_CTL_REMOVE	(1<<0)

static inline void blob_convert_disk_control(struct blob_disk_control *ctl)
{
	ctl->flags = dnet_bswap64(ctl->flags);
	ctl->size = dnet_bswap64(ctl->size);
}

struct blob_ram_control {
	unsigned char		key[DNET_ID_SIZE + 1];
	size_t			offset;
	uint64_t		size;
};

static int blob_write_low_level(void *state, int fd, void *data, size_t size, size_t offset)
{
	ssize_t err = 0;

	while (size) {
		err = pwrite(fd, data, size, offset);
		if (err <= 0) {
			err = -errno;
			dnet_command_handler_log(state, DNET_LOG_ERROR, "blob: failed (%zd) to write %zu bytes into datafile: %s.\n",
					err, size, strerror(errno));
			if (!err)
				err = -EINVAL;
			goto err_out_exit;
		}

		data += err;
		size -= err;
		offset += err;
	}

	err = 0;

err_out_exit:
	return err;
}

//static unsigned char blob_empty_buf[4096];

static int blob_write_raw(struct blob_backend *b, void *state, int hist, struct dnet_io_attr *io, void *data)
{
	ssize_t err;
	int fd;
	struct blob_disk_control disk_ctl;
	struct blob_ram_control ctl;
	off_t offset;

	memcpy(disk_ctl.id, io->origin, DNET_ID_SIZE);
	disk_ctl.flags = 0;
	disk_ctl.size = io->size;

	blob_convert_disk_control(&disk_ctl);

	memcpy(ctl.key, io->origin, DNET_ID_SIZE);
	ctl.key[DNET_ID_SIZE] = !!hist;

	pthread_mutex_lock(&b->lock);

	if (hist) {
		fd = b->historyfd;
		ctl.offset = b->history_offset;
	} else {
		fd = b->datafd;
		ctl.offset = b->data_offset;
	}

	offset = ctl.offset;
	err = blob_write_low_level(state, fd, &disk_ctl, sizeof(struct blob_disk_control), offset);
	if (err)
		goto err_out_unlock;
	offset += sizeof(struct blob_disk_control);

	err = blob_write_low_level(state, fd, data, io->size, offset);
	if (err)
		goto err_out_unlock;
	offset += io->size;
#if 0
	size = (io->size + sizeof(struct blob_ram_control)) % b->hash_size;
	while (size) {
		int sz = size;

		if (sz > sizeof(blob_empty_buf))
			sz = sizeof(blob_empty_buf);

		err = blob_write_low_level(state, fd, blob_empty_buf, sz, offset);
		if (err)
			goto err_out_unlock;

		size -= sz;
		offset += sz;
	}
#endif
	ctl.size = offset - ctl.offset;

	err = dnet_hash_replace(b->hash, ctl.key, sizeof(ctl.key), &ctl, sizeof(ctl));
	if (err) {
		dnet_command_handler_log(state, DNET_LOG_ERROR, "blob: %s: failed to add hash entry: %s [%d].\n",
				dnet_dump_id(io->origin), strerror(-err), err);
		goto err_out_unlock;
	}

	if (hist)
		b->history_offset +=  ctl.size;
	else
		b->data_offset += ctl.size;

	dnet_command_handler_log(state, DNET_LOG_INFO, "blob: %s: written history: %d, position: %zu, size: %llu, on-disk-size: %llu.\n",
			dnet_dump_id(io->origin), hist, ctl.offset, (unsigned long long)io->size, (unsigned long long)ctl.size);

err_out_unlock:
	pthread_mutex_unlock(&b->lock);
	return err;
}

static int blob_write_history_meta(void *state, void *backend, struct dnet_io_attr *io,
		struct dnet_meta *m, void *data)
{
	struct blob_backend *b = backend;
	struct blob_ram_control ctl;
	unsigned char key[DNET_ID_SIZE + 1];
	unsigned int dsize = sizeof(struct blob_ram_control);
	void *hdata, *new_hdata;
	size_t size = 0;
	int err;

	memcpy(key, io->origin, DNET_ID_SIZE);
	key[DNET_ID_SIZE] = 1;

	err = dnet_hash_lookup(b->hash, key, sizeof(key), &ctl, &dsize);
	if (!err)
		size = ctl.size;

	hdata = malloc(size);
	if (!hdata) {
		err = -ENOMEM;
		dnet_command_handler_log(state, DNET_LOG_ERROR,
			"%s: failed to allocate %zu bytes for history data: %s.\n",
				dnet_dump_id(key), size, strerror(errno));
		goto err_out_exit;
	}

	if (!err) {
		struct blob_disk_control *dc;

		dnet_command_handler_log(state, DNET_LOG_INFO,
			"%s: found existing block at: %llu, size: %zu.\n",
			dnet_dump_id(key), (unsigned long long)ctl.offset, size);

		err = pread(b->historyfd, hdata, size, ctl.offset);
		if (err != (int)size) {
			err = -errno;
			dnet_command_handler_log(state, DNET_LOG_ERROR,
				"%s: failed to read %zu bytes from history at %llu: %s.\n",
				dnet_dump_id(key), size, (unsigned long long)ctl.offset, strerror(errno));
			goto err_out_free;
		}

		dc = hdata;

		blob_convert_disk_control(dc);
		dc->flags |= BLOB_DISK_CTL_REMOVE;
		size = dc->size;
		blob_convert_disk_control(dc);

		err = pwrite(b->historyfd, dc, sizeof(struct blob_disk_control), ctl.offset);
		if (err != (int)sizeof(*dc)) {
			err = -errno;
			dnet_command_handler_log(state, DNET_LOG_ERROR,
				"%s: failed to erase (mark) history entry at %llu: %s.\n",
				dnet_dump_id(key), (unsigned long long)ctl.offset, strerror(errno));
			goto err_out_free;
		}

		memmove(hdata, dc + 1, size);
	}

	new_hdata = backend_process_meta(state, io, hdata, &size, m, data);
	if (!new_hdata) {
		err = -ENOMEM;
		dnet_command_handler_log(state, DNET_LOG_ERROR,
			"%s: failed to update history file: %s.\n",
				dnet_dump_id(key), strerror(errno));
		goto err_out_free;
	}
	hdata = new_hdata;

	io->size = size;
	err = blob_write_raw(b, state, 1, io, new_hdata);
	if (err) {
		err = -errno;
		dnet_command_handler_log(state, DNET_LOG_ERROR,
			"%s: failed to update (%zu bytes) history: %s.\n",
				dnet_dump_id(key), size, strerror(errno));
		goto err_out_free;
	}

	err = 0;

err_out_free:
	free(hdata);
err_out_exit:
	return err;
}

static int blob_write_history(struct blob_backend *b, void *state, struct dnet_io_attr *io, void *data)
{
	return backend_write_history(state, b, io, data, blob_write_history_meta);
}

static int blob_write(struct blob_backend *r, void *state, struct dnet_cmd *cmd,
		struct dnet_attr *attr __unused, void *data)
{
	int err;
	struct dnet_io_attr *io = data;

	dnet_convert_io_attr(io);
	
	data += sizeof(struct dnet_io_attr);

	if (io->flags & DNET_IO_FLAGS_HISTORY) {
		err = blob_write_history(r, state, io, data);
		if (err)
			goto err_out_exit;
	} else {
		err = blob_write_raw(r, state, 0, io, data);
		if (err)
			goto err_out_exit;

		if (!(io->flags & DNET_IO_FLAGS_NO_HISTORY_UPDATE)) {
			struct dnet_history_entry e;

			dnet_setup_history_entry(&e, io->id, io->size, io->offset, NULL, io->flags);

			io->flags |= DNET_IO_FLAGS_APPEND | DNET_IO_FLAGS_HISTORY;
			io->flags &= ~DNET_IO_FLAGS_META;
			io->size = sizeof(struct dnet_history_entry);
			io->offset = 0;

			err = blob_write_history(r, state, io, &e);
			if (err)
				goto err_out_exit;
		}
	}

	dnet_command_handler_log(state, DNET_LOG_NOTICE,
		"blob: %s: IO offset: %llu, size: %llu.\n", dnet_dump_id(cmd->id),
		(unsigned long long)io->offset, (unsigned long long)io->size);

	return 0;

err_out_exit:
	return err;
}

static int blob_read(struct blob_backend *b, void *state, struct dnet_cmd *cmd,
		struct dnet_attr *attr, void *data)
{
	struct dnet_io_attr *io = data;
	struct blob_ram_control ctl;
	unsigned char key[DNET_ID_SIZE + 1];
	unsigned long long size = io->size;
	unsigned int dsize = sizeof(struct blob_ram_control);
	off_t offset;
	int fd, err;

	data += sizeof(struct dnet_io_attr);

	dnet_convert_io_attr(io);

	memcpy(key, io->origin, DNET_ID_SIZE);
	key[DNET_ID_SIZE] = !!(io->flags & DNET_IO_FLAGS_HISTORY);
	fd = (io->flags & DNET_IO_FLAGS_HISTORY) ? b->historyfd : b->datafd;

	err = dnet_hash_lookup(b->hash, key, sizeof(key), &ctl, &dsize);
	if (err) {
		dnet_command_handler_log(state, DNET_LOG_ERROR,
			"blob: %s: could not find data: %d.\n",
				dnet_dump_id(io->origin), err);
		goto err_out_exit;
	}

	if (!size)
		size = ctl.size - sizeof(struct blob_disk_control);

	offset = ctl.offset + sizeof(struct blob_disk_control) + io->offset;

	if (attr->size == sizeof(struct dnet_io_attr)) {
		struct dnet_data_req *r;
		struct dnet_cmd *c;
		struct dnet_attr *a;
		struct dnet_io_attr *rio;

		r = dnet_req_alloc(state, sizeof(struct dnet_cmd) +
				sizeof(struct dnet_attr) + sizeof(struct dnet_io_attr));
		if (!r) {
			err = -ENOMEM;
			dnet_command_handler_log(state, DNET_LOG_ERROR,
				"%s: failed to allocate reply attributes.\n",
					dnet_dump_id(io->origin));
			goto err_out_exit;
		}

		dnet_req_set_fd(r, fd, offset, size, 0);

		c = dnet_req_header(r);
		a = (struct dnet_attr *)(c + 1);
		rio = (struct dnet_io_attr *)(a + 1);

		memcpy(c->id, io->origin, DNET_ID_SIZE);
		memcpy(rio->origin, io->origin, DNET_ID_SIZE);
	
		dnet_command_handler_log(state, DNET_LOG_NOTICE,
			"%s: read: requested offset: %llu, size: %llu, stored-size: %llu, data lives at: %zu.\n",
				dnet_dump_id(io->origin), (unsigned long long)io->offset,
				size, (unsigned long long)ctl.size, ctl.offset);

		if (cmd->flags & DNET_FLAGS_NEED_ACK)
			c->flags = DNET_FLAGS_MORE;

		c->status = 0;
		c->size = sizeof(struct dnet_attr) + sizeof(struct dnet_io_attr) + size;
		c->trans = cmd->trans | DNET_TRANS_REPLY;

		a->cmd = DNET_CMD_READ;
		a->size = sizeof(struct dnet_io_attr) + size;
		a->flags = attr->flags;

		rio->size = size;
		rio->offset = io->offset;
		rio->flags = io->flags;

		dnet_convert_cmd(c);
		dnet_convert_attr(a);
		dnet_convert_io_attr(rio);

		err = dnet_data_ready(state, r);
		if (err)
			goto err_out_exit;
	} else {
		if (size > attr->size - sizeof(struct dnet_io_attr))
			size = attr->size - sizeof(struct dnet_io_attr);

		err = pread(fd, data, size, offset);
		if (err <= 0) {
			err = -errno;
			dnet_command_handler_log(state, DNET_LOG_ERROR,
				"%s: failed to read object data: %s.\n",
					dnet_dump_id(io->origin), strerror(errno));
			goto err_out_exit;
		}

		io->size = err;
		attr->size = sizeof(struct dnet_io_attr) + io->size;
	}

	return 0;

err_out_exit:
	return err;
}

static int blob_del(struct blob_backend *r, void *state __unused, struct dnet_cmd *cmd,
		struct dnet_attr *attr, void *data)
{
	return -1;
}

static int blob_backend_command_handler(void *state, void *priv,
		struct dnet_cmd *cmd, struct dnet_attr *attr, void *data)
{
	int err;
	struct blob_backend *r = priv;

	switch (attr->cmd) {
		case DNET_CMD_WRITE:
			err = blob_write(r, state, cmd, attr, data);
			break;
		case DNET_CMD_READ:
			err = blob_read(r, state, cmd, attr, data);
			break;
		case DNET_CMD_LIST:
			err = -ENOTSUP;
			//err = blob_list(r, state, cmd, attr);
			break;
		case DNET_CMD_STAT:
			err = backend_stat(state, NULL, cmd, attr);
			break;
		case DNET_CMD_DEL:
			err = blob_del(r, state, cmd, attr, data);
			break;
		default:
			err = -EINVAL;
			break;
	}

	return err;
}

static int dnet_blob_set_sync(struct dnet_config_backend *b, char *key __unused, char *value)
{
	struct blob_backend *r = b->data;

	r->sync = atoi(value);
	return 0;
}

static int dnet_blob_set_data(struct dnet_config_backend *b, char *key, char *file)
{
	struct blob_backend *r = b->data;
	int fd, err = 0;
	off_t offset;

	fd = open(file, O_RDWR | O_CREAT, 0644);
	if (fd < 0) {
		err = -errno;
		fprintf(stderr, "Failed to open %s file '%s': %s.\n", key, file, strerror(errno));
		goto err_out_exit;
	}

	offset = lseek(fd, 0, SEEK_END);
	if (offset == (off_t) -1) {
		fprintf(stderr, "Failed to determine %s file '%s' offset: %s.\n", key, file, strerror(errno));
		goto err_out_close;
	}

	if (!strcmp(key, "data")) {
		r->datafd = fd;
		r->data_offset = offset;
	} else if (!strcmp(key, "history")) {
		r->historyfd = fd;
		r->history_offset = offset;
	} else {
		err = -EINVAL;
		goto err_out_close;
	}

	return 0;

err_out_close:
	close(fd);
err_out_exit:
	return err;
}

static int dnet_blob_set_block_size(struct dnet_config_backend *b, char *key __unused, char *value)
{
	struct blob_backend *r = b->data;

	r->bsize = strtoul(value, NULL, 0);
	return 0;
}

static int dnet_blob_set_hash_size(struct dnet_config_backend *b, char *key __unused, char *value)
{
	struct blob_backend *r = b->data;

	r->hash_size = strtoul(value, NULL, 0);
	return 0;
}

static int dnet_blob_set_hash_flags(struct dnet_config_backend *b, char *key __unused, char *value)
{
	struct blob_backend *r = b->data;

	r->hash_flags = strtoul(value, NULL, 0);
	return 0;
}

static int dnet_blob_config_init(struct dnet_config_backend *b, struct dnet_config *c)
{
	struct blob_backend *r = b->data;
	int err;

	if (!r->datafd || !r->historyfd) {
		err = -EINVAL;
		goto err_out_exit;
	}

	err = pthread_mutex_init(&r->lock, NULL);
	if (err) {
		fprintf(stderr, "Failed to initialize pthread mutex: %d\n", err);
		err = -errno;
		goto err_out_close;
	}

	if (!r->hash_size)
		r->hash_size = DNET_BLOB_DEFAULT_HASH_SIZE;

	r->hash = dnet_hash_init(r->hash_size, r->hash_flags);
	if (!r->hash) {
		err = -EINVAL;
		goto err_out_lock_destroy;
	}

	c->command_private = b->data;
	c->command_handler = blob_backend_command_handler;

	return 0;

err_out_lock_destroy:
	pthread_mutex_destroy(&r->lock);
err_out_close:
	close(r->datafd);
	close(r->historyfd);
err_out_exit:
	return err;
}

static void dnet_blob_config_cleanup(struct dnet_config_backend *b)
{
	struct blob_backend *r = b->data;

	dnet_hash_exit(r->hash);

	close(r->datafd);
	close(r->historyfd);
	pthread_mutex_destroy(&r->lock);
}

static struct dnet_config_entry dnet_cfg_entries_blobsystem[] = {
	{"sync", dnet_blob_set_sync},
	{"data", dnet_blob_set_data},
	{"history", dnet_blob_set_data},
	{"block_size", dnet_blob_set_block_size},
	{"hash_table_size", dnet_blob_set_hash_size},
	{"hash_table_flags", dnet_blob_set_hash_flags},
};

static struct dnet_config_backend dnet_blob_backend = {
	.name			= "blob",
	.ent			= dnet_cfg_entries_blobsystem,
	.num			= ARRAY_SIZE(dnet_cfg_entries_blobsystem),
	.size			= sizeof(struct blob_backend),
	.init			= dnet_blob_config_init,
	.cleanup		= dnet_blob_config_cleanup,
};

int dnet_blob_backend_init(void)
{
	return dnet_backend_register(&dnet_blob_backend);
}

void dnet_blob_backend_exit(void)
{
	/* cleanup routing will be called explicitly through backend->cleanup() callback */
}
