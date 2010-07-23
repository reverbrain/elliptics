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

#define _XOPEN_SOURCE 600

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

#include "../backends.h"
#include "blob.h"

#ifndef __unused
#define __unused	__attribute__ ((unused))
#endif

#define DNET_BLOB_INDEX_SUFFIX			".index"
#define DNET_BLOB_DEFAULT_HASH_SIZE		1024*1024*10

struct blob_backend
{
	unsigned int		hash_size;
	unsigned int		hash_flags;
	int			sync;

	char			*data_file, *history_file;

	int			iterate_threads;

	pthread_mutex_t		lock;

	unsigned int		data_bsize, history_bsize;
	int			data_index, history_index;
	struct blob_backend_io	*data, *history;

	uint64_t		blob_size;

	struct dnet_hash	*hash;
};

struct dnet_blob_iterator_data {
	pthread_t		id;

	struct blob_backend	*b;
	struct blob_backend_io	*io;
	struct dnet_log		*log;

	size_t			num;
	off_t			pos;

	int			(* iterator)(struct blob_disk_control *dc, int file_index,
					void *data, off_t position, void *priv);
	void			*priv;

	int			err;
};

static void *dnet_blob_iterator(void *data)
{
	struct dnet_blob_iterator_data *p = data;

	p->err = blob_iterate(p->io, p->pos, p->num, p->log, p->iterator, p->priv);
	if (p->err)
		dnet_backend_log(DNET_LOG_ERROR, "blob: data iteration failed: %d.\n", p->err);

	return &p->err;
};

static int dnet_blob_iterate(struct blob_backend *b, int hist, struct dnet_log *log,
	int (* iterator)(struct blob_disk_control *dc, int file_index, void *data, off_t position, void *priv),
	void *priv)
{
	int j, index_num = hist ? b->history_index : b->data_index;
	int error = 0;
	int iterate_threads = b->iterate_threads;

	for (j=0; j<index_num + 1; ++j) {
		struct blob_backend_io *io = hist ? &b->history[j] : &b->data[j];

		if (!io->index_pos)
			break;

		if ((uint64_t)io->index_pos < iterate_threads + b->blob_size / sizeof(struct blob_disk_control))
			iterate_threads = 1;

		{
			int i, err;
			int thread_num = iterate_threads - 1;
			struct dnet_blob_iterator_data p[thread_num + 1];
			off_t pos = 0, num = io->index_pos / iterate_threads;
			off_t rest = io->index_pos;

			memset(p, 0, sizeof(p));

			for (i=0; i<thread_num + 1; ++i) {
				p[i].pos = pos;
				p[i].num = num;
				p[i].b = b;
				p[i].io = io;
				p[i].iterator = iterator;
				p[i].priv = priv;
				p[i].log = log;

				pos += num;
				rest -= num;
			}
			p[thread_num].num = rest + num;

			for (i=0; i<thread_num; ++i) {
				err = pthread_create(&p[i].id, NULL, dnet_blob_iterator, &p[i]);
				if (err) {
					dnet_backend_log(DNET_LOG_ERROR, "blob: failed to create iterator thread: %d.\n", err);
					break;
				}
			}

			dnet_blob_iterator(&p[thread_num]);

			error = p[thread_num].err;

			for (i=0; i<thread_num; ++i) {
				pthread_join(p[i].id, NULL);

				if (p[i].err)
					error = p[i].err;
			}

			posix_fadvise(io->fd, 0, io->offset, POSIX_FADV_RANDOM);

			dnet_backend_log(DNET_LOG_INFO, "blob: %d/%d: iteration completed: num: %llu, threads: %u, status: %d.\n",
					j, index_num, (unsigned long long)io->index_pos, iterate_threads, error);
		}

	}

	return error;
}

static int dnet_blob_open_file(char *file, off_t *off_ptr)
{
	int fd, err = 0;
	off_t offset;

	fd = open(file, O_RDWR | O_CREAT, 0644);
	if (fd < 0) {
		err = -errno;
		dnet_backend_log(DNET_LOG_ERROR, "Failed to open file '%s': %s.\n", file, strerror(errno));
		goto err_out_exit;
	}

	offset = lseek(fd, 0, SEEK_END);
	if (offset == (off_t) -1) {
		dnet_backend_log(DNET_LOG_ERROR, "Failed to determine file's '%s' size: %s.\n", file, strerror(errno));
		goto err_out_close;
	}

	posix_fadvise(fd, 0, offset, POSIX_FADV_SEQUENTIAL);

	*off_ptr = offset;
	return fd;

err_out_close:
	close(fd);
err_out_exit:
	return err;
}

static int dnet_blob_open_files(char *path, struct blob_backend_io *io)
{
	char index[strlen(path)+sizeof(DNET_BLOB_INDEX_SUFFIX) + 1]; /* 0-byte */
	int err;

	io->fd = dnet_blob_open_file(path, &io->offset);
	if (io->fd < 0) {
		err = io->fd;
		goto err_out_exit;
	}

	sprintf(index, "%s%s", path, DNET_BLOB_INDEX_SUFFIX);

	io->index = dnet_blob_open_file(index, &io->index_pos);
	if (io->index < 0) {
		err = io->index;
		goto err_out_close;
	}

	io->index_pos = io->index_pos / sizeof(struct blob_disk_control);

	dnet_backend_log(DNET_LOG_ERROR, "file: %s, size: %llu, indexed %llu entries, fds: %d, %d.\n",
			path, io->offset, io->index_pos, io->fd, io->index);
	return 0;

err_out_close:
	close(io->fd);
err_out_exit:
	return err;
}

static void dnet_blob_close_files_all(struct blob_backend *b)
{
	int i;

	for (i=0; i<b->data_index; ++i)
		close(b->data[i].fd);
	for (i=0; i<b->history_index; ++i)
		close(b->history[i].fd);
}

static int dnet_blob_extend_io(struct blob_backend *b, struct blob_backend_io *new_io, int num, int hist)
{
	struct blob_backend_io *io = hist ? b->history : b->data;

	io = realloc(io, num * sizeof(struct blob_backend_io));
	if (!io)
		return -ENOMEM;

	memcpy(&io[num - 1], new_io, sizeof(struct blob_backend_io));

	if (hist) {
		b->history = io;
		b->history_index++;
	} else {
		b->data = io;
		b->data_index++;
	}

	return 0;
}

static int dnet_blob_allocate_io(struct blob_backend *b, char *path, int hist)
{
	struct blob_backend_io tmp;
	char file[strlen(path) + 16 + sizeof(DNET_BLOB_INDEX_SUFFIX)]; /* should be enough for file index */
	int err, i = 0, last = 0, idx;

	idx = hist ? b->history_index : b->data_index;
	idx++;

	for (i=idx; ; i++) {
		snprintf(file, sizeof(file), "%s.%d", path, i);

		err = open(file, O_RDWR);
		if (err < 0 && (errno == ENOENT)) {
			last = 1;
			if (i > idx) {
				err = -errno;
				break;
			}
		}
		if (err >= 0)
			close(err);

		memset(&tmp, 0, sizeof(tmp));

		err = dnet_blob_open_files(file, &tmp);
		if (err)
			break;

		tmp.file_index = i;

		err = dnet_blob_extend_io(b, &tmp, i + 1, hist);
		if (err)
			break;

		if (last)
			break;
	}

	if (i && (err == -ENOENT))
		err = 0;

	return err;
}

static int blob_write_low_level(int fd, void *data, size_t size, size_t offset)
{
	ssize_t err = 0;

	while (size) {
		err = pwrite(fd, data, size, offset);
		if (err <= 0) {
			err = -errno;
			dnet_backend_log(DNET_LOG_ERROR, "blob: failed (%zd) to write %zu bytes at offset %llu into (fd: %d) datafile: %s.\n",
					err, size, (unsigned long long)offset, fd, strerror(errno));
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

static int blob_mark_index_removed(int fd, off_t offset, int hist)
{
	uint64_t flags = dnet_bswap64(BLOB_DISK_CTL_REMOVE);
	int err;

	err = pwrite(fd, &flags, sizeof(flags), offset + offsetof(struct blob_disk_control, flags));
	if (err != (int)sizeof(flags))
		err = -errno;

	dnet_backend_log(DNET_LOG_NOTICE, "backend: marking index entry as removed: history: %d, "
			"position: %llu (0x%llx), fd: %d, err: %d.\n",
			hist, (unsigned long long)offset, (unsigned long long)offset, fd, err);
	return 0;
}

static unsigned char blob_empty_buf[40960];

static int blob_update_index(struct blob_backend *b, struct blob_backend_io *io, struct blob_ram_control *data_ctl, struct blob_ram_control *old)
{
	struct blob_disk_control dc;
	off_t *offset = &io->index_pos;
	int err;

	memcpy(dc.id, data_ctl->key, DNET_ID_SIZE);
	dc.flags = 0;
	dc.data_size = data_ctl->size;
	dc.disk_size = sizeof(struct blob_disk_control);
	dc.position = data_ctl->offset;

	if (data_ctl->key[DNET_ID_SIZE])
		dc.flags = BLOB_DISK_CTL_HISTORY;

	dnet_backend_log(DNET_LOG_NOTICE, "%s: updated index at position %llu (0x%llx), data position: %llu (0x%llx), data size: %llu.\n",
			dnet_dump_id(data_ctl->key),
			(unsigned long long)(*offset)*sizeof(dc), (unsigned long long)(*offset)*sizeof(dc),
			(unsigned long long)data_ctl->offset, (unsigned long long)data_ctl->offset,
			data_ctl->size);

	blob_convert_disk_control(&dc);

	err = pwrite(io->index, &dc, sizeof(dc), (*offset)*sizeof(dc));
	if (err != (int)sizeof(dc)) {
		err = -errno;
		dnet_backend_log(DNET_LOG_ERROR, "%s: failed to write index data at %llu: %s.\n",
			dnet_dump_id(data_ctl->key), (unsigned long long)(*offset)*sizeof(dc), strerror(errno));
		goto err_out_exit;
	}

	printf("wrote %u bytes at %llu into %d\n", sizeof(dc), (*offset)*sizeof(dc), io->index);

	*offset = *offset + 1;
	err = 0;

	if (old) {
		int hist = data_ctl->key[DNET_ID_SIZE];
		io = hist ? &b->history[old->file_index] : &b->data[old->file_index];

		blob_mark_index_removed(io->index, old->index_pos * sizeof(dc), data_ctl->key[DNET_ID_SIZE]);
		blob_mark_index_removed(io->fd, old->offset, data_ctl->key[DNET_ID_SIZE]);
	}

err_out_exit:
	return err;
}

static ssize_t blob_write_data(struct blob_backend *b, struct blob_backend_io *io, int hist, struct dnet_io_attr *ioattr, void *data)
{
	struct blob_disk_control disk_ctl;
	struct blob_ram_control ctl, old;
	unsigned int dsize = sizeof(old);
	off_t offset;
	size_t disk_size;
	ssize_t err;
	int have_old = 0, bsize = b->data_bsize;

	memcpy(ctl.key, ioattr->origin, DNET_ID_SIZE);
	ctl.key[DNET_ID_SIZE] = !!hist;

	ctl.offset = io->offset;
	ctl.index_pos = io->index_pos;
	ctl.file_index = io->file_index;

	disk_ctl.flags = 0;
	if (hist) {
		bsize = b->history_bsize;
		disk_ctl.flags = BLOB_DISK_CTL_HISTORY;
	}

	disk_ctl.position = ctl.offset;
	disk_ctl.data_size = ioattr->size;
	disk_ctl.disk_size = ioattr->size + sizeof(struct blob_disk_control);
	if (bsize)
		disk_ctl.disk_size = ALIGN(disk_ctl.disk_size, bsize);

	memcpy(disk_ctl.id, ioattr->origin, DNET_ID_SIZE);

	blob_convert_disk_control(&disk_ctl);

	offset = ctl.offset;
	err = blob_write_low_level(io->fd, &disk_ctl, sizeof(struct blob_disk_control), offset);
	if (err)
		goto err_out_exit;
	offset += sizeof(struct blob_disk_control);

	err = blob_write_low_level(io->fd, data, ioattr->size, offset);
	if (err)
		goto err_out_exit;
	offset += ioattr->size;

	if (bsize) {
		int size = bsize - ((offset - ctl.offset) % bsize);

		while (size && size < bsize) {
			unsigned int sz = size;

			if (sz > sizeof(blob_empty_buf))
				sz = sizeof(blob_empty_buf);

			err = blob_write_low_level(io->fd, blob_empty_buf, sz, offset);
			if (err)
				goto err_out_exit;

			size -= sz;
			offset += sz;
		}
	}
	disk_size = offset - ctl.offset;
	ctl.size = ioattr->size;

	err = dnet_hash_lookup(b->hash, ctl.key, sizeof(ctl.key), &old, &dsize);
	if (!err)
		have_old = 1;

	err = dnet_hash_replace(b->hash, ctl.key, sizeof(ctl.key), &ctl, sizeof(ctl));
	if (err) {
		dnet_backend_log(DNET_LOG_ERROR, "blob: %s: failed to add hash entry: %s [%d].\n",
				dnet_dump_id(ioattr->origin), strerror(-err), err);
		goto err_out_exit;
	}

	io->offset += disk_size;

	err = blob_update_index(b, io, &ctl, have_old ? &old : NULL);
	if (err)
		goto err_out_exit;

	dnet_backend_log(DNET_LOG_INFO, "blob: %s: written history: %d, position: %zu, size: %llu, on-disk-size: %zu.\n",
			dnet_dump_id(ioattr->origin), hist, ctl.offset, (unsigned long long)ioattr->size, disk_size);

err_out_exit:
	return err;
}

static int blob_write_raw(struct blob_backend *b, int hist, struct dnet_io_attr *ioattr, void *data)
{
	ssize_t err;
	struct blob_backend_io *io;

	pthread_mutex_lock(&b->lock);

	if (hist)
		io = &b->history[b->history_index];
	else
		io = &b->data[b->data_index];

	err = blob_write_data(b, io, hist, ioattr, data);
	if (err)
		goto err_out_unlock;

	if (io->offset >= (off_t)b->blob_size) {
		char *file = hist ? b->history_file : b->data_file;

		err = dnet_blob_allocate_io(b, file, hist);
		if (err)
			goto err_out_unlock;
	}

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
	uint64_t saved_io_size = io->size;
	size_t size = 0;
	int err;

	memcpy(key, io->origin, DNET_ID_SIZE);
	key[DNET_ID_SIZE] = 1;

	err = dnet_hash_lookup(b->hash, key, sizeof(key), &ctl, &dsize);
	if (!err)
		size = ctl.size + sizeof(struct blob_disk_control);

	hdata = malloc(size);
	if (!hdata) {
		err = -ENOMEM;
		dnet_backend_log(DNET_LOG_ERROR, "%s: failed to allocate %zu bytes for history data: %s.\n",
				dnet_dump_id(key), size, strerror(errno));
		goto err_out_exit;
	}

	if (!err) {
		struct blob_disk_control *dc;
		struct blob_backend_io *io;
		
		pthread_mutex_lock(&b->lock);

		io = &b->history[ctl.file_index];

		dnet_backend_log(DNET_LOG_INFO,	"%s: found existing block at: %llu, size: %zu, file_index: %d.\n",
			dnet_dump_id(key), (unsigned long long)ctl.offset, size, ctl.file_index);

		err = pread(io->fd, hdata, size, ctl.offset);
		if (err != (int)size) {
			err = -errno;
			dnet_backend_log(DNET_LOG_ERROR, "%s: failed to read %zu bytes from history at %llu: %s.\n",
				dnet_dump_id(key), size, (unsigned long long)ctl.offset, strerror(errno));
			pthread_mutex_unlock(&b->lock);
			goto err_out_free;
		}

		dc = hdata;

		blob_convert_disk_control(dc);
		dc->flags |= BLOB_DISK_CTL_REMOVE;
		size = dc->data_size;
		blob_convert_disk_control(dc);

		err = pwrite(io->fd, dc, sizeof(struct blob_disk_control), ctl.offset);
		if (err != (int)sizeof(*dc)) {
			err = -errno;
			dnet_backend_log(DNET_LOG_ERROR, "%s: failed to erase (mark) history entry at %llu: %s.\n",
				dnet_dump_id(key), (unsigned long long)ctl.offset, strerror(errno));
			pthread_mutex_unlock(&b->lock);
			goto err_out_free;
		}

		pthread_mutex_unlock(&b->lock);

		memmove(hdata, dc + 1, size);
	}

	new_hdata = backend_process_meta(state, io, hdata, (uint32_t *)&size, m, data);
	if (!new_hdata) {
		err = -ENOMEM;
		dnet_backend_log(DNET_LOG_ERROR, "%s: failed to update history file: %s.\n",
				dnet_dump_id(key), strerror(errno));
		goto err_out_free;
	}
	hdata = new_hdata;

	io->size = size;
	err = blob_write_raw(b, 1, io, new_hdata);
	io->size = saved_io_size;
	if (err) {
		err = -errno;
		dnet_backend_log(DNET_LOG_ERROR, "%s: failed to update (%zu bytes) history: %s.\n",
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
		err = blob_write_raw(r, 0, io, data);
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

	dnet_backend_log(DNET_LOG_NOTICE, "blob: %s: IO offset: %llu, size: %llu.\n", dnet_dump_id(cmd->id),
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

	err = dnet_hash_lookup(b->hash, key, sizeof(key), &ctl, &dsize);
	if (err) {
		dnet_backend_log(DNET_LOG_ERROR, "blob: %s: could not find data: %d.\n",
				dnet_dump_id(io->origin), err);
		goto err_out_exit;
	}

	fd = (io->flags & DNET_IO_FLAGS_HISTORY) ?
		b->history[ctl.file_index].fd :
		b->data[ctl.file_index].fd;

	if (!size)
		size = ctl.size;

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
			dnet_backend_log(DNET_LOG_ERROR, "%s: failed to allocate reply attributes.\n",
					dnet_dump_id(io->origin));
			goto err_out_exit;
		}

		dnet_req_set_fd(r, fd, offset, size, 0);

		c = dnet_req_header(r);
		a = (struct dnet_attr *)(c + 1);
		rio = (struct dnet_io_attr *)(a + 1);

		memcpy(c->id, io->origin, DNET_ID_SIZE);
		memcpy(rio->origin, io->origin, DNET_ID_SIZE);

		dnet_backend_log(DNET_LOG_NOTICE, "%s: read: requested offset: %llu, size: %llu, "
				"stored-size: %llu, data lives at: %zu.\n",
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
			dnet_backend_log(DNET_LOG_ERROR, "%s: failed to read object data: %s.\n",
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

static int blob_del_entry(struct blob_backend *b, struct dnet_cmd *cmd, int hist)
{
	unsigned char key[DNET_ID_SIZE + 1];
	struct blob_ram_control ctl;
	unsigned int dsize = sizeof(struct blob_ram_control);
	struct blob_disk_control dc;
	int err, fd;

	memcpy(key, cmd->id, DNET_ID_SIZE);
	key[DNET_ID_SIZE] = !!hist;

	err = dnet_hash_lookup(b->hash, key, sizeof(key), &ctl, &dsize);
	if (err) {
		dnet_backend_log(DNET_LOG_ERROR, "blob: %s: could not find data to be removed: %d.\n",
				dnet_dump_id(key), err);
		goto err_out_exit;
	}

	fd = (hist) ? b->history[ctl.file_index].fd : b->data[ctl.file_index].fd;

	dnet_backend_log(DNET_LOG_INFO,	"%s: removing block at: %llu, size: %llu.\n",
		dnet_dump_id(key), (unsigned long long)ctl.offset, (unsigned long long)ctl.size);

	err = pread(fd, &dc, sizeof(dc), ctl.offset);
	if (err != (int)sizeof(dc)) {
		err = -errno;
		dnet_backend_log(DNET_LOG_ERROR, "%s: failed to read disk control structure from history at %llu: %s.\n",
			dnet_dump_id(key), (unsigned long long)ctl.offset, strerror(errno));
		goto err_out_exit;
	}

	blob_convert_disk_control(&dc);
	dc.flags |= BLOB_DISK_CTL_REMOVE;
	blob_convert_disk_control(&dc);

	err = pwrite(fd, &dc, sizeof(struct blob_disk_control), ctl.offset);
	if (err != (int)sizeof(dc)) {
		err = -errno;
		dnet_backend_log(DNET_LOG_ERROR, "%s: failed to erase (mark) entry at %llu: %s.\n",
			dnet_dump_id(key), (unsigned long long)ctl.offset, strerror(errno));
		goto err_out_exit;
	}
	err = 0;

	blob_mark_index_removed((hist) ? b->history[ctl.file_index].index : b->data[ctl.file_index].index,
			ctl.offset, hist);

err_out_exit:
	return err;
}

static int blob_del(struct blob_backend *b, struct dnet_cmd *cmd)
{
	int err;

	err = blob_del_entry(b, cmd, 0);
	err = blob_del_entry(b, cmd, 1);

	return err;
}

struct blob_iterate_shared {
	struct blob_backend	*b;
	void			*state;
	struct dnet_cmd		*cmd;
	struct dnet_attr	*attr;
	unsigned char		id[DNET_ID_SIZE];

	int			pos;

	pthread_mutex_t		lock;
	struct dnet_id		ids[10240];
};

static int blob_iterate_list_callback(struct blob_disk_control *dc, int file_index __unused,
		void *data, off_t position __unused, void *priv)
{
	struct blob_iterate_shared *s = priv;
	struct dnet_history_entry *e;
	struct dnet_meta *m;
	int err = 0;

	if (s->attr->flags & DNET_ATTR_ID_OUT) {
		if (!dnet_id_within_range(dc->id, s->id, s->cmd->id))
			goto err_out_exit;
	}

	if (dc->flags & BLOB_DISK_CTL_REMOVE)
		goto err_out_exit;

	m = dnet_meta_search(NULL, data, dc->data_size, DNET_META_HISTORY);
	if (!m) {
		dnet_backend_log(DNET_LOG_ERROR, "%s: failed to locate history metadata.\n",
				dnet_dump_id(dc->id));
		goto err_out_exit;
	}

	if (!m->size)
		goto err_out_exit;

	if (m->size % sizeof(struct dnet_history_entry)) {
		dnet_backend_log(DNET_LOG_ERROR, "%s: Corrupted history object, "
				"its history metadata size %llu has to be modulo of %zu.\n",
				dnet_dump_id(dc->id), (unsigned long long)m->size,
				sizeof(struct dnet_history_entry));
		err = -EINVAL;
		goto err_out_exit;
	}

	e = (struct dnet_history_entry *)m->data;

	dnet_backend_log(DNET_LOG_INFO, "%s: flags: %08x\n", dnet_dump_id(dc->id), e->flags);

	pthread_mutex_lock(&s->lock);

	if (s->pos == ARRAY_SIZE(s->ids)) {
		err = dnet_send_reply(s->state, s->cmd, s->attr, s->ids, s->pos * sizeof(struct dnet_id), 1);
		if (!err)
			s->pos = 0;
	}

	if (s->pos < (int)ARRAY_SIZE(s->ids)) {
		memcpy(s->ids[s->pos].id, dc->id, DNET_ID_SIZE);
		s->ids[s->pos].flags = dnet_bswap32(e->flags);
		dnet_convert_id(&s->ids[s->pos]);
		s->pos++;
	}

	pthread_mutex_unlock(&s->lock);

err_out_exit:
	return err;
}

static int blob_list(struct blob_backend *b, void *state, struct dnet_cmd *cmd, struct dnet_attr *attr)
{
	struct blob_iterate_shared s;
	int err;

	s.b = b;
	s.state = state;
	s.cmd = cmd;
	s.attr = attr;
	s.pos = 0;

	err = pthread_mutex_init(&s.lock, NULL);
	if (err)
		goto err_out_exit;

	if (attr->flags & DNET_ATTR_ID_OUT)
		dnet_state_get_next_id(state, s.id);

	err = dnet_blob_iterate(b, 1, NULL, blob_iterate_list_callback, &s);
	if (err)
		goto err_out_lock_destroy;

	if (s.pos)
		err = dnet_send_reply(s.state, s.cmd, s.attr, s.ids, s.pos * sizeof(struct dnet_id), 1);

err_out_lock_destroy:
	pthread_mutex_destroy(&s.lock);
err_out_exit:
	return err;
}

static int blob_backend_command_handler(void *state, void *priv,
		struct dnet_cmd *cmd, struct dnet_attr *attr, void *data)
{
	int err;
	struct blob_backend *b = priv;

	switch (attr->cmd) {
		case DNET_CMD_WRITE:
			err = blob_write(b, state, cmd, attr, data);
			break;
		case DNET_CMD_READ:
			err = blob_read(b, state, cmd, attr, data);
			break;
		case DNET_CMD_LIST:
			err = blob_list(b, state, cmd, attr);
			break;
		case DNET_CMD_STAT:
			err = backend_stat(state, NULL, cmd, attr);
			break;
		case DNET_CMD_DEL:
			err = blob_del(b, cmd);
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

	if (!strcmp(key, "history")) {
		free(r->history_file);
		r->history_file = strdup(file);
		if (!r->history_file)
			return -ENOMEM;
	} else {
		free(r->data_file);
		r->data_file = strdup(file);
		if (!r->data_file)
			return -ENOMEM;
	}

	return 0;
}

static int dnet_blob_set_block_size(struct dnet_config_backend *b, char *key, char *value)
{
	struct blob_backend *r = b->data;

	if (!strcmp(key, "data_block_size"))
		r->data_bsize = strtoul(value, NULL, 0);
	else
		r->history_bsize = strtoul(value, NULL, 0);
	return 0;
}

static int dnet_blob_set_blob_size(struct dnet_config_backend *b, char *key __unused, char *value)
{
	struct blob_backend *r = b->data;
	uint64_t val = strtoul(value, NULL, 0);

	if (strchr(value, 'T'))
		val *= 1024*1024*1024*1024ULL;
	else if (strchr(value, 'G'))
		val *= 1024*1024*1024ULL;
	else if (strchr(value, 'M'))
		val *= 1024*1024;
	else if (strchr(value, 'K'))
		val *= 1024;

	r->blob_size = val;
	return 0;
}

static int dnet_blob_set_iterate_thread_num(struct dnet_config_backend *b, char *key __unused, char *value)
{
	struct blob_backend *r = b->data;

	r->iterate_threads = strtoul(value, NULL, 0);
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

static int dnet_blob_iter(struct blob_disk_control *dc, int file_index, void *data __unused, off_t position __unused, void *priv, int hist)
{
	struct blob_backend *b = priv;
	struct blob_ram_control ctl;
	char id[DNET_ID_SIZE*2+1];
	int err;

	dnet_backend_log(DNET_LOG_NOTICE, "%s (hist: %d): file index: %d, index position: %llu (0x%llx), data position: %llu (0x%llx), "
			"data size: %llu, disk size: %llu, flags: %llx.\n",
			dnet_dump_id_len_raw(dc->id, DNET_ID_SIZE, id), hist, file_index,
			(unsigned long long)position, (unsigned long long)position,
			(unsigned long long)dc->position, (unsigned long long)dc->position,
			(unsigned long long)dc->data_size, (unsigned long long)dc->disk_size,
			(unsigned long long)dc->flags);

	if (dc->flags & BLOB_DISK_CTL_REMOVE)
		return 0;

	memcpy(ctl.key, dc->id, DNET_ID_SIZE);
	ctl.key[DNET_ID_SIZE] = hist;
	ctl.index_pos = position / sizeof(struct blob_disk_control);
	ctl.offset = dc->position;
	ctl.size = dc->data_size;
	ctl.file_index = file_index;

	err = dnet_hash_replace(b->hash, ctl.key, sizeof(ctl.key), &ctl, sizeof(ctl));
	if (err)
		return err;

	return 0;
}

static int dnet_blob_iter_history(struct blob_disk_control *dc, int file_index, void *data, off_t position, void *priv)
{
	return dnet_blob_iter(dc, file_index, data, position, priv, 1);
}

static int dnet_blob_iter_data(struct blob_disk_control *dc, int file_index, void *data, off_t position, void *priv)
{
	return dnet_blob_iter(dc, file_index, data, position, priv, 0);
}

static int dnet_blob_config_init(struct dnet_config_backend *b, struct dnet_config *c)
{
	struct blob_backend *r = b->data;
	int err;

	if (!r->data_file || !r->history_file) {
		dnet_backend_log(DNET_LOG_ERROR, "blob: no data/history file present. Exiting.\n");
		err = -EINVAL;
		goto err_out_exit;
	}

	r->history_index = -1;
	r->data_index = -1;

	err = dnet_blob_allocate_io(r, r->data_file, 0);
	if (err)
		goto err_out_free;

	err = dnet_blob_allocate_io(r, r->history_file, 1);
	if (err)
		goto err_out_free;

	if (!r->blob_size)
		r->blob_size = 50*1024*1024*1024ULL;

	if (!r->iterate_threads)
		r->iterate_threads = 1;

	err = pthread_mutex_init(&r->lock, NULL);
	if (err) {
		dnet_backend_log(DNET_LOG_ERROR, "Failed to initialize pthread mutex: %d\n", err);
		err = -errno;
		goto err_out_close;
	}

	if (!r->hash_size)
		r->hash_size = DNET_BLOB_DEFAULT_HASH_SIZE;

	r->hash = dnet_hash_init(r->hash_size, r->hash_flags);
	if (!r->hash) {
		dnet_backend_log(DNET_LOG_ERROR, "blob: failed to initialize hash table: num: %u, flags: 0x%x.\n",
				r->hash_size, r->hash_flags);
		err = -EINVAL;
		goto err_out_lock_destroy;
	}
	
	err = dnet_blob_iterate(r, 0, b->log, dnet_blob_iter_data, r);
	if (err) {
		dnet_backend_log(DNET_LOG_ERROR, "blob: history iteration failed: %d.\n", err);
		goto err_out_hash_destroy;
	}

	err = dnet_blob_iterate(r, 1, b->log, dnet_blob_iter_history, r);
	if (err) {
		dnet_backend_log(DNET_LOG_ERROR, "blob: history iteration failed: %d.\n", err);
		goto err_out_hash_destroy;
	}

	c->command_private = b->data;
	c->command_handler = blob_backend_command_handler;

	return 0;

err_out_hash_destroy:
	dnet_hash_exit(r->hash);
err_out_lock_destroy:
	pthread_mutex_destroy(&r->lock);
err_out_close:
	dnet_blob_close_files_all(r);
err_out_free:
	free(r->data_file);
	free(r->history_file);
err_out_exit:
	return err;
}

static void dnet_blob_config_cleanup(struct dnet_config_backend *b)
{
	struct blob_backend *r = b->data;

	dnet_hash_exit(r->hash);

	dnet_blob_close_files_all(r);

	pthread_mutex_destroy(&r->lock);
}

static struct dnet_config_entry dnet_cfg_entries_blobsystem[] = {
	{"sync", dnet_blob_set_sync},
	{"data", dnet_blob_set_data},
	{"history", dnet_blob_set_data},
	{"data_block_size", dnet_blob_set_block_size},
	{"history_block_size", dnet_blob_set_block_size},
	{"hash_table_size", dnet_blob_set_hash_size},
	{"hash_table_flags", dnet_blob_set_hash_flags},
	{"iterate_thread_num", dnet_blob_set_iterate_thread_num},
	{"blob_size", dnet_blob_set_blob_size},
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
