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

#include <eblob/blob.h>

#include "elliptics/packet.h"
#include "elliptics/interface.h"

#include "backends.h"
#include "common.h"

#ifndef __unused
#define __unused	__attribute__ ((unused))
#endif

struct eblob_backend_config {
	struct eblob_config		data, history;
	struct eblob_backend		*data_blob, *history_blob;
};

static int blob_write_history_meta(void *state, void *backend, struct dnet_io_attr *io,
		struct dnet_meta *m, void *data)
{
	struct eblob_backend *b = backend;
	void *hdata, *new_hdata;
	uint64_t size = 0, offset;
	int err, fd;

	dnet_backend_log(DNET_LOG_NOTICE, "%s: writing history: io-offset: %llu, io-size: %llu.\n",
				dnet_dump_id(io->origin), (unsigned long long)io->offset, (unsigned long long)io->size);

	err = eblob_read(b, io->origin, DNET_ID_SIZE, &fd, &offset, &size);

	if (!err) {
		dnet_backend_log(DNET_LOG_NOTICE, "%s: found existing entry: offset: %llu, size: %llu, fd: %d.\n",
				dnet_dump_id(io->origin), (unsigned long long)offset, (unsigned long long)size, fd);

		size += sizeof(struct eblob_disk_control);
	}

	hdata = malloc(size);
	if (!hdata) {
		err = -ENOMEM;
		dnet_backend_log(DNET_LOG_ERROR, "%s: failed to allocate %llu bytes for history data: %s.\n",
				dnet_dump_id(io->origin), (unsigned long long)size, strerror(errno));
		goto err_out_exit;
	}

	if (!err) {
		struct eblob_disk_control *dc;

		err = pread(fd, hdata, size, offset);
		if (err != (int)size) {
			err = -errno;
			dnet_backend_log(DNET_LOG_ERROR, "%s: failed to read %llu bytes from history at %llu: %s.\n",
				dnet_dump_id(io->origin), (unsigned long long)size, (unsigned long long)offset,
				strerror(errno));
			goto err_out_free;
		}

		dc = hdata;

		eblob_convert_disk_control(dc);

		dnet_backend_log(DNET_LOG_INFO,	"%s: found existing block at: %llu, size: %llu, on-disk-stored-size: %llu, fd: %d.\n",
			dnet_dump_id(io->origin), (unsigned long long)offset, (unsigned long long)size,
			(unsigned long long)dc->data_size, fd);

		if (dc->data_size > size) {
			dnet_backend_log(DNET_LOG_INFO,	"%s: existing block corrupted: allocated size: %llu, on-disk-stored-size: %llu.\n",
					dnet_dump_id(io->origin), (unsigned long long)size, (unsigned long long)dc->data_size);
			err = -EINVAL;
			goto err_out_free;
		}

		size = dc->data_size;

		eblob_remove(b, io->origin, DNET_ID_SIZE);

		memmove(hdata, dc + 1, size);
	}

	new_hdata = backend_process_meta(state, io, hdata, (uint32_t *)&size, m, data);
	if (!new_hdata) {
		err = -ENOMEM;
		dnet_backend_log(DNET_LOG_ERROR, "%s: failed to update history file: %s.\n",
				dnet_dump_id(io->origin), strerror(errno));
		goto err_out_free;
	}
	hdata = new_hdata;
	
	dnet_backend_log(DNET_LOG_NOTICE, "%s: updating history: size: %llu, iosize: %llu.\n",
				dnet_dump_id(io->origin), (unsigned long long)size, (unsigned long long)io->size);

	err = eblob_write_data(b, io->origin, DNET_ID_SIZE, new_hdata, size, BLOB_DISK_CTL_NOCSUM);
	if (err) {
		err = -errno;
		dnet_backend_log(DNET_LOG_ERROR, "%s: failed to update (%llu bytes) history: %s.\n",
				dnet_dump_id(io->origin), (unsigned long long)size, strerror(errno));
		goto err_out_free;
	}

err_out_free:
	free(hdata);
err_out_exit:
	return err;
}

static int blob_write_history(struct eblob_backend *b, void *state,
		struct dnet_io_attr *io, void *data)
{
	return backend_write_history(state, b, io, data, blob_write_history_meta);
}

static int blob_write(struct eblob_backend_config *c, void *state, struct dnet_cmd *cmd,
		struct dnet_attr *attr __unused, void *data)
{
	int err;
	struct dnet_io_attr *io = data;

	dnet_convert_io_attr(io);

	data += sizeof(struct dnet_io_attr);

	if (io->flags & DNET_IO_FLAGS_HISTORY) {
		err = blob_write_history(c->history_blob, state, io, data);
		if (err)
			goto err_out_exit;
	} else {
		err = eblob_write_data(c->data_blob, io->origin, DNET_ID_SIZE,
				data, io->size, BLOB_DISK_CTL_NOCSUM);
		if (err)
			goto err_out_exit;

		if (!(io->flags & DNET_IO_FLAGS_NO_HISTORY_UPDATE)) {
			struct dnet_history_entry e;

			dnet_setup_history_entry(&e, io->id, io->size, io->offset,
					NULL, io->flags);

			io->flags |= DNET_IO_FLAGS_APPEND | DNET_IO_FLAGS_HISTORY;
			io->flags &= ~DNET_IO_FLAGS_META;
			io->size = sizeof(struct dnet_history_entry);
			io->offset = 0;

			err = blob_write_history(c->history_blob, state, io, &e);
			if (err)
				goto err_out_exit;
		}
	}

	dnet_backend_log(DNET_LOG_NOTICE, "blob: %s: IO offset: %llu, size: %llu.\n",
		dnet_dump_id(cmd->id),
		(unsigned long long)io->offset, (unsigned long long)io->size);

	return 0;

err_out_exit:
	return err;
}

static int blob_read(struct eblob_backend_config *c, void *state, struct dnet_cmd *cmd,
		struct dnet_attr *attr __unused, void *data)
{
	struct dnet_io_attr *io = data;
	struct eblob_backend *b;
	uint64_t offset, size;
	int fd, err;

	data += sizeof(struct dnet_io_attr);

	dnet_convert_io_attr(io);

	if (io->flags & DNET_IO_FLAGS_HISTORY)
		b = c->history_blob;
	else
		b = c->data_blob;

	err = eblob_read(b, io->origin, DNET_ID_SIZE, &fd, &offset, &size);
	if (err) {
		dnet_backend_log(DNET_LOG_ERROR, "%s: failed to lookup requested key: %d.\n",
				dnet_dump_id(io->origin), err);
		goto err_out_exit;
	}

	if (io->size && size > io->size)
		size = io->size;

	offset += sizeof(struct eblob_disk_control) + io->offset;

	io->size = size;
	io->offset = offset;
	err = dnet_send_read_data(state, cmd, io, NULL, fd);

err_out_exit:
	return err;
}

static int blob_del(struct eblob_backend_config *c, struct dnet_cmd *cmd)
{
	int err;

	err = eblob_remove(c->data_blob, cmd->id, DNET_ID_SIZE);
	if (!err)
		err = eblob_remove(c->history_blob, cmd->id, DNET_ID_SIZE);

	return err;
}

struct blob_iterate_shared {
	void			*state;
	struct dnet_cmd		*cmd;
	struct dnet_attr	*attr;
	unsigned char		id[DNET_ID_SIZE];

	int			pos;

	pthread_mutex_t		lock;
	struct dnet_id		ids[1024];
};

static int blob_iterate_list_callback(struct eblob_disk_control *dc, int file_index __unused,
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

static int blob_list(struct eblob_backend_config *c, void *state, struct dnet_cmd *cmd, struct dnet_attr *attr)
{
	struct blob_iterate_shared s;
	int err;

	s.state = state;
	s.cmd = cmd;
	s.attr = attr;
	s.pos = 0;

	err = pthread_mutex_init(&s.lock, NULL);
	if (err)
		goto err_out_exit;

	if (attr->flags & DNET_ATTR_ID_OUT)
		dnet_state_get_next_id(state, s.id);

	err = eblob_blob_iterate(c->history_blob, 0, blob_iterate_list_callback, &s);
	if (err)
		goto err_out_lock_destroy;

	if (s.pos)
		err = dnet_send_reply(s.state, s.cmd, s.attr, s.ids, s.pos * sizeof(struct dnet_id), 1);

err_out_lock_destroy:
	pthread_mutex_destroy(&s.lock);
err_out_exit:
	return err;
}

static int eblob_backend_command_handler(void *state, void *priv,
		struct dnet_cmd *cmd, struct dnet_attr *attr, void *data)
{
	int err;
	struct eblob_backend_config *c = priv;

	switch (attr->cmd) {
		case DNET_CMD_WRITE:
			err = blob_write(c, state, cmd, attr, data);
			break;
		case DNET_CMD_READ:
			err = blob_read(c, state, cmd, attr, data);
			break;
		case DNET_CMD_LIST:
			err = blob_list(c, state, cmd, attr);
			break;
		case DNET_CMD_STAT:
			err = backend_stat(state, NULL, cmd, attr);
			break;
		case DNET_CMD_DEL:
			err = blob_del(c, cmd);
			break;
		default:
			err = -EINVAL;
			break;
	}

	return err;
}

static int dnet_blob_set_sync(struct dnet_config_backend *b, char *key __unused, char *value)
{
	struct eblob_backend_config *c = b->data;

	c->data.sync = c->history.sync = atoi(value);
	return 0;
}

static int dnet_blob_set_data(struct dnet_config_backend *b, char *key, char *file)
{
	struct eblob_backend_config *c = b->data;

	if (!strcmp(key, "history")) {
		free(c->history.file);
		c->history.file = strdup(file);
		if (!c->history.file)
			return -ENOMEM;
	} else {
		free(c->data.file);
		c->data.file = strdup(file);
		if (!c->data.file)
			return -ENOMEM;
	}

	return 0;
}

static int dnet_blob_set_block_size(struct dnet_config_backend *b, char *key, char *value)
{
	struct eblob_backend_config *c = b->data;

	if (!strcmp(key, "data_block_size"))
		c->data.bsize = strtoul(value, NULL, 0);
	else
		c->history.bsize = strtoul(value, NULL, 0);
	return 0;
}

static int dnet_blob_set_blob_size(struct dnet_config_backend *b, char *key __unused, char *value)
{
	struct eblob_backend_config *c = b->data;
	uint64_t val = strtoul(value, NULL, 0);

	if (strchr(value, 'T'))
		val *= 1024*1024*1024*1024ULL;
	else if (strchr(value, 'G'))
		val *= 1024*1024*1024ULL;
	else if (strchr(value, 'M'))
		val *= 1024*1024;
	else if (strchr(value, 'K'))
		val *= 1024;

	c->data.blob_size = c->history.blob_size = val;
	return 0;
}

static int dnet_blob_set_iterate_thread_num(struct dnet_config_backend *b, char *key __unused, char *value)
{
	struct eblob_backend_config *c = b->data;

	c->data.iterate_threads = c->history.iterate_threads = strtoul(value, NULL, 0);
	return 0;
}

static int dnet_blob_set_hash_size(struct dnet_config_backend *b, char *key, char *value)
{
	struct eblob_backend_config *c = b->data;

	if (!strcmp(key, "history_hash_table_size"))
		c->history.hash_size = strtoul(value, NULL, 0);
	else
		c->data.hash_size = strtoul(value, NULL, 0);
	return 0;
}

static int dnet_blob_set_hash_flags(struct dnet_config_backend *b, char *key, char *value)
{
	struct eblob_backend_config *c = b->data;

	if (!strcmp(key, "history_hash_table_flags"))
		c->history.hash_flags = strtoul(value, NULL, 0);
	else
		c->data.hash_flags = strtoul(value, NULL, 0);
	return 0;
}

static int dnet_blob_config_init(struct dnet_config_backend *b, struct dnet_config *cfg)
{
	struct eblob_backend_config *c = b->data;
	int err = 0;

	if (!c->data.file || !c->history.file) {
		dnet_backend_log(DNET_LOG_ERROR, "blob: no data/history file present. Exiting.\n");
		err = -EINVAL;
		goto err_out_exit;
	}

	c->data.log = (struct eblob_log *)b->log;
	c->history.log = (struct eblob_log *)b->log;

	c->data_blob = eblob_init(&c->data);
	if (!c->data_blob) {
		err = -EINVAL;
		goto err_out_exit;
	}

	c->history_blob = eblob_init(&c->history);
	if (!c->history_blob) {
		err = -EINVAL;
		goto err_out_free_data_blob;
	}

	cfg->command_private = c;
	cfg->command_handler = eblob_backend_command_handler;

	return 0;

err_out_free_data_blob:
	eblob_cleanup(c->data_blob);
err_out_exit:
	return err;
}

static void dnet_blob_config_cleanup(struct dnet_config_backend *b)
{
	struct eblob_backend_config *c = b->data;

	eblob_cleanup(c->data_blob);
	eblob_cleanup(c->history_blob);

	free(c->data.file);
	free(c->history.file);
}

static struct dnet_config_entry dnet_cfg_entries_blobsystem[] = {
	{"sync", dnet_blob_set_sync},
	{"data", dnet_blob_set_data},
	{"history", dnet_blob_set_data},
	{"data_block_size", dnet_blob_set_block_size},
	{"history_block_size", dnet_blob_set_block_size},
	{"data_hash_table_size", dnet_blob_set_hash_size},
	{"history_hash_table_size", dnet_blob_set_hash_size},
	{"data_hash_table_flags", dnet_blob_set_hash_flags},
	{"history_hash_table_flags", dnet_blob_set_hash_flags},
	{"iterate_thread_num", dnet_blob_set_iterate_thread_num},
	{"blob_size", dnet_blob_set_blob_size},
};

static struct dnet_config_backend dnet_eblob_backend = {
	.name			= "blob",
	.ent			= dnet_cfg_entries_blobsystem,
	.num			= ARRAY_SIZE(dnet_cfg_entries_blobsystem),
	.size			= sizeof(struct eblob_backend_config),
	.init			= dnet_blob_config_init,
	.cleanup		= dnet_blob_config_cleanup,
};

int dnet_eblob_backend_init(void)
{
	return dnet_backend_register(&dnet_eblob_backend);
}

void dnet_eblob_backend_exit(void)
{
	/* cleanup routing will be called explicitly through backend->cleanup() callback */
}
