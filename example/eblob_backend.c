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
	struct eblob_config		data;
	struct eblob_backend		*eblob;
};

#if EBLOB_ID_SIZE != DNET_ID_SIZE
#error "EBLOB_ID_SIZE must be equal to DNET_ID_SIZE" 
#endif

static int blob_write(struct eblob_backend_config *c, void *state __unused, struct dnet_cmd *cmd __unused,
		struct dnet_attr *attr __unused, void *data)
{
	int err;
	struct dnet_io_attr *io = data;
	struct eblob_key key;
	uint64_t flags = BLOB_DISK_CTL_NOCSUM;

	dnet_convert_io_attr(io);

	data += sizeof(struct dnet_io_attr);

	if (io->flags & DNET_IO_FLAGS_COMPRESS)
		flags |= BLOB_DISK_CTL_COMPRESS;

	memcpy(key.id, io->id, EBLOB_ID_SIZE);
	err = eblob_write(c->eblob, &key, data, io->size, flags, io->type);
	if (err) {
		dnet_backend_log(DNET_LOG_ERROR, "%s: EBLOB: blob-write: WRITE: %d: %s\n",
			dnet_dump_id_str(io->id), err, strerror(-err));
		goto err_out_exit;
	}

	dnet_backend_log(DNET_LOG_NOTICE, "%s: EBLOB: blob-write: WRITE: 0: offset: %llu, size: %llu, type: %d.\n",
		dnet_dump_id_str(io->id), (unsigned long long)io->offset, (unsigned long long)io->size, io->type);

	return 0;

err_out_exit:
	return err;
}

static int blob_read(struct eblob_backend_config *c, void *state, struct dnet_cmd *cmd,
		struct dnet_attr *attr __unused, void *data)
{
	struct dnet_io_attr *io = data;
	struct eblob_backend *b = c->eblob;
	uint64_t offset, size;
	struct eblob_key key;
	char *read_data = NULL;
	int fd, err;

	dnet_convert_io_attr(io);

	memcpy(key.id, io->id, EBLOB_ID_SIZE);

	err = eblob_read(b, &key, &fd, &offset, &size, io->type);
	if (err < 0) {
		dnet_backend_log(DNET_LOG_ERROR, "%s: EBLOB: blob-read-fd: READ: %d: %s\n",
			dnet_dump_id_str(io->id), err, strerror(-err));
		goto err_out_exit;
	} else if (err > 0) {
		/* data is compressed */
		
		err = eblob_read_data(b, &key, io->offset, &read_data, &size, io->type);
		if (err) {
			dnet_backend_log(DNET_LOG_ERROR, "%s: EBLOB: blob-read-data: READ: %d: %s\n",
				dnet_dump_id_str(io->id), err, strerror(-err));
			goto err_out_exit;
		}

		fd = -1;
	} else {
		if (io->offset >= size) {
			err = -E2BIG;
			goto err_out_exit;
		}

		offset += io->offset;
		size -= io->offset;

		if (io->size && size > io->size)
			size = io->size;
	}

	io->size = size;
	err = dnet_send_read_data(state, cmd, io, read_data, fd, offset);

	/* free compressed data */
	free(read_data);

err_out_exit:
	return err;
}

struct eblob_read_range_priv {
	void			*state;
	struct dnet_cmd		*cmd;
};


static int blob_read_range_callback(struct eblob_range_request *req)
{
	struct eblob_read_range_priv *p = req->priv;
	int len = 10;
	char start_id[len*2+1], end_id[len*2+1], cur_id[2*len+1];
	struct dnet_io_attr io;
	int err;

	dnet_dump_id_len_raw(req->start, len, start_id);
	dnet_dump_id_len_raw(req->end, len, end_id);
	dnet_dump_id_len_raw(req->record_key, len, cur_id);

	dnet_backend_log(DNET_LOG_NOTICE, "%s: EBLOB: blob-read-range: READ: limit: %llu [%llu, %llu]: "
			"start: %s, end: %s: io record/requested: offset: %llu/%llu, size: %llu/%llu, type: %d\n",
			cur_id,
			(unsigned long long)req->current_pos,
			(unsigned long long)req->requested_limit_start, (unsigned long long)req->requested_limit_num,
			start_id, end_id,
			(unsigned long long)req->record_offset, (unsigned long long)req->requested_offset,
			(unsigned long long)req->record_size, (unsigned long long)req->requested_size,
			req->requested_type);

	if (req->requested_offset > req->record_size) {
		err = 0;
		goto err_out_exit;
	}

	io.flags = 0;
	io.size = req->record_size - req->requested_offset;
	io.offset = req->requested_offset;
	io.type = req->requested_type;
	
	memcpy(io.id, req->record_key, DNET_ID_SIZE);
	memcpy(io.parent, req->end, DNET_ID_SIZE);

	err = dnet_send_read_data(p->state, p->cmd, &io, NULL, req->record_fd,
			req->record_offset + req->requested_offset);
	if (!err)
		req->current_pos++;
err_out_exit:
	return err;
}

static int blob_read_range(struct eblob_backend_config *c, void *state, struct dnet_cmd *cmd,
		struct dnet_attr *attr __unused, void *data)
{
	struct eblob_read_range_priv p;
	struct dnet_io_attr *io = data;
	struct eblob_backend *b = c->eblob;
	struct eblob_range_request req;
	int err;

	p.cmd = cmd;
	p.state = state;

	dnet_convert_io_attr(io);

	memset(&req, 0, sizeof(req));

	memcpy(req.start, io->id, EBLOB_ID_SIZE);
	memcpy(req.end, io->parent, EBLOB_ID_SIZE);
	req.requested_offset = io->offset;
	req.requested_size = io->size;
	req.requested_limit_start = io->start;
	req.requested_limit_num = io->num;
	req.requested_type = io->type;

	if (!req.requested_limit_num)
		req.requested_limit_num = ~0ULL;

	req.priv = state;
	req.callback = blob_read_range_callback;
	req.back = b;
	req.priv = &p;

	err = eblob_read_range(&req);
	if (err) {
		dnet_backend_log(DNET_LOG_ERROR, "%s: EBLOB: blob-read-range: READ: %d: %s\n",
			dnet_dump_id_str(io->id), err, strerror(-err));
		goto err_out_exit;
	}

	if (req.current_pos) {
		struct dnet_io_attr r;

		memcpy(&r, io, sizeof(struct dnet_io_attr));
		r.num = req.current_pos;
		r.offset = r.size = 0;

		err = dnet_send_read_data(state, cmd, &r, NULL, -1, 0);
	}

err_out_exit:
	return err;
}

static int blob_del(struct eblob_backend_config *c, struct dnet_cmd *cmd)
{
	struct eblob_key key;
	int err;

	memcpy(key.id, cmd->id.id, EBLOB_ID_SIZE);
	err = eblob_remove(c->eblob, &key, cmd->id.type);

	if (err) {
		dnet_backend_log(DNET_LOG_ERROR, "%s: EBLOB: blob-del: REMOVE: type: %d: %d: %s\n",
			dnet_dump_id_str(cmd->id.id), cmd->id.type, err, strerror(-err));
	}

	return err;
}

static int eblob_send(void *state, void *priv, struct dnet_id *id)
{
	struct dnet_node *n = dnet_get_node_from_state(state);
	struct eblob_backend_config *c = priv;
	struct eblob_backend *b = c->eblob;
	uint64_t offset, size;
	struct eblob_key key;
	int err, fd;

	memcpy(key.id, id->id, EBLOB_ID_SIZE);
	err = eblob_read(b, &key, &fd, &offset, &size, id->type);
	if (err >= 0) {
		struct dnet_io_control ctl;

		memset(&ctl, 0, sizeof(ctl));

		ctl.fd = fd;
		memcpy(&ctl.id, id, sizeof(struct dnet_id));

		ctl.io.offset = offset;
		ctl.io.size = size;
		ctl.io.type = id->type;
		ctl.io.flags = 0;

		err = dnet_write_data_wait(n, &ctl);
		if (err < 0) {
			goto err_out_exit;
		}
		err = 0;
	}

err_out_exit:
	return err;
}

static int eblob_backend_checksum(struct dnet_node *n, void *priv, struct dnet_id *id, void *csum, int *csize)
{
	struct eblob_backend_config *c = priv;
	struct eblob_backend *b = c->eblob;
	uint64_t offset, size;
	struct eblob_key key;
	int fd, err;

	memcpy(key.id, id->id, EBLOB_ID_SIZE);
	err = eblob_read(b, &key, &fd, &offset, &size, EBLOB_TYPE_DATA);
	if (err < 0) {
		dnet_backend_log(DNET_LOG_ERROR, "%s: EBLOB: blob-checksum: read-index: type: %d: %d: %s.\n",
				dnet_dump_id_str(id->id), id->type, err, strerror(-err));
		goto err_out_exit;
	}

	err = dnet_checksum_fd(n, csum, csize, fd, offset, size);

err_out_exit:
	return err;
}

static int blob_file_info(struct eblob_backend_config *c, void *state, struct dnet_cmd *cmd, struct dnet_attr *attr)
{
	struct dnet_node *n = dnet_get_node_from_state(state);
	int err, len = strlen(c->data.file) + 1 + 32; /* should be enough for .NNN aka index */
	struct eblob_backend *b = c->eblob;
	struct dnet_file_info *info;
	struct dnet_addr_attr *a;
	struct eblob_key key;
	uint64_t offset, size;
	int fd, flen, csize;
	struct stat st;

	a = malloc(sizeof(struct dnet_addr_attr) + sizeof(struct dnet_file_info) + len);
	if (!a) {
		err = -ENOMEM;
		goto err_out_exit;
	}
	info = (struct dnet_file_info *)(a + 1);

	dnet_fill_addr_attr(n, a);

	memcpy(key.id, cmd->id.id, EBLOB_ID_SIZE);
	err = eblob_read(b, &key, &fd, &offset, &size, EBLOB_TYPE_DATA);
	if (err < 0) {
		dnet_backend_log(DNET_LOG_ERROR, "%s: EBLOB: blob-file-info: info-read-index: %d: %s.\n",
				dnet_dump_id(&cmd->id), err, strerror(-err));
		goto err_out_free;
	}

	err = fstat(fd, &st);
	if (err) {
		err = -errno;
		dnet_backend_log(DNET_LOG_ERROR, "%s: EBLOB: blob-idx-XXX: info-stat: %d: %s.\n",
				dnet_dump_id(&cmd->id), err, strerror(-err));
		goto err_out_free;
	}

	dnet_info_from_stat(info, &st);

	csize = sizeof(info->checksum);
	if (attr->flags & DNET_ATTR_NOCSUM) {
		memset(info->checksum, 0, csize);
	} else {
		err = dnet_verify_checksum_io(n, &cmd->id, info->checksum, &csize);
		if (err && (err != -ENODATA))
			goto err_out_free;
	}

	info->size = size;
	info->offset = offset;

	/* XXX need to read full path through /proc/self/fd */
	flen = info->flen = snprintf((char *)(info + 1), len, "%s.XXX", c->data.file) + 1;
	dnet_convert_file_info(info);

	err = dnet_send_reply(state, cmd, attr, a, sizeof(struct dnet_addr_attr) + sizeof(struct dnet_file_info) + flen, 0);

err_out_free:
	free(a);
err_out_exit:
	return err;
}

static int eblob_backend_command_handler(void *state, void *priv,
		struct dnet_cmd *cmd, struct dnet_attr *attr, void *data)
{
	int err;
	struct eblob_backend_config *c = priv;

	switch (attr->cmd) {
		case DNET_CMD_LOOKUP:
			err = blob_file_info(c, state, cmd, attr);
			break;
		case DNET_CMD_WRITE:
			err = blob_write(c, state, cmd, attr, data);
			break;
		case DNET_CMD_READ:
			err = blob_read(c, state, cmd, attr, data);
			break;
		case DNET_CMD_READ_RANGE:
			err = blob_read_range(c, state, cmd, attr, data);
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

	c->data.sync = atoi(value);
	return 0;
}

static int dnet_blob_set_data(struct dnet_config_backend *b, char *key __unused, char *file)
{
	struct eblob_backend_config *c = b->data;
	int err;

	err = backend_storage_size(b, file);
	if (err) {
		char root[strlen(file)+1], *ptr;

		snprintf(root, sizeof(root), "%s", file);
		ptr = strrchr(root, '/');
		if (ptr) {
			*ptr = '\0';
			err = backend_storage_size(b, root);
		}

		if (err)
			return err;
	}

	free(c->data.file);
	c->data.file = strdup(file);
	if (!c->data.file)
		return -ENOMEM;

	return 0;
}

static int dnet_blob_set_block_size(struct dnet_config_backend *b, char *key __unused, char *value)
{
	struct eblob_backend_config *c = b->data;

	c->data.bsize = strtoul(value, NULL, 0);
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

	c->data.blob_size = val;
	return 0;
}

static int dnet_blob_set_iterate_thread_num(struct dnet_config_backend *b, char *key __unused, char *value)
{
	struct eblob_backend_config *c = b->data;

	c->data.iterate_threads = strtoul(value, NULL, 0);
	return 0;
}

static int dnet_blob_set_hash_size(struct dnet_config_backend *b, char *key __unused, char *value)
{
	struct eblob_backend_config *c = b->data;

	c->data.hash_size = strtoul(value, NULL, 0);
	return 0;
}

static int dnet_blob_set_hash_flags(struct dnet_config_backend *b, char *key __unused, char *value)
{
	struct eblob_backend_config *c = b->data;

	c->data.hash_flags = strtoul(value, NULL, 0);
	return 0;
}

int eblob_backend_storage_stat(void *priv, struct dnet_stat *st)
{
	int err;
	struct eblob_backend_config *r = priv;

	memset(st, 0, sizeof(struct dnet_stat));

	err = backend_stat_low_level(r->data.file, st);
	if (err) {
		char root[strlen(r->data.file)+1], *ptr;

		snprintf(root, sizeof(root), "%s", r->data.file);
		ptr = strrchr(root, '/');
		if (ptr) {
			*ptr = '\0';
			err = backend_stat_low_level(root, st);
		}

		if (err)
			return err;
	}

	return 0;
}

static void eblob_backend_cleanup(void *priv)
{
	struct eblob_backend_config *c = priv;

	eblob_cleanup(c->eblob);

	unlink(c->data.mmap_file);

	free(c->data.mmap_file);
	free(c->data.file);
}

static ssize_t dnet_eblob_db_read(void *priv, struct dnet_raw_id *id, void **datap)
{
	struct eblob_backend_config *c = priv;
	return dnet_db_read_raw(c->eblob, id, datap);
}

static int dnet_eblob_db_write(void *priv, struct dnet_raw_id *id, void *data, size_t size)
{
	struct eblob_backend_config *c = priv;
	return dnet_db_write_raw(c->eblob, id, data, size);
}

static int dnet_eblob_db_remove(void *priv, struct dnet_raw_id *id, int real_del)
{
	struct eblob_backend_config *c = priv;
	return dnet_db_remove_raw(c->eblob, id, real_del);
}

static long long dnet_eblob_db_total_elements(void *priv)
{
	struct eblob_backend_config *c = priv;
	return eblob_total_elements(c->eblob);
}

static int dnet_eblob_db_iterate(void *priv, unsigned int flags,
		int (* callback)(struct eblob_disk_control *dc,
			struct eblob_ram_control *rc, void *data, void *p),
		void *callback_private)
{
	struct eblob_backend_config *c = priv;
	return dnet_db_iterate(c->eblob, flags, callback, callback_private);
}

static int dnet_blob_config_init(struct dnet_config_backend *b, struct dnet_config *cfg)
{
	struct eblob_backend_config *c = b->data;
	char mmap_file[256];
	int err = 0;

	if (!c->data.file) {
		dnet_backend_log(DNET_LOG_ERROR, "blob: no data file present. Exiting.\n");
		err = -EINVAL;
		goto err_out_exit;
	}

	c->data.log = (struct eblob_log *)b->log;
	snprintf(mmap_file, sizeof(mmap_file), "%s.mmap", c->data.file);

	c->data.mmap_file = strdup(mmap_file);
	if (!c->data.mmap_file) {
		err = -ENOMEM;
		goto err_out_exit;
	}

	c->eblob = eblob_init(&c->data);
	if (!c->eblob) {
		err = -EINVAL;
		goto err_out_free;
	}

	cfg->cb = &b->cb;
	cfg->storage_size = b->storage_size;
	cfg->storage_free = b->storage_free;
	b->cb.storage_stat = eblob_backend_storage_stat;
	b->cb.checksum = eblob_backend_checksum;

	b->cb.command_private = c;
	b->cb.command_handler = eblob_backend_command_handler;
	b->cb.send = eblob_send;
	b->cb.backend_cleanup = eblob_backend_cleanup;

	b->cb.meta_read = dnet_eblob_db_read;
	b->cb.meta_write = dnet_eblob_db_write;
	b->cb.meta_remove = dnet_eblob_db_remove;
	b->cb.meta_total_elements = dnet_eblob_db_total_elements;
	b->cb.meta_iterate = dnet_eblob_db_iterate;

	return 0;

err_out_free:
	free(c->data.mmap_file);
err_out_exit:
	return err;
}

static void dnet_blob_config_cleanup(struct dnet_config_backend *b)
{
	struct eblob_backend_config *c = b->data;

	eblob_backend_cleanup(c);
}

static struct dnet_config_entry dnet_cfg_entries_blobsystem[] = {
	{"sync", dnet_blob_set_sync},
	{"data", dnet_blob_set_data},
	{"data_block_size", dnet_blob_set_block_size},
	{"data_hash_table_size", dnet_blob_set_hash_size},
	{"data_hash_table_flags", dnet_blob_set_hash_flags},
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
