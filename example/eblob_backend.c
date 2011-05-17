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
	struct eblob_backend		*data_blob;
};

static int blob_write(struct eblob_backend_config *c, void *state __unused, struct dnet_cmd *cmd __unused,
		struct dnet_attr *attr __unused, void *data)
{
	int err;
	struct dnet_io_attr *io = data;

	dnet_convert_io_attr(io);

	data += sizeof(struct dnet_io_attr);

	err = eblob_write_data(c->data_blob, io->id, DNET_ID_SIZE,
			data, io->size, BLOB_DISK_CTL_NOCSUM);
	if (err) {
		dnet_backend_log(DNET_LOG_ERROR, "%s: EBLOB: blob-write: WRITE: %d: %s\n",
			dnet_dump_id_str(io->id), err, strerror(-err));
		goto err_out_exit;
	}

	dnet_backend_log(DNET_LOG_NOTICE, "%s: EBLOB: blob-write: WRITE: 0: offset: %llu, size: %llu.\n",
		dnet_dump_id_str(io->id), (unsigned long long)io->offset, (unsigned long long)io->size);

	return 0;

err_out_exit:
	return err;
}

static int blob_read(struct eblob_backend_config *c, void *state, struct dnet_cmd *cmd,
		struct dnet_attr *attr __unused, void *data)
{
	struct dnet_io_attr *io = data;
	struct eblob_backend *b = c->data_blob;
	uint64_t offset, size;
	int fd, err;

	data += sizeof(struct dnet_io_attr);

	dnet_convert_io_attr(io);

	err = eblob_read(b, io->id, DNET_ID_SIZE, &fd, &offset, &size);
	if (err) {
		dnet_backend_log(DNET_LOG_ERROR, "%s: EBLOB: blob-read: READ: %d: %s\n",
			dnet_dump_id_str(io->id), err, strerror(-err));
		goto err_out_exit;
	}

	if (io->size && size > io->size)
		size = io->size;

	offset += sizeof(struct eblob_disk_control) + io->offset;

	io->size = size;
	err = dnet_send_read_data(state, cmd, io, NULL, fd, offset);

err_out_exit:
	return err;
}

static int blob_del(struct eblob_backend_config *c, struct dnet_cmd *cmd)
{
	int err = eblob_remove(c->data_blob, cmd->id.id, DNET_ID_SIZE);

	if (err) {
		dnet_backend_log(DNET_LOG_ERROR, "%s: EBLOB: blob-del: REMOVE: %d: %s\n",
			dnet_dump_id_str(cmd->id.id), err, strerror(-err));
	}

	return err;
}

static int eblob_send(void *state, void *priv, struct dnet_id *id)
{
	struct dnet_node *n = dnet_get_node_from_state(state);
	struct eblob_backend_config *c = priv;
	struct eblob_backend *b = c->data_blob;
	uint64_t offset, size;
	int err, fd;

	err = eblob_read(b, id->id, DNET_ID_SIZE, &fd, &offset, &size);
	if (!err) {
		err = dnet_write_data_wait(n, NULL, 0, id, NULL, fd, offset + sizeof(struct eblob_disk_control), 0, size,
				NULL, DNET_ATTR_DIRECT_TRANSACTION, 0);
		if (err)
			goto err_out_exit;
	}

err_out_exit:
	return err;
}

static int eblob_backend_checksum(struct dnet_node *n, void *priv, struct dnet_id *id, void *csum, int *csize)
{
	struct eblob_backend_config *c = priv;
	struct eblob_backend *b = c->data_blob;
	uint64_t offset, size;
	int fd, index, err;

	err = eblob_read_file_index(b, id->id, DNET_ID_SIZE, &fd, &offset, &size, &index);
	if (err) {
		dnet_backend_log(DNET_LOG_ERROR, "%s: EBLOB: blob-checksum: read-index: %d: %s.\n",
				dnet_dump_id(id), err, strerror(errno));
		goto err_out_exit;
	}

	offset += sizeof(struct eblob_disk_control);

	err = dnet_checksum_fd(n, csum, csize, fd, offset, size);

err_out_exit:
	return err;
}

static int blob_file_info(struct eblob_backend_config *c, void *state, struct dnet_cmd *cmd, struct dnet_attr *attr)
{
	struct dnet_node *n = dnet_get_node_from_state(state);
	int err, len = strlen(c->data.file) + 1 + 32; /* should be enough for .NNN aka index */
	struct eblob_backend *b = c->data_blob;
	struct dnet_file_info *info;
	struct dnet_addr_attr *a;
	uint64_t offset, size;
	int fd, index, flen, csize;
	struct stat st;

	a = malloc(sizeof(struct dnet_addr_attr) + sizeof(struct dnet_file_info) + len);
	if (!a) {
		err = -ENOMEM;
		goto err_out_exit;
	}
	info = (struct dnet_file_info *)(a + 1);

	dnet_fill_addr_attr(n, a);

	err = eblob_read_file_index(b, cmd->id.id, DNET_ID_SIZE, &fd, &offset, &size, &index);
	if (err) {
		dnet_backend_log(DNET_LOG_ERROR, "%s: EBLOB: blob-file-info: info-read-index: %d: %s.\n",
				dnet_dump_id(&cmd->id), err, strerror(errno));
		goto err_out_free;
	}

	err = fstat(fd, &st);
	if (err) {
		err = -errno;
		dnet_backend_log(DNET_LOG_ERROR, "%s: EBLOB: blob-idx-%d: info-stat: %d: %s.\n",
				dnet_dump_id(&cmd->id), index, err, strerror(errno));
		goto err_out_free;
	}

	dnet_info_from_stat(info, &st);

	csize = sizeof(info->checksum);
	if (attr->flags & DNET_ATTR_NOCSUM) {
		memset(info->checksum, 0, csize);
	} else {
		err = eblob_backend_checksum(n, c, &cmd->id, info->checksum, &csize);
		if (err)
			goto err_out_free;
	}

	info->size = size;
	info->offset = offset + sizeof(struct eblob_disk_control);

	flen = info->flen = snprintf((char *)(info + 1), len, "%s.%d", c->data.file, index) + 1;
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

static int dnet_blob_config_init(struct dnet_config_backend *b, struct dnet_config *cfg)
{
	struct eblob_backend_config *c = b->data;
	int err = 0;

	if (!c->data.file) {
		dnet_backend_log(DNET_LOG_ERROR, "blob: no data file present. Exiting.\n");
		err = -EINVAL;
		goto err_out_exit;
	}

	c->data.log = (struct eblob_log *)b->log;

	c->data_blob = eblob_init(&c->data);
	if (!c->data_blob) {
		err = -EINVAL;
		goto err_out_exit;
	}

	cfg->storage_size = b->storage_size;
	cfg->storage_free = b->storage_free;
	cfg->storage_stat = eblob_backend_storage_stat;
	cfg->checksum = eblob_backend_checksum;

	cfg->command_private = c;
	cfg->command_handler = eblob_backend_command_handler;
	cfg->send = eblob_send;

	return 0;

err_out_exit:
	return err;
}

static void dnet_blob_config_cleanup(struct dnet_config_backend *b)
{
	struct eblob_backend_config *c = b->data;

	eblob_cleanup(c->data_blob);

	free(c->data.file);
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
