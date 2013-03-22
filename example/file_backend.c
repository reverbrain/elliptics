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
#include <dirent.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "elliptics/packet.h"

#include "backends.h"
#include "common.h"

#ifndef __unused
#define __unused	__attribute__ ((unused))
#endif

struct file_backend_root
{
	char			*root;
	int			root_len;
	int			rootfd;
	int			sync;
	int			bit_num;

	uint64_t		records_in_blob;
	uint64_t		blob_size;
	int			defrag_percentage;
	int			defrag_timeout;

	struct eblob_log	log;
	struct eblob_backend	*meta;
};

static inline void file_backend_setup_file(struct file_backend_root *r, char *file,
		unsigned int size, const unsigned char *id)
{
	char dir[2*DNET_ID_SIZE+1];
	char id_str[2*DNET_ID_SIZE+1];

	file_backend_get_dir(id, r->bit_num, dir);
	snprintf(file, size, "%s/%s", dir, dnet_dump_id_len_raw(id, DNET_ID_SIZE, id_str));
}

static inline uint64_t file_backend_get_dir_bits(const unsigned char *id, int bit_num)
{
#if 0
	uint64_t res = *(uint64_t *)id;

	bit_num = 64 - bit_num;

	res <<= bit_num;
	res >>= bit_num;

	return res;
#else
	char sub[DNET_ID_SIZE*2+1];
	char *res = file_backend_get_dir(id, bit_num, sub);
	char hex[DNET_ID_SIZE*2 + 1 + 2];

	snprintf(hex, sizeof(hex), "0x%s", res);
	return strtoull(hex, NULL, 16);
#endif
}

static void dnet_remove_file_if_empty_raw(char *file)
{
	struct stat st;
	int err;

	err = stat(file, &st);
	if (!err && !st.st_size)
		remove(file);
}

static void dnet_remove_file_if_empty(struct file_backend_root *r, struct dnet_io_attr *io)
{
	char file[DNET_ID_SIZE * 2 + 8 + 8 + 2];

	file_backend_setup_file(r, file, sizeof(file), io->id);
	dnet_remove_file_if_empty_raw(file);
}

static int file_write_raw(struct file_backend_root *r, struct dnet_io_attr *io)
{
	/* null byte + maximum directory length (32 bits in hex) + '/' directory prefix */
	char file[DNET_ID_SIZE * 2 + 8 + 8 + 2];
	int oflags = O_RDWR | O_CREAT | O_LARGEFILE | O_CLOEXEC;
	void *data = io + 1;
	int fd;
	ssize_t err;

	file_backend_setup_file(r, file, sizeof(file), io->id);

	if (io->flags & DNET_IO_FLAGS_APPEND)
		oflags |= O_APPEND;
	else if (!io->offset)
		oflags |= O_TRUNC;
	
	fd = open(file, oflags, 0644);
	if (fd < 0) {
		err = -errno;
		dnet_backend_log(DNET_LOG_ERROR, "%s: FILE: %s: OPEN: %zd: %s.\n",
				dnet_dump_id_str(io->id), file, err, strerror(-err));
		goto err_out_exit;
	}

	err = pwrite(fd, data, io->size, io->offset);
	if (err != (ssize_t)io->size) {
		err = -errno;
		dnet_backend_log(DNET_LOG_ERROR, "%s: FILE: %s: WRITE: %zd: offset: %llu, size: %llu: %s.\n",
			dnet_dump_id_str(io->id), file, err,
			(unsigned long long)io->offset, (unsigned long long)io->size,
			strerror(-err));
		goto err_out_close;
	}

	if (!r->sync)
		fsync(fd);

	return fd;

err_out_close:
	dnet_remove_file_if_empty_raw(file);
	close(fd);
err_out_exit:
	return err;
}

static int file_write(struct file_backend_root *r, void *state __unused, struct dnet_cmd *cmd, void *data)
{
	int err, fd;
	char dir[2*DNET_ID_SIZE+1];
	struct dnet_io_attr *io = data;

	dnet_convert_io_attr(io);
	
	data += sizeof(struct dnet_io_attr);

	file_backend_get_dir(io->id, r->bit_num, dir);

	err = mkdir(dir, 0755);
	if (err < 0) {
		if (errno != EEXIST) {
			err = -errno;
			dnet_backend_log(DNET_LOG_ERROR, "%s: FILE: %s: dir-create: %d: %s.\n",
					dnet_dump_id(&cmd->id), dir, err, strerror(-err));
			goto err_out_exit;
		}
	}

	err = file_write_raw(r, io);
	if (err < 0)
		goto err_out_check_remove;

	fd = err;

	dnet_backend_log(DNET_LOG_INFO, "%s: FILE: %s: WRITE: Ok: offset: %llu, size: %llu.\n",
			dnet_dump_id(&cmd->id), dir, (unsigned long long)io->offset, (unsigned long long)io->size);
	err = dnet_send_file_info(state, cmd, fd, 0, -1);
	if (err)
		goto err_out_close;

	close(fd);

	return 0;

err_out_close:
	close(fd);
err_out_check_remove:
	dnet_remove_file_if_empty(r, io);
err_out_exit:
	return err;
}

static int file_read(struct file_backend_root *r, void *state, struct dnet_cmd *cmd, void *data)
{
	struct dnet_io_attr *io = data;
	int fd, err;
	ssize_t size;
	char file[DNET_ID_SIZE * 2 + 8 + 8 + 2];
	struct stat st;

	data += sizeof(struct dnet_io_attr);

	dnet_convert_io_attr(io);

	file_backend_setup_file(r, file, sizeof(file), io->id);

	fd = open(file, O_RDONLY | O_CLOEXEC, 0644);
	if (fd < 0) {
		err = -errno;
		dnet_backend_log(DNET_LOG_ERROR, "%s: FILE: %s: READ: %d: %s.\n",
				dnet_dump_id(&cmd->id), file, err, strerror(-err));
		goto err_out_exit;
	}

	size = io->size;

	err = fstat(fd, &st);
	if (err) {
		err = -errno;
		dnet_backend_log(DNET_LOG_ERROR, "%s: FILE: %s: read-stat: %d: %s.\n",
				dnet_dump_id(&cmd->id), file, err, strerror(-err));
		goto err_out_close_fd;
	}

	size = dnet_backend_check_get_size(io, st.st_size);
	if (size <= 0) {
		err = size;
		goto err_out_close_fd;
	}

	io->size = size;
	err = dnet_send_read_data(state, cmd, io, NULL, fd, io->offset, 1);
	if (err)
		goto err_out_close_fd;
	return 0;

err_out_close_fd:
	close(fd);
err_out_exit:
	return err;
}

static int file_del(struct file_backend_root *r, void *state __unused, struct dnet_cmd *cmd, void *data __unused)
{
	char file[DNET_ID_SIZE * 2 + 2*DNET_ID_SIZE + 2]; /* file + dir + suffix + slash + 0-byte */
	char dir[2*DNET_ID_SIZE+1];
	char id[2*DNET_ID_SIZE+1];

	file_backend_get_dir(cmd->id.id, r->bit_num, dir);

	snprintf(file, sizeof(file), "%s/%s",
		dir, dnet_dump_id_len_raw(cmd->id.id, DNET_ID_SIZE, id));
	remove(file);

	return 0;
}

static int file_info(struct file_backend_root *r, void *state, struct dnet_cmd *cmd)
{
	char file[DNET_ID_SIZE * 2 + 2*DNET_ID_SIZE + 2]; /* file + dir + suffix + slash + 0-byte */
	char dir[2*DNET_ID_SIZE+1];
	char id[2*DNET_ID_SIZE+1];
	int fd, err;

	file_backend_get_dir(cmd->id.id, r->bit_num, dir);

	snprintf(file, sizeof(file), "%s/%s",
		dir, dnet_dump_id_len_raw(cmd->id.id, DNET_ID_SIZE, id));

	err = open(file, O_RDONLY | O_CLOEXEC);
	if (err < 0) {
		err = -errno;
		dnet_backend_log(DNET_LOG_ERROR, "%s: FILE: %s: info-stat-open-csum: %d: %s.\n",
			dnet_dump_id(&cmd->id), file, err, strerror(-err));
		goto err_out_exit;
	}
	fd = err;

	err = dnet_send_file_info(state, cmd, fd, 0, -1);
	if (err)
		goto err_out_close;
	
	err = 0;

err_out_close:
	close(fd);
err_out_exit:
	return err;
}

static int file_bulk_read(struct file_backend_root *r, void *state, struct dnet_cmd *cmd, void *data)
{
	int err = -1, ret;
	struct dnet_io_attr *io = data;
	struct dnet_io_attr *ios = io+1;
	uint64_t count = 0;
	uint64_t i;

	dnet_convert_io_attr(io);
	count = io->size / sizeof(struct dnet_io_attr);

	for (i = 0; i < count; i++) {
		ret = file_read(r, state, cmd, &ios[i]);
		if (!ret)
			err = 0;
		else if (err == -1)
			err = ret;
	}

	return err;
}
static int file_backend_command_handler(void *state, void *priv, struct dnet_cmd *cmd,void *data)
{
	int err;
	struct file_backend_root *r = priv;

	switch (cmd->cmd) {
		case DNET_CMD_LOOKUP:
			err = file_info(r, state, cmd);
			break;
		case DNET_CMD_WRITE:
			err = file_write(r, state, cmd, data);
			break;
		case DNET_CMD_READ:
			err = file_read(r, state, cmd, data);
			break;
		case DNET_CMD_STAT:
			err = backend_stat(state, r->root, cmd);
			break;
		case DNET_CMD_DEL:
			err = file_del(r, state, cmd, data);
			break;
		case DNET_CMD_BULK_READ:
			err = file_bulk_read(r, state, cmd, data);
			break;
		case DNET_CMD_READ_RANGE:
			err = -ENOTSUP;
			break;
		default:
			err = -EINVAL;
			break;
	}

	return err;
}

static int dnet_file_set_bit_number(struct dnet_config_backend *b, char *key __unused, char *value)
{
	struct file_backend_root *r = b->data;

	r->bit_num = ALIGN(atoi(value), 4);
	return 0;
}

static int dnet_file_set_records_in_blob(struct dnet_config_backend *b, char *key __unused, char *value)
{
	struct file_backend_root *r = b->data;

	r->records_in_blob = (unsigned int)strtoull(value, NULL, 0);
	return 0;
}

static int dnet_file_set_blob_size(struct dnet_config_backend *b, char *key __unused, char *value)
{
	struct file_backend_root *r = b->data;
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

static int dnet_file_set_defrag_timeout(struct dnet_config_backend *b, char *key __unused, char *value)
{
	struct file_backend_root *r = b->data;

	r->defrag_timeout = strtoul(value, NULL, 0);
	return 0;
}

static int dnet_file_set_defrag_percentage(struct dnet_config_backend *b, char *key __unused, char *value)
{
	struct file_backend_root *r = b->data;

	r->defrag_percentage = strtoul(value, NULL, 0);
	return 0;
}

static int dnet_file_set_sync(struct dnet_config_backend *b, char *key __unused, char *value)
{
	struct file_backend_root *r = b->data;

	r->sync = atoi(value);
	return 0;
}

static int dnet_file_set_root(struct dnet_config_backend *b, char *key __unused, char *root)
{
	struct file_backend_root *r = b->data;
	int err;

	err = backend_storage_size(b, root);
	if (err)
		goto err_out_exit;

	r->root = strdup(root);
	if (!r->root) {
		err = -ENOMEM;
		goto err_out_exit;
	}

	r->rootfd = open(r->root, O_RDONLY | O_CLOEXEC);
	if (r->rootfd < 0) {
		err = -errno;
		dnet_backend_log(DNET_LOG_ERROR, "Failed to open root '%s': %s.\n", root, strerror(-err));
		goto err_out_free;
	}
	r->root_len = strlen(r->root);

	err = fchdir(r->rootfd);
	if (err) {
		err = -errno;
		dnet_backend_log(DNET_LOG_ERROR, "Failed to change current dir to root '%s' directory: %s.\n",
				root, strerror(-err));
		goto err_out_close;
	}

	return 0;

err_out_close:
	close(r->rootfd);
	r->rootfd = -1;
err_out_free:
	free(r->root);
	r->root = NULL;
err_out_exit:
	return err;
}

static int file_backend_send(void *state, void *priv, struct dnet_id *id)
{
	struct dnet_node *n = dnet_get_node_from_state(state);
	struct file_backend_root *r = priv;
	char file[DNET_ID_SIZE * 2 + 2*DNET_ID_SIZE + 2]; /* file + dir + suffix + slash + 0-byte */
	int err = -ENOENT;

	file_backend_setup_file(r, file, sizeof(file), id->id);

	if (!access(file, R_OK)) {
		struct dnet_session *s = dnet_session_create(n);
		dnet_session_set_groups(s, (int *)&id->group_id, 1);
		err = dnet_write_file_id(s, file, id, 0, 0, 0);
		if (err < 0) {
			goto err_out_exit;
		}
	}

err_out_exit:
	return err;
}

int file_backend_storage_stat(void *priv, struct dnet_stat *st)
{
	int err;
	struct file_backend_root *r = priv;

	memset(st, 0, sizeof(struct dnet_stat));

	err = backend_stat_low_level(r->root?r->root:".", st);
	if (err)
		return err;

	return 0;
}

static void dnet_file_db_cleanup(struct file_backend_root *r)
{
	eblob_cleanup(r->meta);
}

static int dnet_file_db_init(struct file_backend_root *r, struct dnet_config *c, const char *path)
{
	static char meta_path[300];
	struct eblob_config ecfg;
	int err = 0;

	snprintf(meta_path, sizeof(meta_path), "%s/meta", path);

	memset(&ecfg, 0, sizeof(ecfg));
	ecfg.file = meta_path;
	ecfg.sync = r->sync;
	ecfg.blob_flags = EBLOB_TRY_OVERWRITE | EBLOB_OVERWRITE_COMMITS | EBLOB_NO_FREE_SPACE_CHECK;
	ecfg.records_in_blob = r->records_in_blob;
	ecfg.blob_size = r->blob_size;
	ecfg.defrag_percentage = r->defrag_percentage;
	ecfg.defrag_timeout = r->defrag_timeout;
	ecfg.log = (struct eblob_log *)c->log;

	r->meta = eblob_init(&ecfg);
	if (!r->meta) {
		err = -EINVAL;
		dnet_backend_log(DNET_LOG_ERROR, "Failed to initialize metadata eblob\n");
	}

	return err;
}

static void file_backend_cleanup(void *priv)
{
	struct file_backend_root *r = priv;

	dnet_file_db_cleanup(r);
	close(r->rootfd);
	free(r->root);
}

static ssize_t dnet_file_db_read(void *priv, struct dnet_raw_id *id, void **datap)
{
	struct file_backend_root *r = priv;
	return dnet_db_read_raw(r->meta, id, datap);
}

static int dnet_file_db_write(void *priv, struct dnet_raw_id *id, void *data, size_t size)
{
	struct file_backend_root *r = priv;
	return dnet_db_write_raw(r->meta, id, data, size);
}

static int dnet_file_db_remove(void *priv, struct dnet_raw_id *id, int real_del)
{
	struct file_backend_root *r = priv;
	return dnet_db_remove_raw(r->meta, id, real_del);
}

static long long dnet_file_db_total_elements(void *priv)
{
	struct file_backend_root *r = priv;
	return eblob_total_elements(r->meta);
}

static int dnet_file_db_iterate(struct dnet_iterate_ctl *ctl)
{
	struct file_backend_root *r = ctl->iterate_private;
	return dnet_db_iterate(r->meta, ctl);
}

static int file_backend_checksum(struct dnet_node *n, void *priv, struct dnet_id *id, void *csum, int *csize)
{
	struct file_backend_root *r = priv;
	char file[DNET_ID_SIZE * 2 + 2*DNET_ID_SIZE + 2];
	/* file + dir + suffix + slash + 0-byte */

	file_backend_setup_file(r, file, sizeof(file), id->id);
	return dnet_checksum_file(n, file, 0, 0, csum, *csize);
}

static int dnet_file_config_init(struct dnet_config_backend *b, struct dnet_config *c)
{
	struct file_backend_root *r = b->data;
	int err;

	c->cb = &b->cb;

	b->cb.command_private = r;

	b->cb.command_handler = file_backend_command_handler;
	b->cb.send = file_backend_send;
	b->cb.checksum = file_backend_checksum;

	c->storage_size = b->storage_size;
	c->storage_free = b->storage_free;

	b->cb.storage_stat = file_backend_storage_stat;
	b->cb.backend_cleanup = file_backend_cleanup;

	b->cb.meta_read = dnet_file_db_read;
	b->cb.meta_write = dnet_file_db_write;
	b->cb.meta_remove = dnet_file_db_remove;
	b->cb.meta_total_elements = dnet_file_db_total_elements;
	b->cb.meta_iterate = dnet_file_db_iterate;

	mkdir("history", 0755);
	err = dnet_file_db_init(r, c, "history");
	if (err)
		return err;

	return 0;
}

static void dnet_file_config_cleanup(struct dnet_config_backend *b)
{
	struct file_backend_root *r = b->data;

	file_backend_cleanup(r);
}

static struct dnet_config_entry dnet_cfg_entries_filesystem[] = {
	{"directory_bit_number", dnet_file_set_bit_number},
	{"sync", dnet_file_set_sync},
	{"root", dnet_file_set_root},
	{"records_in_blob", dnet_file_set_records_in_blob},
	{"blob_size", dnet_file_set_blob_size},
	{"defrag_timeout", dnet_file_set_defrag_timeout},
	{"defrag_percentage", dnet_file_set_defrag_percentage},
};

static struct dnet_config_backend dnet_file_backend = {
	.name			= "filesystem",
	.ent			= dnet_cfg_entries_filesystem,
	.num			= ARRAY_SIZE(dnet_cfg_entries_filesystem),
	.size			= sizeof(struct file_backend_root),
	.init			= dnet_file_config_init,
	.cleanup		= dnet_file_config_cleanup,
};

int dnet_file_backend_init(void)
{
	return dnet_backend_register(&dnet_file_backend);
}

void dnet_file_backend_exit(void)
{
	/* cleanup routing will be called explicitly through backend->cleanup() callback */
}
