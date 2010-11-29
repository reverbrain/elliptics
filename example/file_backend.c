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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "elliptics/packet.h"
#include "elliptics/interface.h"

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
	int oflags = O_RDWR | O_CREAT | O_LARGEFILE;
	void *data = io + 1;
	int fd;
	ssize_t err;

	file_backend_setup_file(r, file, sizeof(file), io->id);

	if (io->flags & DNET_IO_FLAGS_APPEND)
		oflags |= O_APPEND;
	else
		oflags |= O_TRUNC;
	
	fd = open(file, oflags, 0644);
	if (fd < 0) {
		err = -errno;
		dnet_backend_log(DNET_LOG_ERROR, "%s: failed to open data file '%s': %s.\n",
				dnet_dump_id_str(io->id), file, strerror(errno));
		goto err_out_exit;
	}

	err = write(fd, data, io->size);
	if (err != (ssize_t)io->size) {
		err = -errno;
		dnet_backend_log(DNET_LOG_ERROR, "%s: failed to write into '%s': %s.\n",
			dnet_dump_id_str(io->id), file, strerror(errno));
		goto err_out_close;
	}

	if (r->sync)
		fsync(fd);
	close(fd);

	return 0;

err_out_close:
	dnet_remove_file_if_empty_raw(file);
	close(fd);
err_out_exit:
	return err;
}

static int file_write(struct file_backend_root *r, void *state __unused, struct dnet_cmd *cmd,
		struct dnet_attr *attr __unused, void *data)
{
	int err;
	char dir[2*DNET_ID_SIZE+1];
	struct dnet_io_attr *io = data;

	dnet_convert_io_attr(io);
	
	data += sizeof(struct dnet_io_attr);

	file_backend_get_dir(io->id, r->bit_num, dir);

	err = mkdir(dir, 0755);
	if (err < 0) {
		if (errno != EEXIST) {
			err = -errno;
			dnet_backend_log(DNET_LOG_ERROR, "%s: faliled to create dir '%s': %s.\n",
					dnet_dump_id(&cmd->id), dir, strerror(errno));
			goto err_out_exit;
		}
	}

	err = file_write_raw(r, io);
	if (err)
		goto err_out_check_remove;

	dnet_backend_log(DNET_LOG_NOTICE, "%s: IO offset: %llu, size: %llu.\n", dnet_dump_id(&cmd->id),
			(unsigned long long)io->offset, (unsigned long long)io->size);

	return 0;

err_out_check_remove:
	dnet_remove_file_if_empty(r, io);
err_out_exit:
	return err;
}

static int file_read(struct file_backend_root *r, void *state, struct dnet_cmd *cmd,
		struct dnet_attr *attr __unused, void *data)
{
	struct dnet_io_attr *io = data;
	int fd, err;
	size_t size;
	char file[DNET_ID_SIZE * 2 + 8 + 8 + 2];
	struct stat st;

	data += sizeof(struct dnet_io_attr);

	dnet_convert_io_attr(io);

	file_backend_setup_file(r, file, sizeof(file), io->id);

	fd = open(file, O_RDONLY, 0644);
	if (fd < 0) {
		err = -errno;
		dnet_backend_log(DNET_LOG_ERROR, "%s: failed to open data file '%s': %s.\n",
				dnet_dump_id(&cmd->id), file, strerror(errno));
		goto err_out_exit;
	}

	size = io->size;

	err = fstat(fd, &st);
	if (err) {
		err = -errno;
		dnet_backend_log(DNET_LOG_ERROR, "%s: failed to stat file '%s': %s.\n",
				dnet_dump_id(&cmd->id), file, strerror(errno));
		goto err_out_close_fd;
	}

	size = dnet_backend_check_get_size(io, st.st_size);
	if (!size) {
		err = 0;
		goto err_out_close_fd;
	}

	io->size = size;
	err = dnet_send_read_data(state, cmd, io, NULL, fd, io->offset);

err_out_close_fd:
	close(fd);
err_out_exit:
	return err;
}

static int file_del(struct file_backend_root *r, void *state __unused, struct dnet_cmd *cmd,
		struct dnet_attr *attr __unused, void *data __unused)
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

static int file_backend_command_handler(void *state, void *priv,
		struct dnet_cmd *cmd, struct dnet_attr *attr, void *data)
{
	int err;
	struct file_backend_root *r = priv;

	switch (attr->cmd) {
		case DNET_CMD_WRITE:
			err = file_write(r, state, cmd, attr, data);
			break;
		case DNET_CMD_READ:
			err = file_read(r, state, cmd, attr, data);
			break;
		case DNET_CMD_STAT:
			err = backend_stat(state, r->root, cmd, attr);
			break;
		case DNET_CMD_DEL:
			err = file_del(r, state, cmd, attr, data);
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

	r->rootfd = open(r->root, O_RDONLY);
	if (r->rootfd < 0) {
		err = -errno;
		dnet_backend_log(DNET_LOG_ERROR, "Failed to open root '%s': %s.\n", root, strerror(errno));
		goto err_out_free;
	}
	r->root_len = strlen(r->root);

	err = fchdir(r->rootfd);
	if (err) {
		err = -errno;
		dnet_backend_log(DNET_LOG_ERROR, "Failed to change current dir to root '%s' directory: %s.\n",
				root, strerror(errno));
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
	int err = 0;

	file_backend_setup_file(r, file, sizeof(file), id->id);

	if (!access(file, R_OK)) {
		err = dnet_write_file_local_offset(n, file, NULL, 0, id, 0, 0, 0,
				DNET_ATTR_DIRECT_TRANSACTION, 0);
		if (err)
			goto err_out_exit;
	}

err_out_exit:
	return err;
}

static int dnet_file_config_init(struct dnet_config_backend *b, struct dnet_config *c)
{
	c->command_private = b->data;
	c->command_handler = file_backend_command_handler;
	c->send = file_backend_send;

	c->storage_size = b->storage_size;
	c->storage_free = b->storage_free;

	return 0;
}

static void dnet_file_config_cleanup(struct dnet_config_backend *b)
{
	struct file_backend_root *r = b->data;

	close(r->rootfd);
	free(r->root);
}

static struct dnet_config_entry dnet_cfg_entries_filesystem[] = {
	{"directory_bit_number", dnet_file_set_bit_number},
	{"sync", dnet_file_set_sync},
	{"root", dnet_file_set_root},
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
