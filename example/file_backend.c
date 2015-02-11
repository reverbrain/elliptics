/*
 * Copyright 2008+ Evgeniy Polyakov <zbr@ioremap.net>
 * Copytight 2015+ Kirill Smorodinnikov <shaitkir@gmail.com>
 *
 * This file is part of Elliptics.
 * 
 * Elliptics is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * Elliptics is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public License
 * along with Elliptics.  If not, see <http://www.gnu.org/licenses/>.
 */

#define _XOPEN_SOURCE 600

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <sys/wait.h>

#include <ctype.h>
#include <dirent.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <eblob/blob.h>

#include "elliptics/packet.h"
#include "elliptics/backends.h"

#include "common.h"

#include "example/file_backend.h"

#ifndef __unused
#define __unused	__attribute__ ((unused))
#endif

static inline void file_backend_setup_file(struct file_backend_root *r, char *file,
		unsigned int size, const unsigned char *id)
{
	char dir[2*DNET_ID_SIZE+1];
	char id_str[2*DNET_ID_SIZE+1];

	file_backend_get_dir(id, r->bit_num, dir);
	snprintf(file, size, "%s/%s/%s", r->root, dir, dnet_dump_id_len_raw(id, DNET_ID_SIZE, id_str));
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
	char file[DNET_ID_SIZE * 4 + 4 + r->root_len];

	file_backend_setup_file(r, file, sizeof(file), io->id);
	dnet_remove_file_if_empty_raw(file);
}

static void dnet_remove_file_local(struct file_backend_root *r, struct dnet_io_attr *io)
{
	char file[DNET_ID_SIZE * 4 + 4 + r->root_len];

	file_backend_setup_file(r, file, sizeof(file), io->id);
	remove(file);
}

static int file_write_raw(struct file_backend_root *r, struct dnet_io_attr *io)
{
	/* root/dir/file + 0-byte */
	char file[DNET_ID_SIZE * 4 + 4 + r->root_len];
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
		dnet_backend_log(r->blog, DNET_LOG_ERROR, "%s: FILE: %s: OPEN: %zd: %s.",
				dnet_dump_id_str(io->id), file, err, strerror(-err));
		goto err_out_exit;
	}

	err = pwrite(fd, data, io->size, io->offset);
	if (err != (ssize_t)io->size) {
		err = -errno;
		dnet_backend_log(r->blog, DNET_LOG_ERROR, "%s: FILE: %s: WRITE: %zd: offset: %llu, size: %llu: %s.",
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
	char dir_only[2 * DNET_ID_SIZE + 1];
	char dir[DNET_ID_SIZE * 4 + 4 + r->root_len];
	struct dnet_io_attr *io = data;
	struct eblob_key key;
	struct dnet_ext_list elist;
	static const size_t ehdr_size = sizeof(struct dnet_ext_list_hdr);
	struct dnet_ext_list_hdr ehdr;

	dnet_convert_io_attr(io);

	dnet_ext_list_init(&elist);
	dnet_ext_io_to_list(io, &elist);

	memcpy(key.id, io->id, EBLOB_ID_SIZE);

	data += sizeof(struct dnet_io_attr);

	file_backend_get_dir(io->id, r->bit_num, dir);
	snprintf(dir, sizeof(dir), "%s/%s", r->root, dir_only);

	err = mkdir(dir, 0755);
	if (err < 0) {
		if (errno != EEXIST) {
			err = -errno;
			dnet_backend_log(r->blog, DNET_LOG_ERROR, "%s: FILE: %s: dir-create: %d: %s.",
					dnet_dump_id(&cmd->id), dir, err, strerror(-err));
			goto err_out_exit;
		}
	}

	err = file_write_raw(r, io);
	if (err < 0)
		goto err_out_check_remove;

	fd = err;

	/* Copy data from elist to ehdr */
	dnet_ext_list_to_hdr(&elist, &ehdr);

	err = eblob_write(r->meta, &key, &ehdr, 0, ehdr_size, 0);

	if (err) {
		dnet_backend_log(r->blog, DNET_LOG_ERROR, "%s: FILE: %s: META WRITE: %d: %s.",
				dnet_dump_id(&cmd->id), dir, err, strerror(-err));
		goto err_out_remove;
	}

	dnet_backend_log(r->blog, DNET_LOG_INFO, "%s: FILE: %s: WRITE: Ok: offset: %llu, size: %llu, ts: %lld.",
			dnet_dump_id(&cmd->id), dir, (unsigned long long)io->offset, (unsigned long long)io->size,
			(unsigned long long)elist.timestamp.tsec);

	if (io->flags & DNET_IO_FLAGS_WRITE_NO_FILE_INFO) {
		cmd->flags |= DNET_FLAGS_NEED_ACK;
		err = 0;
		goto err_out_close;
	}

	err = dnet_send_file_info(state, cmd, fd, 0, -1);
	if (err)
		goto err_out_close;

	close(fd);

	return 0;

err_out_remove:
	dnet_remove_file_local(r, io);
err_out_close:
	close(fd);
err_out_check_remove:
	dnet_remove_file_if_empty(r, io);
err_out_exit:
	dnet_ext_list_destroy(&elist);
	return err;
}

static int file_io_attr(struct file_backend_root *r, const char *file, int fd, struct dnet_cmd *cmd, struct dnet_io_attr *io, uint8_t *id)
{
	int err;
	struct eblob_write_control wc;
	struct eblob_key key;
	struct dnet_ext_list elist;
	struct stat st;
	uint64_t offset, size;
	static const size_t ehdr_size = sizeof(struct dnet_ext_list_hdr);

	dnet_ext_list_init(&elist);

	err = fstat(fd, &st);
	if (err < 0) {
		err = -errno;
		dnet_backend_log(r->blog, DNET_LOG_ERROR, "%s: FILE: %s: info-stat-stat: %d: %s.",
			dnet_dump_id(&cmd->id), file, err, strerror(-err));
		goto err_out_exit;
	}

	offset = 0;
	size = st.st_size;

	err = dnet_backend_check_get_size(io, &offset, &size);
	if (err) {
		goto err_out_exit;
	}

	memcpy(key.id, id, EBLOB_ID_SIZE);
	err = eblob_read_return(r->meta, &key, EBLOB_READ_NOCSUM, &wc);

	if (!err && wc.total_data_size != ehdr_size) {
		err = -ERANGE;
		goto err_out_exit;
	}

	elist.timestamp.tsec = st.st_mtime;
	elist.timestamp.tnsec = 0;

	if (err) {
		dnet_backend_log(r->blog, DNET_LOG_ERROR, "%s: FILE: %s: meta-read-return: %d: %s.",
			dnet_dump_id(&cmd->id), file, err, strerror(-err));
	} else {
		struct dnet_ext_list_hdr ehdr;

		err = dnet_ext_hdr_read(&ehdr, wc.data_fd, wc.data_offset);

		if (err) {
			dnet_backend_log(r->blog, DNET_LOG_ERROR, "%s: FILE: %s: meta-read-hdr: %d: %s.",
				dnet_dump_id(&cmd->id), file, err, strerror(-err));
		} else {
			dnet_ext_hdr_to_list(&ehdr, &elist);
		}
	}

	err = 0;

	io->timestamp = elist.timestamp;
	io->user_flags = elist.flags;

err_out_exit:
	dnet_ext_list_destroy(&elist);
	return err;
}

static int file_read(struct file_backend_root *r, void *state, struct dnet_cmd *cmd, void *data)
{
	struct dnet_io_attr *io = data;
	int fd, err;
	char file[DNET_ID_SIZE * 4 + 4 + r->root_len];

	data += sizeof(struct dnet_io_attr);

	dnet_convert_io_attr(io);

	file_backend_setup_file(r, file, sizeof(file), io->id);

	fd = open(file, O_RDONLY | O_CLOEXEC, 0644);
	if (fd < 0) {
		err = -errno;
		dnet_backend_log(r->blog, DNET_LOG_ERROR, "%s: FILE: %s: READ: %d: %s.",
				dnet_dump_id(&cmd->id), file, err, strerror(-err));
		goto err_out_exit;
	}

	err = file_io_attr(r, file, fd, cmd, io, io->id);
	if (err)
		goto err_out_close;

	err = dnet_send_read_data(state, cmd, io, NULL, fd, io->offset, 1);
	if (err)
		goto err_out_close;
	return 0;

err_out_close:
	close(fd);
err_out_exit:
	return err;
}

static int file_del(struct file_backend_root *r, void *state __unused, struct dnet_cmd *cmd __unused, void *data)
{
	struct dnet_io_attr *io = data;
	char file[DNET_ID_SIZE * 4 + 4 + r->root_len];
	struct eblob_key key;

	data += sizeof(struct dnet_io_attr);

	dnet_convert_io_attr(io);

	memcpy(key.id, io->id, EBLOB_ID_SIZE);

	file_backend_setup_file(r, file, sizeof(file), io->id);

	remove(file);

	eblob_remove(r->meta, &key);

	return 0;
}

static int file_info(struct file_backend_root *r, void *state, struct dnet_cmd *cmd)
{
	char file[DNET_ID_SIZE * 4 + 4 + r->root_len];
	struct dnet_io_attr io;
	int fd, err;

	file_backend_setup_file(r, file, sizeof(file), cmd->id.id);

	err = open(file, O_RDONLY | O_CLOEXEC);
	if (err < 0) {
		err = -errno;
		dnet_backend_log(r->blog, DNET_LOG_ERROR, "%s: FILE: %s: info-stat-open: %d: %s.",
			dnet_dump_id(&cmd->id), file, err, strerror(-err));
		goto err_out_exit;
	}
	fd = err;

	memset(&io, 0, sizeof(struct dnet_io_attr));
	err = file_io_attr(r, file, fd, cmd, &io, cmd->id.id);
	if (err)
		goto err_out_close;

	err = dnet_send_file_info_ts(state, cmd, fd, 0, io.size, &io.timestamp);
	if (err)
		goto err_out_close;

	err = 0;

err_out_close:
	close(fd);
err_out_exit:
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
		case DNET_CMD_DEL:
			err = file_del(r, state, cmd, data);
			break;
		case DNET_CMD_READ_RANGE:
			err = -ENOTSUP;
			break;
		default:
			err = -ENOTSUP;
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

	r->root_len = strlen(r->root);

	return 0;

err_out_exit:
	return err;
}

static void dnet_file_db_cleanup(struct file_backend_root *r)
{
	eblob_cleanup(r->meta);
}

static int dnet_file_db_init(struct file_backend_root *r)
{
	static char meta_path[PATH_MAX];
	struct eblob_config ecfg;
	int err = 0;

	snprintf(meta_path, sizeof(meta_path), "%s/history", r->root);
	mkdir(meta_path, 0755);

	snprintf(meta_path, sizeof(meta_path), "%s/history/meta", r->root);

	memset(&ecfg, 0, sizeof(ecfg));
	ecfg.file = meta_path;
	ecfg.sync = r->sync;
	ecfg.blob_flags = EBLOB_NO_FREE_SPACE_CHECK | EBLOB_AUTO_DATASORT;
	ecfg.records_in_blob = r->records_in_blob;
	ecfg.blob_size = r->blob_size;
	ecfg.defrag_percentage = r->defrag_percentage;
	ecfg.defrag_timeout = r->defrag_timeout;
	ecfg.log = &r->log;

	r->meta = eblob_init(&ecfg);
	if (!r->meta) {
		err = -EINVAL;
		dnet_backend_log(r->blog, DNET_LOG_ERROR, "Failed to initialize metadata eblob");
	}

	return err;
}

static void file_backend_cleanup(void *priv)
{
	struct file_backend_root *r = priv;

	dnet_file_db_cleanup(r);
	free(r->root);
}

static int file_backend_checksum(struct dnet_node *n, void *priv, struct dnet_id *id, void *csum, int *csize)
{
	struct file_backend_root *r = priv;
	char file[DNET_ID_SIZE * 2 + 2*DNET_ID_SIZE + 2];
	/* file + dir + suffix + slash + 0-byte */

	file_backend_setup_file(r, file, sizeof(file), id->id);
	return dnet_checksum_file(n, file, 0, 0, csum, *csize);
}

static int dnet_file_config_init(struct dnet_config_backend *b)
{
	struct file_backend_root *r = b->data;
	int err;

	r->blog = b->log;
	if (!r->bit_num)
		r->bit_num = 16;

	b->cb.command_private = r;

	b->cb.command_handler = file_backend_command_handler;
	b->cb.checksum = file_backend_checksum;

	b->cb.backend_cleanup = file_backend_cleanup;

	err = dnet_file_db_init(r);
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
	.to_json		= dnet_file_config_to_json,
};

struct dnet_config_backend *dnet_file_backend_info(void)
{
	return &dnet_file_backend;
}
