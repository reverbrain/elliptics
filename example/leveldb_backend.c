/*
 * 2012+ Copyright (c) Evgeniy Polyakov <zbr@ioremap.net>
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

#include <leveldb/c.h>

#ifndef __unused
#define __unused	__attribute__ ((unused))
#endif

struct leveldb_backend
{
	int			sync;
	struct eblob_log	elog;

	size_t			cache_size;
	size_t			write_buffer_size;
	size_t			block_size;
	int			block_restart_interval;
	int			max_open_files;
	int			compression;
	char			*path;
	char			*log;

	leveldb_env_t		*env;
	leveldb_cache_t		*cache;
	leveldb_options_t	*options;
	leveldb_readoptions_t	*roptions;
	leveldb_writeoptions_t	*woptions;
	leveldb_comparator_t	*cmp;

	leveldb_t		*db;
};

/*
static int leveldb_backend_lookup_raw(struct leveldb_backend *s, struct index *idx, void *state, struct dnet_cmd *cmd)
{
	int err, fd;
	char *path;

	err = smack_lookup(s->smack, idx, &path);
	if (err < 0)
		goto err_out_exit;

	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		err = -errno;
		dnet_backend_log(DNET_LOG_ERROR, "%s: SMACK: %s: lookup-open: size: %llu: %s %d.\n",
				dnet_dump_id_str(idx->id), path,
				(unsigned long long)idx->data_size,
				strerror(-err), err);
		goto err_out_free;
	}

	err = dnet_send_file_info(state, cmd, fd, 0, idx->data_size);
	if (err)
		goto err_out_close;

	dnet_backend_log(DNET_LOG_INFO, "%s: SMACK: %s: lookup: size: %llu.\n",
			dnet_dump_id(&cmd->id), path, (unsigned long long)idx->data_size);

err_out_close:
	close(fd);
err_out_free:
	free(path);
err_out_exit:
	return err;
}
*/

static int leveldb_backend_lookup(struct leveldb_backend *s __unused, void *state __unused, struct dnet_cmd *cmd __unused)
{
/*
	struct index idx;

	smack_setup_idx(&idx, cmd->id.id);
	return leveldb_backend_lookup_raw(s, &idx, state, cmd);
*/
	return 0;
}

static int leveldb_backend_write(struct leveldb_backend *s, void *state, struct dnet_cmd *cmd, void *data)
{
	int err = -EINVAL;
	char *error_string = NULL;
	struct dnet_io_attr *io = data;

	dnet_convert_io_attr(io);
	if (io->offset) {
		err = -ERANGE;
		goto err_out_exit;
	}
	
	data += sizeof(struct dnet_io_attr);

	leveldb_put(s->db, s->woptions, (const char *)cmd->id.id, DNET_ID_SIZE, data, io->size, &error_string);
	if (error_string)
		goto err_out_exit;

	err = dnet_send_file_info_without_fd(state, cmd, 0, io->size);
	if (err < 0)
		goto err_out_free;

	dnet_backend_log(DNET_LOG_NOTICE, "%s: leveldb: : WRITE: Ok: size: %llu.\n",
			dnet_dump_id(&cmd->id), (unsigned long long)io->size);

err_out_free:
	free(addr);
err_out_exit:
	if (err < 0)
		dnet_backend_log(DNET_LOG_ERROR, "%s: leveldb: : WRITE: error: %s: %d.\n",
			dnet_dump_id(&cmd->id), error_string, err);
	free(error_string);
	return err;
}

static int leveldb_backend_read(struct leveldb_backend *s, void *state, struct dnet_cmd *cmd, void *iodata, int last)
{
	struct dnet_io_attr *io = iodata;
	char *data;
	size_t data_size;
	int err = -EINVAL;
	char *error_string = NULL;

	dnet_convert_io_attr(io);
	if (io->size || io->offset) {
		err = -ERANGE;
		goto err_out_exit;
	}

	data = leveldb_get(s->db, s->roptions, (const char *)io->id, DNET_ID_SIZE, &data_size, &error_string);
	if (error_string || !data) {
		if (!data)
			err = -ENOENT;
		goto err_out_exit;
	}

	io->size = data_size;
	if (data_size && data && last)
		cmd->flags &= ~DNET_FLAGS_NEED_ACK;
	err = dnet_send_read_data(state, cmd, io, data, -1, io->offset, 0);
	if (err < 0)
		goto err_out_free;

	dnet_backend_log(DNET_LOG_NOTICE, "%s: leveldb: : READ: Ok: size: %llu.\n",
			dnet_dump_id(&cmd->id), (unsigned long long)io->size);

err_out_free:
	free(data);
err_out_exit:
	if (err < 0)
		dnet_backend_log(DNET_LOG_ERROR, "%s: leveldb: READ: error: %s: %d\n",
			dnet_dump_id(&cmd->id), error_string, err);

	free(error_string);
	return err;
}

static int leveldb_backend_remove(struct leveldb_backend *s, void *state __unused, struct dnet_cmd *cmd, void *data __unused)
{
	char *error_string = NULL;

	leveldb_delete(s->db, s->woptions, (const char *)cmd->id.id, DNET_ID_SIZE, &error_string);
	if (error_string) {
		dnet_backend_log(DNET_LOG_ERROR, "%s: leveldb: REMOVE: error: %s\n",
				dnet_dump_id(&cmd->id), error_string);
		free(error_string);
		return -ENOENT;
	}

	return 0;
}

static int leveldb_backend_bulk_read(struct leveldb_backend *s, void *state, struct dnet_cmd *cmd, void *data)
{
	int err = -ENOENT, ret;
	struct dnet_io_attr *io = data;
	struct dnet_io_attr *ios = io+1;
	uint64_t count = 0;
	uint64_t i;

	dnet_convert_io_attr(io);
	count = io->size / sizeof(struct dnet_io_attr);

	for (i = 0; i < count; i++) {
		ret = leveldb_backend_read(s, state, cmd, &ios[i], i + 1 == count);
		if (!ret)
			err = 0;
		else if (err == -ENOENT)
			err = ret;
	}

	return err;
}

static int leveldb_backend_range_read(struct leveldb_backend *s, void *state, struct dnet_cmd *cmd, void *data)
{
	int err = -ENOENT;
	char * error_string = NULL;
	struct dnet_io_attr *io = data;
	struct dnet_io_attr dst_io;
	unsigned i = 0, j = 0;
	dnet_convert_io_attr(io);

	leveldb_iterator_t * it = leveldb_create_iterator(s->db, s->roptions);
	if (!it) {
		return err;
	}

	for (leveldb_iter_seek(it, (const char*)io->id, DNET_ID_SIZE);
	     leveldb_iter_valid(it) && j < io->num; leveldb_iter_next(it), i++)
	{
		size_t size;
		const char * key = leveldb_iter_key(it, &size);
		const char * val = 0;
		if (memcmp(io->parent, key, DNET_ID_SIZE) < 0) {
			break;
		}
		if (i < io->start) {
			continue;
		}
		++j;

		err = 0;
		switch (cmd->cmd) {
			case DNET_CMD_READ_RANGE: 
				val = leveldb_iter_value(it, &size);
				memset(&dst_io, 0, sizeof(dst_io));
				dst_io.flags  = 0;
				dst_io.size   = size;
				dst_io.offset = 0;
				dst_io.type   = io->type;
				memcpy(dst_io.id, key, DNET_ID_SIZE);
				memcpy(dst_io.parent, io->parent, DNET_ID_SIZE);
				err = dnet_send_read_data(state, cmd, &dst_io, (char*)val, -1, 0, 0);
				break;
			case DNET_CMD_DEL_RANGE:
				leveldb_delete(s->db, s->woptions, key, size, &error_string);
				if (error_string) {
					dnet_backend_log(DNET_LOG_ERROR, "%s: LEVELDB: REMOVE: error: %s",
					                 dnet_dump_id_str((const unsigned char*)key), error_string);
					err = -ENOENT;
					free(error_string);
				}
				break;
		}

		if (err) {
			j = 0;
			break;
		}
	}

	if (j) {
		struct dnet_io_attr r;

		memcpy(&r, io, sizeof(struct dnet_io_attr));
		r.num    = j - io->start;
		r.offset = r.size = 0;

		err = dnet_send_read_data(state, cmd, &r, NULL, -1, 0, 0);		
	}

	leveldb_iter_destroy(it);

	return err;
}

static int leveldb_backend_command_handler(void *state, void *priv, struct dnet_cmd *cmd, void *data)
{
	int err;
	struct leveldb_backend *s = priv;

	switch (cmd->cmd) {
		case DNET_CMD_LOOKUP:
			err = leveldb_backend_lookup(s, state, cmd);
			break;
		case DNET_CMD_WRITE:
			err = leveldb_backend_write(s, state, cmd, data);
			break;
		case DNET_CMD_READ:
			err = leveldb_backend_read(s, state, cmd, data, 1);
			break;
		case DNET_CMD_STAT:
			err = backend_stat(state, s->path, cmd);
			break;
		case DNET_CMD_DEL:
			err = leveldb_backend_remove(s, state, cmd, data);
			break;
		case DNET_CMD_DEL_RANGE:
		case DNET_CMD_READ_RANGE:
			err = leveldb_backend_range_read(s, state, cmd, data);
			break;
		case DNET_CMD_BULK_READ:
			err = leveldb_backend_bulk_read(s, state, cmd, data);
			break;
		default:
			err = -ENOTSUP;
			break;
	}

	return err;
}

static int dnet_leveldb_set_cache_size(struct dnet_config_backend *b, char *key __unused, char *value)
{
	struct leveldb_backend *s = b->data;

	s->cache_size = atol(value);
	return 0;
}

static int dnet_leveldb_set_write_buffer_size(struct dnet_config_backend *b, char *key __unused, char *value)
{
	struct leveldb_backend *s = b->data;

	s->write_buffer_size = atol(value);
	return 0;
}

static int dnet_leveldb_set_block_size(struct dnet_config_backend *b, char *key __unused, char *value)
{
	struct leveldb_backend *s = b->data;

	s->block_size = atol(value);
	return 0;
}

static int dnet_leveldb_set_block_restart_interval(struct dnet_config_backend *b, char *key __unused, char *value)
{
	struct leveldb_backend *s = b->data;

	s->block_restart_interval = atoi(value);
	return 0;
}

static int dnet_leveldb_set_max_open_files(struct dnet_config_backend *b, char *key __unused, char *value)
{
	struct leveldb_backend *s = b->data;

	s->max_open_files = atoi(value);
	return 0;
}

static int dnet_leveldb_set_sync(struct dnet_config_backend *b, char *key __unused, char *value)
{
	struct leveldb_backend *s = b->data;

	s->sync = atoi(value);
	return 0;
}

static int dnet_leveldb_set_compression(struct dnet_config_backend *b, char *key __unused, char *value)
{
	struct leveldb_backend *s = b->data;

	if (!strcmp(value, "snappy"))
		s->compression = leveldb_snappy_compression;

	return 0;
}

static int dnet_leveldb_set_log(struct dnet_config_backend *b, char *key __unused, char *value)
{
	struct leveldb_backend *s = b->data;
	char *tmp;

	tmp = strdup(value);
	if (!tmp)
		return -ENOMEM;

	if (s->log)
		free(s->log);
	s->log = tmp;
	return 0;
}

static int dnet_leveldb_set_root(struct dnet_config_backend *b, char *key __unused, char *root)
{
	struct leveldb_backend *s = b->data;
	int err;

	err = backend_storage_size(b, root);
	if (err)
		goto err_out_exit;

	s->path = strdup(root);
	if (!s->path) {
		err = -ENOMEM;
		goto err_out_exit;
	}

	return 0;

err_out_exit:
	return err;
}

/*
static int leveldb_backend_send(void *state, void *priv, struct dnet_id *id)
{
	struct dnet_node *n = dnet_get_node_from_state(state);
	struct leveldb_backend *s = priv;
	char *result = NULL;
	char *data;
	int err;

	smack_setup_idx(&idx, id->id);
	err = smack_read(s->smack, &idx, &data);
	if (err)
		goto err_out_exit;

	struct dnet_io_control ctl;

	memset(&ctl, 0, sizeof(ctl));

	ctl.fd = -1;

	ctl.data = data;

	memcpy(&ctl.id, id, sizeof(struct dnet_id));

	ctl.io.offset = 0;
	ctl.io.size = idx.data_size;
	ctl.io.type = 0;
	ctl.io.flags = 0;

	struct dnet_session *sess = dnet_session_create(n);
	dnet_session_set_groups(sess, (int *)&id->group_id, 1);

	err = dnet_write_data_wait(sess, &ctl, (void **)&result);
	if (err < 0)
		goto err_out_free;
	free(result);
	err = 0;

err_out_free:
	free(data);
err_out_exit:
	return err;
}
*/
int leveldb_backend_storage_stat(void *priv, struct dnet_stat *st)
{
	int err;
	struct leveldb_backend *s = priv;

	memset(st, 0, sizeof(struct dnet_stat));

	err = backend_stat_low_level(s->path ? s->path : ".", st);
	if (err)
		return err;

	return 0;
}

static void dnet_leveldb_db_cleanup(struct leveldb_backend *s)
{
}

static int dnet_leveldb_db_init(struct leveldb_backend *s, struct dnet_config *c, const char *path)
{
	return 0;
}

static void leveldb_backend_cleanup(void *priv)
{
	struct leveldb_backend *s = priv;

	leveldb_close(s->db);
	leveldb_writeoptions_destroy(s->woptions);
	leveldb_readoptions_destroy(s->roptions);
	leveldb_cache_destroy(s->cache);
	leveldb_options_destroy(s->options);
	//leveldb_comparator_destroy(s->cmp);
	leveldb_env_destroy(s->env);

	dnet_leveldb_db_cleanup(s);

	free(s->path);
}

static ssize_t dnet_leveldb_db_read(void *priv, struct dnet_raw_id *id, void **datap)
{
	return -ENOTSUP;
}

static int dnet_leveldb_db_write(void *priv, struct dnet_raw_id *id, void *data, size_t size)
{
	char tmp[24];
	dnet_backend_log(DNET_LOG_ERROR, "%s: metadata operation is not supported, it will be removed soon. \n"
			"Please add flags = 16 to your server config, this will disable metadata updates\n",
			dnet_dump_id_len_raw(id->id, sizeof(tmp), tmp));
	return -ENOTSUP;
}

static int dnet_leveldb_db_remove(void *priv, struct dnet_raw_id *id, int real_del)
{
	return -ENOTSUP;
}

static int dnet_leveldb_db_iterate(struct dnet_iterate_ctl *ctl)
{
	return -ENOTSUP;
}

static long long dnet_leveldb_total_elements(void *priv)
{
	struct leveldb_backend *s = priv;
	char *prop;
	char propname[256];
	int level = 0;
	long long count = 0;

	do {
		snprintf(propname, sizeof(propname), "leveldb.num-files-at-level%d", level);
		prop = leveldb_property_value(s->db, propname);
		if (prop) {
			dnet_backend_log(DNET_LOG_DEBUG, "leveldb: properties: %s -> %s\n", propname, prop);
			count += atoi(prop);
		}
		level++;
	} while (prop);

	dnet_backend_log(DNET_LOG_DEBUG, "leveldb: count: %lld\n", count);

	return count;
}

static int dnet_leveldb_config_init(struct dnet_config_backend *b, struct dnet_config *c)
{
	struct leveldb_backend *s = b->data;
	int err;
	char *error_string = NULL;
	char *hpath;
	int hlen;

	err = -EINVAL;
	if (!s->path) {
		dnet_backend_log(DNET_LOG_ERROR, "leveldb: you must provide root path\n");
		goto err_out_exit;
	}

	if (!s->cache_size)
		s->cache_size = 1024 * 1024;

	hlen = strlen(s->path) + 128; /* 128 is for /history suffix */
	hpath = alloca(hlen);
	if (!hpath) {
		err = -ENOMEM;
		goto err_out_exit;
	}

	c->cb = &b->cb;

	b->cb.command_private = s;

	b->cb.command_handler = leveldb_backend_command_handler;
	//b->cb.send = leveldb_backend_send;

	c->storage_size = b->storage_size;
	c->storage_free = b->storage_free;

	b->cb.storage_stat = leveldb_backend_storage_stat;
	b->cb.backend_cleanup = leveldb_backend_cleanup;

	b->cb.meta_read = dnet_leveldb_db_read;
	b->cb.meta_write = dnet_leveldb_db_write;
	b->cb.meta_remove = dnet_leveldb_db_remove;
	b->cb.meta_total_elements = dnet_leveldb_total_elements;
	b->cb.meta_iterate = dnet_leveldb_db_iterate;

	snprintf(hpath, hlen, "%s/history", s->path);
	mkdir(hpath, 0755);
	err = dnet_leveldb_db_init(s, c, hpath);
	if (err) {
		dnet_backend_log(DNET_LOG_ERROR, "leveldb: could not initialize history database: %d\n", err);
		goto err_out_exit;
	}

	err = -ENOMEM;

	//s->cmp = leveldb_comparator_create(NULL, CmpDestroy, CmpCompare, CmpName);
	s->env = leveldb_create_default_env();
	if (!s->env) {
		dnet_backend_log(DNET_LOG_ERROR, "leveldb: could not create environment\n");
		goto err_out_cleanup;
	}

	s->options = leveldb_options_create();
	if (!s->options) {
		dnet_backend_log(DNET_LOG_ERROR, "leveldb: could not create options\n");
		goto err_out_env_cleanup;
	}

	s->cache = leveldb_cache_create_lru(s->cache_size);
	if (!s->cache) {
		dnet_backend_log(DNET_LOG_ERROR, "leveldb: could not create cache, size: %zd\n", s->cache_size);
		goto err_out_options_cleanup;
	}
	//leveldb_options_set_comparator(s->options, s->cmp);
	leveldb_options_set_create_if_missing(s->options, 1);
	leveldb_options_set_cache(s->options, s->cache);
	leveldb_options_set_env(s->options, s->env);
	leveldb_options_set_info_log(s->options, NULL);
	leveldb_options_set_write_buffer_size(s->options, s->write_buffer_size);
	leveldb_options_set_paranoid_checks(s->options, 1);
	leveldb_options_set_max_open_files(s->options, s->max_open_files);
	leveldb_options_set_block_size(s->options, s->block_size);
	leveldb_options_set_block_restart_interval(s->options, s->block_restart_interval);
	leveldb_options_set_compression(s->options, leveldb_no_compression);

	s->roptions = leveldb_readoptions_create();
	if (!s->roptions) {
		dnet_backend_log(DNET_LOG_ERROR, "leveldb: could not create read options\n");
		goto err_out_cache_cleanup;
	}

	leveldb_readoptions_set_verify_checksums(s->roptions, 1);
	leveldb_readoptions_set_fill_cache(s->roptions, 1);

	s->woptions = leveldb_writeoptions_create();
	if (!s->woptions) {
		dnet_backend_log(DNET_LOG_ERROR, "leveldb: could not create write options\n");
		goto err_out_read_options_cleanup;
	}

	leveldb_writeoptions_set_sync(s->woptions, s->sync);

	s->db = leveldb_open(s->options, s->path, &error_string);
	if (!s->db || error_string) {
		dnet_backend_log(DNET_LOG_ERROR, "leveldb: failed to open leveldb: %s\n", error_string);
		goto err_out_write_options_cleanup;
	}

	return 0;

	leveldb_close(s->db);
err_out_write_options_cleanup:
	free(error_string);
	leveldb_writeoptions_destroy(s->woptions);
err_out_read_options_cleanup:
	leveldb_readoptions_destroy(s->roptions);
err_out_cache_cleanup:
	leveldb_cache_destroy(s->cache);
err_out_options_cleanup:
	leveldb_options_destroy(s->options);
	//leveldb_comparator_destroy(s->cmp);
err_out_env_cleanup:
	leveldb_env_destroy(s->env);
err_out_cleanup:
	dnet_leveldb_db_cleanup(s);
err_out_exit:
	return err;
}

static void dnet_leveldb_config_cleanup(struct dnet_config_backend *b)
{
	struct leveldb_backend *s = b->data;

	leveldb_backend_cleanup(s);
}

static struct dnet_config_entry dnet_cfg_entries_leveldb[] = {
	{"log", dnet_leveldb_set_log},
	{"sync", dnet_leveldb_set_sync},
	{"root", dnet_leveldb_set_root},
	{"cache_size", dnet_leveldb_set_cache_size},
	{"write_buffer_size", dnet_leveldb_set_write_buffer_size},
	{"block_size", dnet_leveldb_set_block_size},
	{"block_restart_interval", dnet_leveldb_set_block_restart_interval},
	{"max_open_files", dnet_leveldb_set_max_open_files},
	{"compression", dnet_leveldb_set_compression},
//	{"", dnet_leveldb_set_},
};

static struct dnet_config_backend dnet_leveldb_backend = {
	.name			= "leveldb",
	.ent			= dnet_cfg_entries_leveldb,
	.num			= ARRAY_SIZE(dnet_cfg_entries_leveldb),
	.size			= sizeof(struct leveldb_backend),
	.init			= dnet_leveldb_config_init,
	.cleanup		= dnet_leveldb_config_cleanup,
};

int dnet_leveldb_backend_init(void)
{
	return dnet_backend_register(&dnet_leveldb_backend);
}

void dnet_leveldb_backend_exit(void)
{
	/* cleanup routing will be called explicitly through backend->cleanup() callback */
}
