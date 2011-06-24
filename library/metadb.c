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
#include <sys/mman.h>

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "elliptics.h"
#include "elliptics/interface.h"

ssize_t dnet_db_read_raw(struct dnet_node *n, unsigned char *id, void **datap)
{
	struct eblob_key key;
	void *data;
	uint64_t offset, size;
	int fd, err;

	memcpy(key.id, id, DNET_ID_SIZE);

	err = eblob_read(n->meta, &key, &fd, &offset, &size, EBLOB_TYPE_META);
	if (err) {
		if (err == -ENOENT)
			dnet_counter_inc(n, DNET_CNTR_DBR_NOREC, err);
		else
			dnet_counter_inc(n, DNET_CNTR_DBR_ERROR, err);
	
		goto err_out_exit;
	}

	data = malloc(size);
	if (!data) {
		err = -ENOMEM;
		goto err_out_exit;
	}

	err = pread(fd, data, size, offset);
	if (err != (int)size) {
		err = -errno;
		dnet_counter_inc(n, DNET_CNTR_DBW_ERROR, err);
		goto err_out_free;
	}

	*datap = data;

	return size;

err_out_free:
	free(data);
err_out_exit:
	return err;
}

int dnet_db_read(struct dnet_net_state *st, struct dnet_cmd *cmd, struct dnet_io_attr *io)
{
	struct dnet_node *n = st->n;
	struct eblob_key key;
	uint64_t offset, size;
	int fd, err;

	memcpy(key.id, io->id, DNET_ID_SIZE);
	err = eblob_read(n->meta, &key, &fd, &offset, &size, EBLOB_TYPE_META);
	if (err < 0)
		return err;

	io->size = size;
	err = dnet_send_read_data(st, cmd, io, NULL, fd, offset);

	return err;
}

int dnet_db_write_raw(struct dnet_node *n, unsigned char *id, void *data, unsigned int size)
{
	struct eblob_key key;

	memcpy(key.id, id, DNET_ID_SIZE);
	return eblob_write(n->meta, &key, data, size, BLOB_DISK_CTL_NOCSUM, EBLOB_TYPE_META);
}

static int db_del_direct(struct dnet_node *n, struct dnet_id *id)
{
	struct eblob_key key;

	memcpy(key.id, id->id, EBLOB_ID_SIZE);
	return eblob_remove(n->meta, &key, EBLOB_TYPE_META);
}

int dnet_db_del(struct dnet_node *n, struct dnet_cmd *cmd, struct dnet_attr *attr)
{
	if (attr->flags & DNET_ATTR_DELETE_HISTORY) {
		db_del_direct(n, &cmd->id);
		dnet_log(n, DNET_LOG_DSA, "Metadata is removed\n");
		return 1;
	}

	return dnet_update_ts_metadata(n, &cmd->id, DNET_IO_FLAGS_REMOVED, 0);
}

int dnet_db_write(struct dnet_node *n, struct dnet_cmd *cmd, void *data)
{
	struct dnet_io_attr *io = data;

	if (io->flags & DNET_IO_FLAGS_META)
		return dnet_db_write_raw(n, io->id, io + 1, io->size);

	return dnet_update_ts_metadata(n, &cmd->id, 0, 0);
}

void dnet_db_cleanup(struct dnet_node *n)
{
	if (n->meta)
		eblob_cleanup(n->meta);
}

int dnet_db_init(struct dnet_node *n, struct dnet_config *cfg)
{
	static char meta_path[4096];
	struct eblob_config ecfg;
	int err = 0;

	snprintf(meta_path, sizeof(meta_path), "%s/meta", cfg->history_env);

	memset(&ecfg, 0, sizeof(ecfg));
	ecfg.file = meta_path;

	n->elog.log = n->log->log;
	n->elog.log_private = n->log->log_private;
	n->elog.log_mask = EBLOB_LOG_ERROR | EBLOB_LOG_INFO | EBLOB_LOG_NOTICE | 0xff;

	ecfg.log = &n->elog;

	n->meta = eblob_init(&ecfg);
	if (!n->meta) {
		err = -EINVAL;
		dnet_log(n, DNET_LOG_ERROR, "Failed to initialize metadata eblob\n");
	}

	return err;
}
