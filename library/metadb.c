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

ssize_t dnet_db_read_raw(struct eblob_backend *b, struct dnet_raw_id *id, void **datap)
{
	struct eblob_key key;
	void *data;
	uint64_t offset, size;
	int fd, err;

	memcpy(key.id, id->id, DNET_ID_SIZE);

	err = eblob_read(b, &key, &fd, &offset, &size, EBLOB_TYPE_META);
	if (err) {
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
		goto err_out_free;
	}

	*datap = data;

	return size;

err_out_free:
	free(data);
err_out_exit:
	return err;
}

int dnet_db_write_raw(struct eblob_backend *b, struct dnet_raw_id *id, void *data, unsigned int size)
{
	struct eblob_key key;

	memcpy(key.id, id->id, DNET_ID_SIZE);
	return eblob_write(b, &key, data, size, BLOB_DISK_CTL_NOCSUM, EBLOB_TYPE_META);
}

static int dnet_db_remove_direct(struct eblob_backend *b, struct dnet_raw_id *id)
{
	struct eblob_key key;

	memcpy(key.id, id->id, EBLOB_ID_SIZE);
	return eblob_remove(b, &key, EBLOB_TYPE_META);
}

int dnet_db_remove_raw(struct eblob_backend *b, struct dnet_raw_id *id, int real_del)
{
	if (real_del) {
		dnet_db_remove_direct(b, id);
		return 1;
	}

	return dnet_update_ts_metadata(b, id, DNET_IO_FLAGS_REMOVED, 0);
}

int dnet_process_meta(struct dnet_net_state *st, struct dnet_cmd *cmd, struct dnet_attr *a, struct dnet_io_attr *io)
{
	struct dnet_node *n = st->n;
	struct dnet_raw_id id;
	void *data;
	int err;

	if (a->cmd == DNET_CMD_READ || a->cmd == DNET_CMD_WRITE) {

		if (a->size < sizeof(struct dnet_io_attr)) {
			dnet_log(n, DNET_LOG_ERROR,
				"%s: wrong read attribute, size does not match "
					"IO attribute size: size: %llu, must be: %zu.\n",
					dnet_dump_id(&cmd->id), (unsigned long long)a->size,
					sizeof(struct dnet_io_attr));
			err = -EINVAL;
			goto err_out_exit;
		}

		memcpy(id.id, io->id, DNET_ID_SIZE);
	}

	switch (a->cmd) {
	case DNET_CMD_READ:
		err = n->cb->meta_read(n->cb->command_private, &id, &data);
		if (err > 0) {
			io->size = err;
			err = dnet_send_read_data(st, cmd, io, data, -1, io->offset);
			free(data);
		}
		break;
	case DNET_CMD_WRITE:
		if (n->flags & DNET_CFG_NO_META) {
			err = 0;
			break;
		}

		data = io + 1;

		err = n->cb->meta_write(n->cb->command_private, &id, data, io->size);
		if (!err && !(a->flags & DNET_ATTR_NOCSUM) && !(n->flags & DNET_CFG_NO_CSUM)) {
			err = dnet_meta_update_checksum(n, &id);
		}
		break;
	case DNET_CMD_DEL:
		memcpy(id.id, cmd->id.id, DNET_ID_SIZE);
		err = n->cb->meta_remove(n->cb->command_private, &id, !!(a->flags & DNET_ATTR_DELETE_HISTORY));
		if (err > 0) {
			/* if positive value returned we will delete data object */

			err = n->cb->command_handler(st, n->cb->command_private, cmd, a, io);
		}
		break;
	default:
		err = -EINVAL;
		break;
	}

err_out_exit:
	return err;
}

int dnet_db_iterate(struct eblob_backend *b, unsigned int flags,
		int (* callback)(struct eblob_disk_control *dc,
			struct eblob_ram_control *rc, void *data, void *p),
		void *callback_private)
{
	struct eblob_iterate_control ctl;

	memset(&ctl, 0, sizeof(ctl));

	ctl.check_index = 1;
	ctl.priv = callback_private;
	ctl.iterator = callback;
	ctl.start_type = ctl.max_type = EBLOB_TYPE_META;

	return eblob_iterate(b, &ctl);
}

