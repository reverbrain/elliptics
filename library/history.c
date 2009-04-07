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

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "elliptics.h"
#include "dnet/interface.h"

static int dnet_compare_history(struct dnet_node *n, struct dnet_cmd *cmd, struct dnet_attr *la, struct dnet_attr *ra)
{
	struct dnet_io_attr *rio, *lio;
	unsigned long long num;
	int err = 0;

	if (!ra->size || ra->size != la->size) {
		dnet_log(n, DNET_LOG_ERROR, "%s: attribute size mismatch: remote: %llu, local: %llu.\n",
				dnet_dump_id(cmd->id), (unsigned long long)ra->size, (unsigned long long)la->size);
		err = -EINVAL;
		goto out;
	}

	num = ra->size / sizeof(struct dnet_io_attr) - 1;

	rio = &((struct dnet_io_attr *)(ra + 1))[num];
	lio = &((struct dnet_io_attr *)(la + 1))[num];
	
	dnet_convert_io_attr(rio);
	dnet_convert_io_attr(lio);

	if (rio->size != lio->size || rio->offset != lio->offset) {
		dnet_log(n, DNET_LOG_ERROR, "%s: last IO attribute mismatch: remote/local: offset: %llu/%llu, size: %llu/%llu.\n",
				dnet_dump_id(cmd->id), (unsigned long long)rio->offset, (unsigned long long)lio->offset,
				(unsigned long long)rio->size, (unsigned long long)lio->size);
		err = -EINVAL;
		goto out;
	}

	err = memcmp(rio->id, lio->id, DNET_ID_SIZE);
	if (err) {
		dnet_log(n, DNET_LOG_ERROR, "Last transaction mismatch: local : %s", dnet_dump_id(lio->id));
		dnet_log(n, DNET_LOG_ERROR, "Last transaction mismatch: remote: %s", dnet_dump_id(rio->id));
		err = -EINVAL;
		goto out;
	}

	dnet_log(n, DNET_LOG_ERROR, "%s: last transaction matched: size: %llu, offset: %llu.\n",
			dnet_dump_id(rio->id), (unsigned long long)rio->size, (unsigned long long)rio->offset);
out:
	return err;
}

static int dnet_read_object_complete(struct dnet_net_state *st, struct dnet_cmd *cmd,
		struct dnet_attr *attr, void *priv __unused)
{
	int err;
	struct dnet_node *n = NULL;
	struct dnet_io_attr *io;

	if (!st || !cmd || cmd->status || !cmd->size) {
		err = -EINVAL;
		if (cmd) {
			err = cmd->status;
			dnet_log(st->n, DNET_LOG_INFO, "%s: received object, err: %d.\n",
					dnet_dump_id(cmd->id), err);
		}
		goto out;
	}

	n = st->n;

	err = cmd->status;
	
	if (cmd->size <= sizeof(struct dnet_attr)) {
		dnet_log(n, DNET_LOG_ERROR, "%s: wrong cmd size: %llu.\n",
				dnet_dump_id(cmd->id), (unsigned long long)cmd->size);
		err = -EINVAL;
		goto err_out_exit;
	}

	if (cmd->size != attr->size + sizeof(struct dnet_attr)) {
		dnet_log(n, DNET_LOG_ERROR, "%s: wrong sizes: cmd_size: %llu, attr_size: %llu.\n",
				dnet_dump_id(cmd->id), (unsigned long long)cmd->size, (unsigned long long)attr->size);
		err = -EINVAL;
		goto err_out_exit;
	}

	io = (struct dnet_io_attr *)(attr + 1);

	dnet_convert_io_attr(io);
	/*
	 * Do not update history for this write since we fetched object and its transaction
	 * history from the network and it is not a real IO started by the client.
	 */
	io->flags = DNET_IO_FLAGS_OBJECT;
	dnet_convert_io_attr(io);

	attr->cmd = DNET_CMD_WRITE;
	err = n->command_handler(st, n->command_private, cmd, attr, io);
	dnet_log(st->n, DNET_LOG_INFO, "%s: stored object locally, err: %d.\n",
			dnet_dump_id(cmd->id), err);
	if (err)
		goto err_out_exit;

	return 0;

out:
	if (st) {
		dnet_wakeup(st->n->wait, do { st->n->wait->cond--; st->n->total_synced_files++; } while (0));
		dnet_wait_put(st->n->wait);
	}

err_out_exit:
	if (st && err)
		st->n->error = err;
	return err;
}

static int dnet_complete_history_read(struct dnet_net_state *st, struct dnet_cmd *cmd,
		struct dnet_attr *attr, void *priv __unused)
{
	int err;
	struct dnet_node *n = NULL;
	struct dnet_cmd *c = NULL;
	struct dnet_attr *a;
	struct dnet_io_attr *io;

	if (!st || !cmd || cmd->status || !cmd->size) {
		err = -EINVAL;
		if (cmd) {
			err = cmd->status;
			dnet_log(st->n, DNET_LOG_INFO, "%s: received remote history: status: %d.\n",
					dnet_dump_id(cmd->id), err);
		}
		goto out;
	}

	n = st->n;

	err = cmd->status;
	
	if (cmd->size <= sizeof(struct dnet_attr)) {
		dnet_log(n, DNET_LOG_ERROR, "%s: wrong cmd size: %llu.\n",
				dnet_dump_id(cmd->id), (unsigned long long)cmd->size);
		err = -EINVAL;
		goto err_out_exit;
	}

	if (cmd->size != attr->size + sizeof(struct dnet_attr)) {
		dnet_log(n, DNET_LOG_ERROR, "%s: wrong sizes: cmd_size: %llu, attr_size: %llu.\n",
				dnet_dump_id(cmd->id), (unsigned long long)cmd->size, (unsigned long long)attr->size);
		err = -EINVAL;
		goto err_out_exit;
	}

	c = malloc(cmd->size + sizeof(struct dnet_cmd));
	if (!c) {
		dnet_log(n, DNET_LOG_ERROR, "%s: failed to allocate %llu bytes "
				"for history request.\n",
				dnet_dump_id(cmd->id), (unsigned long long)cmd->size);
		err = -ENOMEM;
		goto err_out_exit;
	}

	a = (struct dnet_attr *)(c + 1);
	io = (struct dnet_io_attr *)(a + 1);

	*c = *cmd;
	*a = *attr;

	a->cmd = DNET_CMD_READ;

	io->size = attr->size - sizeof(struct dnet_io_attr);
	io->offset = 0;
	io->flags = DNET_IO_FLAGS_HISTORY | DNET_IO_FLAGS_OBJECT;
	memcpy(io->id, cmd->id, DNET_ID_SIZE);
	
	dnet_log(n, DNET_LOG_INFO, "%s: reading local history: io_size: %llu.\n",
					dnet_dump_id(cmd->id), (unsigned long long)io->size);

	dnet_convert_io_attr(io);

	err = n->command_handler(st, n->command_private, c, a, io);
	dnet_log(n, DNET_LOG_INFO, "%s: read local history: io_size: %llu, err: %d.\n",
					dnet_dump_id(cmd->id), (unsigned long long)io->size, err);
	if (err) {
		struct dnet_io_control ctl;
		
		if (attr->size > sizeof(struct dnet_io_attr)) {
			attr->cmd = DNET_CMD_WRITE;

			err = n->command_handler(st, n->command_private, cmd, attr, attr+1);
			dnet_log(st->n, DNET_LOG_INFO, "%s: stored history locally, err: %d, asize: %llu.\n",
				dnet_dump_id(cmd->id), err, (unsigned long long)attr->size);
			if (err)
				goto err_out_free;
		}

		memset(&ctl, 0, sizeof(struct dnet_io_control));

		memcpy(ctl.id, cmd->id, DNET_ID_SIZE);
		memcpy(ctl.io.id, cmd->id, DNET_ID_SIZE);

		ctl.io.size = 0;
		ctl.io.offset = 0;
		ctl.io.flags = 0;

		ctl.priv = NULL;
		ctl.complete = dnet_read_object_complete;
		ctl.cmd = DNET_CMD_READ;
		
		dnet_wakeup(n->wait, n->wait->cond++);
		dnet_wait_get(n->wait);

		err = dnet_read_object(n, &ctl);
		if (err)
			goto err_out_free;
	} else {
		err = dnet_compare_history(n, cmd, a, attr);
		if (err)
			goto err_out_free;
	}
	free(c);

	return 0;

out:
	if (st) {
		n = st->n;
		dnet_wakeup(n->wait, n->wait->cond--);
		dnet_wait_put(n->wait);
	}
err_out_free:
	free(c);
err_out_exit:
	if (st && err)
		st->n->error = err;
	return err;
}

static int dnet_recv_list_complete(struct dnet_net_state *st, struct dnet_cmd *cmd,
		struct dnet_attr *attr, void *priv)
{
	struct dnet_node *n = NULL;
	uint64_t size, i;
	struct dnet_io_control ctl;
	int err = 0;
	void *data = attr + 1;

	if (!st || !cmd || !attr || cmd->status || !cmd->size) {
		if (cmd)
			err = cmd->status;
		goto out;
	}

	n = st->n;
	size = cmd->size;
	err = cmd->status;

	if (size < sizeof(struct dnet_attr)) {
		err = -EINVAL;
		dnet_log(n, DNET_LOG_ERROR, "%s: wrong command size %llu, must be more than %zu.\n",
				dnet_dump_id(cmd->id), (unsigned long long)cmd->size, sizeof(struct dnet_attr));
		goto err_out_exit;
	}

	size -= sizeof(struct dnet_attr);
	
	if (size % DNET_ID_SIZE) {
		dnet_log(n, DNET_LOG_ERROR, "%s: wrong command size %llu, must be multiple of DNET_ID_SIZE (%u).\n",
				dnet_dump_id(cmd->id), (unsigned long long)cmd->size, DNET_ID_SIZE);
		err = -EINVAL;
		goto err_out_exit;
	}

	memset(&ctl, 0, sizeof(struct dnet_io_control));

	ctl.complete = dnet_complete_history_read;
	ctl.io.flags = DNET_IO_FLAGS_HISTORY | DNET_IO_FLAGS_OBJECT;
	ctl.priv = priv;
	ctl.cmd = DNET_CMD_READ;

	n->wait->cond += size / DNET_ID_SIZE;

	for (i=0; i<size / DNET_ID_SIZE; ++i) {
		memcpy(ctl.id, data, DNET_ID_SIZE);
		memcpy(ctl.io.id, data, DNET_ID_SIZE);

		dnet_log(n, DNET_LOG_NOTICE, "%s: requesting history.\n", dnet_dump_id(ctl.id));

		dnet_wait_get(n->wait);
		dnet_read_object(n, &ctl);

		data += DNET_ID_SIZE;
	}

	return 0;

out:
	if (st) {
		n = st->n;
		dnet_wakeup(n->wait, n->wait->cond--);
		dnet_wait_put(n->wait);
	}
err_out_exit:
	if (cmd && n)
		dnet_log(n, DNET_LOG_NOTICE, "%s: listing completed with status: %d, "
				"size: %llu, err: %d, files_synced: %llu.\n",
			dnet_dump_id(cmd->id), cmd->status, (unsigned long long)cmd->size,
			err, (unsigned long long)n->total_synced_files);
	if (st && err)
		st->n->error = err;
	return err;
}

int dnet_recv_list(struct dnet_node *n, struct dnet_net_state *st)
{
	struct dnet_trans *t;
	struct dnet_cmd *cmd;
	struct dnet_attr *a;
	int err, need_wait = !st;
	struct dnet_wait *w = n->wait;

	t = dnet_trans_alloc(n, sizeof(struct dnet_cmd) +
			sizeof(struct dnet_attr));
	if (!t) {
		err = -ENOMEM;
		goto err_out_put;
	}

	memset(t, 0, sizeof(struct dnet_trans));

	t->complete = dnet_recv_list_complete;

	cmd = (struct dnet_cmd *)(t + 1);
	a = (struct dnet_attr *)(cmd + 1);

	memcpy(cmd->id, n->id, DNET_ID_SIZE);
	cmd->flags = DNET_FLAGS_NEED_ACK;
	cmd->status = 0;
	cmd->trans = 0;
	cmd->size = sizeof(struct dnet_attr);

	a->cmd = DNET_CMD_LIST;
	a->size = 0;
	a->flags = 0;

	if (!st) {
		st = dnet_state_get_first(n, cmd->id, n->st);
		if (!st) {
			err = -ENOENT;
			dnet_log(n, DNET_LOG_ERROR, "%s: can not get output state.\n", dnet_dump_id(n->id));
			goto err_out_destroy;
		}
	} else
		st = dnet_state_get(st);

	t->st = st;

	err = dnet_trans_insert(t);
	if (err)
		goto err_out_destroy;

	cmd->trans = t->trans;

	dnet_convert_cmd(cmd);
	dnet_convert_attr(a);

	if (need_wait) {
		/*
		 * Will be decreased in the completion callback.
		 * If there will be some files to sync, counter will
		 * be first increased prior to completion callback
		 * finish and the decreased back in the read object
		 * completion.
		 */
		w->cond = 1;
		n->total_synced_files = 0;
	}

	t->r.header = cmd;
	t->r.hsize = sizeof(struct dnet_cmd) + sizeof(struct dnet_attr);
	t->r.fd = -1;
	t->r.offset = 0;
	t->r.size = 0;

	dnet_req_set_flags(&t->r, ~0, DNET_REQ_NO_DESTRUCT);

	err = dnet_data_ready(st, &t->r);
	if (err)
		goto err_out_destroy;

	if (need_wait) {
		err = dnet_wait_event(w, w->cond == 0, &n->wait_ts);
		if (err) {
			dnet_log(n, DNET_LOG_ERROR, "%s: failed to wait for the content sync, err: %d, n_err: %d.\n",
					dnet_dump_id(n->id), err, n->error);
			goto err_out_exit;
		}
	}

	if (n->error) {
		err = n->error;

		dnet_log(n, DNET_LOG_ERROR, "%s: failed to sync the content, err: %d.\n",
				dnet_dump_id(n->id), err);
		goto err_out_exit;
	}

	dnet_log(n, DNET_LOG_INFO, "%s: successfully synced %llu files.\n", dnet_dump_id(n->id),
			(unsigned long long)n->total_synced_files);

	return 0;

err_out_destroy:
	dnet_trans_destroy(t);
err_out_put:
	dnet_wait_put(w);
err_out_exit:
	return err;
}
