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

static int dnet_history_send(struct dnet_net_state *st, struct dnet_io_attr *io)
{
	struct dnet_io_control ctl;

	memset(&ctl, 0, sizeof(struct dnet_io_control));

	ctl.cmd = DNET_CMD_WRITE;
	ctl.cflags = DNET_FLAGS_NEED_ACK;

	memcpy(ctl.addr, io->id, DNET_ID_SIZE);
	memcpy(&ctl.io, io, sizeof(struct dnet_io_attr));

	ctl.io.flags = DNET_IO_FLAGS_HISTORY;

	return dnet_trans_create_send(st->n, &ctl);
}

static int dnet_read_object_complete(struct dnet_net_state *st, struct dnet_cmd *cmd,
		struct dnet_attr *attr, void *priv)
{
	int err;
	struct dnet_node *n = NULL;
	struct dnet_io_attr *io;
	struct dnet_wait *w = priv;

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
				dnet_dump_id(cmd->id), (unsigned long long)cmd->size,
				(unsigned long long)attr->size);
		err = -EINVAL;
		goto err_out_exit;
	}

	io = (struct dnet_io_attr *)(attr + 1);

	dnet_convert_io_attr(io);
	/*
	 * Do not update history for this write since we fetched object and its transaction
	 * history from the network and it is not a real IO started by the client.
	 */
	io->flags = DNET_IO_FLAGS_NO_HISTORY_UPDATE;
	dnet_convert_io_attr(io);

	attr->cmd = DNET_CMD_WRITE;
	err = n->command_handler(st, n->command_private, cmd, attr, io);
	dnet_log(st->n, DNET_LOG_INFO, "%s: stored object locally, err: %d.\n",
			dnet_dump_id(cmd->id), err);
	if (err)
		goto err_out_exit;

	return 0;

out:
	if (st && w) {
		dnet_wakeup(w, do { w->cond--; st->n->total_synced_files++; } while (0));
		dnet_wait_put(w);
	}

err_out_exit:
	if (st && err) {
		dnet_log(st->n, DNET_LOG_ERROR, "%s: read object completion error: %d.\n",
				dnet_dump_id(st->id), err);
		st->n->error = err;
	}
	return 0;
}

static int dnet_history_save(struct dnet_net_state *st, struct dnet_cmd *cmd,
		struct dnet_attr *attr, struct dnet_io_attr *io, struct dnet_wait *w)
{
	struct dnet_node *n = st->n;
	struct dnet_io_control ctl;
	int err;

	attr->cmd = DNET_CMD_WRITE;

	err = n->command_handler(st, n->command_private, cmd, attr, io);
	dnet_log(st->n, DNET_LOG_INFO, "%s: stored history locally, err: %d, "
			"iosize: %llu.\n",
		dnet_dump_id(cmd->id), err, (unsigned long long)io->size);
	if (err)
		goto err_out_exit;

	memset(&ctl, 0, sizeof(struct dnet_io_control));

	memcpy(ctl.addr, cmd->id, DNET_ID_SIZE);
	memcpy(ctl.io.origin, cmd->id, DNET_ID_SIZE);

	ctl.priv = w;
	ctl.complete = dnet_read_object_complete;
	ctl.cmd = DNET_CMD_READ;
	ctl.cflags = DNET_FLAGS_NEED_ACK;

	if (w) {
		dnet_wakeup(w, w->cond++);
		dnet_wait_get(w);
	}

	err = dnet_read_object(st->n, &ctl);
	if (err)
		goto err_out_exit;

	return 0;

err_out_exit:
	return err;
}

static int dnet_compare_history(struct dnet_net_state *st, struct dnet_cmd *cmd,
		struct dnet_attr *la, struct dnet_attr *ra)
{
	struct dnet_node *n = st->n;
	struct dnet_io_attr *rio, *lio, *io;
	struct dnet_history_entry *rh, *lh, *rem_hist, *local_hist, *mhist;
	long long rnum, lnum, i, j, last_j = -1, last_i, size, num, append_num;
	int err = 0;

	if (!ra->size || ra->size < sizeof(struct dnet_io_attr) + sizeof(struct dnet_history_entry)) {
		dnet_log(n, DNET_LOG_ERROR, "%s: attribute size mismatch: remote: %llu, local: %llu.\n",
				dnet_dump_id(cmd->id), (unsigned long long)ra->size, (unsigned long long)la->size);
		err = -EINVAL;
		goto err_out_exit;
	}

	rio = (struct dnet_io_attr *)(ra + 1);
	lio = (struct dnet_io_attr *)(la + 1);

	dnet_convert_io_attr(rio);
	dnet_convert_io_attr(lio);

	if (!rio->size || rio->size % sizeof(struct dnet_history_entry)) {
		dnet_log(n, DNET_LOG_ERROR, "%s: wrong remote IO attribute size: offset: %llu, size: %llu "
				"(must be multiple of %zu).\n",	dnet_dump_id(cmd->id),
				(unsigned long long)rio->offset, (unsigned long long)rio->size,
				sizeof(struct dnet_history_entry));
		err = -EINVAL;
		goto err_out_exit;
	}
	
	if (!lio->size || lio->size % sizeof(struct dnet_history_entry)) {
		dnet_log(n, DNET_LOG_ERROR, "%s: wrong local IO attribute size: offset: %llu, size: %llu "
				"(must be multiple of %zu).\n",	dnet_dump_id(cmd->id),
				(unsigned long long)lio->offset, (unsigned long long)lio->size,
				sizeof(struct dnet_history_entry));
		err = -EINVAL;
		goto err_out_exit;
	}

	rnum = rio->size / sizeof(struct dnet_history_entry);
	lnum = lio->size / sizeof(struct dnet_history_entry);

	rem_hist = (struct dnet_history_entry *)(rio + 1);
	local_hist = (struct dnet_history_entry *)(lio + 1);

	for (j=0; j<lnum; ++j) {
		for (i=0; i<rnum; ++i) {
			if (j == lnum)
				break;

			rh = &rem_hist[i];
			lh = &local_hist[j+i];

			if (memcmp(rh, lh, sizeof(struct dnet_history_entry)))
				break;

			last_j = j;
			last_i = i;
		}
	}

	if (n->merge_strategy == DNET_MERGE_REMOTE_PLUS_LOCAL_UPDATES) {
		append_num = lnum - 1 - last_j;
		num = rnum;
	} else {
		append_num = rnum - 1 - last_i;
		num = lnum;
	}

	size = (num + append_num) * sizeof(struct dnet_history_entry);

	dnet_log(n, DNET_LOG_INFO, "%s: history size: %lld, entries: first: %lld, "
			"appended: %lld, strategy: %d.\n",
			dnet_dump_id(cmd->id), size, num, append_num, n->merge_strategy);

	size += sizeof(struct dnet_io_attr);

	io = malloc(size);
	if (!io) {
		dnet_log_err(n, "failed to allocate %lld bytes for merged log", size);
		goto err_out_exit;
	}

	mhist = (struct dnet_history_entry *)(io + 1);

	if (n->merge_strategy == DNET_MERGE_REMOTE_PLUS_LOCAL_UPDATES) {
		memcpy(mhist, rem_hist, num * sizeof(struct dnet_history_entry));
		memcpy(&mhist[rnum], &local_hist[last_j], append_num * sizeof(struct dnet_history_entry));
	} else {
		memcpy(mhist, local_hist, num * sizeof(struct dnet_history_entry));
		memcpy(&mhist[lnum], &rem_hist[last_i], append_num * sizeof(struct dnet_history_entry));
	}

	memcpy(io->id, cmd->id, DNET_ID_SIZE);
	memcpy(io->origin, cmd->id, DNET_ID_SIZE);

	io->flags = DNET_IO_FLAGS_HISTORY;
	io->offset = 0;
	io->size = size;

	la->size = io->size + sizeof(struct dnet_io_attr);
	cmd->size = la->size + sizeof(struct dnet_attr);

	dnet_convert_io_attr(io);

	err = dnet_history_send(st, io);
	if (err) {
		dnet_log(n, DNET_LOG_ERROR, "%s: failed to send merged history into network, err: %d.\n",
				dnet_dump_id(cmd->id), err);
		goto err_out_free;
	}

	err = dnet_history_save(st, cmd, la, io, NULL);
	if (err) {
		dnet_log(n, DNET_LOG_ERROR, "%s: failed to store merged history locally, err: %d.\n",
				dnet_dump_id(cmd->id), err);
		goto err_out_free;
	}

	free(io);
	return 0;

err_out_free:
	free(io);
err_out_exit:
	dnet_log(n, DNET_LOG_ERROR, "%s: failed to merge histories, err: %d.\n",
			dnet_dump_id(cmd->id), err);
	return err;
}

static int dnet_complete_history_read(struct dnet_net_state *st, struct dnet_cmd *cmd,
		struct dnet_attr *attr, void *priv)
{
	int err;
	struct dnet_node *n = NULL;
	struct dnet_cmd *local_cmd = NULL;
	struct dnet_attr *local_attr;
	struct dnet_io_attr *io, *local_io;
	struct dnet_wait *w = priv;

	if (!st || !cmd || cmd->status || !cmd->size) {
		err = -EINVAL;
		if (cmd) {
			err = cmd->status;
			dnet_log(st->n, DNET_LOG_INFO, "%s: received remote history: "
					"status: %d.\n",
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

	if (cmd->size != attr->size + sizeof(struct dnet_attr) ||
			attr->size < sizeof(struct dnet_io_attr)) {
		dnet_log(n, DNET_LOG_ERROR, "%s: wrong sizes: cmd_size: %llu, "
				"attr_size: %llu.\n",
				dnet_dump_id(cmd->id), (unsigned long long)cmd->size,
				(unsigned long long)attr->size);
		err = -EINVAL;
		goto err_out_exit;
	}

	io = (struct dnet_io_attr *)(attr + 1);

	dnet_convert_io_attr(io);

	if (io->size % sizeof(struct dnet_history_entry)) {
		dnet_log(n, DNET_LOG_ERROR, "%s: wrong history IO size: %llu, "
				"must be multiple of %zu.\n",
				dnet_dump_id(cmd->id), (unsigned long long)io->size,
				sizeof(struct dnet_history_entry));
		err = -EINVAL;
		goto err_out_exit;
	}

	if (n->merge_strategy == DNET_MERGE_PREFER_NETWORK) {
		err = dnet_history_save(st, cmd, attr, io, w);
		if (err)
			goto err_out_exit;

		return 0;
	}

	local_cmd = malloc(cmd->size + sizeof(struct dnet_cmd));
	if (!local_cmd) {
		dnet_log(n, DNET_LOG_ERROR, "%s: failed to allocate %llu bytes "
				"for history request.\n",
				dnet_dump_id(cmd->id), (unsigned long long)cmd->size);
		err = -ENOMEM;
		goto err_out_exit;
	}

	local_attr = (struct dnet_attr *)(local_cmd + 1);
	local_io = (struct dnet_io_attr *)(local_attr + 1);

	*local_cmd = *cmd;
	*local_attr = *attr;

	local_attr->cmd = DNET_CMD_READ;

	local_io->size = attr->size - sizeof(struct dnet_io_attr);
	local_io->offset = 0;
	local_io->flags = DNET_IO_FLAGS_HISTORY;
	memcpy(local_io->origin, cmd->id, DNET_ID_SIZE);

	dnet_log(n, DNET_LOG_INFO, "%s: reading local history: io_size: %llu.\n",
			dnet_dump_id(cmd->id), (unsigned long long)local_io->size);

	dnet_convert_io_attr(local_io);

	err = n->command_handler(st, n->command_private, local_cmd, local_attr, local_io);
	dnet_log(n, DNET_LOG_INFO, "%s: read local history: io_size: %llu, err: %d.\n",
					dnet_dump_id(cmd->id),
					(unsigned long long)local_io->size, err);
	if (err) {
		err = dnet_history_save(st, cmd, attr, io, w);
	} else {
		if (n->merge_strategy == DNET_MERGE_PREFER_LOCAL)
			err = dnet_history_send(st, local_io);
		else
			err = dnet_compare_history(st, cmd, local_attr, attr);
	}

	if (err)
		goto err_out_free;

	free(local_cmd);

	return 0;

out:
	if (w) {
		dnet_wakeup(w, w->cond--);
		dnet_wait_put(w);
	}
err_out_free:
	free(local_cmd);
err_out_exit:
	if (st && err) {
		dnet_log(st->n, DNET_LOG_ERROR, "%s: read history completion error: %d.\n",
				dnet_dump_id(st->id), err);
		st->n->error = err;
	}
	return 0;
}

int dnet_fetch_objects(struct dnet_net_state *st, void *data, uint64_t num,
		struct dnet_wait *w)
{
	struct dnet_node *n = st->n;
	struct dnet_io_control ctl;
	uint64_t i;

	memset(&ctl, 0, sizeof(struct dnet_io_control));

	ctl.complete = dnet_complete_history_read;
	ctl.io.flags = DNET_IO_FLAGS_HISTORY;
	ctl.priv = w;
	ctl.cmd = DNET_CMD_READ;
	ctl.cflags = DNET_FLAGS_NEED_ACK;

	dnet_log(n, DNET_LOG_INFO, "%s: received %llu history IDs.\n",
			dnet_dump_id(ctl.addr), (unsigned long long)num);
	for (i=0; i<num; ++i) {
		memcpy(ctl.addr, data, DNET_ID_SIZE);
		memcpy(ctl.io.origin, data, DNET_ID_SIZE);

		dnet_log(n, DNET_LOG_NOTICE, "%s: requesting history.\n",
				dnet_dump_id(ctl.addr));

		if (w)
			dnet_wait_get(w);
		dnet_read_object(n, &ctl);

		data += DNET_ID_SIZE;
	}

	return 0;
}

static int dnet_recv_list_complete(struct dnet_net_state *st, struct dnet_cmd *cmd,
		struct dnet_attr *attr, void *priv)
{
	struct dnet_node *n = NULL;
	uint64_t size, num;
	int err = 0;
	void *data = attr + 1;
	struct dnet_wait *w = priv;

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
		dnet_log(n, DNET_LOG_ERROR, "%s: wrong command size %llu, "
				"must be more than %zu.\n",
				dnet_dump_id(cmd->id), (unsigned long long)cmd->size,
				sizeof(struct dnet_attr));
		goto err_out_exit;
	}

	size -= sizeof(struct dnet_attr);
	
	if (!size || size % DNET_ID_SIZE) {
		dnet_log(n, DNET_LOG_ERROR, "%s: wrong command size %llu, "
				"must be multiple of DNET_ID_SIZE (%u).\n",
				dnet_dump_id(cmd->id), (unsigned long long)cmd->size,
				DNET_ID_SIZE);
		err = -EINVAL;
		goto err_out_exit;
	}

	num = size / DNET_ID_SIZE;

	n->wait->cond += num;
	dnet_fetch_objects(st, data, num, n->wait);

	return 0;

out:
	if (w) {
		dnet_wakeup(w, w->cond--);
		dnet_wait_put(w);
	}
err_out_exit:
	if (cmd && n)
		dnet_log(n, DNET_LOG_NOTICE, "%s: listing completed with status: %d, "
				"size: %llu, err: %d, files_synced: %llu.\n",
			dnet_dump_id(cmd->id), cmd->status, (unsigned long long)cmd->size,
			err, (unsigned long long)n->total_synced_files);
	if (st && err) {
		dnet_log(n, DNET_LOG_ERROR, "%s: listing completion error: %d.\n",
				dnet_dump_id(st->id), err);
		st->n->error = err;
	}
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

	t->complete = dnet_recv_list_complete;
	if (need_wait)
		t->priv = dnet_wait_get(w);

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
			dnet_log(n, DNET_LOG_ERROR, "%s: can not get output state.\n",
					dnet_dump_id(n->id));
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

	dnet_log(n, DNET_LOG_INFO, "%s: successfully synced %llu files.\n",
		dnet_dump_id(n->id), (unsigned long long)n->total_synced_files);

	return 0;

err_out_destroy:
	dnet_trans_destroy(t);
err_out_put:
	dnet_wait_put(w);
err_out_exit:
	return err;
}
