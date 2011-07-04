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
			struct dnet_id did;
			dnet_setup_id(&did, cmd->id.group_id, id.id);
			did.type = io->type;

			err = dnet_meta_update_checksum(n, &did);
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

struct dnet_db_list_control {
	struct dnet_node		*n;
	struct dnet_net_state		*st;
	struct dnet_cmd			*cmd;
	struct dnet_attr		*attr;
	struct dnet_check_request	*req;

	atomic_t			completed;
	atomic_t			errors;
	atomic_t			total;
};

static long long dnet_meta_get_ts(struct dnet_node *n, struct dnet_meta_container *mc)
{
	struct dnet_meta *m;
	struct dnet_meta_check_status *c;

	m = dnet_meta_search(n, mc, DNET_META_CHECK_STATUS);
	if (!m)
		return -ENOENT;

	c = (struct dnet_meta_check_status *)m->data;
	dnet_convert_meta_check_status(c);

	return (long long)c->tsec;
}

static int dnet_db_send_check_reply(struct dnet_db_list_control *ctl)
{
	struct dnet_check_reply reply;

	memset(&reply, 0, sizeof(reply));

	reply.total = atomic_read(&ctl->total);
	reply.errors = atomic_read(&ctl->errors);
	reply.completed = atomic_read(&ctl->completed);

	dnet_convert_check_reply(&reply);
	return dnet_send_reply(ctl->st, ctl->cmd, ctl->attr, &reply, sizeof(reply), 1);
}


int dnet_db_iterate(struct eblob_backend *b, unsigned int flags __unused,
		struct eblob_iterate_callbacks *iterate_cb,
		void *callback_private)
{
	struct eblob_iterate_control ctl;

	memset(&ctl, 0, sizeof(ctl));

	ctl.check_index = 1;
	ctl.priv = callback_private;
	memcpy(&ctl.iterator_cb, iterate_cb, sizeof(struct eblob_iterate_callbacks));
	ctl.start_type = ctl.max_type = EBLOB_TYPE_META;

	return eblob_iterate(b, &ctl);
}

static int dnet_db_list_iter(struct eblob_disk_control *dc, struct eblob_ram_control *rc, void *data, void *p)
{
	struct dnet_db_list_control *ctl = p;
	struct dnet_node *n = ctl->n;
	struct dnet_meta_container mc;
	struct dnet_net_state *tmp;
	long long ts, edge = ctl->req->timestamp;
	char time_buf[64], ctl_time[64];
	struct tm tm;
	int will_check, should_be_merged;
	int send_check_reply = 1;
	int err;

	mc.data = data;
	mc.size = rc->size;

	if (edge) {
		localtime_r((time_t *)&edge, &tm);
		strftime(ctl_time, sizeof(ctl_time), "%F %R:%S %Z", &tm);
	} else {
		snprintf(ctl_time, sizeof(ctl_time), "all records");
	}

	dnet_setup_id(&mc.id, n->id.group_id, dc->key.id);

	/*
	* Use group ID field to specify whether we should check number of copies
	* or merge transaction with other history log in the storage
	*
	* tmp == NULL means this key belongs to given node and we should check
	* number of its copies in the storage. If state is not NULL then given
	* key must be moved to another machine and potentially merged with data
	* present there
	*/
	tmp = dnet_state_get_first(n, &mc.id);
	should_be_merged = (tmp != NULL);
	dnet_state_put(tmp);

	/*
	* If timestamp is specified check should be performed only to files
	* that was not checked since that timestamp
	*/
	ts = dnet_meta_get_ts(n, &mc);
	will_check = !(edge && (ts > edge));

	if (!should_be_merged && (ctl->req->flags & DNET_CHECK_MERGE)) {
		will_check = 0;
	}

	if (should_be_merged && (ctl->req->flags & DNET_CHECK_FULL)) {
		will_check = 0;
	}

	if (n->log->log_mask & DNET_LOG_NOTICE) {
		localtime_r((time_t *)&ts, &tm);
		strftime(time_buf, sizeof(time_buf), "%F %R:%S %Z", &tm);

		dnet_log_raw(n, DNET_LOG_NOTICE, "CHECK: start key: %s, timestamp: %lld [%s], check before: %lld [%s], "
						"will check: %d, should_be_merged: %d, dry: %d, flags: %x, size: %u.\n",
				dnet_dump_id(&mc.id), ts, time_buf, edge, ctl_time,
				will_check, should_be_merged, !!(ctl->req->flags & DNET_CHECK_DRY_RUN), ctl->req->flags, mc.size);
	}

	if (will_check) {
		err = dnet_check(n, &mc, NULL, should_be_merged);
//		if (err >= 0 && !should_be_merged)
//			err = dnet_db_check_update(n, ctl, &mc);

		dnet_log_raw(n, DNET_LOG_NOTICE, "CHECK: complete key: %s, timestamp: %lld [%s], err: %d\n",
				dnet_dump_id(&mc.id), ts, time_buf, err);

	}

	if ((atomic_inc(&ctl->total) % 30000) == 0) {
		if (send_check_reply) {
			if (dnet_db_send_check_reply(ctl))
				send_check_reply = 0;
		}

		dnet_log(n, DNET_LOG_INFO, "CHECK: total: %d, completed: %d, errors: %d\n",
				atomic_read(&ctl->total), atomic_read(&ctl->completed), atomic_read(&ctl->errors));
	}

	return 0;
}

int dnet_db_list(struct dnet_net_state *st, struct dnet_cmd *cmd, struct dnet_attr *attr)
{
	struct dnet_node *n = st->n;
	struct dnet_db_list_control ctl;
	struct dnet_check_request *r, req;
	char ctl_time[64];
	struct tm tm;
	int err = 0;

	if (n->check_in_progress)
		return -EINPROGRESS;

	if (attr->size < sizeof(struct dnet_check_request)) {
		dnet_log(n, DNET_LOG_ERROR, "%s: CHECK: invalid check request size %llu, must be %zu\n",
		dnet_dump_id(&cmd->id), (unsigned long long)attr->size, sizeof(struct dnet_check_request));
		return -EINVAL;
	}

	r = (struct dnet_check_request *)(attr + 1);
	dnet_convert_check_request(r);

	n->check_in_progress = 1;

	if (!r->thread_num)
		r->thread_num = 50;

	memcpy(&req, r, sizeof(req));

	memset(&ctl, 0, sizeof(struct dnet_db_list_control));

	atomic_init(&ctl.completed, 0);
	atomic_init(&ctl.errors, 0);
	atomic_init(&ctl.total, 0);

	ctl.n = n;
	ctl.st = st;
	ctl.cmd = cmd;
	ctl.attr = attr;
	ctl.req = &req;

	if (req.timestamp) {
		localtime_r((time_t *)&req.timestamp, &tm);
		strftime(ctl_time, sizeof(ctl_time), "%F %R:%S %Z", &tm);
	} else {
		snprintf(ctl_time, sizeof(ctl_time), "all records");
	}

	dnet_log(n, DNET_LOG_INFO, "CHECK: Started %u checking threads, recovering %llu transactions, "
			"which started before %s: merge: %d, full: %d, dry: %d.\n",
			req.thread_num, (unsigned long long)req.obj_num, ctl_time,
			!!(req.flags & DNET_CHECK_MERGE), !!(req.flags & DNET_CHECK_FULL),
			!!(req.flags & DNET_CHECK_DRY_RUN));

	if (req.obj_num > 0) {
		struct dnet_id *ids = (struct dnet_id *)(r + 1);
		struct eblob_disk_control dc;
		struct eblob_ram_control rc;
		struct dnet_raw_id id;
		void *data;
		int err;
		uint32_t i;

		memset(&dc, 0, sizeof(struct eblob_disk_control));
		memset(&rc, 0, sizeof(struct eblob_ram_control));

		for (i = 0; i < req.obj_num; ++i) {
			memcpy(&id.id, &ids[i].id, DNET_ID_SIZE);
			err = n->cb->meta_read(n->cb->command_private, &id, &data);
			if (err > 0) {
				rc.size = err;
				memcpy(&dc.key.id, &ids[i].id, DNET_ID_SIZE);
				err = dnet_db_list_iter(&dc, &rc, data, &ctl);
			}
		}
	} else {
		//err = n->cb->meta_iterate(n->cb->command_private, 0, dnet_db_list_iter, &ctl);
	}

	if(r->flags & DNET_CHECK_MERGE) {
		dnet_counter_set(n, DNET_CNTR_NODE_LAST_MERGE, 0, atomic_read(&ctl.completed));
		dnet_counter_set(n, DNET_CNTR_NODE_LAST_MERGE, 1, atomic_read(&ctl.errors));
	}

	dnet_db_send_check_reply(&ctl);

	n->check_in_progress = 0;
	return err;
}


