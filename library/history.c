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

int dnet_db_read_raw(struct dnet_node *n, int meta, unsigned char *id, void **datap)
{
	int err;
	size_t size;
	KCDB *db = n->history;
	void *data;

	if (meta)
		db = n->meta;

	data = kcdbget(db, (void *)id, DNET_ID_SIZE, &size);
	if (!data) {
		err = -kcdbecode(db);
		dnet_log_raw(n, DNET_LOG_ERROR, "%s: raw DB read failed "
			"err: %d: %s.\n", dnet_dump_id_str(id),
			err, kcecodename(-err));
		goto err_out_exit;
	}

	*datap = data;

	return size;

err_out_exit:
	return err;
}

int dnet_db_read(struct dnet_net_state *st, struct dnet_cmd *cmd, struct dnet_io_attr *io)
{
	struct dnet_node *n = st->n;
	int err;
	void *data;

	err = dnet_db_read_raw(n, !!(io->flags & DNET_IO_FLAGS_META), io->id, &data);
	if (err <= 0)
		return err;

	io->size = err;
	err = dnet_send_read_data(st, cmd, io, data, -1, 0);
	kcfree(data);

	return err;
}

static int db_put_data(struct dnet_node *n, struct dnet_cmd *cmd, struct dnet_io_attr *io, void *data, unsigned int size)
{
	int ret, append = 0;
	KCDB *db = n->history;
	char *dbf = "history";
	int err;

	if (io->flags & DNET_IO_FLAGS_META) {
		db = n->meta;
		dbf = "meta";
	} else if ((io->flags & DNET_IO_FLAGS_APPEND) || !(io->flags & DNET_IO_FLAGS_NO_HISTORY_UPDATE)) {
		append = 1;
	}

	ret = kcdbbegintran(db, 1);
	if (!ret) {
		err = -kcdbecode(db);
		dnet_log_raw(n, DNET_LOG_ERROR, "%s: failed to start update transaction, err: %d: %s.\n",
			dnet_dump_id(&cmd->id), err, kcecodename(-err));
		goto err_out_exit;
	}

	if (append) {
		ret = kcdbappend(db, (void *)io->id, DNET_ID_SIZE, data, size);
	} else {
		ret = kcdbset(db, (void *)io->id, DNET_ID_SIZE, data, size);
	}

	if (!ret) {
		err = -kcdbecode(db);
		dnet_log(n, DNET_LOG_ERROR, "%s: %s: failed to store %u bytes: %s [%d]\n", dnet_dump_id(&cmd->id), dbf,
				size, kcecodename(-err), err);
		goto err_out_txn_end;
	}
	kcdbendtran(db, 1);

	dnet_log_raw(n, DNET_LOG_NOTICE, "%s: %s: stored %u bytes.\n",
			dnet_dump_id(&cmd->id), dbf, size);

	return 0;

err_out_txn_end:
	kcdbendtran(db, 0);
err_out_exit:
	return err;
}

int dnet_db_write(struct dnet_node *n, struct dnet_cmd *cmd, void *data)
{
	struct dnet_io_attr *io = data;
	struct dnet_history_entry e;

	if ((io->flags & DNET_IO_FLAGS_HISTORY) || (io->flags & DNET_IO_FLAGS_META))
		return db_put_data(n, cmd, io, io + 1, io->size);

	if (io->flags & DNET_IO_FLAGS_NO_HISTORY_UPDATE)
		return 0;

	dnet_setup_history_entry(&e, io->parent, io->size, io->offset, NULL, io->flags);
	return db_put_data(n, cmd, io, &e, sizeof(struct dnet_history_entry));
}

static int db_del_direct_notran(struct dnet_node *n, struct dnet_cmd *cmd)
{
	kcdbremove(n->history, (void *)cmd->id.id, DNET_ID_SIZE);
	kcdbremove(n->meta, (void *)cmd->id.id, DNET_ID_SIZE);

	return 0;
}

static int db_del_direct_trans(struct dnet_node *n, struct dnet_id *id, int meta)
{
	int ret, err = 0;
	KCDB *db = meta ? n->meta : n->history;
	char *dbname = meta ? "meta" : "history";

	ret = kcdbbegintran(db, 1);
	if (!ret) {
		err = -kcdbecode(db);
		dnet_log_raw(n, DNET_LOG_ERROR, "%s: failed to start %s remove transaction, err: %d: %s.\n",
			dnet_dump_id(id), dbname, err, kcecodename(-err));
		goto err_out_exit;
	}

	ret = kcdbremove(db, (void *)id->id, DNET_ID_SIZE);
	if (!ret) {
		err = -kcdbecode(db);
		dnet_log_raw(n, DNET_LOG_ERROR, "%s: failed to remove %s object, err: %d: %s.\n",
			dnet_dump_id(id), dbname, err, kcecodename(-err));
	}
	kcdbendtran(db, ret);

err_out_exit:
	return err;
}

static int db_del_direct(struct dnet_node *n, struct dnet_cmd *cmd)
{
	db_del_direct_trans(n, &cmd->id, 1);
	db_del_direct_trans(n, &cmd->id, 0);
	return 0;
}

static int dnet_history_del_entry(struct dnet_node *n, struct dnet_id *id, struct dnet_history_entry *e, unsigned int num)
{
	unsigned int i;

	for (i=0; i<num; ++i) {
		if (!memcmp(id->id, e[i].id, DNET_ID_SIZE))
			break;
	}

	if (i == num) {
		dnet_log_raw(n, DNET_LOG_INFO, "%s: requested transaction was not found.\n",
			dnet_dump_id(id));
		return -ENOENT;
	}

	dnet_log_raw(n, DNET_LOG_INFO, "%s: removing transaction from position %u/%u.\n",
			dnet_dump_id(id), i, num);

	if (i < num - 1)
		memmove(&e[i], &e[i+1], (num - i - 1) * sizeof(struct dnet_history_entry));

	return 0;
}

int dnet_db_del(struct dnet_node *n, struct dnet_cmd *cmd, struct dnet_attr *attr)
{
	int err = -EINVAL, ret;
	size_t size;
	void *e = NULL;
	unsigned int num;

	if (attr->flags & DNET_ATTR_DIRECT_TRANSACTION) {
		db_del_direct(n, cmd);
		return 1;
	}

	ret = kcdbbegintran(n->history, 1);
	if (!ret) {
		err = -kcdbecode(n->history);
		dnet_log_raw(n, DNET_LOG_ERROR, "%s: failed to start history deletion transaction, err: %d: %s.\n",
			dnet_dump_id(&cmd->id), err, kcecodename(-err));
		goto err_out_exit;
	}

	e = kcdbget(n->history, (void *)cmd->id.id, DNET_ID_SIZE, &size);
	if (!e) {
		err = -kcdbecode(n->history);
		dnet_log_raw(n, DNET_LOG_ERROR, "%s: failed to read history of to be deleted object, err: %d: %s.\n",
			dnet_dump_id(&cmd->id), err, kcecodename(-err));

		goto err_out_txn_end;
	}

	if (size % sizeof(struct dnet_history_entry)) {
		err = -EINVAL;
		dnet_log_raw(n, DNET_LOG_ERROR, "%s: corrupted history of to be deleted object.\n",
			dnet_dump_id(&cmd->id));
		goto err_out_free;
	}

	num = size / sizeof(struct dnet_history_entry);
	size -= sizeof(struct dnet_history_entry);

	err = dnet_history_del_entry(n, &cmd->id, e, num);
	if (err)
		goto err_out_free;

	if (size) {
		ret = kcdbset(n->history, (void *)cmd->id.id, DNET_ID_SIZE, e, size);
		if (!ret) {
			err = -kcdbecode(n->history);
			dnet_log_raw(n, DNET_LOG_ERROR, "%s: failed to store truncated history, err: %d: %s.\n",
				dnet_dump_id(&cmd->id), err, kcecodename(-err));

			goto err_out_free;
		}
	} else {
		db_del_direct_notran(n, cmd);
		ret = 1;
	}

	dnet_log_raw(n, DNET_LOG_NOTICE, "%s: truncated history: going to remove object: %d.\n",
		dnet_dump_id(&cmd->id), ret);

	kcfree(e);
	kcdbendtran(n->history, 1);

	return ret;

err_out_free:
	kcfree(e);
err_out_txn_end:
	kcdbendtran(n->history, 0);
err_out_exit:
	return err;
}

struct dnet_db_list_control {
	struct dnet_node		*n;
	struct dnet_net_state		*st;
	struct dnet_cmd			*cmd;
	struct dnet_attr		*attr;

	KCCUR				*cursor;
	pthread_mutex_t			lock;

	int				need_exit;

	unsigned int			obj_pos;
	struct dnet_check_request	*req;

	atomic_t			completed;
	atomic_t			errors;
	atomic_t			total;
};

static int dnet_db_check_update(struct dnet_node *n, struct dnet_db_list_control *ctl, struct dnet_meta_container *morig)
{
	struct dnet_meta_container *mc = morig;
	struct dnet_meta *m;
	struct dnet_meta_check_status *c;
	struct timeval tv;
	struct dnet_io_attr io;
	int err;

	m = dnet_meta_search(n, mc->data, mc->size, DNET_META_CHECK_STATUS);
	if (!m) {
		mc = malloc(sizeof(*mc) + mc->size + sizeof(struct dnet_meta_check_status) + sizeof(struct dnet_meta));
		if (!mc)
			return -ENOMEM;

		memcpy(mc, morig, sizeof(*mc) + morig->size);

		m = (struct dnet_meta *)(mc->data + morig->size);

		memset(m, 0, sizeof(*m));

		m->size = sizeof(struct dnet_meta_check_status);
		m->type = DNET_META_CHECK_STATUS;

		mc->size += sizeof(struct dnet_meta_check_status) + sizeof(struct dnet_meta);
	}

	c = (struct dnet_meta_check_status *)m->data;

	gettimeofday(&tv, NULL);

	c->tsec = tv.tv_sec;
	c->tnsec = tv.tv_usec * 1000;
	c->status = 0;

	dnet_convert_meta_check_status(c);
	dnet_convert_meta(m);

	memset(&io, 0, sizeof(io));
	io.flags = DNET_IO_FLAGS_META;

	memcpy(&io.id, mc->id.id, sizeof(io.id));

	err = db_put_data(n, ctl->cmd, &io, mc->data, mc->size);
	if (mc != morig)
		free(mc);

	return err;
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

static long long dnet_meta_get_ts(struct dnet_node *n, struct dnet_meta_container *mc)
{
	struct dnet_meta *m;
	struct dnet_meta_check_status *c;

	m = dnet_meta_search(n, mc->data, mc->size, DNET_META_CHECK_STATUS);
	if (!m)
		return -ENOENT;

	c = (struct dnet_meta_check_status *)m->data;
	dnet_convert_meta_check_status(c);

	return (long long)c->tsec;
}

static void *dnet_db_list_iter(void *data)
{
	struct dnet_db_list_control *ctl = data;
	struct dnet_node *n = ctl->n;
	int group_id = n->st->idc->group->group_id;
	struct dnet_meta_container *mc;
	struct dnet_net_state *tmp;
	int err = 0, check_copies;
	void *kbuf, *dbuf;
	unsigned char *key = NULL;
	size_t ksize, dsize;
	int send_check_reply = 1, will_check;
	int only_merge = !!(ctl->req->flags & DNET_CHECK_MERGE);
	struct dnet_id *ids = (struct dnet_id *)(ctl->req + 1);
	char time_buf[64], ctl_time[64];
	struct tm tm;
	size_t buf_size = 1024*1024;
	long long ts, edge = ctl->req->timestamp;
	void *buf;
	int check_copies_from_request = (ctl->req->flags & DNET_CHECK_FULL) ? DNET_CHECK_COPIES_FULL : DNET_CHECK_COPIES_HISTORY;
	int dry_run = !!(ctl->req->flags & DNET_CHECK_DRY_RUN);

	dnet_set_name("iterator");

	if (edge) {
		localtime_r((time_t *)&edge, &tm);
		strftime(ctl_time, sizeof(ctl_time), "%F %R:%S %Z", &tm);
	} else {
		snprintf(ctl_time, sizeof(ctl_time), "all records");
	}

	buf = malloc(buf_size);
	if (!buf) {
		err = -ENOMEM;
		dnet_log(n, DNET_LOG_ERROR, "Failed to allocate temporal buffer for cursor data.\n");
		goto out_exit;
	}

	mc = buf;

	while (!ctl->need_exit) {
		pthread_mutex_lock(&ctl->lock);
		if (ctl->req->obj_num) {
			kbuf = NULL;

			if (ctl->obj_pos < ctl->req->obj_num) {
				struct dnet_id *id = &ids[ctl->obj_pos];

				dnet_convert_id(id);
				err = dnet_db_read_raw(n, 1, id->id, &dbuf);
				if (err < 0) {
					dnet_log(n, DNET_LOG_ERROR, "%s: there is no object on given node.\n", dnet_dump_id_str(id->id));
					dbuf = NULL;
				} else {
					dsize = err;
				}

				kbuf = dbuf;
				key = id->id;
				ctl->obj_pos++;
			} else {
				ctl->need_exit = 1;
			}
		} else {
			kbuf = kccurget(ctl->cursor, &ksize, (const char **)&dbuf, &dsize, 1);
			if (!kbuf) {
				dnet_log(n, DNET_LOG_ERROR, "cursor reading returned no data.\n");
				ctl->need_exit = 1;
			}
			key = kbuf;
		}
		pthread_mutex_unlock(&ctl->lock);

		if (ctl->need_exit)
			goto err_out_kcfree;

		/*
		 * Happens when we loop over list of ids received from client, i.e. not from cursor,
		 * and given ID does not exist on the node check runs on.
		 */
		if (!kbuf) {
			err = -ENOENT;
			goto err_out_kcfree;
		}

		if (sizeof(struct dnet_meta_container) + dsize > buf_size) {
			dnet_log(n, DNET_LOG_ERROR, "%s: cursor returned too big data chunk: data_size: %zu, max_size: %zu.\n",
					dnet_dump_id_str(key), sizeof(struct dnet_meta_container) + dsize, buf_size);
			err = -EINVAL;
			goto err_out_kcfree;
		}

		memset(mc, 0, sizeof(struct dnet_meta_container));

		dnet_setup_id(&mc->id, group_id, key);
		mc->size = dsize;
		memcpy(mc->data, dbuf, mc->size);

		tmp = dnet_state_get_first(n, &mc->id);

		/*
		 * Use group ID field to specify whether we should check number of copies
		 * or merge transaction with other history log in the storage
		 */
		check_copies = !!(tmp == n->st);
#if 0
		if (mc->id.id[0] == 0x90 && mc->id.id[1] == 0x77 && mc->id.id[2] == 0x4f) {
			char key_str[DNET_ID_SIZE*2+1];
			dnet_log_raw(n, DNET_LOG_INFO, "check key: %s, dst: %s, check_copies: %d, size: %u, err: %d.\n",
				dnet_dump_id_len_raw(mc->id.id, DNET_ID_SIZE, key_str),
				tmp ? dnet_state_dump_addr(tmp) : "NULL",
				check_copies, mc->size, err);
		}
#endif

		dnet_state_put(tmp);

		ts = dnet_meta_get_ts(n, mc);
		will_check = !(edge && (ts > edge)) && (!check_copies || !only_merge);

		if (n->log->log_mask & DNET_LOG_NOTICE) {
			localtime_r((time_t *)&ts, &tm);
			strftime(time_buf, sizeof(time_buf), "%F %R:%S %Z", &tm);

			dnet_log_raw(n, DNET_LOG_NOTICE, "start key: %s, timestamp: %lld [%s], check before: %lld [%s], will check: %d, check_copies: %d, only_merge: %d, dry: %d, size: %u.\n",
				dnet_dump_id(&mc->id), ts, time_buf, edge, ctl_time, will_check, check_copies, only_merge, dry_run, mc->size);
		}

		if (will_check) {
			if (check_copies)
				check_copies = check_copies_from_request;

			if (!dry_run) {
				err = dnet_check(n, mc, check_copies);
				if (err >= 0)
					err = dnet_db_check_update(n, ctl, mc);
			}

			dnet_log_raw(n, DNET_LOG_NOTICE, "complete key: %s, timestamp: %lld [%s], check_copies: %d, only_merge: %d, dry: %d, size: %u, err: %d.\n",
				dnet_dump_id(&mc->id), ts, time_buf, check_copies, only_merge, dry_run, mc->size, err);

			atomic_inc(&ctl->completed);
		}

err_out_kcfree:
		atomic_inc(&ctl->total);
		if (err < 0)
			atomic_inc(&ctl->errors);

		kcfree(kbuf);

		if ((atomic_read(&ctl->total) % 30000) == 0) {
			if (send_check_reply) {
				if (dnet_db_send_check_reply(ctl))
					send_check_reply = 0;
			}

			dnet_log(n, DNET_LOG_INFO, "check: total: %d, completed: %d, errors: %d\n",
					atomic_read(&ctl->total), atomic_read(&ctl->completed), atomic_read(&ctl->errors));
		}
#if 0
		if (err)
			break;
#endif
	}

	free(buf);

out_exit:
	if (err)
		ctl->need_exit = err;

	dnet_log(n, DNET_LOG_INFO, "Exited iteration loop, err: %d, need_exit: %d.\n", err, ctl->need_exit);

	return NULL;
}

int dnet_db_list(struct dnet_net_state *st, struct dnet_cmd *cmd, struct dnet_attr *attr)
{
	struct dnet_node *n = st->n;
	struct dnet_db_list_control ctl;
	struct dnet_check_request *r;
	unsigned int i;
	int err;
	pthread_t *tid;
	char ctl_time[64];
	struct tm tm;

	if (n->check_in_progress)
		return -EINPROGRESS;

	if (attr->size < sizeof(struct dnet_check_request)) {
		dnet_log(n, DNET_LOG_ERROR, "%s: check: invalid check request size %llu, must be %zu\n",
				dnet_dump_id(&cmd->id),	(unsigned long long)attr->size, sizeof(struct dnet_check_request));
		return -EINVAL;
	}

	r = (struct dnet_check_request *)(attr + 1);
	dnet_convert_check_request(r);

	if (!r->thread_num)
		r->thread_num = 50;

	/* Racy, but we do not care much */
	n->check_in_progress = 1;

	memset(&ctl, 0, sizeof(struct dnet_db_list_control));

	atomic_init(&ctl.completed, 0);
	atomic_init(&ctl.errors, 0);
	atomic_init(&ctl.total, 0);

	ctl.n = n;
	ctl.st = st;
	ctl.cmd = cmd;
	ctl.attr = attr;
	ctl.req = r;

	tid = malloc(sizeof(pthread_t) * r->thread_num);
	if (!tid) {
		err = -ENOMEM;
		goto err_out_exit;
	}

	ctl.cursor = kcdbcursor(n->meta);
	if (!ctl.cursor) {
		err = -kcdbecode(n->meta);
		dnet_log_raw(n, DNET_LOG_ERROR, "%s: failed to open list cursor, err: %d: %s.\n",
				dnet_dump_id(&cmd->id), err, kcecodename(-err));
		goto err_out_free;
	}
	kccurjump(ctl.cursor);

	err = pthread_mutex_init(&ctl.lock, NULL);
	if (err)
		goto err_out_close_cursor;

	for (i=0; i<r->thread_num; ++i) {
		err = pthread_create(&tid[i], NULL, dnet_db_list_iter, &ctl);
		if (err) {
			dnet_log_err(n, "can not create %d'th check thread out of %d", i, r->thread_num);
			r->thread_num = i;
			ctl.need_exit = 1;
			goto err_out_join;
		}
	}

	if (r->timestamp) {
		localtime_r((time_t *)&r->timestamp, &tm);
		strftime(ctl_time, sizeof(ctl_time), "%F %R:%S %Z", &tm);
	} else {
		snprintf(ctl_time, sizeof(ctl_time), "all records");
	}

	dnet_log(n, DNET_LOG_INFO, "Started %u checking threads, recovering %llu transactions, which started before %s: merge: %d, full: %d, err: %d.\n",
			r->thread_num, (unsigned long long)r->obj_num, ctl_time,
			!!(r->flags & DNET_CHECK_MERGE), !!(r->flags & DNET_CHECK_FULL),
			err);

err_out_join:
	for (i=0; i<r->thread_num; ++i)
		pthread_join(tid[i], NULL);

	dnet_log(n, DNET_LOG_INFO, "Completed %d checking threads, err: %d.\n", r->thread_num, err);
	dnet_log(n, DNET_LOG_INFO, "checked: total: %d, completed: %d, errors: %d\n",
			atomic_read(&ctl.total), atomic_read(&ctl.completed), atomic_read(&ctl.errors));

	dnet_db_send_check_reply(&ctl);

	pthread_mutex_destroy(&ctl.lock);
err_out_close_cursor:
	kccurdel(ctl.cursor);
err_out_free:
	free(tid);
err_out_exit:
	n->check_in_progress = 0;
	return err;
}

static KCDB *db_backend_open(struct dnet_node *n, char *dbfile)
{
	int err, ret;
	KCDB *db;

	db = kcdbnew();
	if (!db)
		goto err_out_exit;

	ret = kcdbopen(db, dbfile, KCOWRITER | KCOCREATE | KCOAUTOTRAN);
	if (!ret) {
		err = -kcdbecode(db);
		dnet_log_raw(n, DNET_LOG_ERROR, "Failed to open '%s' database, err: %d %s\n", dbfile, err, kcecodename(-err));
		goto err_out_close;
	}

	return db;

err_out_close:
	kcdbdel(db);
err_out_exit:
	return NULL;
}

int dnet_db_init(struct dnet_node *n, struct dnet_config *cfg)
{
	int err = -EINVAL;
	/* 32 has to be enough for meta/history dbname + .kch suffix, 128 - for tune params*/
	char path[strlen(cfg->history_env) + 32 + 128];

	if (!cfg->db_buckets)
		cfg->db_buckets = 10 * 1024 * 1024;
	if (!cfg->db_map)
		cfg->db_map = 10 * 1024 * 1024;

	snprintf(path, sizeof(path), "%s/%s.kch#bnum=%llu#msiz=%llu", cfg->history_env, "history", cfg->db_buckets, cfg->db_map);
	n->history = db_backend_open(n, path);
	if (!n->history)
		goto err_out_exit;

	snprintf(path, sizeof(path), "%s/%s.kch#bnum=%llu#msiz=%llu", cfg->history_env, "meta", cfg->db_buckets, cfg->db_map);
	n->meta = db_backend_open(n, path);
	if (!n->meta)
		goto err_out_close_history;

	return 0;

err_out_close_history:
	kcdbdel(n->history);
err_out_exit:
	return err;
}

void dnet_db_cleanup(struct dnet_node *n)
{
	if (n->history)
		kcdbdel(n->history);

	if (n->meta)
		kcdbdel(n->meta);
}
