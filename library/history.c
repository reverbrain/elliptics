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
#include "elliptics/interface.h"

static int bdb_get_record_size(struct dnet_node *n, DB *db, DB_TXN *txn, unsigned char *id, unsigned int *size, int rmw)
{
	DBT key, data;
	int err;
	uint32_t flags = 0;
	DBC *cursor;

	if (rmw)
		flags = DB_RMW;

	memset(&key, 0, sizeof(DBT));
	memset(&data, 0, sizeof(DBT));

	key.data = id;
	key.size = DNET_ID_SIZE;

	err = db->cursor(db, txn, &cursor, DB_READ_UNCOMMITTED);
	if (err) {
		dnet_log_raw(n, DNET_LOG_ERROR, "%s: failed to open list cursor, err: %d: %s.\n",
				dnet_dump_id_str(id), err, db_strerror(err));
		goto err_out_exit;
	}

	err = cursor->c_get(cursor, &key, &data, DB_SET | DB_RMW);
	if (err) {
		if (err == DB_NOTFOUND) {
			err = 0;
			*size = 0;
		} else {
			dnet_log_raw(n, DNET_LOG_ERROR, "%s: failed to get record size, err: %d: %s.\n",
				dnet_dump_id_str(id), err, db_strerror(err));
		}
		goto err_out_close_cursor;
	}

	dnet_log_raw(n, DNET_LOG_DSA, "%s: bdb record size read: data size: %u, dlen: %u.\n",
			dnet_dump_id_str(id), data.size, data.dlen);

	*size = data.size;

	err = cursor->c_close(cursor);
	if (err) {
		dnet_log_raw(n, DNET_LOG_ERROR, "%s: failed to close list cursor: err: %d: %s.\n",
				dnet_dump_id_str(id), err, db_strerror(err));
		goto err_out_exit;
	}

	return 0;

err_out_close_cursor:
	cursor->c_close(cursor);
err_out_exit:
	return err;
}

int dnet_db_read_raw(struct dnet_node *n, int meta, unsigned char *id, void **datap)
{
	int err;
	DBT key, data;
	unsigned int size;
	DB *db = n->history;

	if (meta)
		db = n->meta;

	memset(&key, 0, sizeof(DBT));
	memset(&data, 0, sizeof(DBT));

	key.data = id;
	key.size = key.dlen = key.ulen = DNET_ID_SIZE;
	key.flags = DB_DBT_USERMEM;

	data.size = data.dlen = 0;
	data.flags = DB_DBT_MALLOC;
	data.doff = 0;

	err = db->get(db, NULL, &key, &data, 0);
	if (err) {
		dnet_log_raw(n, DNET_LOG_ERROR, "%s: allocated read failed "
			"err: %d: %s.\n", dnet_dump_id_str(id),
			err, db_strerror(err));
		goto err_out_exit;
	}

	size = data.size;
	*datap = data.data;

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
	free(data);

	return err;
}

static int bdb_put_data_raw(DB *db, DB_TXN *txn,
		void *kdata, unsigned int ksize,
		void *vdata, unsigned int offset, unsigned int size,
		int partial)
{
	DBT key, data;

	memset(&key, 0, sizeof(DBT));
	memset(&data, 0, sizeof(DBT));

	key.data = kdata;
	key.size = ksize;

	data.doff = offset;
	data.ulen = data.size = data.dlen = size;
	data.flags = DB_DBT_USERMEM;
	data.data = vdata;

	if (partial)
		data.flags |= DB_DBT_PARTIAL;
	
	return db->put(db, txn, &key, &data, 0);
}

static int bdb_put_data(struct dnet_node *n, struct dnet_cmd *cmd, struct dnet_io_attr *io, void *data, unsigned int size)
{
	int err;
	DB_TXN *txn;
	DB *db = n->history;
	char *dbf = "history";
	unsigned int offset = 0;

retry:
	txn = NULL;
	err = n->env->txn_begin(n->env, NULL, &txn, 0);
	if (err) {
		dnet_log_raw(n, DNET_LOG_ERROR, "%s: failed to start a write transaction, err: %d: %s.\n",
				dnet_dump_id(&cmd->id), err, db_strerror(err));
		goto err_out_exit;
	}

	if (io->flags & DNET_IO_FLAGS_META) {
		db = n->meta;
		dbf = "meta";
	} else if ((io->flags & DNET_IO_FLAGS_APPEND) || !(io->flags & DNET_IO_FLAGS_NO_HISTORY_UPDATE)) {
		err = bdb_get_record_size(n, db, txn, io->id, &offset, 1);
		if (err) {
			if (err == DB_LOCK_DEADLOCK || err == DB_LOCK_NOTGRANTED)
				goto err_out_txn_abort_continue;
			goto err_out_close_txn;
		}
	}

	err = bdb_put_data_raw(db, txn, io->id, DNET_ID_SIZE, data, offset, size, offset != 0);
	if (err) {
		dnet_log_raw(n, DNET_LOG_ERROR,	"%s: %s object put failed: offset: %llu, size: %llu, err: %d: %s.\n",
			dnet_dump_id(&cmd->id), dbf, (unsigned long long)io->offset,
			(unsigned long long)io->size, err, db_strerror(err));
		if (err == DB_LOCK_DEADLOCK || err == DB_LOCK_NOTGRANTED)
			goto err_out_txn_abort_continue;

		goto err_out_close_txn;
	}

	dnet_log_raw(n, DNET_LOG_NOTICE, "%s: stored %s object: io_size: %llu, io_offset: %llu, update_size: %u, update_offset: %u.\n",
			dnet_dump_id(&cmd->id), dbf, (unsigned long long)io->size, (unsigned long long)io->offset,
			size, offset);

	err = txn->commit(txn, 0);
	if (err) {
		dnet_log_raw(n, DNET_LOG_ERROR, "%s: failed to commit a write transaction: %d: %s.\n",
				dnet_dump_id(&cmd->id), err, db_strerror(err));
		if (err == DB_LOCK_DEADLOCK || err == DB_LOCK_NOTGRANTED)
			goto err_out_txn_abort_continue;

		goto err_out_exit;
	}

	return 0;

err_out_txn_abort_continue:
	txn->abort(txn);
	goto retry;

err_out_close_txn:
	txn->abort(txn);
err_out_exit:
	return err;
}

int dnet_db_write(struct dnet_node *n, struct dnet_cmd *cmd, void *data)
{
	struct dnet_io_attr *io = data;
	struct dnet_history_entry e;

	if ((io->flags & DNET_IO_FLAGS_HISTORY) || (io->flags & DNET_IO_FLAGS_META))
		return bdb_put_data(n, cmd, io, io + 1, io->size);

	if (io->flags & DNET_IO_FLAGS_NO_HISTORY_UPDATE)
		return 0;

	dnet_setup_history_entry(&e, io->parent, io->size, io->offset, NULL, io->flags);
	return bdb_put_data(n, cmd, io, &e, sizeof(struct dnet_history_entry));
}

static int bdb_del_direct(struct dnet_node *n, struct dnet_cmd *cmd)
{
	int err;
	DBT key, data;
	DB_TXN *txn;

retry:
	txn = NULL;
	err = n->env->txn_begin(n->env, NULL, &txn, 0);
	if (err) {
		dnet_log_raw(n, DNET_LOG_ERROR, "%s: failed to start a deletion transaction, err: %d: %s.\n",
				dnet_dump_id(&cmd->id), err, db_strerror(err));
		goto err_out_exit;
	}

	memset(&key, 0, sizeof(DBT));
	memset(&data, 0, sizeof(DBT));

	key.data = cmd->id.id;
	key.size = DNET_ID_SIZE;

	err = n->history->del(n->history, txn, &key, 0);
	if (err) {
		dnet_log_raw(n, DNET_LOG_ERROR, "%s: history object removal failed, err: %d: %s.\n",
			dnet_dump_id(&cmd->id), err, db_strerror(err));
		if (err == DB_LOCK_DEADLOCK || err == DB_LOCK_NOTGRANTED)
			goto err_out_txn_abort_continue;
	}

	err = n->meta->del(n->meta, txn, &key, 0);
	if (err) {
		dnet_log_raw(n, DNET_LOG_ERROR, "%s: meta object removal failed, err: %d: %s.\n",
			dnet_dump_id(&cmd->id), err, db_strerror(err));
		if (err == DB_LOCK_DEADLOCK || err == DB_LOCK_NOTGRANTED)
			goto err_out_txn_abort_continue;
	}

	err = txn->commit(txn, 0);
	if (err) {
		dnet_log_raw(n, DNET_LOG_ERROR, "%s: failed to commit a deletion transaction: %d: %s.\n",
				dnet_dump_id(&cmd->id), err, db_strerror(err));
		if (err == DB_LOCK_DEADLOCK || err == DB_LOCK_NOTGRANTED)
			goto err_out_txn_abort_continue;

		goto err_out_exit;
	}

	return 0;

err_out_txn_abort_continue:
	txn->abort(txn);
	goto retry;

err_out_exit:
	return err;
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
	int err = -EINVAL;
	int ret = 0;
	DBT key, data;
	void *e = NULL;
	DB_TXN *txn;
	unsigned int num;

	if (attr->flags & DNET_ATTR_DIRECT_TRANSACTION) {
		bdb_del_direct(n, cmd);
		return 1;
	}

retry:
	txn = NULL;
	err = n->env->txn_begin(n->env, NULL, &txn, 0);
	if (err) {
		dnet_log_raw(n, DNET_LOG_ERROR, "%s: failed to start a deletion transaction, err: %d: %s.\n",
				dnet_dump_id(&cmd->id), err, db_strerror(err));
		goto err_out_exit;
	}

	memset(&key, 0, sizeof(DBT));
	memset(&data, 0, sizeof(DBT));

	key.data = cmd->id.id;
	key.ulen = key.size = DNET_ID_SIZE;
	key.flags = DB_DBT_USERMEM;

	data.flags = DB_DBT_MALLOC;

	err = n->history->get(n->history, txn, &key, &data, DB_RMW);
	if (err) {
		dnet_log_raw(n, DNET_LOG_ERROR, "%s: failed to read history of to be deleted object, err: %d: %s.\n",
			dnet_dump_id(&cmd->id), err, db_strerror(err));
		if (err == DB_LOCK_DEADLOCK || err == DB_LOCK_NOTGRANTED)
			goto err_out_txn_abort_continue;

		goto err_out_close_txn;
	}

	e = data.data;

	if (data.size % sizeof(struct dnet_history_entry)) {
		err = -EINVAL;
		dnet_log_raw(n, DNET_LOG_ERROR, "%s: corrupted history of to be deleted object.\n",
			dnet_dump_id(&cmd->id));
		goto err_out_free;
	}

	num = data.size / sizeof(struct dnet_history_entry);
	data.size -= sizeof(struct dnet_history_entry);

	err = dnet_history_del_entry(n, &cmd->id, data.data, num);
	if (err)
		goto err_out_free;

	if (data.size) {
		err = bdb_put_data_raw(n->history, txn, key.data, DNET_ID_SIZE, data.data, 0, data.size, 0);
		if (err) {
			dnet_log_raw(n, DNET_LOG_ERROR, "%s: object put updated history object after "
				"transaction removal, err: %d: %s.\n",
				dnet_dump_id(&cmd->id), err, db_strerror(err));
			if (err == DB_LOCK_DEADLOCK || err == DB_LOCK_NOTGRANTED)
				goto err_out_txn_abort_continue;

			goto err_out_free;
		}
	} else {
		err = n->history->del(n->history, txn, &key, 0);
		if (err) {
			dnet_log_raw(n, DNET_LOG_ERROR, "%s: history object removal failed, err: %d: %s.\n",
				dnet_dump_id(&cmd->id), err, db_strerror(err));
			if (err == DB_LOCK_DEADLOCK || err == DB_LOCK_NOTGRANTED)
				goto err_out_txn_abort_continue;
		}

		err = n->meta->del(n->meta, txn, &key, 0);
		if (err) {
			dnet_log_raw(n, DNET_LOG_ERROR, "%s: meta object removal failed, err: %d: %s.\n",
				dnet_dump_id(&cmd->id), err, db_strerror(err));
			if (err == DB_LOCK_DEADLOCK || err == DB_LOCK_NOTGRANTED)
				goto err_out_txn_abort_continue;
		}

		ret = 1;
	}

	dnet_log_raw(n, DNET_LOG_NOTICE, "%s: updated history of to be removed object: should be deleted: %d.\n",
		dnet_dump_id(&cmd->id), ret);

	free(e);

	err = txn->commit(txn, 0);
	if (err) {
		dnet_log_raw(n, DNET_LOG_ERROR,
			"%s: failed to commit a deletion transaction: %d: %s.\n",
				dnet_dump_id(&cmd->id), err, db_strerror(err));
		if (err == DB_LOCK_DEADLOCK || err == DB_LOCK_NOTGRANTED)
			goto err_out_txn_abort_continue;

		goto err_out_exit;
	}

	return ret;

err_out_txn_abort_continue:
	txn->abort(txn);
	free(e);
	goto retry;

err_out_free:
	free(e);
err_out_close_txn:
	txn->abort(txn);
err_out_exit:
	return err;
}

int dnet_db_list(struct dnet_net_state *st, struct dnet_cmd *cmd, struct dnet_attr *attr __unused)
{
	struct dnet_node *n = st->n;
	struct dnet_net_state *tmp;
	struct dnet_meta_container mc;
	unsigned long long size = 0;
	struct dnet_id id;
	DBT key, dbdata;
	DB_TXN *txn = NULL;
	DB *db = n->meta;
	DBC *cursor;
	int err, fd;
	char file[256];

	snprintf(file, sizeof(file), "/%s/check.%d", n->check_dir, getpid());
	fd = open(file, O_RDWR | O_TRUNC | O_CREAT | O_APPEND, 0644);
	if (fd < 0) {
		err = -errno;
		dnet_log_err(n, "failed to open/create temporary check file");
		goto err_out_exit;
	}

	memset(&key, 0, sizeof(DBT));
	memset(&dbdata, 0, sizeof(DBT));

	memset(&id, 0, sizeof(struct dnet_id));

	key.data = id.id;
	key.size = DNET_ID_SIZE;

	err = db->cursor(db, txn, &cursor, DB_READ_UNCOMMITTED);
	if (err) {
		dnet_log_raw(n, DNET_LOG_ERROR, "%s: failed to open list cursor, err: %d: %s.\n",
				dnet_dump_id(&cmd->id), err, db_strerror(err));
		goto err_out_close_txn;
	}

	while ((err = cursor->c_get(cursor, &key, &dbdata, DB_NEXT)) == 0) {
		dnet_setup_id(&mc.id, cmd->id.group_id, key.data);

		tmp = dnet_state_search(n, &mc.id);

		/*
		 * Use group ID field to specify whether we should check number of copies
		 * or merge transaction with other history log in the storage
		 */
		mc.id.group_id = !!(tmp == n->st);

		dnet_state_put(tmp);

		dnet_log_raw(n, DNET_LOG_DSA, "key: %s, check_copies: %d, size: %u.\n",
				dnet_dump_id_str(key.data), mc.id.group_id, dbdata.size);

		mc.size = dbdata.size;

		err = write(fd, &mc, sizeof(struct dnet_meta_container));
		if (err != sizeof(struct dnet_meta_container)) {
			err = -errno;
			dnet_log_err(n, "failed to write ID entry (meta container) to be checked");
			goto err_out_close_cursor;
		}

		err = write(fd, dbdata.data, mc.size);
		if (err != (signed)mc.size) {
			err = -errno;
			dnet_log_err(n, "failed to write ID entry (metadata) to be checked");
			goto err_out_close_cursor;
		}

		size += sizeof(struct dnet_meta_container) + mc.size;
	}

	err = cursor->c_close(cursor);
	if (err) {
		dnet_log_raw(n, DNET_LOG_ERROR,
			"%s: failed to close list cursor: err: %d: %s.\n",
				dnet_dump_id(&cmd->id), err, db_strerror(err));
		goto err_out_close_txn;
	}

	close(fd);

	return dnet_check(n, file, size);

err_out_close_cursor:
	cursor->c_close(cursor);
err_out_close_txn:
	txn->abort(txn);
	close(fd);
err_out_exit:
	return err;
}

static void bdb_backend_error_handler(const DB_ENV *env, const char *prefix, const char *msg)
{
	struct dnet_node *n = env->app_private;
	dnet_log(n, DNET_LOG_ERROR, "%s: %s.\n", prefix, msg);
}

static int bdb_compare(DB *db __unused, const DBT *key1, const DBT *key2)
{
	return dnet_id_cmp_str(key1->data, key2->data);
}

static DB *bdb_backend_open(struct dnet_node *n, char *dbfile)
{
	int err;
	DB *db;

	err = db_create(&db, n->env, 0);
	if (err) {
		dnet_log_raw(n, DNET_LOG_ERROR, "Failed to create new database instance, err: %d.\n", err);
		goto err_out_exit;
	}

	db->set_bt_compare(db, bdb_compare);
	db->set_errcall(db, bdb_backend_error_handler);
	db->set_errpfx(db, "bdb");

	err = db->open(db, NULL, dbfile, NULL, DB_BTREE, DB_CREATE | DB_AUTO_COMMIT |
			DB_THREAD | DB_READ_UNCOMMITTED, 0);
	if (err) {
		dnet_log_raw(n, DNET_LOG_ERROR, "Failed to open '%s' database, err: %d %s\n", dbfile, err, db_strerror(err));
		goto err_out_close;
	}

	return db;

err_out_close:
	db->close(db, 0);
err_out_exit:
	return NULL;
}

int dnet_db_checkpoint(struct dnet_node *n)
{
	int err;

	if (!n->env)
		return -1;

	err = n->env->txn_checkpoint(n->env, 0, 0, 0);
	if (err) {
		n->env->err(n->env, err, "checkpoint thread");
		exit(err);
        }

	return 0;
}

int dnet_db_init(struct dnet_node *n, char *env_dir)
{
	int err;
	DB_ENV *env;

	err = db_env_create(&env, 0);
	if (err) {
		dnet_log_raw(n, DNET_LOG_ERROR, "Failed to create new environment instance, err: %d.\n", err);
		goto err_out_exit;
	}
	env->app_private = n;

	env->log_set_config(env, DB_LOG_ZERO | DB_LOG_AUTO_REMOVE | DB_LOG_IN_MEMORY, 1);
	/*
	 * We do not need durable transaction, so we do not
	 * want disk IO at transaction commit.
	 * It shuold have no effect because of the in-memory logging though.
	 */
	env->set_flags(env, DB_TXN_NOSYNC, 1);

	err = env->set_lg_bsize(env, 5 * DNET_MAX_TRANS_SIZE);
	if (err != 0) {
		dnet_log_raw(n, DNET_LOG_ERROR, "Failed to set log buffer size: %s\n", db_strerror(err));
		goto err_out_destroy_env;
	}

	err = env->set_lk_detect(env, DB_LOCK_MINWRITE);
	if (err) {
		dnet_log_raw(n, DNET_LOG_ERROR, "Failed to set minimum write deadlock break method: %s.\n",
				db_strerror(err));
		goto err_out_destroy_env;
	}

	/*
	 * Set lock timeout in microseconds.
	 * It should fire on deadlocks observed with DB_RMW flag,
	 * but also will signal about too long transactions.
	 *
	 * After it fires (put()/get() returns DB_LOCK_DEADLOCK or DB_LOCK_NOTGRANTED),
	 * transaction is being destroyed and command restarted.
	 */
	err = env->set_timeout(env, 10000, DB_SET_TXN_TIMEOUT);
	if (err) {
		dnet_log_raw(n, DNET_LOG_ERROR, "Failed to set transaction lock timeout: %s.\n", db_strerror(err));
		goto err_out_destroy_env;
	}

	err = env->open(env, env_dir, DB_CREATE | DB_INIT_MPOOL |
			DB_INIT_TXN | DB_INIT_LOCK | DB_INIT_LOG | DB_THREAD, 0);
	if (err) {
		dnet_log_raw(n, DNET_LOG_ERROR, "Failed to open '%s' environment instance, err: %d %s.\n",
				env_dir, err, db_strerror(err));
		goto err_out_destroy_env;
	}

	n->env = env;

	err = -EINVAL;
	n->history = bdb_backend_open(n, "history");
	if (!n->history)
		goto err_out_close_env;

	n->meta = bdb_backend_open(n, "meta");
	if (!n->meta)
		goto err_out_close_history;

	n->check_dir = strdup(env_dir);
	if (!n->check_dir) {
		err = -ENOMEM;
		goto err_out_close_meta;
	}

	return 0;

err_out_close_meta:
	n->meta->close(n->meta, 0);
	n->meta = NULL;
err_out_close_history:
	n->history->close(n->history, 0);
	n->history = NULL;
err_out_close_env:
	env->close(env, 0);
	n->env = NULL;
err_out_destroy_env:
err_out_exit:
	return err;
}

void dnet_db_cleanup(struct dnet_node *n)
{
	if (n->history)
		n->history->close(n->history, 0);

	if (n->meta)
		n->meta->close(n->meta, 0);

	if (n->env)
		n->env->close(n->env, 0);

	free(n->check_dir);
}
