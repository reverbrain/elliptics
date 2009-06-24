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

#ifndef __unused
#define __unused	__attribute__ ((unused))
#endif

#include "dnet/packet.h"
#include "dnet/interface.h"

#include "backends.h"

#ifdef HAVE_BDB_SUPPORT
#include <db.h>

static void bdb_backend_error_handler(const DB_ENV *env __unused, const char *prefix, const char *msg)
{
	fprintf(stderr, "%s: %s.\n", prefix, msg);
}

struct bdb_entry
{
	DB			*db;
};

struct bdb_backend
{
	char			*env_dir;
	DB_ENV			*env;
	struct bdb_entry	*data, *hist;
};

static int bdb_get_record_size(void *state, struct bdb_entry *ent, DB_TXN *txn,
		unsigned char *id, unsigned int *size, int rmw)
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

	err = ent->db->cursor(ent->db, txn, &cursor, DB_READ_UNCOMMITTED);
	if (err) {
		dnet_command_handler_log(state, DNET_LOG_ERROR,
			"%s: failed to open list cursor, err: %d: %s.\n",
				dnet_dump_id(id), err, db_strerror(err));
		goto err_out_exit;
	}

	err = cursor->c_get(cursor, &key, &data, DB_SET | DB_RMW);
	if (err) {
		if (err == DB_NOTFOUND) {
			err = 0;
			*size = 0;
		} else {
			dnet_command_handler_log(state, DNET_LOG_ERROR,
					"%s: failed to get record size, err: %d: %s.\n",
				dnet_dump_id(id), err, db_strerror(err));
		}
		goto err_out_close_cursor;
	}

	dnet_command_handler_log(state, DNET_LOG_NOTICE, "%s: data size: %u, dlen: %u.\n",
				dnet_dump_id(id), data.size, data.dlen);

	*size = data.size;

	err = cursor->c_close(cursor);
	if (err) {
		dnet_command_handler_log(state, DNET_LOG_ERROR,
			"%s: failed to close list cursor: err: %d: %s.\n",
				dnet_dump_id(id), err, db_strerror(err));
		goto err_out_exit;
	}

	return 0;

err_out_close_cursor:
	cursor->c_close(cursor);
err_out_exit:
	return err;
}

static int bdb_get_data(void *state, struct bdb_backend *be, struct dnet_cmd *cmd,
		struct dnet_attr *attr, void *buf)
{
	int err;
	DBT key, data;
	struct bdb_entry *e = be->data;
	struct dnet_io_attr *io = buf;
	unsigned int size;
	DB_TXN *txn;

	if (attr->size < sizeof(struct dnet_io_attr)) {
		dnet_command_handler_log(state, DNET_LOG_ERROR,
			"%s: wrong read attribute, size does not match "
				"IO attribute size: size: %llu, must be: %zu.\n",
				dnet_dump_id(cmd->id), (unsigned long long)attr->size,
				sizeof(struct dnet_io_attr));
		err = -EINVAL;
		goto err_out_exit;
	}

	buf += sizeof(struct dnet_io_attr);

	dnet_convert_io_attr(io);

	if (io->flags & DNET_IO_FLAGS_HISTORY)
		e = be->hist;

retry:
	txn = NULL;
	err = be->env->txn_begin(be->env, NULL, &txn, DB_READ_UNCOMMITTED);
	if (err) {
		dnet_command_handler_log(state, DNET_LOG_ERROR,
			"%s: failed to start a read transaction, err: %d: %s.\n",
				dnet_dump_id(cmd->id), err, db_strerror(err));
		goto err_out_exit;
	}

	err = bdb_get_record_size(state, e, txn, io->origin, &size, 0);
	if (err) {
		if (err == DB_LOCK_DEADLOCK || err == DB_LOCK_NOTGRANTED)
			goto err_out_txn_abort_continue;
		goto err_out_close_txn;
	}

	/*
	 * Do not process empty records, pretend we do not have it.
	 */
	if (!err && !size) {
		err = -ENOENT;
		goto err_out_close_txn;
	}

	size = dnet_backend_check_get_size(io, size);
	if (!size) {
		err = 0;
		goto err_out_close_txn;
	}

	if (attr->size == sizeof(struct dnet_io_attr)) {
		struct dnet_data_req *r;
		struct dnet_cmd *c;
		struct dnet_attr *a;
		struct dnet_io_attr *rio;

		memset(&key, 0, sizeof(DBT));
		memset(&data, 0, sizeof(DBT));

		key.data = io->origin;
		key.size = DNET_ID_SIZE;

		data.size = size;
		data.flags = DB_DBT_PARTIAL | DB_DBT_MALLOC;
		data.doff = io->offset;
		data.dlen = size;

		err = e->db->get(e->db, txn, &key, &data, 0);
		if (err) {
			dnet_command_handler_log(state, DNET_LOG_ERROR,
				"%s: allocated read failed offset: %u, "
				"size: %u, err: %d: %s.\n", dnet_dump_id(io->origin),
				(unsigned int)io->offset, size, err, db_strerror(err));
			if (err == DB_LOCK_DEADLOCK || err == DB_LOCK_NOTGRANTED)
				goto err_out_txn_abort_continue;
			goto err_out_close_txn;
		}

		r = dnet_req_alloc(state, sizeof(struct dnet_cmd) +
				sizeof(struct dnet_attr) + sizeof(struct dnet_io_attr));
		if (!r) {
			err = -ENOMEM;
			dnet_command_handler_log(state, DNET_LOG_ERROR,
				"%s: failed to allocate reply attributes.\n",
				dnet_dump_id(io->origin));
			goto err_out_close_txn;
		}

		dnet_req_set_data(r, data.data, size, 0, 1);

		c = dnet_req_header(r);
		a = (struct dnet_attr *)(c + 1);
		rio = (struct dnet_io_attr *)(a + 1);

		memcpy(c->id, io->origin, DNET_ID_SIZE);
		memcpy(rio->origin, io->origin, DNET_ID_SIZE);
	
		dnet_command_handler_log(state, DNET_LOG_NOTICE,
			"%s: read reply offset: %llu, size: %u.\n",
			dnet_dump_id(io->origin), (unsigned long long)io->offset, size);

		if (cmd->flags & DNET_FLAGS_NEED_ACK)
			c->flags = DNET_FLAGS_MORE;

		c->status = 0;
		c->size = sizeof(struct dnet_attr) + sizeof(struct dnet_io_attr) + size;
		c->trans = cmd->trans | DNET_TRANS_REPLY;

		a->cmd = DNET_CMD_READ;
		a->size = sizeof(struct dnet_io_attr) + size;
		a->flags = attr->flags;

		rio->size = size;
		rio->offset = io->offset;
		rio->flags = io->flags;

		dnet_convert_cmd(c);
		dnet_convert_attr(a);
		dnet_convert_io_attr(rio);

		err = dnet_data_ready(state, r);
		if (err)
			goto err_out_close_txn;
	} else {
		if (size > attr->size - sizeof(struct dnet_io_attr))
			size = attr->size - sizeof(struct dnet_io_attr);

		memset(&key, 0, sizeof(DBT));
		memset(&data, 0, sizeof(DBT));

		key.data = io->origin;
		key.size = DNET_ID_SIZE;

		data.data = buf;
		data.ulen = data.size = data.dlen = size;
		data.doff = io->offset;
		data.flags = DB_DBT_PARTIAL | DB_DBT_USERMEM;

		err = e->db->get(e->db, txn, &key, &data, 0);
		if (err) {
			dnet_command_handler_log(state, DNET_LOG_ERROR,
				"%s: umem read failed offset: %llu, "
				"size: %u, err: %d: %s.\n",
				dnet_dump_id(io->origin), (unsigned long long)io->offset,
				size, err, db_strerror(err));
			if (err == DB_LOCK_DEADLOCK || err == DB_LOCK_NOTGRANTED)
				goto err_out_txn_abort_continue;
			goto err_out_close_txn;
		}
		dnet_command_handler_log(state, DNET_LOG_NOTICE,
			"%s: umem read offset: %llu, size: %u.\n",
			dnet_dump_id(io->origin), (unsigned long long)io->offset, size);

		io->size = size;
		attr->size = sizeof(struct dnet_io_attr) + io->size;
	}

	err = txn->commit(txn, 0);
	if (err) {
		dnet_command_handler_log(state, DNET_LOG_ERROR,
			"%s: failed to commit a read transaction: err: %d: %s.\n",
				dnet_dump_id(cmd->id), err, db_strerror(err));
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

static int bdb_put_data_raw(struct bdb_entry *ent, DB_TXN *txn,
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
	
	return ent->db->put(ent->db, txn, &key, &data, 0);
}

static int bdb_put_data(void *state, struct bdb_backend *be, struct dnet_cmd *cmd,
		struct dnet_attr *attr, void *buf)
{
	int err;
	DBT key, data;
	struct bdb_entry *ent = be->data;
	struct dnet_io_attr *io = buf;
	struct dnet_history_entry e;
	unsigned int offset = 0;
	DB_TXN *txn;

	if (attr->size < sizeof(struct dnet_io_attr)) {
		dnet_command_handler_log(state, DNET_LOG_ERROR,
			"%s: wrong write attribute, size does not match "
				"IO attribute size: size: %llu, must be more than %zu.\n",
				dnet_dump_id(cmd->id), (unsigned long long)attr->size,
				sizeof(struct dnet_io_attr));
		err = -EINVAL;
		goto err_out_exit;
	}

	dnet_convert_io_attr(io);

	buf += sizeof(struct dnet_io_attr);

	if (io->flags & DNET_IO_FLAGS_HISTORY)
		ent = be->hist;

retry:
	txn = NULL;
	err = be->env->txn_begin(be->env, NULL, &txn, 0);
	if (err) {
		dnet_command_handler_log(state, DNET_LOG_ERROR,
				"%s: failed to start a write transaction, err: %d: %s.\n",
				dnet_dump_id(cmd->id), err, db_strerror(err));
		goto err_out_exit;
	}

	if (io->flags & DNET_IO_FLAGS_HISTORY) {
		ent = be->hist;

		if (io->size == sizeof(struct dnet_history_entry)) {
			struct dnet_history_entry *r = buf;

			memset(&key, 0, sizeof(DBT));
			memset(&data, 0, sizeof(DBT));

			key.data = io->origin;
			key.size = DNET_ID_SIZE;

			data.ulen = data.dlen = data.size = sizeof(struct dnet_history_entry);
			data.flags = DB_DBT_PARTIAL | DB_DBT_USERMEM;
			data.data = &e;

			err = ent->db->get(ent->db, txn, &key, &data, DB_RMW);
			if (err) {
				if (err != DB_NOTFOUND) {
					if (err == DB_LOCK_DEADLOCK || err == DB_LOCK_NOTGRANTED)
						goto err_out_txn_abort_continue;

					dnet_command_handler_log(state, DNET_LOG_ERROR,
							"%s: failed to get history metadata, err: %d: %s.\n",
						dnet_dump_id(io->origin), err, db_strerror(err));
					goto err_out_close_txn;
				}

				dnet_convert_history_entry(r);

				memcpy(e.id, r->id, DNET_ID_SIZE);
				e.flags = r->flags;
				e.size = r->size + r->offset;
				e.offset = 0;

				dnet_convert_history_entry(r);

				dnet_command_handler_log(state, DNET_LOG_NOTICE,
					"%s: creating history metadata, size: %llu.\n",
					dnet_dump_id(io->origin), (unsigned long long)e.size);

				dnet_convert_history_entry(&e);

				err = bdb_put_data_raw(ent, txn, io->origin, DNET_ID_SIZE,
					&e, 0, sizeof(struct dnet_history_entry), 0);
			} else {
				dnet_convert_history_entry(&e);
				dnet_convert_history_entry(r);

				dnet_command_handler_log(state, DNET_LOG_NOTICE,
					"%s: history metadata, stored_size: %llu, trans_size: %llu "
					"(size: %llu, offset: %llu).\n",
					dnet_dump_id(io->origin), (unsigned long long)e.size,
					(unsigned long long)(r->size + r->offset),
					(unsigned long long)r->size, (unsigned long long)r->offset);

				if (e.size < r->size + r->offset) {
					e.size = r->size + r->offset;

					dnet_convert_history_entry(&e);
					err = bdb_put_data_raw(ent, txn, io->origin, DNET_ID_SIZE,
						&e, 0, sizeof(struct dnet_history_entry), 1);
				}
				dnet_convert_history_entry(r);
			}
			if (err) {
				if (err == DB_LOCK_DEADLOCK || err == DB_LOCK_NOTGRANTED)
					goto err_out_txn_abort_continue;
				dnet_command_handler_log(state, DNET_LOG_ERROR,
						"%s: failed to update history metadata, err: %d: %s.\n",
					dnet_dump_id(io->origin), err, db_strerror(err));
				goto err_out_close_txn;
			}
		}
	}

	if (io->flags & DNET_IO_FLAGS_APPEND) {
		err = bdb_get_record_size(state, ent, txn, io->origin, &offset, 1);
		if (err) {
			if (err == DB_LOCK_DEADLOCK || err == DB_LOCK_NOTGRANTED)
				goto err_out_txn_abort_continue;
			goto err_out_close_txn;
		}
	}

	err = bdb_put_data_raw(ent, txn, io->origin, DNET_ID_SIZE,
			buf, offset, io->size, offset != 0);
	if (err) {
		dnet_command_handler_log(state, DNET_LOG_ERROR,
			"%s: object put failed: offset: %llu, "
			"size: %llu, err: %d: %s.\n",
			dnet_dump_id(io->origin), (unsigned long long)io->offset,
			(unsigned long long)io->size, err, db_strerror(err));
		if (err == DB_LOCK_DEADLOCK || err == DB_LOCK_NOTGRANTED)
			goto err_out_txn_abort_continue;

		goto err_out_close_txn;
	}

	dnet_command_handler_log(state, DNET_LOG_NOTICE,
		"%s: stored %s object: size: %llu, offset: %llu, update_offset: %u.\n",
			dnet_dump_id(io->origin),
			(io->flags & DNET_IO_FLAGS_HISTORY) ? "history" : "data",
			(unsigned long long)io->size, (unsigned long long)io->offset,
			offset);

	if (!(io->flags & DNET_IO_FLAGS_NO_HISTORY_UPDATE) && !(io->flags & DNET_IO_FLAGS_HISTORY)) {
		unsigned int size;

		ent = be->hist;

		err = bdb_get_record_size(state, ent, txn, io->origin, &size, 1);
		if (err) {
			if (err == DB_LOCK_DEADLOCK || err == DB_LOCK_NOTGRANTED)
				goto err_out_txn_abort_continue;
			goto err_out_close_txn;
		}

		dnet_setup_history_entry(&e, io->id, io->size, io->offset, 0);

		err = bdb_put_data_raw(ent, txn, io->origin, DNET_ID_SIZE,
				&e, size, sizeof(struct dnet_history_entry), 1);
		if (err) {
			dnet_command_handler_log(state, DNET_LOG_ERROR,
				"%s: history update failed offset: %llu, "
				"size: %llu, err: %d: %s.\n",
					dnet_dump_id(io->origin), (unsigned long long)io->offset,
					(unsigned long long)io->size, err, db_strerror(err));
			if (err == DB_LOCK_DEADLOCK || err == DB_LOCK_NOTGRANTED)
				goto err_out_txn_abort_continue;
			goto err_out_close_txn;
		}

		dnet_command_handler_log(state, DNET_LOG_NOTICE,
			"%s: history updated: size: %llu, offset: %llu.\n",
				dnet_dump_id(io->origin), (unsigned long long)io->size,
				(unsigned long long)io->offset);
	}

	err = txn->commit(txn, 0);
	if (err) {
		dnet_command_handler_log(state, DNET_LOG_ERROR,
			"%s: failed to commit a write transaction: %d: %s.\n",
				dnet_dump_id(cmd->id), err, db_strerror(err));
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

static int bdb_list(void *state, struct bdb_backend *be, struct dnet_cmd *cmd,
		struct dnet_attr *attr)
{
	int err, end = 0;
	struct bdb_entry *e = be->hist;
	unsigned char id[DNET_ID_SIZE], *k, stop;
	DBT key, dbdata;
	unsigned long long osize = 1024 * 1024, size;
	void *odata, *data;
	DB_TXN *txn;
	DBC *cursor;

	err = dnet_state_get_range(state, cmd->id, id);
	if (err)
		goto err_out_exit;

	memset(&key, 0, sizeof(DBT));
	memset(&dbdata, 0, sizeof(DBT));

	key.data = id;
	key.size = DNET_ID_SIZE;

	odata = malloc(osize);
	if (!odata) {
		err = -ENOMEM;
		goto err_out_exit;
	}

	data = odata;
	size = osize;

	stop = cmd->id[0];

	err = dnet_id_cmp(cmd->id, id);
	if (err <= 0)
		end = 1;

	txn = NULL;
	err = be->env->txn_begin(be->env, NULL, &txn, DB_READ_UNCOMMITTED);
	if (err) {
		dnet_command_handler_log(state, DNET_LOG_ERROR,
			"%s: failed to start a list transaction, err: %d: %s.\n",
				dnet_dump_id(cmd->id), err, db_strerror(err));
		goto err_out_free;
	}

	err = e->db->cursor(e->db, txn, &cursor, DB_READ_UNCOMMITTED);
	if (err) {
		dnet_command_handler_log(state, DNET_LOG_ERROR,
			"%s: failed to open list cursor, err: %d: %s.\n",
				dnet_dump_id(cmd->id), err, db_strerror(err));
		goto err_out_close_txn;
	}

	while (1) {
		err = cursor->c_get(cursor, &key, &dbdata, DB_SET_RANGE);

		do {
			if (err)
				continue;

			k = key.data;

			if (end && k[0] > stop)
				break;

			if (size < DNET_ID_SIZE) {
				err = dnet_send_reply(state, cmd, attr,
						odata, osize - size, 1);
				if (err)
					goto err_out_close_cursor;

				size = osize;
				data = odata;
			}

			memcpy(data, k, DNET_ID_SIZE);
			data += DNET_ID_SIZE;
			size -= DNET_ID_SIZE;

			dnet_command_handler_log(state, DNET_LOG_NOTICE, "%s.\n",
					dnet_dump_id(k));
		} while ((err = cursor->c_get(cursor, &key, &dbdata, DB_NEXT)) == 0);

		if (!end) {
			memset(id, 0, DNET_ID_SIZE);
			key.data = id;
			end = 1;
		} else
			break;
	}

	if (osize != size) {
		err = dnet_send_reply(state, cmd, attr, odata, osize - size, 0);
		if (err)
			goto err_out_close_cursor;
	}

	err = cursor->c_close(cursor);
	if (err) {
		dnet_command_handler_log(state, DNET_LOG_ERROR,
			"%s: failed to close list cursor: err: %d: %s.\n",
				dnet_dump_id(cmd->id), err, db_strerror(err));
		goto err_out_close_txn;
	}

	err = txn->commit(txn, 0);
	if (err) {
		dnet_command_handler_log(state, DNET_LOG_ERROR,
			"%s: failed to commit a list transaction: err: %d: %s.\n",
				dnet_dump_id(cmd->id), err, db_strerror(err));
		goto err_out_free;
	}

	free(odata);

	return 0;

err_out_close_cursor:
	cursor->c_close(cursor);
err_out_close_txn:
	txn->abort(txn);
err_out_free:
	free(odata);
err_out_exit:
	return err;
}

static struct bdb_entry *bdb_backend_open(DB_ENV *env, char *dbfile)
{
	int err;
	struct bdb_entry *e;
	DB *db;

	e = malloc(sizeof(struct bdb_entry));
	if (!e)
		goto err_out_exit;

	err = db_create(&db, env, 0);
	if (err) {
		fprintf(stderr, "Failed to create new database instance, err: %d.\n", err);
		goto err_out_free;
	}

	db->set_errcall(db, bdb_backend_error_handler);
	db->set_errpfx(db, "bdb_backend");

	err = db->open(db, NULL, dbfile, NULL, DB_BTREE, DB_CREATE | DB_AUTO_COMMIT |
			DB_THREAD | DB_READ_UNCOMMITTED, 0);
	if (err) {
		db->err(db, err, "Failed to open '%s' database, err: %d", dbfile, err);
		goto err_out_free;
	}

	e->db = db;

	return e;

err_out_free:
	free(e);
err_out_exit:
	return NULL;
}

static void bdb_backend_close(struct bdb_entry *e)
{
	e->db->close(e->db, 0);
	free(e);
}

void bdb_backend_exit(void *data)
{
	struct bdb_backend *be = data;

	bdb_backend_close(be->data);
	bdb_backend_close(be->hist);

	be->env->close(be->env, 0);

	free(be->env_dir);
	free(be);
}

void *bdb_backend_init(char *env_dir, char *dbfile, char *histfile)
{
	int err;
	DB_ENV *env;
	struct bdb_backend *be;

	be = malloc(sizeof(struct bdb_backend));
	if (!be) {
		err = -ENOMEM;
		goto err_out_exit;
	}
	memset(be, 0, sizeof(struct bdb_backend));

	if (env_dir) {
		be->env_dir = strdup(env_dir);
		if (!be->env_dir) {
			fprintf(stderr, "Failed to duplicate environment dir\n");
			goto err_out_free;
		}
	}

	err = db_env_create(&env, 0);
	if (err) {
		fprintf(stderr, "Failed to create new environment instance, err: %d.\n", err);
		goto err_out_free_env;
	}

	/*
	 * We can not use in-memory logging since we do not know the maximum size of the transaction.
	 */
#if 0
#ifdef DB_LOG_IN_MEMORY
#define __DB_LOG_IN_MEMORY	DB_LOG_IN_MEMORY
#else
#define __DB_LOG_IN_MEMORY	DB_LOG_INMEMORY
#endif

#if DB_VERSION_MINOR >= 7
	/* 
	 * We want logging to be done in memory for performance.
	 * In the perfect world this could be configured though.
	 */
	env->log_set_config(env, __DB_LOG_IN_MEMORY, 1);
#else
#endif
	env->set_flags(env, __DB_LOG_IN_MEMORY, 1);
#endif
	/*
	 * We do not need durable transaction, so we do not
	 * want disk IO at transaction commit.
	 * It shuold have no effect because of the in-memory logging though.
	 */
	env->set_flags(env, DB_TXN_NOSYNC, 1);

	err = env->set_lg_bsize(env, 5 * DNET_MAX_TRANS_SIZE);
	if (err != 0) {
		fprintf(stderr, "Failed to set log buffer size: %s\n", db_strerror(err));
		goto err_out_destroy_env;
	}

	err = env->set_lk_detect(env, DB_LOCK_MINWRITE);
	if (err) {
		fprintf(stderr, "Failed to set minimum write deadlock break method: %s.\n",
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
	err = env->set_timeout(env, 100000, DB_SET_TXN_TIMEOUT);
	if (err) {
		fprintf(stderr, "Failed to set transaction lock timeout: %s.\n", db_strerror(err));
		goto err_out_destroy_env;
	}

	err = env->open(env, env_dir, DB_CREATE | DB_INIT_MPOOL |
			DB_INIT_TXN | DB_INIT_LOCK | DB_INIT_LOG | DB_THREAD, 0);
	if (err) {
		fprintf(stderr, "Failed to open '%s' environment instance, err: %d.\n", env_dir, err);
		goto err_out_destroy_env;
	}

	be->data = bdb_backend_open(env, dbfile);
	if (!be->data)
		goto err_out_close_env;

	be->hist = bdb_backend_open(env, histfile);
	if (!be->hist)
		goto err_out_close_db;

	be->env = env;

	return be;

err_out_close_db:
	be->data->db->close(be->data->db, 0);
err_out_close_env:
	env->close(env, 0);
err_out_destroy_env:
err_out_free_env:
	free(be->env_dir);
err_out_free:
	free(be);
err_out_exit:
	return NULL;
}

int bdb_backend_command_handler(void *state, void *priv, struct dnet_cmd *cmd,
		struct dnet_attr *attr, void *data)
{
	int err;
	struct bdb_backend *e = priv;

	switch (attr->cmd) {
		case DNET_CMD_WRITE:
			err = bdb_put_data(state, e, cmd, attr, data);
			break;
		case DNET_CMD_READ:
			err = bdb_get_data(state, e, cmd, attr, data);
			break;
		case DNET_CMD_SYNC:
		case DNET_CMD_LIST:
			err = bdb_list(state, e, cmd, attr);
			break;
		case DNET_CMD_STAT:
			err = backend_stat(state, e->env_dir, cmd, attr);
			break;
		default:
			err = -EINVAL;
			break;
	}

	return err;
}
#else
int bdb_backend_command_handler(void *state __unused, void *priv __unused,
		struct dnet_cmd *cmd __unused, struct dnet_attr *attr __unused,
		void *data __unused)
{
	return -ENOTSUP;
}

void bdb_backend_exit(void *data __unused)
{
}

void *bdb_backend_init(char *env_dir __unused, char *dbfile __unused, char *histfile __unused)
{
	return NULL;
}
#endif
