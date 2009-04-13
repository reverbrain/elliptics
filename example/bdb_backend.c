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

#ifdef HAVE_BDB_SUPPORT
#include <db.h>

#include "dnet/packet.h"
#include "dnet/interface.h"

static void bdb_backend_error_handler(const DB_ENV *env __unused, const char *prefix, const char *msg)
{
	fprintf(stderr, "%s: %s.\n", prefix, msg);
}

struct bdb_entry
{
	DB			*db;
	DBC			*cursor;
};

struct bdb_backend
{
	DB_ENV			*env;
	struct bdb_entry	*data, *hist;
};

static int bdb_get_record_size(void *state, struct bdb_entry *e, unsigned char *id, unsigned int *size)
{
	DBT key, data;
	int err;

	memset(&key, 0, sizeof(DBT));
	memset(&data, 0, sizeof(DBT));

	key.data = id;
	key.size = DNET_ID_SIZE;

	err = e->cursor->c_get(e->cursor, &key, &data, DB_SET);
	if (err) {
		if (err == DB_NOTFOUND) {
			err = 0;
			*size = 0;
		} else {
			e->db->err(e->db, err, "%s: failed to get record size, err: %d",
				dnet_dump_id(id), err);
		}
		goto err_out_exit;
	}
	
	dnet_command_handler_log(state, DNET_LOG_NOTICE, "%s: data size: %u, dlen: %u.\n",
				dnet_dump_id(id), data.size, data.dlen);

	*size = data.size;

	return 0;

err_out_exit:
	return err;
}

static int bdb_get_data(void *state, struct bdb_backend *be, struct dnet_cmd *cmd, struct dnet_attr *attr, void *buf)
{
	int err;
	DBT key, data;
	struct bdb_entry *e = be->data;
	struct dnet_io_attr *io = buf;
	unsigned int size, total_size, offset;

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

	size = io->size;
	if ((io->size == 0) && (attr->size == sizeof(struct dnet_io_attr))) {
		err = bdb_get_record_size(state, e, io->id, &size);
		if (err)
			goto err_out_exit;
	}

	total_size = size;
	offset = io->offset;

	if (attr->size == sizeof(struct dnet_io_attr)) {
		struct dnet_data_req *r;
		struct dnet_cmd *c;
		struct dnet_attr *a;
		struct dnet_io_attr *rio;

		while (total_size) {
			size = total_size;
			if (size > DNET_MAX_READ_TRANS_SIZE)
				size = DNET_MAX_READ_TRANS_SIZE;

			memset(&key, 0, sizeof(DBT));
			memset(&data, 0, sizeof(DBT));

			key.data = io->id;
			key.size = DNET_ID_SIZE;

			data.size = size;
			data.flags = DB_DBT_PARTIAL | DB_DBT_MALLOC;
			data.doff = offset;
			data.dlen = size;

			err = e->cursor->c_get(e->cursor, &key, &data, DB_SET);
			if (err) {
				e->db->err(e->db, err, "%s: allocated read failed offset: %u, size: %u, err: %d",
						dnet_dump_id(io->id), offset, size, err);
				goto err_out_exit;
			}

			r = dnet_req_alloc(state, sizeof(struct dnet_cmd) +
					sizeof(struct dnet_attr) + sizeof(struct dnet_io_attr));
			if (!r) {
				err = -ENOMEM;
				dnet_command_handler_log(state, DNET_LOG_ERROR,
					"%s: failed to allocate reply attributes.\n", dnet_dump_id(io->id));
				goto err_out_exit;
			}

			dnet_req_set_data(r, data.data, size, 1);

			c = dnet_req_header(r);
			a = (struct dnet_attr *)(c + 1);
			rio = (struct dnet_io_attr *)(a + 1);

			memcpy(c->id, io->id, DNET_ID_SIZE);
			memcpy(rio->id, io->id, DNET_ID_SIZE);
		
			dnet_command_handler_log(state, DNET_LOG_NOTICE,
				"%s: read reply offset: %u, size: %u.\n", dnet_dump_id(io->id), offset, size);

			if (total_size <= DNET_MAX_READ_TRANS_SIZE) {
				if (cmd->flags & DNET_FLAGS_NEED_ACK)
					c->flags = DNET_FLAGS_MORE;
			} else
				c->flags = DNET_FLAGS_MORE;

			c->status = 0;
			c->size = sizeof(struct dnet_attr) + sizeof(struct dnet_io_attr) + size;
			c->trans = cmd->trans | DNET_TRANS_REPLY;

			a->cmd = DNET_CMD_READ;
			a->size = sizeof(struct dnet_io_attr) + size;
			a->flags = attr->flags;

			rio->size = size;
			rio->offset = offset;
			rio->flags = io->flags;

			dnet_convert_cmd(c);
			dnet_convert_attr(a);
			dnet_convert_io_attr(rio);

			err = dnet_data_ready(state, r);
			if (err)
				goto err_out_exit;

			offset += size;
			total_size -= size;
		}
	} else {
		size = attr->size - sizeof(struct dnet_io_attr);

		memset(&key, 0, sizeof(DBT));
		memset(&data, 0, sizeof(DBT));

		key.data = io->id;
		key.size = DNET_ID_SIZE;

		data.data = buf;
		data.ulen = size;
		data.size = size;
		data.flags = DB_DBT_PARTIAL | DB_DBT_USERMEM;
		data.doff = io->offset;
		data.dlen = size;

		err = e->cursor->c_get(e->cursor, &key, &data, DB_SET);
		if (err) {
			e->db->err(e->db, err, "%s: umem read failed offset: %u, size: %llu, err: %d",
					dnet_dump_id(io->id), offset, size, err);
			goto err_out_exit;
		}

		io->size = size;
		attr->size = sizeof(struct dnet_io_attr) + err;
	}

	return 0;

err_out_exit:
	return err;
}

static int bdb_put_data(void *state, struct bdb_backend *be, struct dnet_cmd *cmd, struct dnet_attr *attr, void *buf)
{
	int err;
	DBT key, data;
	struct bdb_entry *e = be->data;
	struct dnet_io_attr *io = buf;

	if (attr->size <= sizeof(struct dnet_io_attr)) {
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
		e = be->hist;

	if (io->flags & DNET_IO_FLAGS_OBJECT) {
		if ((io->size != attr->size - sizeof(struct dnet_io_attr)) ||
				(io->size > cmd->size)){
			dnet_command_handler_log(state, DNET_LOG_ERROR,
				"%s: wrong io size: %llu, must be equal to %llu.\n",
					dnet_dump_id(cmd->id), (unsigned long long)io->size,
					(unsigned long long)attr->size - sizeof(struct dnet_io_attr));
			err = -EINVAL;
			goto err_out_exit;
		}

		memset(&key, 0, sizeof(DBT));
		memset(&data, 0, sizeof(DBT));

		key.data = cmd->id;
		key.size = DNET_ID_SIZE;

		data.data = buf;
		data.size = io->size;
		data.ulen = io->size;
		data.flags = DB_DBT_PARTIAL | DB_DBT_USERMEM;
		data.doff = io->offset;
		data.dlen = io->size;

		err = e->cursor->c_put(e->cursor, &key, &data, DB_KEYFIRST);
		if (err) {
			e->db->err(e->db, err, "%s: object put failed: offset: %llu, size: %llu, err: %d",
					dnet_dump_id(cmd->id), (unsigned long long)io->offset,
					(unsigned long long)io->size, err);
			goto err_out_exit;
		}

		dnet_command_handler_log(state, DNET_LOG_NOTICE,
			"%s: stored %s object: size: %llu, offset: %llu.\n",
				dnet_dump_id(cmd->id), (io->flags & DNET_IO_FLAGS_HISTORY) ? "history" : "data",
				(unsigned long long)io->size, (unsigned long long)io->offset);
	}
	
	if ((io->flags & DNET_IO_FLAGS_HISTORY_UPDATE) && !(io->flags & DNET_IO_FLAGS_HISTORY)) {
		unsigned int size;

		e = be->hist;

		err = bdb_get_record_size(state, e, cmd->id, &size);
		if (err)
			goto err_out_exit;

		memset(&key, 0, sizeof(DBT));
		memset(&data, 0, sizeof(DBT));

		key.data = cmd->id;
		key.size = DNET_ID_SIZE;

		data.data = io;
		data.doff = size;
		data.ulen = sizeof(struct dnet_io_attr);
		data.dlen = sizeof(struct dnet_io_attr);
		data.size = sizeof(struct dnet_io_attr);
		data.flags = DB_DBT_PARTIAL | DB_DBT_USERMEM;

		dnet_command_handler_log(state, DNET_LOG_NOTICE,
			"%s: updating history: size: %llu, offset: %llu.\n",
				dnet_dump_id(io->id), (unsigned long long)io->size, (unsigned long long)io->offset);

		dnet_convert_io_attr(io);

		err = e->cursor->c_put(e->cursor, &key, &data, DB_KEYFIRST);

		dnet_convert_io_attr(io);

		if (err) {
			e->db->err(e->db, err, "%s: history update failed offset: %llu, size: %llu, err: %d",
					dnet_dump_id(io->id), (unsigned long long)io->offset,
					(unsigned long long)io->size, err);
			goto err_out_exit;
		}
		
		dnet_command_handler_log(state, DNET_LOG_NOTICE,
			"%s: history updated: size: %llu, offset: %llu.\n",
				dnet_dump_id(io->id), (unsigned long long)io->size, (unsigned long long)io->offset);
	}

	return 0;

err_out_exit:
	return err;
}

static struct bdb_entry *bdb_backend_open(DB_ENV *env, char *dbfile)
{
	int err;
	struct bdb_entry *e;
	DB *db;
	DBC *cursor;

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

	err = db->open(db, NULL, dbfile, NULL, DB_HASH, DB_CREATE, 0);
	if (err) {
		db->err(db, err, "Failed to open '%s' database, err: %d", dbfile, err);
		goto err_out_free;
	}

	err = db->cursor(db, NULL, &cursor, 0);
	if (err) {
		db->err(db, err, "Failed to open '%s' database cursor, err: %d", dbfile, err);
		goto err_out_close;
	}

	e->cursor = cursor;
	e->db = db;

	return e;

err_out_close:
	db->close(db, 0);
err_out_free:
	free(e);
err_out_exit:
	return NULL;
}

static void bdb_backend_close(struct bdb_entry *e)
{
	e->cursor->c_close(e->cursor);
	e->db->close(e->db, 0);
	free(e);
}

void bdb_backend_exit(void *data)
{
	struct bdb_backend *be = data;

	bdb_backend_close(be->data);
	bdb_backend_close(be->hist);

	be->env->close(be->env, 0);
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

	err = db_env_create(&env, 0);
	if (err) {
		fprintf(stderr, "Failed to create new environment instance, err: %d.\n", err);
		goto err_out_free;
	}

	err = env->open(env, env_dir, DB_CREATE | DB_INIT_MPOOL, 0);
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
err_out_free:
	free(be);
err_out_exit:
	return NULL;
}

static int dnet_send_list(void *state, struct dnet_cmd *cmd, void *odata, unsigned int size)
{
	struct dnet_cmd *c;
	struct dnet_attr *a;
	struct dnet_data_req *r;
	void *data;

	r = dnet_req_alloc(state, sizeof(struct dnet_cmd) + sizeof(struct dnet_attr) + size);
	if (!r)
		return -ENOMEM;

	c = dnet_req_header(r);
	a = (struct dnet_attr *)(c + 1);
	data = a + 1;

	*c = *cmd;
	c->trans |= DNET_TRANS_REPLY;
	c->flags = DNET_FLAGS_MORE;
	c->status = 0;
	c->size = sizeof(struct dnet_attr) + size;

	a->size = size;
	a->flags = 0;
	a->cmd = DNET_CMD_LIST;

	memcpy(data, odata, size);

	dnet_convert_cmd(c);
	dnet_convert_attr(a);

	dnet_command_handler_log(state, DNET_LOG_NOTICE,
		"%s: sending %u list entries.\n",
		dnet_dump_id(cmd->id), size / DNET_ID_SIZE);

	return dnet_data_ready(state, r);
}

static int bdb_list(void *state, struct bdb_backend *be, struct dnet_cmd *cmd)
{
	int err, end = 0;
	struct bdb_entry *e = be->hist;
	unsigned char id[DNET_ID_SIZE], *k, stop;
	DBT key, dbdata;
	unsigned long long osize = 1024 * 1024, size;
	void *odata, *data;

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

	while (1) {
		err = e->cursor->c_get(e->cursor, &key, &dbdata, DB_SET_RANGE);

		do {
			if (err)
				continue;

			k = key.data;

			if (end && k[0] >= stop)
				break;

			if (size < DNET_ID_SIZE) {
				err = dnet_send_list(state, cmd, odata, osize - size);
				if (err)
					goto err_out_exit;

				size = osize;
				data = odata;
			}

			memcpy(data, k, DNET_ID_SIZE);
			data += DNET_ID_SIZE;
			size -= DNET_ID_SIZE;

			dnet_command_handler_log(state, DNET_LOG_NOTICE, "%s.\n", dnet_dump_id(k));
		} while ((err = e->cursor->c_get(e->cursor, &key, &dbdata, DB_NEXT)) == 0);

		if (!end) {
			memset(id, 0, DNET_ID_SIZE);
			key.data = id;
			end = 1;
		} else
			break;
	}

	if (osize != size) {
		err = dnet_send_list(state, cmd, odata, osize - size);
		if (err)
			goto err_out_exit;
	}

	return 0;

err_out_exit:
	return err;
}

int bdb_backend_command_handler(void *state, void *priv, struct dnet_cmd *cmd, struct dnet_attr *attr, void *data)
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
		case DNET_CMD_LIST:
			err = bdb_list(state, e, cmd);
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
