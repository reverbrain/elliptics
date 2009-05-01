/*
 * 2009+ Copyright (c) Tuncer Ayaz <tuncer.ayaz@gmail.com>
 * 2009+ Copyright (c) Evgeniy Polyakov <zbr@ioremap.net>
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
#include <pthread.h>

#ifndef __unused
#define __unused	__attribute__ ((unused))
#endif

#include "dnet/packet.h"
#include "dnet/interface.h"

#ifdef HAVE_TOKYOCABINET_SUPPORT

#include <tcadb.h>

struct tc_backend
{
	TCADB	*data, *hist;
};

struct tc_get_completion
{
	pthread_mutex_t		lock;
	int			refcnt;
	void			*ptr;
};

static int __tc_get_complete(struct tc_get_completion *c)
{
	int destroy = 0;

	pthread_mutex_lock(&c->lock);
	c->refcnt--;
	if (!c->refcnt)
		destroy = 1;
	pthread_mutex_unlock(&c->lock);

	if (destroy) {
		pthread_mutex_destroy(&c->lock);
		free(c->ptr);
		free(c);
	}

	return destroy;
}

static void tc_get_complete(struct dnet_data_req *r)
{
	struct tc_get_completion *c = dnet_req_private(r);

	__tc_get_complete(c);
	free(r);
}

static int tc_get_data(void *state, struct tc_backend *be, struct dnet_cmd *cmd,
		struct dnet_attr *attr, void *buf)
{
	TCADB *db = be->data;
	int err;
	struct dnet_io_attr *io = buf;
	int size, total_size, offset;
	struct tc_get_completion *complete;
	void *ptr;
	struct dnet_data_req *r;

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
		db = be->hist;

	offset = io->offset;

	complete = malloc(sizeof(struct tc_get_completion));
	if (!complete) {
		err = -ENOMEM;
		goto err_out_exit;
	}

	err = pthread_mutex_init(&complete->lock, NULL);
	if (err) {
		err = -err;
		dnet_command_handler_log(state, DNET_LOG_ERROR,
			"%s: failed to initialize completion mutex: %d.\n",
			dnet_dump_id(io->origin), err);
		goto err_out_put;
	}

	complete->refcnt = 1;
	complete->ptr = NULL;

	ptr = tcadbget(db, io->origin, DNET_ID_SIZE, &total_size);
	if (!ptr) {
		dnet_command_handler_log(state, DNET_LOG_ERROR,
			"%s: failed to read object.\n", dnet_dump_id(io->origin));
		err = -ENOENT;
		goto err_out_put;
	}

	complete->ptr = ptr;

	/*
	 * Yeah-yeah-yeah, TokyoCabinet is 31-bits only.
	 */
	if (total_size < (int)io->offset) {
		dnet_command_handler_log(state, DNET_LOG_ERROR,
			"%s: object is too small: offset: %d, size: %d.\n",
			dnet_dump_id(io->origin), offset, total_size);
		err = -E2BIG;
		goto err_out_put;
	}

	if (total_size < (int)(io->offset + io->size)) {
		dnet_command_handler_log(state, DNET_LOG_ERROR,
			"%s: object is too small: truncating output: offset: %u, size: %u, requested_size: %llu.\n",
			dnet_dump_id(io->origin), offset, total_size, (unsigned long long)io->size);
	}

	if (io->size)
		total_size = io->size;

	if (attr->size == sizeof(struct dnet_io_attr)) {
		struct dnet_cmd *c;
		struct dnet_attr *a;
		struct dnet_io_attr *rio;

		while (total_size) {
			size = total_size;
			if (size > DNET_MAX_READ_TRANS_SIZE)
				size = DNET_MAX_READ_TRANS_SIZE;

			r = dnet_req_alloc(state, sizeof(struct dnet_cmd) +
					sizeof(struct dnet_attr) + sizeof(struct dnet_io_attr));
			if (!r) {
				err = -ENOMEM;
				dnet_command_handler_log(state, DNET_LOG_ERROR,
					"%s: failed to allocate reply attributes.\n",
					dnet_dump_id(io->origin));
				goto err_out_put;
			}

			dnet_req_set_data(r, ptr, size, offset, 0);
			dnet_req_set_complete(r, tc_get_complete, complete);

			c = dnet_req_header(r);
			a = (struct dnet_attr *)(c + 1);
			rio = (struct dnet_io_attr *)(a + 1);

			memcpy(c->id, io->origin, DNET_ID_SIZE);
			memcpy(rio->origin, io->origin, DNET_ID_SIZE);

			dnet_command_handler_log(state, DNET_LOG_NOTICE,
				"%s: read reply offset: %u, size: %u.\n",
				dnet_dump_id(io->origin), offset, size);

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

			pthread_mutex_lock(&complete->lock);
			complete->refcnt++;
			pthread_mutex_unlock(&complete->lock);

			err = dnet_data_ready(state, r);
			if (err)
				goto err_out_free_req;

			offset += size;
			total_size -= size;
		}
	} else {
		size = attr->size - sizeof(struct dnet_io_attr);

		if (size < total_size)
			size = total_size;
		memcpy(buf, ptr + io->offset, size);

		io->size = size;
		attr->size = sizeof(struct dnet_io_attr) + err;
	}

	__tc_get_complete(complete);

	return 0;

err_out_free_req:
	dnet_req_destroy(r);
err_out_put:
	__tc_get_complete(complete);
err_out_exit:
	return err;
}

static int tc_put_data(void *state, struct tc_backend *be, struct dnet_cmd *cmd,
		struct dnet_attr *attr, void *data)
{
	int err;
	TCADB *db = be->data;
	struct dnet_io_attr *io = data;
	struct dnet_history_entry *e, n, *r;
	bool res;

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

	data += sizeof(struct dnet_io_attr);
	
	if (io->flags & DNET_IO_FLAGS_HISTORY) {
		db = be->hist;

		if (io->size == sizeof(struct dnet_history_entry)) {
			int esize;

			r = data;

			res = tcadbtranbegin(db);
			if (!res) {
				err = -EINVAL;
				dnet_command_handler_log(state, DNET_LOG_ERROR,
					"%s: failed to start history transactio.\n",
						dnet_dump_id(io->origin));
				goto err_out_exit;
			}

			e = tcadbget(db, io->origin, DNET_ID_SIZE, &esize);
			if (!e) {
				res = tcadbput(db, io->origin, DNET_ID_SIZE, r, sizeof(struct dnet_history_entry));
			} else {
				dnet_convert_history_entry(e);
				dnet_convert_history_entry(r);
				
				if (e->size < r->offset + r->size) {
					e->size = r->offset + r->size;
					dnet_convert_history_entry(e);
					res = tcadbput(db, io->origin, DNET_ID_SIZE, e, esize);
				}

				dnet_convert_history_entry(r);
			}

			if (esize)
				free(e);
			
			if (!res) {
				err = -EINVAL;
				dnet_command_handler_log(state, DNET_LOG_ERROR,
					"%s: history metadata update failed.\n",
						dnet_dump_id(io->origin));
				goto err_out_abort_transaction;
			}
		}
	}

	if (io->flags & DNET_IO_FLAGS_APPEND) {
		res = tcadbputcat(db, io->origin, DNET_ID_SIZE, data, io->size);
	} else {
		res = tcadbput(db, io->origin, DNET_ID_SIZE, data, io->size);
	}
	if (!res) {
		dnet_command_handler_log(state, DNET_LOG_ERROR,
			"%s: direct object put failed: offset: %llu, size: %llu.\n",
			dnet_dump_id(io->origin), (unsigned long long)io->offset,
			(unsigned long long)io->size);
		err = -EINVAL;
		goto err_out_exit;
	}

	if (io->flags & DNET_IO_FLAGS_HISTORY) {
		res = tcadbtrancommit(be->hist);
		if (!res) {
			err = -EINVAL;
			dnet_command_handler_log(state, DNET_LOG_ERROR,
				"%s: history transaction commit failed..\n",
					dnet_dump_id(io->origin));
			goto err_out_abort_transaction;
		}
	}

	dnet_command_handler_log(state, DNET_LOG_NOTICE,
		"%s: stored %s object: size: %llu, offset: %llu.\n",
			dnet_dump_id(io->origin),
			(io->flags & DNET_IO_FLAGS_HISTORY) ? "history" : "data",
			(unsigned long long)io->size, (unsigned long long)io->offset);

	if (!(io->flags & DNET_IO_FLAGS_NO_HISTORY_UPDATE) && !(io->flags & DNET_IO_FLAGS_HISTORY)) {
		e = &n;

		memcpy(e->id, io->id, DNET_ID_SIZE);
		e->size = io->size;
		e->offset = io->offset;
		e->flags = 0;

		dnet_convert_history_entry(e);

		res = tcadbputcat(db, io->origin, DNET_ID_SIZE, e, sizeof(struct dnet_history_entry));
		if (!res) {
			err = -EINVAL;
			dnet_command_handler_log(state, DNET_LOG_ERROR,
				"%s: history update failed offset: %llu, size: %llu.\n",
					dnet_dump_id(io->origin), (unsigned long long)io->offset,
					(unsigned long long)io->size);
			goto err_out_exit;
		}

		dnet_command_handler_log(state, DNET_LOG_NOTICE,
			"%s: history updated: size: %llu, offset: %llu.\n",
				dnet_dump_id(io->origin), (unsigned long long)io->size,
				(unsigned long long)io->offset);
	}

	return 0;

err_out_abort_transaction:
	tcadbtranabort(be->hist);
err_out_exit:
	return err;
}

static int tc_list(void *state, struct tc_backend *be, struct dnet_cmd *cmd)
{
	int err, num, size, i;
	TCADB *e = be->hist;
	unsigned char id[DNET_ID_SIZE], start, last;
	TCLIST *l;
	int inum = 10240, ipos = 0;
	unsigned char ids[inum][DNET_ID_SIZE];

	err = dnet_state_get_range(state, cmd->id, id);
	if (err)
		goto err_out_exit;

	last = id[0] - 1;

	for (start = cmd->id[0]; start != last; --start) {
		l = tcadbfwmkeys(e, &start, 1, -1);
		if (!l)
			continue;

		num = tclistnum(l);
		if (!num)
			goto out_clean;

		for (i=0; i<num; ++i) {
			const unsigned char *idx = tclistval(l, i, &size);

			if (!idx)
				break;

			if (start == cmd->id[0] && dnet_id_cmp(cmd->id, idx) >= 0)
				continue;

			if (ipos == inum) {
				err = dnet_send_list(state, cmd, ids, ipos * DNET_ID_SIZE);
				if (err)
					goto out_clean;

				ipos = 0;
			}

			dnet_command_handler_log(state, DNET_LOG_INFO, "%s\n", dnet_dump_id(idx));
			memcpy(ids[ipos], idx, DNET_ID_SIZE);
			ipos++;
		}

out_clean:
		tclistdel(l);
		if (err)
			goto err_out_exit;
	}

	if (ipos) {
		err = dnet_send_list(state, cmd, ids, ipos * DNET_ID_SIZE);
		if (err)
			goto err_out_exit;
	}

	return 0;

err_out_exit:
	return err;
}

int tc_backend_command_handler(void *state, void *priv,
		struct dnet_cmd *cmd, struct dnet_attr *attr,
		void *data)
{
	int err;
	struct tc_backend *e = priv;

	switch (attr->cmd) {
		case DNET_CMD_WRITE:
			err = tc_put_data(state, e, cmd, attr, data);
			break;
		case DNET_CMD_READ:
			err = tc_get_data(state, e, cmd, attr, data);
			break;
		case DNET_CMD_LIST:
			err = tc_list(state, e, cmd);
			break;
		default:
			err = -EINVAL;
			break;
	}

	return err;
}

void tc_backend_exit(void *data)
{
	struct tc_backend *be = data;

	/* close dbs and delete objects if existing */
	if (!tcadbclose(be->data))
		fprintf(stderr, "tc_backend_exit: tcadbclose(be->data) failed\n");

	tcadbdel(be->data);

	if (!tcadbclose(be->hist))
		fprintf(stderr, "tc_backend_exit: tcadbclose(be->hist) failed\n");

	tcadbdel(be->hist);

	free(be);
}

static int tc_backend_open(TCADB *adb, const char *env_dir, const char *file)
{
	int err;
	char *path;
	size_t len;

	if (!env_dir) {
		if (!tcadbopen(adb, file)) {
			err = -EINVAL;
			goto err_out_print;
		}

		return 0;
	}

	/* if env_dir passed open db there
	 * 
	 * Create path string from env_dir and file
	 * Added place for '/' and null byte at the end.
	 */
	len = strlen(env_dir) + strlen(file) + 2;

	path = malloc(len);
	if (!path) {
		err = -ENOMEM;
		fprintf(stderr, "%s: malloc path failed\n", __func__);
		goto err_out_exit;
	}

	snprintf(path, len, "%s/%s", env_dir, file);

	/* try to open database in env_dir */
	if (!tcadbopen(adb, path)) {
		err = -EINVAL;
		goto err_out_free;
	}

	free(path);

	return 0;

err_out_free:
	free(path);
err_out_print:
	fprintf(stderr, "Failed to open database at dir: '%s', file: '%s'.\n", env_dir, file);
err_out_exit:
	return err;
}

void *tc_backend_init(const char *env_dir, const char *dbfile, const char *histfile)
{
	/* initialize tc_backend struct */
	struct tc_backend *be;
	int err;
	
	be = malloc(sizeof(struct tc_backend));
	if (!be) {
		fprintf(stderr, "malloc(tc_backend) failed\n");
		goto err_out_exit;
	}
	memset(be, 0, sizeof(struct tc_backend));

	/* create data TCADB object */
	be->data = tcadbnew();
	if(!be->data) {
		fprintf(stderr, "tcadbnew(be->data) failed\n");
		goto err_out_free_be;
	}
	/* create hist TCADB object */
	be->hist = tcadbnew();
	if(!be->hist) {
		fprintf(stderr, "tcadbnew(be->hist) failed\n");
		goto err_out_del_data;
	}

	/* open data database */
	err = tc_backend_open(be->data, env_dir, dbfile);
	if (err) {
		fprintf(stderr, "tcadbopen(be->data,%s) failed\n", dbfile);
		goto err_out_del_hist;
	}
	/* open hist database */
	err = tc_backend_open(be->hist, env_dir, histfile);
	if (err) {
		fprintf(stderr, "tcadbopen(be->hist,%s) failed\n", histfile);
		goto err_out_close_data;
	}

	return be;

err_out_close_data:
	tcadbclose(be->data);
err_out_del_hist:
	tcadbdel(be->hist);
err_out_del_data:
	tcadbdel(be->data);
err_out_free_be:
	free(be);
err_out_exit:
	return NULL;
}
#else
int tc_backend_command_handler(void *state __unused, void *priv __unused,
		struct dnet_cmd *cmd __unused, struct dnet_attr *attr __unused,
		void *data __unused)
{
	return -ENOTSUP;
}

void tc_backend_exit(void *data __unused)
{
	return;
}

void *tc_backend_init(const char *env_dir __unused,
		const char *dbfile __unused, const char *histfile __unused)
{
	return NULL;
}

#endif
