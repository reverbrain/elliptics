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

static int tc_get_record_size(void *state, TCADB *e,
		unsigned char *id, unsigned int *size)
{
	const void *kbuf = id;
	int ksiz = strlen(kbuf);
	int vsiz = tcadbvsiz(e, kbuf, ksiz);
	if (vsiz == -1) {
		dnet_command_handler_log(state, DNET_LOG_ERROR,
			"%s: failed to get TCADB value size.\n",
				dnet_dump_id(id));
		goto rs_exit;
	}

	dnet_command_handler_log(state, DNET_LOG_NOTICE, "%s: value size: %u.\n",
				dnet_dump_id(id), vsiz);

	*size = vsiz;

rs_exit:
	return vsiz;
}

static int tc_get_data(void *state, struct tc_backend *be, struct dnet_cmd *cmd,
		struct dnet_attr *attr, void *buf)
{
	TCADB *e = be->data;
	struct dnet_io_attr *io = buf;

	if (attr->size < sizeof(struct dnet_io_attr)) {
		dnet_command_handler_log(state, DNET_LOG_ERROR,
			"%s: wrong read attribute, size does not match "
				"IO attribute size: size: %llu, must be: %zu.\n",
				dnet_dump_id(cmd->id), (unsigned long long)attr->size,
				sizeof(struct dnet_io_attr));
		return -EINVAL;
	}

	buf += sizeof(struct dnet_io_attr);

	dnet_convert_io_attr(io);

	if (io->flags & DNET_IO_FLAGS_HISTORY)
		e = be->hist;

	return -ENOTSUP;
}

static int tc_put_data(void *state, struct tc_backend *be, struct dnet_cmd *cmd,
		struct dnet_attr *attr, void *buf)
{
	return -ENOTSUP;
}

static int tc_list(void *state, struct tc_backend *be, struct dnet_cmd *cmd)
{
	return -ENOTSUP;
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
	if(be) {
		if(be->data) {
			if(!tcadbclose(be->data))
				fprintf(stderr,"tc_backend_exit: tcadbclose(be->data) failed\n");
			tcadbdel(be->data);
		}
		if(be->hist) {
			if(!tcadbclose(be->hist))
				fprintf(stderr,"tc_backend_exit: tcadbclose(be->hist) failed\n");
			tcadbdel(be->hist);
		}

		free(be);
	}
}

static bool tc_backend_open(TCADB *adb, const char *env_dir, const char *file)
{
	char *path = NULL;
	bool res = false;

	/* if env_dir passed open db in there */
	if(env_dir) {
		/* create path string from env_dir and file */
		size_t len = strlen(env_dir) + strlen(file) + 1;
		path = (char*)malloc(len);
		if(!path) {
			fprintf(stderr, "tc_backend_open: malloc path failed\n");
			free(path);
			return false;
		}
		if (env_dir[strlen(env_dir) - 1] == '/')
			snprintf(path, len, "%s%s", env_dir, file);
		else
			snprintf(path, len, "%s/%s", env_dir, file);

		/* try to open database in env_dir */
		res = tcadbopen(adb, path);

		free(path);
	} else {
		/* try to open database */
		res = tcadbopen(adb, file);
	}

	return res;
}

void *tc_backend_init(const char *env_dir, const char *dbfile, const char *histfile)
{
	/* initialize tc_backend struct */
	struct tc_backend *be = malloc(sizeof(struct tc_backend));
	if(!be) {
		fprintf(stderr, "malloc(tc_backend) failed\n");
		goto err_init_be_null;
	}
	memset(be, 0, sizeof(struct tc_backend));

	/* create data TCADB object */
	be->data = tcadbnew();
	if(!be->data) {
		fprintf(stderr, "tcadbnew(be->data) failed\n");
		goto err_init_free_be;
	}
	/* create hist TCADB object */
	be->hist = tcadbnew();
	if(!be->hist) {
		fprintf(stderr, "tcadbnew(be->hist) failed\n");
		goto err_init_del_data;
	}

	/* open data database */
	if (!tc_backend_open(be->data, env_dir, dbfile)) {
		fprintf(stderr, "tcadbopen(be->data,%s) failed\n", dbfile);
		goto err_init_del_hist;
	}
	/* open hist database */
	if (!tc_backend_open(be->hist, env_dir, histfile)) {
		fprintf(stderr, "tcadbopen(be->hist,%s) failed\n", histfile);
		goto err_init_close_data;
	}

	return be;

err_init_close_data:
	tcadbclose(be->data);
err_init_del_hist:
	tcadbdel(be->hist);
err_init_del_data:
	tcadbdel(be->data);
err_init_free_be:
	free(be);
err_init_be_null:
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
	return -ENOTSUP;
}

void *tc_backend_init(const char *env_dir __unused,
		const char *dbfile __unused, const char *histfile __unused)
{
	return NULL;
}

#endif
