/*
 * 2011+ Copyright (c) Evgeniy Polyakov <zbr@ioremap.net>
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

#include <ctype.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "elliptics.h"

#include <elliptics/packet.h>
#include <elliptics/interface.h>

#include <elliptics/srw/srwc.h>

static char srw_init_path[4096];
static char srw_pipe_path[4096];

struct dnet_srw_init_conf {
	int			len;
	char			path[0];
};

static int dnet_srw_init_python(struct dnet_node *n, struct dnet_config *cfg)
{
	struct dnet_srw_init_conf *base;
	int num = n->io->thread_num / 3 + 1;
	int err;

	base = malloc(sizeof(struct dnet_srw_init_conf) + strlen(cfg->history_env) + 1);
	if (!base) {
		err = -ENOMEM;
		goto err_out_exit;
	}

	base->len = strlen(cfg->history_env);
	sprintf(base->path, "%s", cfg->history_env);

	snprintf(srw_init_path, sizeof(srw_init_path), "%s/python.init", cfg->history_env);
	snprintf(srw_pipe_path, sizeof(srw_pipe_path), "%s/python-pipe", cfg->history_env);

	dnet_log(n, DNET_LOG_INFO, "srw: binary: '%s', log: '%s', base: '%s', threads: %d\n",
			cfg->srw_binary, cfg->srw_log, base->path, num);
	n->srw = srwc_init_python(cfg->srw_binary, cfg->srw_log, srw_pipe_path, srw_init_path, num, base);
	if (!n->srw) {
		err = -EINVAL;
		dnet_log(n, DNET_LOG_ERROR, "srw: failed to initialize external python workers\n");
		goto err_out_free;
	}

	return 0;

err_out_free:
	free(base);
err_out_exit:
	return err;
}

int dnet_srw_init(struct dnet_node *n, struct dnet_config *cfg)
{
	return dnet_srw_init_python(n, cfg);
}

void dnet_srw_cleanup(struct dnet_node *n)
{
	if (!n->srw)
		return;

	free(n->srw->priv);
	srwc_cleanup_python(n->srw);
}

static int dnet_cmd_exec_python_raw(struct dnet_net_state *st, struct dnet_cmd *cmd, struct dnet_attr *attr,
		char *data, uint64_t size, void *binary, uint64_t bsize)
{
	struct dnet_node *n = st->n;
	int err;
	struct srwc_ctl ctl;

	memset(&ctl, 0, sizeof(struct srwc_ctl));

	ctl.cmd = data;
	ctl.cmd_size = size;
	ctl.binary = binary;
	ctl.binary_size = bsize;

	err = srwc_process(n->srw, &ctl);
	if (err < 0) {
		dnet_log(n, DNET_LOG_ERROR, "%s: python processing failed: %s %d\n", dnet_dump_id(&cmd->id), strerror(-err), err);
		goto err_out_exit;
	}

	dnet_log(n, DNET_LOG_DSA, "%s: reply %llu bytes: '%.*s'\n",
			dnet_dump_id(&cmd->id), (unsigned long long)ctl.res_size, (int)ctl.res_size, ctl.result);

	if (ctl.res_size) {
		err = dnet_send_reply(st, cmd, attr, ctl.result, ctl.res_size, 0);
		free(ctl.result);
	}

err_out_exit:
	return err;
}

int dnet_cmd_exec_python(struct dnet_net_state *st, struct dnet_cmd *cmd, struct dnet_attr *attr, struct dnet_exec *e)
{
	struct dnet_node *n = st->n;
	void *binary = NULL;
	if (e->binary_size)
		binary = e->data + e->script_size + e->name_size;

	if (!n->srw)
		return -ENOTSUP;

	return dnet_cmd_exec_python_raw(st, cmd, attr, e->data, e->script_size, binary, e->binary_size);
}

int dnet_cmd_exec_python_script(struct dnet_net_state *st, struct dnet_cmd *cmd,
		struct dnet_attr *attr, struct dnet_exec *e)
{
	struct dnet_node *n = st->n;
	char *full_path, *name, *script, *ptr;
	struct dnet_srw_init_conf *base;
	struct dnet_map_fd m;
	struct stat fst;
	int err, total, fd;
	void *binary = NULL;

	if (!n->srw)
		return -ENOTSUP;

	base = n->srw->priv;
	if (e->binary_size) {
		binary = e->data + e->name_size + e->script_size;
	}

	name = malloc(e->name_size + 1);
	if (!name) {
		err = -ENOMEM;
		goto err_out_exit;
	}

	memcpy(name, e->data, e->name_size);
	name[e->name_size] = '\0';

	ptr = strrchr(name, '/');
	if (ptr) {
		*ptr = '\0';
		ptr++;
	} else {
		ptr = name;
	}

	if (*ptr == '\0') {
		err = -EINVAL;
		goto err_out_free;
	}

	full_path = malloc(base->len + 2 + strlen(ptr));
	if (!full_path) {
		err = -ENOMEM;
		goto err_out_free;
	}

	sprintf(full_path, "%s/%s", base->path, ptr);

	fd = open(full_path, O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		err = -errno;
		dnet_log_err(n, "%s: dnet_cmd_exec_python_script: open: %s", dnet_dump_id(&cmd->id), full_path);
		goto err_out_free_full;
	}

	err = fstat(fd, &fst);
	if (err) {
		err = -errno;
		dnet_log_err(n, "%s: dnet_cmd_exec_python_script: fstat: %s", dnet_dump_id(&cmd->id), full_path);
		goto err_out_close;
	}

	total = fst.st_size + e->script_size + 3; /* \n + null byte and null byte on the next string */
	script = malloc(total);
	if (!script) {
		err = -ENOMEM;
		goto err_out_close;
	}

	memset(&m, 0, sizeof(struct dnet_map_fd));

	m.fd = fd;
	m.size = fst.st_size;

	err = dnet_data_map(&m);
	if (err) {
		err = -errno;
		dnet_log_err(n, "%s: dnet_cmd_exec_python_script: map: %s", dnet_dump_id(&cmd->id), full_path);
		goto err_out_free_script;
	}

	if (e->script_size) {
		memcpy(script, e->data + e->name_size, e->script_size);
		script[e->script_size] = '\n';
		memcpy(script + e->script_size + 1, m.data, m.size);
		script[e->script_size + 1 + m.size] = '\0';
		total = e->script_size + 1 + m.size + 1;
	} else {
		memcpy(script, m.data, m.size);
		script[m.size] = '\0';
		total = m.size + 1;
	}
	dnet_log(n, DNET_LOG_NOTICE, "%s: dnet_cmd_exec_python_script: '%s'\n", dnet_dump_id(&cmd->id), full_path);

	err = dnet_cmd_exec_python_raw(st, cmd, attr, script, total, binary, e->binary_size);
	if (err) {
		dnet_log_err(n, "%s: dnet_cmd_exec_python_script: exec: %s", dnet_dump_id(&cmd->id), full_path);
		goto err_out_unmap;
	}

err_out_unmap:
	dnet_data_unmap(&m);
err_out_free_script:
	free(script);
err_out_close:
	close(fd);
err_out_free_full:
	free(full_path);
err_out_free:
	free(name);
err_out_exit:
	return err;
}

int dnet_srw_update(struct dnet_node *n, int pid)
{
	return srwc_drop(n->srw, pid);
}
