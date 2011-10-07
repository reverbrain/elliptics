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

#include "elliptics/packet.h"
#include "elliptics/interface.h"

#ifdef HAVE_SRW_SUPPORT

#include <srw/srwc.h>

static char srw_init_path[4096];

static int dnet_srw_init_python(struct dnet_node *n, struct dnet_config *cfg)
{
	int fd, err;
	struct dnet_map_fd m;
	struct stat st;
	char *srw_base;
	char *chroot_path = NULL;

	memset(&m, 0, sizeof(struct dnet_map_fd));

	snprintf(srw_init_path, sizeof(srw_init_path), "%s/init.python", cfg->history_env);

	srw_base = strdup(cfg->history_env);
	if (!srw_base) {
		err = -ENOMEM;
		goto err_out_exit;
	}

	fd = open(srw_init_path, O_RDONLY);
	if (fd < 0) {
		err = -errno;
		dnet_log_err(n, "could not open python srw init script %s", srw_init_path);
		goto err_out_free;
	}

	err = fstat(fd, &st);
	if (err) {
		err = -errno;
		dnet_log_err(n, "could not stat python srw init script %s", srw_init_path);
		goto err_out_close;
	}

	m.fd = fd;
	m.size = st.st_size;

	err = dnet_data_map(&m);
	if (err) {
		dnet_log_err(n, "could not mmap python srw init script %s", srw_init_path);
		goto err_out_close;
	}

	if (geteuid() == 0) {
		chroot_path = cfg->history_env;
	} else {
		dnet_log(n, DNET_LOG_INFO, "\nsrw: DO NOT CHROOTING because of incufficient privilege !!!\n\n");
	}

	n->srw = srwc_init_python(chroot_path, n->io->thread_num, m.data, m.size, srw_base);
	if (!n->srw) {
		err = -EINVAL;
		dnet_log(n, DNET_LOG_ERROR, "srw: failed to initialize external python workers\n");
		goto err_out_unmap;
	}

	dnet_data_unmap(&m);
	close(fd);

	return 0;

err_out_unmap:
	dnet_data_unmap(&m);
err_out_close:
	close(fd);
err_out_free:
	free(srw_base);
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

int dnet_cmd_exec_python(struct dnet_net_state *st, struct dnet_cmd *cmd, struct dnet_attr *attr, struct dnet_exec *e)
{
	struct dnet_node *n = st->n;
	int err;
	char *res = NULL;

	err = srwc_process(n->srw, e->data, e->size, &res);
	if (err < 0) {
		dnet_log(n, DNET_LOG_ERROR, "%s: python processing failed: %s %d\n", dnet_dump_id(&cmd->id), strerror(-err), err);
		goto err_out_exit;
	}

	dnet_log(n, DNET_LOG_NOTICE, "%s: reply %d bytes: '%s'\n", dnet_dump_id(&cmd->id), err, err ? res : "none");

	if (err > 0) {
		err = dnet_send_reply(st, cmd, attr, res, err, 0);
		free(res);
	}

err_out_exit:
	return err;
}

int dnet_cmd_exec_python_script(struct dnet_net_state *st __unused, struct dnet_cmd *cmd __unused,
		struct dnet_attr *attr __unused, struct dnet_exec *e __unused)
{
	return -ENOTSUP;
}

#else
int dnet_srw_init(struct dnet_node *n __unused, struct dnet_config *cfg __unusued)
{
	return 0;
}

void dnet_srw_cleanup(struct dnet_node *n __unused)
{
}

int dnet_cmd_exec_python(struct dnet_net_state *st __unused, struct dnet_cmd *cmd __unused,
		struct dnet_attr *attr __unused, struct dnet_exec *e __unused)
{
	return -ENOTSUP;
}

int dnet_cmd_exec_python_script(struct dnet_net_state *st __unused, struct dnet_cmd *cmd __unused,
		struct dnet_attr *attr __unused, struct dnet_exec *e __unused)
{
	return -ENOTSUP;
}
#endif
