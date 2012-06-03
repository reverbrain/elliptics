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

int dnet_srw_init(struct dnet_node *n, struct dnet_config *cfg)
{
	int err = 0;

	if (!cfg->srw.config)
		cfg->srw.config = cfg->addr;

	dnet_log(n, DNET_LOG_INFO, "srw: binary: '%s', log: '%s', pipe: '%s', init: '%s', config: '%s', threads: %d\n",
			cfg->srw.binary, cfg->srw.log, cfg->srw.pipe, cfg->srw.init, cfg->srw.config, cfg->srw.num);

	if (!cfg->srw.init || cfg->srw.num <= 0 || !cfg->srw.binary || !cfg->srw.pipe) {
		err = 0;
		dnet_log(n, DNET_LOG_INFO, "srw: do not initialize - insufficient parameters in config\n");
		goto err_out_exit;
	}

	cfg->srw.priv = NULL;

	n->srw = srwc_init(&cfg->srw);
	if (!n->srw) {
		err = -EINVAL;
		dnet_log(n, DNET_LOG_ERROR, "srw: failed to initialize external python workers\n");
		goto err_out_exit;
	}

err_out_exit:
	return err;
}

void dnet_srw_cleanup(struct dnet_node *n)
{
	if (n->srw)
		srwc_cleanup(n->srw);
}

int dnet_cmd_exec_raw(struct dnet_net_state *st, struct dnet_cmd *cmd, struct sph *header, const void *data)
{
	struct dnet_node *n = st->n;
	int err;
	struct srwc_ctl ctl;

	memset(&ctl, 0, sizeof(struct srwc_ctl));

	ctl.header = *header;

	err = srwc_process(n->srw, &ctl, data);
	if (err < 0) {
		dnet_log(n, DNET_LOG_ERROR, "%s: processing failed: %s %d\n", dnet_dump_id(&cmd->id), strerror(-err), err);
		goto err_out_exit;
	}

	dnet_log(n, DNET_LOG_DSA, "%s: reply %llu bytes: '%.*s'\n",
			dnet_dump_id(&cmd->id), (unsigned long long)ctl.res_size, (int)ctl.res_size, ctl.result);

	if (ctl.res_size) {
		err = dnet_send_reply(st, cmd, ctl.result, ctl.res_size, 0);
		free(ctl.result);
	}

err_out_exit:
	return err;
}

int dnet_srw_update(struct dnet_node *n, int pid)
{
	return srwc_drop(n->srw, pid);
}
