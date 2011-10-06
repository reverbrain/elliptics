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

int dnet_srw_init(struct dnet_node *n, struct dnet_config *cfg)
{
	char str[] = 	"import sys\nsys.path.append('/tmp/dnet/lib')\n"
				"from libelliptics_python import *\n"
				"log = elliptics_log_file('/dev/stderr', 40)\n"
				"n = elliptics_node_python(log)\n"
				"n.add_groups([1,2,3])\n"
				"n.add_remote('localhost', 1025)\n"
				"__return_data = 'unused'";

	n->srw = srwc_init_python(n->io->thread_num, str, sizeof(str) + 1, NULL);
	if (!n->srw) {
		dnet_log(n, DNET_LOG_ERROR, "srw: failed to initialize external python workers\n");
		return -EINVAL;
	}

	return 0;
}

void dnet_srw_cleanup(struct dnet_node *n)
{
	if (n->srw)
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
