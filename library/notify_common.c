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

#include <ctype.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "elliptics.h"

#include "elliptics/packet.h"
#include "elliptics/interface.h"

static int dnet_request_notification_raw(struct dnet_node *n, struct dnet_id *id,
	int (* complete)(struct dnet_net_state *state,
			struct dnet_cmd *cmd,
			void *priv),
	void *priv, uint64_t cflags)
{
	struct dnet_trans_control ctl;

	memset(&ctl, 0, sizeof(struct dnet_trans_control));

	memcpy(&ctl.id, id, sizeof(struct dnet_id));
	ctl.cmd = DNET_CMD_NOTIFY;
	ctl.complete = complete;
	ctl.priv = priv;
	ctl.cflags = DNET_FLAGS_NEED_ACK | cflags;

	return dnet_trans_alloc_send(n, &ctl);
}

int dnet_request_notification(struct dnet_node *n, struct dnet_id *id,
	int (* complete)(struct dnet_net_state *state,
			struct dnet_cmd *cmd,
			void *priv),
	void *priv)
{
	uint64_t cflags = 0;

	if (!complete || !id)
		return -EINVAL;

	return dnet_request_notification_raw(n, id, complete, priv, cflags);
}

int dnet_drop_notification(struct dnet_node *n, struct dnet_id *id)
{
	uint64_t cflags = DNET_ATTR_DROP_NOTIFICATION;
	if (!id)
		return -EINVAL;

	return dnet_request_notification_raw(n, id, NULL, NULL, cflags);
}

