/*
 * Copyright 2008+ Evgeniy Polyakov <zbr@ioremap.net>
 *
 * This file is part of Elliptics.
 * 
 * Elliptics is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * Elliptics is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public License
 * along with Elliptics.  If not, see <http://www.gnu.org/licenses/>.
 */

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

static int dnet_request_notification_raw(struct dnet_session *s, struct dnet_id *id,
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

	return dnet_trans_alloc_send(s, &ctl);
}

int dnet_request_notification(struct dnet_session *s, struct dnet_id *id,
	int (* complete)(struct dnet_net_state *state,
			struct dnet_cmd *cmd,
			void *priv),
	void *priv)
{
	uint64_t cflags = 0;

	if (!complete || !id)
		return -EINVAL;

	return dnet_request_notification_raw(s, id, complete, priv, cflags);
}

int dnet_drop_notification(struct dnet_session *s, struct dnet_id *id)
{
	uint64_t cflags = DNET_ATTR_DROP_NOTIFICATION;
	if (!id)
		return -EINVAL;

	return dnet_request_notification_raw(s, id, NULL, NULL, cflags);
}

