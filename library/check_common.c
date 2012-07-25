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
#include <sys/mman.h>

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "elliptics.h"
#include "elliptics/interface.h"

static int dnet_check_complete(struct dnet_net_state *state, struct dnet_cmd *cmd, void *priv)
{
	struct dnet_wait *w = priv;
	int err = -EINVAL;

	if (is_trans_destroyed(state, cmd)) {
		dnet_wakeup(w, w->cond++);
		dnet_wait_put(w);
		return 0;
	}

	if (cmd->size == sizeof(struct dnet_check_reply)) {
		struct dnet_check_reply *r = (struct dnet_check_reply *)(cmd + 1);

		dnet_convert_check_reply(r);

		dnet_log(state->n, DNET_LOG_INFO, "check: total: %d, completed: %d, errors: %d\n",
				r->total, r->completed, r->errors);
	}

	w->status = cmd->status;
	return err;
}

static int dnet_send_check_request(struct dnet_net_state *st, struct dnet_id *id,
		struct dnet_wait *w, struct dnet_check_request *r)
{
	struct dnet_trans_control ctl;
	char ctl_time[64];
	struct tm tm;

	memset(&ctl, 0, sizeof(struct dnet_trans_control));

	memcpy(&ctl.id, id, sizeof(struct dnet_id));
	ctl.cmd = DNET_CMD_LIST;
	ctl.complete = dnet_check_complete;
	ctl.priv = w;
	ctl.cflags = DNET_FLAGS_NEED_ACK | DNET_FLAGS_NOLOCK;

	if (r->timestamp) {
		localtime_r((time_t *)&r->timestamp, &tm);
		strftime(ctl_time, sizeof(ctl_time), "%F %R:%S %Z", &tm);
	} else {
		snprintf(ctl_time, sizeof(ctl_time), "all records");
	}

	dnet_log(st->n, DNET_LOG_INFO, "%s: check request: objects: %llu, threads: %llu, timestamp: %s, merge: %d\n",
			dnet_state_dump_addr(st), (unsigned long long)r->obj_num, (unsigned long long)r->thread_num,
			ctl_time, !!(r->flags & DNET_CHECK_MERGE));

	dnet_convert_check_request(r);

	ctl.data = r;
	ctl.size = sizeof(*r) + r->obj_num * sizeof(struct dnet_id) + r->group_num * sizeof(int);

	return dnet_trans_alloc_send_state(st, &ctl);
}

int dnet_request_check(struct dnet_node *n, struct dnet_check_request *r)
{
	struct dnet_wait *w;
	struct dnet_net_state *st;
	struct dnet_group *g;
	int err, num = 0;

	w = dnet_wait_alloc(0);
	if (!w) {
		err = -ENOMEM;
		goto err_out_exit;
	}

	pthread_mutex_lock(&n->state_lock);
	list_for_each_entry(g, &n->group_list, group_entry) {
		list_for_each_entry(st, &g->state_list, state_entry) {
			struct dnet_id raw;

			if (st == n->st)
				continue;

			dnet_wait_get(w);

			dnet_setup_id(&raw, st->idc->group->group_id, st->idc->ids[0].raw.id);
			dnet_send_check_request(st, &raw, w, r);
			num++;
		}
	}
	pthread_mutex_unlock(&n->state_lock);

	err = dnet_wait_event(w, w->cond == num, &n->wait_ts);
	if (err)
		goto err_out_put;

	if (w->status) {
		err = w->status;
		goto err_out_put;
	}

	dnet_wait_put(w);

	return num;

err_out_put:
	dnet_wait_put(w);
err_out_exit:
	dnet_log(n, DNET_LOG_ERROR, "Check exited with status %d\n", err);
	return err;
}
