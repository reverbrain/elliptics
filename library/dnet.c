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

#define _XOPEN_SOURCE 600

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <sys/wait.h>

#include <alloca.h>
#include <assert.h>
#include <ctype.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "elliptics.h"
#include "monitor/monitor.h"

#include "elliptics/packet.h"
#include "elliptics/interface.h"

#include "monitor/measure_points.h"

int dnet_remove_local(struct dnet_backend_io *backend, struct dnet_node *n, struct dnet_id *id)
{
	const size_t cmd_size = sizeof(struct dnet_cmd) + sizeof(struct dnet_io_attr);
	int err;
	char buffer[cmd_size];
	struct dnet_cmd *cmd = (struct dnet_cmd *)buffer;
	struct dnet_io_attr *io = (struct dnet_io_attr *)(cmd + 1);

	memset(buffer, 0, cmd_size);

	cmd->id = *id;
	cmd->size = cmd_size - sizeof(struct dnet_cmd);
	cmd->flags = DNET_FLAGS_NOLOCK;
	cmd->cmd = DNET_CMD_DEL;

	io->flags = DNET_IO_FLAGS_SKIP_SENDING;

	memcpy(io->parent, id->id, DNET_ID_SIZE);
	memcpy(io->id, id->id, DNET_ID_SIZE);

	dnet_convert_io_attr(io);

	err = backend->cb->command_handler(n->st, backend->cb->command_private, cmd, io);
	dnet_log(n, DNET_LOG_NOTICE, "%s: local remove: err: %d.", dnet_dump_id(&cmd->id), err);

	return err;

}

static int dnet_cmd_route_list(struct dnet_net_state *orig, struct dnet_cmd *cmd)
{
	struct dnet_node *n = orig->n;
	struct dnet_net_state *st;
	struct dnet_addr_cmd *acmd = NULL;
	struct dnet_addr *addrs = NULL;
	size_t total_size;
	size_t states_num = 0;
	int err;

	pthread_mutex_lock(&n->state_lock);
	list_for_each_entry(st, &n->dht_state_list, node_entry) {
		if (dnet_addr_equal(&st->addr, &orig->addr) || !st->addrs)
			continue;
		++states_num;
	}

	total_size = sizeof(struct dnet_addr_cmd) + states_num * n->addr_num * sizeof(struct dnet_addr);
	acmd = malloc(total_size);

	if (!acmd) {
		pthread_mutex_unlock(&n->state_lock);
		return -ENOMEM;
	}

	memset(acmd, 0, total_size);

//	cmd = &acmd->cmd;
	acmd->cnt.addr_num = states_num * n->addr_num;
	acmd->cnt.node_addr_num = n->addr_num;
	addrs = acmd->cnt.addrs;
	const int dump_size = 128;
	char orig_addr_str[dump_size+1], addr_str[dump_size+1], first_addr_str[dump_size+1];

	dnet_addr_string_raw(&orig->addr, orig_addr_str, dump_size);

	list_for_each_entry(st, &n->dht_state_list, node_entry) {
		int skip = dnet_addr_equal(&st->addr, &orig->addr) || !st->addrs;

		if (!st->addrs)
			snprintf(first_addr_str, sizeof(first_addr_str), "no-address");
		else
			dnet_addr_string_raw(&st->addrs[0], first_addr_str, dump_size);

		dnet_addr_string_raw(&st->addr, addr_str, dump_size);

		dnet_log(n, DNET_LOG_NOTICE, "route-list: request-from: %s, route-table-node: %s, "
				"addr_num: %d, first-addr: %s, skip: %d",
				orig_addr_str, addr_str,
				n->addr_num,
				first_addr_str, skip);

		if (skip)
			continue;

		assert(st->addr_num == n->addr_num);

		dnet_log(n, DNET_LOG_NOTICE, "%s: addr_num: %d",
				dnet_addr_string(&st->addrs[0]),
				n->addr_num);

		memcpy(addrs, st->addrs, n->addr_num * sizeof(struct dnet_addr));
		addrs += n->addr_num;
	}
	pthread_mutex_unlock(&n->state_lock);
	memcpy(&acmd->cmd.id, &cmd->id, sizeof(struct dnet_id));
	acmd->cmd.size = total_size - sizeof(struct dnet_cmd);

	acmd->cmd.flags = DNET_FLAGS_NOLOCK | DNET_FLAGS_REPLY;
	acmd->cmd.trans = cmd->trans;

	acmd->cmd.cmd = DNET_CMD_ROUTE_LIST;

	dnet_convert_addr_cmd(acmd);
	err = dnet_send(orig, acmd, total_size);

	if (err == 0) {
		cmd->flags &= ~DNET_FLAGS_NEED_ACK;
	}

	free(acmd);
	return err;
}

static int dnet_cmd_exec(struct dnet_net_state *st, struct dnet_cmd *cmd, void *data)
{
	struct dnet_node *n = st->n;
	struct sph *e = data;
	int err = -ENOTSUP;

	data += sizeof(struct sph);

	dnet_convert_sph(e);

	if (e->event_size + e->data_size + sizeof(struct sph) != cmd->size) {
		err = -E2BIG;
		dnet_log(n, DNET_LOG_ERROR, "%s: invalid size: event-size %d, data-size %llu must be: %llu",
				dnet_dump_id(&cmd->id),
				e->event_size,
				(unsigned long long)e->data_size,
				(unsigned long long)cmd->size);
		goto err_out_exit;
	}

	err = dnet_cmd_exec_raw(st, cmd, e, data);

err_out_exit:
	return err;
}

static int dnet_cmd_status(struct dnet_net_state *orig, struct dnet_cmd *cmd __unused, void *data)
{
	struct dnet_node *n = orig->n;
	struct dnet_node_status *st = data;

	dnet_convert_node_status(st);

	dnet_log(n, DNET_LOG_INFO, "%s: status-change: nflags: %s->%s, log_level: %d->%d, "
			"status_flags: EXIT: %d, RO: %d",
			dnet_dump_id(&cmd->id), dnet_flags_dump_cfgflags(n->flags), dnet_flags_dump_cfgflags(st->nflags),
			(int)dnet_log_get_verbosity(n->log), st->log_level,
			!!(st->status_flags & DNET_STATUS_EXIT), !!(st->status_flags & DNET_STATUS_RO));

	if (st->status_flags != -1) {
		if (st->status_flags & DNET_STATUS_EXIT) {
			dnet_set_need_exit(n);
		}

		if (st->status_flags & DNET_STATUS_RO) {
			n->ro = 1;
		} else {
			n->ro = 0;
		}
	}

	if (st->nflags != -1)
		n->flags = st->nflags;

	if (st->log_level != ~0U)
		dnet_log_set_verbosity(n->log, (enum dnet_log_level)st->log_level);

	st->nflags = n->flags;
	st->log_level = dnet_log_get_verbosity(n->log);
	st->status_flags = 0;

	if (n->need_exit)
		st->status_flags |= DNET_STATUS_EXIT;

	if (n->ro)
		st->status_flags |= DNET_STATUS_RO;

	dnet_convert_node_status(st);

	return dnet_send_reply(orig, cmd, st, sizeof(struct dnet_node_status), 1);
}

static int dnet_cmd_auth(struct dnet_net_state *orig, struct dnet_cmd *cmd __unused, void *data)
{
	struct dnet_node *n = orig->n;
	struct dnet_auth *a = data;
	int err = 0;

	if (cmd->size != sizeof(struct dnet_auth)) {
		err = -EINVAL;
		goto err_out_exit;
	}

	dnet_convert_auth(a);
	if (memcmp(n->cookie, a->cookie, DNET_AUTH_COOKIE_SIZE)) {
		err = -EPERM;
		dnet_log(n, DNET_LOG_ERROR, "%s: auth cookies do not match", dnet_state_dump_addr(orig));
	} else {
		dnet_log(n, DNET_LOG_INFO, "%s: authentication succeeded", dnet_state_dump_addr(orig));
	}

err_out_exit:
	return err;
}

int dnet_send_ack(struct dnet_net_state *st, struct dnet_cmd *cmd, int err, int recursive)
{
	if (st && cmd && (cmd->flags & DNET_FLAGS_NEED_ACK)) {
		struct dnet_node *n = st->n;
		unsigned long long tid = cmd->trans;
		struct dnet_cmd ack = *cmd;

		ack.trans = cmd->trans;
		ack.size = 0;
		// In recursive mode keep DNET_FLAGS_MORE flag
		if (recursive)
			ack.flags = cmd->flags & ~(DNET_FLAGS_NEED_ACK);
		else
			ack.flags = cmd->flags & ~(DNET_FLAGS_NEED_ACK | DNET_FLAGS_MORE);
		ack.flags |= DNET_FLAGS_REPLY;
		ack.status = err;

		dnet_log(n, DNET_LOG_NOTICE, "%s: %s: ack -> %s: trans: %llu, flags: %s, status: %d.",
				dnet_dump_id(&cmd->id), dnet_cmd_string(cmd->cmd), dnet_addr_string(&st->addr),
				tid, dnet_flags_dump_cflags(ack.flags), err);

		dnet_convert_cmd(&ack);
		err = dnet_send(st, &ack, sizeof(struct dnet_cmd));
	}

	return err;
}

int dnet_send_reply(void *state, struct dnet_cmd *cmd, const void *odata, unsigned int size, int more)
{
	struct dnet_net_state *st = state;
	struct dnet_cmd *c;
	void *data;
	int err;

	c = malloc(sizeof(struct dnet_cmd) + size);
	if (!c)
		return -ENOMEM;

	memset(c, 0, sizeof(struct dnet_cmd) + size);

	data = c + 1;
	*c = *cmd;

	if ((cmd->flags & DNET_FLAGS_NEED_ACK) || more)
		c->flags |= DNET_FLAGS_MORE;

	c->size = size;
	c->flags |= DNET_FLAGS_REPLY;

	if (size)
		memcpy(data, odata, size);

	dnet_log(st->n, DNET_LOG_NOTICE, "%s: %s: reply -> %s (%p): trans: %lld, size: %u, cflags: %s",
		dnet_dump_id(&cmd->id), dnet_cmd_string(cmd->cmd), dnet_state_dump_addr(st), st,
		(unsigned long long)c->trans,
		size, dnet_flags_dump_cflags(c->flags));

	dnet_convert_cmd(c);

	err = dnet_send(st, c, sizeof(struct dnet_cmd) + size);
	free(c);

	return err;
}

/*
 * Queue replies to send queue wrt high and low watermark limits.
 * This is usefull to avoid memory bloat (and hence OOM) when data gets queued
 * into send queue faster than it could be send over wire.
 */
int dnet_send_reply_threshold(void *state, struct dnet_cmd *cmd,
		const void *odata, unsigned int size, int more)
{
	struct dnet_net_state *st = state;
	int err;

	if (st == st->n->st)
		return 0;

	/* Send reply */
	err = dnet_send_reply(state, cmd, odata, size, more);
	if (err == 0)
		/* If send succeeded then we should increase queue size */
		if (atomic_inc(&st->send_queue_size) > DNET_SEND_WATERMARK_HIGH) {
			/* If high watermark is reached we should sleep */
			dnet_log(st->n, DNET_LOG_DEBUG,
					"State high_watermark reached: %s: %d, sleeping",
					dnet_addr_string(&st->addr),
					atomic_read(&st->send_queue_size));

			pthread_mutex_lock(&st->send_lock);
			// after successful dnet_send_reply the state can be removed from another thread
			// do not wait send_wait of removed state because no one broadcast it
			if (!st->__need_exit)
				pthread_cond_wait(&st->send_wait, &st->send_lock);
			else
				err = st->__need_exit;
			pthread_mutex_unlock(&st->send_lock);

			dnet_log(st->n, DNET_LOG_DEBUG, "State woken up: %s: %d",
					dnet_addr_string(&st->addr),
					atomic_read(&st->send_queue_size));
		}

	return err;
}

/*!
 * Internal callback that writes result to \a fd opened in append mode
 */
static int dnet_iterator_callback_file(void *priv, void *data, uint64_t dsize)
{
	struct dnet_iterator_file_private *file = priv;
	ssize_t err;

	err = write(file->fd, data, dsize);
	if (err == -1)
		return -errno;
	if (err != (ssize_t)dsize)
		return -EINTR;
	return 0;
}

/*!
 * Internal callback that sends result to state \a st
 */
static int dnet_iterator_callback_send(void *priv, void *data, uint64_t dsize)
{
	struct dnet_iterator_send_private *send = priv;

	/*
	 * If need_exit is set - skips sending reply and return -EINTR to
	 * interrupt execution of current iterator
	 */
	if (send->st->__need_exit) {
		dnet_log(send->st->n, DNET_LOG_ERROR,
				"%s: Interrupting iterator because peer has been disconnected",
				dnet_dump_id(&send->cmd->id));
		return -EINTR;
	}

	return dnet_send_reply_threshold(send->st, send->cmd, data, dsize, 1);
}

/*!
 * This routine decides whenever it's time for iterator to pause/cancel.
 *
 * While state is 'paused' - wait on condition variable.
 * If state is 'canceled' - exit with error.
 */
static int dnet_iterator_flow_control(struct dnet_iterator_common_private *ipriv)
{
	int err = 0;

	pthread_mutex_lock(&ipriv->it->lock);
	while (ipriv->it->state == DNET_ITERATOR_ACTION_PAUSE)
		err = pthread_cond_wait(&ipriv->it->wait, &ipriv->it->lock);
	if (ipriv->it->state == DNET_ITERATOR_ACTION_CANCEL)
		err = -ENOEXEC;
	pthread_mutex_unlock(&ipriv->it->lock);

	return err;
}

/*!
 * Common callback part that is run by all iterator types.
 * It's responsible for sanity checks and flow control.
 *
 * Also now it "prepares" data for next callback by combining data itself with
 * fixed-size response header.
 */
static int dnet_iterator_callback_common(void *priv, struct dnet_raw_id *key,
					 int fd, uint64_t data_offset, uint64_t dsize, struct dnet_ext_list *elist)
{
	struct dnet_iterator_common_private *ipriv = priv;
	struct dnet_iterator_response *response;
	static const uint64_t response_size = sizeof(struct dnet_iterator_response);
	uint64_t size;
	const uint64_t fsize = dsize;
	unsigned char *combined = NULL, *position;
	ssize_t bytes;
	int err = 0;
	uint64_t iterated_keys = 0;

	/* Sanity */
	if (ipriv == NULL || key == NULL || fd < 0 || elist == NULL)
		return -EINVAL;

	iterated_keys = atomic_inc(&ipriv->iterated_keys);

	/* If DNET_IFLAGS_TS_RANGE is set... */
	if (ipriv->req->flags & DNET_IFLAGS_TS_RANGE) {
		/* ...skip ts not in ts range */
		if (dnet_time_cmp(&elist->timestamp, &ipriv->req->time_begin) < 0 ||
		    dnet_time_cmp(&elist->timestamp, &ipriv->req->time_end) > 0) {
			goto key_skipped;
		}
	}

	/* Set data to NULL in case it's not requested */
	if (!(ipriv->req->flags & DNET_IFLAGS_DATA)) {
		dsize = 0;
	}
	size = response_size + dsize;

	/* Prepare combined buffer */
	position = combined = malloc(size);
	if (combined == NULL) {
		err = -ENOMEM;
		goto err_out_exit;
	}

	atomic_set(&ipriv->skipped_keys, 0);

	/* Response */
	response = (struct dnet_iterator_response *)combined;
	memset(response, 0, response_size);
	response->key = *key;
	response->timestamp = elist->timestamp;
	response->user_flags = elist->flags;
	response->size = fsize;
	response->total_keys = ipriv->total_keys;
	response->iterated_keys = iterated_keys;
	dnet_convert_iterator_response(response);

	/* Data */
	err = dnet_read_ll(fd, position, dsize, data_offset);
	if (err)
		goto err_out_exit;

	/* Finally run next callback */
	err = ipriv->next_callback(ipriv->next_private, combined, size);
	if (err)
		goto err_out_exit;

	/* Check that we are allowed to run */
	err = dnet_iterator_flow_control(ipriv);

	goto err_out_exit;

key_skipped:
	if (atomic_inc(&ipriv->skipped_keys) == 10000) {
		atomic_sub(&ipriv->skipped_keys, 10000);
		size = response_size;
		combined = malloc(size);
		if (combined == NULL) {
			err = -ENOMEM;
			goto err_out_exit;
		}
		response = (struct dnet_iterator_response *)combined;
		memset(response, 0, response_size);
		response->status = 1;
		response->total_keys = ipriv->total_keys;
		response->iterated_keys = iterated_keys;
		dnet_convert_iterator_response(response);

		/* Finally run next callback */
		err = ipriv->next_callback(ipriv->next_private, combined, size);
		if (err)
			goto err_out_exit;
	}

err_out_exit:
	free(combined);
	return err;
}

static int dnet_iterator_check_key_range(struct dnet_net_state *st, struct dnet_cmd *cmd,
		struct dnet_iterator_request *ireq,
		struct dnet_iterator_range *irange)
{
	unsigned int i;
	char k1[2*DNET_ID_SIZE+1];
	char k2[2*DNET_ID_SIZE+1];

	if (ireq->flags & DNET_IFLAGS_KEY_RANGE) {
		struct dnet_raw_id empty_key = { .id = {} };

		/* Unset DNET_IFLAGS_KEY_RANGE if all keys are empty */
		for (i = 0; i < ireq->range_num; ++i) {
			struct dnet_iterator_range *range = &irange[i];

			if (memcmp(&empty_key, &range->key_begin, sizeof(struct dnet_raw_id)) != 0
					|| memcmp(&empty_key, &range->key_end, sizeof(struct dnet_raw_id)) != 0) {
				break;
			}
		}

		if (i == ireq->range_num) {
			dnet_log(st->n, DNET_LOG_ERROR, "%s: all keys in all ranges are 0",
				dnet_dump_id(&cmd->id));
			ireq->flags &= ~DNET_IFLAGS_KEY_RANGE;
			return 0;
		}

		/* Check that each range is valid */
		for (i = 0; i < ireq->range_num; ++i) {
			struct dnet_iterator_range *range = &irange[i];

			if (dnet_id_cmp_str(range->key_begin.id, range->key_end.id) > 0) {
				dnet_log(st->n, DNET_LOG_ERROR, "%s: %u: key_begin (%s) > key_end (%s)",
					dnet_dump_id(&cmd->id), i,
					dnet_dump_id_len_raw(range->key_begin.id, DNET_ID_SIZE, k1),
					dnet_dump_id_len_raw(range->key_end.id, DNET_ID_SIZE, k2));
				return -ERANGE;
			}
		}

		for (i = 0; i < ireq->range_num; ++i) {
			struct dnet_iterator_range *range = &irange[i];

			dnet_log(st->n, DNET_LOG_NOTICE, "%s: using key range: %s...%s",
					dnet_dump_id(&cmd->id),
					dnet_dump_id_len_raw(range->key_begin.id, DNET_ID_SIZE, k1),
					dnet_dump_id_len_raw(range->key_end.id, DNET_ID_SIZE, k2));
		}
	}
	return 0;
}

static int dnet_iterator_check_ts_range(struct dnet_net_state *st, struct dnet_cmd *cmd,
		struct dnet_iterator_request *ireq)
{
	if (ireq->flags & DNET_IFLAGS_TS_RANGE) {
		struct dnet_time empty_time = {0, 0};
		/* Unset DNET_IFLAGS_KEY_RANGE if both times are empty */
		if (memcmp(&empty_time, &ireq->time_begin, sizeof(struct dnet_time)) == 0
				&& memcmp(&empty_time, &ireq->time_end, sizeof(struct dnet_time) == 0)) {
			dnet_log(st->n, DNET_LOG_NOTICE, "%s: both times are zero: cmd: %u",
				dnet_dump_id(&cmd->id), cmd->cmd);
			ireq->flags &= ~DNET_IFLAGS_TS_RANGE;
		}
		/* Check that range is valid */
		if (dnet_time_cmp(&ireq->time_begin, &ireq->time_end) > 0) {
			dnet_log(st->n, DNET_LOG_ERROR, "%s: time_begin > time_begin: cmd: %u",
				dnet_dump_id(&cmd->id), cmd->cmd);
			return -ERANGE;
		}
	}
	if (ireq->flags & DNET_IFLAGS_TS_RANGE)
		dnet_log(st->n, DNET_LOG_NOTICE, "%s: using ts range: "
				"%" PRIu64 ":%" PRIu64 "...%" PRIu64 ":%" PRIu64 "",
				dnet_dump_id(&cmd->id),
				ireq->time_begin.tsec, ireq->time_begin.tnsec,
				ireq->time_end.tsec, ireq->time_end.tnsec);
	return 0;
}

static int dnet_iterator_start(struct dnet_backend_io *backend, struct dnet_net_state *st, struct dnet_cmd *cmd,
		struct dnet_iterator_request *ireq,
		struct dnet_iterator_range *irange)
{
	struct dnet_iterator_common_private cpriv = {
		.req = ireq,
		.range = irange,
	};
	struct dnet_iterator_ctl ictl = {
		.iterate_private = backend->cb->command_private,
		.callback = dnet_iterator_callback_common,
		.callback_private = &cpriv,
	};
	struct dnet_iterator_send_private spriv;
	struct dnet_iterator_file_private fpriv;
	int err;

	/* Check flags */
	if ((ireq->flags & ~DNET_IFLAGS_ALL) != 0) {
		err = -ENOTSUP;
		goto err_out_exit;
	}

	/* Check callback type */
	if (ireq->itype <= DNET_ITYPE_FIRST || ireq->itype >= DNET_ITYPE_LAST) {
		err = -ENOTSUP;
		goto err_out_exit;
	}

	/* Check ranges */
	if ((err = dnet_iterator_check_key_range(st, cmd, ireq, irange)) ||
	    (err = dnet_iterator_check_ts_range(st, cmd, ireq)))
		goto err_out_exit;

	atomic_init(&cpriv.iterated_keys, 0);

	if (backend->cb->total_elements)
		cpriv.total_keys = backend->cb->total_elements(backend->cb->command_private);
	else
		cpriv.total_keys = 0;

	switch (ireq->itype) {
	case DNET_ITYPE_NETWORK:
		memset(&spriv, 0, sizeof(struct dnet_iterator_send_private));

		spriv.st = st;
		spriv.cmd = cmd;

		cpriv.next_callback = dnet_iterator_callback_send;
		cpriv.next_private = &spriv;
		break;
	case DNET_ITYPE_DISK:
		memset(&fpriv, 0, sizeof(struct dnet_iterator_file_private));
		cpriv.next_callback = dnet_iterator_callback_file;
		cpriv.next_private = &fpriv;
		/* TODO: Implement local file-based iterators */
		err = -ENOTSUP;
		goto err_out_exit;
	default:
		err = -EINVAL;
		goto err_out_exit;
	}

	/* Create iterator */
	cpriv.it = dnet_iterator_create(st->n);
	if (cpriv.it == NULL) {
		err = -ENOMEM;
		goto err_out_exit;
	}

	/* Run iterator */
	err = backend->cb->iterator(&ictl, ireq, irange);

	/* Remove iterator */
	dnet_iterator_destroy(st->n, cpriv.it);

err_out_exit:
	dnet_log(st->n, DNET_LOG_NOTICE, "%s: %s: iteration finished: err: %d",
			__func__, dnet_dump_id(&cmd->id), err);
	return err;
}

/*!
 * Starts low-level backend iterator and passes data to network or file
 */
static int dnet_cmd_iterator(struct dnet_backend_io *backend, struct dnet_net_state *st, struct dnet_cmd *cmd, void *data)
{
	struct dnet_iterator_request *ireq = data;
	struct dnet_iterator_range *irange = data + sizeof(struct dnet_iterator_request);
	int err = 0;

	/*
	 * Sanity
	 */
	if (ireq == NULL || st == NULL || cmd == NULL)
		return -EINVAL;
	dnet_convert_iterator_request(ireq);

	dnet_log(st->n, DNET_LOG_NOTICE,
			"%s: started: %s: id: %" PRIu64 ", action: %d",
			__func__, dnet_dump_id(&cmd->id), ireq->id, ireq->action);

	/*
	 * Check iterator action start/pause/cont
	 * On pause, find in list and mark as stopped
	 * On cont, find in list and mark as running, broadcast condition variable.
	 * On start, (surprise!) create and start iterator.
	 */
	switch (ireq->action) {
	case DNET_ITERATOR_ACTION_START:
		err = dnet_iterator_start(backend, st, cmd, ireq, irange);
		break;
	case DNET_ITERATOR_ACTION_PAUSE:
	case DNET_ITERATOR_ACTION_CONTINUE:
	case DNET_ITERATOR_ACTION_CANCEL:
		err = dnet_iterator_set_state(st->n, ireq->action, ireq->id);
		break;
	default:
		err = -EINVAL;
		goto err_out_exit;
	}

err_out_exit:
	dnet_log(st->n, DNET_LOG_NOTICE,
			"%s: finished: %s: id: %" PRIu64 ", action: %d, err: %d",
			__func__, dnet_dump_id(&cmd->id), ireq->id, ireq->action, err);
	return err;
}

static int dnet_cmd_bulk_read(struct dnet_backend_io *backend, struct dnet_net_state *st, struct dnet_cmd *cmd, void *data)
{
	int err = -1, ret;
	struct dnet_io_attr *io = data;
	struct dnet_io_attr *ios = io + 1;
	uint64_t count = 0;
	uint64_t i;

	struct dnet_cmd read_cmd = *cmd;
	read_cmd.size = sizeof(struct dnet_io_attr);
	read_cmd.cmd = DNET_CMD_READ;
	read_cmd.flags |= DNET_FLAGS_MORE;

	dnet_convert_io_attr(io);
	count = io->size / sizeof(struct dnet_io_attr);

	if (count > 0) {
		cmd->flags &= ~DNET_FLAGS_NEED_ACK;
	}

	/*
	 * we have to drop io lock, otherwise it will be grabbed again in dnet_process_cmd_raw() being recursively called
	 * Lock will be taken again after loop has been finished
	 */
	if (!(cmd->flags & DNET_FLAGS_NOLOCK)) {
		dnet_opunlock(st->n, &cmd->id);
	}

	dnet_log(st->n, DNET_LOG_NOTICE, "%s: starting BULK_READ for %d commands",
		dnet_dump_id(&cmd->id), (int) count);

	for (i = 0; i < count; i++) {
		ret = dnet_process_cmd_raw(backend, st, &read_cmd, &ios[i], 1);
		dnet_log(st->n, DNET_LOG_NOTICE, "%s: processing BULK_READ.READ for %d/%d command, err: %d",
			dnet_dump_id(&cmd->id), (int) i, (int) count, ret);

		if (i + 1 == count)
			cmd->flags |= DNET_FLAGS_NEED_ACK;

		if (!ret)
			err = 0;
		else if (err == -1)
			err = ret;
	}

	if (!(cmd->flags & DNET_FLAGS_NOLOCK)) {
		dnet_oplock(st->n, &cmd->id);
	}

	return err;
}

int dnet_cas_local(struct dnet_backend_io *backend, struct dnet_node *n, struct dnet_id *id, void *remote_csum, int csize)
{
	char csum[DNET_ID_SIZE];
	int err = 0;

	if (!backend->cb->checksum) {
		dnet_log(n, DNET_LOG_ERROR, "%s: cas: checksum operation is not supported in backend",
				dnet_dump_id(id));
		return -ENOTSUP;
	}

	err = backend->cb->checksum(n, backend->cb->command_private, id, csum, &csize);
	if (err != 0 && err != -ENOENT) {
		dnet_log(n, DNET_LOG_ERROR, "%s: cas: checksum operation failed", dnet_dump_id(id));
		return err;
	}

	/*
	 * If err == -ENOENT then there is no data to checksum, and CAS should succeed
	 * This is not 'client-safe' since two or more clients with unlocked CAS write
	 * may find out that there is no data and try to write their data, but we do not
	 * case about parallel writes being made without locks.
	 */

	if (err == 0) {
		if (memcmp(csum, remote_csum, DNET_ID_SIZE)) {
			char disk_csum[DNET_ID_SIZE * 2 + 1];
			char recv_csum[DNET_ID_SIZE * 2 + 1];

			dnet_dump_id_len_raw((const unsigned char *)csum, DNET_ID_SIZE, disk_csum);
			dnet_dump_id_len_raw(remote_csum, DNET_ID_SIZE, recv_csum);
			dnet_log(n, DNET_LOG_ERROR, "%s: cas: checksum mismatch: disk-csum: %s, recv-csum: %s",
					dnet_dump_id(id), disk_csum, recv_csum);
			return -EBADFD;
		} else if (dnet_log_enabled(n->log, DNET_LOG_NOTICE)) {
			char recv_csum[DNET_ID_SIZE * 2 + 1];

			dnet_dump_id_len_raw(remote_csum, DNET_ID_SIZE, recv_csum);
			dnet_log(n, DNET_LOG_NOTICE, "%s: cas: checksum; %s",
					dnet_dump_id(id), recv_csum);
		}
	}

	return err;
}

// Keep this enums in sync with enums from dnet_cmd_needs_backend
static int dnet_process_cmd_without_backend_raw(struct dnet_net_state *st, struct dnet_cmd *cmd, void *data)
{
	int err = 0;

	switch (cmd->cmd) {
		case DNET_CMD_AUTH:
			err = dnet_cmd_auth(st, cmd, data);
			break;
		case DNET_CMD_STATUS:
			err = dnet_cmd_status(st, cmd, data);
			break;
		case DNET_CMD_REVERSE_LOOKUP:
			err = dnet_route_list_reverse_lookup(st, cmd, data);
			break;
		case DNET_CMD_JOIN:
			err = dnet_route_list_join(st, cmd, data);
			break;
		case DNET_CMD_ROUTE_LIST:
			err = dnet_cmd_route_list(st, cmd);
			break;
		case DNET_CMD_EXEC:
			err = dnet_cmd_exec(st, cmd, data);
			break;
		case DNET_CMD_MONITOR_STAT:
			err = dnet_monitor_process_cmd(st, cmd, data);
			break;
		case DNET_CMD_BACKEND_CONTROL:
			err = dnet_cmd_backend_control(st, cmd, data);
			break;
		case DNET_CMD_BACKEND_STATUS:
			err = dnet_cmd_backend_status(st, cmd, data);
			break;
		default:
			err = -ENOTSUP;
			break;
	}

	return err;
}

static int dnet_process_cmd_with_backend_raw(struct dnet_backend_io *backend, struct dnet_net_state *st,
		struct dnet_cmd *cmd, void *data, int *handled_in_cache)
{
	int err = 0;
	struct dnet_node *n = st->n;
	struct dnet_io_attr *io = NULL;
	uint64_t iosize = 0;
	long diff;
	struct timeval start, end;

	gettimeofday(&start, NULL);

	// sleep before running a command, since for some commands ->command_handler sends reply itself,
	// and client will not wait for this thread to finish
	if (backend->delay) {
		long seconds = backend->delay / 1000;
		long useconds = (backend->delay % 1000) * 1000;

		if (seconds) {
			sleep(seconds);
		}

		if (useconds) {
			usleep(useconds);
		}
	}

	switch (cmd->cmd) {
		case DNET_CMD_ITERATOR:
			err = dnet_cmd_iterator(backend, st, cmd, data);
			break;
		case DNET_CMD_INDEXES_UPDATE:
		case DNET_CMD_INDEXES_INTERNAL:
		case DNET_CMD_INDEXES_FIND:
			err = dnet_process_indexes(backend, st, cmd, data);
			break;
		case DNET_CMD_NOTIFY:
			if (!(cmd->flags & DNET_ATTR_DROP_NOTIFICATION)) {
				err = dnet_notify_add(st, cmd);
				/*
				 * We drop 'need ack' flag, since notification
				 * transaction is a long-living one, since
				 * every notification will be sent as transaction
				 * completion.
				 *
				 * Transaction acknowledge will be sent when
				 * notification is removed.
				 */
				if (!err)
					cmd->flags &= ~DNET_FLAGS_NEED_ACK;
			} else
				err = dnet_notify_remove(st, cmd);
			break;
		case DNET_CMD_BULK_READ:
			err = backend->cb->command_handler(st, backend->cb->command_private, cmd, data);

			if (err == -ENOTSUP) {
				err = dnet_cmd_bulk_read(backend, st, cmd, data);
			}
			break;
		case DNET_CMD_READ:
		case DNET_CMD_WRITE:
		case DNET_CMD_DEL:
			if ((n->ro || backend->read_only) && ((cmd->cmd == DNET_CMD_DEL) || (cmd->cmd == DNET_CMD_WRITE))) {
				err = -EROFS;
				break;
			}

			io = NULL;
			if (cmd->size < sizeof(struct dnet_io_attr)) {
				dnet_log(st->n, DNET_LOG_ERROR, "%s: invalid size: cmd: %u, cmd.size: %llu",
					dnet_dump_id(&cmd->id), cmd->cmd, (unsigned long long)cmd->size);
				err = -EINVAL;
				break;
			}
			io = data;
			dnet_convert_io_attr(io);

			if (n->flags & DNET_CFG_NO_CSUM)
				io->flags |= DNET_IO_FLAGS_NOCSUM;

			if (!(io->flags & DNET_IO_FLAGS_NOCACHE)) {
				err = dnet_cmd_cache_io(backend, st, cmd, io, data + sizeof(struct dnet_io_attr));

				if (err != -ENOTSUP) {
					*handled_in_cache = 1;
					break;
				}
			}

			if ((io->flags & DNET_IO_FLAGS_COMPARE_AND_SWAP) && (cmd->cmd == DNET_CMD_WRITE)) {
				err = dnet_cas_local(backend, n, &cmd->id, io->parent, DNET_ID_SIZE);

				if (err != 0 && err != -ENOENT)
					break;
			}

			if (io->flags & DNET_IO_FLAGS_CACHE_ONLY)
				break;

			dnet_convert_io_attr(io);
		default:
			if (cmd->cmd == DNET_CMD_LOOKUP && !(cmd->flags & DNET_FLAGS_NOCACHE)) {
				err = dnet_cmd_cache_lookup(backend, st, cmd);

				if (err != -ENOTSUP) {
					*handled_in_cache = 1;
					break;
				}
			}

			/* Remove DNET_FLAGS_NEED_ACK flags for READ and WRITE commands
			   to eliminate double reply packets
			   (the first one with dnet_file_info structure or data has been read,
			   the second to destroy transaction on client side, i.e. packet without DNET_FLAGS_MORE bit) */
			if ((cmd->cmd == DNET_CMD_WRITE) || (cmd->cmd == DNET_CMD_READ) || (cmd->cmd == DNET_CMD_LOOKUP)) {
				cmd->flags &= ~DNET_FLAGS_NEED_ACK;
			}
			err = backend->cb->command_handler(st, backend->cb->command_private, cmd, data);

			/* If there was error in READ or WRITE command - send empty reply
			   to notify client with error code and destroy transaction */
			if (err && ((cmd->cmd == DNET_CMD_WRITE) || (cmd->cmd == DNET_CMD_READ) || (cmd->cmd == DNET_CMD_LOOKUP))) {
				cmd->flags |= DNET_FLAGS_NEED_ACK;
			}

			if (!err && (cmd->cmd == DNET_CMD_WRITE)) {
				dnet_update_notify(st, cmd, data);
			}
			break;
	}

	gettimeofday(&end, NULL);
	diff = DIFF(start, end);


	if (io) {
		iosize = io->size;

		// do not count error read size
		// otherwise it leads to HUGE read traffic stats, although nothing was actually read
		if (cmd->cmd == DNET_CMD_READ && err < 0)
			iosize = 0;
	}

	dnet_backend_command_stats_update(n, backend, cmd, iosize, *handled_in_cache, err, diff);
	return err;
}

int dnet_process_cmd_raw(struct dnet_backend_io *backend, struct dnet_net_state *st, struct dnet_cmd *cmd, void *data, int recursive)
{
	int err = 0;
	struct dnet_node *n = st->n;
	const unsigned long long tid = cmd->trans;
	struct dnet_io_attr *io = NULL;
	struct timeval start, end;
	uint64_t iosize = 0;

	long diff;
	int handled_in_cache = 0;

	HANDY_TIMER_SCOPE(recursive ? "io.cmd_recursive" : "io.cmd");
	FORMATTED(HANDY_TIMER_SCOPE, ("io.cmd%s.%s", (recursive ? "_recursive" : ""), dnet_cmd_string(cmd->cmd)));

	if (!(cmd->flags & DNET_FLAGS_NOLOCK)) {
		FORMATTED(HANDY_TIMER_SCOPE, ("io.cmd.%s.lock_time", dnet_cmd_string(cmd->cmd)));
		dnet_oplock(n, &cmd->id);
	}

	gettimeofday(&start, NULL);

	err = dnet_process_cmd_without_backend_raw(st, cmd, data);
	if (err == -ENOTSUP && backend) {
		err = dnet_process_cmd_with_backend_raw(backend, st, cmd, data, &handled_in_cache);
	}

	gettimeofday(&end, NULL);
	diff = DIFF(start, end);

	switch (cmd->cmd) {
		case DNET_CMD_READ:
		case DNET_CMD_WRITE:
		case DNET_CMD_DEL:
			if (cmd->size < sizeof(struct dnet_io_attr)) {
				dnet_log(st->n, DNET_LOG_ERROR, "%s: invalid size: cmd: %u, cmd.size: %llu",
					dnet_dump_id(&cmd->id), cmd->cmd, (unsigned long long)cmd->size);
				err = -EINVAL;
				break;
			}

			// no need to convert IO attribute here, it is aloready converted in backend processing code
			io = data;


			break;
		default:
			break;
	}

	if (((cmd->cmd == DNET_CMD_READ) || (cmd->cmd == DNET_CMD_WRITE)) && io) {
		char time_str[64];
		struct tm io_tm;
		struct timeval io_tv;

		/* io has been already set in the switch above */

		// do not count error read size
		// otherwise it leads to HUGE read traffic stats, although nothing was actually read
		iosize = io->size;
		if (cmd->cmd == DNET_CMD_READ && err < 0)
			iosize = 0;

		io_tv.tv_sec = io->timestamp.tsec;
		io_tv.tv_usec = io->timestamp.tnsec / 1000;

		localtime_r((time_t *)&io_tv.tv_sec, &io_tm);
		strftime(time_str, sizeof(time_str), "%F %R:%S", &io_tm);

		dnet_log(n, DNET_LOG_INFO, "%s: %s: client: %s, trans: %llu, cflags: %s, "
				"ioflags: %s, io-offset: %llu, io-size: %llu/%llu, io-user-flags: 0x%llx, ts: %ld.%06ld '%s.%06lu', "
				"time: %ld usecs, err: %d.",
				dnet_dump_id(&cmd->id), dnet_cmd_string(cmd->cmd), dnet_state_dump_addr(st),
				tid, dnet_flags_dump_cflags(cmd->flags),
				dnet_flags_dump_ioflags(io->flags),
				(unsigned long long)io->offset, (unsigned long long)io->size, (unsigned long long)io->total_size,
				(unsigned long long)io->user_flags,
				io_tv.tv_sec, io_tv.tv_usec, time_str, io_tv.tv_usec,
				diff, err);
	} else {
		dnet_log(n, DNET_LOG_INFO, "%s: %s: client: %s, trans: %llu, cflags: %s, time: %ld usecs, err: %d.",
				dnet_dump_id(&cmd->id), dnet_cmd_string(cmd->cmd), dnet_state_dump_addr(st),
				tid, dnet_flags_dump_cflags(cmd->flags), diff, err);
	}

	// we must provide real error from the backend into statistics
	dnet_monitor_stats_update(n, cmd, err, handled_in_cache, iosize, diff);

	err = dnet_send_ack(st, cmd, err, recursive);

	if (!(cmd->flags & DNET_FLAGS_NOLOCK))
		dnet_opunlock(n, &cmd->id);

	dnet_stat_inc(st->stat, cmd->cmd, err);
	if (st->__join_state == DNET_JOIN)
		dnet_counter_inc(n, cmd->cmd, err);
	else
		dnet_counter_inc(n, cmd->cmd + __DNET_CMD_MAX, err);

	return err;
}

int dnet_send_read_data(void *state, struct dnet_cmd *cmd, struct dnet_io_attr *io, void *data,
		int fd, uint64_t offset, int on_exit)
{
	struct dnet_net_state *st = state;
	struct dnet_node *n = st->n;
	struct dnet_cmd *c;
	struct dnet_io_attr *rio;
	int hsize = sizeof(struct dnet_cmd) + sizeof(struct dnet_io_attr);
	int err;
	long csum_time, send_time, total_time;
	struct timeval start_tv, csum_tv, send_tv;

	/*
	 * A simple hack to forbid read reply sending.
	 * It is used in local stat - we do not want to send stat data
	 * back to parental client, instead server will wrap data into
	 * proper transaction reply next to this obscure packet.
	 */
	if (io->flags & DNET_IO_FLAGS_SKIP_SENDING)
		return 0;

	gettimeofday(&start_tv, NULL);

	c = malloc(hsize);
	if (!c) {
		err = -ENOMEM;
		goto err_out_exit;
	}

	memset(c, 0, hsize);

	rio = (struct dnet_io_attr *)(c + 1);

	dnet_setup_id(&c->id, cmd->id.group_id, io->id);

	c->flags = cmd->flags & ~(DNET_FLAGS_NEED_ACK);
	if (cmd->flags & DNET_FLAGS_NEED_ACK)
		c->flags |= DNET_FLAGS_MORE;
	c->flags |= DNET_FLAGS_REPLY;

	c->size = sizeof(struct dnet_io_attr) + io->size;
	c->trans = cmd->trans;
	c->trace_id = cmd->trace_id;
	c->cmd = DNET_CMD_READ;
	c->backend_id = cmd->backend_id;

	memcpy(rio, io, sizeof(struct dnet_io_attr));

	dnet_convert_cmd(c);
	dnet_convert_io_attr(rio);

	if (io->flags & DNET_IO_FLAGS_CHECKSUM) {
		if (data) {
			err = dnet_checksum_data(n, data, rio->size, rio->parent, sizeof(rio->parent));
		} else {
			err = dnet_checksum_fd(n, fd, offset, rio->size, rio->parent, sizeof(rio->parent));
		}

		if (err)
			goto err_out_free;
	}

	gettimeofday(&csum_tv, NULL);

	if (data)
		err = dnet_send_data(st, c, hsize, data, rio->size);
	else
		err = dnet_send_fd(st, c, hsize, fd, offset, rio->size, on_exit);

	gettimeofday(&send_tv, NULL);

	csum_time = DIFF(start_tv, csum_tv);
	send_time = DIFF(csum_tv, send_tv);
	total_time = DIFF(start_tv, send_tv);

	dnet_log(n, DNET_LOG_INFO, "%s: %s: reply: cflags: %s, ioflags: %s, offset: %llu, size: %llu, csum-time: %ld, send-time: %ld, total-time: %ld usecs.",
			dnet_dump_id(&c->id), dnet_cmd_string(c->cmd),
			dnet_flags_dump_cflags(cmd->flags), dnet_flags_dump_ioflags(io->flags),
			(unsigned long long)io->offset,	(unsigned long long)io->size,
			csum_time, send_time, total_time);


err_out_free:
	free(c);
err_out_exit:
	return err;
}

static void dnet_fill_state_addr(void *state, struct dnet_addr *addr)
{
	struct dnet_net_state *st = state;
	struct dnet_node *n = st->n;

	memcpy(addr, &n->addrs[0], sizeof(struct dnet_addr));
}

static int dnet_fd_readlink(int fd, char **datap)
{
	char *dst, src[64];
	int dsize = 4096;
	int err;

	snprintf(src, sizeof(src), "/proc/self/fd/%d", fd);

	dst = malloc(dsize);
	if (!dst) {
		err = -ENOMEM;
		goto err_out_exit;
	}

	err = readlink(src, dst, dsize);
	if (err < 0)
		goto err_out_free;

	dst[err] = '\0';
	*datap = dst;

	return err + 1; /* including 0-byte */

err_out_free:
	free(dst);
err_out_exit:
	return err;
}

int dnet_send_file_info(void *state, struct dnet_cmd *cmd, int fd, uint64_t offset, int64_t size)
{
	struct dnet_node *n = dnet_get_node_from_state(state);
	struct dnet_file_info *info;
	struct dnet_addr *addr;
	int flen, err;
	char *file;
	struct stat st;

	err = dnet_fd_readlink(fd, &file);
	if (err < 0)
		goto err_out_exit;

	flen = err;

	addr = malloc(sizeof(struct dnet_addr) + sizeof(struct dnet_file_info) + flen);
	if (!addr) {
		err = -ENOMEM;
		goto err_out_free_file;
	}
	info = (struct dnet_file_info *)(addr + 1);

	dnet_fill_state_addr(state, addr);
	dnet_convert_addr(addr);

	err = fstat(fd, &st);
	if (err) {
		err = -errno;
		dnet_log(n, DNET_LOG_ERROR, "%s: file-info: %s: info-stat: %d: %s.",
				dnet_dump_id(&cmd->id), file, err, strerror(-err));
		goto err_out_free;
	}

	dnet_info_from_stat(info, &st);
	/* this is not valid data from raw blob file stat */
	info->mtime.tsec = 0;

	if (size >= 0)
		info->size = size;
	if (offset)
		info->offset = offset;

	if (cmd->flags & DNET_FLAGS_CHECKSUM) {
		err = dnet_checksum_fd(n, fd, info->offset, info->size, info->checksum, sizeof(info->checksum));
		if (err) {
			dnet_log(n, DNET_LOG_ERROR, "%s: file-info: %s: checksum: %d: %s.",
					dnet_dump_id(&cmd->id), file, err, strerror(-err));
			goto err_out_free;
		}
	}

	if (info->size == 0) {
		err = -EINVAL;
		dnet_log(n, DNET_LOG_NOTICE, "%s: EBLOB: %s: info-stat: ZERO-FILE-SIZE, fd: %d.",
				dnet_dump_id(&cmd->id), file, fd);
		goto err_out_free;
	}

	info->flen = flen;
	memcpy(info + 1, file, flen);

	dnet_convert_file_info(info);

	err = dnet_send_reply(state, cmd, addr, sizeof(struct dnet_addr) + sizeof(struct dnet_file_info) + flen, 0);

err_out_free:
	free(addr);
err_out_free_file:
	free(file);
err_out_exit:
	return err;
}

/*
 * @offset should be set not to offset within given record,
 * but offset within file descriptor
 */
int dnet_send_file_info_ts(void *state, struct dnet_cmd *cmd, int fd,
		uint64_t offset, int64_t size, struct dnet_time *timestamp)
{
	struct dnet_net_state *st = state;
	struct dnet_file_info *info;
	struct dnet_addr *a;
	size_t a_size = 0;
	int err, flen;
	char *file;

	/* Sanity */
	if (state == NULL || cmd == NULL || timestamp == NULL)
		return -EINVAL;
	if (size < 0 || fd < 0)
		return -EINVAL;

	flen = dnet_fd_readlink(fd, &file);
	if (flen < 0) {
		err = flen;
		goto err_out_exit;
	}

	a_size = sizeof(struct dnet_addr) + sizeof(struct dnet_file_info) + flen;
	a = calloc(1, a_size);
	if (a == NULL) {
		err = -ENOMEM;
		goto err_out_free_file;
	}

	info = (struct dnet_file_info *)(a + 1);

	dnet_fill_state_addr(state, a);
	dnet_convert_addr(a);

	info->offset = offset;
	info->size = size;
	info->mtime = *timestamp;
	info->flen = flen;
	memcpy(info + 1, file, flen);

	if (cmd->flags & DNET_FLAGS_CHECKSUM)
		dnet_checksum_fd(st->n, fd, info->offset,
				info->size, info->checksum, sizeof(info->checksum));

	dnet_convert_file_info(info);
	err = dnet_send_reply(state, cmd, a, a_size, 0);
	free(a);

err_out_free_file:
	free(file);
err_out_exit:
	return err;
}

int dnet_send_file_info_without_fd(void *state, struct dnet_cmd *cmd, const void *data, int64_t size)
{
	return dnet_send_file_info_ts_without_fd(state, cmd, data, size, NULL);
}

int dnet_send_file_info_ts_without_fd(void *state, struct dnet_cmd *cmd, const void *data, int64_t size, struct dnet_time *timestamp)
{
	struct dnet_net_state *st = state;
	struct dnet_file_info *info;
	struct dnet_addr *a;
	const size_t a_size = sizeof(struct dnet_addr) + sizeof(struct dnet_file_info) + 1;

	a = alloca(a_size);
	memset(a, 0, a_size);

	info = (struct dnet_file_info *)(a + 1);

	dnet_fill_state_addr(state, a);
	dnet_convert_addr(a);

	if (size >= 0)
		info->size = size;

	if (cmd->flags & DNET_FLAGS_CHECKSUM)
		dnet_checksum_data(st->n, data, size, info->checksum, sizeof(info->checksum));

	if (timestamp)
		info->mtime = *timestamp;

	dnet_convert_file_info(info);
	return dnet_send_reply(state, cmd, a, a_size, 0);
}

int dnet_checksum_data(struct dnet_node *n, const void *data, uint64_t size, unsigned char *csum, int csize)
{
	return dnet_transform_node(n, data, size, csum, csize);
}

int dnet_checksum_file(struct dnet_node *n, const char *file, uint64_t offset, uint64_t size, void *csum, int csize)
{
	int fd, err;

	err = open(file, O_RDONLY);

	if (err < 0) {
		err = -errno;
		dnet_log_err(n, "failed to open to be csummed file '%s'", file);
		goto err_out_exit;
	}
	fd = err;
	err = dnet_checksum_fd(n, fd, offset, size, csum, csize);
	close(fd);

err_out_exit:
	return err;
}

int dnet_checksum_fd(struct dnet_node *n, int fd, uint64_t offset, uint64_t size, void *csum, int csize)
{
	int err;

	if (!size) {
		struct stat st;

		err = fstat(fd, &st);
		if (err < 0) {
			err = -errno;
			dnet_log_err(n, "CSUM: fd: %d", fd);
			goto err_out_exit;
		}

		size = st.st_size;
	}

	err = dnet_transform_file(n, fd, offset, size, csum, csize);

err_out_exit:
	return err;
}
