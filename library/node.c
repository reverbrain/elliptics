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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>

#include "elliptics.h"
#include "dnet/interface.h"

static struct dnet_node *dnet_node_alloc(struct dnet_config *cfg)
{
	struct dnet_node *n;
	int err;

	n = malloc(sizeof(struct dnet_node));
	if (!n)
		return NULL;

	memset(n, 0, sizeof(struct dnet_node));

	n->trans = 0;
	n->trans_root = RB_ROOT;

	err = dnet_log_init(n, cfg->log_private, cfg->log_mask, cfg->log);
	if (err)
		goto err_out_free;

	err = pthread_rwlock_init(&n->state_lock, NULL);
	if (err) {
		dnet_log_err(n, "Failed to initialize state lock: err: %d", err);
		goto err_out_free;
	}

	err = dnet_lock_init(&n->trans_lock);
	if (err) {
		dnet_log_err(n, "Failed to initialize transaction lock: err: %d", err);
		goto err_out_destroy_state;
	}

	err = pthread_rwlock_init(&n->transform_lock, NULL);
	if (err) {
		dnet_log_err(n, "Failed to initialize transformation lock: err: %d", err);
		goto err_out_destroy_trans;
	}
	
	err = pthread_rwlock_init(&n->io_thread_lock, NULL);
	if (err) {
		dnet_log_err(n, "Failed to initialize IO thread lock: err: %d", err);
		goto err_out_destroy_transform_lock;
	}

	n->wait = dnet_wait_alloc(0);
	if (!n->wait) {
		dnet_log(n, DNET_LOG_ERROR, "Failed to allocate wait structure.\n");
		goto err_out_destroy_io_thread_lock;
	}

	err = pthread_mutex_init(&n->reconnect_lock, NULL);
	if (err) {
		err = -err;
		dnet_log_err(n, "Failed to initialize reconnection lock: err: %d", err);
		goto err_out_destroy_wait;
	}

	INIT_LIST_HEAD(&n->transform_list);
	INIT_LIST_HEAD(&n->state_list);
	INIT_LIST_HEAD(&n->empty_state_list);
	INIT_LIST_HEAD(&n->io_thread_list);
	INIT_LIST_HEAD(&n->reconnect_list);

	INIT_LIST_HEAD(&n->check_entry);

	return n;

err_out_destroy_wait:
	dnet_wait_put(n->wait);
err_out_destroy_io_thread_lock:
	pthread_rwlock_destroy(&n->io_thread_lock);
err_out_destroy_transform_lock:
	pthread_rwlock_destroy(&n->transform_lock);
err_out_destroy_trans:
	dnet_lock_destroy(&n->trans_lock);
err_out_destroy_state:
	pthread_rwlock_destroy(&n->state_lock);
err_out_free:
	free(n);
	return NULL;
}

void dnet_state_remove(struct dnet_net_state *st)
{
	struct dnet_node *n = st->n;

	pthread_rwlock_wrlock(&n->state_lock);
	list_del_init(&st->state_entry);
	pthread_rwlock_unlock(&n->state_lock);
}

static int dnet_state_insert_raw(struct dnet_net_state *new)
{
	struct dnet_node *n = new->n;
	struct dnet_net_state *st;
	int err = 1;

	list_for_each_entry(st, &n->state_list, state_entry) {
		err = dnet_id_cmp(st->id, new->id);

		if (!err) {
#if 0
			dnet_log(n, DNET_LOG_ERROR, "%s: state exists: old: %s.\n", dnet_dump_id(st->id),
				dnet_server_convert_dnet_addr(&st->addr));
			dnet_log(n, DNET_LOG_ERROR, "%s: state exists: new: %s.\n", dnet_dump_id(new->id),
				dnet_server_convert_dnet_addr(&new->addr));
#endif
			break;
		}

		if (err < 0) {
			dnet_log(n, DNET_LOG_NOTICE, "adding %s before %s.\n",
					dnet_server_convert_dnet_addr(&new->addr),
					dnet_dump_id(st->id));
			list_add_tail(&new->state_entry, &st->state_entry);
			break;
		}
	}

	if (err > 0) {
		dnet_log(n, DNET_LOG_NOTICE, "adding %s to the end.\n",
				dnet_server_convert_dnet_addr(&new->addr));
		list_add_tail(&new->state_entry, &n->state_list);
	}

	if (err) {
		dnet_log(n, DNET_LOG_INFO, "%s: node list dump:\n", dnet_dump_id(new->id));
		list_for_each_entry(st, &n->state_list, state_entry) {
			dnet_log(n, DNET_LOG_INFO, "      id: %s [%02x], addr: %s.\n",
				dnet_dump_id(st->id), st->id[0],
				dnet_server_convert_dnet_addr(&st->addr));
		}
	}

	if (!err)
		err = -EEXIST;
	else
		err = 0;

	return err;
}

int dnet_state_insert(struct dnet_net_state *st)
{
	int err;
	struct dnet_node *n = st->n;

	pthread_rwlock_wrlock(&n->state_lock);
	err = dnet_state_insert_raw(st);
	pthread_rwlock_unlock(&n->state_lock);

	return err;
}

static struct dnet_net_state *__dnet_state_search(struct dnet_node *n, unsigned char *id, struct dnet_net_state *self)
{
	struct dnet_net_state *st = NULL;
	int err = 1;

	list_for_each_entry(st, &n->state_list, state_entry) {
		if (st == self)
			continue;

		err = dnet_id_cmp(st->id, id);

		//dnet_log(n, DNET_LOG_INFO, "id: %02x, state: %02x, err: %d.\n", id[0], st->id[0], err);

		if (err <= 0) {
			dnet_state_get(st);
			break;
		}
	}

	if (err > 0)
		st = NULL;

	return st;
}

struct dnet_net_state *dnet_state_search(struct dnet_node *n, unsigned char *id, struct dnet_net_state *self)
{
	struct dnet_net_state *st;

	pthread_rwlock_rdlock(&n->state_lock);
	st = __dnet_state_search(n, id, self);
	pthread_rwlock_unlock(&n->state_lock);

	return st;
}

struct dnet_net_state *dnet_state_get_first(struct dnet_node *n, unsigned char *id, struct dnet_net_state *self)
{
	struct dnet_net_state *st = NULL;
	int err = 0;

	pthread_rwlock_rdlock(&n->state_lock);
	st = __dnet_state_search(n, id, self);

	if (!st) {
		err = -ENOENT;
		list_for_each_entry(st, &n->state_list, state_entry) {
			if (st == self)
				continue;

			dnet_state_get(st);
			err = 0;
			break;
		}
	}
	pthread_rwlock_unlock(&n->state_lock);

	if (err)
		return NULL;

	return st;
}

int dnet_state_get_range(void *state, unsigned char *req, unsigned char *id)
{
	struct dnet_net_state *st = state, *prev = NULL;
	struct dnet_node *n = st->n;
	int err = -ENOENT;
	char prev_id[64];

	pthread_rwlock_rdlock(&n->state_lock);
	st = __dnet_state_search(n, req, st);
	if (st) {
		prev = list_entry(st->state_entry.prev, struct dnet_net_state, state_entry);
		if (&prev->state_entry == &n->state_list)
			prev = NULL;
	}

	if (!prev && !list_empty(&n->state_list)) {
		prev = list_entry(n->state_list.prev, struct dnet_net_state, state_entry);
		dnet_log(n, DNET_LOG_INFO, "%s: last.\n", dnet_dump_id(prev->id));
	}

	if (prev) {
		dnet_log(n, DNET_LOG_INFO, "%s - %s\n", dnet_dump_id(prev->id),
				dnet_server_convert_dnet_addr(&prev->addr));
		snprintf(prev_id, sizeof(prev_id), "%s", dnet_dump_id(prev->id));
		dnet_log(n, DNET_LOG_INFO, "%s: range to %s\n", dnet_dump_id(req), prev_id);

		memcpy(id, prev->id, DNET_ID_SIZE);
		err = 0;
	}
	pthread_rwlock_unlock(&n->state_lock);

	return err;
}

struct dnet_net_state *dnet_state_get_next(struct dnet_net_state *st)
{
	struct dnet_net_state *next;
	struct dnet_node *n = st->n;

	pthread_rwlock_rdlock(&n->state_lock);
	next = list_entry(st->state_entry.next, struct dnet_net_state, state_entry);
	if (&next->state_entry == &n->state_list)
		next = NULL;

	if (!next && !list_empty(&n->state_list)) {
		next = list_entry(n->state_list.next, struct dnet_net_state, state_entry);
		dnet_log(n, DNET_LOG_INFO, "%s: getting first.\n", dnet_dump_id(next->id));
	}

	if (next) {
		dnet_log(n, DNET_LOG_INFO, "Sync to %s.\n", dnet_dump_id(next->id));
		dnet_state_get(next);
	}
	pthread_rwlock_unlock(&n->state_lock);

	return next;
}

struct dnet_net_state *dnet_state_get_prev(struct dnet_net_state *st)
{
	struct dnet_net_state *prev;
	struct dnet_node *n = st->n;

	pthread_rwlock_rdlock(&n->state_lock);
	prev = list_entry(st->state_entry.prev, struct dnet_net_state, state_entry);
	if (&prev->state_entry == &n->state_list)
		prev = NULL;

	if (!prev && !list_empty(&n->state_list)) {
		prev = list_entry(n->state_list.prev, struct dnet_net_state, state_entry);
		dnet_log(n, DNET_LOG_INFO, "%s: getting first.\n", dnet_dump_id(prev->id));
	}

	if (prev) {
		dnet_log(n, DNET_LOG_INFO, "Sync to %s.\n", dnet_dump_id(prev->id));
		dnet_state_get(prev);
	}
	pthread_rwlock_unlock(&n->state_lock);

	return prev;
}

int dnet_state_get_prev_id(struct dnet_node *n, unsigned char *id, unsigned char *res, int num)
{
	struct dnet_net_state *prev, *old_prev;

	prev = dnet_state_get_first(n, id, NULL);
	if (!prev)
		return -ENOENT;

	while (num) {
		old_prev = prev;
		prev = dnet_state_get_prev(old_prev);
		dnet_state_put(old_prev);

		if (!prev)
			return -ENOENT;

		num--;
	}

	memcpy(res, prev->id, DNET_ID_SIZE);
	dnet_state_put(prev);

	return 0;
}

int dnet_state_move(struct dnet_net_state *st)
{
	struct dnet_node *n = st->n;
	int err;

	dnet_log(n, DNET_LOG_INFO, "%s: moving state %s.\n", dnet_dump_id(st->id),
		dnet_server_convert_dnet_addr(&st->addr));

	pthread_rwlock_wrlock(&n->state_lock);
	list_del_init(&st->state_entry);

	err = dnet_state_insert_raw(st);
	pthread_rwlock_unlock(&n->state_lock);

	return err;
}

static void dnet_dummy_pipe_read(int s, short event, void *arg)
{
	struct dnet_io_thread *t = arg;
	struct dnet_node *n = t->node;
	struct dnet_thread_signal ts;
	int err;

	dnet_log(n, DNET_LOG_DSA, "%s: thread control pipe event: %x.\n",
			dnet_dump_id(n->id), event);

	if (!(event & EV_READ))
		return;

	while (1) {
		err = read(s, &ts, sizeof(struct dnet_thread_signal));
		if (err < 0) {
			err = -errno;
			if (err != -EAGAIN && err != -EINTR) {
				dnet_log_err(n, "failed to read from pipe");
				break;
			}

			break;
		}

		dnet_log(n, DNET_LOG_DSA, "thread: %lu, err: %d, cmd: %u, state: %s.\n",
				(unsigned long)t->tid, err, ts.cmd, ts.state?dnet_dump_id(ts.state->id):"raw");

		/*
		 * Size we read has to be smaller than atomic pipe IO size.
		 */

		switch (ts.cmd) {
			case DNET_THREAD_DATA_READY:
				dnet_event_schedule(ts.state, EV_READ | EV_WRITE);
				break;
			case DNET_THREAD_SCHEDULE:
				dnet_schedule_socket(ts.state);
				break;
			case DNET_THREAD_EXIT:
				event_base_loopexit(t->base, 0);
				break;
			default:
				break;
		}

		dnet_state_put(ts.state);
	}

	return;
}

static void *dnet_io_thread_process(void *data)
{
	struct dnet_io_thread *t = data;
	struct dnet_node *n = t->node;
	int err = 0;
	sigset_t sig;

	sigemptyset(&sig);
	sigaddset(&sig, SIGPIPE);
	pthread_sigmask(SIG_BLOCK, &sig, NULL);

	while (!t->need_exit) {
		err = event_base_dispatch(t->base);
		if (err) {
			dnet_log(n, DNET_LOG_NOTICE, "%s: thread %lu fails to "
					"process events: %d.\n",
					dnet_dump_id(t->node->id),
					(unsigned long)t->tid, err);
			sleep(1);
		}
	}

	event_del(&t->ev);
	close(t->pipe[0]);
	close(t->pipe[1]);
	event_base_free(t->base);

	t->need_exit = err;
	dnet_log(n, DNET_LOG_ERROR, "%s: thread %lu exiting with status %d.\n",
		dnet_dump_id(n->id), (unsigned long)t->tid, err);
	return &t->need_exit;
}

static void dnet_stop_io_threads(struct dnet_node *n)
{
	struct dnet_io_thread *t, *tmp;

	list_for_each_entry_safe(t, tmp, &n->io_thread_list, thread_entry) {
		t->need_exit = 1;
		
		dnet_signal_thread_raw(t, NULL, DNET_THREAD_EXIT);
		pthread_join(t->tid, NULL);

		list_del(&t->thread_entry);
		free(t);
	}
}

static int dnet_start_io_threads(struct dnet_node *n)
{
	int i, err;
	struct dnet_io_thread *t;

	dnet_log(n, DNET_LOG_NOTICE, "%s: starting %d IO threads.\n",
			dnet_dump_id(n->id), n->io_thread_num);
	for (i=0; i<n->io_thread_num; ++i) {
		t = malloc(sizeof(struct dnet_io_thread));
		if (!t) {
			err = -ENOMEM;
			goto err_out_free_all;
		}
		memset(t, 0, sizeof(struct dnet_io_thread));

		t->node = n;

		err = pipe(t->pipe);
		if (err) {
			err = -errno;
			dnet_log_err(n, "failed to create a dummy IO pipe");
			goto err_out_free;
		}

		fcntl(t->pipe[0], F_SETFL, O_NONBLOCK);

		t->base = event_init();
		if (!t->base) {
			err = -errno;
			dnet_log(n, DNET_LOG_ERROR, "%s: failed to initialize event base.\n",
					dnet_dump_id(n->id));
			if (!err)
				err = -EINVAL;
			goto err_out_close;
		}

		event_set(&t->ev, t->pipe[0], EV_READ | EV_PERSIST, dnet_dummy_pipe_read, t);
		event_base_set(t->base, &t->ev);
		event_add(&t->ev, NULL);

		err = pthread_create(&t->tid, NULL, dnet_io_thread_process, t);
		if (err) {
			dnet_log(n, DNET_LOG_ERROR, "%s: failed to create IO thread: err: %d.\n",
					dnet_dump_id(n->id), err);
			err = -err;
			goto err_out_free_base;
		}

		pthread_rwlock_wrlock(&n->io_thread_lock);
		list_add_tail(&t->thread_entry, &n->io_thread_list);
		pthread_rwlock_unlock(&n->io_thread_lock);
	}

	return 0;

err_out_free_base:
	event_base_free(t->base);
err_out_close:
	close(t->pipe[0]);
	close(t->pipe[1]);
err_out_free:
	free(t);
err_out_free_all:
	dnet_stop_io_threads(n);
	return err;
}

struct dnet_node *dnet_node_create(struct dnet_config *cfg)
{
	struct dnet_node *n;
	int err = -ENOMEM;
	sigset_t sig;

	sigemptyset(&sig);
	sigaddset(&sig, SIGPIPE);
	pthread_sigmask(SIG_BLOCK, &sig, NULL);

	if (cfg->join && !cfg->command_handler) {
		err = -EINVAL;
		if (cfg->log)
			cfg->log(cfg->log_private, DNET_LOG_ERROR, "Joining node has to register "
					"a comamnd handler.\n");
		goto err_out_exit;
	}

	n = dnet_node_alloc(cfg);
	if (!n) {
		err = -ENOMEM;
		goto err_out_exit;
	}

	memcpy(n->id, cfg->id, DNET_ID_SIZE);
	n->proto = cfg->proto;
	n->sock_type = cfg->sock_type;
	n->family = cfg->family;
	n->wait_ts.tv_sec = cfg->wait_timeout;
	n->command_handler = cfg->command_handler;
	n->command_private = cfg->command_private;
	n->io_thread_num = cfg->io_thread_num;
	n->notify_hash_size = cfg->hash_size;
	n->merge_strategy = cfg->merge_strategy;
	n->resend_count = cfg->resend_count;
	n->resend_timeout = cfg->resend_timeout;

	/*
	 * Only allow resends for client nodes,
	 * joined nodes only forward that data or store it locally.
	 */
	if (cfg->join)
		n->resend_count = 0;

	if (!n->resend_timeout.tv_sec && !n->resend_timeout.tv_nsec) {
		n->resend_timeout.tv_sec = DNET_DEFAULT_RESEND_TIMEOUT_SEC;
		dnet_log(n, DNET_LOG_ERROR, "%s: using default resend timeout (%ld seconds).\n",
				dnet_dump_id(n->id), n->resend_timeout.tv_sec);
	}

	if (!n->merge_strategy || n->merge_strategy >= __DNET_MERGE_MAX) {
		n->merge_strategy = DNET_MERGE_PREFER_NETWORK;
		dnet_log(n, DNET_LOG_ERROR, "%s: prefer network transaction log merge strategy.\n",
				dnet_dump_id(n->id));
	}

	if (!n->notify_hash_size) {
		n->notify_hash_size = DNET_DEFAULT_NOTIFY_HASH_SIZE;
		dnet_log(n, DNET_LOG_ERROR, "%s: no hash size provided, using default %d.\n",
				dnet_dump_id(n->id), n->notify_hash_size);
	}

	err = dnet_notify_init(n);
	if (err)
		goto err_out_free;

	if (!n->io_thread_num) {
		n->io_thread_num = DNET_IO_THREAD_NUM_DEFAULT;
		dnet_log(n, DNET_LOG_ERROR, "%s: no IO thread number provided, using default %d.\n",
				dnet_dump_id(n->id), n->io_thread_num);
	}
	
	n->max_pending = cfg->max_pending;
	if (!n->max_pending) {
		n->max_pending = DNET_IO_MAX_PENDING;
		dnet_log(n, DNET_LOG_ERROR, "%s: no maximum number of transaction from the same client "
				"processed in parallel, using default %llu.\n",
				dnet_dump_id(n->id), (unsigned long long)n->max_pending);
	}

	n->addr.addr_len = sizeof(n->addr.addr);

	err = dnet_socket_create(n, cfg, (struct sockaddr *)&n->addr.addr, &n->addr.addr_len, 1);
	if (err < 0)
		goto err_out_notify_exit;

	n->listen_socket = err;

	err = dnet_start_io_threads(n);
	if (err)
		goto err_out_sock_close;

	n->st = dnet_state_create(n, (cfg->join)?n->id:NULL, &n->addr, n->listen_socket);
	if (!n->st)
		goto err_out_stop_io_threads;

	err = dnet_resend_thread_start(n);
	if (err)
		goto err_out_state_destroy;

	dnet_log(n, DNET_LOG_INFO, "%s: new node has been created at %s, id_size: %u.\n",
			dnet_dump_id(n->id), dnet_dump_node(n), DNET_ID_SIZE);
	return n;

err_out_state_destroy:
	dnet_state_put(n->st);
err_out_stop_io_threads:
	dnet_stop_io_threads(n);
err_out_sock_close:
	close(n->listen_socket);
err_out_notify_exit:
	dnet_notify_exit(n);
err_out_free:
	free(n);
err_out_exit:
	if (cfg->log)
		cfg->log(cfg->log_private, DNET_LOG_ERROR, "Error during node creation.\n");
	return NULL;
}

void dnet_node_destroy(struct dnet_node *n)
{
	struct dnet_net_state *st, *tmp;
	struct dnet_addr_storage *it, *atmp;

	dnet_log(n, DNET_LOG_INFO, "%s: destroying node at %s.\n",
			dnet_dump_id(n->id), dnet_dump_node(n));

	n->need_exit = 1;
	dnet_resend_thread_stop(n);

	list_for_each_entry_safe(st, tmp, &n->empty_state_list, state_entry) {
		dnet_state_put(n->st);
	}

	dnet_check_tree(n, 1);
	list_for_each_entry_safe(st, tmp, &n->state_list, state_entry) {
		list_del_init(&st->state_entry);

		dnet_log(n, DNET_LOG_NOTICE, "%s: addr: %s, refcnt: %d.\n",
				dnet_dump_id(st->id), dnet_state_dump_addr(st), atomic_read(&st->refcnt));
		dnet_state_put(st);
	}

	dnet_stop_io_threads(n);

	pthread_rwlock_destroy(&n->state_lock);
	dnet_lock_destroy(&n->trans_lock);
	pthread_rwlock_destroy(&n->transform_lock);

	list_for_each_entry_safe(it, atmp, &n->reconnect_list, reconnect_entry) {
		list_del(&it->reconnect_entry);
		free(it);
	}
	pthread_mutex_destroy(&n->reconnect_lock);

	dnet_wait_put(n->wait);

	free(n);
}

