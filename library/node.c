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

	err = pthread_mutex_init(&n->state_lock, NULL);
	if (err) {
		dnet_log_err(n, "Failed to initialize state lock: err: %d", err);
		goto err_out_free;
	}

	err = pthread_mutex_init(&n->trans_lock, NULL);
	if (err) {
		dnet_log_err(n, "Failed to initialize transaction lock: err: %d", err);
		goto err_out_destroy_state;
	}

	err = pthread_mutex_init(&n->tlock, NULL);
	if (err) {
		dnet_log_err(n, "Failed to initialize transformation lock: err: %d", err);
		goto err_out_destroy_trans;
	}
	
	err = pthread_mutex_init(&n->io_thread_lock, NULL);
	if (err) {
		dnet_log_err(n, "Failed to initialize IO thread lock: err: %d", err);
		goto err_out_destroy_tlock;
	}

	n->wait = dnet_wait_alloc(0);
	if (!n->wait) {
		dnet_log(n, DNET_LOG_ERROR, "Failed to allocate wait structure.\n");
		goto err_out_destroy_io_thread_lock;
	}

	INIT_LIST_HEAD(&n->tlist);
	INIT_LIST_HEAD(&n->state_list);
	INIT_LIST_HEAD(&n->empty_state_list);
	INIT_LIST_HEAD(&n->io_thread_list);

	return n;

err_out_destroy_io_thread_lock:
	pthread_mutex_destroy(&n->io_thread_lock);
err_out_destroy_tlock:
	pthread_mutex_destroy(&n->tlock);
err_out_destroy_trans:
	pthread_mutex_destroy(&n->trans_lock);
err_out_destroy_state:
	pthread_mutex_destroy(&n->state_lock);
err_out_free:
	free(n);
	return NULL;
}

void dnet_state_remove(struct dnet_net_state *st)
{
	struct dnet_node *n = st->n;

	pthread_mutex_lock(&n->state_lock);
	list_del(&st->state_entry);
	INIT_LIST_HEAD(&st->state_entry);
	pthread_mutex_unlock(&n->state_lock);
}

int dnet_state_insert(struct dnet_net_state *new)
{
	struct dnet_node *n = new->n;
	struct dnet_net_state *st;
	int err = 1;

	pthread_mutex_lock(&n->state_lock);

	list_for_each_entry(st, &n->state_list, state_entry) {
		err = dnet_id_cmp(st->id, new->id);

		if (!err) {
			dnet_log(n, DNET_LOG_ERROR, "%s: state exists: old: %s.\n", dnet_dump_id(st->id),
				dnet_server_convert_dnet_addr(&st->addr));
			dnet_log(n, DNET_LOG_ERROR, "%s: state exists: new: %s.\n", dnet_dump_id(new->id),
				dnet_server_convert_dnet_addr(&new->addr));
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

	pthread_mutex_unlock(&n->state_lock);

	if (!err)
		err = -EEXIST;
	else
		err = 0;

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

	pthread_mutex_lock(&n->state_lock);
	st = __dnet_state_search(n, id, self);
	pthread_mutex_unlock(&n->state_lock);

	return st;
}

struct dnet_net_state *dnet_state_get_first(struct dnet_node *n, unsigned char *id, struct dnet_net_state *self)
{
	struct dnet_net_state *st = NULL;
	int err = 0;

	pthread_mutex_lock(&n->state_lock);
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
	pthread_mutex_unlock(&n->state_lock);

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

	pthread_mutex_lock(&n->state_lock);
	st = __dnet_state_search(n, req, st);
	if (st) {
		prev = list_entry(st->state_entry.prev, struct dnet_net_state, state_entry);
		if (&prev->state_entry == &n->state_list)
			prev = NULL;
	}

	if (!prev && !list_empty(&n->state_list)) {
		prev = list_first_entry(&n->state_list, struct dnet_net_state, state_entry);
		dnet_log(n, DNET_LOG_INFO, "%s: getting first.\n", dnet_dump_id(prev->id));
	}

	if (prev) {
		dnet_log(n, DNET_LOG_INFO, "%s - %s\n", dnet_dump_id(prev->id), dnet_server_convert_dnet_addr(&prev->addr));
		snprintf(prev_id, sizeof(prev_id), "%s", dnet_dump_id(prev->id));
		dnet_log(n, DNET_LOG_INFO, "%s: range to %s\n", dnet_dump_id(req), prev_id);

		memcpy(id, prev->id, DNET_ID_SIZE);
		err = 0;
	}
	pthread_mutex_unlock(&n->state_lock);

	return err;
}

static void dnet_dummy_pipe_read(int s, short event, void *arg)
{
	struct dnet_io_thread *t = arg;
	struct dnet_node *n = t->node;

	dnet_log(n, DNET_LOG_NOTICE, "%s: thread control pipe event: %x.\n",
			dnet_dump_id(n->id), event);

	if (event & EV_READ) {
		unsigned long data;
		struct dnet_net_state *st;
		int err;

		err = read(s, &data, sizeof(unsigned long));
		if (err < 0) {
			err = -errno;
			if (err != -EAGAIN && err != -EINTR) {
				dnet_log_err(n, "failed to read from pipe");
				goto out;
			}

			goto out;
		}

		/*
		 * Size we read has to be smaller than atomic pipe IO size.
		 */

		st = (struct dnet_net_state *)data;

		dnet_event_schedule(st, EV_READ | EV_WRITE);
		dnet_state_put(st);
	}

out:
	event_add(&t->ev, NULL);
	return;
}

static void *dnet_io_thread_process(void *data)
{
	struct dnet_io_thread *t = data;
	struct dnet_node *n = t->node;
	int err = 0;
	struct timeval tv;
	sigset_t sig;

	sigemptyset(&sig);
	sigaddset(&sig, SIGPIPE);
	pthread_sigmask(SIG_BLOCK, &sig, NULL);

	tv.tv_sec = t->node->wait_ts.tv_sec;
	tv.tv_usec = t->node->wait_ts.tv_nsec / 1000;

	event_set(&t->ev, t->pipe[0], EV_READ, dnet_dummy_pipe_read, t);
	event_base_set(t->base, &t->ev);
	event_add(&t->ev, NULL);

	while (!t->need_exit) {
		//err = event_base_loopexit(t->base, &tv);
		err = event_base_dispatch(t->base);
		if (err) {
			dnet_log(n, DNET_LOG_NOTICE, "%s: thread %lu fails to "
					"process events: %d.\n",
					dnet_dump_id(t->node->id), t->tid, err);
			sleep(1);
		}
	}

	event_del(&t->ev);
	close(t->pipe[0]);
	close(t->pipe[1]);
	event_base_free(t->base);

	t->need_exit = err;
	return &t->need_exit;
}

static void dnet_stop_io_threads(struct dnet_node *n)
{
	struct dnet_io_thread *t, *tmp;

	list_for_each_entry_safe(t, tmp, &n->io_thread_list, thread_entry) {
		t->need_exit = 1;
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

		t->base = event_init();
		if (!t->base) {
			err = -errno;
			dnet_log(n, DNET_LOG_ERROR, "%s: failed to initialize event base.\n",
					dnet_dump_id(n->id));
			if (!err)
				err = -EINVAL;
			goto err_out_close;
		}

		err = pthread_create(&t->tid, NULL, dnet_io_thread_process, t);
		if (err) {
			dnet_log(n, DNET_LOG_ERROR, "%s: failed to create IO thread: err: %d.\n",
					dnet_dump_id(n->id), err);
			err = -err;
			goto err_out_free_base;
		}

		pthread_mutex_lock(&n->io_thread_lock);
		list_add_tail(&t->thread_entry, &n->io_thread_list);
		pthread_mutex_unlock(&n->io_thread_lock);
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
	n->wait_ts.tv_sec = cfg->wait_timeout;
	n->command_handler = cfg->command_handler;
	n->command_private = cfg->command_private;
	n->io_thread_num = cfg->io_thread_num;

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
		goto err_out_free;

	n->listen_socket = err;

	err = dnet_start_io_threads(n);
	if (err)
		goto err_out_sock_close;

	n->st = dnet_state_create(n, (cfg->join)?n->id:NULL, &n->addr, n->listen_socket);
	if (!n->st)
		goto err_out_stop_io_threads;

	dnet_log(n, DNET_LOG_INFO, "%s: new node has been created at %s, id_size: %u.\n",
			dnet_dump_id(n->id), dnet_dump_node(n), DNET_ID_SIZE);
	return n;

err_out_stop_io_threads:
	dnet_stop_io_threads(n);
err_out_sock_close:
	close(n->listen_socket);
err_out_free:
	free(n);
err_out_exit:
	return NULL;
}

void dnet_node_destroy(struct dnet_node *n)
{
	struct dnet_net_state *st, *tmp;

	dnet_log(n, DNET_LOG_INFO, "%s: destroying node at %s.\n", dnet_dump_id(n->id), dnet_dump_node(n));

	pthread_mutex_lock(&n->state_lock);
	list_for_each_entry_safe(st, tmp, &n->state_list, state_entry) {
		list_del(&st->state_entry);

		dnet_state_put(st);
	}
	pthread_mutex_unlock(&n->state_lock);

	dnet_stop_io_threads(n);

	close(n->listen_socket);

	pthread_mutex_destroy(&n->state_lock);
	pthread_mutex_destroy(&n->trans_lock);
	pthread_mutex_destroy(&n->tlock);

	dnet_wait_put(n->wait);

	free(n);
}

