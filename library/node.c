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
#include "elliptics/interface.h"

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

	n->listen_socket = -1;

	err = dnet_log_init(n, cfg->log);
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

	err = pthread_rwlock_init(&n->io_thread_lock, NULL);
	if (err) {
		dnet_log_err(n, "Failed to initialize IO thread lock: err: %d", err);
		goto err_out_destroy_trans;
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

	err = pthread_attr_init(&n->attr);
	if (err) {
		err = -err;
		dnet_log_err(n, "Failed to initialize pthread attributes: err: %d", err);
		goto err_out_destroy_reconnect_lock;
	}

	err = pthread_attr_setstacksize(&n->attr, cfg->stack_size);
	if (err) {
		err = -err;
		dnet_log_err(n, "Failed to set stack size to %d, err: %d", cfg->stack_size, err);
		goto err_out_destroy_attr;
	}


	INIT_LIST_HEAD(&n->group_list);
	INIT_LIST_HEAD(&n->empty_state_list);
	INIT_LIST_HEAD(&n->io_thread_list);
	INIT_LIST_HEAD(&n->reconnect_list);

	INIT_LIST_HEAD(&n->check_entry);

	return n;

err_out_destroy_attr:
	pthread_attr_destroy(&n->attr);
err_out_destroy_reconnect_lock:
	pthread_mutex_destroy(&n->reconnect_lock);
err_out_destroy_wait:
	dnet_wait_put(n->wait);
err_out_destroy_io_thread_lock:
	pthread_rwlock_destroy(&n->io_thread_lock);
err_out_destroy_trans:
	dnet_lock_destroy(&n->trans_lock);
err_out_destroy_state:
	pthread_rwlock_destroy(&n->state_lock);
err_out_free:
	free(n);
	return NULL;
}

static struct dnet_group *dnet_group_create(unsigned int group_id)
{
	struct dnet_group *g;

	g = malloc(sizeof(struct dnet_group));
	if (!g)
		return NULL;

	memset(g, 0, sizeof(struct dnet_group));

	INIT_LIST_HEAD(&g->state_list);
	atomic_set(&g->refcnt, 1);
	g->group_id = group_id;

	return g;
}

void dnet_group_destroy(struct dnet_group *g)
{
	if (!list_empty(&g->state_list)) {
		fprintf(stderr, "BUG in dnet_group_destroy, reference leak.\n");
		exit(-1);
	}
	list_del(&g->group_entry);
	free(g);
}

static struct dnet_group *dnet_group_search(struct dnet_node *n, unsigned int group_id)
{
	struct dnet_group *g, *found = NULL;

	list_for_each_entry(g, &n->group_list, group_entry) {
		if (g->group_id == group_id) {
			found = dnet_group_get(g);
			break;
		}
	}

	return found;
}

void dnet_state_remove(struct dnet_net_state *st)
{
	struct dnet_node *n = st->n;

	pthread_rwlock_wrlock(&n->state_lock);
	list_del_init(&st->state_entry);
	pthread_rwlock_unlock(&n->state_lock);
}

int dnet_state_insert_raw(struct dnet_net_state *new)
{
	struct dnet_node *n = new->n;
	struct dnet_group *g;
	struct dnet_net_state *st;
	int err = 1;

	g = dnet_group_search(n, new->id.group_id);
	if (!g) {
		g = dnet_group_create(new->id.group_id);
		if (!g)
			return -ENOMEM;

		list_add_tail(&g->group_entry, &n->group_list);
	}

	new->group = g;

	list_for_each_entry(st, &g->state_list, state_entry) {
		err = dnet_id_cmp(&st->id, &new->id);

		if (!err) {
#if 0
			dnet_log(n, DNET_LOG_ERROR, "%s: state exists: old: %s.\n", dnet_dump_id(&st->id),
				dnet_server_convert_dnet_addr(&st->addr));
			dnet_log(n, DNET_LOG_ERROR, "%s: state exists: new: %s.\n", dnet_dump_id(&new->id),
				dnet_server_convert_dnet_addr(&new->addr));
#endif
			break;
		}

		if (err < 0) {
			dnet_log(n, DNET_LOG_DSA, "adding %s before %s.\n",
					dnet_server_convert_dnet_addr(&new->addr),
					dnet_dump_id(&st->id));
			list_add_tail(&new->state_entry, &st->state_entry);
			break;
		}
	}

	if (err > 0) {
		dnet_log(n, DNET_LOG_DSA, "adding %s to the end.\n",
				dnet_server_convert_dnet_addr(&new->addr));
		list_add_tail(&new->state_entry, &g->state_list);
	}

	if (err) {
		dnet_log(n, DNET_LOG_DSA, "%s: group: %u list dump:\n", dnet_dump_id(&new->id), g->group_id);
		list_for_each_entry(st, &g->state_list, state_entry) {
			dnet_log(n, DNET_LOG_DSA, "      id: %s, addr: %s.\n",
				dnet_dump_id(&st->id), dnet_server_convert_dnet_addr(&st->addr));
		}
	}

	if (!err) {
		err = -EEXIST;
		dnet_group_put(new->group);
		new->group = NULL;
	} else
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

static struct dnet_net_state *__dnet_state_search(struct dnet_node *n, struct dnet_id *id, struct dnet_net_state *self)
{
	struct dnet_net_state *st, *found = NULL;
	struct dnet_group *group;
	int cmp;

	group = dnet_group_search(n, id->group_id);
	if (!group)
		return NULL;

	list_for_each_entry(st, &group->state_list, state_entry) {
		if (st == self)
			continue;

		cmp = dnet_id_cmp(&st->id, id);

		dnet_log(n, DNET_LOG_DSA, "state search: group: %u, id: %02x, state: %02x, cmp: %d.\n",
				id->group_id, id->id[0], st->id.id[0], cmp);

		if (cmp <= 0) {
			found = st;
			dnet_state_get(found);
			break;
		}
	}

	dnet_group_put(group);

	return found;
}

struct dnet_net_state *dnet_state_search_by_addr(struct dnet_node *n, struct dnet_addr *addr)
{
	struct dnet_net_state *st, *found = NULL;
	struct dnet_group *g;

	pthread_rwlock_rdlock(&n->state_lock);
	list_for_each_entry(g, &n->group_list, group_entry) {
		list_for_each_entry(st, &g->state_list, state_entry) {
			if (!memcmp(addr, &st->addr, sizeof(struct dnet_addr))) {
				found = st;
				break;
			}
		}
		if (found) {
			dnet_state_get(found);
			break;
		}
	}
	pthread_rwlock_unlock(&n->state_lock);

	return found;
}

struct dnet_net_state *dnet_state_search(struct dnet_node *n, struct dnet_id *id, struct dnet_net_state *self)
{
	struct dnet_net_state *st;

	pthread_rwlock_rdlock(&n->state_lock);
	st = __dnet_state_search(n, id, self);
	pthread_rwlock_unlock(&n->state_lock);

	return st;
}

struct dnet_net_state *dnet_state_get_first(struct dnet_node *n, struct dnet_id *id, struct dnet_net_state *self)
{
	struct dnet_net_state *found;

	pthread_rwlock_rdlock(&n->state_lock);
	found = __dnet_state_search(n, id, self);
	if (!found) {
		struct dnet_group *g;
		struct dnet_net_state *st;

		g = dnet_group_search(n, id->group_id);
		if (!g)
			goto err_out_unlock;

		list_for_each_entry(st, &g->state_list, state_entry) {
			if (st == self)
				continue;

			found = st;
			dnet_state_get(found);
			break;
		}

		dnet_group_put(g);
	}

err_out_unlock:
	pthread_rwlock_unlock(&n->state_lock);
	return found;
}

int dnet_state_get_next_id(struct dnet_node *n, struct dnet_id *id)
{
	struct dnet_net_state *st, *next = NULL;
	struct dnet_group *g;

	pthread_rwlock_rdlock(&n->state_lock);
	st = __dnet_state_search(n, id, n->st);
	if (!st)
		goto err_out_unlock;

	g = dnet_group_search(n, id->group_id);
	if (!g)
		goto err_out_put;

	next = list_entry(st->state_entry.prev, struct dnet_net_state, state_entry);
	if (&next->state_entry == &g->state_list)
		next = list_entry(g->state_list.prev, struct dnet_net_state, state_entry);

	memcpy(id, &next->id, DNET_ID_SIZE);

	dnet_log(n, DNET_LOG_INFO, "st: %s\n", dnet_dump_id(&st->id));
	dnet_log(n, DNET_LOG_INFO, "nx: %s\n", dnet_dump_id(&next->id));

	dnet_group_put(g);

err_out_put:
	dnet_state_put(st);
err_out_unlock:
	dnet_log(n, DNET_LOG_INFO, "%s - %s\n", dnet_dump_id_len(id, DNET_ID_SIZE),
			dnet_server_convert_dnet_addr(&next->addr));

	pthread_rwlock_unlock(&n->state_lock);

	return 0;
}

struct dnet_node *dnet_node_create(struct dnet_config *cfg)
{
	struct dnet_node *n;
	int err = -ENOMEM;
	sigset_t sig;

	sigemptyset(&sig);
	sigaddset(&sig, SIGPIPE);
	pthread_sigmask(SIG_BLOCK, &sig, NULL);

	if ((cfg->join & DNET_JOIN_NETWORK) && !cfg->command_handler) {
		err = -EINVAL;
		if (cfg->log && cfg->log->log)
			cfg->log->log(cfg->log->log_private, DNET_LOG_ERROR, "Joining node has to register "
					"a comamnd handler.\n");
		goto err_out_exit;
	}

	if (!cfg->stack_size)
		cfg->stack_size = 100*1024;

	n = dnet_node_alloc(cfg);
	if (!n) {
		err = -ENOMEM;
		goto err_out_exit;
	}

	if (!cfg->sock_type)
		cfg->sock_type = SOCK_STREAM;
	if (!cfg->proto)
		cfg->proto = IPPROTO_TCP;
	if (!cfg->family)
		cfg->family = AF_INET;

	memcpy(&n->id, &cfg->id, sizeof(struct dnet_id));

	n->proto = cfg->proto;
	n->sock_type = cfg->sock_type;
	n->family = cfg->family;
	n->wait_ts.tv_sec = cfg->wait_timeout;
	n->command_handler = cfg->command_handler;
	n->command_private = cfg->command_private;
	n->notify_hash_size = cfg->hash_size;
	n->check_timeout = cfg->check_timeout;

	if (!n->log)
		dnet_log_init(n, cfg->log);

	if (!n->wait_ts.tv_sec)
		n->wait_ts.tv_sec = 60*60;

	dnet_log(n, DNET_LOG_NOTICE, "%s: using %d stack size.\n",
			dnet_dump_id(&n->id), cfg->stack_size);

	if (!n->check_timeout) {
		n->check_timeout = DNET_DEFAULT_CHECK_TIMEOUT_SEC;
		dnet_log(n, DNET_LOG_NOTICE, "%s: using default check timeout (%ld seconds).\n",
				dnet_dump_id(&n->id), n->check_timeout);
	}

	if (!n->notify_hash_size) {
		n->notify_hash_size = DNET_DEFAULT_NOTIFY_HASH_SIZE;
		dnet_log(n, DNET_LOG_NOTICE, "%s: no hash size provided, using default %d.\n",
				dnet_dump_id(&n->id), n->notify_hash_size);
	}

	if (cfg->join & DNET_JOIN_NETWORK) {
		err = dnet_db_init(n, cfg->history_env);
		if (err)
			goto err_out_free;
	}

	err = dnet_crypto_init(n);
	if (err)
		goto err_out_db_cleanup;

	err = dnet_notify_init(n);
	if (err)
		goto err_out_crypto_cleanup;

	if (cfg->join & DNET_JOIN_NETWORK) {
		n->addr.addr_len = sizeof(n->addr.addr);

		err = dnet_socket_create(n, cfg, (struct sockaddr *)&n->addr.addr, &n->addr.addr_len, 1);
		if (err < 0)
			goto err_out_notify_exit;

		n->listen_socket = err;

		n->st = dnet_state_create(n, (cfg->join & DNET_JOIN_NETWORK)?&n->id:NULL, &n->addr, n->listen_socket);
		if (!n->st) {
			close(n->listen_socket);
			goto err_out_notify_exit;
		}
	}

	err = dnet_check_thread_start(n);
	if (err)
		goto err_out_state_destroy;

	dnet_log(n, DNET_LOG_INFO, "%s: new node has been created at %s, id_size: %u.\n",
			dnet_dump_id(&n->id), dnet_dump_node(n), DNET_ID_SIZE);
	return n;

err_out_state_destroy:
	dnet_state_put(n->st);
err_out_notify_exit:
	dnet_notify_exit(n);
err_out_crypto_cleanup:
	dnet_crypto_cleanup(n);
err_out_db_cleanup:
	dnet_db_cleanup(n);
err_out_free:
	free(n);
err_out_exit:
	if (cfg->log && cfg->log->log)
		cfg->log->log(cfg->log->log_private, DNET_LOG_ERROR, "Error during node creation.\n");
	return NULL;
}

void dnet_node_destroy(struct dnet_node *n)
{
	struct dnet_addr_storage *it, *atmp;

	dnet_log(n, DNET_LOG_INFO, "%s: destroying node at %s, st: %p.\n",
			dnet_dump_id(&n->id), dnet_dump_node(n), n->st);

	n->need_exit = 1;
	dnet_check_thread_stop(n);

	dnet_check_tree(n, 1);

	while (!list_empty(&n->empty_state_list) || !list_empty(&n->group_list)) {
		dnet_log(n, DNET_LOG_NOTICE, "%s: waiting for state lists to become empty: empty_state_list: %d, group_list: %d.\n",
				dnet_dump_id(&n->id), list_empty(&n->empty_state_list), list_empty(&n->group_list));
		sleep(1);
	}

	dnet_notify_exit(n);

	dnet_db_cleanup(n);

	pthread_attr_destroy(&n->attr);

	pthread_rwlock_destroy(&n->state_lock);
	dnet_lock_destroy(&n->trans_lock);
	dnet_crypto_cleanup(n);

	list_for_each_entry_safe(it, atmp, &n->reconnect_list, reconnect_entry) {
		list_del(&it->reconnect_entry);
		free(it);
	}
	pthread_mutex_destroy(&n->reconnect_lock);

	dnet_wait_put(n->wait);

	free(n->groups);

	free(n);
}

void dnet_node_set_groups(struct dnet_node *n, int *groups, int group_num)
{
	free(n->groups);

	n->groups = groups;
	n->group_num = group_num;
}

void dnet_node_set_id(struct dnet_node *n, struct dnet_id *id)
{
	memcpy(&n->id, id, sizeof(struct dnet_id));
}
