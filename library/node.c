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

#include <sys/stat.h>

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

	atomic_init(&n->trans, 0);

	err = dnet_log_init(n, cfg->log);
	if (err)
		goto err_out_free;

	err = pthread_mutex_init(&n->state_lock, NULL);
	if (err) {
		dnet_log_err(n, "Failed to initialize state lock: err: %d", err);
		goto err_out_free;
	}

	n->wait = dnet_wait_alloc(0);
	if (!n->wait) {
		dnet_log(n, DNET_LOG_ERROR, "Failed to allocate wait structure.\n");
		goto err_out_destroy_state;
	}

	err = dnet_counter_init(n);
	if (err) {
		dnet_log_err(n, "Failed to initialize statictics counters lock: err: %d", err);
		goto err_out_destroy_wait;
	}

	err = pthread_mutex_init(&n->reconnect_lock, NULL);
	if (err) {
		err = -err;
		dnet_log_err(n, "Failed to initialize reconnection lock: err: %d", err);
		goto err_out_destroy_counter;
	}

	err = pthread_mutex_init(&n->group_lock, NULL);
	if (err) {
		err = -err;
		dnet_log_err(n, "Failed to initialize group lock: err: %d", err);
		goto err_out_destroy_reconnect_lock;
	}

	err = pthread_attr_init(&n->attr);
	if (err) {
		err = -err;
		dnet_log_err(n, "Failed to initialize pthread attributes: err: %d", err);
		goto err_out_destroy_group_lock;
	}
	pthread_attr_setdetachstate(&n->attr, PTHREAD_CREATE_DETACHED);

	INIT_LIST_HEAD(&n->group_list);
	INIT_LIST_HEAD(&n->empty_state_list);
	INIT_LIST_HEAD(&n->storage_state_list);
	INIT_LIST_HEAD(&n->reconnect_list);

	INIT_LIST_HEAD(&n->check_entry);

	memcpy(n->cookie, cfg->cookie, DNET_AUTH_COOKIE_SIZE);

	return n;

err_out_destroy_group_lock:
	pthread_mutex_destroy(&n->group_lock);
err_out_destroy_reconnect_lock:
	pthread_mutex_destroy(&n->reconnect_lock);
err_out_destroy_counter:
	dnet_counter_destroy(n);
err_out_destroy_wait:
	dnet_wait_put(n->wait);
err_out_destroy_state:
	pthread_mutex_destroy(&n->state_lock);
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

	atomic_init(&g->refcnt, 1);
	g->group_id = group_id;

	INIT_LIST_HEAD(&g->state_list);

	g->id_num = 0;
	g->ids = NULL;

	return g;
}

void dnet_group_destroy(struct dnet_group *g)
{
	if (!list_empty(&g->state_list)) {
		fprintf(stderr, "BUG in dnet_group_destroy, reference leak.\n");
		exit(-1);
	}
	list_del(&g->group_entry);
	free(g->ids);
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

static int dnet_idc_compare(const void *k1, const void *k2)
{
	const struct dnet_state_id *id1 = k1;
	const struct dnet_state_id *id2 = k2;

	return dnet_id_cmp_str(id1->raw.id, id2->raw.id);
}

static void dnet_idc_remove_ids(struct dnet_net_state *st, struct dnet_group *g)
{
	int i, pos;

	for (i=0, pos=0; i<g->id_num; ++i) {
		if (g->ids[i].idc != st->idc) {
			g->ids[pos] = g->ids[i];
			pos++;
		}
	}

	g->id_num = pos;

	qsort(g->ids,  g->id_num, sizeof(struct dnet_state_id), dnet_idc_compare);
	st->idc = NULL;
}

int dnet_idc_create(struct dnet_net_state *st, int group_id, struct dnet_raw_id *ids, int id_num)
{
	struct dnet_node *n = st->n;
	struct dnet_idc *idc;
	struct dnet_group *g;
	int err = -ENOMEM, i, num;
	struct timeval start, end;
	long diff;

	gettimeofday(&start, NULL);

	idc = malloc(sizeof(struct dnet_idc) + sizeof(struct dnet_state_id) * id_num);
	if (!idc)
		goto err_out_exit;

	memset(idc, 0, sizeof(struct dnet_idc));

	for (i=0; i<id_num; ++i) {
		struct dnet_state_id *sid = &idc->ids[i];
		memcpy(&sid->raw, &ids[i], sizeof(struct dnet_raw_id));
		sid->idc = idc;
	}

	pthread_mutex_lock(&n->state_lock);

	g = dnet_group_search(n, group_id);
	if (!g) {
		g = dnet_group_create(group_id);
		if (!g)
			goto err_out_unlock;

		list_add_tail(&g->group_entry, &n->group_list);
	}

	g->ids = realloc(g->ids, (g->id_num + id_num) * sizeof(struct dnet_state_id));
	if (!g->ids) {
		g->id_num = 0;
		goto err_out_unlock_put;
	}

	num = 0;
	for (i=0; i<id_num; ++i) {
		if (!bsearch(&idc->ids[i], g->ids, g->id_num, sizeof(struct dnet_state_id), dnet_idc_compare)) {
			memcpy(&g->ids[g->id_num + num], &idc->ids[i], sizeof(struct dnet_state_id));
			num++;
		}
	}

	if (!num) {
		err = -EEXIST;
		goto err_out_unlock_put;
	}

	g->id_num += num;
	qsort(g->ids, g->id_num, sizeof(struct dnet_state_id), dnet_idc_compare);

	list_add_tail(&st->state_entry, &g->state_list);
	list_add_tail(&st->storage_state_entry, &n->storage_state_list);

	idc->id_num = id_num;
	idc->st = st;
	idc->group = g;

	st->idc = idc;

	if (n->log->log_mask & DNET_LOG_DSA) {
		for (i=0; i<g->id_num; ++i) {
			struct dnet_state_id *id = &g->ids[i];
			dnet_log(n, DNET_LOG_DSA, "%d: %s -> %s\n", g->group_id, dnet_dump_id_str(id->raw.id), dnet_state_dump_addr(id->idc->st));
		}
	}

	err = dnet_setup_control_nolock(st);
	if (err)
		goto err_out_remove_nolock;

	pthread_mutex_unlock(&n->state_lock);

	gettimeofday(&end, NULL);
	diff = (end.tv_sec - start.tv_sec) * 1000000 + end.tv_usec - start.tv_usec;

	dnet_log(n, DNET_LOG_NOTICE, "Initialized group: %d, total ids: %d, added ids: %d out of %d: %ld usecs.\n",
			g->group_id, g->id_num, num, id_num, diff);

	if (n->server_prio) {
		err = setsockopt(st->read_s, SOL_SOCKET, SO_PRIORITY, &n->server_prio, 4);
		if (err) {
			err = -errno;
			dnet_log_err(n, "could not set read server prio %d", n->server_prio);
		}
		err = setsockopt(st->write_s, SOL_SOCKET, SO_PRIORITY, &n->server_prio, 4);
		if (err) {
			err = -errno;
			dnet_log_err(n, "could not set write server prio %d", n->server_prio);
		}

		if (!err) {
			dnet_log(n, DNET_LOG_INFO, "Server net priority set to %d\n", n->server_prio);
		}
	}

	return 0;

err_out_remove_nolock:
	dnet_idc_remove_ids(st, g);
	list_del_init(&st->state_entry);
	list_del_init(&st->storage_state_entry);
err_out_unlock_put:
	dnet_group_put(g);
err_out_unlock:
	pthread_mutex_unlock(&n->state_lock);
	free(idc);
err_out_exit:
	gettimeofday(&end, NULL);
	diff = (end.tv_sec - start.tv_sec) * 1000000 + end.tv_usec - start.tv_usec;
	dnet_log(n, DNET_LOG_ERROR, "Failed to initialized group %d with %d ids: err: %d: %ld usecs.\n", group_id, id_num, err, diff);
	return err;
}

void dnet_idc_destroy_nolock(struct dnet_net_state *st)
{
	struct dnet_idc *idc;
	struct dnet_group *g;

	idc = st->idc;
	if (!idc)
		return;

	g = idc->group;
	dnet_idc_remove_ids(st, g);
	dnet_group_put(g);
	free(idc);
}

static int __dnet_idc_search(struct dnet_group *g, struct dnet_id *id)
{
	int low, high, i, cmp;
	struct dnet_state_id *sid;

	for (low = -1, high = g->id_num; high-low > 1; ) {
		i = low + (high - low)/2;
		sid = &g->ids[i];

		cmp = dnet_id_cmp_str(sid->raw.id, id->id);
		if (cmp < 0)
			low = i;
		else if (cmp > 0)
			high = i;
		else
			goto out;
	}
	i = high - 1;

out:
	if (i == -1)
		i = g->id_num - 1;

	dnet_log(g->ids[0].idc->st->n, DNET_LOG_DSA, "%s: found idc pos: %d\n", dnet_dump_id(id), i);

	return i;
}

static struct dnet_state_id *dnet_idc_search(struct dnet_group *g, struct dnet_id *id)
{
	return &g->ids[__dnet_idc_search(g, id)];
}

static int dnet_search_range_nolock(struct dnet_node *n, struct dnet_id *id, struct dnet_raw_id *start, struct dnet_raw_id *next)
{
	struct dnet_state_id *sid;
	struct dnet_group *group;
	int idc_pos;

	group = dnet_group_search(n, id->group_id);
	if (!group)
		return -ENOENT;

	idc_pos = __dnet_idc_search(group, id);
	sid = &group->ids[idc_pos];
	memcpy(start, &sid->raw, sizeof(struct dnet_raw_id));

	if (++idc_pos >= group->id_num)
		idc_pos = 0;
	sid = &group->ids[idc_pos];
	memcpy(next, &sid->raw, sizeof(struct dnet_raw_id));

	dnet_group_put(group);

	return 0;
}

int dnet_search_range(struct dnet_node *n, struct dnet_id *id, struct dnet_raw_id *start, struct dnet_raw_id *next)
{
	int err;

	pthread_mutex_lock(&n->state_lock);
	err = dnet_search_range_nolock(n, id, start, next);
	pthread_mutex_unlock(&n->state_lock);

	return err;
}

static struct dnet_state_id *__dnet_state_search_id(struct dnet_node *n, struct dnet_id *id)
{
	struct dnet_state_id *sid;
	struct dnet_group *group;

	group = dnet_group_search(n, id->group_id);
	if (!group)
		return NULL;

	sid = dnet_idc_search(group, id);

	dnet_group_put(group);

	return sid;
}

static struct dnet_net_state *__dnet_state_search(struct dnet_node *n, struct dnet_id *id)
{
	struct dnet_state_id *sid = __dnet_state_search_id(n, id);

	if (!sid)
		return NULL;

	return dnet_state_get(sid->idc->st);
}

struct dnet_net_state *dnet_state_search_by_addr(struct dnet_node *n, struct dnet_addr *addr)
{
	struct dnet_net_state *st, *found = NULL;
	struct dnet_group *g;

	pthread_mutex_lock(&n->state_lock);
	list_for_each_entry(g, &n->group_list, group_entry) {
		list_for_each_entry(st, &g->state_list, state_entry) {
			if (st->addr.addr_len == addr->addr_len &&
					!memcmp(addr, &st->addr, st->addr.addr_len)) {
				found = st;
				break;
			}
		}
		if (found) {
			dnet_state_get(found);
			break;
		}
	}
	pthread_mutex_unlock(&n->state_lock);

	return found;
}

struct dnet_net_state *dnet_state_search_nolock(struct dnet_node *n, struct dnet_id *id)
{
	struct dnet_net_state *found;

	found = __dnet_state_search(n, id);
	if (!found) {
		struct dnet_group *g;

		g = dnet_group_search(n, id->group_id);
		if (!g)
			goto err_out_exit;

		found = dnet_state_get(g->ids[0].idc->st);
		dnet_group_put(g);
	}

err_out_exit:
	return found;
}

struct dnet_net_state *dnet_state_get_first(struct dnet_node *n, struct dnet_id *id)
{
	struct dnet_net_state *found;

	pthread_mutex_lock(&n->state_lock);
	found = dnet_state_search_nolock(n, id);
	if (found == n->st) {
		dnet_state_put(found);
		found = NULL;
	}

	pthread_mutex_unlock(&n->state_lock);

	return found;
}

/*
 * We do not blindly return n->st, since it will go away eventually,
 * since we want multiple states/listen sockets per single node
 */
struct dnet_net_state *dnet_node_state(struct dnet_node *n)
{
	struct dnet_net_state *found;

	pthread_mutex_lock(&n->state_lock);
	found = dnet_state_search_nolock(n, &n->id);
	pthread_mutex_unlock(&n->state_lock);

	return found;
}

static int dnet_ids_generate(struct dnet_node *n, const char *file, unsigned long long storage_free)
{
	int fd, err, size = 1024, i, num;
	struct dnet_id id;
	struct dnet_raw_id raw;
	unsigned long long q = 100 * 1024 * 1024 * 1024ULL;
	char *buf;

	srand(time(NULL) + (unsigned long)n + (unsigned long)file + (unsigned long)&buf);

	fd = open(file, O_RDWR | O_CREAT | O_TRUNC | O_APPEND, 0644);
	if (fd < 0) {
		err = -errno;
		dnet_log_err(n, "failed to open/create ids file '%s'", file);
		goto err_out_exit;
	}

	buf = malloc(size);
	if (!buf) {
		err = -ENOMEM;
		goto err_out_close;
	}

	num = storage_free / q + 1;
	for (i=0; i<num; ++i) {
		int r = rand();
		memcpy(buf, &n->addr, sizeof(struct dnet_addr));
		memcpy(buf + sizeof(struct dnet_addr), &r, sizeof(r));

		dnet_transform(n, buf, size, &id);
		memcpy(&raw, id.id, sizeof(struct dnet_raw_id));

		err = write(fd, &raw, sizeof(struct dnet_raw_id));
		if (err != sizeof(struct dnet_raw_id)) {
			dnet_log_err(n, "failed to write id into ids file '%s'", file);
			goto err_out_unlink;
		}
	}

	close(fd);
	return 0;

err_out_unlink:
	unlink(file);
err_out_close:
	close(fd);
err_out_exit:
	return err;
}

static struct dnet_raw_id *dnet_ids_init(struct dnet_node *n, const char *hdir, int *id_num, unsigned long long storage_free)
{
	int fd, err, num;
	const char *file = "ids";
	char path[strlen(hdir) + 1 + strlen(file) + 1]; /* / + null-byte */
	struct stat st;
	struct dnet_raw_id *ids;

	snprintf(path, sizeof(path), "%s/%s", hdir, file);

again:
	fd = open(path, O_RDONLY);
	if (fd < 0) {
		err = -errno;
		if (err == -ENOENT) {
			err = dnet_ids_generate(n, path, storage_free);
			if (err)
				goto err_out_exit;

			goto again;
		}

		dnet_log_err(n, "failed to open ids file '%s'", path);
		goto err_out_exit;
	}

	err = fstat(fd, &st);
	if (err)
		goto err_out_close;

	if (st.st_size % sizeof(struct dnet_raw_id)) {
		dnet_log(n, DNET_LOG_ERROR, "Ids file size (%lu) is wrong, must be modulo of raw ID size (%zu).\n",
				(unsigned long)st.st_size, sizeof(struct dnet_raw_id));
		goto err_out_close;
	}

	num = st.st_size / sizeof(struct dnet_raw_id);

	dnet_log(n, DNET_LOG_DSA, "Reading ids file: %d ids found.\n", num);

	if (!num) {
		dnet_log(n, DNET_LOG_ERROR, "No ids read, exiting.\n");
		err = -EINVAL;
		goto err_out_close;
	}

	ids = malloc(st.st_size);
	if (!ids) {
		err = -ENOMEM;
		goto err_out_close;
	}

	err = read(fd, ids, st.st_size);
	if (err != st.st_size) {
		err = -errno;
		dnet_log_err(n, "Failed to read ids file '%s'", path);
		goto err_out_free;
	}

	close(fd);

	*id_num = num;
	return ids;

err_out_free:
	free(ids);
err_out_close:
	close(fd);
err_out_exit:
	return NULL;
}

struct dnet_node *dnet_node_create(struct dnet_config *cfg)
{
	struct dnet_node *n;
	struct dnet_raw_id *ids = NULL;
	int id_num;
	int err = -ENOMEM;
	sigset_t sig;

	dnet_set_name("main");

	srand(time(NULL));

	sigemptyset(&sig);
	sigaddset(&sig, SIGPIPE);
	pthread_sigmask(SIG_BLOCK, &sig, NULL);

	sigemptyset(&sig);
	sigaddset(&sig, SIGPIPE);

	if ((cfg->flags & DNET_CFG_JOIN_NETWORK) && (!cfg->cb)) {
		err = -EINVAL;
		if (cfg->log && cfg->log->log)
			cfg->log->log(cfg->log->log_private, DNET_LOG_ERROR, "Joining node has to register "
					"a command handler.\n");
		goto err_out_exit;
	}

	/*
	 * Client must have SINGLE io thread num, since only this can guarantee message order
	 * Messages are picked in dnet_io_process_pool() by different threads, and it is possible that completion
	 * callbacks will be executed out of order, which will badly break things.
	 */
	if (!cfg->io_thread_num) {
		cfg->io_thread_num = 1;
		if (cfg->flags & DNET_CFG_JOIN_NETWORK)
			cfg->io_thread_num = 20;
	}

	if (!cfg->net_thread_num) {
		cfg->net_thread_num = 1;
		if (cfg->flags & DNET_CFG_JOIN_NETWORK)
			cfg->net_thread_num = 8;
	}

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

	if (!cfg->removal_delay)
		cfg->removal_delay = 10; /* Store removed files 10 days by default */

	n->proto = cfg->proto;
	n->sock_type = cfg->sock_type;
	n->family = cfg->family;
	n->wait_ts.tv_sec = cfg->wait_timeout;

	n->cb = cfg->cb;

	n->notify_hash_size = cfg->hash_size;
	n->check_timeout = cfg->check_timeout;
	n->id.group_id = cfg->group_id;
	n->bg_ionice_class = cfg->bg_ionice_class;
	n->bg_ionice_prio = cfg->bg_ionice_prio;
	n->removal_delay = cfg->removal_delay;
	n->flags = cfg->flags;
	if (strlen(cfg->temp_meta_env))
		n->temp_meta_env = cfg->temp_meta_env;
	else
		n->temp_meta_env = cfg->history_env;

	if (!n->log)
		dnet_log_init(n, cfg->log);

	dnet_log(n, DNET_LOG_INFO, "Elliptics starts, version: %s, changed files: %s\n", ELLIPTICS_GIT_VERSION, ELLIPTICS_HAS_CHANGES);

	if (!n->wait_ts.tv_sec) {
		n->wait_ts.tv_sec = 5;
		dnet_log(n, DNET_LOG_NOTICE, "Using default wait timeout (%ld seconds).\n",
				n->wait_ts.tv_sec);
	}

	if (!n->check_timeout) {
		n->check_timeout = DNET_DEFAULT_CHECK_TIMEOUT_SEC;
		dnet_log(n, DNET_LOG_NOTICE, "Using default check timeout (%ld seconds).\n",
				n->check_timeout);
	}

	if (!n->notify_hash_size) {
		n->notify_hash_size = DNET_DEFAULT_NOTIFY_HASH_SIZE;
		dnet_log(n, DNET_LOG_NOTICE, "No notify hash size provided, using default %d.\n",
				n->notify_hash_size);
	}

	n->client_prio = cfg->client_prio;
	n->server_prio = cfg->server_prio;

	err = dnet_crypto_init(n, cfg->ns, cfg->nsize);
	if (err)
		goto err_out_free;

	err = dnet_notify_init(n);
	if (err)
		goto err_out_crypto_cleanup;

	err = dnet_monitor_init(n, cfg);
	if (err)
		goto err_out_notify_exit;

	err = dnet_io_init(n, cfg);
	if (err)
		goto err_out_monitor_exit;

	if (cfg->flags & DNET_CFG_JOIN_NETWORK) {
		int s;

		err = dnet_srw_init(n, cfg);
		if (err) {
			dnet_log(n, DNET_LOG_ERROR, "srw: initialization failure: %s %d\n", strerror(-err), err);
			if (err != -ENOTSUP)
				goto err_out_io_exit;
		}

		ids = dnet_ids_init(n, cfg->history_env, &id_num, cfg->storage_free);
		if (!ids)
			goto err_out_srw_cleanup;

		n->addr.addr_len = sizeof(n->addr.addr);
		err = dnet_socket_create(n, cfg, &n->addr, 1);
		if (err < 0)
			goto err_out_ids_cleanup;

		s = err;
		dnet_setup_id(&n->id, cfg->group_id, ids[0].id);

		n->st = dnet_state_create(n, cfg->group_id, ids, id_num, &n->addr, s, &err, DNET_JOIN, dnet_state_accept_process);
		if (!n->st) {
			close(s);
			goto err_out_state_destroy;
		}

		free(ids);
		ids = NULL;
	}

	err = dnet_check_thread_start(n);
	if (err)
		goto err_out_state_destroy;

	dnet_log(n, DNET_LOG_DSA, "New node has been created at %s, id_size: %u.\n",
			dnet_dump_node(n), DNET_ID_SIZE);
	return n;

err_out_state_destroy:
	dnet_state_put(n->st);
err_out_ids_cleanup:
	free(ids);
err_out_srw_cleanup:
	dnet_srw_cleanup(n);
err_out_io_exit:
	dnet_io_exit(n);
err_out_monitor_exit:
	dnet_monitor_exit(n);
err_out_notify_exit:
	dnet_notify_exit(n);
err_out_crypto_cleanup:
	dnet_crypto_cleanup(n);
err_out_free:
	free(n);
err_out_exit:
	if (cfg->log && cfg->log->log)
		cfg->log->log(cfg->log->log_private, DNET_LOG_ERROR, "Error during node creation.\n");
	return NULL;
}

int dnet_need_exit(struct dnet_node *n)
{
	return n->need_exit;
}

void dnet_set_need_exit(struct dnet_node *n)
{
	n->need_exit = 1;
}

void dnet_node_destroy(struct dnet_node *n)
{
	struct dnet_addr_storage *it, *atmp;

	dnet_log(n, DNET_LOG_DSA, "Destroying node at %s, st: %p.\n",
			dnet_dump_node(n), n->st);

	n->need_exit = 1;
	dnet_check_thread_stop(n);

	dnet_io_exit(n);

	dnet_srw_cleanup(n);

	dnet_notify_exit(n);

	pthread_attr_destroy(&n->attr);

	pthread_mutex_destroy(&n->state_lock);
	dnet_crypto_cleanup(n);

	list_for_each_entry_safe(it, atmp, &n->reconnect_list, reconnect_entry) {
		list_del(&it->reconnect_entry);
		free(it);
	}
	dnet_counter_destroy(n);
	pthread_mutex_destroy(&n->reconnect_lock);
	pthread_mutex_destroy(&n->group_lock);

	dnet_wait_put(n->wait);

	free(n->groups);

	if (n->cb && n->cb->backend_cleanup)
		n->cb->backend_cleanup(n->cb->command_private);

	free(n);
}

int dnet_node_set_groups(struct dnet_node *n, int *groups, int group_num)
{
	int *g, i;

	if (groups && !group_num)
		return -EINVAL;
	if (group_num && !groups)
		return -EINVAL;

	g = malloc(group_num * sizeof(int));
	if (!g)
		return -ENOMEM;

	for (i=0; i<group_num; ++i)
		g[i] = groups[i];

	pthread_mutex_lock(&n->group_lock);
	free(n->groups);

	n->groups = g;
	n->group_num = group_num;
	pthread_mutex_unlock(&n->group_lock);

	return 0;
}
