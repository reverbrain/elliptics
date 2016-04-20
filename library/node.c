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

#include <sys/stat.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>

#include "elliptics.h"
#include "elliptics/interface.h"
#include "monitor/monitor.h"

static struct dnet_node *dnet_node_alloc(struct dnet_config *cfg)
{
	struct dnet_node *n;
	int err;

	n = calloc(1, sizeof(struct dnet_node));
	if (!n) {
		goto err_out_free;
	}

	atomic_init(&n->trans, 0);

	err = dnet_log_init(n, cfg->log);
	if (err)
		goto err_out_free;

	err = pthread_mutex_init(&n->state_lock, NULL);
	if (err) {
		dnet_log(n, DNET_LOG_ERROR, "Failed to initialize state lock: err: %d", err);
		goto err_out_free;
	}

	n->wait = dnet_wait_alloc(0);
	if (!n->wait) {
		dnet_log(n, DNET_LOG_ERROR, "Failed to allocate wait structure.");
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
		dnet_log(n, DNET_LOG_ERROR, "Failed to initialize reconnection lock: err: %d", err);
		goto err_out_destroy_counter;
	}

	err = pthread_rwlock_init(&n->test_settings_lock, NULL);
	if (err) {
		err = -err;
		dnet_log(n, DNET_LOG_ERROR, "Failed to initialize test settings lock: err: %d", err);
		goto err_out_destroy_reconnect_lock;
	}

	err = pthread_attr_init(&n->attr);
	if (err) {
		err = -err;
		dnet_log(n, DNET_LOG_ERROR, "Failed to initialize pthread attributes: err: %d", err);
		goto err_out_destroy_test_settings;
	}
	pthread_attr_setdetachstate(&n->attr, PTHREAD_CREATE_DETACHED);

	n->group_root = RB_ROOT;
	INIT_LIST_HEAD(&n->empty_state_list);
	INIT_LIST_HEAD(&n->dht_state_list);
	INIT_LIST_HEAD(&n->storage_state_list);
	INIT_LIST_HEAD(&n->reconnect_list);
	INIT_LIST_HEAD(&n->iterator_list);

	INIT_LIST_HEAD(&n->check_entry);

	memcpy(n->cookie, cfg->cookie, DNET_AUTH_COOKIE_SIZE);

	return n;

err_out_destroy_test_settings:
	pthread_rwlock_destroy(&n->test_settings_lock);
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

static struct dnet_group *dnet_group_create(struct dnet_node *n, unsigned int group_id)
{
	struct dnet_group *g;

	g = malloc(sizeof(struct dnet_group));
	if (!g)
		return NULL;

	memset(g, 0, sizeof(struct dnet_group));

	atomic_init(&g->refcnt, 1);
	g->group_id = group_id;
	g->node = n;

	INIT_LIST_HEAD(&g->idc_list);

	g->id_num = 0;
	g->ids = NULL;

	return g;
}

void dnet_group_destroy(struct dnet_group *g)
{
	if (!list_empty(&g->idc_list)) {
		fprintf(stderr, "BUG in dnet_group_destroy, reference leak.");
		exit(-1);
	}
	rb_erase(&g->group_entry, &g->node->group_root);
	free(g->ids);
	free(g);
}

static struct dnet_group *dnet_group_search(struct dnet_node *n, unsigned int group_id)
{
	struct rb_root *root = &n->group_root;
	struct rb_node *it = root->rb_node;
	struct dnet_group *g = NULL;

	while (it) {
		g = rb_entry(it, struct dnet_group, group_entry);

		if (g->group_id < group_id)
			it = it->rb_left;
		else if (g->group_id > group_id)
			it = it->rb_right;
		else
			return dnet_group_get(g);
	}

	return NULL;
}

int dnet_group_insert_nolock(struct dnet_node *n, struct dnet_group *a)
{
	struct rb_root *root = &n->group_root;
	struct rb_node **it = &root->rb_node, *parent = NULL;
	struct dnet_group *g = NULL;

	while (*it) {
		parent = *it;

		g = rb_entry(parent, struct dnet_group, group_entry);

		if (g->group_id < a->group_id)
			it = &parent->rb_left;
		else if (g->group_id > a->group_id)
			it = &parent->rb_right;
		else
			return -EEXIST;
	}

	rb_link_node(&a->group_entry, parent, it);
	rb_insert_color(&a->group_entry, root);

	return 0;
}

static int dnet_idc_compare(const void *k1, const void *k2)
{
	const struct dnet_state_id *id1 = k1;
	const struct dnet_state_id *id2 = k2;

	return dnet_id_cmp_str(id1->raw.id, id2->raw.id);
}

static void dnet_idc_remove_nolock(struct dnet_idc *idc)
{
	int i, pos;
	struct dnet_group *g = idc->group;

	for (i=0, pos=0; i<g->id_num; ++i) {
		if (g->ids[i].idc != idc) {
			g->ids[pos] = g->ids[i];
			pos++;
		} else {
			struct dnet_state_id *id = &g->ids[i];
			dnet_log(idc->st->n, DNET_LOG_DEBUG, "dnet_idc_remove: group: %d, id: %s -> host: %s, backend: %d",
				g->group_id, dnet_dump_id_str(id->raw.id), dnet_state_dump_addr(id->idc->st), id->idc->backend_id);
		}
	}

	g->id_num = pos;

	qsort(g->ids,  g->id_num, sizeof(struct dnet_state_id), dnet_idc_compare);

	if (idc->state_entry.rb_parent_color) {
		rb_erase(&idc->state_entry, &idc->st->idc_root);
		idc->state_entry.rb_parent_color = 0;
	}
	list_del(&idc->group_entry);
	dnet_group_put(g);
	free(idc);
}

static struct dnet_idc *dnet_idc_search_backend_nolock(struct dnet_net_state *st, int backend_id)
{
	struct rb_root *root = &st->idc_root;
	struct rb_node *n = root->rb_node;
	struct dnet_idc *idc;

	while (n) {
		idc = rb_entry(n, struct dnet_idc, state_entry);

		if (idc->backend_id < backend_id)
			n = n->rb_left;
		else if (idc->backend_id > backend_id)
			n = n->rb_right;
		else
			return idc;
	}

	return NULL;
}

int dnet_idc_insert_nolock(struct dnet_net_state *st, struct dnet_idc *idc_new)
{
	struct rb_root *root = &st->idc_root;
	struct rb_node **n = &root->rb_node, *parent = NULL;
	struct dnet_idc *idc;

	while (*n) {
		parent = *n;

		idc = rb_entry(parent, struct dnet_idc, state_entry);

		if (idc->backend_id < idc_new->backend_id)
			n = &parent->rb_left;
		else if (idc->backend_id > idc_new->backend_id)
			n = &parent->rb_right;
		else
			return -EEXIST;
	}

	rb_link_node(&idc_new->state_entry, parent, n);
	rb_insert_color(&idc_new->state_entry, root);
	return 0;
}

void dnet_idc_remove_backend_nolock(struct dnet_net_state *st, int backend_id)
{
	struct dnet_idc *idc = dnet_idc_search_backend_nolock(st, backend_id);
	if (idc) {
		pthread_rwlock_wrlock(&st->idc_lock);
		dnet_idc_remove_nolock(idc);
		pthread_rwlock_unlock(&st->idc_lock);
	}
}

static void dnet_idc_remove_all(struct dnet_net_state *st)
{
	struct dnet_idc *idc;
	struct rb_node *rb_node, *next;

	pthread_rwlock_wrlock(&st->idc_lock);
	for (rb_node = rb_first(&st->idc_root); rb_node != NULL; rb_node = next) {
		idc = rb_entry(rb_node, struct dnet_idc, state_entry);

		next = rb_next(rb_node);
		dnet_idc_remove_nolock(idc);
	}
	pthread_rwlock_unlock(&st->idc_lock);
}

int dnet_state_set_server_prio(struct dnet_net_state *st)
{
	struct dnet_node *n = st->n;
	int err = 0;

	if (n->server_prio) {
		err = setsockopt(st->read_s, IPPROTO_IP, IP_TOS, &n->server_prio, 4);
		if (err) {
			err = -errno;
			dnet_log_err(n, "could not set read server prio %d", n->server_prio);
		}
		err = setsockopt(st->write_s, IPPROTO_IP, IP_TOS, &n->server_prio, 4);
		if (err) {
			err = -errno;
			dnet_log_err(n, "could not set write server prio %d", n->server_prio);
		}

		if (!err) {
			dnet_log(n, DNET_LOG_INFO, "%s: server net TOS value set to %d",
					dnet_addr_string(&st->addr), n->server_prio);
		}
	}

	return err;
}

int dnet_idc_update_backend(struct dnet_net_state *st, struct dnet_backend_ids *backend)
{
	struct dnet_node *n = st->n;
	struct dnet_idc *idc;
	struct dnet_group *g;
	int err = -ENOMEM, i, num;
	struct timeval start, end;
	long diff;
	struct dnet_raw_id *ids = backend->ids;
	int id_num = backend->ids_count;
	int group_id = backend->group_id;

	gettimeofday(&start, NULL);

	const int remove_backend = (backend->flags & DNET_BACKEND_DISABLE);

	if (remove_backend) {
		pthread_mutex_lock(&n->state_lock);
		dnet_idc_remove_backend_nolock(st, backend->backend_id);
		pthread_mutex_unlock(&n->state_lock);

		return 0;
	}

	idc = malloc(sizeof(struct dnet_idc) + sizeof(struct dnet_state_id) * id_num);
	if (!idc)
		goto err_out_exit;

	memset(idc, 0, sizeof(struct dnet_idc));

	INIT_LIST_HEAD(&idc->group_entry);

	for (i=0; i<id_num; ++i) {
		struct dnet_state_id *sid = &idc->ids[i];
		memcpy(&sid->raw, &ids[i], sizeof(struct dnet_raw_id));
		sid->idc = idc;
	}

	pthread_mutex_lock(&n->state_lock);

	g = dnet_group_search(n, group_id);
	if (!g) {
		g = dnet_group_create(n, group_id);
		if (!g)
			goto err_out_unlock;

		err = dnet_group_insert_nolock(n, g);
		if (err)
			goto err_out_unlock_put;
	}

	dnet_idc_remove_backend_nolock(st, backend->backend_id);

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

	idc->id_num = id_num;
	idc->st = st;
	idc->group = g;
	idc->backend_id = backend->backend_id;
	idc->disk_weight = DNET_STATE_DEFAULT_WEIGHT;
	idc->cache_weight = DNET_STATE_DEFAULT_WEIGHT;

	pthread_rwlock_wrlock(&st->idc_lock);
	dnet_idc_insert_nolock(st, idc);
	pthread_rwlock_unlock(&st->idc_lock);

	list_add_tail(&idc->group_entry, &g->idc_list);

	if (dnet_log_enabled(n->log, DNET_LOG_DEBUG)) {
		for (i=0; i<g->id_num; ++i) {
			struct dnet_state_id *id = &g->ids[i];
			dnet_log(n, DNET_LOG_DEBUG, "dnet_idc_update: group: %d, id: %s -> host: %s, backend: %d",
				g->group_id, dnet_dump_id_str(id->raw.id), dnet_state_dump_addr(id->idc->st), id->idc->backend_id);
		}
	}

	pthread_mutex_unlock(&n->state_lock);

	gettimeofday(&end, NULL);
	diff = (end.tv_sec - start.tv_sec) * 1000000 + end.tv_usec - start.tv_usec;

	dnet_log(n, DNET_LOG_NOTICE, "Initialized group: %d, "
			"total ids: %d, added ids: %d, received ids: %d, "
			"state: %s, backend: %d, idc: %p, time-took: %ld usecs.",
			g->group_id,
			g->id_num, num, id_num,
			dnet_state_dump_addr(st), backend->backend_id, idc, diff);

	return 0;

err_out_unlock_put:
	dnet_group_put(g);
err_out_unlock:
	pthread_mutex_unlock(&n->state_lock);
	free(idc);
err_out_exit:
	gettimeofday(&end, NULL);
	diff = (end.tv_sec - start.tv_sec) * 1000000 + end.tv_usec - start.tv_usec;
	dnet_log(n, DNET_LOG_ERROR, "Failed to initialize group %d with %d ids, state: %s, backend: %d, err: %d: %ld usecs.",
		group_id, id_num, dnet_state_dump_addr(st), backend->backend_id, err, diff);
	return err;
}

void dnet_idc_destroy_nolock(struct dnet_net_state *st)
{
	dnet_idc_remove_all(st);
}

static int __dnet_idc_search(struct dnet_group *g, const struct dnet_id *id)
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

	return i;
}

static struct dnet_state_id *dnet_idc_search(struct dnet_group *g, const struct dnet_id *id)
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
		return -ENXIO;

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

static struct dnet_state_id *__dnet_state_search_id(struct dnet_node *n, const struct dnet_id *id)
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

static struct dnet_net_state *__dnet_state_search(struct dnet_node *n, const struct dnet_id *id, int *backend_id)
{
	struct dnet_state_id *sid = __dnet_state_search_id(n, id);

	if (!sid)
		return NULL;

	if (backend_id)
		*backend_id = sid->idc->backend_id;

	return dnet_state_get(sid->idc->st);
}

struct dnet_net_state *dnet_state_search_by_addr(struct dnet_node *n, const struct dnet_addr *addr)
{
	struct dnet_net_state *st, *found = NULL;

	pthread_mutex_lock(&n->state_lock);
	list_for_each_entry(st, &n->dht_state_list, node_entry) {
		if (dnet_addr_equal(&st->addr, addr)) {
			found = st;
			dnet_state_get(found);
			break;
		}
	}
	pthread_mutex_unlock(&n->state_lock);

	return found;
}

struct dnet_net_state *dnet_state_search_nolock(struct dnet_node *n, const struct dnet_id *id, int *backend_id)
{
	struct dnet_net_state *found;

	found = __dnet_state_search(n, id, backend_id);
	if (!found) {
		struct dnet_group *g;

		g = dnet_group_search(n, id->group_id);
		if (!g)
			goto err_out_exit;

		found = dnet_state_get(g->ids[0].idc->st);
		if (backend_id)
			*backend_id = g->ids[0].idc->backend_id;

		dnet_group_put(g);
	}

err_out_exit:
	return found;
}

ssize_t dnet_state_search_backend(struct dnet_node *n, const struct dnet_id *id)
{
	ssize_t backend_id = -1;
	struct dnet_state_id *sid;

	pthread_mutex_lock(&n->state_lock);

	sid = __dnet_state_search_id(n, id);
	if (!sid) {
		struct dnet_group *g;

		g = dnet_group_search(n, id->group_id);
		if (g) {
			sid = &g->ids[0];
		}
	}

	if (sid && sid->idc->st == n->st)
		backend_id = sid->idc->backend_id;

	pthread_mutex_unlock(&n->state_lock);

	return backend_id;
}

int dnet_get_backend_weight(struct dnet_net_state *st, int backend_id, uint32_t ioflags, double *weight)
{
	struct dnet_idc *idc;
	int err = -ENOENT;

	pthread_rwlock_rdlock(&st->idc_lock);
	idc = dnet_idc_search_backend_nolock(st, backend_id);
	if (idc) {
		err = 0;

		if (ioflags & (DNET_IO_FLAGS_CACHE | DNET_IO_FLAGS_CACHE_ONLY)) {
			*weight = idc->cache_weight;
		} else {
			*weight = idc->disk_weight;
		}
	}
	pthread_rwlock_unlock(&st->idc_lock);

	return err;
}

void dnet_set_backend_weight(struct dnet_net_state *st, int backend_id, uint32_t ioflags, double weight)
{
	struct dnet_idc *idc;

	pthread_rwlock_rdlock(&st->idc_lock);
	idc = dnet_idc_search_backend_nolock(st, backend_id);
	if (idc) {
		if (ioflags & (DNET_IO_FLAGS_CACHE | DNET_IO_FLAGS_CACHE_ONLY)) {
			idc->cache_weight = weight;
		} else {
			idc->disk_weight = weight;
		}
	}
	pthread_rwlock_unlock(&st->idc_lock);
}

void dnet_update_backend_weight(struct dnet_net_state *st, const struct dnet_cmd *cmd, uint64_t ioflags, long time) {
	double old_weight = 0., new_weight = 0.;
	if (!st)
		return;

	int err = dnet_get_backend_weight(st, cmd->backend_id, ioflags, &old_weight);
	if (!err &&
	    cmd->status == 0 &&
	    cmd->size) {
		const double norm = (double)time / (double) cmd->size;
		new_weight = 1.0 / ((1.0 / old_weight + norm) / 2.0);
		dnet_set_backend_weight(st, cmd->backend_id, ioflags, new_weight);
	}
}

struct dnet_net_state *dnet_state_get_first_with_backend(struct dnet_node *n, const struct dnet_id *id, int *backend_id)
{
	struct dnet_net_state *found;

	pthread_mutex_lock(&n->state_lock);
	found = dnet_state_search_nolock(n, id, backend_id);
	pthread_mutex_unlock(&n->state_lock);

	if (!found) {
		dnet_log(n, DNET_LOG_ERROR, "%s: could not find network state for request", dnet_dump_id(id));
	}

	return found;
}

struct dnet_net_state *dnet_state_get_first(struct dnet_node *n, const struct dnet_id *id)
{
	return dnet_state_get_first_with_backend(n, id, NULL);
}

void dnet_state_put(struct dnet_net_state *st)
{
	/*
	 * State can be NULL here when we just want to kick IO thread.
	 */
	if (st && atomic_dec_and_test(&st->refcnt))
		dnet_state_destroy(st);
}

/*
 * We do not blindly return n->st, since it will go away eventually,
 * since we want multiple states/listen sockets per single node
 */
struct dnet_net_state *dnet_node_state(struct dnet_node *n)
{
	return dnet_state_get(n->st);
}

struct dnet_node *dnet_node_create(struct dnet_config *cfg)
{
	struct dnet_node *n;
	int err = -ENOMEM;

	sigset_t previous_sigset;
	sigset_t sigset;
	sigfillset(&sigset);
	pthread_sigmask(SIG_BLOCK, &sigset, &previous_sigset);

	srand(time(NULL));

	if (!cfg->io_thread_num) {
		cfg->io_thread_num = 1;
		if (cfg->flags & DNET_CFG_JOIN_NETWORK)
			cfg->io_thread_num = 20;
	}

	if (!cfg->nonblocking_io_thread_num) {
		cfg->nonblocking_io_thread_num = 1;

		if (cfg->flags & DNET_CFG_JOIN_NETWORK) {
			if (cfg->io_thread_num > 100)
				cfg->nonblocking_io_thread_num = 10;
		}
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

	if (!cfg->family)
		cfg->family = AF_INET;

	if (!cfg->removal_delay)
		cfg->removal_delay = 10; /* Store removed files 10 days by default */

	n->wait_ts.tv_sec = cfg->wait_timeout;

	n->keep_cnt = 3;
	n->keep_idle = 10;
	n->keep_interval = 10;

	n->notify_hash_size = cfg->hash_size;
	n->check_timeout = cfg->check_timeout;
	n->stall_count = cfg->stall_count;
	n->bg_ionice_class = cfg->bg_ionice_class;
	n->bg_ionice_prio = cfg->bg_ionice_prio;
	n->removal_delay = cfg->removal_delay;
	n->flags = cfg->flags;
	n->indexes_shard_count = cfg->indexes_shard_count;

	if (!n->log)
		dnet_log_init(n, cfg->log);

	dnet_log(n, DNET_LOG_INFO, "Elliptics starts, flags: %s", dnet_flags_dump_cfgflags(n->flags));

	if (!n->wait_ts.tv_sec) {
		n->wait_ts.tv_sec = DNET_DEFAULT_WAIT_TIMEOUT_SEC;
		dnet_log(n, DNET_LOG_NOTICE, "Using default wait timeout (%ld seconds).",
				n->wait_ts.tv_sec);
	}

	if (!n->check_timeout) {
		n->check_timeout = DNET_DEFAULT_CHECK_TIMEOUT_SEC;
		dnet_log(n, DNET_LOG_NOTICE, "Using default check timeout (%ld seconds).",
				n->check_timeout);
	}

	if (!n->stall_count) {
		n->stall_count = DNET_DEFAULT_STALL_TRANSACTIONS;
		dnet_log(n, DNET_LOG_NOTICE, "Using default stall count (%ld transactions).",
				n->stall_count);
	}

	n->client_prio = cfg->client_prio;
	n->server_prio = cfg->server_prio;

	if (!n->indexes_shard_count) {
		n->indexes_shard_count = DNET_DEFAULT_INDEXES_SHARD_COUNT;
		dnet_log(n, DNET_LOG_NOTICE, "Using default indexes shard count (%d shards).",
				n->indexes_shard_count);
	}

	err = dnet_crypto_init(n);
	if (err)
		goto err_out_free;

	err = dnet_io_init(n, cfg);
	if (err)
		goto err_out_crypto_cleanup;

	err = dnet_check_thread_start(n);
	if (err)
		goto err_out_io_exit;

	dnet_log(n, DNET_LOG_DEBUG, "New node has been created.");
	pthread_sigmask(SIG_SETMASK, &previous_sigset, NULL);
	return n;

err_out_io_exit:
	dnet_io_stop(n);
	dnet_io_cleanup(n);
err_out_crypto_cleanup:
	dnet_crypto_cleanup(n);
err_out_free:
	free(n);
err_out_exit:
	pthread_sigmask(SIG_SETMASK, &previous_sigset, NULL);

	dnet_log_only_log(cfg->log, DNET_LOG_ERROR, "Error during node creation.");

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

void dnet_node_stop_common_resources(struct dnet_node *n)
{
	dnet_set_need_exit(n);
	dnet_iterator_cancel_all(n);
	dnet_check_thread_stop(n);

	dnet_io_stop(n);
}

void dnet_node_cleanup_common_resources(struct dnet_node *n)
{
	struct dnet_addr_storage *it, *atmp;

	dnet_io_cleanup(n);

	pthread_attr_destroy(&n->attr);

	pthread_mutex_destroy(&n->state_lock);
	dnet_crypto_cleanup(n);

	list_for_each_entry_safe(it, atmp, &n->reconnect_list, reconnect_entry) {
		list_del(&it->reconnect_entry);
		free(it);
	}
	pthread_rwlock_destroy(&n->test_settings_lock);
	pthread_mutex_destroy(&n->reconnect_lock);

	dnet_wait_put(n->wait);

	free(n->test_settings);
	free(n->route_addr);
}

void dnet_node_destroy(struct dnet_node *n)
{
	dnet_log(n, DNET_LOG_DEBUG, "Destroying node.");

	dnet_node_stop_common_resources(n);
	dnet_node_cleanup_common_resources(n);
	dnet_counter_destroy(n);

	free(n);
}

struct dnet_session *dnet_session_create(struct dnet_node *n)
{
	struct dnet_session *s;

	s = (struct dnet_session *)malloc(sizeof(struct dnet_session));
	if (!s)
		return NULL;

	memset(s, 0, sizeof(struct dnet_session));
	dnet_empty_time(&s->ts);
	s->node = n;
	s->wait_ts = n->wait_ts;

	return s;
}

struct dnet_session *dnet_session_copy(struct dnet_session *s)
{
	struct dnet_session *new_s = dnet_session_create(s->node);
	int err = 0;
	if (!new_s)
		goto err_out_exit;

	new_s->wait_ts = s->wait_ts;
	new_s->trace_id = s->trace_id;
	new_s->cflags = s->cflags;
	new_s->ioflags = s->ioflags;
	new_s->ts = s->ts;
	new_s->user_flags = s->user_flags;
	new_s->direct_addr = s->direct_addr;
	new_s->direct_backend = s->direct_backend;

	if (s->group_num > 0) {
		err = dnet_session_set_groups(new_s, s->groups, s->group_num);

		if (err)
			goto err_out_free;
	}

	if (s->ns && s->nsize) {
		err = dnet_session_set_ns(new_s, s->ns, s->nsize);

		if (err)
			goto err_out_free;
	}

	return new_s;

err_out_free:
	dnet_session_destroy(new_s);
err_out_exit:
	return NULL;
}

void dnet_session_destroy(struct dnet_session *s)
{
	dnet_log(s->node, DNET_LOG_DEBUG, "Destroying session.");

	free(s->groups);
	free(s->ns);
	free(s);
}

int dnet_session_set_groups(struct dnet_session *s, const int *groups, int group_num)
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

	free(s->groups);

	s->groups = g;
	s->group_num = group_num;

	return 0;
}

int *dnet_session_get_groups(struct dnet_session *s, int *count)
{
	*count = s->group_num;
	return s->groups;
}

void dnet_session_set_trace_id(struct dnet_session *s, trace_id_t trace_id)
{
	s->trace_id = trace_id;
}

trace_id_t dnet_session_get_trace_id(struct dnet_session *s)
{
	return s->trace_id;
}

void dnet_session_set_trace_bit(struct dnet_session *s, int trace)
{
	if (trace)
		s->cflags |= DNET_FLAGS_TRACE_BIT;
	else
		s->cflags &= ~DNET_FLAGS_TRACE_BIT;
}

int dnet_session_get_trace_bit(struct dnet_session *s)
{
	return !!(s->cflags & DNET_FLAGS_TRACE_BIT);
}

void dnet_session_set_ioflags(struct dnet_session *s, uint32_t ioflags)
{
	s->ioflags = ioflags;
}

int dnet_session_set_ns(struct dnet_session *s, const char *ns, int nsize)
{
	char *old = s->ns;
	int err;

	if (ns && nsize) {
		s->ns = malloc(nsize);
		if (!s->ns) {
			err = -ENOMEM;
			goto err_out_exit;
		}

		memcpy(s->ns, ns, nsize);
		s->nsize = nsize;

		free(old);
	} else {
		s->ns = NULL;
		free(old);
	}

	return 0;

err_out_exit:
	s->ns = old;
	return err;
}

uint32_t dnet_session_get_ioflags(struct dnet_session *s)
{
	return s->ioflags;
}

void dnet_session_set_cflags(struct dnet_session *s, uint64_t cflags)
{
	s->cflags = cflags;
}

uint64_t dnet_session_get_cflags(struct dnet_session *s)
{
	return s->cflags;
}

void dnet_session_set_user_flags(struct dnet_session *s, uint64_t user_flags)
{
	s->user_flags = user_flags;
}

uint64_t dnet_session_get_user_flags(struct dnet_session *s)
{
	return s->user_flags;
}

void dnet_session_set_timeout(struct dnet_session *s, long wait_timeout)
{
	s->wait_ts.tv_sec = wait_timeout;
}

struct timespec *dnet_session_get_timeout(struct dnet_session *s)
{
	return s->wait_ts.tv_sec ? &s->wait_ts : &s->node->wait_ts;
}

void dnet_set_timeouts(struct dnet_node *n, long wait_timeout, long check_timeout)
{
	n->wait_ts.tv_sec = wait_timeout;
	n->check_timeout = check_timeout;
}

void dnet_set_keepalive(struct dnet_node *n, int idle, int cnt, int interval)
{
	n->keep_cnt = cnt;
	n->keep_idle = idle;
	n->keep_interval = interval;
}

struct dnet_node *dnet_session_get_node(struct dnet_session *s)
{
	return s->node;
}

void dnet_session_set_timestamp(struct dnet_session *s, const struct dnet_time *ts)
{
	s->ts = *ts;
}

void dnet_session_get_timestamp(struct dnet_session *s, struct dnet_time *ts)
{
	*ts = s->ts;
}

struct dnet_id *dnet_session_get_direct_id(struct dnet_session *s)
{
	return &s->direct_id;
}

void dnet_session_set_direct_id(struct dnet_session *s, const struct dnet_id *id)
{
	s->direct_id = *id;
}

const struct dnet_addr *dnet_session_get_direct_addr(struct dnet_session *s)
{
	return &s->direct_addr;
}

void dnet_session_set_direct_addr(struct dnet_session *s, const struct dnet_addr *addr)
{
	s->direct_addr = *addr;
}

uint32_t dnet_session_get_direct_backend(struct dnet_session *s)
{
	return s->direct_backend;
}

void dnet_session_set_direct_backend(struct dnet_session *s, uint32_t backend_id)
{
	s->direct_backend = backend_id;
}
