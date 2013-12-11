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

	err = pthread_attr_init(&n->attr);
	if (err) {
		err = -err;
		dnet_log_err(n, "Failed to initialize pthread attributes: err: %d", err);
		goto err_out_destroy_reconnect_lock;
	}
	pthread_attr_setdetachstate(&n->attr, PTHREAD_CREATE_DETACHED);

	n->autodiscovery_socket = -1;

	INIT_LIST_HEAD(&n->group_list);
	INIT_LIST_HEAD(&n->empty_state_list);
	INIT_LIST_HEAD(&n->storage_state_list);
	INIT_LIST_HEAD(&n->reconnect_list);
	INIT_LIST_HEAD(&n->iterator_list);

	INIT_LIST_HEAD(&n->check_entry);

	memcpy(n->cookie, cfg->cookie, DNET_AUTH_COOKIE_SIZE);

	return n;

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

	if (n->log->log_level >= DNET_LOG_DEBUG) {
		for (i=0; i<g->id_num; ++i) {
			struct dnet_state_id *id = &g->ids[i];
			dnet_log(n, DNET_LOG_DEBUG, "%d: %s -> %s\n", g->group_id,
				dnet_dump_id_str(id->raw.id), dnet_state_dump_addr(id->idc->st));
		}
	}

	err = dnet_setup_control_nolock(st);
	if (err)
		goto err_out_remove_nolock;

	pthread_mutex_unlock(&n->state_lock);

	gettimeofday(&end, NULL);
	diff = (end.tv_sec - start.tv_sec) * 1000000 + end.tv_usec - start.tv_usec;

	dnet_log(n, DNET_LOG_NOTICE, "Initialized group: %d, total ids: %d, added ids: %d, received ids: %d, time-took: %ld usecs.\n",
			g->group_id, g->id_num, num, id_num, diff);

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
			dnet_log(n, DNET_LOG_INFO, "%s: server net TOS value set to %d\n",
					dnet_server_convert_dnet_addr(&st->addr), n->server_prio);
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
			if (dnet_addr_equal(&st->addr, addr)) {
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
	struct dnet_net_state *found;

	pthread_mutex_lock(&n->state_lock);
	found = dnet_state_search_nolock(n, &n->id);
	pthread_mutex_unlock(&n->state_lock);

	return found;
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

	n->cb = cfg->cb;

	n->notify_hash_size = cfg->hash_size;
	n->check_timeout = cfg->check_timeout;
	n->stall_count = cfg->stall_count;
	n->id.group_id = cfg->group_id;
	n->bg_ionice_class = cfg->bg_ionice_class;
	n->bg_ionice_prio = cfg->bg_ionice_prio;
	n->removal_delay = cfg->removal_delay;
	n->flags = cfg->flags;
	n->cache_size = cfg->cache_size;
	n->caches_number = cfg->caches_number;
	n->cache_pages_number = cfg->cache_pages_number;
	n->cache_pages_proportions = cfg->cache_pages_proportions;
	n->indexes_shard_count = cfg->indexes_shard_count;

	if (!n->log)
		dnet_log_init(n, cfg->log);

	dnet_log(n, DNET_LOG_INFO, "Elliptics starts\n");

	if (!n->wait_ts.tv_sec) {
		n->wait_ts.tv_sec = DNET_DEFAULT_WAIT_TIMEOUT_SEC;
		dnet_log(n, DNET_LOG_NOTICE, "Using default wait timeout (%ld seconds).\n",
				n->wait_ts.tv_sec);
	}

	if (!n->check_timeout) {
		n->check_timeout = DNET_DEFAULT_CHECK_TIMEOUT_SEC;
		dnet_log(n, DNET_LOG_NOTICE, "Using default check timeout (%ld seconds).\n",
				n->check_timeout);
	}

	if (!n->cache_sync_timeout) {
		n->cache_sync_timeout = DNET_DEFAULT_CACHE_SYNC_TIMEOUT_SEC;
		dnet_log(n, DNET_LOG_NOTICE, "Using default check timeout (%d seconds).\n",
				n->cache_sync_timeout);
	}

	if (!n->stall_count) {
		n->stall_count = DNET_DEFAULT_STALL_TRANSACTIONS;
		dnet_log(n, DNET_LOG_NOTICE, "Using default stall count (%ld transactions).\n",
				n->stall_count);
	}

	n->client_prio = cfg->client_prio;
	n->server_prio = cfg->server_prio;

	if (!n->indexes_shard_count) {
		n->indexes_shard_count = DNET_DEFAULT_INDEXES_SHARD_COUNT;
		dnet_log(n, DNET_LOG_NOTICE, "Using default indexes shard count (%d shards).\n",
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

	dnet_log(n, DNET_LOG_DEBUG, "New node has been created.\n");
	pthread_sigmask(SIG_SETMASK, &previous_sigset, NULL);
	return n;

err_out_io_exit:
	dnet_io_exit(n);
err_out_crypto_cleanup:
	dnet_crypto_cleanup(n);
err_out_free:
	free(n);
err_out_exit:
	pthread_sigmask(SIG_SETMASK, &previous_sigset, NULL);

	if (cfg->log && cfg->log->log)
		cfg->log->log(cfg->log->log_private, DNET_LOG_ERROR, "Error during node creation.\n");

	if (cfg->cb && cfg->cb->backend_cleanup)
		cfg->cb->backend_cleanup(cfg->cb->command_private);
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

void dnet_node_cleanup_common_resources(struct dnet_node *n)
{
	struct dnet_addr_storage *it, *atmp;

	n->need_exit = 1;
	dnet_iterator_cancel_all(n);
	dnet_check_thread_stop(n);

	dnet_io_exit(n);

	pthread_attr_destroy(&n->attr);

	pthread_mutex_destroy(&n->state_lock);
	dnet_crypto_cleanup(n);

	list_for_each_entry_safe(it, atmp, &n->reconnect_list, reconnect_entry) {
		list_del(&it->reconnect_entry);
		free(it);
	}
	pthread_mutex_destroy(&n->reconnect_lock);

	dnet_wait_put(n->wait);

	close(n->autodiscovery_socket);
}

void dnet_node_destroy(struct dnet_node *n)
{
	dnet_log(n, DNET_LOG_DEBUG, "Destroying node.\n");

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

	return s;
}

struct dnet_session *dnet_session_copy(struct dnet_session *s)
{
	struct dnet_session *new_s = dnet_session_create(s->node);
	int err = 0;
	if (!new_s)
		goto err_out_exit;

	new_s->wait_ts = s->wait_ts;
	new_s->cflags = s->cflags;
	new_s->ioflags = s->ioflags;
	new_s->ts = s->ts;
	new_s->user_flags = s->user_flags;

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
	dnet_log(s->node, DNET_LOG_DEBUG, "Destroying session.\n");

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

void dnet_session_set_timeout(struct dnet_session *s, unsigned int wait_timeout)
{
	s->wait_ts.tv_sec = wait_timeout;
}

struct timespec *dnet_session_get_timeout(struct dnet_session *s)
{
	return s->wait_ts.tv_sec ? &s->wait_ts : &s->node->wait_ts;
}

void dnet_set_timeouts(struct dnet_node *n, int wait_timeout, int check_timeout)
{
	n->wait_ts.tv_sec = wait_timeout;
	n->check_timeout = check_timeout;
}

struct dnet_node *dnet_session_get_node(struct dnet_session *s)
{
	return s->node;
}

void dnet_session_set_timestamp(struct dnet_session *s, struct dnet_time *ts)
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

void dnet_session_set_direct_id(struct dnet_session *s, struct dnet_id *id)
{
	s->direct_id = *id;
}
