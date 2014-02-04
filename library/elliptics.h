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

#ifndef __DNET_ELLIPTICS_H
#define __DNET_ELLIPTICS_H

#include <sys/time.h>
#include <sys/socket.h>
#include <sys/epoll.h>

#include <errno.h>
#include <limits.h>
#include <netdb.h>
#include <pthread.h>
#include <string.h>
#include <time.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <eblob/blob.h>

#ifndef HAVE_UCHAR
typedef unsigned char u_char;
typedef unsigned short u_short;
#endif

#include "list.h"

#include "rbtree.h"

#include "atomic.h"
#include "lock.h"

#include "elliptics/packet.h"
#include "elliptics/interface.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifndef __unused
#define __unused	__attribute__ ((unused))
#endif

struct dnet_node;
struct dnet_group;
struct dnet_net_state;

extern __thread uint32_t trace_id;

#define dnet_log(n, level, format, a...)							\
	do {											\
		if (n->log && ((n->log->log_level >= level) || (trace_id & DNET_TRACE_BIT)))	\
			dnet_log_raw(n, level, format, ##a);					\
		} while (0)
#define dnet_log_err(n, f, a...) dnet_log(n, DNET_LOG_ERROR, f ": %s [%d].\n", ##a, strerror(errno), errno)

struct dnet_io_req {
	struct list_head	req_entry;

	struct dnet_net_state	*st;

	void			*header;
	size_t			hsize;

	void			*data;
	size_t			dsize;

	int			on_exit;
	int			fd;
	off_t			local_offset;
	size_t			fsize;
};

/*
 * Currently executed network state machine:
 * receives and sends command and data.
 */

/* Reading a command */
#define DNET_IO_CMD		(1<<0)

/* Attached data should be discarded */
#define DNET_IO_DROP		(1<<1)

#define DNET_STATE_MAX_WEIGHT		(1024 * 10)

/* Iterator watermarks for sending data and sleeping */
#define DNET_SEND_WATERMARK_HIGH	(1024 * 100)
#define DNET_SEND_WATERMARK_LOW		(512 * 100)

/* Internal flag to ignore cache */
#define DNET_IO_FLAGS_NOCACHE		(1<<28)

struct dnet_net_state
{
	struct list_head	state_entry;
	struct list_head	storage_state_entry;

	struct dnet_node	*n;

	atomic_t		refcnt;
	int			read_s, write_s;

	int			__need_exit;

	int			stall;

	int			__join_state;

	/* all address of the given node */
	int			addr_num;
	struct dnet_addr	*addrs;

	/* index of the connected address in array of all addresses of given node */
	int			idx;

	/* address used to connect to cluster */
	struct dnet_addr	addr;

	int			(* process)(struct dnet_net_state *st, struct epoll_event *ev);

	struct dnet_cmd		rcv_cmd;
	uint64_t		rcv_offset;
	uint64_t		rcv_end;
	unsigned int		rcv_flags;
	void			*rcv_data;

	int			epoll_fd;
	size_t			send_offset;
	pthread_mutex_t		send_lock;
	struct list_head	send_list;
	/*
	 * Condition variable to wait when send_queue_size reaches high
	 * watermark
	 */
	pthread_cond_t		send_wait;
	/* Number of queued requests in send queue from iterator */
	atomic_t		send_queue_size;

	pthread_mutex_t		trans_lock;
	struct rb_root		trans_root;
	struct list_head	trans_list;


	int			la;
	unsigned long long	free;
	float			weight;
	long			median_read_time;

	struct dnet_idc		*idc;

	struct dnet_stat_count	stat[__DNET_CMD_MAX];

	/* Remote protocol version */
	int version[4];
};

int dnet_socket_local_addr(int s, struct dnet_addr *addr);
int dnet_local_addr_index(struct dnet_node *n, struct dnet_addr *addr);

int dnet_copy_addrs(struct dnet_net_state *nst, struct dnet_addr *addrs, int addr_num);

struct dnet_idc;
struct dnet_state_id {
	struct dnet_raw_id	raw;
	struct dnet_idc		*idc;
};

struct dnet_idc {
	struct dnet_net_state	*st;
	struct dnet_group	*group;
	int			id_num;
	struct dnet_state_id	ids[];
};

int dnet_idc_create(struct dnet_net_state *st, int group_id, struct dnet_raw_id *ids, int id_num);
void dnet_idc_destroy_nolock(struct dnet_net_state *st);

int dnet_state_micro_init(struct dnet_net_state *st, struct dnet_node *n, struct dnet_addr *addr, int join,
		int (* process)(struct dnet_net_state *st, struct epoll_event *ev));

struct dnet_net_state *dnet_state_create(struct dnet_node *n,
		int group_id, struct dnet_raw_id *ids, int id_num,
		struct dnet_addr *addr, int s, int *errp, int join, int idx,
		int (* process)(struct dnet_net_state *st, struct epoll_event *ev));

void dnet_state_reset(struct dnet_net_state *st, int error);
void dnet_state_clean(struct dnet_net_state *st);
void dnet_state_remove_nolock(struct dnet_net_state *st);

struct dnet_net_state *dnet_state_search_by_addr(struct dnet_node *n, struct dnet_addr *addr);
struct dnet_net_state *dnet_state_get_first(struct dnet_node *n, struct dnet_id *id);
struct dnet_net_state *dnet_state_search_nolock(struct dnet_node *n, struct dnet_id *id);
struct dnet_net_state *dnet_node_state(struct dnet_node *n);

void dnet_node_cleanup_common_resources(struct dnet_node *n);

int dnet_search_range(struct dnet_node *n, struct dnet_id *id,
		struct dnet_raw_id *start, struct dnet_raw_id *next);

int dnet_recv_route_list(struct dnet_net_state *st);

void dnet_state_destroy(struct dnet_net_state *st);

void dnet_schedule_command(struct dnet_net_state *st);

int dnet_schedule_send(struct dnet_net_state *st);
int dnet_schedule_recv(struct dnet_net_state *st);

void dnet_unschedule_send(struct dnet_net_state *st);
void dnet_unschedule_recv(struct dnet_net_state *st);

int dnet_setup_control_nolock(struct dnet_net_state *st);

int dnet_add_reconnect_state(struct dnet_node *n, struct dnet_addr *addr, unsigned int join_state);

static inline struct dnet_net_state *dnet_state_get(struct dnet_net_state *st)
{
	atomic_inc(&st->refcnt);
	return st;
}

struct dnet_wait
{
	pthread_cond_t		wait;
	pthread_mutex_t		wait_lock;
	int			cond;
	int			status;

	void			*ret;
	int			size;

	atomic_t		refcnt;
};

#define dnet_wait_event(w, condition, wts)						\
({											\
	int __err = 0;									\
	struct timespec __ts;								\
 	struct timeval __tv;								\
	gettimeofday(&__tv, NULL);							\
	__ts.tv_nsec = __tv.tv_usec * 1000 + (wts)->tv_nsec;				\
	__ts.tv_sec = __tv.tv_sec + (wts)->tv_sec;						\
	pthread_mutex_lock(&(w)->wait_lock);						\
	while (!(condition) && !__err)							\
		__err = pthread_cond_timedwait(&(w)->wait, &(w)->wait_lock, &__ts);		\
	pthread_mutex_unlock(&(w)->wait_lock);						\
	-__err;										\
})

#define dnet_wakeup(w, task)								\
({											\
	pthread_mutex_lock(&(w)->wait_lock);						\
	task;										\
	pthread_cond_broadcast(&(w)->wait);						\
	pthread_mutex_unlock(&(w)->wait_lock);						\
})

struct dnet_wait *dnet_wait_alloc(int cond);
void dnet_wait_destroy(struct dnet_wait *w);

static inline struct dnet_wait *dnet_wait_get(struct dnet_wait *w)
{
	atomic_inc(&w->refcnt);
	return w;
}

static inline void dnet_wait_put(struct dnet_wait *w)
{
	if (atomic_dec_and_test(&w->refcnt))
		dnet_wait_destroy(w);
}

struct dnet_notify_bucket
{
	struct list_head		notify_list;
	pthread_rwlock_t		notify_lock;
};

int dnet_update_notify(struct dnet_net_state *st, struct dnet_cmd *cmd, void *data);

int dnet_notify_add(struct dnet_net_state *st, struct dnet_cmd *cmd);
int dnet_notify_remove(struct dnet_net_state *st, struct dnet_cmd *cmd);

int dnet_notify_init(struct dnet_node *n);
void dnet_notify_exit(struct dnet_node *n);

struct dnet_group
{
	struct list_head	group_entry;

	unsigned int		group_id;

	struct list_head	state_list;

	atomic_t		refcnt;

	int			id_num;
	struct dnet_state_id	*ids;
};

static inline struct dnet_group *dnet_group_get(struct dnet_group *g)
{
	atomic_inc(&g->refcnt);
	return g;
}

void dnet_group_destroy(struct dnet_group *g);
static inline void dnet_group_put(struct dnet_group *g)
{
	if (g && atomic_dec_and_test(&g->refcnt))
		dnet_group_destroy(g);
}

struct dnet_transform
{
	void			*priv;

	int 			(* transform)(void *priv, struct dnet_session *s, const void *src, uint64_t size,
					void *dst, unsigned int *dsize, unsigned int flags);
};

int dnet_crypto_init(struct dnet_node *n);
void dnet_crypto_cleanup(struct dnet_node *n);

struct dnet_net_io {
	int			epoll_fd;
	pthread_t		tid;
	struct dnet_node	*n;
};

enum dnet_work_io_mode {
	DNET_WORK_IO_MODE_BLOCKING = 0,
	DNET_WORK_IO_MODE_NONBLOCKING,
	DNET_WORK_IO_MODE_EXEC_BLOCKING,
};

struct dnet_work_pool;
struct dnet_work_io {
	struct list_head	wio_entry;
	int			thread_index;
	pthread_t		tid;
	struct dnet_work_pool	*pool;
};

struct list_stat {
	uint64_t		list_size;
	uint64_t		volume;
	uint64_t		min_list_size;
	uint64_t		max_list_size;
	struct timeval	time_base;
};

static inline void list_stat_init(struct list_stat *st) {
	st->list_size = 0ULL;
	st->volume = 0ULL;
	st->min_list_size = ~0ULL;
	st->max_list_size = 0ULL;
	memset(&st->time_base, 0, sizeof(struct timeval));
}

static inline void list_stat_size_increase(struct list_stat *st, int num) {
	st->list_size += num;

	st->volume += num;
	if (st->list_size > st->max_list_size)
		st->max_list_size = st->list_size;
}

static inline void list_stat_size_decrease(struct list_stat *st, int num) {
	st->list_size -= num;

	if (st->list_size < st->min_list_size)
		st->min_list_size = st->list_size;
}

static inline void list_stat_reset(struct list_stat *st, struct timeval *time) {
	st->volume = 0ULL;
	st->min_list_size = ~0ULL;
	st->max_list_size = 0ULL;
	st->time_base.tv_sec = time->tv_sec;
	st->time_base.tv_usec = time->tv_usec;
}

struct dnet_work_pool {
	struct dnet_node	*n;
	int			mode;
	int			num;
	struct list_head	list;
	struct list_stat	list_stats;
	pthread_mutex_t		lock;
	pthread_cond_t		wait;
	struct list_head	wio_list;
	uint64_t		*trans;
};

struct dnet_io {
	int			need_exit;

	int			net_thread_num, net_thread_pos;
	struct dnet_net_io	*net;

	struct dnet_work_pool	*recv_pool;
	struct dnet_work_pool	*recv_pool_nb;

	// condition variable for waiting when io pools are able to process packets
	pthread_mutex_t		full_lock;
	pthread_cond_t		full_wait;
};

int dnet_state_accept_process(struct dnet_net_state *st, struct epoll_event *ev);
int dnet_state_net_process(struct dnet_net_state *st, struct epoll_event *ev);
int dnet_io_init(struct dnet_node *n, struct dnet_config *cfg);
void dnet_io_exit(struct dnet_node *n);

void dnet_io_req_free(struct dnet_io_req *r);

struct dnet_locks_entry {
	struct rb_node		lock_tree_entry;
	struct list_head	lock_list_entry;
	pthread_mutex_t		lock;
	pthread_cond_t		wait;
	struct dnet_raw_id	id;
	int			locked;
	atomic_t		refcnt;
};

struct dnet_locks {
	struct list_head	lock_list;
	struct rb_root		lock_tree;
	pthread_mutex_t		lock;
};

void dnet_locks_destroy(struct dnet_node *n);
int dnet_locks_init(struct dnet_node *n, int num);
void dnet_oplock(struct dnet_node *n, struct dnet_id *key);
void dnet_opunlock(struct dnet_node *n, struct dnet_id *key);
int dnet_optrylock(struct dnet_node *n, struct dnet_id *key);

struct dnet_config_data {
	struct dnet_log backend_logger;
	char *logger_value;

	int cfg_addr_num;
	struct dnet_addr *cfg_addrs;

	struct dnet_config cfg_state;
	char *cfg_remotes;
	int daemon_mode;

	struct dnet_config_entry *cfg_entries;
	int cfg_size;
	struct dnet_config_backend *cfg_current_backend;

	struct dnet_config_backend *cfg_backend;
	int cfg_backend_num;
};

struct dnet_node
{
	struct list_head	check_entry;

	struct dnet_transform	transform;

	int			need_exit;

	int			autodiscovery_socket;
	struct dnet_addr	autodiscovery_addr;

	struct dnet_id		id;

	int			flags;
	int			ro;

	pthread_attr_t		attr;

	int			addr_num;
	struct dnet_addr	*addrs;

	pthread_mutex_t		state_lock;
	struct list_head	group_list;

	/* hosts client states, i.e. those who didn't join network */
	struct list_head	empty_state_list;

	/* hosts all states added to given node */
	struct list_head	storage_state_list;

	atomic_t		trans;

	struct dnet_net_state	*st;

	int			error;

	struct dnet_log		*log;

	struct dnet_wait	*wait;
	struct timespec		wait_ts;

	struct dnet_io		*io;

	int			check_in_progress;
	long			check_timeout;
	int			cache_sync_timeout;

	pthread_t		check_tid;
	pthread_t		reconnect_tid;
	long			stall_count;


	struct dnet_backend_callbacks	*cb;

	unsigned int		notify_hash_size;
	struct dnet_notify_bucket	*notify_hash;

	pthread_mutex_t		reconnect_lock;
	struct list_head	reconnect_list;

	struct dnet_lock	counters_lock;
	struct dnet_stat_count	counters[__DNET_CNTR_MAX];

	int			bg_ionice_class;
	int			bg_ionice_prio;
	int			removal_delay;

	char			cookie[DNET_AUTH_COOKIE_SIZE];

	void			*srw;
	void			*indexes;
	int			indexes_shard_count;

	int			server_prio;
	int			client_prio;

	struct dnet_locks	*locks;
	/*
	 * List of dnet_iterator.
	 * Used for iterator management e.g. pause/continue actions.
	 */
	struct list_head	iterator_list;
	/*
	 * Lock used for list management
	 */
	pthread_mutex_t		iterator_lock;

	size_t			cache_size;
	size_t			caches_number;
	size_t			cache_pages_number;
	unsigned int	*cache_pages_proportions;
	void			*cache;

	void			*monitor;
	pthread_rwlock_t monitor_rwlock;

	struct dnet_config_data *config_data;
};


struct dnet_session {
	struct dnet_node	*node;

	int			group_num;
	int			*groups;

	struct timespec		wait_ts;

	struct dnet_time	ts;

	uint64_t		cflags;
	uint64_t		user_flags;
	uint32_t		ioflags;

	/*
	 * If DNET_FLAGS_DIRECT is set then direct_id is used for sticking
	 * requests to the node which is responsible for a particular
	 * direct_id.id.
	 */
	struct dnet_id		direct_id;

	/* Namespace */
	char			*ns;
	int			nsize;
};

static inline int dnet_counter_init(struct dnet_node *n)
{
	memset(&n->counters, 0, __DNET_CNTR_MAX * sizeof(struct dnet_stat_count));
	return dnet_lock_init(&n->counters_lock);
}

static inline void dnet_counter_destroy(struct dnet_node *n)
{
	return dnet_lock_destroy(&n->counters_lock);
}

static inline void dnet_counter_inc(struct dnet_node *n, int counter, int err)
{
	if (counter >= __DNET_CNTR_MAX)
		counter = DNET_CNTR_UNKNOWN;

	dnet_lock_lock(&n->counters_lock);
	if (!err)
		n->counters[counter].count++;
	else
		n->counters[counter].err++;
	dnet_lock_unlock(&n->counters_lock);

	dnet_log(n, DNET_LOG_DEBUG, "Incrementing counter: %d, err: %d, value is: %llu %llu.\n",
				counter, err,
				(unsigned long long)n->counters[counter].count,
				(unsigned long long)n->counters[counter].err);
}

static inline void dnet_counter_set(struct dnet_node *n, int counter, int err, int64_t val)
{
	if (counter >= __DNET_CNTR_MAX)
		counter = DNET_CNTR_UNKNOWN;

	dnet_lock_lock(&n->counters_lock);
	if (!err)
		n->counters[counter].count = val;
	else
		n->counters[counter].err = val;
	dnet_lock_unlock(&n->counters_lock);
}

struct dnet_trans;
int __attribute__((weak)) dnet_process_cmd_raw(struct dnet_net_state *st, struct dnet_cmd *cmd, void *data, int recursive);
int dnet_process_recv(struct dnet_net_state *st, struct dnet_io_req *r);

int dnet_recv(struct dnet_net_state *st, void *data, unsigned int size);
int dnet_sendfile(struct dnet_net_state *st, int fd, uint64_t *offset, uint64_t size);

int dnet_send_request(struct dnet_net_state *st, struct dnet_io_req *r);

int __attribute__((weak)) dnet_send_ack(struct dnet_net_state *st, struct dnet_cmd *cmd, int err, int recursive);

struct dnet_config;
int dnet_socket_create(struct dnet_node *n, char *addr_str, int port, struct dnet_addr *addr, int listening);
int dnet_socket_create_addr(struct dnet_node *n, struct dnet_addr *addr, int listening);

void dnet_set_sockopt(int s);
void dnet_sock_close(int s);

enum dnet_join_state {
	DNET_JOIN = 1,			/* Node joined the network */
	DNET_WANT_RECONNECT,		/* State must be reconnected, when remote peer failed */
};

int __attribute__((weak)) dnet_state_join_nolock(struct dnet_net_state *st);

struct dnet_trans
{
	struct rb_node			trans_entry;
	struct list_head		trans_list_entry;

	struct timeval			time, start;
	struct timespec			wait_ts;

	struct dnet_net_state		*orig; /* only for forward */

	struct dnet_net_state		*st;
	uint64_t			trans, rcv_trans;
	struct dnet_cmd			cmd;

	atomic_t			refcnt;

	int				command; /* main command this transaction carries */

	void				*priv;
	int				(* complete)(struct dnet_net_state *st,
						     struct dnet_cmd *cmd,
						     void *priv);
};

void dnet_trans_destroy(struct dnet_trans *t);
struct dnet_trans *dnet_trans_alloc(struct dnet_node *n, uint64_t size);
int dnet_trans_alloc_send_state(struct dnet_session *s, struct dnet_net_state *st, struct dnet_trans_control *ctl);
int dnet_trans_timer_setup(struct dnet_trans *t);

static inline struct dnet_trans *dnet_trans_get(struct dnet_trans *t)
{
	atomic_inc(&t->refcnt);
	return t;
}

static inline void dnet_trans_put(struct dnet_trans *t)
{
	if (t && atomic_dec_and_test(&t->refcnt))
		dnet_trans_destroy(t);
}

int dnet_trans_insert_nolock(struct rb_root *root, struct dnet_trans *a);
void dnet_trans_remove(struct dnet_trans *t);
void dnet_trans_remove_nolock(struct rb_root *root, struct dnet_trans *t);
struct dnet_trans *dnet_trans_search(struct rb_root *root, uint64_t trans);

void dnet_trans_clean_list(struct list_head *head);
int dnet_trans_iterate_move_transaction(struct dnet_net_state *st, struct list_head *head);
int dnet_state_reset_nolock_noclean(struct dnet_net_state *st, int error, struct list_head *head);

int dnet_trans_send(struct dnet_trans *t, struct dnet_io_req *req);

int dnet_recv_list(struct dnet_node *n, struct dnet_net_state *st);

ssize_t dnet_send_fd(struct dnet_net_state *st, void *header, uint64_t hsize,
		int fd, uint64_t offset, uint64_t dsize, int on_exit);
ssize_t dnet_send_data(struct dnet_net_state *st, void *header, uint64_t hsize, void *data, uint64_t dsize);
ssize_t dnet_send(struct dnet_net_state *st, void *data, uint64_t size);
ssize_t dnet_send_nolock(struct dnet_net_state *st, void *data, uint64_t size);

struct dnet_io_completion
{
	struct dnet_wait	*wait;
	char			*file;
	uint64_t		offset;
};

struct dnet_addr_storage
{
	int				reconnect_time, reconnect_time_max;
	struct list_head		reconnect_entry;
	struct dnet_addr		addr;
	unsigned int			__join_state;
};

int dnet_check_thread_start(struct dnet_node *n);
void dnet_check_thread_stop(struct dnet_node *n);
int dnet_try_reconnect(struct dnet_node *n);

int dnet_set_name(char *name);
int dnet_ioprio_set(long pid, int class_id, int prio);
int dnet_ioprio_get(long pid);

struct dnet_map_fd {
	int			fd;
	uint64_t		offset, size;

	void			*data;

	uint64_t		mapped_size;
	void			*mapped_data;
};

/* Read only mapping wrapper */
int dnet_data_map(struct dnet_map_fd *map);
/* Read-write mapping wrapper */
int dnet_data_map_rw(struct dnet_map_fd *map);
void dnet_data_unmap(struct dnet_map_fd *map);

int dnet_srw_init(struct dnet_node *n, struct dnet_config *cfg);
void dnet_srw_cleanup(struct dnet_node *n);
int dnet_cmd_exec_raw(struct dnet_net_state *st, struct dnet_cmd *cmd, struct sph *header, const void *data);

int dnet_cache_init(struct dnet_node *n);
void dnet_cache_cleanup(struct dnet_node *n);
int dnet_cmd_cache_io(struct dnet_net_state *st, struct dnet_cmd *cmd, struct dnet_io_attr *io, char *data);
int dnet_cmd_cache_indexes(struct dnet_net_state *st, struct dnet_cmd *cmd, struct dnet_indexes_request *request);
int dnet_cmd_cache_lookup(struct dnet_net_state *st, struct dnet_cmd *cmd);

int dnet_indexes_init(struct dnet_node *, struct dnet_config *);
void dnet_indexes_cleanup(struct dnet_node *);
int dnet_process_indexes(struct dnet_net_state *st, struct dnet_cmd *cmd, void *data);

int dnet_ids_update(int update_local, const char *file, struct dnet_addr *cfg_addrs, char *remotes);

int __attribute__((weak)) dnet_remove_local(struct dnet_node *n, struct dnet_id *id);
int __attribute__((weak)) dnet_cas_local(struct dnet_node *n, struct dnet_id *id, void *csum, int csize);

int dnet_discovery(struct dnet_node *n);

/*
 * Internal iterator state
 */
struct dnet_iterator {
	uint64_t			id;		/* Iterator's unique id */
	enum dnet_iterator_action	state;		/* Desired state of iterator */
	struct list_head		list;		/* List of all iterators */
	pthread_mutex_t			lock;		/* Lock for iterator manipulation */
	pthread_cond_t			wait;		/* We wait here in case we stopped */
};

/*
 * Public iterator API
 */
struct dnet_iterator *dnet_iterator_create(struct dnet_node *n);
void dnet_iterator_destroy(struct dnet_node *n, struct dnet_iterator *it);
int dnet_iterator_set_state(struct dnet_node *n,
		enum dnet_iterator_action action, uint64_t id);
void dnet_iterator_cancel_all(struct dnet_node *n);

/*
 * Low level iterator API
 * TODO: make static?
 */

/* Allocate and init iterator */
struct dnet_iterator *dnet_iterator_alloc(uint64_t id);
/* Free previously allocated iterator */
void dnet_iterator_free(struct dnet_iterator *it);
/* Iterator list management routines */
int dnet_iterator_list_insert_nolock(struct dnet_node *n, struct dnet_iterator *it);
struct dnet_iterator *dnet_iterator_list_lookup_nolock(struct dnet_node *n, uint64_t id);
int dnet_iterator_list_remove(struct dnet_node *n, uint64_t id);
/* Misc routines */
uint64_t dnet_iterator_list_next_id_nolock(struct dnet_node *n);

/*
 * Common private data:
 * Request + next callback and it's argument.
 */
struct dnet_iterator_common_private {
	struct dnet_iterator_request	*req;		/* Original request */
	struct dnet_iterator_range		*range;		/* Original ranges */
	struct dnet_iterator		*it;		/* Iterator control structure */
	int				(*next_callback)(void *priv, void *data, uint64_t dsize);
	void				*next_private;	/* One of predefined callbacks */
};

/*
 * Send over network callback private.
 */
struct dnet_iterator_send_private {
	struct dnet_net_state		*st;		/* State to send data to */
	struct dnet_cmd			*cmd;		/* Command */
};

/*
 * Save to file callback private.
 */
struct dnet_iterator_file_private {
	int				fd;		/* Append mode file descriptor */
};

#ifndef CONFIG_ELLIPTICS_VERSION_0
#error "Elliptics version macros is not defined"
#endif
#ifndef CONFIG_ELLIPTICS_VERSION_1
#error "Elliptics version macros is not defined"
#endif
#ifndef CONFIG_ELLIPTICS_VERSION_2
#error "Elliptics version macros is not defined"
#endif
#ifndef CONFIG_ELLIPTICS_VERSION_3
#error "Elliptics version macros is not defined"
#endif

static inline void dnet_version_encode(struct dnet_id *id)
{
	int *ids = (int *)(id->id);

	ids[0] = dnet_bswap32(CONFIG_ELLIPTICS_VERSION_0);
	ids[1] = dnet_bswap32(CONFIG_ELLIPTICS_VERSION_1);
	ids[2] = dnet_bswap32(CONFIG_ELLIPTICS_VERSION_2);
	ids[3] = dnet_bswap32(CONFIG_ELLIPTICS_VERSION_3);
}

static inline void dnet_version_decode(struct dnet_id *id, int version[4])
{
	int *ids = (int *)(id->id);
	unsigned int i;

	for (i = 0; i < 4; ++i)
		version[i] = dnet_bswap32(ids[i]);
}

static inline int dnet_version_check(struct dnet_net_state *st, int *version)
{
	struct dnet_node *n = st->n;
	int err = 0;

	if ((version[0] == CONFIG_ELLIPTICS_VERSION_0) && (version[1] == CONFIG_ELLIPTICS_VERSION_1)) {
		dnet_log(n, DNET_LOG_INFO, "%s: reverse lookup command: network version: %d.%d.%d.%d, local version: %d.%d.%d.%d\n",
				dnet_state_dump_addr(st),
				version[0], version[1], version[2], version[3],
				CONFIG_ELLIPTICS_VERSION_0, CONFIG_ELLIPTICS_VERSION_1,
				CONFIG_ELLIPTICS_VERSION_2, CONFIG_ELLIPTICS_VERSION_3);
	} else {
		dnet_log(n, DNET_LOG_ERROR, "%s: reverse lookup command: VERSION MISMATCH: "
				"network version: %d.%d.%d.%d, local version: %d.%d.%d.%d\n",
				dnet_state_dump_addr(st),
				version[0], version[1], version[2], version[3],
				CONFIG_ELLIPTICS_VERSION_0, CONFIG_ELLIPTICS_VERSION_1,
				CONFIG_ELLIPTICS_VERSION_2, CONFIG_ELLIPTICS_VERSION_3);
		err = -EPROTO;
	}

	return err;
}

static inline void dnet_indexes_shard_count_encode(struct dnet_id *id, int count)
{
    int *data = (int *)(id->id);

    data[5] = dnet_bswap32(count);
}

static inline void dnet_indexes_shard_count_decode(struct dnet_id *id, int *count)
{
    int *data = (int *)(id->id);

    *count = dnet_bswap32(data[5]);
}

static inline int dnet_empty_addr(struct dnet_addr *addr)
{
	static struct dnet_addr __empty;

	return memcmp(addr, &__empty, addr->addr_len) == 0;
}

#ifdef __cplusplus
}
#endif

#endif /* __DNET_ELLIPTICS_H */
