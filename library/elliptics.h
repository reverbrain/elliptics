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

#ifndef __DNET_ELLIPTICS_H
#define __DNET_ELLIPTICS_H

#include <sys/time.h>
#include <sys/socket.h>
#include <sys/epoll.h>

#include <errno.h>
#include <netdb.h>
#include <string.h>
#include <pthread.h>
#include <time.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <eblob/blob.h>

#ifndef HAVE_UCHAR
typedef unsigned char u_char;
typedef unsigned short u_short;
#endif

#include "list.h"

#undef offsetof
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

#define dnet_log(n, mask, format, a...) do { if (n->log && (n->log->log_mask & mask)) dnet_log_raw(n, mask, format, ##a); } while (0)
#define dnet_log_err(n, f, a...) dnet_log(n, DNET_LOG_ERROR, f ": %s [%d].\n", ##a, strerror(errno), errno)

struct dnet_io_req {
	struct list_head	req_entry;

	struct dnet_net_state	*st;

	void			*header;
	size_t			hsize;

	void			*data;
	size_t			dsize;

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

struct dnet_net_state
{
	struct list_head	state_entry;
	struct list_head	storage_state_entry;

	struct dnet_node	*n;

	atomic_t		refcnt;
	int			read_s, write_s;

	int			need_exit;

	int			stall;

	int			__join_state;

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

	pthread_mutex_t		trans_lock;
	struct rb_root		trans_root;
	struct list_head	trans_list;


	int			la;
	unsigned long long	free;
	float			weight;
	long			median_read_time;

	struct dnet_idc		*idc;

	struct dnet_stat_count	stat[__DNET_CMD_MAX];
};

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

struct dnet_net_state *dnet_state_create(struct dnet_node *n,
		int group_id, struct dnet_raw_id *ids, int id_num,
		struct dnet_addr *addr, int s, int *errp, int join,
		int (* process)(struct dnet_net_state *st, struct epoll_event *ev));

void dnet_state_reset(struct dnet_net_state *st);
void dnet_state_remove_nolock(struct dnet_net_state *st);

struct dnet_net_state *dnet_state_search_by_addr(struct dnet_node *n, struct dnet_addr *addr);
struct dnet_net_state *dnet_state_get_first(struct dnet_node *n, struct dnet_id *id);
struct dnet_net_state *dnet_state_search_nolock(struct dnet_node *n, struct dnet_id *id);
struct dnet_net_state *dnet_node_state(struct dnet_node *n);

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
static inline void dnet_state_put(struct dnet_net_state *st)
{
	/*
	 * State can be NULL here when we just want to kick IO thread.
	 */
	if (st && atomic_dec_and_test(&st->refcnt))
		dnet_state_destroy(st);
}

struct dnet_wait
{
	pthread_cond_t		wait;
	pthread_mutex_t		wait_lock;
	int			cond;
	int			status;

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

int dnet_update_notify(struct dnet_net_state *st, struct dnet_cmd *cmd,
		struct dnet_attr *attr, void *data);

int dnet_notify_add(struct dnet_net_state *st, struct dnet_cmd *cmd);
int dnet_notify_remove(struct dnet_net_state *st, struct dnet_cmd *cmd,
		struct dnet_attr *a);

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

	int 			(* transform)(void *priv, void *src, uint64_t size,
					void *dst, unsigned int *dsize, unsigned int flags);
};

int dnet_crypto_init(struct dnet_node *n, void *ns, int nsize);
void dnet_crypto_cleanup(struct dnet_node *n);

struct dnet_net_io {
	int			epoll_fd;
	pthread_t		tid;
	struct dnet_node	*n;
};

struct dnet_io {
	int			need_exit;

	int			net_thread_num, net_thread_pos;
	struct dnet_net_io	*net;

	pthread_mutex_t		recv_lock;
	struct list_head	recv_list;
	pthread_cond_t		recv_wait;

	int			thread_num;
	pthread_t		*threads;
};

int dnet_state_accept_process(struct dnet_net_state *st, struct epoll_event *ev);
int dnet_state_net_process(struct dnet_net_state *st, struct epoll_event *ev);
int dnet_io_init(struct dnet_node *n, struct dnet_config *cfg);
void dnet_io_exit(struct dnet_node *n);

void dnet_io_req_free(struct dnet_io_req *r);

struct dnet_node
{
	struct list_head	check_entry;

	struct dnet_transform	transform;

	pthread_mutex_t		group_lock;
	int			group_num;
	int			*groups;

	int			need_exit;

	struct dnet_id		id;

	int			flags;
	int			ro;

	pthread_attr_t		attr;

	struct dnet_addr	addr;
	int			sock_type, proto, family;

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
	pthread_t		check_tid;

	pthread_t		monitor_tid;
	int			monitor_fd;

	char			*temp_meta_env;

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

	dnet_log(n, DNET_LOG_DSA, "Incrementing counter: %d, err: %d, value is: %llu %llu.\n",
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

static inline char *dnet_dump_node(struct dnet_node *n)
{
	static char buf[128];

	return dnet_server_convert_dnet_addr_raw(&n->addr, buf, sizeof(buf));
}

struct dnet_trans;
int dnet_process_cmd_raw(struct dnet_net_state *st, struct dnet_cmd *cmd, void *data);
int dnet_process_recv(struct dnet_net_state *st, struct dnet_io_req *r);

int dnet_recv(struct dnet_net_state *st, void *data, unsigned int size);
int dnet_sendfile(struct dnet_net_state *st, int fd, uint64_t *offset, uint64_t size);

int dnet_send_request(struct dnet_net_state *st, struct dnet_io_req *r);

struct dnet_config;
int dnet_socket_create(struct dnet_node *n, struct dnet_config *cfg, struct dnet_addr *addr, int listening);
int dnet_socket_create_addr(struct dnet_node *n, int sock_type, int proto, int family,
		struct sockaddr *sa, unsigned int salen, int listening);

void dnet_set_sockopt(int s);
void dnet_sock_close(int s);

enum dnet_join_state {
	DNET_JOIN = 1,			/* Node joined the network */
	DNET_WANT_RECONNECT,		/* State must be reconnected, when remote peer failed */
};

int dnet_state_join_nolock(struct dnet_net_state *st);

struct dnet_trans
{
	struct rb_node			trans_entry;
	struct list_head		trans_list_entry;

	struct timeval			time, start;

	struct dnet_net_state		*orig; /* only for forward */

	struct dnet_net_state		*st;
	uint64_t			trans, rcv_trans;
	struct dnet_cmd			cmd;

	atomic_t			refcnt;

	int				command; /* main command this transaction carries */

	void				*priv;
	int				(* complete)(struct dnet_net_state *st,
						     struct dnet_cmd *cmd,
						     struct dnet_attr *attr,
						     void *priv);
};

void dnet_trans_destroy(struct dnet_trans *t);
struct dnet_trans *dnet_trans_alloc(struct dnet_node *n, uint64_t size);
int dnet_trans_alloc_send_state(struct dnet_net_state *st, struct dnet_trans_control *ctl);
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

int dnet_trans_send(struct dnet_trans *t, struct dnet_io_req *req);

int dnet_trans_create_send_all(struct dnet_node *n, struct dnet_io_control *ctl);

int dnet_recv_list(struct dnet_node *n, struct dnet_net_state *st);

ssize_t dnet_send_fd(struct dnet_net_state *st, void *header, uint64_t hsize, int fd, uint64_t offset, uint64_t dsize);
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

/*
 * Returns true if t1 is before than t2.
 */
static inline int dnet_time_before(struct timespec *t1, struct timespec *t2)
{
	if ((long)(t1->tv_sec - t2->tv_sec) < 0)
		return 1;
	
	if ((long)(t2->tv_sec - t1->tv_sec) < 0)
		return 0;

	return ((long)(t1->tv_nsec - t2->tv_nsec) < 0);
}
#define dnet_time_after(t2, t1) 	dnet_time_before(t1, t2)

int dnet_check_thread_start(struct dnet_node *n);
void dnet_check_thread_stop(struct dnet_node *n);
int dnet_try_reconnect(struct dnet_node *n);

int dnet_read_file_id(struct dnet_node *n, char *file, unsigned int len,
		int direct, uint64_t write_offset, uint64_t io_offset, uint64_t io_size,
		struct dnet_id *id, struct dnet_wait *w, int wait);

#define DNET_CHECK_TYPE_COPIES_HISTORY		1
#define DNET_CHECK_TYPE_COPIES_FULL		2
#define DNET_CHECK_TYPE_MERGE			3
#define DNET_CHECK_TYPE_DELETE			4

#define DNET_BULK_IDS_SIZE			1000
#define DNET_BULK_STATES_ALLOC_STEP		10
#define DNET_BULK_META_UPD_SIZE			1000

struct dnet_bulk_id
{
	uint8_t	id[DNET_ID_SIZE];
	struct dnet_meta_update last_update;
} __attribute__ ((packed));

struct dnet_bulk_state
{
	struct dnet_addr addr;
	pthread_mutex_t	state_lock;
	int num;
	struct dnet_bulk_id *ids;
};

struct dnet_bulk_array
{
	int num;
	struct dnet_bulk_state *states;
};

static inline int dnet_compare_bulk_state(const void *k1, const void *k2)
{
        const struct dnet_bulk_state *st1 = k1;
        const struct dnet_bulk_state *st2 = k2;

	if (st1->addr.addr_len > st2->addr.addr_len)
		return 1;
	if (st1->addr.addr_len < st2->addr.addr_len)
		return -1;
	return memcmp(st1->addr.addr, st2->addr.addr, st1->addr.addr_len);
}

int dnet_check(struct dnet_node *n, struct dnet_meta_container *mc, struct dnet_bulk_array *bulk_array, int check_copies);
int dnet_check_list(struct dnet_net_state *st, struct dnet_check_request *r);
#ifdef HAVE_CHECK
int dnet_cmd_bulk_check(struct dnet_net_state *orig, struct dnet_cmd *cmd, struct dnet_attr *attr, void *data);
int dnet_request_bulk_check(struct dnet_node *n, struct dnet_bulk_state *state);
#endif

struct dnet_meta_update * dnet_get_meta_update(struct dnet_node *n, struct dnet_meta_container *mc,
		struct dnet_meta_update *meta_update);

int dnet_update_ts_metadata(struct eblob_backend *b, struct dnet_raw_id *id, uint64_t flags_set, uint64_t flags_clear);
int dnet_meta_read_checksum(struct dnet_node *n, struct dnet_raw_id *id, struct dnet_meta_checksum *csum);

int dnet_process_meta(struct dnet_net_state *st, struct dnet_cmd *cmd, struct dnet_attr *a, struct dnet_io_attr *io);

void dnet_monitor_exit(struct dnet_node *n);
int dnet_monitor_init(struct dnet_node *n, struct dnet_config *cfg);

int dnet_set_name(char *name);
int dnet_ioprio_set(long pid, int class, int prio);
int dnet_ioprio_get(long pid);

#ifdef __cplusplus
}
#endif

#endif /* __DNET_ELLIPTICS_H */
