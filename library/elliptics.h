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

#include <errno.h>
#include <netdb.h>
#include <string.h>
#include <pthread.h>
#include <time.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#ifndef HAVE_UCHAR
typedef unsigned char u_char;
typedef unsigned short u_short;
#endif

#include <event.h>

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

#define dnet_log(n, mask, format, a...) do { if (n->log && (n->log->log_mask & mask)) dnet_log_raw(n, mask, format, ##a); } while (0)
#define dnet_log_err(n, f, a...) dnet_log(n, DNET_LOG_ERROR, "%s: " f ": %s [%d].\n", \
		dnet_dump_id(n->id), ##a, strerror(errno), errno)

/*
 * Currently executed network state machine:
 * receives and sends command and data.
 */

/* Reading a command */
#define DNET_IO_CMD		(1<<0)

/* Attached data should be discarded */
#define DNET_IO_DROP		(1<<1)

struct dnet_net_state
{
	struct list_head	state_entry;

	struct dnet_node	*n;
	long			timeout;

	atomic_t		refcnt;
	int			s;

	int			__join_state;
	unsigned char		id[DNET_ID_SIZE];

	struct dnet_addr	addr;

	struct event		event;

	struct dnet_cmd		rcv_cmd;
	uint64_t		rcv_offset;
	uint64_t		rcv_size;
	unsigned int		rcv_flags;
	void			*rcv_data;
	struct dnet_trans	*rcv_trans;
	
	struct list_head	snd_list;
	unsigned long long	snd_offset;
	unsigned long long	snd_size;
	unsigned long long	dsize, fsize, hsize, foffset;

	uint64_t		req_pending;

	struct dnet_io_thread	*th;

	struct dnet_stat_count	stat[__DNET_CMD_MAX];
};

struct dnet_net_state *dnet_state_create(struct dnet_node *n, unsigned char *id,
		struct dnet_addr *addr, int s);

int dnet_event_schedule(struct dnet_net_state *st, short mask);

void *dnet_state_process(void *data);

int dnet_state_insert(struct dnet_net_state *new);
int dnet_state_insert_raw(struct dnet_net_state *new);
void dnet_state_remove(struct dnet_net_state *st);
struct dnet_net_state *dnet_state_search_by_addr(struct dnet_node *n, struct dnet_addr *addr);
struct dnet_net_state *dnet_state_search(struct dnet_node *n, unsigned char *id, struct dnet_net_state *self);
struct dnet_net_state *dnet_state_get_first(struct dnet_node *n, unsigned char *id, struct dnet_net_state *self);

struct dnet_net_state *dnet_state_get_next(struct dnet_net_state *st);
struct dnet_net_state *dnet_state_get_prev(struct dnet_net_state *st);

int dnet_state_move(struct dnet_net_state *st);
void dnet_state_destroy(struct dnet_net_state *st);

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
	int err = 0;									\
	struct timespec ts;								\
 	struct timeval tv;								\
	gettimeofday(&tv, NULL);							\
	ts.tv_nsec = tv.tv_usec * 1000 + (wts)->tv_nsec;				\
	ts.tv_sec = tv.tv_sec + (wts)->tv_sec;						\
	pthread_mutex_lock(&(w)->wait_lock);						\
	while (!(condition) && !err)							\
		err = pthread_cond_timedwait(&(w)->wait, &(w)->wait_lock, &ts);		\
	pthread_mutex_unlock(&(w)->wait_lock);						\
	-err;										\
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

struct dnet_io_thread
{
	struct list_head	thread_entry;

	int			pipe[2];
	struct event		ev;

	int			need_exit;

	pthread_t		tid;

	struct dnet_node	*node;

	struct event_base	*base;
};

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

struct dnet_node
{
	struct list_head	check_entry;

	unsigned char		id[DNET_ID_SIZE];

	pthread_rwlock_t	transform_lock;
	struct list_head	transform_list;
	int			transform_num;

	int			need_exit;

	int			listen_socket;

	struct dnet_addr	addr;
	int			sock_type, proto, family;

	pthread_rwlock_t	state_lock;
	struct list_head	state_list;
	struct list_head	empty_state_list;

	struct dnet_lock	trans_lock;
	struct rb_root		trans_root;
	uint64_t		trans;

	struct dnet_net_state	*st;

	int			error;

	int			merge_strategy;

	struct dnet_log		*log;

	struct dnet_wait	*wait;
	struct timespec		wait_ts;

	int			join_state;

	int			resend_count;
	struct timespec		resend_timeout;
	pthread_t		resend_tid;

	int			(* command_handler)(void *state, void *priv,
			struct dnet_cmd *cmd, struct dnet_attr *attr, void *data);
	void			*command_private;

	struct list_head	io_thread_list;
	pthread_rwlock_t	io_thread_lock;
	int			io_thread_num, io_thread_pos;

	uint64_t		max_pending;

	unsigned int		notify_hash_size;
	struct dnet_notify_bucket	*notify_hash;

	pthread_mutex_t		reconnect_lock;
	struct list_head	reconnect_list;
};

static inline char *dnet_dump_node(struct dnet_node *n)
{
	static char buf[128];

	return dnet_server_convert_dnet_addr_raw(&n->addr, buf, sizeof(buf));
}

struct dnet_trans;
int dnet_process_cmd(struct dnet_trans *t);

int dnet_send(struct dnet_net_state *st, void *data, unsigned int size);
int dnet_recv(struct dnet_net_state *st, void *data, unsigned int size);
int dnet_wait(struct dnet_net_state *st);
int dnet_sendfile_data(struct dnet_net_state *st,
		int fd, uint64_t offset, uint64_t size,
		void *header, unsigned int hsize);
int dnet_sendfile(struct dnet_net_state *st, int fd, uint64_t *offset, uint64_t size);

struct dnet_config;
int dnet_socket_create(struct dnet_node *n, struct dnet_config *cfg,
		struct sockaddr *sa, unsigned int *addr_len, int listening);
int dnet_socket_create_addr(struct dnet_node *n, int sock_type, int proto, int family,
		struct sockaddr *sa, unsigned int salen, int listening);

enum dnet_join_state {
	DNET_JOIN = 1,			/* Node joined the network */
	DNET_WANT_RECONNECT,		/* State must be reconnected, when remote peer failed */
};

struct dnet_data_req
{
	struct list_head	req_entry;

	struct dnet_net_state	*st;

	void			*header;
	uint64_t		hsize;

	void			*data;
	uint64_t		dsize;
	uint64_t		doff;

	unsigned int		flags;

	int			fd;
	uint64_t		offset;
	uint64_t		size;

	void			*priv;
	void			(* complete)(struct dnet_data_req *r, int err);
};

struct dnet_trans
{
	struct rb_node			trans_entry;
	struct dnet_net_state		*st;
	uint64_t			trans, recv_trans;
	struct dnet_cmd			cmd;
	void				*data;

	struct dnet_data_req		r;

	atomic_t			refcnt;
	int				resend_count;
	struct timespec			fire_time;

	void				*priv;
	int				(* complete)(struct dnet_net_state *st,
						     struct dnet_cmd *cmd,
						     struct dnet_attr *attr,
						     void *priv);
};

void dnet_trans_destroy(struct dnet_trans *t);
struct dnet_trans *dnet_trans_alloc(struct dnet_node *n, uint64_t size);

static inline struct dnet_trans *dnet_trans_get(struct dnet_trans *t)
{
	atomic_inc(&t->refcnt);
	return t;
}

static inline void dnet_trans_put(struct dnet_trans *t)
{
	if (atomic_dec_and_test(&t->refcnt))
		dnet_trans_destroy(t);
}

void dnet_trans_remove(struct dnet_trans *t);
void dnet_trans_remove_nolock(struct rb_root *root, struct dnet_trans *t);
int dnet_trans_insert(struct dnet_trans *t);
struct dnet_trans *dnet_trans_search(struct rb_root *root, uint64_t trans);

int dnet_trans_create_send(struct dnet_node *n, struct dnet_io_control *ctl);

int dnet_recv_list(struct dnet_node *n, struct dnet_net_state *st);

struct dnet_io_completion
{
	struct dnet_wait	*wait;
	char			*file;
	uint64_t		offset;
	uint64_t		size;
};

struct dnet_transform
{
	struct list_head	tentry;

	char			name[DNET_MAX_NAME_LEN];

	void			*priv;

	int 			(* transform)(void *priv, void *src, uint64_t size,
					void *dst, unsigned int *dsize, unsigned int flags);

	void			(* cleanup)(void *priv);
};

enum dnet_thread_cmd {
	DNET_THREAD_SCHEDULE = 1,		/* Schedule new state event on given thread */
	DNET_THREAD_DATA_READY,			/* Given state has new data, reschedule write event */
	DNET_THREAD_EXIT,			/* Exit event processing */
};

struct dnet_thread_signal
{
	unsigned int		cmd;
	struct dnet_net_state	*state;
} __attribute__ ((packed));

int dnet_signal_thread(struct dnet_net_state *st, unsigned int cmd);
int dnet_signal_thread_raw(struct dnet_io_thread *t, struct dnet_net_state *st, unsigned int cmd);
int dnet_schedule_socket(struct dnet_net_state *st);

void dnet_req_trans_destroy(struct dnet_data_req *r, int err);
int dnet_data_ready_nolock(struct dnet_net_state *st, struct dnet_data_req *r);

struct dnet_addr_storage
{
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

	return !!((long)(t1->tv_nsec - t2->tv_nsec));
}
#define dnet_time_after(t2, t1) 	dnet_time_before(t1, t2)

int dnet_resend_thread_start(struct dnet_node *n);
void dnet_resend_thread_stop(struct dnet_node *n);
int dnet_try_reconnect(struct dnet_node *n);
void dnet_check_tree(struct dnet_node *n, int kill);

int dnet_read_file_id(struct dnet_node *n, char *file, int len,
		int direct, uint64_t write_offset,
		struct dnet_io_attr *io,
		struct dnet_wait *w, int hist, int wait);

#ifdef __cplusplus
}
#endif

#endif /* __DNET_ELLIPTICS_H */
