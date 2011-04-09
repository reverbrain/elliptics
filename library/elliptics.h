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

#include <kclangc.h>

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

struct dnet_net_state
{
	struct list_head	state_entry;
	struct list_head	storage_state_entry;

	struct dnet_node	*n;

	atomic_t		refcnt;
	int			read_s, write_s;

	int			need_exit;

	int			__join_state;

	struct dnet_addr	addr;

	int			(* process)(struct dnet_net_state *st, struct epoll_event *ev);

	struct dnet_cmd		rcv_cmd;
	uint64_t		rcv_offset;
	uint64_t		rcv_end;
	unsigned int		rcv_flags;
	void			*rcv_data;

	size_t			send_offset;
	pthread_mutex_t		send_lock;
	struct list_head	send_list;

	pthread_mutex_t		trans_lock;
	struct rb_root		trans_root;

	int			la;
	unsigned long long	free;

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
void dnet_idc_destroy(struct dnet_net_state *st);

struct dnet_net_state *dnet_state_create(struct dnet_node *n,
		int group_id, struct dnet_raw_id *ids, int id_num,
		struct dnet_addr *addr, int s, int *errp,
		int (* process)(struct dnet_net_state *st, struct epoll_event *ev));

void dnet_state_reset(struct dnet_net_state *st);

struct dnet_net_state *dnet_state_search_by_addr(struct dnet_node *n, struct dnet_addr *addr);
int dnet_state_search_id(struct dnet_node *n, struct dnet_id *id, struct dnet_state_id *sidp, struct dnet_addr *addr);
struct dnet_net_state *dnet_state_get_first(struct dnet_node *n, struct dnet_id *id);

void dnet_state_destroy(struct dnet_net_state *st);

int dnet_schedule_send(struct dnet_net_state *st);
int dnet_schedule_recv(struct dnet_net_state *st);
void dnet_schedule_command(struct dnet_net_state *st);

void dnet_unschedule_send(struct dnet_net_state *st);
void dnet_unschedule_recv(struct dnet_net_state *st);

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

struct dnet_io {
	int			need_exit;

	int			epoll_fd;

	pthread_t		tid;

	pthread_mutex_t		recv_lock;
	struct list_head	recv_list;
	pthread_cond_t		recv_wait;

	int			thread_num;
	pthread_t		threads[0];
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

	int			listen_socket;

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

	int			join_state;

	int			check_in_progress;
	long			check_timeout;
	pthread_t		check_tid;

	pthread_t		monitor_tid;
	int			monitor_fd;

	KCDB			*history, *meta;

	int			(* command_handler)(void *state, void *priv,
			struct dnet_cmd *cmd, struct dnet_attr *attr, void *data);
	void			*command_private;
	int			(* send)(void *state, void *priv, struct dnet_id *id);

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

struct dnet_trans
{
	struct rb_node			trans_entry;
	struct dnet_net_state		*st;
	uint64_t			trans, rcv_trans;
	struct dnet_cmd			cmd;

	atomic_t			refcnt;

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

struct dnet_trans_send_ctl {
	struct dnet_net_state		*st;
	struct dnet_trans		*t;

	void				*header;
	unsigned long long		hsize;

	void				*data;
	unsigned long long		dsize;

	int				fd;
	unsigned long long		foffset, fsize;
};

int dnet_trans_send(struct dnet_trans_send_ctl *ctl);

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
		struct dnet_id *id, struct dnet_wait *w, int hist, int wait);

int dnet_db_write(struct dnet_node *n, struct dnet_cmd *cmd, void *data);
int dnet_db_read(struct dnet_net_state *st, struct dnet_cmd *cmd, struct dnet_io_attr *io);
int dnet_db_read_raw(struct dnet_node *n, int meta, unsigned char *id, void **datap);
int dnet_db_del(struct dnet_node *n, struct dnet_cmd *cmd, struct dnet_attr *attr);
int dnet_db_list(struct dnet_net_state *st, struct dnet_cmd *cmd, struct dnet_attr *attr);
int dnet_db_sync(struct dnet_node *n);
void dnet_db_cleanup(struct dnet_node *n);
int dnet_db_init(struct dnet_node *n, struct dnet_config *cfg);

#define DNET_CHECK_COPIES_HISTORY		1
#define DNET_CHECK_COPIES_FULL			2

int dnet_check(struct dnet_node *n, struct dnet_meta_container *mc, int check_copies);
int dnet_check_list(struct dnet_net_state *st, struct dnet_check_request *r);

int dnet_request_cmd_single(struct dnet_node *n,
	struct dnet_net_state *st, struct dnet_id *id,
	unsigned int cmd, unsigned int aflags,
	int (* complete)(struct dnet_net_state *state,
			struct dnet_cmd *cmd,
			struct dnet_attr *attr,
			void *priv),
	void *priv);

void dnet_monitor_exit(struct dnet_node *n);
int dnet_monitor_init(struct dnet_node *n, struct dnet_config *cfg);

int dnet_set_name(char *name);

#ifdef __cplusplus
}
#endif

#endif /* __DNET_ELLIPTICS_H */
