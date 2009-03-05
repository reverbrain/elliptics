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

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

#include <errno.h>
#include <netdb.h>
#include <string.h>
#include <pthread.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "rbtree.h"
#include "list.h"
#include "packet.h"

#ifdef __cplusplus
extern "C" {
#endif

static inline int el_id_cmp(unsigned char *id1, unsigned char *id2)
{
	unsigned int i = 0;
#if 0
	const unsigned long *l1 = (unsigned long *)id1;
	const unsigned long *l2 = (unsigned long *)id2;

	for (i=0; i<EL_ID_SIZE/sizeof(unsigned long); ++i) {
		if (l1[i] > l2[i])
			return -1;
		if (l1[i] < l2[i])
			return 1;
	}
#endif
	for (i*=sizeof(unsigned long); i<EL_ID_SIZE; ++i) {
		if (id1[i] > id2[i])
			return -1;
		if (id1[i] < id2[i])
			return 1;
	}

	return 0;
}

extern void uloga(const char *f, ...) __attribute__ ((format (printf, 1, 2)));
extern void ulog(const char *f, ...) __attribute__ ((format (printf, 1, 2)));
extern int ulog_init(char *log);

#define ulog_err(f, a...) ulog(f ": %s [%d].\n", ##a, strerror(errno), errno)

static inline char *el_dump_id(unsigned char *id)
{
	unsigned int i;
	static char __el_dump_str[2 * EL_ID_SIZE + 1];

	for (i=0; i<EL_ID_SIZE; ++i)
		sprintf(&__el_dump_str[2*i], "%02x", id[i]);
	return __el_dump_str;
}

#define NIP6(addr) \
	ntohs((addr).s6_addr16[0]), \
	ntohs((addr).s6_addr16[1]), \
	ntohs((addr).s6_addr16[2]), \
	ntohs((addr).s6_addr16[3]), \
	ntohs((addr).s6_addr16[4]), \
	ntohs((addr).s6_addr16[5]), \
	ntohs((addr).s6_addr16[6]), \
	ntohs((addr).s6_addr16[7])
#define NIP6_FMT "%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x"

static inline char *el_server_convert_addr(struct sockaddr *sa, unsigned int len)
{
	static char inet_addr[128];

	memset(&inet_addr, 0, sizeof(inet_addr));
	if (len == sizeof(struct sockaddr_in)) {
		struct sockaddr_in *in = (struct sockaddr_in *)sa;
		sprintf(inet_addr, "%s", inet_ntoa(in->sin_addr));
	} else if (len == sizeof(struct sockaddr_in6)) {
		struct sockaddr_in6 *in = (struct sockaddr_in6 *)sa;
		sprintf(inet_addr, NIP6_FMT, NIP6(in->sin6_addr));
	}
	return inet_addr;
}

static inline int el_server_convert_port(struct sockaddr *sa, unsigned int len)
{
	if (len == sizeof(struct sockaddr_in)) {
		struct sockaddr_in *in = (struct sockaddr_in *)sa;
		return ntohs(in->sin_port);
	} else if (len == sizeof(struct sockaddr_in6)) {
		struct sockaddr_in6 *in = (struct sockaddr_in6 *)sa;
		return ntohs(in->sin6_port);
	}
	return 0;
}

struct dnet_net_state
{
	struct list_head	state_entry;

	struct dnet_node	*n;
	long			timeout;

	pthread_mutex_t		lock;
	int			refcnt;
	int			s;

	pthread_t		tid;

	int			empty;
	unsigned char		id[EL_ID_SIZE];

	struct sockaddr		addr;
	int			addr_len;
};

struct dnet_net_state *dnet_state_create(struct dnet_node *n, unsigned char *id,
		struct sockaddr *addr, int addr_len, int s, void *(* process)(void *));

static inline struct dnet_net_state *dnet_state_get(struct dnet_net_state *st)
{
	pthread_mutex_lock(&st->lock);
	st->refcnt++;
	pthread_mutex_unlock(&st->lock);
	return st;
}
void dnet_state_put(struct dnet_net_state *st);
void *dnet_state_process(void *data);

int dnet_state_insert(struct dnet_net_state *new);
void dnet_state_remove(struct dnet_net_state *st);
struct dnet_net_state *dnet_state_search(struct dnet_node *n, unsigned char *id, struct dnet_net_state *self);
struct dnet_net_state *dnet_state_get_first(struct dnet_node *n, struct dnet_net_state *self);
int dnet_state_move(struct dnet_net_state *st);

struct dnet_node
{
	unsigned char		id[EL_ID_SIZE];

	pthread_mutex_t		tlock;
	struct list_head	tlist;

	int			need_exit;
	pthread_t		tid;

	int			listen_socket;

	struct sockaddr		addr;
	int			addr_len, sock_type, proto;

	pthread_mutex_t		state_lock;
	struct list_head	state_list;
	struct list_head	empty_state_list;

	pthread_mutex_t		trans_lock;
	struct rb_root		trans_root;
	__u64			trans;

	struct dnet_net_state	*st;

	int			rootfd;
	char			*root;
};

static inline char *dnet_dump_node(struct dnet_node *n)
{
	static char buf[128];

	snprintf(buf, sizeof(buf), "%s:%d",
		el_server_convert_addr(&n->addr, n->addr_len),
		el_server_convert_port(&n->addr, n->addr_len));

	return buf;
}

int dnet_process_cmd(struct dnet_net_state *st, struct el_cmd *cmd, void *data);

int dnet_send(struct dnet_net_state *st, void *data, unsigned int size);
int dnet_recv(struct dnet_net_state *st, void *data, unsigned int size);
int dnet_wait(struct dnet_net_state *st);
int dnet_sendfile_data(struct dnet_net_state *st, char *file,
		int fd, off_t offset, size_t size,
		void *header, unsigned int hsize);

struct dnet_config;
int dnet_socket_create(struct dnet_config *cfg, struct sockaddr *sa, int *addr_len, int listening);
int dnet_socket_create_addr(int sock_type, int proto,
		struct sockaddr *sa, unsigned int salen, int listening);

struct dnet_trans
{
	struct rb_node			trans_entry;
	struct dnet_net_state		*st;
	__u64				trans, recv_trans;
	struct el_cmd			cmd;
	void				*data;

	void				*priv;
	int				(* complete)(struct dnet_trans *t, struct dnet_net_state *st);
};

struct dnet_trans *dnet_trans_create(struct dnet_net_state *st);
void dnet_trans_destroy(struct dnet_trans *t);

int dnet_trans_process(struct dnet_net_state *st);

void dnet_trans_remove(struct dnet_trans *t);
void dnet_trans_remove_nolock(struct rb_root *root, struct dnet_trans *t);
int dnet_trans_insert(struct dnet_trans *t);
struct dnet_trans *dnet_trans_search(struct rb_root *root, __u64 trans);

int dnet_cmd_list(struct dnet_net_state *st, struct el_cmd *cmd);
int dnet_recv_list(struct dnet_node *n);

struct dnet_io_completion
{
	char			*file;
	off_t			offset;
	size_t			size;
};

int dnet_read_complete(struct dnet_trans *t, struct dnet_net_state *st __unused);

struct dnet_transform
{
	struct list_head	tentry;

	char			name[EL_MAX_NAME_LEN];

	void			*priv;

	int			(* init)(void *priv);
	int 			(* update)(void *priv, void *src, __u64 size,
					void *dst, unsigned int *dsize, unsigned int flags);
	int 			(* final)(void *priv, void *dst, unsigned int *dsize, unsigned int flags);
};

#ifdef __cplusplus
}
#endif

#endif /* __DNET_ELLIPTICS_H */
