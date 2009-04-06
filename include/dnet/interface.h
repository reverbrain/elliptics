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

#ifndef __DNET_INTERFACE_H
#define __DNET_INTERFACE_H

#include <dnet/typedefs.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

struct dnet_net_state;
struct dnet_node;

/*
 * Callback data structures.
 *
 * [dnet_cmd]
 * [dnet_attr] [attributes]
 *
 * [dnet_cmd] header when present shows number of attached bytes.
 * It should be equal to the al_attr structure at least in the
 * correct message, otherwise it should be discarded.
 * One can also check cmd->flags if it has DNET_FLAGS_MORE or
 * DNET_FLAGS_DESTROY bit set. The former means that callback
 * will be invoked again in the future and transaction is not
 * yet completed. The latter means that transaction is about
 * to be destroyed.
 */

/*
 * IO helpers.
 *
 * dnet_node is a node pointer returned by calling dnet_node_create()
 * dnet_io_attr contains IO details (size, offset and the checksum)
 * completion callback (if present) will be invoked when IO transaction is finished
 * private data will be stored in the appropriate transaction and can be obtained
 * when transaction completion callback is invoked. It will be automatically
 * freed when transaction is completed.
 */

struct dnet_io_control
{
	unsigned char			id[DNET_ID_SIZE];
	struct dnet_io_attr		io;
	int 				(* complete)(struct dnet_net_state *st, struct dnet_cmd *cmd,
							struct dnet_attr *attr, void *priv);
	void				*priv;

	void				*data;

	unsigned int			aflags;
	int				fd;
	unsigned int			cmd;
};

/*
 * Reads an object identified by the provided ID from the appropriate node.
 * In case of error completion callback may be invoked with all parameters
 * set to null, private pointer will be setto what was provided by the user as private data).
 *
 * Returns negative error value in case of error.
 */
int dnet_read_object(struct dnet_node *n, struct dnet_io_control *ctl);

/*
 * Reads given file from the storage. If there are multiple transformation functions,
 * they will be tried one after another.
 *
 * Returns negative error value in case of error.
 */
int dnet_read_file(struct dnet_node *n, char *file, uint64_t offset, uint64_t size, unsigned int aflags);

/*
 * dnet_write_object() returns number of nodes transaction was sent to.
 * Usually it should be equal to 2 multipled by number of transformation functions,
 * since system sends transaction itself and history update.
 *
 * ->complete() will also be called for each transformation function twice,
 *  if there was an error all parameters maybe NULL (private pointer will be set
 *  to what was provided by the user as private data).
 */
int dnet_write_object(struct dnet_node *n, struct dnet_io_control *ctl, void *remote, unsigned int len);

/*
 * Sends given file to the remote nodes and waits until all of them ack the write.
 *
 * Returns negative error value in case of error.
 */
int dnet_write_file(struct dnet_node *n, char *file, off_t offset, size_t size, unsigned int io_flags, unsigned int aflags);

#define DNET_LOG_NOTICE			(1<<0)
#define DNET_LOG_INFO			(1<<1)
#define DNET_LOG_TRANS			(1<<2)
#define DNET_LOG_ERROR			(1<<3)

#define DNET_MAX_ADDRLEN		256
#define DNET_MAX_PORTLEN		8

/*
 * Node configuration interface.
 */
struct dnet_config
{
	/*
	 * Unique network-wide ID.
	 */
	unsigned char		id[DNET_ID_SIZE];

	/*
	 * Socket type (SOCK_STREAM, SOCK_DGRAM and so on),
	 * a protocol (IPPROTO_TCP for example) and
	 * a family (AF_INET, AF_INET6 and so on)
	 * of the appropriate socket. These parameters are
	 * sent in the lookup replies so that remote nodes
	 * could know how to connect to this one.
	 */
	int			sock_type, proto, family;

	/*
	 * Socket address/port suitable for the getaddrinfo().
	 */
	char			addr[DNET_MAX_ADDRLEN];
	char			port[DNET_MAX_PORTLEN];

	/*
	 * Wait timeout in seconds used for example to wait
	 * for remote content sync.
	 */
	unsigned int		wait_timeout;

	/*
	 * Specifies wether given node will join the network,
	 * or it is a client node and its ID should not be checked
	 * against collision with others.
	 */
	int			join;

	uint32_t		log_mask;
	void			*log_private;
	void 			(* log)(void *priv, uint32_t mask, const char *msg);

	/*
	 * Network command handler.
	 * Returns negative error value or zero in case of success.
	 */
	int			(* command_handler)(void *state, void *priv,
			struct dnet_cmd *cmd, struct dnet_attr *attr, void *data);
	void			*command_private;

	/* Number of IO threads created for each node,
	 * if zero default number will be allocated
	 * (DNET_IO_THREAD_NUM_DEFAULT)
	 */
	int			io_thread_num;

	/*
	 * Maximum number of transactions from the same client processed in parallel.
	 * If not set default number is used 
	 */
	uint64_t		max_pending;	
};

void dnet_command_handler_log(void *state, uint32_t mask, const char *format, ...) DNET_LOG_CHECK;
void dnet_log(struct dnet_node *n, uint32_t mask, const char *format, ...) DNET_LOG_CHECK;
#define dnet_log_err(n, f, a...) dnet_log(n, DNET_LOG_ERROR, "%s: " f ": %s [%d].\n", \
		dnet_dump_id(n->id), ##a, strerror(errno), errno)

/*
 * Transformation functions are used to create ID from the provided data content.
 * One can add/remove them in a run-time. init/update/final sequence is used
 * each time for every transformed block, update can be invoked multiple times
 * between init and final ones.
 */
int dnet_add_transform(struct dnet_node *n, void *priv, char *name,
	int (* init)(void *priv),
	int (* update)(void *priv, void *src, uint64_t size,
		void *dst, unsigned int *dsize, unsigned int flags),
	int (* final)(void *priv, void *dst, unsigned int *dsize, unsigned int flags));
int dnet_remove_transform(struct dnet_node *n, char *name);

/*
 * Node creation/destruction callbacks. Node is a building block of the storage
 * and it is needed for every operation one may want to do with the network.
 */
struct dnet_node *dnet_node_create(struct dnet_config *);
void dnet_node_destroy(struct dnet_node *n);

/*
 * dnet_add_state() is used to add a node into the route list, the more
 * routes are added the less network lookups will be performed to send/receive
 * data requests.
 */
int dnet_add_state(struct dnet_node *n, struct dnet_config *cfg);

/*
 * This is used to join the network. When function is completed, node will be
 * used to store data sent from the network.
 */
int dnet_join(struct dnet_node *n);

static inline char *dnet_dump_id(unsigned char *id)
{
	unsigned int i;
	static char __dnet_dump_str[2 * DNET_ID_SIZE + 1];

	for (i=0; i<DNET_ID_SIZE; ++i)
		sprintf(&__dnet_dump_str[2*i], "%02x", id[i]);
	return __dnet_dump_str;
}

/*
 * Send a shell command to the remote node for execution.
 */
int dnet_send_cmd(struct dnet_node *n, unsigned char *id, char *command);

/*
 * Must be called by the main thread to give up control
 * to the elliptics machinery sometime after node has joined the network.
 *
 * This will pick up disconnected states and rejoin them.
 */
int dnet_give_up_control(struct dnet_node *n);

/*
 * Lookup a node which hosts given ID.
 */
int dnet_lookup_object(struct dnet_node *n, unsigned char *id,
	int (* complete)(struct dnet_net_state *, struct dnet_cmd *, struct dnet_attr *, void *),
	void *priv);
int dnet_lookup(struct dnet_node *n, char *file);
int dnet_lookup_complete(struct dnet_net_state *st, struct dnet_cmd *cmd,
		struct dnet_attr *attr, void *priv);

static inline int dnet_id_cmp(unsigned char *id1, unsigned char *id2)
{
	unsigned int i = 0;
#if 0
	const unsigned long *l1 = (unsigned long *)id1;
	const unsigned long *l2 = (unsigned long *)id2;

	for (i=0; i<DNET_ID_SIZE/sizeof(unsigned long); ++i) {
		if (l1[i] > l2[i])
			return -1;
		if (l1[i] < l2[i])
			return 1;
	}
#endif
	for (i*=sizeof(unsigned long); i<DNET_ID_SIZE; ++i) {
		if (id1[i] > id2[i])
			return -1;
		if (id1[i] < id2[i])
			return 1;
	}

	return 0;
}

int dnet_state_get_range(void *state, unsigned char *req, unsigned char *id);

#define DNET_REQ_FREE_HEADER		(1<<0)
#define DNET_REQ_FREE_DATA		(1<<1)
#define DNET_REQ_CLOSE_FD		(1<<2)
#define DNET_REQ_NO_DESTRUCT		(1<<3)

struct dnet_data_req;

void *dnet_req_header(struct dnet_data_req *r);
void *dnet_req_data(struct dnet_data_req *r);

void dnet_req_set_header(struct dnet_data_req *r, void *header, size_t hsize, int free);
void dnet_req_set_data(struct dnet_data_req *r, void *data, size_t size, int free);
void dnet_req_set_fd(struct dnet_data_req *r, int fd, off_t offset, size_t size, int close);
void dnet_req_set_flags(struct dnet_data_req *r, unsigned int mask, unsigned int flags);

struct dnet_data_req *dnet_req_alloc(struct dnet_net_state *st, size_t hsize);
void dnet_req_destroy(struct dnet_data_req *r);

int dnet_data_ready(struct dnet_net_state *st, struct dnet_data_req *r);

#ifdef __cplusplus
}
#endif

#endif /* __DNET_INTERFACE_H */
