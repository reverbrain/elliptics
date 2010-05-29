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

#include <dnet/core.h>
#include <dnet/typedefs.h>

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include "dnet/packet.h"

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
	/* Used as cmd->id - 'address' of the remote node */
	unsigned char			addr[DNET_ID_SIZE];

	/*
	 * IO control structure - it is copied into resulted transaction as is.
	 * During write origin will be replaced with data transformation, and
	 * id will be replaced with the object name transformation.
	 */
	struct dnet_io_attr		io;

	/*
	 * If present, will be invoked when transaction is completed.
	 * Can be invoked multiple times, the last one will be when
	 * cmd->flags does not have DNET_FLAGS_MORE flag.
	 *
	 * All parameters are releated to the received transaction reply.
	 */
	int 				(* complete)(struct dnet_net_state *st,
							struct dnet_cmd *cmd,
							struct dnet_attr *attr,
							void *priv);

	/*
	 * Transaction completion private data. Will be accessible in the
	 * above completion callback.
	 */
	void				*priv;

	/*
	 * Data to be sent.
	 */
	void				*data;

	/*
	 * Additional attribute data, which will be copied at the beginning
	 * of the command (it will be the first attribute).
	 * Its size has to match attribute srtucture's size, which will be
	 * dereferenced to be checked.
	 *
	 * Thus attribute structure must be present in CPU endian.
	 */
	void				*adata;
	unsigned int			asize;

	/*
	 * Attribute flag. If present, write transaction will not be split
	 * into multiple parts, when its size exceeds DNET_MAX_TRANS_SIZE bytes.
	 */
	unsigned int			aflags;

	/*
	 * File descriptor to read data from (for the write transaction).
	 */
	int				fd;

	/*
	 * This offset represent local data shift, when local and remote offsets differ.
	 * For example when we want to put local object into transaction but place it
	 * after some bytes in the remote object.
	 */
	uint64_t			local_offset;

	/*
	 * IO command.
	 */
	unsigned int			cmd;

	/*
	 * Command flags (DNET_FLAGS_*)
	 */
	unsigned int			cflags;

	/* Data transaction timestamp */
	struct timespec			ts;
};

/*
 * Reads an object identified by the provided ID from the appropriate node.
 * In case of error completion callback may be invoked with all parameters
 * set to null, private pointer will be setto what was provided by the user
 * as private data).
 *
 * Returns negative error value in case of error.
 */
int dnet_read_object(struct dnet_node *n, struct dnet_io_control *ctl);

/*
 * Reads given file from the storage. If there are multiple transformation functions,
 * they will be tried one after another.
 *
 * If @id is set, it is used as a main object ID, otherwise @file transformation
 * is used as object ID.
 *
 * Returns negative error value in case of error.
 *
 * dnet_read_file_direct() works the same way except it sets DNET_FLAGS_DIRECT flag,
 * which means it will ask node for given object, which is the closest in routing
 * table and will not allow to forward this request to other nodes.
 */
int dnet_read_file(struct dnet_node *n, char *file, char *remote, int remote_len,
		unsigned char *id, uint64_t offset, uint64_t size, int hist);
int dnet_read_file_direct(struct dnet_node *n, char *file, char *remote, int remote_len,
		unsigned char *id, uint64_t offset, uint64_t size, int hist);

/*
 * dnet_write_object() returns 0 on success or negative error otherwise.
 * @trans_num will contain number of nodes data was sent to prior return.
 *
 * ->complete() may be called for each transformation function twice:
 *  for tranasction completion and history update (if specified),
 *  if there was an error all parameters maybe NULL (private pointer will be set
 *  to what was provided by the user as private data).
 *
 *  Transaction will be freed when @flags field in
 *  the command structure (if non null)
 *  does not have DNET_FLAGS_MORE bit set.
 *
 *  if @hupdate is 0, no history update for the @remote or @id object will be done,
 *  otherwise another transaction will be sent to update the history.
 *
 *  If @id is set, it is used as master object ID.
 *  Otherwise if @remote is specified, its transformation is used as master object,
 *  whose history is updated (if @hupdate is set).
 *  Otherwise transaction is considered as self-contained,
 *  and only its own history will be updated.
 */
int dnet_write_object(struct dnet_node *n, struct dnet_io_control *ctl,
		void *remote, int remote_len,
		unsigned char *id, int hupdate, int *trans_num);

/*
 * dmet_write_object_single() works the same way dnet_write_object() does,
 * but only uses single transformation function, which number is specified
 * in @pos. It will be 
 */
int dnet_write_object_single(struct dnet_node *n, struct dnet_io_control *ctl,
		void *remote, unsigned int len, unsigned char *id, int hupdate,
		int *trans_nump, int *pos);
/*
 * Sends given file to the remote nodes and waits until all of them ack the write.
 *
 * Returns negative error value in case of error.
 */
int dnet_write_file(struct dnet_node *n, char *file, char *remote, int remote_len,
		unsigned char *id, uint64_t offset, uint64_t size, unsigned int aflags);

/*
 * The same as dnet_write_file() except that is uses @local_offset as local file offset,
 * while @offset is remote file offset. dnet_write_file() assumes that they are the same.
 */
int dnet_write_file_local_offset(struct dnet_node *n, char *file, char *remote, int remote_len,
		unsigned char *id, uint64_t local_offset, uint64_t offset, uint64_t size,
		unsigned int aflags, unsigned int ioflags);

/*
 * Log flags.
 */
#define DNET_LOG_NOTICE			(1<<0)
#define DNET_LOG_INFO			(1<<1)
#define DNET_LOG_TRANS			(1<<2)
#define DNET_LOG_ERROR			(1<<3)
#define DNET_LOG_DSA			(1<<4)

#define DNET_MAX_ADDRLEN		256
#define DNET_MAX_PORTLEN		8

#define DNET_JOIN_NETWORK		(1<<0)
#define DNET_NO_ROUTE_LIST		(1<<1)

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
	 *
	 * Also has a bit to forbid route list download.
	 */
	int			join;

	/*
	 * Logging parameters.
	 * Mask specifies set of the events we are interested in to log.
	 * Private data is used in the log function to get access to whatever
	 * user pointed to.
	 */
	uint32_t		log_mask;
	void			*log_private;
	void 			(* log)(void *priv, uint32_t mask, const char *msg);

	/*
	 * Network command handler.
	 * Returns negative error value or zero in case of success.
	 *
	 * Private data is accessible from the handler as parameter.
	 */
	int			(* command_handler)(void *state, void *priv,
			struct dnet_cmd *cmd, struct dnet_attr *attr, void *data);
	void			*command_private;

	/* Number of IO threads created for each node,
	 * if zero default number will be allocated
	 * (DNET_IO_THREAD_NUM_DEFAULT)
	 */
	int			io_thread_num;

	/* Notify hash table size */
	unsigned int		hash_size;

	/*
	 * Maximum number of transactions from the same client processed in parallel.
	 * If not set default number is used 
	 */
	uint64_t		max_pending;	

	/*
	 * Number of resends client transaction will be tried to be delivered.
	 * Delay between resends corresponds to @resend_timeout.
	 */
	int			resend_count;
	struct timespec		resend_timeout;
};

struct dnet_node *dnet_get_node_from_state(void *state);

/*
 * Logging helpers.
 */

/*
 * Initialize private logging system.
 */
int dnet_log_init(struct dnet_node *n, void *priv, uint32_t mask,
		void (* log)(void *priv, uint32_t mask, const char *msg));

void dnet_command_handler_log_raw(void *state, uint32_t mask, const char *format, ...) DNET_LOG_CHECK;
int dnet_check_log_mask_state(struct dnet_net_state *st, uint32_t mask);
void dnet_log_raw(struct dnet_node *n, uint32_t mask, const char *format, ...) DNET_LOG_CHECK;

#define dnet_command_handler_log(state, mask, format, a...)				\
	do {									\
		if (dnet_check_log_mask_state(state, mask))			\
			dnet_command_handler_log_raw(state, mask, format, ##a); \
	} while (0)

#define NIP6(addr) \
	(addr).s6_addr[0], \
	(addr).s6_addr[1], \
	(addr).s6_addr[2], \
	(addr).s6_addr[3], \
	(addr).s6_addr[4], \
	(addr).s6_addr[5], \
	(addr).s6_addr[6], \
	(addr).s6_addr[7], \
	(addr).s6_addr[8], \
	(addr).s6_addr[9], \
	(addr).s6_addr[10], \
	(addr).s6_addr[11], \
	(addr).s6_addr[12], \
	(addr).s6_addr[13], \
	(addr).s6_addr[14], \
	(addr).s6_addr[15]
#define NIP6_FMT "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x"

/*
 * Logging helpers used for the fine-printed address representation.
 */
static inline char *dnet_server_convert_addr_raw(struct sockaddr *sa, unsigned int len, char *inet_addr, int inet_size)
{
	memset(inet_addr, 0, inet_size);
	if (len == sizeof(struct sockaddr_in)) {
		struct sockaddr_in *in = (struct sockaddr_in *)sa;
		snprintf(inet_addr, inet_size, "%s", inet_ntoa(in->sin_addr));
	} else if (len == sizeof(struct sockaddr_in6)) {
		struct sockaddr_in6 *in = (struct sockaddr_in6 *)sa;
		snprintf(inet_addr, inet_size, NIP6_FMT, NIP6(in->sin6_addr));
	}
	return inet_addr;
}

static inline char *dnet_server_convert_addr(struct sockaddr *sa, unsigned int len)
{
	static char __inet_addr[128];
	return dnet_server_convert_addr_raw(sa, len, __inet_addr, sizeof(__inet_addr));
}

static inline int dnet_server_convert_port(struct sockaddr *sa, unsigned int len)
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

static inline char *dnet_server_convert_dnet_addr_raw(struct dnet_addr *sa, char *inet_addr, int inet_size)
{
	memset(inet_addr, 0, inet_size);
	if (sa->addr_len == sizeof(struct sockaddr_in)) {
		struct sockaddr_in *in = (struct sockaddr_in *)sa->addr;
		snprintf(inet_addr, inet_size, "%s:%d", inet_ntoa(in->sin_addr),
				ntohs(in->sin_port));
	} else if (sa->addr_len == sizeof(struct sockaddr_in6)) {
		struct sockaddr_in6 *in = (struct sockaddr_in6 *)sa->addr;
		snprintf(inet_addr, inet_size, NIP6_FMT":%d", NIP6(in->sin6_addr),
				ntohs(in->sin6_port));
	}
	return inet_addr;
}

static inline char *dnet_server_convert_dnet_addr(struct dnet_addr *sa)
{
	static char ___inet_addr[128];
	return dnet_server_convert_dnet_addr_raw(sa, ___inet_addr, sizeof(___inet_addr));
}

struct dnet_addr *dnet_state_addr(struct dnet_net_state *st);
static inline char *dnet_state_dump_addr(struct dnet_net_state *st)
{
	return dnet_server_convert_dnet_addr(dnet_state_addr(st));
}

static inline char *dnet_state_dump_addr_only(struct dnet_addr *a)
{
	return dnet_server_convert_addr((struct sockaddr *)a->addr, a->addr_len);
}

/*
 * Transformation functions are used to create ID from the provided data content.
 * One can add/remove them in a run-time. init/update/final sequence is used
 * each time for every transformed block, update can be invoked multiple times
 * between init and final ones.
 *
 * Final transformation function has to specify not only transformation result,
 * but also a *dsize bytes of destination address for this data, which will be
 * used as transaction address. This allows to put different IDs to the nodes,
 * which are not supposed to store them.
 *
 * @cleanup will be called wien transformation object is about to be destroyed.
 */
int dnet_add_transform(struct dnet_node *n, void *priv, char *name,
	int (* init)(void *priv, struct dnet_node *n),
	int (* update)(void *priv, void *src, uint64_t size,
		void *dst, unsigned int *dsize, unsigned int flags),
	int (* final)(void *priv, void *dst, void *addr,
		unsigned int *dsize, unsigned int flags),
	void (* cleanup)(void *priv));
int dnet_remove_transform(struct dnet_node *n, char *name, int cleanup);
int dnet_remove_transform_pos(struct dnet_node *n, int pos, int cleanup);
int dnet_move_transform(struct dnet_node *n, char *name, int tail);

/*
 * Cleanup all transformation functions.
 */
void dnet_cleanup_transform(struct dnet_node *n);

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
 * Returns number of states we are connected to.
 * It does not check whether they are alive though.
 */

int dnet_state_num(struct dnet_node *n);

/*
 * This is used to join the network. When function is completed, node will be
 * used to store data sent from the network.
 */
int dnet_join(struct dnet_node *n);

/*
 * Logging helper used to print ID (DNET_ID_SIZE bytes) as a hex string.
 */
static inline char *dnet_dump_id_len_raw(const unsigned char *id, unsigned int len, char *dst)
{
	unsigned int i;

	if (len > DNET_ID_SIZE)
		len = DNET_ID_SIZE;

	for (i=0; i<len; ++i)
		sprintf(&dst[2*i], "%02x", id[i]);
	return dst;
}

static inline char *dnet_dump_id_len(const unsigned char *id, unsigned int len)
{
	static char __dnet_dump_str[2 * DNET_ID_SIZE + 1];
	return dnet_dump_id_len_raw(id, len, __dnet_dump_str);
}

static inline char *dnet_dump_id(const unsigned char *id)
{
	return dnet_dump_id_len(id, 6);
}

/*
 * Send a shell command to the remote node for execution.
 */
int dnet_send_cmd(struct dnet_node *n, unsigned char *id, char *command);

/*
 * Lookup a node which hosts given ID.
 *
 * dnet_lookup_object() will invoke given callback when lookup reply is received.
 * dnet_lookup() will add received address into local route table.
 * dnet_lookup_complete() is a completion function which adds received address
 * 	into local route table.
 *
 * Effectively dnet_lookup() is a dnet_lookup_object() with dnet_lookup_complete()
 * 	completion function.
 */
int dnet_lookup_object(struct dnet_node *n, unsigned char *id, unsigned int aflags,
	int (* complete)(struct dnet_net_state *, struct dnet_cmd *,
		struct dnet_attr *, void *), void *priv);
int dnet_lookup(struct dnet_node *n, char *file);
int dnet_lookup_complete(struct dnet_net_state *st, struct dnet_cmd *cmd,
		struct dnet_attr *attr, void *priv);

/*
 * Compare two IDs.
 * Returns  1 when id1 > id2
 *         -1 when id1 < id2
 *          0 when id1 = id2
 */
static inline int dnet_id_cmp(const unsigned char *id1, const unsigned char *id2)
{
	unsigned int i = 0;

	for (i*=sizeof(unsigned long); i<DNET_ID_SIZE; ++i) {
		if (id1[i] < id2[i])
			return -1;
		if (id1[i] > id2[i])
			return 1;
	}

	return 0;
}

/*
 * Return ID of the next to given node in routing table.
 */
int dnet_state_get_next_id(void *state, unsigned char *id);

static inline int dnet_id_within_range(const unsigned char *id, const unsigned char *start, const unsigned char *last)
{
	int direct = dnet_id_cmp(start, last);
	int ret = 0;

	if (direct > 0) {
		ret = 1;
		if ((dnet_id_cmp(id, start) < 0) && (dnet_id_cmp(id, last) >= 0))
			ret = 0;
	} else if (direct < 0) {
		if ((dnet_id_cmp(id, start) >= 0) && (dnet_id_cmp(id, last) < 0))
			ret = 1;
	} else {
		ret = !!memcmp(id, start, DNET_ID_SIZE);
	}

	return ret;
}

/*
 * Data request machinery.
 * For more details see doc/io_storage_backend.txt
 */
#define DNET_REQ_FREE_HEADER		(1<<0)
#define DNET_REQ_FREE_DATA		(1<<1)
#define DNET_REQ_CLOSE_FD		(1<<2)
#define DNET_REQ_NO_DESTRUCT		(1<<3)

struct dnet_data_req;

void *dnet_req_header(struct dnet_data_req *r);
void *dnet_req_data(struct dnet_data_req *r);
void *dnet_req_private(struct dnet_data_req *r);

void dnet_req_set_header(struct dnet_data_req *r, void *header, uint64_t hsize, int free);
void dnet_req_set_data(struct dnet_data_req *r, void *data, uint64_t size, uint64_t offset, int free);
void dnet_req_set_fd(struct dnet_data_req *r, int fd, uint64_t offset, uint64_t size, int close);
void dnet_req_set_flags(struct dnet_data_req *r, unsigned int mask, unsigned int flags);

/*
 * Completion callback will be invoked when data request is about to be freed,
 * i.e. none holds any reference on it.
 * Completion callback should free data request (if needed) using plain free(3),
 * since otherwise it will not be freed by the system.
 */
void dnet_req_set_complete(struct dnet_data_req *r,
		void (* complete)(struct dnet_data_req *r, int err), void *priv);

struct dnet_data_req *dnet_req_alloc(struct dnet_net_state *st, uint64_t hsize);
void dnet_req_destroy(struct dnet_data_req *r, int err);

int dnet_data_ready(struct dnet_net_state *st, struct dnet_data_req *r);

/*
 * Server-side transformation reading completion structure.
 */
struct dnet_transform_complete
{
	void				*priv;
	void				(* callback)(struct dnet_transform_complete *t,
							char *name);
};

/*
 * Receive list of server-side transformation functions.
 */
int dnet_recv_transform_list(struct dnet_node *n, unsigned char *id,
		struct dnet_transform_complete *t);

/*
 * Send given number of bytes as reply command.
 * It will fill transaction, command and ID from the original command and copy given data.
 * It will set DNET_FLAGS_MORE if original command requested acknowledge or @more is set.
 *
 * If attr->cmd is DNET_CMD_SYNC then plain data will be sent back, otherwise transaction
 * reply will be generated. So effectively difference is in DNET_TRANS_REPLY bit presence.
 */
int dnet_send_reply(void *state, struct dnet_cmd *cmd, struct dnet_attr *attr,
		void *odata, unsigned int size, int more);

/*
 * Request statistics from the node corresponding to given ID.
 * If @id is NULL statistics will be requested from all connected nodes.
 * @cmd specified stat command to use (DNET_CMD_STAT or DNET_CMD_STAT_COUNT).
 *
 * Function will sleep and print into DNET_LOG_INFO log level short
 * statistics if no @complete function is provided, otherwise it returns
 * after queueing all transactions and appropriate callback will be
 * invoked asynchronously.
 * 
 * Function returns number of nodes statistics request was sent to
 * or negative error code. In case of error callback completion can
 * still be called.
 */
int dnet_request_stat(struct dnet_node *n, unsigned char *id, unsigned int cmd,
	int (* complete)(struct dnet_net_state *state,
			struct dnet_cmd *cmd,
			struct dnet_attr *attr,
			void *priv),
	void *priv);

/*
 * Request notifications when given ID is modified.
 * Notifications are sent after update was stored in the IO backend.
 * @id and @complete are not allowed to be NULL.
 *
 * @complete will be invoked each time object with given @id is modified.
 */
int dnet_request_notification(struct dnet_node *n, unsigned char *id,
	int (* complete)(struct dnet_net_state *state,
			struct dnet_cmd *cmd,
			struct dnet_attr *attr,
			void *priv),
	void *priv);

/*
 * Drop notifications for given ID.
 */
int dnet_drop_notification(struct dnet_node *n, unsigned char *id);

/*
 * Low-level transaction allocation and sending function.
 */
struct dnet_trans_control
{
	unsigned char		id[DNET_ID_SIZE];

	unsigned int		cmd;
	unsigned int		cflags;
	unsigned int		aflags;

	unsigned int		size;
	void			*data;

	int			(* complete)(struct dnet_net_state *state,
					struct dnet_cmd *cmd,
					struct dnet_attr *attr,
					void *priv);
	void			*priv;
};

/*
 * Allocate and send transaction according to above control structure.
 */
int dnet_trans_alloc_send(struct dnet_node *n, struct dnet_trans_control *ctl);
int dnet_trans_create_send(struct dnet_node *n, struct dnet_io_control *ctl);

/*
 * Copy ID of the state @num entries back from the one responsible for @id ID.
 * Returns negative error value if operation failed or zero in success case.
 */
int dnet_state_get_prev_id(struct dnet_node *n, unsigned char *id, unsigned char *res, int num);

/*
 * Mark tranasction with @id in the object identified by @origin to be removed.
 * If callback is provided, it will be invoked on completion, otherwise
 * function will block until server returns an acknowledge.
 */
int dnet_remove_object(struct dnet_node *n,
	unsigned char *origin, unsigned char *id,
	int (* complete)(struct dnet_net_state *state,
			struct dnet_cmd *cmd,
			struct dnet_attr *attr,
			void *priv),
	void *priv,
	int direct);

/* Remove object with @id from the storage immediately */
int dnet_remove_object_now(struct dnet_node *n, unsigned char *id, int direct);

/*
 * Remove given file (identified by name or ID) from the storage.
 */
int dnet_remove_file(struct dnet_node *n, char *file, char *remote, int remote_len, unsigned char *file_id);

/*
 * Transformation helper, which uses *ppos as an index for transformation function.
 * @src and @size correspond to to be transformed source data.
 * @dst and @dsize specify destination buffer.
 * Transformation function can fill @addr, which will be copied into command as destination ID,
 * its size is @DNET_ID_SIZE max.
 */
int dnet_transform(struct dnet_node *n, void *src, uint64_t size, void *dst, void *addr,
		unsigned int *dsize, int *ppos);

/*
 * Helper structure and set of functions to map history file and perform basic checks.
 */
struct dnet_history_map
{
	void				*data;
	struct dnet_history_entry	*ent;
	long				num;
	ssize_t				size;
	int				fd;
};

int dnet_map_history(struct dnet_node *n, char *file, struct dnet_history_map *map);
void dnet_unmap_history(struct dnet_node *n, struct dnet_history_map *map);

int dnet_request_ids(struct dnet_node *n, unsigned char *id,
	unsigned int aflags,
	int (* complete)(struct dnet_net_state *state,
			struct dnet_cmd *cmd,
			struct dnet_attr *attr,
			void *priv),
	void *priv);

enum dnet_meta_types {
	DNET_META_TRANSFORM = 1,	/* transformation function names */
	DNET_META_PARENT_OBJECT,	/* parent object name */
	DNET_META_HISTORY,		/* transaction history log */
};

struct dnet_meta
{
	uint32_t			type;
	uint32_t			size;
	uint64_t			common;
	uint8_t				tmp[16];
	uint8_t				data[0];
} __attribute__ ((packed));

static inline void dnet_convert_meta(struct dnet_meta *m)
{
	m->type = dnet_bswap32(m->type);
	m->size = dnet_bswap32(m->size);
	m->common = dnet_bswap64(m->common);
}

/*
 * Modify or search metadata in meta object. Data must be realloc()able.
 */
struct dnet_meta *dnet_meta_search(struct dnet_node *n, void *data, uint32_t size, uint32_t type);
int dnet_meta_remove(struct dnet_node *n, void *data, uint32_t *size, struct dnet_meta *m);
struct dnet_meta *dnet_meta_add(struct dnet_node *n, void *data, uint32_t *size, struct dnet_meta *add, void *add_data);
struct dnet_meta *dnet_meta_replace(struct dnet_node *n, void *data, uint32_t *size, struct dnet_meta *rep, void *rep_data);

/*
 * Read/write metadata object into the storage.
 */
int dnet_meta_write(struct dnet_node *n, struct dnet_meta *m, void *mdata,
		char *obj, int len, char *metafile);
int dnet_meta_read(struct dnet_node *n, char *obj, int len, char *metafile);
int dnet_meta_read_object_id(struct dnet_node *n, unsigned char *id, char *file);

/*
 * Add metadata into meta object located in metafile.
 */
int dnet_meta_create_file(struct dnet_node *n, char *metafile, struct dnet_meta *m, void *mdata);

#ifdef __cplusplus
}
#endif

#endif /* __DNET_INTERFACE_H */
