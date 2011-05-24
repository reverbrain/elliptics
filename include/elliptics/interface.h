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

#include <elliptics/core.h>
#include <elliptics/typedefs.h>

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include "elliptics/packet.h"

#ifdef __cplusplus
extern "C" {
#endif

struct dnet_net_state;
struct dnet_node;

int dnet_need_exit(struct dnet_node *n);
void dnet_set_need_exit(struct dnet_node *n);

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

struct dnet_io_control {
	/* Used as cmd->id/group_id - 'address' of the remote node */
	struct dnet_id			id;

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
 * Read data associated with key @ID and put it to provided @data pointer.
 * Requestted chunk will have at most @size bytes in.
 * It will be read from offset @offset from the start of remote object.
 *
 * Returns number of bytes read or negative error code.
 */
void *dnet_read_data_wait(struct dnet_node *n, struct dnet_id *id, uint64_t *size);

int dnet_send_read_data(void *state, struct dnet_cmd *cmd, struct dnet_io_attr *io,
		void *data, int fd, uint64_t offset);

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
int dnet_read_file(struct dnet_node *n, char *file, void *remote, unsigned int remote_len,
		struct dnet_id *id, uint64_t offset, uint64_t size);
int dnet_read_file_direct(struct dnet_node *n, char *file, void *remote, unsigned int remote_len,
		struct dnet_id *id, uint64_t offset, uint64_t size);

/*
 * dnet_write_object() returns number of transactions sent. If it is equal to 0,
 * then no transactions were sent which indicates error.
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
		void *remote, unsigned int len, struct dnet_id *id);

int dnet_write_data_wait(struct dnet_node *n, void *remote, unsigned int len,
		struct dnet_id *id, void *data, int fd, uint64_t local_offset,
		uint64_t offset, uint64_t size,
		struct timespec *ts, unsigned int aflags, unsigned int ioflags);

/*
 * Sends given file to the remote nodes and waits until all of them ack the write.
 *
 * Returns negative error value in case of error.
 */
int dnet_write_file(struct dnet_node *n, char *file, void *remote, unsigned int len,
		struct dnet_id *id, uint64_t offset, uint64_t size, unsigned int aflags);

/*
 * The same as dnet_write_file() except that is uses @local_offset as local file offset,
 * while @offset is remote file offset. dnet_write_file() assumes that they are the same.
 */
int dnet_write_file_local_offset(struct dnet_node *n, char *file,
		void *remote, unsigned int remote_len, struct dnet_id *id,
		uint64_t local_offset, uint64_t offset, uint64_t size,
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

/* cfg->flags */
#define DNET_CFG_JOIN_NETWORK		(1<<0)		/* given node joins network and becomes part of the storage */
#define DNET_CFG_NO_ROUTE_LIST		(1<<1)		/* do not request route table from remote nodes */
#define DNET_CFG_MIX_STATES		(1<<2)		/* mix states according to their weights before reading data */

struct dnet_log {
	/*
	 * Logging parameters.
	 * Mask specifies set of the events we are interested in to log.
	 * Private data is used in the log function to get access to whatever
	 * user pointed to.
	 */
	uint32_t		log_mask;
	void			*log_private;
	void 			(* log)(void *priv, uint32_t mask, const char *msg);
};

/*
 * Node configuration interface.
 */
struct dnet_config
{
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
	int			flags;

	/*
	 * If node joins network this will be used to find a group to join.
	 */
	int			group_id;

	/* Private logger */
	struct dnet_log		*log;

	/*
	 * Network command handler.
	 * Returns negative error value or zero in case of success.
	 *
	 * Private data is accessible from the handler as parameter.
	 */
	int			(* command_handler)(void *state, void *priv,
			struct dnet_cmd *cmd, struct dnet_attr *attr, void *data);
	void			*command_private;
	int			(* send)(void *state, void *priv, struct dnet_id *id);
	int			(* checksum)(struct dnet_node *n, void *priv, struct dnet_id *id,
			void *csum, int *csize);

	/*
	 * Free and total space on given storage.
	 */
	unsigned long long	storage_free;
	unsigned long long	storage_size;
	int			(* storage_stat)(void *priv, struct dnet_stat *st);

	/* Notify hash table size */
	unsigned int		hash_size;

	/*
	 * Wait until transaction acknowledge is received.
	 */
	long			check_timeout;

	/*
	 * Spawned thread size in bytes.
	 */
	int			stack_size;

	/*
	 * Number of IO threads in processing pool
	 */
	int			io_thread_num;

	/*
	 * Number of threads in network processing pool
	 */
	int			net_thread_num;

	/* Database tuning parameters */
	unsigned long long	db_buckets;
	unsigned long long	db_map;

	/*
	 * KyotoCabinet database flags, can be ORed
	 *
	 * auto sync: 0x20
	 * auto trans: 0x10
	 *
	 * For other flags check /usr/include/kclangc.h -> Open modes
	 */
	unsigned int		db_flags;

	/* Monitor unix socket */
	char			monitor_path[128];

	/* Metadata directory path. */
	char			history_env[1024];
	/* Temporary metadata for CHECK process directory path */
	char			temp_meta_env[1024];

	/* Namespace */
	char			*ns;
	int			nsize;

	/* IO nice parameters for background operations */
	int			bg_ionice_class;
	int			bg_ionice_prio;
	int			removal_delay;
};

struct dnet_node *dnet_get_node_from_state(void *state);

int dnet_node_set_groups(struct dnet_node *n, int *groups, int group_num);

/*
 * Logging helpers.
 */

/*
 * Initialize private logging system.
 */
int dnet_log_init(struct dnet_node *n, struct dnet_log *l);
void dnet_log_raw(struct dnet_node *n, uint32_t mask, const char *format, ...) DNET_LOG_CHECK;

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

#define DNET_DUMP_NUM	6
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

static inline char *dnet_dump_id_len(const struct dnet_id *id, unsigned int len)
{
	static char __dnet_dump_str[2 * DNET_ID_SIZE + 16 + 3];
	char tmp[2*DNET_ID_SIZE + 1];
	
	snprintf(__dnet_dump_str, sizeof(__dnet_dump_str), "%d:%s", id->group_id,
			dnet_dump_id_len_raw(id->id, len, tmp));
	return __dnet_dump_str;
}

static inline char *dnet_dump_id(const struct dnet_id *id)
{
	return dnet_dump_id_len(id, DNET_DUMP_NUM);
}

static inline char *dnet_dump_id_str(const unsigned char *id)
{
	static char __dnet_dump_id_str[2 * DNET_ID_SIZE + 1];
	return dnet_dump_id_len_raw(id, DNET_DUMP_NUM, __dnet_dump_id_str);
}

/*
 * Send a shell command to the remote node for execution.
 */
int dnet_send_cmd(struct dnet_node *n, struct dnet_id *id, char *command);

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
int dnet_lookup_object(struct dnet_node *n, struct dnet_id *id, unsigned int aflags,
	int (* complete)(struct dnet_net_state *, struct dnet_cmd *, struct dnet_attr *, void *),
	void *priv);
int dnet_lookup(struct dnet_node *n, char *file);
int dnet_lookup_complete(struct dnet_net_state *st, struct dnet_cmd *cmd,
		struct dnet_attr *attr, void *priv);
int dnet_stat_local(struct dnet_net_state *st, struct dnet_id *id);

/*
 * Compare two IDs.
 * Returns  1 when id1 > id2
 *         -1 when id1 < id2
 *          0 when id1 = id2
 */
static inline int dnet_id_cmp_str(const unsigned char *id1, const unsigned char *id2)
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
static inline int dnet_id_cmp(const struct dnet_id *id1, const struct dnet_id *id2)
{
	if (id1->group_id < id2->group_id)
		return -1;
	if (id1->group_id > id2->group_id)
		return 1;

	return dnet_id_cmp_str(id1->id, id2->id);
}

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
int dnet_request_stat(struct dnet_node *n, struct dnet_id *id,
	unsigned int cmd, unsigned int aflags,
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
int dnet_request_notification(struct dnet_node *n, struct dnet_id *id,
	int (* complete)(struct dnet_net_state *state,
			struct dnet_cmd *cmd,
			struct dnet_attr *attr,
			void *priv),
	void *priv);

/*
 * Drop notifications for given ID.
 */
int dnet_drop_notification(struct dnet_node *n, struct dnet_id *id);

/*
 * Low-level transaction allocation and sending function.
 */
struct dnet_trans_control
{
	struct dnet_id		id;

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
int dnet_trans_create_send_all(struct dnet_node *n, struct dnet_io_control *ctl);

int dnet_request_cmd(struct dnet_node *n, struct dnet_trans_control *ctl);

/* Change node status on given address or ID */
int dnet_update_status(struct dnet_node *n, struct dnet_addr *addr,
		struct dnet_id *id, unsigned int status);

/*
 * Mark tranasction with @id in the object identified by @origin to be removed.
 * If callback is provided, it will be invoked on completion, otherwise
 * function will block until server returns an acknowledge.
 */
int dnet_remove_object(struct dnet_node *n,
	unsigned char *parent, struct dnet_id *id,
	int (* complete)(struct dnet_net_state *state,
			struct dnet_cmd *cmd,
			struct dnet_attr *attr,
			void *priv),
	void *priv,
	int direct);

/* Remove object with @id from the storage immediately */
int dnet_remove_object_now(struct dnet_node *n, struct dnet_id *id, int direct);

/*
 * Remove given file (identified by name or ID) from the storage.
 */
int dnet_remove_file(struct dnet_node *n, char *remote, int remote_len, struct dnet_id *id);

/*
 * Transformation helper, which uses *ppos as an index for transformation function.
 * @src and @size correspond to to be transformed source data.
 * @dst and @dsize specify destination buffer.
 */
int dnet_transform(struct dnet_node *n, void *src, uint64_t size, struct dnet_id *id);

int dnet_request_ids(struct dnet_node *n, struct dnet_id *id, unsigned int aflags,
	int (* complete)(struct dnet_net_state *state,
			struct dnet_cmd *cmd,
			struct dnet_attr *attr,
			void *priv),
	void *priv);

enum dnet_meta_types {
	DNET_META_PARENT_OBJECT = 1,	/* parent object name */
	DNET_META_GROUPS,		/* this object has copies in given groups */
	DNET_META_CHECK_STATUS,		/* last checking status: timestamp and so on */
	DNET_META_NAMESPACE,		/* namespace where given object lives */
	DNET_META_UPDATE,		/* last update information (timestamp, flags) */
	DNET_META_CHECKSUM,		/* checksum (sha512) of the whole data object calculated on server */
	__DNET_META_MAX,
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

struct dnet_meta_container {
	struct dnet_id			id;
	unsigned int			size;
	void				*data;
} __attribute__ ((packed));

static inline void dnet_convert_meta_container(struct dnet_meta_container *m)
{
	m->size = dnet_bswap32(m->size);
}

struct dnet_metadata_control {
	struct dnet_id			id;
	char				*obj;
	int				len;

	int				*groups;
	int				group_num;

	uint64_t			update_flags;
	struct timespec			ts;
};

/*
 * Reads meta of given file from the storage. If there are multiple transformation functions,
 * they will be tried one after another.
 *
 * If @id is set, it is used as a main object ID, otherwise @remote transformation
 * is used as object ID.
 *
 * Returns negative error value in case of error.
 */
int dnet_read_meta(struct dnet_node *n, struct dnet_meta_container *mc, void *remote, unsigned int remote_len, struct dnet_id *id);

/*
 * Modify or search metadata in meta object. Data must be realloc()able.
 */
struct dnet_meta *dnet_meta_search(struct dnet_node *n, struct dnet_meta_container *mc, uint32_t type);

int dnet_write_metadata(struct dnet_node *n, struct dnet_meta_container *mc, int convert);
int dnet_create_write_metadata(struct dnet_node *n, struct dnet_metadata_control *ctl);
int dnet_create_write_metadata_strings(struct dnet_node *n, void *remote, unsigned int remote_len, struct dnet_id *id, struct timespec *ts);
void dnet_meta_print(struct dnet_node *n, struct dnet_meta_container *mc);

int dnet_lookup_addr(struct dnet_node *n, void *remote, int len, struct dnet_id *id, int group_id, char *dst, int dlen);
void dnet_fill_addr_attr(struct dnet_node *n, struct dnet_addr_attr *attr);

struct dnet_id_param {
	unsigned int		group_id;
	uint64_t		param;
	uint64_t		param_reserved;
} __attribute__ ((packed));

enum id_params {
	DNET_ID_PARAM_LA = 1,
	DNET_ID_PARAM_FREE_SPACE,
};

int dnet_generate_ids_by_param(struct dnet_node *n, struct dnet_id *id, enum id_params param, struct dnet_id_param **dst);
int64_t dnet_get_param(struct dnet_node *n, struct dnet_id *id, enum id_params param);

int dnet_read_multiple(struct dnet_node *n, struct dnet_id *id, int num, struct dnet_id_param **dst);

struct dnet_check_reply {
	int			total;
	int			completed;
	int			errors;
	int			reserved[5];
};

static inline void dnet_convert_check_reply(struct dnet_check_reply *r)
{
	r->total = dnet_bswap32(r->total);
	r->completed = dnet_bswap32(r->completed);
	r->errors = dnet_bswap32(r->errors);
}

struct dnet_meta_update {
	int			group_id;
	int			unused_gap;
	uint64_t		flags;
	uint64_t		tsec, tnsec;
	uint64_t		reserved[4];
} __attribute__((packed));

static inline void dnet_convert_meta_update(struct dnet_meta_update *m)
{
	m->group_id = dnet_bswap32(m->group_id);
	m->flags = dnet_bswap64(m->flags);
	m->tsec = dnet_bswap64(m->tsec);
	m->tnsec = dnet_bswap64(m->tnsec);
}

struct dnet_meta_check_status {
	int			status;
	int			pad;
	uint64_t		tsec, tnsec;
	uint64_t		reserved[4];
} __attribute__ ((packed));

static inline void dnet_convert_meta_check_status(struct dnet_meta_check_status *c)
{
	c->status = dnet_bswap32(c->status);
	c->tsec = dnet_bswap64(c->tsec);
	c->tnsec = dnet_bswap64(c->tnsec);
}

struct dnet_meta_checksum {
	uint8_t			checksum[DNET_CSUM_SIZE];
	uint64_t		tsec, tnsec;
} __attribute__ ((packed));

static inline void dnet_convert_meta_checksum(struct dnet_meta_checksum *c)
{
	c->tsec = dnet_bswap64(c->tsec);
	c->tnsec = dnet_bswap64(c->tnsec);
}

/* Set by dnet_check when we only want to merge transaction
 * and do not check copies in other groups
 */
#define DNET_CHECK_MERGE			(1<<0)
/* Check not only history presence but also try to read part of the data object */
#define DNET_CHECK_FULL				(1<<1)
/* Do not actually perform any action, just update counters */
#define DNET_CHECK_DRY_RUN			(1<<2)
/* Physically delete files marked as REMOVED in history */
#define DNET_CHECK_DELETE			(1<<3)

struct dnet_check_request {
	uint32_t		flags;
	uint32_t		thread_num;
	uint64_t		timestamp;
	uint32_t		obj_num;
	uint32_t		pad;
} __attribute__ ((packed));

static inline void dnet_convert_check_request(struct dnet_check_request *r)
{
	r->timestamp = dnet_bswap64(r->timestamp);
	r->flags = dnet_bswap32(r->flags);
	r->thread_num = dnet_bswap32(r->thread_num);
	r->obj_num = dnet_bswap32(r->obj_num);
}

int dnet_request_check(struct dnet_node *n, struct dnet_check_request *r);

void *dnet_node_get_ns(struct dnet_node *n, int *nsize);
void dnet_node_set_ns(struct dnet_node *n, void *ns, int nsize);

long dnet_get_id(void);

static inline int is_trans_destroyed(struct dnet_net_state *st, struct dnet_cmd *cmd,
		struct dnet_attr *attr __attribute__ ((unused)))
{
	int ret = 0;

	if (!st || !cmd || (cmd->flags & DNET_FLAGS_DESTROY)) {
		ret = 1;
		if (cmd && cmd->status)
			ret = cmd->status;
	}

	return ret;
}

int dnet_mix_states(struct dnet_node *n, struct dnet_id *id, int **groupsp);

char *dnet_cmd_string(int cmd);

int dnet_checksum_data(struct dnet_node *n, void *csum, int *csize, void *data, uint64_t size);
int dnet_checksum_fd(struct dnet_node *n, void *csum, int *csize, int fd, uint64_t offset, uint64_t size);
int dnet_checksum_file(struct dnet_node *n, void *csum, int *csize, const char *file, uint64_t offset, uint64_t size);

int dnet_meta_update_checksum(struct dnet_node *n, struct dnet_id *id);
int dnet_verify_checksum_io(struct dnet_node *n, unsigned char *id, unsigned char *result, int *res_len);

#ifdef __cplusplus
}
#endif

#endif /* __DNET_INTERFACE_H */
