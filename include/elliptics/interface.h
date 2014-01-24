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

#ifndef __DNET_INTERFACE_H
#define __DNET_INTERFACE_H

#include <elliptics/core.h>

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

#include <sys/socket.h>
#include <sys/time.h>

#include <arpa/inet.h>
#include <netinet/in.h>

#include <elliptics/packet.h>
#include <elliptics/srw.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifndef O_CLOEXEC
#define O_CLOEXEC	02000000
#endif

#ifndef FD_CLOEXEC
#define FD_CLOEXEC	1
#endif

struct dnet_net_state;
struct dnet_config_data;
struct dnet_node;
struct dnet_session;

int dnet_need_exit(struct dnet_node *n);
void dnet_set_need_exit(struct dnet_node *n);

/*
 * Callback data structures.
 *
 * [dnet_cmd]
 * [attributes]
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
							void *priv);

	/*
	 * Transaction completion private data. Will be accessible in the
	 * above completion callback.
	 */
	void				*priv;

	/*
	 * Data to be sent.
	 */
	const void			*data;

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
	uint64_t			cflags;

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
int dnet_read_object(struct dnet_session *s, struct dnet_io_control *ctl);

int dnet_search_range(struct dnet_node *n, struct dnet_id *id,
		struct dnet_raw_id *start, struct dnet_raw_id *next);


/*
 * Operations to perform on request's data when request is about to be destroyed
 */
#define DNET_IO_REQ_FLAGS_CLOSE			(1<<0)	/* close fd */
#define DNET_IO_REQ_FLAGS_CACHE_FORGET		(1<<1)	/* try to remove read data from page cache using fadvice */

int __attribute__((weak)) dnet_send_read_data(void *state, struct dnet_cmd *cmd, struct dnet_io_attr *io,
		void *data, int fd, uint64_t offset, int on_exit);

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
int dnet_read_file_id(struct dnet_session *s, const char *file, struct dnet_id *id,
		uint64_t offset, uint64_t size);
int dnet_read_file(struct dnet_session *s, const char *file, const void *remote, int remote_size,
		uint64_t offset, uint64_t size);

/*
 * dnet_write_object() returns number of transactions sent. If it is equal to 0,
 * then no transactions were sent which indicates an error.
 *
 * ->complete() can be called multiple times, depending on how server sends data
 */
int dnet_write_object(struct dnet_session *s, struct dnet_io_control *ctl);

/*
 * Sends given file to the remote nodes and waits until all of them ack the write.
 *
 * Returns negative error value in case of error.
 */
int dnet_write_file_id(struct dnet_session *s, const char *file, struct dnet_id *id, uint64_t local_offset,
		uint64_t remote_offset, uint64_t size);

int dnet_write_file(struct dnet_session *s, const char *file, const void *remote, int remote_len,
		uint64_t local_offset, uint64_t remote_offset, uint64_t size);

enum dnet_log_level {
	DNET_LOG_DATA = 0,
	DNET_LOG_ERROR,
	DNET_LOG_INFO,
	DNET_LOG_NOTICE,
	DNET_LOG_DEBUG,
};

#define DNET_MAX_ADDRLEN		256
#define DNET_MAX_PORTLEN		8

#define DNET_TRACE_BIT         (1<<31)         /*is used in trace_id for ignoring current log level*/

/* cfg->flags */
#define DNET_CFG_JOIN_NETWORK		(1<<0)		/* given node joins network and becomes part of the storage */
#define DNET_CFG_NO_ROUTE_LIST		(1<<1)		/* do not request route table from remote nodes */
#define DNET_CFG_MIX_STATES		(1<<2)		/* mix states according to their weights before reading data */
#define DNET_CFG_NO_CSUM		(1<<3)		/* globally disable checksum verification and update */
#define DNET_CFG_RANDOMIZE_STATES	(1<<5)		/* randomize states for read requests */
#define DNET_CFG_KEEPS_IDS_IN_CLUSTER	(1<<6)		/* keeps ids in elliptics cluster */

struct dnet_log {
	/*
	 * Logging parameters.
	 * Mask specifies set of the events we are interested in to log.
	 * Private data is used in the log function to get access to whatever
	 * user pointed to.
	 */
	int			log_level;
	void			*log_private;
	void 			(* log)(void *priv, int level, const char *msg);
};

/*
 * New-style iterator control
 */
struct dnet_iterator_ctl {
	void				*iterate_private;
	void				*callback_private;
	int				(* callback)(void *priv, struct dnet_raw_id *key,
			void *data, uint64_t dsize, struct dnet_ext_list *elist);
};

/*
 * Iterator result container routines
 */
int dnet_iterator_response_container_sort(int fd, size_t size);
int dnet_iterator_response_container_append(const struct dnet_iterator_response
		*response, int fd, uint64_t pos);
int dnet_iterator_response_container_read(int fd, uint64_t pos,
		struct dnet_iterator_response *response);
int64_t dnet_iterator_response_container_diff(int diff_fd, int left_fd, uint64_t left_size,
		int right_fd, uint64_t right_size);

struct dnet_backend_callbacks {
	/* command handler processes DNET_CMD_* commands */
	int			(* command_handler)(void *state, void *priv, struct dnet_cmd *cmd, void *data);

	/* this must be provided as @priv argument to all above and below callbacks*/
	void			*command_private;

	/* fills storage statistics */
	int			(* storage_stat)(void *priv, struct dnet_stat *st);

	/* cleanups backend at exit */
	void			(* backend_cleanup)(void *command_private);

	/*
	 * calculates checksum and writes (no more than *@csize bytes) it
	 * into @csum,
	 * @csize must be set to actual @csum size
	 */
	int			(* checksum)(struct dnet_node *n, void *priv, struct dnet_id *id, void *csum, int *csize);

	/*
	 * Iterator.
	 * Invokes callback on each record's data and metadata.
	 */
	int			(* iterator)(struct dnet_iterator_ctl *ictl);

	/*
	 * Returns dir used by backend
	 */
	char *			(* dir)(void);
};

/*
 * Node configuration interface.
 */
struct dnet_config
{
	/*
	 * Family (AF_INET, AF_INET6) of the appropriate socket.
	 * These parameters are sent in the lookup replies so that remote nodes
	 * could know how to connect to this one.
	 */
	int			family;

	/*
	 * Socket port.
	 */
	int			port;

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
	struct dnet_backend_callbacks	*cb;

	/*
	 * Free and total space on given storage.
	 */
	unsigned long long	storage_free;
	unsigned long long	storage_size;

	/* Notify hash table size */
	unsigned int		hash_size;

	/*
	 * Wait until transaction acknowledge is received.
	 */
	long			check_timeout;

	/*
	 * Destroy state if stall_count transactions stalled.
	 */
	long			stall_count;

	/*
	 * Number of IO threads in processing pool
	 */
	int			io_thread_num;

	/*
	 * Number of IO threads in processing pool dedicated to non-blocking operations
	 * Those operations are started from recursive commands like from DNET_CMD_EXEC handler
	 */
	int			nonblocking_io_thread_num;

	/*
	 * Number of threads in network processing pool
	 */
	int			net_thread_num;

	/*
	 * This dir hosts:
	 *  - 'ids' file automatically generated for ID ranges
	 *  - python.init script used to initialize external python workers
	 *  - all scripts are hosted here and are chrooted here
	 */
	char			history_env[1024];

	/* IO nice parameters for background operations */
	int			bg_ionice_class;
	int			bg_ionice_prio;
	int			removal_delay;

	char			cookie[DNET_AUTH_COOKIE_SIZE];

	/* man 7 socket for IP_PRIORITY - priorities are set for joined (server) and others (client) connections */
	int			server_prio;
	int			client_prio;

	/* Number of shards to store indexes data */
	int			indexes_shard_count;

	struct srw_init_ctl	srw;

	/* Total cache size */
	uint64_t		cache_size;

	int			cache_sync_timeout;

	/* Caches number */
	unsigned int		caches_number;

	/* Cache pages number */
	unsigned int	cache_pages_number;

	/* Cache pages proportions */
	unsigned int*	cache_pages_proportions;

	/*
	 * Monitor socket port
	 */
	unsigned int		monitor_port;

	/* so that we do not change major version frequently */
	int			reserved_for_future_use[8 - (sizeof(unsigned int*) / sizeof(int))];
};

struct dnet_node *dnet_get_node_from_state(void *state);

int __attribute__((weak)) dnet_session_set_groups(struct dnet_session *s, const int *groups, int group_num);
int *dnet_session_get_groups(struct dnet_session *s, int *count);

void dnet_session_set_ioflags(struct dnet_session *s, uint32_t ioflags);
uint32_t dnet_session_get_ioflags(struct dnet_session *s);

void dnet_session_set_cflags(struct dnet_session *s, uint64_t cflags);
uint64_t dnet_session_get_cflags(struct dnet_session *s);

void dnet_session_set_timestamp(struct dnet_session *s, struct dnet_time *ts);
void dnet_session_get_timestamp(struct dnet_session *s, struct dnet_time *ts);

struct dnet_id *dnet_session_get_direct_id(struct dnet_session *s);
void dnet_session_set_direct_id(struct dnet_session *s, struct dnet_id *id);

void dnet_session_set_user_flags(struct dnet_session *s, uint64_t user_flags);
uint64_t dnet_session_get_user_flags(struct dnet_session *s);

void dnet_session_set_timeout(struct dnet_session *s, unsigned int wait_timeout);
struct timespec *dnet_session_get_timeout(struct dnet_session *s);

int dnet_session_set_ns(struct dnet_session *s, const char *ns, int nsize);

struct dnet_node *dnet_session_get_node(struct dnet_session *s);

/*
 * Logging helpers.
 */

/*
 * Initialize private logging system.
 */
int dnet_log_init(struct dnet_node *s, struct dnet_log *l);
void __attribute__((weak)) dnet_log_raw(struct dnet_node *n, int level, const char *format, ...) DNET_LOG_CHECK;

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

static inline char *dnet_server_convert_dnet_addr_raw(const struct dnet_addr *addr, char *inet_addr, int inet_size)
{
	memset(inet_addr, 0, inet_size);
	if (addr->family == AF_INET) {
		const struct sockaddr_in *in = (const struct sockaddr_in *)addr->addr;
		snprintf(inet_addr, inet_size, "%s:%d", inet_ntoa(in->sin_addr), ntohs(in->sin_port));
	} else if (addr->family == AF_INET6) {
		const struct sockaddr_in6 *in = (const struct sockaddr_in6 *)addr->addr;
		snprintf(inet_addr, inet_size, NIP6_FMT":%d", NIP6(in->sin6_addr), ntohs(in->sin6_port));
	}
	return inet_addr;
}

static inline char *dnet_server_convert_dnet_addr(const struct dnet_addr *sa)
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

static inline char *dnet_print_time(const struct dnet_time *t)
{
	char str[64];
	struct tm tm;

	static char __dnet_print_time[128];

	localtime_r((time_t *)&t->tsec, &tm);
	strftime(str, sizeof(str), "%F %R:%S", &tm);

	snprintf(__dnet_print_time, sizeof(__dnet_print_time), "%s.%06llu", str, (long long unsigned) t->tnsec / 1000);
	return __dnet_print_time;
}

/*
 * Node creation/destruction callbacks. Node is a building block of the storage
 * and it is needed for every operation one may want to do with the network.
 */
struct dnet_node *dnet_node_create(struct dnet_config *);
void dnet_node_destroy(struct dnet_node *n);

/*
 * Create a session from node.
 * Session is not thread safe!
 */
struct dnet_session *dnet_session_create(struct dnet_node *n);
struct dnet_session *dnet_session_copy(struct dnet_session *s);
void dnet_session_destroy(struct dnet_session *s);

/* Server node creation/destruction.
 */
struct dnet_node *dnet_server_node_create(struct dnet_config_data *cfg_data, struct dnet_config *cfg, struct dnet_addr *addrs, int addr_num);
void dnet_server_node_destroy(struct dnet_node *s);

/*
 * dnet_add_state() is used to add a node into the route list, the more
 * routes are added the less network lookups will be performed to send/receive
 * data requests.
 */
int dnet_add_state(struct dnet_node *n, char *addr_str, int port, int family, int flags);

/*
 * Returns number of states we are connected to.
 * It does not check whether they are alive though.
 */

int dnet_state_num(struct dnet_session *s);
int dnet_node_state_num(struct dnet_node *n);
struct dnet_net_state *dnet_state_get_first(struct dnet_node *n, struct dnet_id *id);
void dnet_state_put(struct dnet_net_state *st);

#define DNET_DUMP_NUM	6
#define DNET_DUMP_ID_LEN(name, id_struct, data_length) \
	char name[2 * DNET_ID_SIZE + 16 + 3]; \
	do { \
		char tmp[2 * DNET_ID_SIZE + 1]; \
		snprintf(name, sizeof(name), "%d:%s", (id_struct)->group_id, \
			dnet_dump_id_len_raw((id_struct)->id, (data_length), tmp)); \
	} while (0)
#define DNET_DUMP_ID(name, id_struct) DNET_DUMP_ID_LEN(name, id_struct, DNET_DUMP_NUM)
/*
 * Logging helper used to print ID (DNET_ID_SIZE bytes) as a hex string.
 */
static inline char *dnet_dump_id_len_raw(const unsigned char *id, unsigned int len, char *dst)
{
	static const char hex[] = "0123456789abcdef";

	unsigned int i;

	if (len > DNET_ID_SIZE)
		len = DNET_ID_SIZE;

	for (i=0; i<len; ++i) {
		dst[2*i  ] = hex[id[i] >>  4];
		dst[2*i+1] = hex[id[i] & 0xf];
	}
	dst[2*len] = '\0';
	return dst;
}

static inline char *dnet_dump_id_len(const struct dnet_id *id, unsigned int len)
{
	static char __dnet_dump_str[2 * DNET_ID_SIZE + 16 + 3];
	char tmp[2*DNET_ID_SIZE + 1];
	char tmp2[2*DNET_ID_SIZE + 1];

	unsigned int len2 = (DNET_ID_SIZE - len) < len ? (DNET_ID_SIZE - len) : len;

	if (len < DNET_ID_SIZE)
		snprintf(__dnet_dump_str, sizeof(__dnet_dump_str),
		         "%d:%s...%s",
		         id->group_id,
		         dnet_dump_id_len_raw(id->id, len, tmp),
		         dnet_dump_id_len_raw(id->id + DNET_ID_SIZE - len2, len2, tmp2));
	else
		snprintf(__dnet_dump_str, sizeof(__dnet_dump_str),
		         "%d:%s",
		         id->group_id,
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
int dnet_lookup_object(struct dnet_session *s, struct dnet_id *id,
	int (* complete)(struct dnet_net_state *, struct dnet_cmd *, void *),
	void *priv);

int dnet_stat_local(struct dnet_net_state *st, struct dnet_id *id);

int dnet_version_compare(struct dnet_net_state *st, int *version);

/*!
 * Compares two dnet_time structs
 * Returns
 *	< 0 if t1 < t2
 *	> 0 if t1 > t2
 *	= 0 if t1 == t2
 */
static inline int dnet_time_cmp(const struct dnet_time *t1, const struct dnet_time *t2)
{
	if (t1->tsec < t2->tsec)
		return -1;
	else if (t1->tsec > t2->tsec)
		return 1;

	if (t1->tnsec < t2->tnsec)
		return -1;
	else if (t1->tnsec > t2->tnsec)
		return 1;

	return 0;
}

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
 * If cmd->cmd is DNET_CMD_SYNC then plain data will be sent back, otherwise transaction
 * reply will be generated. So effectively difference is in DNET_TRANS_REPLY bit presence.
 */
int __attribute__((weak)) dnet_send_reply(void *state, struct dnet_cmd *cmd, void *odata, unsigned int size, int more);
int __attribute__((weak)) dnet_send_reply_threshold(void *state, struct dnet_cmd *cmd, void *odata, unsigned int size, int more);


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
int dnet_request_stat(struct dnet_session *s, struct dnet_id *id,
	unsigned int cmd,
	int (* complete)(struct dnet_net_state *state,
			struct dnet_cmd *cmd,
			void *priv),
	void *priv);

/*
 * Request notifications when given ID is modified.
 * Notifications are sent after update was stored in the IO backend.
 * @id and @complete are not allowed to be NULL.
 *
 * @complete will be invoked each time object with given @id is modified.
 */
int dnet_request_notification(struct dnet_session *s, struct dnet_id *id,
	int (* complete)(struct dnet_net_state *state,
			struct dnet_cmd *cmd,
			void *priv),
	void *priv);

/*
 * Drop notifications for given ID.
 */
int dnet_drop_notification(struct dnet_session *s, struct dnet_id *id);

/*
 * Low-level transaction allocation and sending function.
 */
struct dnet_trans_control
{
	struct dnet_id		id;

	unsigned int		cmd;
	uint64_t		cflags;

	unsigned int		size;
	void			*data;

	int			(* complete)(struct dnet_net_state *state, struct dnet_cmd *cmd, void *priv);
	void			*priv;
};

/*
 * Allocate and send transaction according to above control structure.
 */
int dnet_trans_alloc_send(struct dnet_session *s, struct dnet_trans_control *ctl);
int dnet_trans_create_send_all(struct dnet_session *s, struct dnet_io_control *ctl);

int dnet_request_cmd(struct dnet_session *s, struct dnet_trans_control *ctl);

int dnet_fill_addr(struct dnet_addr *addr, const char *saddr, const int port, const int sock_type, const int proto);

/* Change node status on given address or ID */
int dnet_update_status(struct dnet_session *s, struct dnet_addr *addr, struct dnet_id *id, struct dnet_node_status *status);

/*
 * Remove object by @id
 * If callback is provided, it will be invoked on completion, otherwise
 * function will block until server returns an acknowledge.
 *
 * Returns negative number on error, zero on success
 * and positive number is count of objects which will be provided
 * to complete function.
 */
int dnet_remove_object(struct dnet_session *s, struct dnet_id *id,
	int (* complete)(struct dnet_net_state *state,
			struct dnet_cmd *cmd,
			void *priv),
	void *priv);

/* Remove object with @id from the storage immediately */
int dnet_remove_object_now(struct dnet_session *s, struct dnet_id *id);

/*
 * Remove given file (identified by name or ID) from the storage.
 */
int dnet_remove_file(struct dnet_session *s, char *remote, int remote_len, struct dnet_id *id);

/*
 * Transformation helper, which uses *ppos as an index for transformation function.
 * @src and @size correspond to to be transformed source data.
 * @dst and @dsize specify destination buffer.
 */
int dnet_transform(struct dnet_session *s, const void *src, uint64_t size, struct dnet_id *id);
int __attribute__((weak)) dnet_transform_node(struct dnet_node *n, const void *src, uint64_t size,
		unsigned char *csum, int csize);
int dnet_transform_raw(struct dnet_session *s, const void *src, uint64_t size, char *csum, unsigned int csize);

/*
 * Transformation implementation, currently it's sha512 hash.
 * It calculates checksum for @src of @size and writes it to @id.
 */
int dnet_digest_transform(const void *src, uint64_t size, struct dnet_id *id);
/*
 * @dnet_digest_transform overload.
 * Writes most of @csum_size bytes to @csum.
 */
int dnet_digest_transform_raw(const void *src, uint64_t size, void *csum, int csum_size);

/*
 * Calculates message autherization code based on digest_transformation.
 * Uses data from @src of @size and @key of size @key_size. Result is written to @id.
 */
int dnet_digest_auth_transform(const void *src, uint64_t size, const void *key, uint64_t key_size, struct dnet_id *id);
/*
 * @dnet_digest_auth_transform overload.
 * Writes most of @csum_size bytes to @csum.
 */
int dnet_digest_auth_transform_raw(const void *src, uint64_t size, const void *key, uint64_t key_size, void *csum, int csum_size);

/*
 * Transform object id to id where to store object's secondary indexes table
 */
void dnet_indexes_transform_object_id(struct dnet_node *node, const struct dnet_id *src, struct dnet_id *id);
/*
 * Transform index id to id where to store secondary index's objects table.
 * _prepare method makes initial transformation generic for every shard.
 * _id_raw method makes shard-specific changes.
 */
void dnet_indexes_transform_index_prepare(struct dnet_node *node, const struct dnet_raw_id *src, struct dnet_raw_id *id);
void dnet_indexes_transform_index_id_raw(struct dnet_node *node, struct dnet_raw_id *id, int shard_id);
/*
 * Transform index id to id where to store secondary index's objects table.
 * It's equal to iterative calls of _prepare and _id_raw method.
 */
void dnet_indexes_transform_index_id(struct dnet_node *node, const struct dnet_raw_id *src, struct dnet_raw_id *id, int shard_id);
int dnet_indexes_get_shard_id(struct dnet_node *node, const struct dnet_raw_id *object_id);
int dnet_node_get_indexes_shard_count(struct dnet_node *node);

int dnet_lookup_addr(struct dnet_session *s, const void *remote, int len, struct dnet_id *id, int group_id, char *dst, int dlen);

struct dnet_id_param {
	unsigned int		group_id;
	uint64_t		param;
	uint64_t		param_reserved;
} __attribute__ ((packed));

enum id_params {
	DNET_ID_PARAM_LA = 1,
	DNET_ID_PARAM_FREE_SPACE,
};

//TODO int dnet_generate_ids_by_param(struct dnet_session *s, struct dnet_id *id, enum id_params param, struct dnet_id_param **dst);
//TODO int64_t dnet_get_param(struct dnet_session *s, struct dnet_id *id, enum id_params param);

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
	uint64_t		updatestamp_start;
	uint64_t		updatestamp_stop;
	uint32_t		obj_num;
	uint32_t		group_num;
	int			blob_start;
	int			blob_num;
	uint64_t		reserved;
} __attribute__ ((packed));

static inline void dnet_convert_check_request(struct dnet_check_request *r)
{
	r->flags = dnet_bswap32(r->flags);
	r->thread_num = dnet_bswap32(r->thread_num);
	r->timestamp = dnet_bswap64(r->timestamp);
	r->updatestamp_start = dnet_bswap64(r->updatestamp_start);
	r->updatestamp_stop = dnet_bswap64(r->updatestamp_stop);
	r->obj_num = dnet_bswap32(r->obj_num);
	r->group_num = dnet_bswap32(r->group_num);
	r->blob_start = dnet_bswap32(r->blob_start);
	r->blob_num = dnet_bswap32(r->blob_num);
}

int dnet_request_check(struct dnet_session *s, struct dnet_check_request *r);

long __attribute__((weak)) dnet_get_id(void);

static inline int is_trans_destroyed(struct dnet_net_state *st, struct dnet_cmd *cmd)
{
	int ret = 0;

	if (!st || !cmd || (cmd->flags & DNET_FLAGS_DESTROY)) {
		ret = 1;
		if (cmd && cmd->status)
			ret = cmd->status;
	}

	return ret;
}

int dnet_mix_states(struct dnet_session *s, struct dnet_id *id, int **groupsp);

char * __attribute__((weak)) dnet_cmd_string(int cmd);
char *dnet_counter_string(int cntr, int cmd_num);

int dnet_checksum_file(struct dnet_node *n, const char *file, uint64_t offset, uint64_t size, void *csum, int csize);
int dnet_checksum_fd(struct dnet_node *n, int fd, uint64_t offset, uint64_t size, void *csum, int csize);
int dnet_checksum_data(struct dnet_node *n, const void *data, uint64_t size, unsigned char *csum, int csize);

int dnet_send_file_info(void *state, struct dnet_cmd *cmd, int fd, uint64_t offset, int64_t size);
int dnet_send_file_info_without_fd(void *state, struct dnet_cmd *cmd, const void *data, int64_t size);
int dnet_send_file_info_ts(void *state, struct dnet_cmd *cmd, int fd,
		uint64_t offset, int64_t size, struct dnet_time *timestamp);
int dnet_send_file_info_ts_without_fd(void *state, struct dnet_cmd *cmd, const void *data, int64_t size, struct dnet_time *timestamp);

int dnet_get_routes(struct dnet_session *s, struct dnet_id **ids, struct dnet_addr **addrs);
/*
 * Send a shell/python command to the remote node for execution.
 */
int dnet_send_cmd(struct dnet_session *s,
	struct dnet_id *id,
	int (* complete)(struct dnet_net_state *state,
			struct dnet_cmd *cmd,
			void *priv),
	void *priv,
	struct sph *e);

int dnet_flags(struct dnet_node *n);
void dnet_set_timeouts(struct dnet_node *n, int wait_timeout, int check_timeout);

#define DNET_CONF_ADDR_DELIM	':'
int dnet_parse_addr(char *addr, int *portp, int *familyp);

int dnet_start_defrag(struct dnet_session *s, struct dnet_defrag_ctl *ctl);

int dnet_discovery_add(struct dnet_node *n, char *remote_addr, int remote_port, int remote_family);

int dnet_parse_numeric_id(const char *value, unsigned char *id);

#ifdef __cplusplus
}
#endif

#endif /* __DNET_INTERFACE_H */
