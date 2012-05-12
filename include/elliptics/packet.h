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

#ifndef __DNET_PACKET_H
#define __DNET_PACKET_H

#ifndef __KERNEL__
#include <sys/time.h>
#include <arpa/inet.h>
#include <sys/stat.h>

#include <string.h>
#include <stdint.h>

#include <elliptics/typedefs.h>
#include <elliptics/core.h>

#endif

#ifdef __cplusplus
extern "C" {
#endif

enum dnet_commands {
	DNET_CMD_LOOKUP = 1,			/* Lookup address by ID and per-object info: size, permissions and so on*/
	DNET_CMD_REVERSE_LOOKUP,		/* Lookup ID by address */
	DNET_CMD_JOIN,				/* Join the network - force remote nodes to update
						 * their route tables to include given node with given
						 * address
						 */
	DNET_CMD_WRITE,
	DNET_CMD_READ,				/* IO commands. They have to follow by the
						 * IO attribute which will have offset and size
						 * parameters.
						 */
	DNET_CMD_LIST,				/* List all objects for given node ID */
	DNET_CMD_EXEC,				/* Execute given command on the remote node */
	DNET_CMD_ROUTE_LIST,			/* Receive route table from given node */
	DNET_CMD_STAT,				/* Gather remote VM, LA and FS statistics */
	DNET_CMD_NOTIFY,			/* Notify when object in question was modified */
	DNET_CMD_DEL,				/* Remove given object from the storage */
	DNET_CMD_STAT_COUNT,			/* Gather remote per-cmd statistics */
	DNET_CMD_STATUS,			/* Change elliptics node status */
	DNET_CMD_READ_RANGE,			/* Read range of objects */
	DNET_CMD_DEL_RANGE,			/* Remove range of objects */
	DNET_CMD_AUTH,				/* Authentification cookie check */
	DNET_CMD_BULK_READ,			/* Read a number of ids at one time */

	DNET_CMD_UNKNOWN,			/* This slot is allocated for statistics gathered for unknown commands */
	__DNET_CMD_MAX,
};

enum dnet_counters {
	DNET_CNTR_LA1 = __DNET_CMD_MAX*2,	/* Load average for 1 min */
	DNET_CNTR_LA5,				/* Load average for 5 min */
	DNET_CNTR_LA15,				/* Load average for 15 min */
	DNET_CNTR_BSIZE,			/* Block size */
	DNET_CNTR_FRSIZE,			/* Fragment size */
	DNET_CNTR_BLOCKS,			/* Filesystem size in frsize units */
	DNET_CNTR_BFREE,			/* # free blocks */
	DNET_CNTR_BAVAIL,			/* # free blocks for non-root */
	DNET_CNTR_FILES,			/* # inodes */
	DNET_CNTR_FFREE,			/* # free inodes */
	DNET_CNTR_FAVAIL,			/* # free inodes for non-root */
	DNET_CNTR_FSID,				/* File system ID */
	DNET_CNTR_VM_ACTIVE,			/* Active memory */
	DNET_CNTR_VM_INACTIVE,			/* Inactive memory */
	DNET_CNTR_VM_TOTAL,			/* Total memory */
	DNET_CNTR_VM_FREE,			/* Free memory */
	DNET_CNTR_VM_CACHED,			/* Used for cache */
	DNET_CNTR_VM_BUFFERS,			/* Used for buffers */
	DNET_CNTR_NODE_FILES,			/* # files in meta */
	DNET_CNTR_NODE_LAST_MERGE,		/* Result of the last merge */
	DNET_CNTR_NODE_CHECK_COPY,		/* Result of the last check copies */
	DNET_CNTR_DBR_NOREC,			/* Kyoto Cabinet DB read error KCENOREC */
	DNET_CNTR_DBR_SYSTEM,			/* Kyoto Cabinet DB read error KCESYSTEM */
	DNET_CNTR_DBR_ERROR,			/* Kyoto Cabinet DB read error */
	DNET_CNTR_DBW_SYSTEM,			/* Kyoto Cabinet DB write error KCESYSTEM */
	DNET_CNTR_DBW_ERROR,			/* Kyoto Cabinet DB write error */
	DNET_CNTR_UNKNOWN,			/* This slot is allocated for statistics gathered for unknown counters */
	__DNET_CNTR_MAX,
};

/*
 * Transaction ID direction bit.
 * When set, data is a reply for the given transaction.
 */
#define DNET_TRANS_REPLY		0x8000000000000000ULL

/*
 * Command flags.
 */

/*
 * When set, node will generate a reply when transaction
 * is completed and put completion status into cmd.status
 * field.
 */
#define DNET_FLAGS_NEED_ACK		(1<<0)

/* There will be more commands with the same parameters (transaction number and id) */
#define DNET_FLAGS_MORE			(1<<1)

/* Transaction is about to be destroyed */
#define DNET_FLAGS_DESTROY		(1<<2)

/* Do not forward requst to antoher node even if given ID does not belong to our range */
#define DNET_FLAGS_DIRECT		(1<<3)

/* Do not locks operations - must be set for script callers or recursive operations */
#define DNET_FLAGS_NOLOCK		(1<<4)

struct dnet_id {
	uint8_t			id[DNET_ID_SIZE];
	uint32_t		group_id;
	int			type;
} __attribute__ ((packed));

struct dnet_raw_id {
	uint8_t			id[DNET_ID_SIZE];
} __attribute__ ((packed));

static inline void dnet_convert_raw_id(struct dnet_raw_id *id __attribute__ ((unused)))
{
}

static inline void dnet_setup_id(struct dnet_id *id, unsigned int group_id, unsigned char *raw)
{
	memcpy(id->id, raw, DNET_ID_SIZE);
	id->group_id = group_id;
}

struct dnet_cmd
{
	struct dnet_id		id;
	uint32_t		flags;
	int			status;
	uint64_t		trans;
	uint64_t		size;
	uint8_t			data[0];
} __attribute__ ((packed));

/* kernel (pohmelfs) provides own defines for byteorder changes */
#ifndef __KERNEL__
#ifdef WORDS_BIGENDIAN

#define dnet_bswap16(x)		((((x) >> 8) & 0xff) | (((x) & 0xff) << 8))

#define dnet_bswap32(x) \
     ((((x) & 0xff000000) >> 24) | (((x) & 0x00ff0000) >>  8) |		      \
      (((x) & 0x0000ff00) <<  8) | (((x) & 0x000000ff) << 24))

#define dnet_bswap64(x) \
     ((((x) & 0xff00000000000000ull) >> 56)				      \
      | (((x) & 0x00ff000000000000ull) >> 40)				      \
      | (((x) & 0x0000ff0000000000ull) >> 24)				      \
      | (((x) & 0x000000ff00000000ull) >> 8)				      \
      | (((x) & 0x00000000ff000000ull) << 8)				      \
      | (((x) & 0x0000000000ff0000ull) << 24)				      \
      | (((x) & 0x000000000000ff00ull) << 40)				      \
      | (((x) & 0x00000000000000ffull) << 56))
#else
#define dnet_bswap16(x) (x)
#define dnet_bswap32(x) (x)
#define dnet_bswap64(x) (x)
#endif
#endif

static inline void dnet_convert_id(struct dnet_id *id)
{
	id->group_id = dnet_bswap32(id->group_id);
	id->type = dnet_bswap32(id->type);
}

static inline void dnet_convert_cmd(struct dnet_cmd *cmd)
{
	dnet_convert_id(&cmd->id);
	cmd->flags = dnet_bswap32(cmd->flags);
	cmd->status = dnet_bswap32(cmd->status);
	cmd->size = dnet_bswap64(cmd->size);
	cmd->trans = dnet_bswap64(cmd->trans);
}

/* Completely remove object history and metadata */
#define DNET_ATTR_DELETE_HISTORY		(1<<0)

/* What type of counters to fetch */
#define DNET_ATTR_CNTR_GLOBAL			(1<<0)

/* Bulk request for checking files */
#define DNET_ATTR_BULK_CHECK			(1<<0)

/* Fill ctime/mtime from metadata when processing DNET_CMD_LOOKUP */
#define DNET_ATTR_META_TIMES			(1<<1)

/* Do not verify checksum */
#define DNET_ATTR_NOCSUM			(1<<2)

/*
 * ascending sort data before returning range request to user
 */
#define DNET_ATTR_SORT				(1<<3)

/*
 * This flag will force its parent CMD not to lock operation
 * Flag will be propagated to cmd->flags
 */
#define DNET_ATTR_NOLOCK			(1<<4)

struct dnet_attr
{
	uint64_t		size;
	uint32_t		cmd;
	uint32_t		flags;
	uint32_t		unused[2];
} __attribute__ ((packed));

static inline void dnet_convert_attr(struct dnet_attr *a)
{
	a->size = dnet_bswap64(a->size);
	a->cmd = dnet_bswap32(a->cmd);
	a->flags = dnet_bswap32(a->flags);
}

#define DNET_ADDR_SIZE		28

struct dnet_addr
{
	uint8_t			addr[DNET_ADDR_SIZE];
	uint32_t		addr_len;
} __attribute__ ((packed));

struct dnet_list
{
	struct dnet_id		id;
	uint32_t		size;
	uint8_t			data[0];
} __attribute__ ((packed));

static inline void dnet_convert_list(struct dnet_list *l)
{
	dnet_convert_id(&l->id);
	l->size = dnet_bswap32(l->size);
}

struct dnet_addr_attr
{
	uint16_t		sock_type;
	uint16_t		family;
	uint32_t		proto;
	struct dnet_addr	addr;
} __attribute__ ((packed));

static inline void dnet_convert_addr_attr(struct dnet_addr_attr *a)
{
	a->addr.addr_len = dnet_bswap32(a->addr.addr_len);
	a->proto = dnet_bswap32(a->proto);
	a->sock_type = dnet_bswap16(a->sock_type);
	a->family = dnet_bswap16(a->family);
}

struct dnet_addr_cmd
{
	struct dnet_cmd		cmd;
	struct dnet_attr	a;
	struct dnet_addr_attr	addr;
} __attribute__ ((packed));

static inline void dnet_convert_addr_cmd(struct dnet_addr_cmd *l)
{
	dnet_convert_cmd(&l->cmd);
	dnet_convert_attr(&l->a);
	dnet_convert_addr_attr(&l->addr);
}

/* Do not update history for given transaction */
#define DNET_IO_FLAGS_SKIP_SENDING	(1<<0)

/* Append given data at the end of the object */
#define DNET_IO_FLAGS_APPEND		(1<<1)

#define DNET_IO_FLAGS_COMPRESS		(1<<2)

/* Metada IO request */
#define DNET_IO_FLAGS_META		(1<<3)

/* eblob prepare/commit phase */
#define DNET_IO_FLAGS_PREPARE		(1<<4)
#define DNET_IO_FLAGS_COMMIT		(1<<5)

/* Object was removed */
#define DNET_IO_FLAGS_REMOVED		(1<<6)

/* Overwrite data */
#define DNET_IO_FLAGS_OVERWRITE		(1<<7)

/* Do not checksum data */
#define DNET_IO_FLAGS_NOCSUM		(1<<8)

/*
 * this flag is used when we want backend not to perform any additional actions
 * except than write data at given offset. This is no-op in filesystem backend,
 * but eblob one should disable prepare/commit operations.
 */
#define DNET_IO_FLAGS_PLAIN_WRITE	(1<<9)

/* Do not really send data in range request.
 * Send only statistics instead.
 *
 * -- we do not care if it matches above DNET_IO_FLAGS_PLAIN_WRITE,
 *  since using plain write and nodata (read) is useless anyway
 */
#define DNET_IO_FLAGS_NODATA		(1<<9)

struct dnet_io_attr
{
	uint8_t			parent[DNET_ID_SIZE];
	uint8_t			id[DNET_ID_SIZE];

	/*
	 * used in range request as start and number for LIMIT(start, num) 
	 *
	 * write prepare request uses @num is used as a placeholder
	 * for number of bytes to reserve on disk
	 */
	uint64_t		start, num;
	int			type;
	uint32_t		flags;
	uint64_t		offset;
	uint64_t		size;
} __attribute__ ((packed));

static inline void dnet_convert_io_attr(struct dnet_io_attr *a)
{
	a->start = dnet_bswap64(a->start);
	a->num = dnet_bswap64(a->num);

	a->flags = dnet_bswap32(a->flags);
	a->offset = dnet_bswap64(a->offset);
	a->size = dnet_bswap64(a->size);
}

struct dnet_history_entry
{
	uint8_t			id[DNET_ID_SIZE];
	uint32_t		flags;
	uint64_t		reserved;
	uint64_t		tsec, tnsec;
	uint64_t		offset;
	uint64_t		size;
} __attribute__ ((packed));

/*
 * Helper structure and set of functions to map history file and perform basic checks.
 */
struct dnet_history_map
{
	struct dnet_history_entry	*ent;
	long				num;
	ssize_t				size;
	int				fd;
};

static inline void dnet_convert_history_entry(struct dnet_history_entry *a)
{
	a->flags = dnet_bswap32(a->flags);
	a->offset = dnet_bswap64(a->offset);
	a->size = dnet_bswap64(a->size);
	a->tsec = dnet_bswap64(a->tsec);
	a->tnsec = dnet_bswap64(a->tnsec);
}

static inline void dnet_setup_history_entry(struct dnet_history_entry *e,
		unsigned char *id, uint64_t size, uint64_t offset,
		struct timespec *ts, uint32_t flags)
{
	if (!ts) {
		struct timeval tv;

		gettimeofday(&tv, NULL);

		e->tsec = tv.tv_sec;
		e->tnsec = tv.tv_usec * 1000;
	} else {
		e->tsec = ts->tv_sec;
		e->tnsec = ts->tv_nsec;
	}

	memcpy(e->id, id, DNET_ID_SIZE);

	e->size = size;
	e->offset = offset;
	e->flags = flags;
	e->reserved = 0;

	dnet_convert_history_entry(e);
}

struct dnet_stat
{
	/* Load average from the target system multiplied by 100 */
	uint16_t		la[3];

	uint16_t		namemax;	/* maximum filename length */

	uint64_t		bsize;		/* Block size */
	uint64_t		frsize;		/* Fragment size */
	uint64_t		blocks;		/* Filesystem size in frsize units */
	uint64_t		bfree;		/* # free blocks */
	uint64_t		bavail;		/* # free blocks for non-root */
	uint64_t		files;		/* # inodes */
	uint64_t		ffree;		/* # free inodes */
	uint64_t		favail;		/* # free inodes for non-root */
	uint64_t		fsid;		/* file system ID */
	uint64_t		flag;		/* mount flags */

	/*
	 * VM counters in KB (1024) units.
	 * On FreeBSD vm_buffers is used for wire counter.
	 */
	uint64_t		vm_active;
	uint64_t		vm_inactive;
	uint64_t		vm_total;
	uint64_t		vm_free;
	uint64_t		vm_cached;
	uint64_t		vm_buffers;

	/*
	 * Per node IO statistics will live here.
	 * Reserved for future use.
	 */
	uint64_t		reserved[32];
};

static inline void dnet_convert_stat(struct dnet_stat *st)
{
	int i;

	for (i=0; i<3; ++i)
		st->la[i] = dnet_bswap16(st->la[i]);

	st->bsize = dnet_bswap64(st->bsize);
	st->frsize = dnet_bswap64(st->frsize);
	st->blocks = dnet_bswap64(st->blocks);
	st->bfree = dnet_bswap64(st->bfree);
	st->bavail = dnet_bswap64(st->bavail);
	st->files = dnet_bswap64(st->files);
	st->ffree = dnet_bswap64(st->ffree);
	st->favail = dnet_bswap64(st->favail);
	st->fsid = dnet_bswap64(st->fsid);
	st->namemax = dnet_bswap16(st->namemax);

	st->vm_active = dnet_bswap64(st->vm_active);
	st->vm_inactive = dnet_bswap64(st->vm_inactive);
	st->vm_total = dnet_bswap64(st->vm_total);
	st->vm_free = dnet_bswap64(st->vm_free);
	st->vm_buffers = dnet_bswap64(st->vm_buffers);
	st->vm_cached = dnet_bswap64(st->vm_cached);
}

struct dnet_io_notification
{
	struct dnet_addr_attr		addr;
	struct dnet_io_attr		io;
};

static inline void dnet_convert_io_notification(struct dnet_io_notification *n)
{
	dnet_convert_addr_attr(&n->addr);
	dnet_convert_io_attr(&n->io);
}

struct dnet_stat_count
{
	uint64_t			count;
	uint64_t			err;
};

static inline void dnet_convert_stat_count(struct dnet_stat_count *st, int num)
{
	int i;

	for (i=0; i<num; ++i) {
		st[i].count = dnet_bswap64(st[i].count);
		st[i].err = dnet_bswap64(st[i].err);
	}
}

struct dnet_addr_stat
{
	struct dnet_addr		addr;
	int				num;
	int				cmd_num;
	struct dnet_stat_count		count[0];
} __attribute__ ((packed));

static inline void dnet_convert_addr_stat(struct dnet_addr_stat *st, int num)
{
	st->addr.addr_len = dnet_bswap32(st->addr.addr_len);
	st->num = dnet_bswap32(st->num);
	if (!num)
		num = st->num;
	st->cmd_num = dnet_bswap32(st->cmd_num);

	dnet_convert_stat_count(st->count, num);
}

static inline void dnet_stat_inc(struct dnet_stat_count *st, int cmd, int err)
{
	if (cmd >= __DNET_CMD_MAX)
		cmd = DNET_CMD_UNKNOWN;

	if (!err)
		st[cmd].count++;
	else
		st[cmd].err++;
}

struct dnet_time {
	uint64_t		tsec, tnsec;
};

static inline void dnet_convert_time(struct dnet_time *tm)
{
	tm->tsec = dnet_bswap64(tm->tsec);
	tm->tnsec = dnet_bswap64(tm->tnsec);
}

static inline void dnet_current_time(struct dnet_time *t)
{
	struct timeval tv;

	gettimeofday(&tv, NULL);

	t->tsec = tv.tv_sec;
	t->tnsec = tv.tv_usec * 1000;
}

struct dnet_file_info {
	int			flen;		/* filename length, which goes after this structure */
	unsigned char		checksum[DNET_CSUM_SIZE];

	unsigned int		nlink;

	uint64_t		mode;

	uint64_t		dev;
	uint64_t		rdev;

	uint64_t		ino;

	uint64_t		uid;
	uint64_t		gid;

	uint64_t		blksize;
	uint64_t		blocks;

	uint64_t		size;
	uint64_t		offset;		/* offset within eblob */

	struct dnet_time	atime;
	struct dnet_time	ctime;
	struct dnet_time	mtime;
};

static inline void dnet_convert_file_info(struct dnet_file_info *info)
{
	info->flen = dnet_bswap32(info->flen);
	info->nlink = dnet_bswap32(info->nlink);

	info->mode = dnet_bswap64(info->mode);
	info->dev = dnet_bswap64(info->dev);
	info->ino = dnet_bswap64(info->ino);
	info->uid = dnet_bswap64(info->uid);
	info->gid = dnet_bswap64(info->gid);
	info->blksize = dnet_bswap64(info->blksize);
	info->blocks = dnet_bswap64(info->blocks);
	info->rdev = dnet_bswap64(info->rdev);
	info->size = dnet_bswap64(info->size);
	info->offset = dnet_bswap64(info->offset);

	dnet_convert_time(&info->atime);
	dnet_convert_time(&info->ctime);
	dnet_convert_time(&info->mtime);
}

static inline void dnet_info_from_stat(struct dnet_file_info *info, struct stat *st)
{
	info->nlink = st->st_nlink;
	info->mode = st->st_mode;
	info->dev = st->st_dev;
	info->ino = st->st_ino;
	info->uid = st->st_uid;
	info->gid = st->st_gid;
	info->blksize = st->st_blksize;
	info->blocks = st->st_blocks;
	info->rdev = st->st_rdev;
	info->size = st->st_size;
	info->offset = 0;

	info->atime.tsec = st->st_atime;
	info->ctime.tsec = st->st_ctime;
	info->mtime.tsec = st->st_mtime;

	info->atime.tnsec = 0;
	info->ctime.tnsec = 0;
	info->mtime.tnsec = 0;
}

/* Elliptics node status - if set, status will be changed */
#define DNET_ATTR_STATUS_CHANGE		(1<<0)

/* Elliptics node should exit */
#define DNET_STATUS_EXIT		(1<<0)

/* Ellipitcs node goes ro/rw */
#define DNET_STATUS_RO			(1<<1)

struct dnet_node_status {
	int nflags;
	int status_flags;  /* DNET_STATUS_EXIT, DNET_STATUS_RO should be specified here */
	uint32_t log_mask;
};

static inline void dnet_convert_node_status(struct dnet_node_status *st)
{
	st->nflags = dnet_bswap32(st->nflags);
	st->status_flags = dnet_bswap32(st->status_flags);
	st->log_mask = dnet_bswap32(st->log_mask);
}

#define DNET_AUTH_COOKIE_SIZE	32

struct dnet_auth {
	char			cookie[DNET_AUTH_COOKIE_SIZE];
	uint64_t		flags;
	uint64_t		unused[3];
};

static inline void dnet_convert_auth(struct dnet_auth *a)
{
	a->flags = dnet_bswap64(a->flags);
}

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

struct dnet_meta_update {
	int			unused_gap;
	int			group_id;
	uint64_t		flags;
	struct dnet_time	tm;
	uint64_t		reserved[4];
} __attribute__((packed));

static inline void dnet_convert_meta_update(struct dnet_meta_update *m)
{
	dnet_convert_time(&m->tm);
	m->flags = dnet_bswap64(m->flags);
}

struct dnet_meta_check_status {
	int			status;
	int			pad;
	struct dnet_time	tm;
	uint64_t		reserved[4];
} __attribute__ ((packed));

static inline void dnet_convert_meta_check_status(struct dnet_meta_check_status *c)
{
	c->status = dnet_bswap32(c->status);
	dnet_convert_time(&c->tm);
}

struct dnet_meta_checksum {
	uint8_t			checksum[DNET_CSUM_SIZE];
	struct dnet_time	tm;
} __attribute__ ((packed));

static inline void dnet_convert_meta_checksum(struct dnet_meta_checksum *c)
{
	dnet_convert_time(&c->tm);
}

struct sph {
	uint64_t		data_size;		/* size of text data in @data - located after even string */
	uint64_t		binary_size;		/* size of binary data in @data - located after text data */
	uint64_t		flags;
	int			event_size;		/* size of the event string - it is located first in @data */
	int			status;			/* processing status - negative errno code or zero on success */
	int			key;			/* meta-key - used to map header to particular worker, see pool::worker_process() */
	int			pad;
	char			data[0];
} __attribute__ ((packed));

static inline void dnet_convert_sph(struct sph *e)
{
	e->data_size = dnet_bswap64(e->data_size);
	e->binary_size = dnet_bswap64(e->binary_size);
	e->flags = dnet_bswap64(e->flags);
	e->event_size = dnet_bswap32(e->event_size);
	e->status = dnet_bswap32(e->status);
	e->key = dnet_bswap32(e->key);
}

struct srw_init_ctl {
	char			*binary;		/* path to srw_worker binary - it is used to spawn script workers */
	char			*log;			/* srw log path - initialized to the same config string as for 'log' by default */
	char			*pipe;			/* pipe base - elliptics will talk to workers via @pipe.c2w and @pipe.w2c */
	char			*init;			/* path to initialization object */
	char			*config;		/* path to config object */
	void			*priv;			/* opaque private data */
	int			pad;			/* srw worker type */
	int			num;			/* number of workers */
} __attribute__ ((packed));

struct srw_load_ctl {
	int			len;			/* length of the binary-object-name string */
	int			wnum;			/* number of workers for this binary */
	char			name[0];
} __attribute__ ((packed));

static inline void srw_convert_load_ctl(struct srw_load_ctl *ctl)
{
	ctl->len = dnet_bswap32(ctl->len);
	ctl->wnum = dnet_bswap32(ctl->wnum);
}

#ifdef __cplusplus
}
#endif

#endif /* __DNET_PACKET_H */
