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

#include <sys/time.h>
#include <arpa/inet.h>

#include <string.h>
#include <stdint.h>

#include <dnet/typedefs.h>
#include <dnet/core.h>

#ifdef __cplusplus
extern "C" {
#endif

enum dnet_commands {
	DNET_CMD_LOOKUP = 1,			/* Lookup address by ID */
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
	DNET_CMD_TRANSFORM_LIST,		/* Receive list of transformation functions */
	DNET_CMD_STAT,				/* Gather remote VM, LA and FS statistics */
	DNET_CMD_NOTIFY,			/* Notify when object in question was modified */
	DNET_CMD_DEL,				/* Remove given object from the storage */
	DNET_CMD_STAT_COUNT,			/* Gather remote per-cmd statistics */

	DNET_CMD_UNKNOWN,			/* This slot is allocated for statistics gathered for unknown commands */
	__DNET_CMD_MAX,
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

/* Do not perform local transformation of the received transaction */
#define DNET_FLAGS_NO_LOCAL_TRANSFORM	(1<<4)

struct dnet_cmd
{
	uint8_t			id[DNET_ID_SIZE];
	uint32_t		flags;
	int			status;
	uint64_t		trans;
	uint64_t		size;
	uint8_t			data[0];
} __attribute__ ((packed));

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

static inline void dnet_convert_cmd(struct dnet_cmd *cmd)
{
	cmd->flags = dnet_bswap32(cmd->flags);
	cmd->status = dnet_bswap32(cmd->status);
	cmd->size = dnet_bswap64(cmd->size);
	cmd->trans = dnet_bswap64(cmd->trans);
}

/* Do not split data into multiple transactions */
#define DNET_ATTR_NO_TRANSACTION_SPLIT		(1<<0)

/* Do not work with history/transaction machinery, write data as is into object */
#define DNET_ATTR_DIRECT_TRANSACTION		(1<<1)

/* Provide only those IDs which are behind of node's range. */
#define DNET_ATTR_ID_OUT			(1<<0)

/* Read history for given ID and return its flags */
#define DNET_ATTR_ID_FLAGS			(1<<1)

/* Lookup attribute flags */

/* Stat local object and return state address only if object is readable */
#define DNET_ATTR_LOOKUP_STAT			(1<<0)

/* Lookup history object instead of data one */
#define DNET_ATTR_LOOKUP_HISTORY		(1<<1)

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
	uint8_t			id[DNET_ID_SIZE];
	uint32_t		size;
	uint8_t			data[0];
} __attribute__ ((packed));

static inline void dnet_convert_list(struct dnet_list *l)
{
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

struct dnet_route_attr
{
	unsigned char		id[DNET_ID_SIZE];
	struct dnet_addr_attr	addr;
} __attribute__ ((packed));

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
#define DNET_IO_FLAGS_NO_HISTORY_UPDATE	(1<<0)

/* Append given data at the end of the object */
#define DNET_IO_FLAGS_APPEND		(1<<1)

/* History IO request. */
#define DNET_IO_FLAGS_HISTORY		(1<<2)

/* Metada IO request */
#define DNET_IO_FLAGS_META		(1<<3)

/* Transaction ID was generated by content hashing */
#define DNET_IO_FLAGS_ID_CONTENT	(1<<4)

/* Transaction ID contains version information */
#define DNET_IO_FLAGS_ID_VERSION	(1<<5)

/* Object was removed */
#define DNET_IO_FLAGS_REMOVED		(1<<6)

/* Object is a parent object */
#define DNET_IO_FLAGS_PARENT		(1<<7)

struct dnet_io_attr
{
	uint8_t			origin[DNET_ID_SIZE];
	uint8_t			id[DNET_ID_SIZE];
	uint32_t		flags;
	uint64_t		offset;
	uint64_t		size;
} __attribute__ ((packed));

static inline void dnet_convert_io_attr(struct dnet_io_attr *a)
{
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

struct dnet_id
{
	uint32_t			flags;
	unsigned char			id[DNET_ID_SIZE];
} __attribute__ ((packed));

static inline void dnet_convert_id(struct dnet_id *id)
{
	id->flags = dnet_bswap32(id->flags);
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
	unsigned char			id[DNET_ID_SIZE];
	int				num;
	struct dnet_stat_count		count[0];
} __attribute__ ((packed));

static inline void dnet_convert_addr_stat(struct dnet_addr_stat *st, int num)
{
	st->addr.addr_len = dnet_bswap32(st->addr.addr_len);
	st->num = dnet_bswap32(st->num);
	if (!num)
		num = st->num;

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

#ifdef __cplusplus
}
#endif

#endif /* __DNET_PACKET_H */
