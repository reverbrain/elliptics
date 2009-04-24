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

#include <dnet/typedefs.h>
#include <arpa/inet.h>
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
	uint32_t		sock_type;
	uint32_t		proto;
	struct dnet_addr	addr;
} __attribute__ ((packed));

static inline void dnet_convert_addr_attr(struct dnet_addr_attr *a)
{
	a->addr.addr_len = dnet_bswap32(a->addr.addr_len);
	a->proto = dnet_bswap32(a->proto);
	a->sock_type = dnet_bswap32(a->sock_type);
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

/* Update history if set. Is not checked when history file is updated directly */
#define DNET_IO_FLAGS_HISTORY_UPDATE	(1<<0)

/* Append given data at the end of the object */
#define DNET_IO_FLAGS_APPEND		(1<<1)

/* History IO request. */
#define DNET_IO_FLAGS_HISTORY		(1<<2)

/* Update object itself when set */
#define DNET_IO_FLAGS_OBJECT		(1<<3)

/* Only perform transaction storing, no history for the main object will be updated */
#define DNET_IO_FLAGS_TRANS_ONLY	(1<<4)

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
	uint64_t		offset;
	uint64_t		size;
} __attribute__ ((packed));

static inline void dnet_convert_history_entry(struct dnet_history_entry *a)
{
	a->flags = dnet_bswap32(a->flags);
	a->offset = dnet_bswap64(a->offset);
	a->size = dnet_bswap64(a->size);
}

#ifdef __cplusplus
}
#endif

#endif /* __DNET_PACKET_H */
