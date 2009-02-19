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

#ifndef __PACKET_H
#define __PACKET_H

#include <asm/byteorder.h>
#include <arpa/inet.h>

#include "core.h"

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

struct el_cmd
{
	unsigned char			id[EL_ID_SIZE];
	unsigned int			flags;
	int				status;
	__u64				trans;
	__u64				size;
	unsigned char			data[0];
} __attribute__ ((packed));

static inline void el_convert_cmd(struct el_cmd *cmd)
{
	cmd->flags = __cpu_to_be32(cmd->flags);
	cmd->status = __cpu_to_be32(cmd->status);
	cmd->size = __cpu_to_be64(cmd->size);
	cmd->trans = __cpu_to_be64(cmd->trans);
}

struct el_attr
{
	__u64				size;
	unsigned int			cmd;
	unsigned int			flags;
	unsigned int			unused[2];
};

static inline void el_convert_attr(struct el_attr *a)
{
	a->size = __cpu_to_be64(a->size);
	a->cmd = __cpu_to_be32(a->cmd);
	a->flags = __cpu_to_be32(a->flags);
}

#define EL_ADDR_SIZE			128

struct el_addr
{
	unsigned char			addr[EL_ADDR_SIZE];
	unsigned int			addr_size;
};

struct el_list
{
	unsigned char			id[EL_ID_SIZE];
	unsigned int			size;
	unsigned char			data[0];
};

static inline void el_convert_list(struct el_list *l)
{
	l->size = __cpu_to_be32(l->size);
}

struct el_addr_attr
{
	__u32				sock_type;
	__u32				proto;
	__u32				addr_len;
	struct sockaddr			addr;
};

static inline void el_convert_addr_attr(struct el_addr_attr *a)
{
	a->addr_len = htonl(a->addr_len);
	a->proto = htonl(a->proto);
	a->sock_type = htonl(a->sock_type);
}

struct el_addr_cmd
{
	struct el_cmd			cmd;
	struct el_attr			a;
	struct el_addr_attr		addr;
};

static inline void el_convert_addr_cmd(struct el_addr_cmd *l)
{
	el_convert_cmd(&l->cmd);
	el_convert_attr(&l->a);
	el_convert_addr_attr(&l->addr);
}

/*
 * IO is a data updatae and thus history for the corresponding
 * object has to be updated.
 */
#define DNET_IO_FLAGS_UPDATE	(1<<0)
/* Append given data at the end of the object */
#define DNET_IO_FLAGS_APPEND	(1<<1)

struct el_io_attr
{
	unsigned char			id[EL_ID_SIZE];
	unsigned int			flags;
	__u64				offset;
	__u64				size;
};

static inline void el_convert_io_attr(struct el_io_attr *a)
{
	a->flags = __cpu_to_be32(a->flags);
	a->offset = __cpu_to_be64(a->offset);
	a->size = __cpu_to_be64(a->size);
}

#endif /* __PACKET_H */
