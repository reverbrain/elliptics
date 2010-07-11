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

#ifndef __ELLIPTICS_BLOB_H
#define __ELLIPTICS_BLOB_H

#include "elliptics/packet.h"

struct blob_disk_control {
	unsigned char		id[DNET_ID_SIZE];
	uint64_t		flags;
	uint64_t		data_size;
	uint64_t		disk_size;
	uint64_t		position;
} __attribute__ ((packed));

#define BLOB_DISK_CTL_REMOVE	(1<<0)
#define BLOB_DISK_CTL_HISTORY	(1<<1)

static inline void blob_convert_disk_control(struct blob_disk_control *ctl)
{
	ctl->flags = dnet_bswap64(ctl->flags);
	ctl->data_size = dnet_bswap64(ctl->data_size);
	ctl->disk_size = dnet_bswap64(ctl->disk_size);
	ctl->position = dnet_bswap64(ctl->position);
}

struct blob_ram_control {
	unsigned char		key[DNET_ID_SIZE + 1];
	size_t			offset;
	uint64_t		size;
};

int blob_iterate(int fd, struct dnet_log *l,
		int (* callback)(struct blob_disk_control *dc, void *data, off_t position, void *priv),
		void *priv);

#endif /* __ELLIPTICS_BLOB_H */
