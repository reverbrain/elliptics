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

#ifndef __COMMON_H
#define __COMMON_H

#include <sys/mman.h>

#include "elliptics/packet.h"
#include "elliptics/interface.h"

#ifdef __cplusplus
extern "C" {
#endif

void dnet_common_log(void *priv, int level, const char *msg);
void dnet_syslog(void *priv, int level, const char *msg);

int dnet_common_add_remote_addr(struct dnet_node *n, char *orig_addr);

struct dnet_node *dnet_parse_config(const char *file, int mon);
int dnet_parse_groups(char *value, int **groups);

enum dnet_common_embed_types {
	DNET_FCGI_EMBED_DATA		= 1,
	DNET_FCGI_EMBED_TIMESTAMP,
};

struct dnet_common_embed {
	uint64_t		size;
	uint32_t		type;
	uint32_t		flags;
	uint8_t			data[0];
};

static inline void dnet_common_convert_embedded(struct dnet_common_embed *e)
{
	e->size = dnet_bswap64(e->size);
	e->type = dnet_bswap32(e->type);
	e->flags = dnet_bswap32(e->flags);
}

int dnet_common_prepend_data(struct timespec *ts, uint64_t size, void *buf, int *bufsize);

int dnet_background(void);

int dnet_map_history(struct dnet_node *n, char *file, struct dnet_history_map *map);
void dnet_unmap_history(struct dnet_node *n, struct dnet_history_map *map);

#ifdef __cplusplus
}
#endif

#endif /* __COMMON_H */
