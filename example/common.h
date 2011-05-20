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

#ifndef __COMMON_H
#define __COMMON_H

#include <sys/mman.h>

#include "config.h"
#include "elliptics/packet.h"
#include "elliptics/interface.h"

#ifdef __cplusplus
extern "C" {
#endif

int dnet_parse_addr(char *addr, struct dnet_config *cfg);

int dnet_parse_numeric_id(char *value, unsigned char *id);

void dnet_common_log(void *priv, uint32_t mask, const char *msg);
void dnet_syslog(void *priv, uint32_t mask, const char *msg);

#define DNET_VERSION_SIZE		4
#define DNET_VERSION_OFFSET		(DNET_ID_SIZE - DNET_VERSION_SIZE)

static inline void dnet_common_convert_id_version(unsigned char *id, int version)
{
	memcpy(id + DNET_VERSION_OFFSET, &version, DNET_VERSION_SIZE);
}

static inline int dnet_common_get_version(unsigned char *id)
{
	int version;

	memcpy(&version, &id[DNET_VERSION_OFFSET], DNET_VERSION_SIZE);

	return version;
}

int dnet_common_add_remote_addr(struct dnet_node *n, struct dnet_config *main_cfg, char *orig_addr);
int dnet_common_add_transform(struct dnet_node *n, char *orig_hash);

struct dnet_node *dnet_parse_config(char *file, int mon);
int dnet_parse_groups(char *value, int **groups);

int dnet_common_write_object(struct dnet_node *n, struct dnet_id *id,
		void *adata, uint32_t asize, int history_only,
		void *data, uint64_t size, struct timespec *ts,
		int (* complete)(struct dnet_net_state *, struct dnet_cmd *, struct dnet_attr *, void *), void *priv,
		uint32_t ioflags);

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

int dnet_map_history(struct dnet_node *n, char *file, struct dnet_history_map *map);
void dnet_unmap_history(struct dnet_node *n, struct dnet_history_map *map);

struct dnet_meta * dnet_meta_search_cust(struct dnet_meta_container *mc, uint32_t type);

#ifdef __cplusplus
}
#endif

#endif /* __COMMON_H */
