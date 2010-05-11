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

#include "config.h"
#include "dnet/packet.h"
#include "dnet/interface.h"

int dnet_parse_addr(char *addr, struct dnet_config *cfg);

int dnet_parse_numeric_id(char *value, unsigned char *id);

void dnet_common_log(void *priv, uint32_t mask, const char *msg);

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

int dnet_common_write_object(struct dnet_node *n, char *obj, int len,
		void *data, uint64_t size, int version, struct timespec *ts,
		int (* complete)(struct dnet_net_state *, struct dnet_cmd *, struct dnet_attr *, void *),
		void *priv);

int dnet_common_send_meta_transactions(struct dnet_node *n, char *obj, int len,
		char *hashes, int hashes_len);

#endif /* __COMMON_H */
