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

#include "config.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <sys/wait.h>

#include <ctype.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "elliptics.h"

#include "elliptics/packet.h"
#include "elliptics/interface.h"

#define dnet_map_log(n, mask, fmt, a...) do { if ((n)) dnet_log((n), mask, fmt, ##a); else fprintf(stderr, fmt, ##a); } while (0)

struct dnet_meta *dnet_meta_search(struct dnet_node *n, void *data, uint32_t size, uint32_t type)
{
	struct dnet_meta m, *found = NULL;

	while (size) {
		if (size < sizeof(struct dnet_meta)) {
			dnet_map_log(n, DNET_LOG_ERROR, "%s: metadata size %u is too small, min %zu, searching for type 0x%x.\n",
					(n) ? dnet_dump_id(&n->id) : "NULL", size, sizeof(struct dnet_meta), type);
			break;
		}

		m = *(struct dnet_meta *)data;
		//dnet_convert_meta(&m);

		if (m.size + sizeof(struct dnet_meta) > size) {
			dnet_map_log(n, DNET_LOG_ERROR, "%s: metadata entry broken: entry size %u, type: 0x%x, struct size: %zu, "
					"total size left: %u, searching for type: 0x%x.\n",
					(n) ? dnet_dump_id(&n->id) : "NULL", m.size, m.type, sizeof(struct dnet_meta), size, type);
			break;
		}

		if (m.type == type) {
			found = data;
			break;
		}

		data += m.size + sizeof(struct dnet_meta);
		size -= m.size + sizeof(struct dnet_meta);
	}

	return found;
}

int dnet_write_metadata(struct dnet_node *n, struct dnet_meta_container *mc, int convert)
{
	if (convert) {
		void *ptr = mc->data;
		int size = mc->size;
		struct dnet_meta *m;

		while (size) {
			m = ptr;

			ptr += sizeof(struct dnet_meta) + m->size;
			size -= sizeof(struct dnet_meta) + m->size;

			dnet_convert_meta(m);
		}
	}

	return dnet_write_data_wait(n, NULL, 0, &mc->id, mc->data, 0, mc->size, NULL, DNET_ATTR_DIRECT_TRANSACTION, DNET_IO_FLAGS_META);
}

int dnet_create_write_metadata(struct dnet_node *n, struct dnet_id *id, char *obj, int len, int *groups, int group_num)
{
	struct dnet_meta_container *mc;
	struct dnet_meta *m;
	int size = 0, err;

	if (obj && len)
		size += len + sizeof(struct dnet_meta);

	if (groups && group_num)
		size += group_num * sizeof(int) + sizeof(struct dnet_meta);
	else if (n->groups && n->group_num) {
		groups = n->groups;
		group_num = n->group_num;
		size += group_num * sizeof(int) + sizeof(struct dnet_meta);
	}

	if (!size) {
		err = -EINVAL;
		goto err_out_exit;
	}

	mc = malloc(sizeof(struct dnet_meta_container) + size);
	if (!mc) {
		err = -ENOMEM;
		goto err_out_exit;
	}
	memset(mc, 0, sizeof(struct dnet_meta_container) + size);

	m = (struct dnet_meta *)(mc + 1);

	if (obj && len) {
		m->size = len;
		m->type = DNET_META_PARENT_OBJECT;
		memcpy(m->data, obj, len);

		m = (struct dnet_meta *)(m->data + len);
	}

	if (groups && group_num) {
		m->size = group_num * sizeof(int);
		m->type = DNET_META_GROUPS;
		memcpy(m->data, groups, group_num * sizeof(int));

		m = (struct dnet_meta *)(m->data + len);
	}

	mc->size = size;
	memcpy(&mc->id, id, sizeof(struct dnet_id));

	err = dnet_write_metadata(n, mc, 1);

	free(mc);
err_out_exit:
	return err;
}

