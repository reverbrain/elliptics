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

#ifndef __DNET_BACKENDS_H
#define __DNET_BACKENDS_H

#ifdef __cplusplus
extern "C" {
#endif

#include "dnet/packet.h"

static inline uint64_t dnet_backend_check_get_size(struct dnet_io_attr *io, uint64_t record_size)
{
	uint64_t size = io->size;

	if (record_size <= io->offset)
		return 0;

	if (!size || size + io->offset >= record_size) {
		if (!size)
			size = record_size;

		if (size + io->offset >= record_size) {
			if (io->offset >= record_size)
				size = 0;
			else
				size = record_size - io->offset;
		}
	}

	return size;
}

int tc_backend_command_handler(void *state, void *priv,
		struct dnet_cmd *cmd, struct dnet_attr *attr,
		void *data);

void tc_backend_exit(void *data);

void *tc_backend_init(const char *env_dir, const char *dbfile, const char *histfile);


int file_backend_command_handler(void *state, void *priv,
		struct dnet_cmd *cmd, struct dnet_attr *attr, void *data);
void *file_backend_setup_root(char *root, int sync, unsigned int bits);

int backend_stat(void *state, char *path, struct dnet_cmd *cmd, struct dnet_attr *attr);

int backend_del(void *state, struct dnet_io_attr *io, struct dnet_history_entry *e, unsigned int num);

static inline uint64_t file_backend_get_dir(unsigned char *id, uint64_t bit_mask)
{
	uint64_t res, *ptr;

	ptr = (uint64_t *)id;
	res = *ptr;

	return res & bit_mask;
}

#ifdef __cplusplus
}
#endif

#endif /* __DNET_BACKENDS_H */
