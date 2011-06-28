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

#include <strings.h>

#include "elliptics/core.h"
#include "elliptics/packet.h"

static inline int64_t dnet_backend_check_get_size(struct dnet_io_attr *io, uint64_t record_size)
{
	uint64_t size = io->size;

	if (record_size <= io->offset)
		return 0;

	if (!record_size && size)
		return -E2BIG;

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

int backend_stat(void *state, char *path, struct dnet_cmd *cmd, struct dnet_attr *attr);

int backend_stat_low_level(const char *path, struct dnet_stat *st);

static inline char *file_backend_get_dir(const unsigned char *id, uint64_t bit_num, char *dst)
{
	char *res = dnet_dump_id_len_raw(id, ALIGN(bit_num, 8) / 8, dst);

	if (res)
		res[bit_num / 4] = '\0';
	return res;
}

struct dnet_config_backend;
struct dnet_config_entry {
	char		key[64];
	int		(*callback)(struct dnet_config_backend *b, char *key, char *value);
};

struct dnet_config_backend {
	char				name[64];
	struct dnet_config_entry	*ent;
	int				num;
	int				size;
	void				*data;

	unsigned long long		storage_size;
	unsigned long long		storage_free;

	struct dnet_log			*log;

	int				(* init)(struct dnet_config_backend *b, struct dnet_config *cfg);
	void				(* cleanup)(struct dnet_config_backend *b);

	struct dnet_backend_callbacks	cb;
};

int dnet_backend_register(struct dnet_config_backend *b);

int dnet_file_backend_init(void);
void dnet_file_backend_exit(void);

int dnet_eblob_backend_init(void);
void dnet_eblob_backend_exit(void);

int backend_storage_size(struct dnet_config_backend *b, const char *root);

int dnet_backend_check_log_mask(uint32_t mask);
void dnet_backend_log_raw(uint32_t mask, const char *fmt, ...) __attribute__ ((format(printf, 2, 3)));
#define dnet_backend_log(mask, format, a...)				\
	do {								\
		if (dnet_backend_check_log_mask(mask))			\
			dnet_backend_log_raw(mask, format, ##a); 	\
	} while (0)

#ifdef __cplusplus
}
#endif

#endif /* __DNET_BACKENDS_H */
