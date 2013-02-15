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
#include <inttypes.h>

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

int backend_stat(void *state, char *path, struct dnet_cmd *cmd);

int backend_stat_low_level(const char *path, struct dnet_stat *st);

static inline char *file_backend_get_dir(const unsigned char *id, uint64_t bit_num, char *dst)
{
	char *res = dnet_dump_id_len_raw(id, (bit_num + 7) / 8, dst);

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

/*! On disk extension header */
struct dnet_ext {
	uint32_t		etype;		/* Extension type */
	uint32_t		size;		/* Size of data (excluding header) */
	uint32_t		__pad[2];	/* For future use (should be NULLed ) */
	unsigned char		data[0];	/* Data itself */
};

/*! Info extension on-disk structure */
struct dnet_ext_info {
	struct dnet_ext		hdr;		/* Header for information extension */
	uint32_t		size;		/* Size of all extensions */
	uint32_t		count;		/* Number of extensions in record */
	uint64_t		__pad[2];	/* For future use (should be NULLed) */
};

/*! Extensions container */
struct dnet_ext_list {
	uint32_t		size;		/* Total size of extensions */
	uint32_t		count;		/* Number of entries in list */
	struct dnet_ext_hdr	*exts;		/* Pointer to array of extensions */
	uint64_t		__pad[2];	/* For future use (should be NULLed ) */
};

/*! Types of extensions */
enum {
	DNET_EXTENSION_FIRST,		/* Assert */
	DNET_EXTENSION_INFO,		/* Extensions information */
	DNET_EXTENSION_TS,		/* Timestamp */
	DNET_EXTENSION_USERDATA,	/* User-provided metadata */
	DNET_EXTENSION_LAST		/* Assert */
};

/*
 * Extension list manipulation functions
 * TODO: dnet_ext_list_remove / dnet_ext_list_replace
 */

/*! Create list of extensions that can be placed in record's footer */
struct dnet_ext_list *dnet_ext_list_create();
/*! Initialize already allocated list */
void dnet_ext_list_init(struct dnet_ext_list *elist);
/*! Frees memory used by extension list and all extensions in it */
void dnet_ext_list_destroy(struct dnet_ext_list *elist);
/* Create extension from type, size and data and append it to \a elist */
int dnet_ext_list_append(struct dnet_ext_list *elist, int etype, uint64_t size, const void *data);

/*
 * Extension manipulation functions
 */

/*! Get pointer to extension of given \a etype in \a elist */
struct dnet_ext *dnet_ext_get(const struct dnet_ext_list *elist, int etype);
/*! Return size of extension */
uint32_t dnet_ext_get_size(const struct dnet_ext *ext);
/*! Return pointer to data from extension */
void *dnet_ext_get_data(const struct dnet_ext *ext);
/*! Free memory occupied by an extension */
void dnet_ext_put(struct dnet_ext *ext);

int dnet_backend_register(struct dnet_config_backend *b);

int dnet_file_backend_init(void);
void dnet_file_backend_exit(void);

int dnet_eblob_backend_init(void);
void dnet_eblob_backend_exit(void);

int backend_storage_size(struct dnet_config_backend *b, const char *root);

int dnet_backend_check_log_level(int level);
void dnet_backend_log_raw(int level, const char *fmt, ...) __attribute__ ((format(printf, 2, 3)));
#define dnet_backend_log(level, format, a...)				\
	do {								\
		if (dnet_backend_check_log_level(level))		\
			dnet_backend_log_raw(level, format, ##a); 	\
	} while (0)

#ifdef __cplusplus
}
#endif

#endif /* __DNET_BACKENDS_H */
