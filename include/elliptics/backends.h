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

#ifndef __DNET_BACKENDS_H
#define __DNET_BACKENDS_H

#ifdef __cplusplus
extern "C" {
#endif

#include <errno.h>
#include <inttypes.h>
#include <strings.h>

#include "elliptics/core.h"
#include "elliptics/packet.h"
#include "elliptics/interface.h"

static inline int64_t dnet_backend_check_get_size(struct dnet_io_attr *io, uint64_t *offset, uint64_t *size)
{
	io->total_size = *size;

	if (io->offset) {
		if (io->offset >= *size) {
			return -E2BIG;
		}

		*offset += io->offset;
		*size -= io->offset;
	}

	if (io->size != 0 && *size > io->size)
		*size = io->size;
	else
		io->size = *size;

	return 0;
}

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

	dnet_logger			*log;

	int				(* init)(struct dnet_config_backend *b);
	void				(* cleanup)(struct dnet_config_backend *b);
	int				(* to_json)(struct dnet_config_backend *b, char **json_stat, size_t *size);

	struct dnet_backend_callbacks	cb;
};

/*!
 * "Master" functions
 */
/*! Extracts \a elist from data, replaces \a datap pointer and fixes \a sizep */
int dnet_ext_list_extract(void **datap, uint64_t *sizep,
		struct dnet_ext_list *elist, enum dnet_ext_free_data free_data);
/*! Combines \a datap with \a elist and fixes \a sizep */
int dnet_ext_list_combine(void **datap, uint64_t *sizep,
		const struct dnet_ext_list *elist);

/*
 * Extension list manipulation functions
 */

/*! Initialize already allocated list */
void dnet_ext_list_init(struct dnet_ext_list *elist);
/*! Frees memory used by extension list and all extensions in it */
void dnet_ext_list_destroy(struct dnet_ext_list *elist);

/* Conversion functions */
int dnet_ext_list_to_hdr(const struct dnet_ext_list *elist,
		struct dnet_ext_list_hdr *ehdr);
int dnet_ext_hdr_to_list(const struct dnet_ext_list_hdr *ehdr,
		struct dnet_ext_list *elist);
int dnet_ext_list_to_io(const struct dnet_ext_list *elist,
		struct dnet_io_attr *io);
int dnet_ext_io_to_list(const struct dnet_io_attr *io,
		struct dnet_ext_list *elist);

/*! Reads \a ehdr from specified \a offset in given \a fd */
__attribute__((warn_unused_result))
int dnet_ext_hdr_read(struct dnet_ext_list_hdr *ehdr, int fd, uint64_t offset);
/*! Writes \a ehdr to specified \a offset in given \a fd */
__attribute__((warn_unused_result))
int dnet_ext_hdr_write(const struct dnet_ext_list_hdr *ehdr, int fd, uint64_t offset);

int dnet_backend_register(struct dnet_config_data *data, struct dnet_config_backend *b);

struct dnet_config_backend *dnet_eblob_backend_info(void);
struct dnet_config_backend *dnet_file_backend_info(void);
struct dnet_config_backend *dnet_module_backend_info(void);

int dnet_file_backend_init(void);
void dnet_file_backend_exit(void);

int dnet_module_backend_init(void);
void dnet_module_backend_exit(void);

int dnet_eblob_backend_init(void);
void dnet_eblob_backend_exit(void);

int backend_storage_size(struct dnet_config_backend *b, const char *root);

int dnet_backend_check_log_level(dnet_logger *logger, int level);
void dnet_backend_log_raw(dnet_logger *logger, int level, const char *fmt, ...) __attribute__ ((format(printf, 3, 4)));
#define dnet_backend_log(logger, level, format, a...)				\
	do {								\
		if (dnet_backend_check_log_level((logger), (int)(level)))		\
			dnet_backend_log_raw((logger), (int)(level), (format), ##a); 	\
	} while (0)

#ifdef __cplusplus
}
#endif

#endif /* __DNET_BACKENDS_H */
