/*
 * Copyright 2015+ Kirill Smorodinnikov <shaitkir@gmail.com>
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
 * You should have received a copy of the GNU General Public License
 * along with Elliptics.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef __DNET_FILE_BACKEND_H
#define __DNET_FILE_BACKEND_H

#include <sys/types.h>
#include <stdint.h>

#include <eblob/blob.h>

#include "elliptics/interface.h"

#ifdef __cplusplus
extern "C" {
#endif

struct dnet_config_backend;

struct file_backend_root
{
	char			*root;
	int			root_len;
	int			sync;
	int			bit_num;

	uint64_t		records_in_blob;
	uint64_t		blob_size;
	int			defrag_percentage;
	int			defrag_timeout;

	dnet_logger		*blog;
	struct eblob_log	log;
	struct eblob_backend	*meta;
};

int dnet_file_config_to_json(struct dnet_config_backend *b, char **json_stat, size_t *size);

#ifdef __cplusplus
}
#endif

#endif /* __DNET_FILE_BACKEND_H */