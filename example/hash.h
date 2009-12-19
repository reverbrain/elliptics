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

#ifndef __DNET_HASH_H
#define __DNET_HASH_H

#ifdef __cplusplus
extern "C" {
#endif

#include "dnet/core.h"

struct dnet_node;

struct dnet_crypto_engine
{
	char			name[DNET_MAX_NAME_LEN];

	int			num;

	void			*engine;
	int			(* init)(void *priv, struct dnet_node *n);
	int			(* update)(void *priv, void *src, uint64_t size,
					void *dst, unsigned int *dsize, unsigned int flags);
	int			( *final)(void *priv, void *result, void *addr,
					unsigned int *rsize, unsigned int flags);

	void			(* cleanup)(void *priv);
};

int dnet_crypto_engine_init(struct dnet_crypto_engine *e, char *hash);

#ifdef __cplusplus
}
#endif

#endif /* __DNET_HASH_H */
