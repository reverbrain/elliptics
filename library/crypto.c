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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>

#include "elliptics.h"
#include "elliptics/interface.h"

#include "crypto/sha512.h"

static void dnet_transform_final(void *dst, const void *src, unsigned int *rsize, unsigned int rs)
{
	if (*rsize < rs) {
		memcpy((char *)dst, src, *rsize);
		memset((char *)dst + *rsize, 0, rs - *rsize);
	} else {
		memcpy(dst, src, rs);
		*rsize = rs;
	}
}

static int dnet_local_digest_transform(void *priv __unused, struct dnet_session *s,
		const void *src, uint64_t size,
		void *dst, unsigned int *dsize, unsigned int flags __unused)
{
	unsigned int rs = *dsize;
	unsigned char hash[64];
#if 1
	struct sha512_ctx ctx;

	sha512_init_ctx(&ctx);

	if (s && s->ns && s->nsize) {
		sha512_process_bytes(s->ns, s->nsize, &ctx);
		sha512_process_bytes("\0", 1, &ctx);
	}

	sha512_process_bytes(src, size, &ctx);
	sha512_finish_ctx(&ctx, hash);

#else
	sha512_buffer(src, size, hash);
#endif
	dnet_transform_final(dst, hash, dsize, rs);
	return 0;
}

void dnet_crypto_cleanup(struct dnet_node *n __unused)
{
}

int dnet_crypto_init(struct dnet_node *n)
{
	struct dnet_transform *t = &n->transform;

	t->transform = dnet_local_digest_transform;
	t->priv = NULL;

	return 0;
}
