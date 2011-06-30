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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>

#include "elliptics.h"
#include "elliptics/interface.h"

#include "crypto/sha512.h"

struct dnet_local_crypto_engine
{
	struct dnet_lock	lock;
	void			*ns;
	int			nsize;
};

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

static int dnet_local_digest_transform(void *priv, const void *src, uint64_t size,
		void *dst, unsigned int *dsize, unsigned int flags __unused)
{
	struct dnet_local_crypto_engine *e = priv;
	unsigned int rs = *dsize;
	unsigned char hash[64];
#if 1
	struct sha512_ctx ctx;

	sha512_init_ctx(&ctx);

	if (e->nsize) {
		char x = '\0';

		dnet_lock_lock(&e->lock);
		sha512_process_bytes(e->ns, e->nsize, &ctx);
		sha512_process_bytes(&x, 1, &ctx);
		dnet_lock_unlock(&e->lock);
	}

	sha512_process_bytes(src, size, &ctx);
	sha512_finish_ctx(&ctx, hash);

#else
	sha512_buffer(src, size, hash);
#endif
	dnet_transform_final(dst, hash, dsize, rs);
	return 0;
}

void dnet_crypto_cleanup(struct dnet_node *n)
{
	struct dnet_transform *t = &n->transform;
	struct dnet_local_crypto_engine *e = t->priv;

	dnet_lock_destroy(&e->lock);
	free(e);
}

int dnet_crypto_init(struct dnet_node *n, void *ns, int nsize)
{
	struct dnet_local_crypto_engine *e;
	struct dnet_transform *t = &n->transform;
	int err = -ENOMEM;

	e = malloc(sizeof(struct dnet_local_crypto_engine) + nsize);
	if (!e)
		goto err_out_exit;

	memset(e, 0, sizeof(struct dnet_local_crypto_engine));
	e->ns = e + 1;

	memcpy(e->ns, ns, nsize);
	e->nsize = nsize;

	err = dnet_lock_init(&e->lock);
	if (err) {
		dnet_log_raw(n, DNET_LOG_ERROR, "Failed to initialize transform lock: %d.\n", err);
		goto err_out_free;
	}

	t->transform = dnet_local_digest_transform;
	t->priv = e;

	return 0;

err_out_free:
	free(e);
err_out_exit:
	return err;
}

void *dnet_node_get_ns(struct dnet_node *n, int *nsize)
{
	struct dnet_transform *t = &n->transform;
	struct dnet_local_crypto_engine *e = t->priv;

	*nsize = e->nsize;
	return e->ns;
}

void dnet_node_set_ns(struct dnet_node *n, void *ns, int nsize)
{
	struct dnet_transform *t = &n->transform;
	struct dnet_local_crypto_engine *e = t->priv;

	e->ns = ns;
	e->nsize = nsize;
}
