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

#include <openssl/hmac.h>
#include <openssl/evp.h>

#include "elliptics.h"
#include "elliptics/interface.h"

struct dnet_openssl_crypto_engine
{
	EVP_MD_CTX 		mdctx;
	const EVP_MD		*evp_md;
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

static int dnet_openssl_digest_transform(void *priv, const void *src, uint64_t size,
		void *dst, unsigned int *dsize, unsigned int flags __unused)
{
	struct dnet_openssl_crypto_engine *e = priv;
	unsigned char md_value[EVP_MAX_MD_SIZE];
	unsigned int rs = *dsize;

	dnet_lock_lock(&e->lock);
	EVP_DigestInit_ex(&e->mdctx, e->evp_md, NULL);
	if (e->nsize) {
		char x = '\0';
		EVP_DigestUpdate(&e->mdctx, e->ns, e->nsize);
		EVP_DigestUpdate(&e->mdctx, &x, 1);
	}
	EVP_DigestUpdate(&e->mdctx, src, size);
	EVP_DigestFinal_ex(&e->mdctx, md_value, dsize);
	dnet_lock_unlock(&e->lock);

	dnet_transform_final(dst, md_value, dsize, rs);

	return 0;
}

void dnet_crypto_cleanup(struct dnet_node *n)
{
	struct dnet_transform *t = &n->transform;
	struct dnet_openssl_crypto_engine *e = t->priv;

	EVP_MD_CTX_cleanup(&e->mdctx);
	dnet_lock_destroy(&e->lock);
	free(e);
}

int dnet_crypto_init(struct dnet_node *n, void *ns, int nsize)
{
	struct dnet_openssl_crypto_engine *e;
	struct dnet_transform *t = &n->transform;
	char *hash = "sha512";
	int err = -ENOMEM;

	e = malloc(sizeof(struct dnet_openssl_crypto_engine) + nsize);
	if (!e)
		goto err_out_exit;

	memset(e, 0, sizeof(struct dnet_openssl_crypto_engine));
	e->ns = e + 1;

	memcpy(e->ns, ns, nsize);
	e->nsize = nsize;

	e->evp_md = EVP_sha512();
	if (!e->evp_md) {
		dnet_log_raw(n, DNET_LOG_ERROR, "Failed to find algorithm '%s' implementation.\n", hash);
		goto err_out_free;
	}

	err = dnet_lock_init(&e->lock);
	if (err) {
		dnet_log_raw(n, DNET_LOG_ERROR, "Failed to initialize transform lock: %d.\n", err);
		goto err_out_free;
	}

	EVP_MD_CTX_init(&e->mdctx);

	t->transform = dnet_openssl_digest_transform;
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
	struct dnet_openssl_crypto_engine *e = t->priv;

	*nsize = e->nsize;
	return e->ns;
}

void dnet_node_set_ns(struct dnet_node *n, void *ns, int nsize)
{
	struct dnet_transform *t = &n->transform;
	struct dnet_openssl_crypto_engine *e = t->priv;

	e->ns = ns;
	e->nsize = nsize;
}
