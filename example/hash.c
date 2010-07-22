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

#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "hash.h"

#include <elliptics/packet.h>
#include <elliptics/interface.h>

#ifndef __unused
#define __unused	__attribute__ ((unused))
#endif

static void dnet_transform_final(struct dnet_crypto_engine *eng __unused,
		void *dst, void *src, unsigned int *rsize, unsigned int rs)
{
	if (*rsize < rs) {
		memcpy(dst, src, *rsize);
		memset(dst + *rsize, 0, rs - *rsize);
	} else {
		memcpy(dst, src, rs);
		*rsize = rs;
	}

	if (eng->num >= 0) {
		unsigned int *ptr = dst;
		*ptr = eng->num;
		ptr = dst;
		*ptr = eng->num;
	}
}

#ifdef HAVE_OPENSSL

#include <openssl/hmac.h>
#include <openssl/evp.h>

struct dnet_openssl_crypto_engine
{
	EVP_MD_CTX 		mdctx;
	const EVP_MD		*evp_md;
};

static int dnet_openssl_digest_transform(void *priv, void *src, uint64_t size,
		void *dst, unsigned int *dsize, unsigned int flags __unused)
{
	struct dnet_crypto_engine *eng = priv;
	struct dnet_openssl_crypto_engine *e = eng->engine;
	unsigned char md_value[EVP_MAX_MD_SIZE];
	unsigned int rs = *dsize;

	EVP_DigestInit_ex(&e->mdctx, e->evp_md, NULL);
	EVP_DigestUpdate(&e->mdctx, src, size);
	EVP_DigestFinal_ex(&e->mdctx, md_value, dsize);
	dnet_transform_final(eng, dst, md_value, dsize, rs);

	return 0;
}

static void dnet_openssl_crypto_engine_cleanup(void *priv)
{
	struct dnet_crypto_engine *eng = priv;
	struct dnet_openssl_crypto_engine *e = eng->engine;

	EVP_MD_CTX_cleanup(&e->mdctx);
	free(e);
	free(priv);
}

static int dnet_openssl_crypto_engine_init(struct dnet_crypto_engine *eng, char *hash)
{
	struct dnet_openssl_crypto_engine *e;

 	OpenSSL_add_all_digests();

	e = malloc(sizeof(struct dnet_openssl_crypto_engine));
	if (!e)
		return -ENOMEM;
	memset(e, 0, sizeof(struct dnet_openssl_crypto_engine));

	e->evp_md = EVP_get_digestbyname(hash);
	if (!e->evp_md) {
		fprintf(stderr, "Failed to find algorithm '%s' implementation.\n", hash);
		return -ENOENT;
	}

	EVP_MD_CTX_init(&e->mdctx);

	eng->transform = dnet_openssl_digest_transform;
	eng->cleanup = dnet_openssl_crypto_engine_cleanup;
	eng->engine = e;

	return 0;
}

#else

static int dnet_openssl_crypto_engine_init(struct dnet_crypto_engine *e __unused, char *hash __unused)
{
	return -ENOTSUP;
}

#endif

struct dnet_jhash_engine
{
	uint32_t		initval;
};

#ifdef WORDS_BIGENDIAN
extern uint32_t hashbig( const void *key, size_t length, uint32_t initval);
#else
extern uint32_t hashlittle( const void *key, size_t length, uint32_t initval);
#endif

static int dnet_jhash_transform(void *priv, void *src, uint64_t size,
		void *dst, unsigned int *dsize,	unsigned int flags __unused)
{
	struct dnet_crypto_engine *eng = priv;
	struct dnet_jhash_engine *e = eng->engine;
	unsigned int rs = *dsize;

	e->initval = 0;
#ifdef WORDS_BIGENDIAN
	e->initval = hashbig(src, size, e->initval);
#else
	e->initval = hashlittle(src, size, e->initval);
#endif
	*dsize = sizeof(e->initval);
	dnet_transform_final(eng, dst, &e->initval, dsize, rs);

	return 0;
}

static void dnet_jhash_crypto_engine_cleanup(void *priv)
{
	struct dnet_crypto_engine *eng = priv;
	struct dnet_jhash_engine *e = eng->engine;

	free(e);
	free(priv);
}

static int dnet_jhash_crypto_engine_init(struct dnet_crypto_engine *eng)
{
	struct dnet_jhash_engine *e;

	e = malloc(sizeof(struct dnet_jhash_engine));
	if (!e)
		return -ENOMEM;
	memset(e, 0, sizeof(struct dnet_jhash_engine));

	eng->transform = dnet_jhash_transform;
	eng->cleanup = dnet_jhash_crypto_engine_cleanup;
	eng->engine = e;
	return 0;
}

int dnet_crypto_engine_init(struct dnet_crypto_engine *e, char *hash)
{
	char *str = NULL;
	int err;

	e->num = 0;
	snprintf(e->name, sizeof(e->name), "%s", hash);

	err = sscanf(hash, "dc%d_%as", &e->num, &str);
	if (err == 2)
		hash = str;
	else
		e->num = -1;

	if (!strcmp(hash, "jhash")) {
		err = dnet_jhash_crypto_engine_init(e);
		if (err)
			goto out;
	}

	err = dnet_openssl_crypto_engine_init(e, hash);
	if (err)
		goto out;

	err = 0;

out:
	free(str);
	return err;
}
