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

#ifndef __unused
#define __unused	__attribute__ ((unused))
#endif

#ifdef HAVE_OPENSSL

#include <openssl/hmac.h>
#include <openssl/evp.h>

struct dnet_openssl_crypto_engine
{
	EVP_MD_CTX 		mdctx;
	const EVP_MD		*evp_md;
};

static int dnet_openssl_digest_init(void *priv)
{
	struct dnet_crypto_engine *eng = priv;
	struct dnet_openssl_crypto_engine *e = eng->engine;

	EVP_DigestInit_ex(&e->mdctx, e->evp_md, NULL);
	return 0;
}

static int dnet_openssl_digest_update(void *priv, void *src, uint64_t size,
		void *dst __unused, unsigned int *dsize __unused,
		unsigned int flags __unused)
{
	struct dnet_crypto_engine *eng = priv;
	struct dnet_openssl_crypto_engine *e = eng->engine;

	EVP_DigestUpdate(&e->mdctx, src, size);
	return 0;
}

static int dnet_openssl_digest_final(void *priv, void *result, unsigned int *rsize,
		unsigned int flags __unused)
{
	struct dnet_crypto_engine *eng = priv;
	struct dnet_openssl_crypto_engine *e = eng->engine;
	unsigned int rs = *rsize;

	EVP_DigestFinal_ex(&e->mdctx, result, rsize);

	if (*rsize < rs)
		memset(result + *rsize, 0, rs - *rsize);
	EVP_MD_CTX_cleanup(&e->mdctx);
	return 0;
}

int dnet_openssl_crypto_engine_init(struct dnet_crypto_engine *eng, char *hash)
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

	eng->init = dnet_openssl_digest_init;
	eng->update = dnet_openssl_digest_update;
	eng->final = dnet_openssl_digest_final;

	eng->engine = e;

	printf("Successfully initialized '%s' hash.\n", hash);

	return 0;
}
#else
int dnet_openssl_crypto_engine_init(struct dnet_crypto_engine *e __unused, char *hash __unused)
{
	return -ENOTSUP;
}
#endif

struct dnet_jhash_engine
{
	uint32_t		initval;
};

static int dnet_jhash_init(void *priv)
{
	struct dnet_crypto_engine *eng = priv;
	struct dnet_jhash_engine *e = eng->engine;

	e->initval = 0;
	return 0;
}

#ifdef WORDS_BIGENDIAN
extern uint32_t hashbig( const void *key, size_t length, uint32_t initval);
#else
extern uint32_t hashlittle( const void *key, size_t length, uint32_t initval);
#endif

static int dnet_jhash_update(void *priv, void *src, uint64_t size,
		void *dst __unused, unsigned int *dsize __unused,
		unsigned int flags __unused)
{
	struct dnet_crypto_engine *eng = priv;
	struct dnet_jhash_engine *e = eng->engine;

#ifdef WORDS_BIGENDIAN
	e->initval = hashbig(src, size, e->initval);
#else
	e->initval = hashlittle(src, size, e->initval);
#endif

	return 0;
}

static int dnet_jhash_final(void *priv, void *result, unsigned int *rsize,
		unsigned int flags __unused)
{
	struct dnet_crypto_engine *eng = priv;
	struct dnet_jhash_engine *e = eng->engine;
	unsigned int sz = *rsize;

	memset(result, 0, sz);

	if (sz > sizeof(e->initval))
		sz = sizeof(e->initval);

	memcpy(result, &e->initval, sz);
	return 0;
}

static int dnet_jhash_crypto_engine_init(struct dnet_crypto_engine *eng)
{
	struct dnet_jhash_engine *e;

	e = malloc(sizeof(struct dnet_jhash_engine));
	if (!e)
		return -ENOMEM;
	memset(e, 0, sizeof(struct dnet_jhash_engine));

	eng->init = dnet_jhash_init;
	eng->update = dnet_jhash_update;
	eng->final = dnet_jhash_final;

	eng->engine = e;
	return 0;
}

int dnet_crypto_engine_init(struct dnet_crypto_engine *e, char *hash)
{
	snprintf(e->name, sizeof(e->name), "%s", hash);

	if (!strcmp(hash, "jhash"))
		return dnet_jhash_crypto_engine_init(e);

	return dnet_openssl_crypto_engine_init(e, hash);
}
