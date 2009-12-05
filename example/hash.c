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

#include <dnet/packet.h>
#include <dnet/interface.h>

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

static int dnet_openssl_digest_init(void *priv, struct dnet_node *n __attribute__ ((unused)))
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

static int dnet_openssl_digest_final(void *priv, void *result, void *addr,
		unsigned int *rsize, unsigned int flags __unused)
{
	struct dnet_crypto_engine *eng = priv;
	struct dnet_openssl_crypto_engine *e = eng->engine;
	unsigned char md_value[EVP_MAX_MD_SIZE];
	unsigned int rs = *rsize;

	EVP_DigestFinal_ex(&e->mdctx, md_value, rsize);

	if (*rsize < rs) {
		memcpy(result, md_value, *rsize);
		memset(result + *rsize, 0, rs - *rsize);
	} else {
		memcpy(result, md_value, rs);
		*rsize = rs;
	}

	memcpy(addr, result, rs);
	return 0;
}

static void dnet_openssl_crypto_engine_exit(struct dnet_crypto_engine *eng)
{
	struct dnet_openssl_crypto_engine *e = eng->engine;

	EVP_MD_CTX_init(&e->mdctx);
	free(e);
	eng->engine = NULL;
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

	eng->init = dnet_openssl_digest_init;
	eng->update = dnet_openssl_digest_update;
	eng->final = dnet_openssl_digest_final;

	eng->exit = dnet_openssl_crypto_engine_exit;
	eng->engine = e;

	printf("Successfully initialized '%s' hash.\n", hash);

	return 0;
}

#else

static int dnet_openssl_crypto_engine_init(struct dnet_crypto_engine *e __unused, char *hash __unused)
{
	return -ENOTSUP;
}

static void dnet_openssl_crypto_engine_exit(struct dnet_crypto_engine *eng __unused)
{
}

#endif

struct dnet_jhash_engine
{
	uint32_t		initval;
};

static int dnet_jhash_init(void *priv, struct dnet_node *n __unused)
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

static int dnet_jhash_final(void *priv, void *result, void *addr,
		unsigned int *rsize, unsigned int flags __unused)
{
	struct dnet_crypto_engine *eng = priv;
	struct dnet_jhash_engine *e = eng->engine;
	unsigned int sz = *rsize;

	memset(result, 0, sz);

	if (sz > sizeof(e->initval))
		sz = sizeof(e->initval);

	memcpy(result, &e->initval, sz);
	memcpy(addr, result, *rsize);
	return 0;
}

static void dnet_jhash_crypto_engine_exit(struct dnet_crypto_engine *eng)
{
	struct dnet_jhash_engine *e = eng->engine;

	free(e);
	eng->engine = NULL;
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

	eng->exit = dnet_jhash_crypto_engine_exit;
	eng->engine = e;
	return 0;
}

struct dnet_prev_engine
{
	int			num;
	struct dnet_node	*node;
};

static int dnet_prev_init(void *priv, struct dnet_node *n)
{
	struct dnet_crypto_engine *eng = priv;
	struct dnet_prev_engine *e = eng->engine;

	e->node = n;

	return 0;
}

static int dnet_prev_update(void *priv __unused,
		void *src __unused, uint64_t size __unused,
		void *dst __unused, unsigned int *dsize __unused,
		unsigned int flags __unused)
{
	return 0;
}

static int dnet_prev_final(void *priv, void *result, void *addr,
		unsigned int *rsize, unsigned int flags __unused)
{
	struct dnet_crypto_engine *eng = priv;
	struct dnet_prev_engine *e = eng->engine;
	unsigned int sz = *rsize;

	if (sz != DNET_ID_SIZE)
		return -EINVAL;

	return dnet_state_get_prev_id(e->node, result, addr, e->num);
}

static void dnet_prev_engine_exit(struct dnet_crypto_engine *eng)
{
	struct dnet_prev_engine *e = eng->engine;

	free(e);
	eng->engine = NULL;
}

static int dnet_prev_engine_init(struct dnet_crypto_engine *eng, int num)
{
	struct dnet_prev_engine *e;

	e = malloc(sizeof(struct dnet_prev_engine));
	if (!e)
		return -ENOMEM;
	memset(e, 0, sizeof(struct dnet_prev_engine));

	e->num = num;
	eng->engine = e;
	eng->init = dnet_prev_init;
	eng->update = dnet_prev_update;
	eng->final = dnet_prev_final;

	eng->exit = dnet_prev_engine_exit;

	return 0;
}

int dnet_crypto_engine_init(struct dnet_crypto_engine *e, char *hash)
{
	snprintf(e->name, sizeof(e->name), "%s", hash);

	if (!strncmp(hash, "prev", 4)) {
		int num;

		if (strlen(hash) <= 4) {
			fprintf(stderr, "Failed to register 'previos' transformation -"
					" you have to provide a number of entries, like 'prev3'.\n");
			return -EINVAL;
		}

		num = atoi(&hash[4]);

		if (!num)
			return 0;
		if (num < 0) {
			fprintf(stderr, "Negative number (%d) is not allowed to the 'previous' transformation.\n",
					num);
			return -EINVAL;
		}

		return dnet_prev_engine_init(e, num);
	}

	if (!strcmp(hash, "jhash"))
		return dnet_jhash_crypto_engine_init(e);

	return dnet_openssl_crypto_engine_init(e, hash);
}

void dnet_crypto_engine_exit(struct dnet_crypto_engine *e)
{
	free(e->engine);
}
