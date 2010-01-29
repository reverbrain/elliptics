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

static void dnet_transform_final(struct dnet_crypto_engine *eng, void *addr,
		void *dst, void *src, unsigned int *rsize, unsigned int rs)
{
	if (*rsize < rs) {
		memcpy(dst, src, *rsize);
		memset(dst + *rsize, 0, rs - *rsize);
	} else {
		memcpy(dst, src, rs);
		*rsize = rs;
	}

	memcpy(addr, dst, rs);

	if (eng->num >= 0) {
		unsigned int *ptr = addr;
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
	dnet_transform_final(eng, addr, result, md_value, rsize, rs);

	return 0;
}

static void dnet_openssl_crypto_engine_cleanup(void *priv)
{
	struct dnet_crypto_engine *eng = priv;
	struct dnet_openssl_crypto_engine *e = eng->engine;

	EVP_MD_CTX_init(&e->mdctx);
	free(e);
	free(priv);
}

static int dnet_openssl_crypto_engine_init(struct dnet_crypto_engine *eng, char *hash, int num)
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

	eng->num = num;
	eng->init = dnet_openssl_digest_init;
	eng->update = dnet_openssl_digest_update;
	eng->final = dnet_openssl_digest_final;
	eng->cleanup = dnet_openssl_crypto_engine_cleanup;
	eng->engine = e;

	printf("Successfully initialized '%s' hash.\n", hash);

	return 0;
}

#else

static int dnet_openssl_crypto_engine_init(struct dnet_crypto_engine *e __unused, char *hash __unused, int num __unused)
{
	return -ENOTSUP;
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
	unsigned int rs = *rsize;

	*rsize = sizeof(e->initval);
	dnet_transform_final(eng, addr, result, &e->initval, rsize, rs);

	return 0;
}

static void dnet_jhash_crypto_engine_cleanup(void *priv)
{
	struct dnet_crypto_engine *eng = priv;
	struct dnet_jhash_engine *e = eng->engine;

	free(e);
	free(priv);
}

static int dnet_jhash_crypto_engine_init(struct dnet_crypto_engine *eng, int num)
{
	struct dnet_jhash_engine *e;

	e = malloc(sizeof(struct dnet_jhash_engine));
	if (!e)
		return -ENOMEM;
	memset(e, 0, sizeof(struct dnet_jhash_engine));

	eng->num = num;
	eng->init = dnet_jhash_init;
	eng->update = dnet_jhash_update;
	eng->final = dnet_jhash_final;
	eng->cleanup = dnet_jhash_crypto_engine_cleanup;
	eng->engine = e;
	return 0;
}

struct dnet_prev_engine
{
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

	return dnet_state_get_prev_id(e->node, result, addr, eng->num);
}

static void dnet_prev_engine_cleanup(void *priv)
{
	struct dnet_crypto_engine *eng = priv;
	struct dnet_prev_engine *e = eng->engine;

	free(e);
	free(priv);
}

static int dnet_prev_engine_init(struct dnet_crypto_engine *eng, int num)
{
	struct dnet_prev_engine *e;

	e = malloc(sizeof(struct dnet_prev_engine));
	if (!e)
		return -ENOMEM;
	memset(e, 0, sizeof(struct dnet_prev_engine));

	eng->num = num;
	eng->engine = e;
	eng->init = dnet_prev_init;
	eng->update = dnet_prev_update;
	eng->final = dnet_prev_final;
	eng->cleanup = dnet_prev_engine_cleanup;

	return 0;
}

int dnet_crypto_engine_init(struct dnet_crypto_engine *e, char *hash)
{
	char *str = NULL;
	int num, err;

	snprintf(e->name, sizeof(e->name), "%s", hash);

	if (!strncmp(hash, "prev", 4)) {
		if (strlen(hash) <= 4) {
			fprintf(stderr, "Failed to register 'previos' transformation -"
					" you have to provide a number of entries, like 'prev3'.\n");
			return -EINVAL;
		}

		num = atoi(&hash[4]);

		if (num <= 0) {
			fprintf(stderr, "Non-positive number (%s/%d) is not allowed to the 'previous' transformation.\n",
					hash, num);
			return -EINVAL;
		}

		return dnet_prev_engine_init(e, num);
	}

	err = sscanf(hash, "dc%d_%as", &num, &str);
	if (err == 2)
		hash = str;
	else
		num = -1;

	if (!strcmp(hash, "jhash")) {
		err = dnet_jhash_crypto_engine_init(e, num);
		if (err)
			goto out;
	}

	err = dnet_openssl_crypto_engine_init(e, hash, num);
	if (err)
		goto out;

	err = 0;

out:
	free(str);
	return err;
}
