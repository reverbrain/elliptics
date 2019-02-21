/*
 * Copyright 2008+ Evgeniy Polyakov <zbr@ioremap.net>
 * Copyright 2013+ Ruslan Nigmatullin <euroelessar@yandex.ru>
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

static int dnet_local_digest_transform_file(void *priv __unused, struct dnet_session *s,
		int fd, uint64_t offset, uint64_t size,
		void *dst, unsigned int *dsize, unsigned int flags __unused)
{
	int err = 0;
	unsigned int rs = *dsize;
	unsigned char hash[64];
	struct sha512_ctx ctx;

	sha512_init_ctx(&ctx);

	if (s && s->ns && s->nsize) {
		sha512_process_bytes(s->ns, s->nsize, &ctx);
		sha512_process_bytes("\0", 1, &ctx);
	}

	err = sha512_file_ctx(fd, offset, size, &ctx);
	if (err) {
		return err;
	}
	sha512_finish_ctx(&ctx, hash);

	dnet_transform_final(dst, hash, dsize, rs);
	return 0;
}

int dnet_digest_transform(const void *src, uint64_t size, struct dnet_id *id)
{
	return dnet_digest_transform_raw(src, size, id->id, DNET_ID_SIZE);
}

int dnet_digest_transform_raw(const void *src, uint64_t size, void *csum, int csum_size)
{
	unsigned int id_size = csum_size;
	return dnet_local_digest_transform(NULL, NULL, src, size, csum, &id_size, 0);
}

int dnet_digest_auth_transform(const void *src, uint64_t size, const void *key, uint64_t key_size, struct dnet_id *id)
{
	return dnet_digest_auth_transform_raw(src, size, key, key_size, id->id, DNET_ID_SIZE);
}

#define SHA512_BLOCK_SIZE 128

int dnet_digest_auth_transform_raw(const void *src, uint64_t size, const void *key, uint64_t key_size, void *csum, int csum_size)
{
	/*
	 * Calculate HMAC-SHA512 according to http://tools.ietf.org/html/rfc2104
	 */
	char hashed_message[DNET_ID_SIZE];
	char hashed_key[SHA512_BLOCK_SIZE];
	char ikeypad[SHA512_BLOCK_SIZE];
	char okeypad[SHA512_BLOCK_SIZE];
	char result[DNET_ID_SIZE];
	size_t i;
	unsigned int rs = csum_size;
	struct sha512_ctx ctx;

	if (key_size > SHA512_BLOCK_SIZE) {
		dnet_digest_transform_raw(key, key_size, hashed_key, SHA512_BLOCK_SIZE);
		key_size = DNET_ID_SIZE;
	} else {
		memcpy(hashed_key, key, key_size);
	}
	if (key_size < SHA512_BLOCK_SIZE) {
		memset(hashed_key + key_size, 0, SHA512_BLOCK_SIZE - key_size);
	}

	for (i = 0; i < SHA512_BLOCK_SIZE; ++i) {
		ikeypad[i] = hashed_key[i] ^ 0x36;
		okeypad[i] = hashed_key[i] ^ 0x5c;
	}

	sha512_init_ctx(&ctx);
	sha512_process_bytes(ikeypad, SHA512_BLOCK_SIZE, &ctx);
	sha512_process_bytes(src, size, &ctx);
	sha512_finish_ctx(&ctx, hashed_message);

	sha512_init_ctx(&ctx);
	sha512_process_bytes(okeypad, SHA512_BLOCK_SIZE, &ctx);
	sha512_process_bytes(hashed_message, DNET_ID_SIZE, &ctx);
	sha512_finish_ctx(&ctx, result);

	/*
	 * Write to csum most of csum_size bytes from result
	 */
	dnet_transform_final(csum, result, &rs, csum_size);
	return 0;
}

void dnet_crypto_cleanup(struct dnet_node *n __unused)
{
}

int dnet_crypto_init(struct dnet_node *n)
{
	struct dnet_transform *t = &n->transform;

	t->transform = dnet_local_digest_transform;
	t->transform_file = dnet_local_digest_transform_file;
	t->priv = NULL;

	return 0;
}
