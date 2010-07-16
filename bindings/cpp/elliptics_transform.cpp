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

#define _XOPEN_SOURCE 600

#include <errno.h>
#include <string.h>

#include <openssl/hmac.h>
#include <openssl/evp.h>

#include "elliptics/cppdef.h"

#ifndef __unused
#define __unused	__attribute__ ((unused))
#endif

int elliptics_transform::transform_init(void *priv, struct dnet_node *n)
{
	elliptics_transform *t = reinterpret_cast<elliptics_transform *>(priv);
	return t->init(priv, n);

}
int elliptics_transform::transform_update(void *priv, void *src, uint64_t size,
					   void *dst, unsigned int *dsize,
					   unsigned int flags)
{
	elliptics_transform *t = reinterpret_cast<elliptics_transform *>(priv);
	return t->update(priv, src, size, dst, dsize, flags);
}
int elliptics_transform::transform_final(void *priv, void *result, void *addr,
				unsigned int *rsize, unsigned int flags)
{
	elliptics_transform *t = reinterpret_cast<elliptics_transform *>(priv);
	return t->final(priv, result, addr, rsize, flags);
}
void elliptics_transform::transform_cleanup(void *priv)
{
	elliptics_transform *t = reinterpret_cast<elliptics_transform *>(priv);
	t->cleanup(priv);
}

static void dnet_transform_final(void *addr, void *dst, void *src, unsigned int *rsize, unsigned int rs)
{
	if (*rsize < rs) {
		memcpy((char *)dst, src, *rsize);
		memset((char *)dst + *rsize, 0, rs - *rsize);
	} else {
		memcpy(dst, src, rs);
		*rsize = rs;
	}

	memcpy(addr, dst, rs);
}

int elliptics_transform_openssl::init(void *priv __unused, struct dnet_node *n __unused)
{
	EVP_DigestInit_ex(&mdctx, evp_md, NULL);
	return 0;
}

int elliptics_transform_openssl::update(void *priv __unused,
		void *src, uint64_t size, void *dst __unused, unsigned int *dsize __unused,
		unsigned int flags __unused)
{
	EVP_DigestUpdate(&mdctx, src, size);
	return 0;
}

int elliptics_transform_openssl::final(void *priv __unused, void *result, void *addr,
		unsigned int *rsize, unsigned int flags __unused)
{
	unsigned char md_value[EVP_MAX_MD_SIZE];
	unsigned int rs = *rsize;

	EVP_DigestFinal_ex(&mdctx, md_value, rsize);
	dnet_transform_final(addr, result, md_value, rsize, rs);

	return 0;
}

void elliptics_transform_openssl::cleanup(void *priv __unused)
{
	EVP_MD_CTX_cleanup(&mdctx);
}

elliptics_transform_openssl::elliptics_transform_openssl(const char *name) :
	elliptics_transform(name)
{
	int err;

 	OpenSSL_add_all_digests();
	EVP_MD_CTX_init(&mdctx);

	evp_md = EVP_get_digestbyname(name);
	if (!evp_md)
		throw -ENOENT;
}

elliptics_transform_openssl::~elliptics_transform_openssl()
{
	EVP_cleanup();
}
