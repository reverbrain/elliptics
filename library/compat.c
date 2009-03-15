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

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <sys/wait.h>

#include <alloca.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "elliptics.h"

#ifdef HAVE_AT_SYSCALLS
int dnet_mkdirat(struct dnet_node *n, char *path, mode_t mode)
{
	return mkdirat(n->rootfd, path, mode);
}

int dnet_renameat(struct dnet_node *n, char *opath, char *npath)
{
	return renameat(n->rootfd, opath, n->rootfd, npath);
}
#else
int dnet_mkdirat(struct dnet_node *n, char *path, mode_t mode)
{
	int len = strlen(path) + n->root_len + 2; // '/' and null-byte
	char *npath = alloca(len);

	if (!npath)
		return -ENOMEM;

	snprintf(npath, len, "%s/%s", n->root, path);
	return mkdir(npath, mode);
}

int dnet_renameat(struct dnet_node *n, char *opath, char *npath)
{
	int olen = strlen(opath) + n->root_len + 2;
	int nlen = strlen(npath) + n->root_len + 2;
	char *op, *np, *path;

	path = alloca(olen + nlen);
	if (!path)
		return -ENOMEM;

	op = path;
	np = op + snprintf(op, olen, "%s/%s", n->root, opath);
	snprintf(np, nlen, "%s/%s", n->root, npath);

	return rename(op, np);
}
#endif
