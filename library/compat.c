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

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "elliptics.h"

#ifdef HAVE_SENDFILE4_SUPPORT
#include <sys/sendfile.h>
int dnet_sendfile(struct dnet_net_state *st, int fd, off_t *offset, size_t size)
{
	return sendfile(st->s, fd, offset, size);
}
#elif HAVE_SENDFILE7_SUPPORT
#include <sys/uio.h>
int dnet_sendfile(struct dnet_net_state *st, int fd, off_t *offset, size_t size)
{
	return sendfile(fd, st->s, *offset, size, NULL, NULL, 0);
}
#else
#error "Your platform does not support sendfile. Sorry."
#endif
