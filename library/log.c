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
#include <sys/time.h>

#include <sys/syscall.h>

#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

#include "elliptics.h"

int dnet_log_init(struct dnet_node *n, void *priv,
		void (* log)(void *priv, const char *f, ...),
		void (* log_append)(void *priv, const char *f, ...))
{
	if (!n)
		return -EINVAL;

	n->log_priv = priv;
	n->log = log;
	n->log_append = log_append;

	return 0;
}
