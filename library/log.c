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

int dnet_log_init(struct dnet_node *n, struct dnet_log *l)
{
	if (!n)
		return -EINVAL;

	n->log = l;

	return 0;
}

void dnet_log_raw(struct dnet_node *n, int level, uint32_t trace_id, const char *format, ...)
{
	level = trace_id != 0 ? DNET_LOG_ERROR : level;

	va_list args;
	char buf[1024];
	struct dnet_log *l = n->log;
	int buflen = sizeof(buf);

	if (!l->log || (l->log_level < level))
		return;

	va_start(args, format);
	vsnprintf(buf, buflen, format, args);
	buf[buflen-1] = '\0';
	l->log(l->log_private, level, trace_id, buf);
	va_end(args);
}
