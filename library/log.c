/*
 * Copyright 2008+ Evgeniy Polyakov <zbr@ioremap.net>
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

int dnet_log_init(struct dnet_node *n, dnet_logger *l)
{
	if (!n)
		return -EINVAL;

	n->log = l;

	return 0;
}

static void dnet_log_raw_internal(dnet_logger *l, int level, const char *format, va_list args) {
	DNET_LOG_BEGIN_ONLY_LOG(l, (enum dnet_log_level)level);
	DNET_LOG_VPRINT(format, args);
	DNET_LOG_END();
}

void dnet_log_raw_log_only(dnet_logger *l, int level, const char *format, ...) {
	va_list args;

	va_start(args, format);
	dnet_log_raw_internal(l, level, format, args);
	va_end(args);
}

void dnet_log_raw(struct dnet_node *n, int level, const char *format, ...)
{
	va_list args;

	va_start(args, format);
	dnet_log_raw_internal(n->log, level, format, args);
	va_end(args);
}
