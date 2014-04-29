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

extern __thread trace_id_t trace_id;

int dnet_log_init(struct dnet_node *n, struct dnet_log *l)
{
	if (!n)
		return -EINVAL;

	n->log = l;

	return 0;
}

static void dnet_log_raw_internal(struct dnet_log *l, int level, const char *format, va_list args) {
	char buf[2048];
	int buflen = sizeof(buf);
	int msg_len = vsnprintf(buf, buflen, format, args);

	if (msg_len < 0) {
		return;
	} else if (msg_len > buflen - 1) {
		msg_len = buflen - 1;
	}

	if (msg_len == buflen - 1) {
		buf[buflen - 2] = '\n';
	} else if (buf[msg_len - 1] != '\n') {
		buf[msg_len] = '\n';
		buf[msg_len + 1] = '\0';
	}
	l->log(l->log_private, level, buf);
}

void dnet_log_raw_log_only(struct dnet_log *l, int level, const char *format, ...) {
	va_list args;

	if (!l->log || ((l->log_level < level) && !(trace_id & DNET_TRACE_BIT)))
		return;

	va_start(args, format);
	dnet_log_raw_internal(l, level, format, args);
	va_end(args);
}

void dnet_log_raw(struct dnet_node *n, int level, const char *format, ...)
{
	va_list args;

	if (!n->log->log || ((n->log->log_level < level) && !(trace_id & DNET_TRACE_BIT)))
		return;

	va_start(args, format);
	dnet_log_raw_internal(n->log, level, format, args);
	va_end(args);
}
