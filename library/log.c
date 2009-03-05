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

static FILE *dnet_log_stream;

void uloga(const char *f, ...)
{
	va_list ap;

	if (!dnet_log_stream)
		dnet_log_stream = stdout;

	va_start(ap, f);
	vfprintf(dnet_log_stream, f, ap);
	va_end(ap);

	fflush(dnet_log_stream);
}

void ulog(const char *f, ...)
{
	char str[64];
	struct tm tm;
	struct timeval tv;
	va_list ap;

	if (!dnet_log_stream)
		dnet_log_stream = stdout;

	gettimeofday(&tv, NULL);
	localtime_r((time_t *)&tv.tv_sec, &tm);
	strftime(str, sizeof(str), "%F %R:%S", &tm);

	fprintf(dnet_log_stream, "%s.%06lu %6ld ", str, tv.tv_usec, syscall(__NR_gettid));

	va_start(ap, f);
	vfprintf(dnet_log_stream, f, ap);
	va_end(ap);

	fflush(dnet_log_stream);
}

int ulog_init(char *log)
{
	FILE *f;

	f = fopen(log, "a");
	if (!f) {
		ulog_err("Failed to open log file %s", log);
		return -errno;
	}

	dnet_log_stream = f;

	ulog("Logging has been started.\n");
	return 0;
}
