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

#include <errno.h>
#include <ctype.h>
#include <dirent.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "elliptics/interface.h"
#include "backends.h"
#include "blob.h"

#ifndef __unused
#define __unused	__attribute__ ((unused))
#endif

void blob_iterate_low_level_log(void *priv, uint32_t mask, const char *msg)
{
	char str[64];
	struct tm tm;
	struct timeval tv;
	FILE *stream = priv;

	if (!stream)
		stream = stdout;

	gettimeofday(&tv, NULL);
	localtime_r((time_t *)&tv.tv_sec, &tm);
	strftime(str, sizeof(str), "%F %R:%S", &tm);

	fprintf(stream, "%s.%06lu %1x: %s", str, tv.tv_usec, mask, msg);
	fflush(stream);
}

static void blob_iterate_log_raw(struct dnet_log *l, uint32_t mask, const char *format, ...)
{
	va_list args;
	char buf[1024];
	int buflen = sizeof(buf);

	va_start(args, format);
	vsnprintf(buf, buflen, format, args);
	buf[buflen-1] = '\0';
	l->log(l->log_private, mask, buf);
	va_end(args);
}

#define blob_iterate_log(l, mask, format, a...)			\
	do {								\
		if (mask & (l)->log_mask)					\
			blob_iterate_log_raw((l), mask, format, ##a); 	\
	} while (0)

int blob_iterate(int fd, struct dnet_log *l,
		int (* callback)(struct blob_disk_control *dc, void *data, off_t position, void *priv),
		void *priv)

{
	struct blob_disk_control dc;
	struct dnet_log log;
	void *data, *ptr;
	off_t position;
	struct stat st;
	size_t size;
	int err;

	if (!l) {
		log.log = blob_iterate_low_level_log;
		log.log_mask = DNET_LOG_ERROR | DNET_LOG_INFO;
		log.log_private = NULL;

		l = &log;
	}

	err = fstat(fd, &st);
	if (err) {
		err = -errno;
		blob_iterate_log(l, DNET_LOG_ERROR, "blob: failed to stat file: %s.\n", strerror(errno));
		goto err_out_exit;
	}

	size = st.st_size;

	if (!size) {
		err = 0;
		goto err_out_exit;
	}

	ptr = data = mmap(NULL, size, PROT_READ, MAP_SHARED, fd, 0);
	if (data == MAP_FAILED) {
		err = -errno;
		blob_iterate_log(l, DNET_LOG_ERROR, "blob: failed to mmap file, size: %zu: %s.\n", strerror(errno));
		goto err_out_exit;
	}

	while (size) {
		err = -EINVAL;

		if (size < sizeof(struct blob_disk_control)) {
			blob_iterate_log(l, DNET_LOG_ERROR, "blob: iteration fails: size (%zu) is less than disk control struct (%zu).\n",
					size, sizeof(struct blob_disk_control));
			goto err_out_unmap;
		}

		dc = *(struct blob_disk_control *)ptr;
		blob_convert_disk_control(&dc);

		position = ptr - data;

		if (size < dc.disk_size) {
			blob_iterate_log(l, DNET_LOG_ERROR, "blob: iteration fails: size (%zu) is less than on-disk specified size (%llu).\n",
					size, (unsigned long long)dc.disk_size);
			goto err_out_unmap;
		}

		err = callback(&dc, ptr + sizeof(struct blob_disk_control), position, priv);
		if (err < 0) {
			blob_iterate_log(l, DNET_LOG_ERROR, "blob: iteration callback fails: data size: %llu, disk size: %llu, position: %llu, err: %d.\n",
					(unsigned long long)dc.data_size, (unsigned long long)dc.disk_size, position, err);
			goto err_out_unmap;
		}

		ptr += dc.disk_size;
		size -= dc.disk_size;
	}

	err = 0;

err_out_unmap:
	munmap(data, st.st_size);
err_out_exit:
	return err;
}
