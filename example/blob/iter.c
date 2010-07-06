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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "blob.h"

#ifndef __unused
#define __unused	__attribute__ ((unused))
#endif

int blob_iterate(int fd, int (* callback)(struct blob_disk_control *dc, void *data, off_t position, void *priv), void *priv)
{
	struct blob_disk_control dc;
	void *data, *ptr;
	off_t position;
	struct stat st;
	size_t size;
	int err;

	err = fstat(fd, &st);
	if (err) {
		err = -errno;
		goto err_out_exit;
	}

	size = st.st_size;

	ptr = data = mmap(NULL, size, PROT_READ, MAP_SHARED, fd, 0);
	if (data == MAP_FAILED) {
		err = -errno;
		goto err_out_exit;
	}

	while (size) {
		err = -EINVAL;

		if (size < sizeof(struct blob_disk_control))
			goto err_out_unmap;

		dc = *(struct blob_disk_control *)ptr;
		blob_convert_disk_control(&dc);

		position = ptr - data;

		ptr += sizeof(struct blob_disk_control);
		size -= sizeof(struct blob_disk_control);

		if (size < dc.size)
			goto err_out_unmap;

		ptr += dc.size;
		size -= dc.size;

		err = callback(&dc, ptr - dc.size, position, priv);
		if (err < 0)
			goto err_out_unmap;
	}

	err = 0;

err_out_unmap:
	munmap(data, st.st_size);
err_out_exit:
	return err;
}
