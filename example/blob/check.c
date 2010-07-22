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
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <strings.h>

#include "elliptics/packet.h"
#include "elliptics/interface.h"
#include "blob.h"

#ifndef __unused
#define __unused	__attribute__ ((unused))
#endif

static int blob_check_iterator(struct blob_disk_control *dc, void *data __unused, off_t position, void *priv __unused)
{
	char id[DNET_ID_SIZE*2+1];

	printf("%s: position: %llu (0x%llx), data position: %llu (0x%llx), data size: %llu, disk size: %llu, flags: %llx.\n",
			dnet_dump_id_len_raw(dc->id, DNET_ID_SIZE, id),
			(unsigned long long)position, (unsigned long long)position,
			(unsigned long long)dc->position, (unsigned long long)dc->position,
			(unsigned long long)dc->data_size, (unsigned long long)dc->disk_size,
			(unsigned long long)dc->flags);

	return 0;
}

int main(int argc, char *argv[])
{
	int i, err, fd;
	char *file;

	for (i=1; i<argc; ++i) {
		file = argv[i];

		fd = open(file, O_RDONLY);
		if (fd < 0) {
			err = -errno;
			fprintf(stderr, "Failed to open file '%s': %s.\n",
					file, strerror(errno));
			continue;
		}

		printf("%s\n", file);
		err = blob_iterate(fd, 0, 0, NULL, blob_check_iterator, NULL);
	}

	return 0;
}
