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
#include <sys/mman.h>

#include <ctype.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "dnet/packet.h"
#include "dnet/interface.h"

static int hparser_region_match(struct dnet_io_attr *io,
		unsigned long long offset, unsigned long long size)
{
	if ((io->offset > offset) && (io->offset < offset + size))
		return 1;

	if ((io->offset < offset) && (io->offset + io->size > offset))
		return 1;

	return 0;
}

static void hparser_usage(const char *p)
{
	fprintf(stderr, "Usage: %s args\n", p);
	fprintf(stderr, " -f file              - history file to parse\n"
			" -o offset            - offset of the region to highlight\n"
			" -s size              - size of the region to highlight\n"
			" -h                   - this help\n");
	exit(-1);
}

int main(int argc, char *argv[])
{
	struct dnet_io_attr *ios;
	ssize_t i, num;
	int err, fd, ch;
	char *file = NULL;
	void *data;
	struct stat st;
	unsigned long long offset, size;

	size = offset = 0;

	while ((ch = getopt(argc, argv, "s:o:f:h")) != -1) {
		switch (ch) {
			case 's':
				size = strtoull(optarg, NULL, 0);
				break;
			case 'o':
				offset = strtoull(optarg, NULL, 0);
				break;
			case 'f':
				file = optarg;
				break;
			case 'h':
				hparser_usage(argv[0]);
		}
	}

	if (!file) {
		fprintf(stderr, "You have to provide history file to parse.\n");
		hparser_usage(argv[0]);
	}

	fd = open(file, O_RDONLY);
	if (fd < 0) {
		err = -errno;
		fprintf(stderr, "Failed to open history file '%s': %s [%d].\n",
				file, strerror(errno), errno);
		goto err_out_exit;
	}

	err = fstat(fd, &st);
	if (err) {
		err = -errno;
		fprintf(stderr, "Failed to stat history file '%s': %s [%d].\n",
				file, strerror(errno), errno);
		goto err_out_close;
	}

	if (!st.st_size || (st.st_size % sizeof(struct dnet_io_attr))) {
		fprintf(stderr, "Corrupted history file '%s', its size %llu has to be modulo of %zu.\n",
				file, (unsigned long long)st.st_size, sizeof(struct dnet_io_attr));
		err = -EINVAL;
		goto err_out_close;
	}

	data = mmap(NULL, st.st_size, PROT_READ, MAP_SHARED, fd, 0);
	if (data == MAP_FAILED) {
		err = -errno;
		fprintf(stderr, "Failed to map history file '%s': %s [%d]",
				file, strerror(errno), errno);
		goto err_out_close;
	}

	ios = data;
	num = st.st_size / sizeof(struct dnet_io_attr);

	printf("%s: objects: %zd, range: %llu-%llu, counting from the most recent.\n",
			file, num, offset, offset+size);
	for (i=num-1; i>=0; --i) {
		struct dnet_io_attr io = ios[i];

		dnet_convert_io_attr(&io);

		printf("%s: flags: %08x, offset: %8llu, size: %8llu: %c\n",
			dnet_dump_id(io.id), io.flags,
			(unsigned long long)io.offset, (unsigned long long)io.size,
			hparser_region_match(&io, offset, size) ? '+' : '-');
	}

	munmap(data, st.st_size);
	close(fd);

	return 0;

err_out_close:
	close(fd);
err_out_exit:
	return err;
}
