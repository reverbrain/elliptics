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

#include "common.h"

static int hparser_region_match(struct dnet_history_entry *e,
		unsigned long long offset, unsigned long long size)
{
	if ((e->offset > offset) && (e->offset < offset + size))
		return 1;

	if ((e->offset < offset) && (e->offset + e->size > offset))
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
	struct dnet_history_map m;
	long i;
	int err, ch;
	char *file = NULL;
	unsigned long long offset, size;
	char str[64];
	struct tm tm;

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

	err = dnet_map_history(NULL, file, &m);
	if (err) {
		fprintf(stderr, "Failed to map history file '%s': %d.\n", file, err);
		goto err_out_exit;
	}

	printf("%s: objects: %ld, range: %llu-%llu, counting from the most recent (nanoseconds resolution).\n",
			file, m.num, offset, offset+size);

	for (i=m.num-1; i>=0; --i) {
		struct dnet_history_entry e = m.ent[i];
		time_t t;
		int version = -1;

		dnet_convert_history_entry(&e);

		t = e.tsec;
		localtime_r(&t, &tm);
		strftime(str, sizeof(str), "%F %R:%S", &tm);

		if (e.flags & DNET_IO_FLAGS_ID_VERSION)
			version = dnet_common_get_version(e.id);

		printf("%s.%09llu: %s: flags: %08x [P: %d, C: %d, V: %d, version: %d, R: %d], offset: %8llu, size: %8llu: %c\n",
			str, (unsigned long long)e.tnsec,
			dnet_dump_id_len(e.id, DNET_ID_SIZE), e.flags,
			!!(e.flags & DNET_IO_FLAGS_PARENT),
			!!(e.flags & DNET_IO_FLAGS_ID_CONTENT),
			!!(e.flags & DNET_IO_FLAGS_ID_VERSION), version,
			!!(e.flags & DNET_IO_FLAGS_REMOVED),
			(unsigned long long)e.offset, (unsigned long long)e.size,
			hparser_region_match(&e, offset, size) ? '+' : '-');
	}

	dnet_unmap_history(NULL, &m);

err_out_exit:
	return err;
}
