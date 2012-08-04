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
#include <sys/mman.h>

#include <ctype.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "elliptics/packet.h"
#include "elliptics/interface.h"

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
			" -d                   - history database to parse\n"
			" -o offset            - offset of the region to highlight\n"
			" -s size              - size of the region to highlight\n"
			" -h                   - this help\n");
	exit(-1);
}

static void hparser_dump_history(struct dnet_history_map *m, unsigned long long offset,
				unsigned long long size)
{
	long i;
	struct tm tm;
	char str[64];
	char id_str[DNET_ID_SIZE*2 + 1];

	for (i=m->num-1; i>=0; --i) {
		struct dnet_history_entry e = m->ent[i];
		time_t t;

		dnet_convert_history_entry(&e);

		t = e.tsec;
		localtime_r(&t, &tm);
		strftime(str, sizeof(str), "%F %R:%S", &tm);

		printf("%s.%09llu: %s: flags: %08x [removed: %s], offset: %8llu, size: %8llu: %c\n",
			str, (unsigned long long)e.tnsec,
			dnet_dump_id_len_raw(e.id, DNET_ID_SIZE, id_str), e.flags,
			(e.flags & DNET_IO_FLAGS_REMOVED) ? "yes" : "no",
			(unsigned long long)e.offset, (unsigned long long)e.size,
			hparser_region_match(&e, offset, size) ? '+' : '-');
	}
	return;
}

int main(int argc, char *argv[])
{
	struct dnet_history_map m;
	int err, ch;
	char *file = NULL, *database = NULL;
	unsigned long long offset, size;

	size = offset = 0;

	while ((ch = getopt(argc, argv, "s:o:f:d:h")) != -1) {
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
			case 'd':
				database = optarg;
				break;
			case 'h':
				hparser_usage(argv[0]);
		}
	}

	if (!file && !database) {
		fprintf(stderr, "You have to provide history file or database to parse.\n");
		hparser_usage(argv[0]);
	}

	if (file) {
		err = dnet_map_history(NULL, file, &m);
		if (err) {
			fprintf(stderr, "Failed to map history file '%s': %d.\n", file, err);
			goto err_out_exit;
		}

		printf("%s: objects: %ld, range: %llu-%llu, counting from the most recent (nanoseconds resolution).\n",
			file, m.num, offset, offset+size);

		hparser_dump_history(&m, offset, size);

		dnet_unmap_history(NULL, &m);
	}

	if (database) {
		printf("not yet supported\n");
	}

err_out_exit:
	return err;
}
