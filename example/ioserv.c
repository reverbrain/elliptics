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

#include <ctype.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <netinet/in.h>

#include "dnet/packet.h"
#include "dnet/interface.h"

#include "common.h"

#ifndef __unused
#define __unused	__attribute__ ((unused))
#endif

static void dnet_usage(char *p)
{
	fprintf(stderr, "Usage: %s\n"
			" -c config                - config file\n"
			" -l log                   - log file\n"
			" -h                       - this help\n"
			, p);
}

int main(int argc, char *argv[])
{
	int err, ch;
	char *conf = NULL;
	struct dnet_node *n;

	while ((ch = getopt(argc, argv, "c:h")) != -1) {
		switch (ch) {
			case 'c':
				conf = optarg;
				break;
			case 'h':
			default:
				dnet_usage(argv[0]);
				return -1;
		}
	}

	if (!conf) {
		fprintf(stderr, "No config file provided. Exiting.\n");
		return -1;
	}

	n = dnet_parse_config(conf);
	if (!n)
		return -1;

	while (1)
		sleep(1);

	dnet_node_destroy(n);

	printf("Successfully executed given command.\n");

	return 0;
}

