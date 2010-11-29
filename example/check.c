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
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <netinet/in.h>

#include "elliptics/packet.h"
#include "elliptics/interface.h"

#include "common.h"

#ifndef __unused
#define __unused	__attribute__ ((unused))
#endif

static struct dnet_log check_logger;

static void check_usage(char *p)
{
	fprintf(stderr, "Usage: %s\n"
			" -r addr:port:family  - adds remote node\n"
			" -l log               - log file. Default: disabled\n"
			" -w timeout           - wait timeout in seconds used to wait for content sync.\n"
			" -m mask              - log events mask\n"
			" -h                   - this help\n"
	       , p);
}

int main(int argc, char *argv[])
{
	int ch, err, have_remote = 0;
	struct dnet_node *n = NULL;
	struct dnet_config cfg, rem;
	char *logfile = "/dev/stderr";
	FILE *log = NULL;

	memset(&cfg, 0, sizeof(struct dnet_config));

	cfg.sock_type = SOCK_STREAM;
	cfg.proto = IPPROTO_TCP;
	cfg.wait_timeout = 60*60;
	check_logger.log_mask = DNET_LOG_ERROR | DNET_LOG_INFO;
	cfg.check_timeout = 60;

	memcpy(&rem, &cfg, sizeof(struct dnet_config));

	while ((ch = getopt(argc, argv, "m:w:l:r:h")) != -1) {
		switch (ch) {
			case 'm':
				check_logger.log_mask = strtoul(optarg, NULL, 0);
				break;
			case 'w':
				cfg.wait_timeout = atoi(optarg);
				break;
			case 'l':
				logfile = optarg;
				break;
			case 'r':
				err = dnet_parse_addr(optarg, &rem);
				if (err)
					return err;
				have_remote = 1;
				break;
			case 'h':
			default:
				check_usage(argv[0]);
				return -1;
		}
	}

	if (!have_remote) {
		fprintf(stderr, "No remote node specified to route requests.\n");
		return -ENOENT;
	}

	log = fopen(logfile, "a");
	if (!log) {
		err = -errno;
		fprintf(stderr, "Failed to open log file %s: %s.\n", logfile, strerror(errno));
		return err;
	}

	check_logger.log_private = log;
	check_logger.log = dnet_common_log;
	cfg.log = &check_logger;

	n = dnet_node_create(&cfg);
	if (!n)
		return -1;

	rem.join = DNET_NO_ROUTE_LIST;
	err = dnet_add_state(n, &rem);
	if (err)
		return err;

	return dnet_request_check(n);
}
