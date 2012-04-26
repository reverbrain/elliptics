/*
 * 2011+ Copyright (c) Evgeniy Polyakov <zbr@ioremap.net>
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
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <netinet/in.h>

#include "elliptics/packet.h"
#include "elliptics/interface.h"

/*
 *
 * THIS IS REALLY BAD IDEA !!11
 * DO NOT DO THIS
 *
 */
#include "../library/elliptics.h"


#include "backends.h"
#include "common.h"

#ifndef __unused
#define __unused	__attribute__ ((unused))
#endif

static struct dnet_log meta_logger;

static void meta_usage(char *p)
{
	fprintf(stderr, "Usage: %s <options>\n"
			"  -I id                  - use this ID to get metadata\n"
			"  -n name                - use this name to get metadata\n"
			"  -g group:group...      - groups to get matadata from\n"
			"  -w timeout             - wait timeout in seconds\n"
			"  -r addr:port:family    - connect to this remote node\n"
			"  -m mask                - log mask\n"
			"  -l log                 - log file\n"
			"  -f file                - read metadata from file\n"
			, p);
	exit(-1);
}

int main(int argc, char *argv[])
{
	int ch, err, fd = -1;
	char *logfile = "/dev/stderr";
	char *name = NULL;
	FILE *log;
	int *groups, group_num = 0;
	unsigned char trans_id[DNET_ID_SIZE], *id = NULL;
	struct dnet_config cfg, rem;
	struct dnet_node *n;
	struct dnet_id raw;
	struct dnet_meta_container mc;

	memset(&mc, 0, sizeof(mc));
	memset(&cfg, 0, sizeof(cfg));

	cfg.sock_type = SOCK_STREAM;
	cfg.proto = IPPROTO_TCP;
	cfg.wait_timeout = 10;
	meta_logger.log_mask = DNET_LOG_ERROR | DNET_LOG_DATA;

	memcpy(&rem, &cfg, sizeof(struct dnet_config));

	while ((ch = getopt(argc, argv, "f:N:g:w:I:n:r:m:l:h")) != -1) {
		switch (ch) {
			case 'f':
				fd = open(optarg, O_RDONLY | O_CLOEXEC);
				if (fd < 0) {
					fprintf(stderr, "Could not open file '%s': %s\n", optarg, strerror(errno));
					return -errno;
				}
			case 'N':
				cfg.ns = optarg;
				cfg.nsize = strlen(optarg);
				break;
			case 'r':
				err = dnet_parse_addr(optarg, &rem);
				if (err)
					return err;
				break;
			case 'w':
				cfg.wait_timeout = atoi(optarg);
				break;
			case 'l':
				logfile = optarg;
				break;
			case 'm':
				meta_logger.log_mask = strtoul(optarg, NULL, 0);
				break;
			case 'I':
				err = dnet_parse_numeric_id(optarg, trans_id);
				if (err)
					return err;
				id = trans_id;
				break;
			case 'g':
				group_num = dnet_parse_groups(optarg, &groups);
				if (group_num <= 0)
					return -1;
				break;
			case 'n':
				name = optarg;
				break;
			case 'h':
			default:
				meta_usage(argv[0]);
				/* not reached */
		}
	}

	if (!name && !id) {
		fprintf(stderr, "You must specify name or id\n");
		meta_usage(argv[0]);
	}

	if (id && group_num <= 0) {
		fprintf(stderr, "You must specify groups\n");
		meta_usage(argv[0]);
	}

	log = fopen(logfile, "a");
	if (!log) {
		err = -errno;
		fprintf(stderr, "Failed to open log file %s: %s.\n", logfile, strerror(-err));
		goto err_out_exit;
	}

	meta_logger.log_private = log;
	meta_logger.log = dnet_common_log;
	cfg.log = &meta_logger;

	n = dnet_node_create(&cfg);
	if (!n) {
		err = -EINVAL;
		goto err_out_exit;
	}

	if (fd == -1) {
		err = dnet_add_state(n, &rem);
		if (err)
			goto err_out_destroy;

		dnet_node_set_groups(n, groups, group_num);

		if (id) {
			int i;

			for (i=0; i<group_num; ++i) {
				dnet_setup_id(&raw, groups[i], id);
				err = dnet_read_meta(n, &mc, NULL, 0, &raw);
				if (!err)
					dnet_meta_print(n, &mc);
				else
					dnet_log_raw(n, DNET_LOG_ERROR, "%s: could not read metadata\n", dnet_dump_id(&raw));
			}
		} else {
			err = dnet_read_meta(n, &mc, name, strlen(name), NULL);
			if (!err)
				dnet_meta_print(n, &mc);
		}
	} else {
		struct stat st;
		struct dnet_map_fd m;

		fstat(fd, &st);

		memset(&m, 0, sizeof(m));
		m.size = st.st_size - 96;
		m.offset = 96;
		m.fd = fd;

		err = dnet_data_map(&m);
		if (err) {
			dnet_log_raw(n, DNET_LOG_ERROR, "Could not map metadata: %s\n", strerror(-err));
			goto err_out_destroy;
		}

		mc.size = m.size;
		mc.data = m.data;

		dnet_meta_print(n, &mc);

		dnet_data_unmap(&m);
	}

err_out_destroy:
	dnet_node_destroy(n);
err_out_exit:
	return err;
}
