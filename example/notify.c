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

#include "elliptics/packet.h"
#include "elliptics/interface.h"

#include "common.h"

#ifndef __unused
#define __unused	__attribute__ ((unused))
#endif

static struct dnet_log notify_logger;

static int notify_complete(struct dnet_net_state *state,
			struct dnet_cmd *cmd,
			void *priv)
{
	struct dnet_io_notification *io;
	char str[64];
	struct tm tm;
	struct timeval tv;
	FILE *stream = priv;

	if (is_trans_destroyed(state, cmd))
		return 0;

	if (cmd->size != sizeof(struct dnet_io_notification))
		return 0;

	gettimeofday(&tv, NULL);
	localtime_r((time_t *)&tv.tv_sec, &tm);
	strftime(str, sizeof(str), "%F %R:%S", &tm);

	fprintf(stream, "%s.%06lu : ", str, (unsigned long)tv.tv_usec);

	io = (struct dnet_io_notification *)(cmd + 1);

	dnet_convert_io_notification(io);

	fprintf(stream, "%s: client: %s, size: %llu, offset: %llu, flags: %x\n",
			dnet_dump_id_str(io->io.id), dnet_server_convert_dnet_addr(&io->addr.addr),
			(unsigned long long)io->io.size,
			(unsigned long long)io->io.offset, io->io.flags);
	fflush(stream);

	return 0;
}

static void notify_usage(char *p)
{
	fprintf(stderr, "Usage: %s\n"
			" -a addr:port:family  - creates a node with given network address\n"
			" -r addr:port:family  - adds a route to the given node\n"
			" -l log               - log file. Default: disabled\n"
			" -L log               - notifications log. Default: stdout\n"
			" -w timeout           - wait timeout in seconds used to wait for content sync.\n"
			" -m mask              - log events mask\n"
			" -g group_id          - group ID to connect\n"
			" -I id                - request notifications for given ID\n"
	       , p);
}

int main(int argc, char *argv[])
{
	int ch, err, have_remote = 0, i;
	struct dnet_node *n = NULL;
	struct dnet_config cfg, rem;
	int max_id_idx = 1000, id_idx = 0, group_id = 0;
	unsigned char id[max_id_idx][DNET_ID_SIZE];
	char *logfile = "/dev/stderr", *notify_file = "/dev/stdout";
	FILE *log = NULL, *notify;

	memset(&cfg, 0, sizeof(struct dnet_config));

	cfg.sock_type = SOCK_STREAM;
	cfg.proto = IPPROTO_TCP;
	cfg.wait_timeout = 60*60;
	notify_logger.log_mask = DNET_LOG_ERROR | DNET_LOG_INFO;

	memcpy(&rem, &cfg, sizeof(struct dnet_config));

	while ((ch = getopt(argc, argv, "g:m:w:l:I:a:r:h")) != -1) {
		switch (ch) {
			case 'm':
				notify_logger.log_mask = strtoul(optarg, NULL, 0);
				break;
			case 'w':
				cfg.wait_timeout = atoi(optarg);
				break;
			case 'L':
				notify_file = optarg;
				break;
			case 'l':
				logfile = optarg;
				break;
			case 'I':
				if (id_idx < max_id_idx) {
					err = dnet_parse_numeric_id(optarg, id[id_idx]);
					if (err)
						return err;
					id_idx++;
				}
				break;
			case 'g':
				group_id = atoi(optarg);
				break;
			case 'a':
				err = dnet_parse_addr(optarg, &cfg);
				if (err)
					return err;
				break;
			case 'r':
				err = dnet_parse_addr(optarg, &rem);
				if (err)
					return err;
				have_remote = 1;
				break;
			case 'h':
			default:
				notify_usage(argv[0]);
				return -1;
		}
	}

	if (!id_idx) {
		fprintf(stderr, "No ID specified to watch.\n");
		return -EINVAL;
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

	notify_logger.log_private = log;
	notify_logger.log = dnet_common_log;
	cfg.log = &notify_logger;

	notify = fopen(notify_file, "a");
	if (!notify) {
		err = -errno;
		fprintf(stderr, "Failed to open notify file %s: %s.\n", notify_file, strerror(errno));
		return err;
	}

	n = dnet_node_create(&cfg);
	if (!n)
		return -1;

	err = dnet_add_state(n, &rem);
	if (err)
		return err;

	for (i=0; i<id_idx; ++i) {
		struct dnet_id raw;
		dnet_setup_id(&raw, group_id, id[i]);
		err = dnet_request_notification(n, &raw, notify_complete, notify);
	}

	while (1) {
		sleep(1);
	}

	return 0;
}
