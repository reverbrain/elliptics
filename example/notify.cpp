/*
 * 2008+ Copyright (c) Evgeniy Polyakov <zbr@ioremap.net>
 * All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
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
#include <iostream>

#include <netinet/in.h>

#include "elliptics/cppdef.h"

#include "common.h"

using namespace ioremap::elliptics;

#ifndef __unused
#define __unused	__attribute__ ((unused))
#endif

static int notify_complete(struct dnet_addr *addr __unused,
			struct dnet_cmd *cmd,
			void *priv)
{
	struct dnet_io_notification *io;
	char str[64];
	struct tm tm;
	struct timeval tv;
	FILE *stream = reinterpret_cast<FILE*>(priv);

	if (is_trans_destroyed(cmd))
		return 0;

	if (cmd->size != sizeof(struct dnet_io_notification))
		return 0;

	gettimeofday(&tv, NULL);
	localtime_r((time_t *)&tv.tv_sec, &tm);
	strftime(str, sizeof(str), "%F %R:%S", &tm);

	fprintf(stream, "%s.%06lu : ", str, (unsigned long)tv.tv_usec);

	io = (struct dnet_io_notification *)(cmd + 1);

	dnet_convert_io_notification(io);

	fprintf(stream, "%s: client: %s, %s\n",
			dnet_dump_id_str(io->io.id), dnet_addr_string(&io->addr),
			dnet_print_io(&io->io));
	fflush(stream);

	return 0;
}

static void notify_usage(char *p)
{
	fprintf(stderr, "Usage: %s\n"
			" -r addr:port:family  - adds a route to the given node\n"
			" -l log               - log file. Default: disabled\n"
			" -L log               - notifications log. Default: stdout\n"
			" -w timeout           - wait timeout in seconds used to wait for content sync.\n"
			" -m level             - log level\n"
			" -g group_id          - group ID to connect\n"
			" -I id                - request notifications for given ID\n"
	       , p);
}

int main(int argc, char *argv[])
{
	int ch, err, i;
	struct dnet_config cfg;
	char *remote_addr = NULL;
	int remote_port, remote_family;
	int max_id_idx = 1000, id_idx = 0;
	unsigned char id[max_id_idx][DNET_ID_SIZE];
	const char *logfile = "/dev/stderr", *notify_file = "/dev/stdout";
	FILE *notify;
	std::vector<int> groups;
	dnet_log_level log_level = DNET_LOG_INFO;

	memset(&cfg, 0, sizeof(struct dnet_config));

	cfg.wait_timeout = 60*60;

	while ((ch = getopt(argc, argv, "g:m:w:l:I:a:r:h")) != -1) {
		switch (ch) {
			case 'm':
				try {
					log_level = file_logger::parse_level(optarg);
				} catch (std::exception &exc) {
					std::cerr << exc.what() << std::endl;
					return -1;
				}
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
			case 'g': {
				int *groups_tmp = NULL, group_num = 0;
				group_num = dnet_parse_groups(optarg, &groups_tmp);
				if (group_num <= 0)
					return -1;
				groups.assign(groups_tmp, groups_tmp + group_num);
				free(groups_tmp);
				break;
			}
			case 'r':
				err = dnet_parse_addr(optarg, &remote_port, &remote_family);
				if (err)
					return err;
				remote_addr = optarg;
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

	if (!remote_addr) {
		fprintf(stderr, "No remote node specified to route requests.\n");
		return -ENOENT;
	}

	try {
		file_logger log(logfile, log_level);

		node n(logger(log, blackhole::log::attributes_t()), cfg);
		n.add_remote(address(remote_addr, remote_port, remote_family));

		session s(n);

		s.set_groups(groups);

		notify = fopen(notify_file, "a");
		if (!notify) {
			err = -errno;
			fprintf(stderr, "Failed to open notify file %s: %s.\n", notify_file, strerror(errno));
			return err;
		}

		for (i = 0; i < id_idx; ++i) {
			for (size_t j = 0; j < groups.size(); ++j) {
				struct dnet_id raw;
				dnet_setup_id(&raw, groups[j], id[i]);
				err = dnet_request_notification(s.get_native(), &raw, notify_complete, notify);
				if (err)
					fprintf(stderr, "Failed to request notification: %d %s.\n", err, strerror(-err));
			}
		}

		while (1) {
			sleep(1);
		}
	} catch (const std::exception &e) {
		std::cerr << e.what() << std::endl;
	}

	return 0;
}
