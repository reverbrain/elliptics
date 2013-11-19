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

#include <algorithm>

using namespace ioremap::elliptics;

#ifndef __unused
#define __unused	__attribute__ ((unused))
#endif

static struct dnet_log stat_logger;
static int stat_mem, stat_la, stat_fs;
static FILE *stream = NULL;

static void print_stat(const stat_result_entry &result)
{
	dnet_cmd *cmd = result.command();
	dnet_stat *st = result.statistics();

	float la[3];
	char str[64];
	struct tm tm;
	struct timeval tv;

	if (!stat_mem && !stat_la && !stat_fs)
		return;

	gettimeofday(&tv, NULL);
	localtime_r((time_t *)&tv.tv_sec, &tm);
	strftime(str, sizeof(str), "%F %R:%S", &tm);

	fprintf(stream, "%s.%06lu :", str, (unsigned long)tv.tv_usec);

	st = (struct dnet_stat *)(cmd + 1);

	dnet_convert_stat(st);

	la[0] = (float)st->la[0] / 100.0;
	la[1] = (float)st->la[1] / 100.0;
	la[2] = (float)st->la[2] / 100.0;


	fprintf(stream, "%s: %s: ", dnet_dump_id(&cmd->id),
		dnet_server_convert_dnet_addr(result.address()));

	if (stat_la)
		fprintf(stream, "la: %3.2f %3.2f %3.2f ", la[0], la[1], la[2]);

	if (stat_mem)
		fprintf(stream, "mem: total: %8llu kB, free: %8llu kB, cache: %8llu kB, buffers: %8llu, active: %8llu, inactive: %8llu ",
			(unsigned long long)st->vm_total, (unsigned long long)st->vm_free,
			(unsigned long long)st->vm_cached, (unsigned long long)st->vm_buffers,
			(unsigned long long)st->vm_active, (unsigned long long)st->vm_inactive);

	if (stat_fs)
		fprintf(stream, "fs: total: %8llu mB, avail: %8llu/%8llu mB ",
			(unsigned long long)(st->frsize * st->blocks / 1024 / 1024),
			(unsigned long long)(st->bavail * st->bsize / 1024 / 1024),
			(unsigned long long)(st->bfree * st->bsize / 1024 / 1024));

	fprintf(stream, "\n");
	fflush(stream);
}

static void stat_usage(char *p)
{
	fprintf(stderr, "Usage: %s\n"
			" -r addr:port:family  - adds a route to the given node\n"
			" -l log               - log file. Default: disabled\n"
			" -L log               - statistics log. Default: stdout\n"
			" -w timeout           - wait timeout in seconds used to wait for content sync.\n"
			" -m level             - log level\n"
			" -I id                - request statistics from node which handles given id\n"
			" -t timeout           - timeout in seconds to repeatedly request statistics\n"
			" -M                   - show memory usage statistics\n"
			" -F                   - show filesystem usage statistics\n"
			" -A                   - show load average statistics\n"
	       , p);
}

int main(int argc, char *argv[])
{
	int ch, err, i;
	struct dnet_config cfg;
	char *remote_addr = NULL;
	int remote_port, remote_family;
	int max_id_idx = 1000, id_idx = 0;
	int timeout;
	unsigned char id[max_id_idx][DNET_ID_SIZE];
	const char *logfile = "/dev/stderr";
	const char *statfile = "/dev/stdout";
	int group = -1;

	memset(&cfg, 0, sizeof(struct dnet_config));

	cfg.wait_timeout = 60*60;

	timeout = 1;

	while ((ch = getopt(argc, argv, "g:MFAt:m:w:l:I:r:h")) != -1) {
		switch (ch) {
			case 'g':
				group = atoi(optarg);
				break;
			case 'M':
				stat_mem = 1;
				break;
			case 'F':
				stat_fs = 1;
				break;
			case 'A':
				stat_la = 1;
				break;
			case 't':
				timeout = atoi(optarg);
				break;
			case 'm':
				stat_logger.log_level = strtoul(optarg, NULL, 0);
				break;
			case 'w':
				cfg.wait_timeout = atoi(optarg);
				break;
			case 'L':
				statfile = optarg;
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
			case 'r':
				err = dnet_parse_addr(optarg, &remote_port, &remote_family);
				if (err)
					return err;
				remote_addr = optarg;
				break;
			case 'h':
			default:
				stat_usage(argv[0]);
				return -1;
		}
	}

	if (!remote_addr) {
		fprintf(stderr, "No remote node specified to route requests.\n");
		return -ENOENT;
	}

	stream = fopen(statfile, "a");
	if (!stream) {
		err = -errno;
		fprintf(stderr, "Failed to open stat file %s: %s.\n", statfile, strerror(errno));
		return err;
	}

	try {
		file_logger log(logfile, DNET_LOG_ERROR);
		node n(log, cfg);
		session sess(n);
		sess.set_timeout(timeout);

		n.add_remote(remote_addr, remote_port, remote_family);

		for (;;) {
			struct dnet_id raw;

			if (!id_idx) {
				auto result = sess.stat_log();
				std::for_each(result.begin(), result.end(), print_stat);
			} else {
				if (group != -1) {
					for (i = 0; i < id_idx; ++i) {
						dnet_setup_id(&raw, group, id[i]);
						sess.stat_log(raw).connect(print_stat, async_stat_result::final_function());
					}
				} else {
					std::cerr << "If you provide list of IDs you have to specify group number" << std::endl;
					return -1;
				}
			}

			sleep(timeout);
		}
	} catch (const std::exception &e) {
		std::cerr << e.what() << std::endl;
	}

	return 0;
}
