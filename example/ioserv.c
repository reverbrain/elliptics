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
#include <sys/wait.h>

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

static void dnet_usage(char *p)
{
	fprintf(stderr, "Usage: %s\n"
			" -c config                - config file\n"
			" -m                       - run under internal monitor\n"
			" -l log                   - log file\n"
			" -h                       - this help\n"
			, p);
}

static int ioserv_monitor(void)
{
	pid_t pid;

	pid = fork();
	if (pid == -1) {
		fprintf(stderr, "Failed to fork to background: %s.\n", strerror(errno));
		exit(pid);
	}

	if (pid != 0) {
		printf("Children pid: %d\n", pid);
		return pid;
	}
	setsid();

#if 0
	close(0);
	close(1);
	close(2);
#endif
	return 0;
}

static int ioserv_start(char *conf, int mon)
{
	struct dnet_node *n;

	n = dnet_parse_config(conf, mon);
	if (!n)
		return -1;

	while (!dnet_need_exit(n))
		sleep(1);

	dnet_node_destroy(n);
	return 0;
}

int main(int argc, char *argv[])
{
	int ch, mon = 0, err;
	char *conf = NULL;

	while ((ch = getopt(argc, argv, "mc:h")) != -1) {
		switch (ch) {
			case 'm':
				mon = 1;
				break;
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

	if (mon) {
#if 0
		err = ioserv_monitor();
		if (err > 0)
			exit();
#endif
		while (1) {
			err = ioserv_monitor();
			if (err > 0) {
				int status;

				waitpid(err, &status, 0);

				err = WEXITSTATUS(status);
				fprintf(stderr, "child exited with status: %d\n", err);
				if (WIFEXITED(status)) {
					printf("exited, status=%d\n", WEXITSTATUS(status));
				} else if (WIFSIGNALED(status)) {
					printf("killed by signal %d\n", WTERMSIG(status));
				} else if (WIFSTOPPED(status)) {
					printf("stopped by signal %d\n", WSTOPSIG(status));
				} else if (WIFCONTINUED(status)) {
					printf("continued\n");
				}
			} else {
				exit(ioserv_start(conf, mon));
			}

			sleep(1);
		}
	} else {
		ioserv_start(conf, mon);
	}

	return 0;
}

