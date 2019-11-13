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
#include <sys/wait.h>

#include <ctype.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
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

static struct dnet_node *global_n;
static void ioserv_destroy_handler(int sig __unused, siginfo_t *si __unused, void *uc __unused)
{
	dnet_set_need_exit(global_n);
}

extern int dnet_node_reset_log(struct dnet_node *n);

static void ioserv_reload_handler(int sig __unused, siginfo_t *si __unused, void *uc __unused)
{
	dnet_node_reset_log(global_n);
}

static void ioserv_sigchild_handler(int sig __unused, siginfo_t *si __unused, void *uc __unused)
{
	int status, pid;

	while ((pid = waitpid(-1, &status, WNOHANG)) > 0) {
	}
}

static int ioserv_setup_signals(void)
{
	struct sigaction sa;

	memset(&sa, 0, sizeof(sa));
	sa.sa_flags = SA_SIGINFO;
	sa.sa_sigaction = ioserv_destroy_handler;
	sigemptyset(&sa.sa_mask);
	sigaction(SIGTERM, &sa, NULL);
	sigaction(SIGINT, &sa, NULL);

	sa.sa_sigaction = ioserv_reload_handler;
	sigemptyset(&sa.sa_mask);
	sigaction(SIGHUP, &sa, NULL);

	sa.sa_sigaction = ioserv_sigchild_handler;
	sigemptyset(&sa.sa_mask);
	sigaction(SIGCHLD, &sa, NULL);

	signal(SIGTSTP, SIG_DFL);
	signal(SIGQUIT, SIG_DFL);

	sigemptyset(&sa.sa_mask);
	sigaddset(&sa.sa_mask, SIGTERM);
	sigaddset(&sa.sa_mask, SIGINT);
	sigaddset(&sa.sa_mask, SIGHUP);
	sigaddset(&sa.sa_mask, SIGCHLD);
	sigaddset(&sa.sa_mask, SIGTSTP);
	sigaddset(&sa.sa_mask, SIGQUIT);
	pthread_sigmask(SIG_UNBLOCK, &sa.sa_mask, NULL);
	sigprocmask(SIG_UNBLOCK, &sa.sa_mask, NULL);

	return 0;
}

static int ioserv_start(char *conf, int mon)
{
	struct dnet_node *n;

	n = dnet_parse_config(conf, mon);
	if (!n)
		return -EINVAL;

	global_n = n;
	ioserv_setup_signals();

	while (!dnet_need_exit(n))
		sleep(1);

	dnet_server_node_destroy(n);
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
		return ioserv_start(conf, mon);
	}

	return 0;
}

