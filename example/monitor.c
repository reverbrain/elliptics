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

#include "hash.h"
#include "common.h"

#ifndef __unused
#define __unused	__attribute__ ((unused))
#endif

struct monitor_id {
	unsigned char id[DNET_ID_SIZE];
	struct dnet_addr addr;
};

static pthread_cond_t monitor_wait_cond = PTHREAD_COND_INITIALIZER;
static pthread_mutex_t monitor_wait_lock = PTHREAD_MUTEX_INITIALIZER;
static int monitor_wait_num;
static struct monitor_id *monitor_prev_ids, *monitor_current_ids;
static int monitor_prev_num, monitor_current_num;

#define monitor_wait(condition)						\
({										\
	pthread_mutex_lock(&monitor_wait_lock);					\
	while (!(condition)) 							\
		pthread_cond_wait(&monitor_wait_cond, &monitor_wait_lock);	\
	pthread_mutex_unlock(&monitor_wait_lock);				\
})

#define monitor_wakeup(doit)						\
({										\
 	int ______ret;								\
	pthread_mutex_lock(&monitor_wait_lock);					\
 	______ret = (doit);							\
	pthread_cond_broadcast(&monitor_wait_cond);				\
	pthread_mutex_unlock(&monitor_wait_lock);				\
 	______ret;								\
})

static struct dnet_log monitor_logger;

static int monitor_complete(struct dnet_net_state *state,
			struct dnet_cmd *cmd,
			struct dnet_attr *attr,
			void *priv __unused)
{
	struct dnet_node *n = dnet_get_node_from_state(state);
	struct dnet_stat *st;
	int err = 0;

	if (!state || !cmd || !attr)
		return 0;

	if (attr->size != sizeof(struct dnet_stat))
		return 0;

	st = (struct dnet_stat *)(attr + 1);

	pthread_mutex_lock(&monitor_wait_lock);
	monitor_current_ids = realloc(monitor_current_ids, (monitor_current_num + 1) * sizeof(struct monitor_id));
	if (!monitor_current_ids) {
		err = -ENOMEM;
		goto out_unlock;
	}

	memcpy(monitor_current_ids[monitor_current_num].id, cmd->id, DNET_ID_SIZE);
	memcpy(&monitor_current_ids[monitor_current_num].addr, dnet_state_addr(state), sizeof(struct dnet_addr));

out_unlock:
	pthread_mutex_unlock(&monitor_wait_lock);

	monitor_wakeup(monitor_wait_num++);
	dnet_log_raw(n, DNET_LOG_NOTICE, "%s: %s", dnet_dump_id(cmd->id), dnet_state_dump_addr(state));

	return err;
}

static int monitor_compare(const void *data1, const void *data2)
{
	const struct monitor_id *id1 = data1;
	const struct monitor_id *id2 = data2;

	return dnet_id_cmp(id1->id, id2->id);
}

static void monitor_usage(char *p)
{
	fprintf(stderr, "Usage: %s\n"
			" -r addr:port:family  - adds remote node\n"
			" -l log               - log file. Default: disabled\n"
			" -w timeout           - wait timeout in seconds used to wait for content sync.\n"
			" -m mask              - log events mask\n"
			" -t timeout           - timeout in seconds to repeatedly request network state\n"
			" -n num               - how many times to request network state and dump info\n"
			"                           to print diff it should be at least 2, -1 - run forever\n"
			" -h                   - this help\n"
	       , p);
}

int main(int argc, char *argv[])
{
	int ch, err, i, have_remote = 0;
	struct dnet_node *n = NULL;
	struct dnet_config cfg, rem, *remotes = NULL;
	int timeout, check_num;
	int error = -ECONNRESET;
	char *logfile = NULL;
	FILE *log = NULL;

	memset(&cfg, 0, sizeof(struct dnet_config));

	cfg.sock_type = SOCK_STREAM;
	cfg.proto = IPPROTO_TCP;
	cfg.wait_timeout = 60*60;
	monitor_logger.log_mask = DNET_LOG_ERROR | DNET_LOG_INFO;
	cfg.resend_timeout.tv_sec = 60*60*10;
	cfg.resend_count = 0;

	check_num = 1;
	timeout = 1;

	memcpy(&rem, &cfg, sizeof(struct dnet_config));

	while ((ch = getopt(argc, argv, "n:t:m:w:l:r:h")) != -1) {
		switch (ch) {
			case 'n':
				check_num = atoi(optarg);
				break;
			case 't':
				timeout = atoi(optarg);
				break;
			case 'm':
				monitor_logger.log_mask = strtoul(optarg, NULL, 0);
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
				have_remote++;
				remotes = realloc(remotes, sizeof(rem) * have_remote);
				if (!remotes)
					return -ENOMEM;
				memcpy(&remotes[have_remote - 1], &rem, sizeof(rem));
				break;
			case 'h':
			default:
				monitor_usage(argv[0]);
				return -1;
		}
	}

	if (!have_remote) {
		fprintf(stderr, "No remote node specified to route requests.\n");
		return -ENOENT;
	}

	if (!logfile)
		fprintf(stderr, "No log file found, logging will be disabled.\n");

	if (logfile) {
		log = fopen(logfile, "a");
		if (!log) {
			err = -errno;
			fprintf(stderr, "Failed to open log file %s: %s.\n", logfile, strerror(errno));
			return err;
		}

		monitor_logger.log_private = log;
		monitor_logger.log = dnet_common_log;
		cfg.log = &monitor_logger;
	}

	n = dnet_node_create(&cfg);
	if (!n)
		return -1;

	for (i=0; i<have_remote; ++i) {
		err = dnet_add_state(n, &remotes[i]);
		if (!err)
			error = 0;
	}

	if (error)
		return error;

	while (check_num-- != 0) {
		monitor_wait_num = 0;
		err = dnet_request_stat(n, NULL, DNET_CMD_STAT, monitor_complete, NULL);
		if (err < 0)
			return err;

		monitor_wait(monitor_wait_num == err);

		qsort(monitor_current_ids, monitor_current_num, sizeof(struct monitor_id), monitor_compare);

		if (monitor_current_num && monitor_prev_num) {
			int j, cmp;
			struct monitor_id *c, *p;

			for (i=0, j=0; i<monitor_current_num; ++i) {
				c = &monitor_current_ids[i];

				cmp = -1;
				for (; j<monitor_prev_num; ++j) {
					p = &monitor_prev_ids[j];

					cmp = dnet_id_cmp(c->id, p->id);
					if (cmp <= 0)
						break;
					dnet_log_raw(n, DNET_LOG_NOTICE, "diff: - %s: %s", dnet_dump_id(p->id), dnet_server_convert_dnet_addr(&p->addr));
				}

				if (!cmp)
					continue;

				dnet_log_raw(n, DNET_LOG_NOTICE, "diff: + %s: %s", dnet_dump_id(c->id), dnet_server_convert_dnet_addr(&c->addr));
			}
		}

		free(monitor_prev_ids);
		monitor_prev_ids = monitor_current_ids;
		monitor_prev_num = monitor_current_num;

		sleep(timeout);
	}

	return 0;
}
