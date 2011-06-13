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
			, p);
	exit(-1);
}

struct meta_control {
	pthread_cond_t		wait;
	pthread_mutex_t		lock;
	int			num;
};

static int meta_request_complete(struct dnet_net_state *state, struct dnet_cmd *cmd, struct dnet_attr *attr, void *priv)
{
	struct meta_control *mc = priv;
	struct dnet_node *n;
	struct dnet_io_attr *io;
	long long size;
	void *data;

	if (is_trans_destroyed(state, cmd, attr)) {
		pthread_mutex_lock(&mc->lock);
		mc->num++;
		pthread_cond_broadcast(&mc->wait);
		pthread_mutex_unlock(&mc->lock);
		return 0;
	}

	n = dnet_get_node_from_state(state);

	if (!attr) {
		dnet_log_raw(n, DNET_LOG_ERROR, "%s: transaction returned no data: %d\n", dnet_dump_id(&cmd->id), cmd->status);
		return -1;
	}

	if (attr->size <= sizeof(struct dnet_io_attr)) {
		dnet_log_raw(n, DNET_LOG_ERROR, "%s: transaction returned %llu bytes, "
				"which is not enough for IO (must be more than %zu)\n",
				dnet_dump_id(&cmd->id), (unsigned long long)attr->size, sizeof(struct dnet_io_attr));
		return -1;
	}

	io = (struct dnet_io_attr *)(attr + 1);
	dnet_convert_io_attr(io);

	dnet_log_raw(n, DNET_LOG_INFO, "%s: metadata: %llu bytes\n", dnet_dump_id(&cmd->id), (unsigned long long)io->size);

	size = io->size;
	data = io + 1;

	while (size > 0) {
		struct dnet_meta *m = data;

		dnet_convert_meta(m);

		if (m->type == DNET_META_PARENT_OBJECT) {
			char name[m->size + 1];

			memcpy(name, m->data, m->size);
			name[m->size] = '\0';
			dnet_log_raw(n, DNET_LOG_INFO, "type: %u, size: %u, name: '%s'\n", m->type, m->size, name);
		} else if (m->type == DNET_META_GROUPS) {
			int *groups = (int *)m->data;
			int gnum = m->size / sizeof(int);
			char str[gnum * 36 + 1], *ptr;
			int i, rest, err;

			memset(str, 0, sizeof(str));

			ptr = str;
			rest = sizeof(str);
			for (i=0; i<gnum; ++i) {
				err = snprintf(ptr, rest, "%d:", groups[i]);
				if (err > rest)
					break;

				rest -= err;
				ptr += err;

				if (i == gnum - 1)
					*(--ptr) = '\0';
			}

			dnet_log_raw(n, DNET_LOG_INFO, "type: %u, size: %u, groups: %s\n",
					m->type, m->size, str);
		} else if (m->type == DNET_META_CHECK_STATUS) {
			struct dnet_meta_check_status *s = (struct dnet_meta_check_status *)m->data;
			dnet_convert_meta_check_status(s);
			char tstr[64];
			struct tm tm;

			localtime_r((time_t *)&s->tsec, &tm);
			strftime(tstr, sizeof(tstr), "%F %Z %R:%S", &tm);

			dnet_log_raw(n, DNET_LOG_INFO, "type: %u, size: %u, check status: %d, ts: %s.%06lld\n",
					m->type, m->size, s->status, tstr,
					(unsigned long long)s->tnsec);
		} else if (m->type == DNET_META_UPDATE) {
			struct dnet_meta_update *mu = (struct dnet_meta_update *)m->data;
			int num = m->size / sizeof(struct dnet_meta_update), i, rest, err;
			char str[128 * num], *ptr;
			char tstr[64];
			struct tm tm;

			memset(str, 0, sizeof(str));

			ptr = str;
			rest = sizeof(str);
			for (i=0; i<num; ++i) {
				dnet_convert_meta_update(mu);

				localtime_r((time_t *)&mu->tsec, &tm);
				strftime(tstr, sizeof(tstr), "%F %Z %R:%S", &tm);

				err = snprintf(ptr, rest, "%d:%llx:%s.%06lld | ",
						mu->group_id, (unsigned long long)mu->flags, tstr,
						(unsigned long long)mu->tnsec);
				if (err > rest)
					break;

				rest -= err;
				ptr += err;

				/* remove trailing ' | ' */
				if (i == num - 1) {
					*(--ptr) = '\0';
					*(--ptr) = '\0';
					*(--ptr) = '\0';
				}

				++mu;
			}
			dnet_log_raw(n, DNET_LOG_INFO, "type: %u, size: %u, meta updates: %s\n",
					m->type, m->size, str);
		} else if (m->type == DNET_META_NAMESPACE) {
			char str[m->size + 1];
			memcpy(str, m->data, m->size);
			str[m->size] = '\0';

			dnet_log_raw(n, DNET_LOG_INFO, "type: %u, size: %u, namespace: %s\n",
					m->type, m->size, str);
		} else if (m->type == DNET_META_CHECKSUM) {
			struct dnet_meta_checksum *csum = (struct dnet_meta_checksum *)m->data;
			char id_str[sizeof(csum->checksum)*2 + 1];
			char tstr[64];
			struct tm tm;

			dnet_convert_meta_checksum(csum);

			localtime_r((time_t *)&csum->tsec, &tm);
			strftime(tstr, sizeof(tstr), "%F %Z %R:%S", &tm);

			dnet_log_raw(n, DNET_LOG_INFO, "type: %u, size: %u, time: %s.%06lld, csum: %s\n",
					m->type, m->size, tstr, (unsigned long long)csum->tnsec,
					dnet_dump_id_len_raw(csum->checksum, sizeof(csum->checksum), id_str));
		} else {
			dnet_log_raw(n, DNET_LOG_INFO, "type: %u, size: %u\n", m->type, m->size);
		}

		data += m->size + sizeof(*m);
		size -= m->size + sizeof(*m);
	}
	return 0;
}

static int meta_request(struct dnet_node *n, int *groups, int group_num, char *name, unsigned char *raw_id)
{
	struct dnet_id raw;
	struct dnet_io_control ctl;
	int i, err = -ENOENT;
	struct meta_control *mc;

	if (name) {
		dnet_transform(n, name, strlen(name), &raw);
	} else {
		dnet_setup_id(&raw, 0, raw_id);
	}

	mc = malloc(sizeof(*mc));
	if (!mc) {
		err = -ENOMEM;
		goto err_out_exit;
	}
	memset(mc, 0, sizeof(*mc));

	pthread_mutex_init(&mc->lock, NULL);
	pthread_cond_init(&mc->wait, NULL);
	mc->num = 0;

	memset(&ctl, 0, sizeof(ctl));

	memcpy(&ctl.id, &raw, sizeof(raw));
	memcpy(&ctl.io.parent, raw.id, sizeof(ctl.io.parent));
	memcpy(&ctl.io.id, raw.id, sizeof(ctl.io.parent));

	ctl.io.flags = DNET_IO_FLAGS_META;

	ctl.complete = meta_request_complete;
	ctl.priv = mc;

	ctl.cmd = DNET_CMD_READ;
	ctl.cflags = DNET_FLAGS_NEED_ACK;

	for (i=0; i<group_num; ++i) {
		ctl.id.group_id = groups[i];

		err = dnet_read_object(n, &ctl);
	}

	pthread_mutex_lock(&mc->lock);
	while (mc->num != group_num) {
		pthread_cond_wait(&mc->wait, &mc->lock);
	}
	pthread_mutex_unlock(&mc->lock);

	free(mc);

err_out_exit:
	return err;
}

int main(int argc, char *argv[])
{
	int ch, err;
	char *logfile = "/dev/stderr";
	char *name = NULL;
	FILE *log;
	int *groups, group_num = 0;
	unsigned char trans_id[DNET_ID_SIZE], *id = NULL;
	struct dnet_config cfg, rem;
	struct dnet_node *n;

	memset(&cfg, 0, sizeof(cfg));

	cfg.sock_type = SOCK_STREAM;
	cfg.proto = IPPROTO_TCP;
	cfg.wait_timeout = 10;
	meta_logger.log_mask = DNET_LOG_ERROR | DNET_LOG_INFO;

	memcpy(&rem, &cfg, sizeof(struct dnet_config));

	while ((ch = getopt(argc, argv, "g:w:I:n:r:m:l:h")) != -1) {
		switch (ch) {
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

	err = dnet_add_state(n, &rem);
	if (err)
		goto err_out_destroy;

	dnet_node_set_groups(n, groups, group_num);

	err = meta_request(n, groups, group_num, name, id);

err_out_destroy:
	dnet_node_destroy(n);
err_out_exit:
	return err;
}
