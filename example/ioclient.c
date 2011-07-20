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

#include "elliptics/packet.h"
#include "elliptics/interface.h"

#include "backends.h"
#include "common.h"

#ifndef __unused
#define __unused	__attribute__ ((unused))
#endif

static struct dnet_log ioclient_logger;

static void dnet_usage(char *p)
{
	fprintf(stderr, "Usage: %s\n"
			" -r addr:port:family  - adds a route to the given node\n"
			" -W file              - write given file to the network storage\n"
			" -s                   - request IO counter stats from node\n"
			" -z                   - request VFS IO stats from node\n"
			" -a                   - request stats from all connected nodes\n"
			" -U status            - update server status: 1 - elliptics exits, 2 - goes RO\n"
			" -R file              - read given file from the network into the local storage\n"
			" -I id                - transaction id\n"
			" -g groups            - group IDs to connect\n"
			" -c cmd               - execute given command on the remote node\n"
			" -L file              - lookup a storage which hosts given file\n"
			" -l log               - log file. Default: disabled\n"
			" -w timeout           - wait timeout in seconds used to wait for content sync.\n"
			" ...                  - parameters can be repeated multiple times\n"
			"                        each time they correspond to the last added node\n"
			" -m mask              - log events mask\n"
			" -M mask              - set new log mask\n"
			" -O offset            - read/write offset in the file\n"
			" -S size              - read/write transaction size\n"
			" -u file              - unlink file\n"
			" -N namespace         - use this namespace for operations\n"
			, p);
}

int main(int argc, char *argv[])
{
	int ch, err, i, have_remote = 0;
	int io_counter_stat = 0, vfs_stat = 0, single_node_stat = 1;
	struct dnet_node_status node_status;
	int update_status = 0;
	struct dnet_node *n = NULL;
	struct dnet_config cfg, rem, *remotes = NULL;
	char *logfile = "/dev/stderr", *readf = NULL, *writef = NULL, *cmd = NULL, *lookup = NULL;
	char *read_data = NULL;
	char *removef = NULL;
	unsigned char trans_id[DNET_ID_SIZE], *id = NULL;
	FILE *log = NULL;
	uint64_t offset, size;
	int *groups = NULL, group_num = 0;

	memset(&node_status, 0, sizeof(struct dnet_node_status));
	memset(&cfg, 0, sizeof(struct dnet_config));

	size = offset = 0;

	cfg.sock_type = SOCK_STREAM;
	cfg.proto = IPPROTO_TCP;
	cfg.wait_timeout = 60;
	ioclient_logger.log_mask = DNET_LOG_ERROR | DNET_LOG_DATA;

	memcpy(&rem, &cfg, sizeof(struct dnet_config));

	while ((ch = getopt(argc, argv, "M:N:g:u:O:S:m:zsU:aL:w:l:c:I:r:W:R:D:h")) != -1) {
		switch (ch) {
			case 'M':
				node_status.log_mask = strtol(optarg, NULL, 0);
				update_status = 1;
				break;
			case 'N':
				cfg.ns = optarg;
				cfg.nsize = strlen(optarg);
				break;
			case 'u':
				removef = optarg;
				break;
			case 'O':
				offset = strtoull(optarg, NULL, 0);
				break;
			case 'S':
				size = strtoull(optarg, NULL, 0);
				break;
			case 'm':
				ioclient_logger.log_mask = strtoul(optarg, NULL, 0);
				break;
			case 's':
				io_counter_stat = 1;
				break;
			case 'U':
				node_status.status_flags = strtol(optarg, NULL, 0);
				update_status = 1;
				break;
			case 'z':
				vfs_stat = 1;
				break;
			case 'a':
				single_node_stat = 0;
				break;
			case 'L':
				lookup = optarg;
				break;
			case 'w':
				cfg.check_timeout = cfg.wait_timeout = atoi(optarg);
				break;
			case 'l':
				logfile = optarg;
				break;
			case 'c':
				cmd = optarg;
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
			case 'W':
				writef = optarg;
				break;
			case 'R':
				readf = optarg;
				break;
			case 'D':
				read_data = optarg;
				break;
			case 'h':
			default:
				dnet_usage(argv[0]);
				return -1;
		}
	}
	
	log = fopen(logfile, "a");
	if (!log) {
		err = -errno;
		fprintf(stderr, "Failed to open log file %s: %s.\n", logfile, strerror(errno));
		return err;
	}

	ioclient_logger.log_private = log;
	ioclient_logger.log = dnet_common_log;
	cfg.log = &ioclient_logger;

	n = dnet_node_create(&cfg);
	if (!n)
		return -1;

	dnet_node_set_groups(n, groups, group_num);

	if (have_remote) {
		int error = -ECONNRESET;
		for (i=0; i<have_remote; ++i) {
			if (single_node_stat && (vfs_stat || io_counter_stat))
				remotes[i].flags = DNET_CFG_NO_ROUTE_LIST;
			err = dnet_add_state(n, &remotes[i]);
			if (!err)
				error = 0;
		}

		if (error)
			return error;
	}

	if (writef) {
		err = dnet_write_file(n, writef, writef, strlen(writef), offset, offset, size, 0, 0, 0);
		if (err)
			return err;
	}

	if (readf) {
		err = dnet_read_file(n, readf, readf, strlen(readf), offset, size, 0);

		if (err)
			return err;
	}
	
	if (read_data) {
		void *data;
		struct dnet_id raw;
		struct dnet_io_attr io;

		dnet_transform(n, read_data, strlen(read_data), &raw);

		memset(&io, 0, sizeof(io));
		memcpy(io.id, raw.id, DNET_ID_SIZE);
		memcpy(io.parent, raw.id, DNET_ID_SIZE);

		/* number of copies to check to find the latest data */
		io.num = group_num;

		err = dnet_read_latest(n, &raw, &io, 0, &data);
		if (err)
			return err;

		data += sizeof(struct dnet_io_attr);
		io.size -= sizeof(struct dnet_io_attr);

		while (io.size) {
			err = write(1, data, io.size);
			if (err <= 0) {
				err = -errno;
				dnet_log_raw(n, DNET_LOG_ERROR, "%s: can not write data to stdout: %d %s",
						read_data, err, strerror(-err));
				return err;
			}

			io.size -= err;
		}
	}

	if (removef) {
		if (id) {
			struct dnet_id raw;

			for (i=0; i<group_num; ++i) {
				dnet_setup_id(&raw, groups[i], id);
				dnet_remove_object_now(n, &raw, 0);
			}

			return 0;
		}

		err = dnet_remove_file(n, removef, strlen(removef), NULL);
		if (err)
			return err;
	}

	if (cmd) {
		err = dnet_send_cmd(n, NULL, cmd);
		if (err < 0)
			return err;
	}

	if (lookup) {
		err = dnet_lookup(n, lookup);
		if (err)
			return err;
	}

	if (vfs_stat) {
		err = dnet_request_stat(n, NULL, DNET_CMD_STAT, 0, NULL, NULL);
		if (err < 0)
			return err;
	}

	if (io_counter_stat) {
		err = dnet_request_stat(n, NULL, DNET_CMD_STAT_COUNT, DNET_ATTR_CNTR_GLOBAL, NULL, NULL);
		if (err < 0)
			return err;
	}

	if (update_status) {
		struct dnet_addr addr;

		node_status.nflags = -1;
		for (i=0; i<have_remote; ++i) {
			err = dnet_fill_addr(&addr, remotes[i].addr, remotes[i].port,
						remotes[i].family, remotes[i].sock_type, remotes[i].proto);

			err = dnet_update_status(n, &addr, NULL, &node_status, update_status > 0);
		}

	}

	dnet_node_destroy(n);

	return 0;
}

