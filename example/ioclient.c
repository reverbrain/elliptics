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

#include "hash.h"
#include "backends.h"
#include "common.h"

#ifndef __unused
#define __unused	__attribute__ ((unused))
#endif

static void dnet_usage(char *p)
{
	fprintf(stderr, "Usage: %s\n"
			" -a addr:port:family  - creates a node with given network address\n"
			" -r addr:port:family  - adds a route to the given node\n"
			" -W file              - write given file to the network storage\n"
			" -s                   - request stats from all connected nodes\n"
			" -R file              - read given file from the network into the local storage\n"
			" -H file              - read a history for given file into the local storage\n"
			" -T hash              - OpenSSL hash to use as a transformation function\n"
			" -i id                - node's ID (zero by default)\n"
			" -I id                - transaction id\n"
			" -c cmd               - execute given command on the remote node\n"
			" -L file              - lookup a storage which hosts given file\n"
			" -l log               - log file. Default: disabled\n"
			" -w timeout           - wait timeout in seconds used to wait for content sync.\n"
			" ...                  - parameters can be repeated multiple times\n"
			"                        each time they correspond to the last added node\n"
			" -m mask              - log events mask\n"
			" -N num               - number of IO threads\n"
			" -O offset            - read/write offset in the file\n"
			" -S size              - read/write transaction size\n"
			" -u file              - unlink file\n"
			, p);
}

int main(int argc, char *argv[])
{
	int trans_max = 5, trans_num = 0;
	int ch, err, i, have_remote = 0, stat = 0;
	struct dnet_node *n = NULL;
	struct dnet_config cfg, rem, *remotes = NULL;
	struct dnet_crypto_engine *e, *trans[trans_max];
	char *logfile = NULL, *readf = NULL, *writef = NULL, *cmd = NULL, *lookup = NULL;
	char *historyf = NULL, *removef = NULL;
	unsigned char trans_id[DNET_ID_SIZE], *id = NULL;
	FILE *log = NULL;
	uint64_t offset, size;

	memset(&cfg, 0, sizeof(struct dnet_config));

	size = offset = 0;

	memcpy(&rem, &cfg, sizeof(struct dnet_config));

	while ((ch = getopt(argc, argv, "u:O:S:N:m:sH:L:w:l:c:I:i:a:r:W:R:T:h")) != -1) {
		switch (ch) {
			case 'u':
				removef = optarg;
				break;
			case 'O':
				offset = strtoull(optarg, NULL, 0);
				break;
			case 'S':
				size = strtoull(optarg, NULL, 0);
				break;
			case 'N':
				cfg.io_thread_num = atoi(optarg);
				break;
			case 'm':
				cfg.log_mask = strtoul(optarg, NULL, 0);
				break;
			case 's':
				stat = 1;
				break;
			case 'H':
				historyf = optarg;
				break;
			case 'L':
				lookup = optarg;
				break;
			case 'w':
				cfg.resend_timeout.tv_sec = cfg.wait_timeout = atoi(optarg);
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
			case 'i':
				err = dnet_parse_numeric_id(optarg, cfg.id);
				if (err)
					return err;
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
			case 'T':
				if (trans_num == trans_max - 1) {
					fprintf(stderr, "Only %d transformation functions allowed in this example.\n",
							trans_max);
					break;
				}

				e = malloc(sizeof(struct dnet_crypto_engine));
				if (!e)
					return -ENOMEM;
				memset(e, 0, sizeof(struct dnet_crypto_engine));

				err = dnet_crypto_engine_init(e, optarg);
				if (err)
					return err;
				trans[trans_num++] = e;
				break;
			case 'h':
			default:
				dnet_usage(argv[0]);
				return -1;
		}
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

		cfg.log_private = log;
		cfg.log = dnet_common_log;
	}

	n = dnet_node_create(&cfg);
	if (!n)
		return -1;

	for (i=0; i<trans_num; ++i) {
		err = dnet_add_transform(n, trans[i], trans[i]->name,
			trans[i]->init,	trans[i]->update, trans[i]->final, trans[i]->cleanup);
		if (err)
			return err;
	}

	if (have_remote) {
		for (i=0; i<have_remote; ++i)
			err = dnet_add_state(n, &remotes[i]);
	}

	if (writef) {
		err = dnet_write_file(n, writef, writef, strlen(writef), id, offset, size, 0);
		if (err)
			return err;
	}

	if (readf) {
		err = dnet_read_file(n, readf, readf, strlen(readf), id, offset, size, 0);
		if (err)
			return err;
	}

	if (historyf) {
		err = dnet_read_file(n, historyf, historyf, strlen(historyf), id, offset, size, 1);
		if (err)
			return err;
	}
	
	if (removef) {
		err = dnet_remove_file(n, removef, removef, strlen(removef), id);
		if (err)
			return err;
	}

	if (cmd) {
		err = dnet_send_cmd(n, trans_id, cmd);
		if (err)
			return err;
	}

	if (lookup) {
		err = dnet_lookup(n, lookup);
		if (err)
			return err;
	}

	if (stat) {
		err = dnet_request_stat(n, NULL, DNET_CMD_STAT, NULL, NULL);
		if (err)
			return err;
		err = dnet_request_stat(n, NULL, DNET_CMD_STAT_COUNT, NULL, NULL);
		if (err)
			return err;
	}

	dnet_node_destroy(n);

	printf("Successfully executed given command.\n");

	return 0;
}

