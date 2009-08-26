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

#include "dnet/packet.h"
#include "dnet/interface.h"

#include "hash.h"
#include "backends.h"
#include "common.h"

#ifndef __unused
#define __unused	__attribute__ ((unused))
#endif

static int dnet_background(void)
{
	pid_t pid;

	pid = fork();
	if (pid == -1) {
		fprintf(stderr, "Failed to fork to background: %s.\n", strerror(errno));
		return -1;
	}

	if (pid != 0) {
		printf("Daemon pid: %d.\n", pid);
		exit(0);
	}

	setsid();

	close(1);
	close(2);

	return 0;
}

static void dnet_usage(char *p)
{
	fprintf(stderr, "Usage: %s\n"
			" -a addr:port:family  - creates a node with given network address\n"
			" -r addr:port:family  - adds a route to the given node\n"
			" -j <join>            - join the network\n"
			"                        become a fair node which may store data from the other nodes\n"
			" -b <BDB>             - use BerkeleyDB (if present) IO storage backend\n"
			" -t <TokyoCabinet>    - use TokyoCabinet (if present) IO storage backend\n"
			" -d root              - root directory to load/store the objects\n"
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
			" -D <daemon>          - go background\n"
			" -m mask              - log events mask\n"
			" -N num               - number of IO threads\n"
			" -P num               - maximum number of pending write transactions opened by single thread\n"
			" -O offset            - read/write offset in the file\n"
			" -S size              - read/write transaction size\n"
			" -M strategy          - transaction log merge strategy\n"
			" -u file              - unlink file\n"
			, p);
}

int main(int argc, char *argv[])
{
	int trans_max = 5, trans_num = 0;
	int ch, err, i, have_remote = 0, daemon = 0, bdb = 0, stat = 0;
	int tc = 0;
	struct dnet_node *n = NULL;
	struct dnet_config cfg, rem;
	struct dnet_crypto_engine *e, *trans[trans_max];
	char *logfile = NULL, *readf = NULL, *writef = NULL, *cmd = NULL, *lookup = NULL;
	char *historyf = NULL, *root = NULL, *removef = NULL;
	unsigned char trans_id[DNET_ID_SIZE], *id = NULL;
	FILE *log = NULL;
	uint64_t offset, size;

	memset(&cfg, 0, sizeof(struct dnet_config));

	cfg.sock_type = SOCK_STREAM;
	cfg.proto = IPPROTO_TCP;
	cfg.wait_timeout = 60*60;
	cfg.log_mask = ~0;
	cfg.merge_strategy = DNET_MERGE_PREFER_NETWORK;
	cfg.resend_count = 3;

	size = offset = 0;

	memcpy(&rem, &cfg, sizeof(struct dnet_config));

	while ((ch = getopt(argc, argv, "u:M:O:S:P:N:bm:tsH:L:Dc:I:w:l:i:T:W:R:a:r:jd:h")) != -1) {
		switch (ch) {
			case 'u':
				removef = optarg;
				break;
			case 'M':
				cfg.merge_strategy = atoi(optarg);
				break;
			case 'O':
				offset = strtoull(optarg, NULL, 0);
				break;
			case 'S':
				size = strtoull(optarg, NULL, 0);
				break;
			case 'P':
				cfg.max_pending = atoi(optarg);
				break;
			case 'N':
				cfg.io_thread_num = atoi(optarg);
				break;
			case 'b':
				bdb = 1;
				break;
			case 't':
				tc = 1;
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
			case 'D':
				daemon = 1;
				break;
			case 'w':
				cfg.wait_timeout = atoi(optarg);
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
				have_remote = 1;
				break;
			case 'j':
				cfg.join = 1;
				break;
			case 'd':
				root = optarg;
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

	if (root) {
		if (bdb) {
			cfg.command_private = bdb_backend_init(root, "data.db", "history.db");
			if (!cfg.command_private)
				return -EINVAL;
			cfg.command_handler = bdb_backend_command_handler;
		} else if (tc) {
			cfg.command_private = tc_backend_init(root, "data.tch", "history.tch");
			if (!cfg.command_private)
				return -EINVAL;
			cfg.command_handler = tc_backend_command_handler;
		} else {
			cfg.command_private = file_backend_setup_root(root);
			if (!cfg.command_private)
				return -EINVAL;
			cfg.command_handler = file_backend_command_handler;
			cfg.command_private = root;
		}
	}

	if (daemon)
		dnet_background();

	n = dnet_node_create(&cfg);
	if (!n)
		return -1;

	for (i=0; i<trans_num; ++i) {
		err = dnet_add_transform(n, trans[i], trans[i]->name,
			trans[i]->init,	trans[i]->update, trans[i]->final);
		if (err)
			return err;
	}

	if (have_remote) {
		err = dnet_add_state(n, &rem);
		if (err)
			return err;
	}

	if (cfg.join) {
		err = dnet_join(n);
		if (err)
			return err;
	}

	if (writef) {
		err = dnet_write_file(n, writef, id, offset, size, 0);
		if (err)
			return err;
	}

	if (readf) {
		err = dnet_read_file(n, readf, id, offset, size, 0);
		if (err)
			return err;
	}

	if (historyf) {
		err = dnet_read_file(n, historyf, id, offset, size, 1);
		if (err)
			return err;
	}
	
	if (removef) {
		err = dnet_remove_file(n, removef, id);
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
		err = dnet_request_stat(n, NULL, NULL, NULL);
		if (err)
			return err;
	}

	if (cfg.join) {
		/* Zzzz... */
		while (1)
			sleep(1);
	}

	dnet_node_destroy(n);

	printf("Successfully executed given command.\n");

	return 0;
}

