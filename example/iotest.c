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
#include <sys/mman.h>

#include <ctype.h>
#include <fcntl.h>
#include <errno.h>
#include <poll.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <netinet/in.h>

#include "dnet/packet.h"
#include "dnet/interface.h"

#include "hash.h"
#include "common.h"

#ifndef __unused
#define __unused	__attribute__ ((unused))
#endif

struct iotest_state
{
	struct iotest_state		*next;
	struct dnet_config		cfg;
	unsigned long long		bytes, completed, errors;
	unsigned long long		send_syscalls, recv_syscalls;

	struct dnet_addr		addr;
	int				error;
};

static struct iotest_state iotest_root;
static unsigned long long iotest_bytes, iotest_completed, iotest_started;
static int iotest_lookup_num, iotest_lookup_found, iotest_lookup_pending;
static unsigned long iotest_max_pending = 100000;

static int iotest_sleep;
static int iotest_pipe[2];

static int iotest_complete(struct dnet_net_state *st __unused, struct dnet_cmd *cmd,
		struct dnet_attr *attr __unused, void *priv)
{
	if (!cmd || !cmd->size || cmd->status) {
		struct iotest_state *is = iotest_root.next;

		while (is) {
			int err = dnet_id_cmp(cmd->id, is->cfg.id);

			if (err >= 0)
				break;

			is = is->next;
		}

		if (!is)
			is = iotest_root.next;

		if (!cmd || cmd->status) {
			is->errors++;
			is->error = cmd->status;
			memcpy(&is->addr, dnet_state_addr(st), sizeof(struct dnet_addr));
		}

		if (cmd && !(cmd->flags & DNET_FLAGS_MORE)) {
			unsigned long bytes = (unsigned long)priv;

			is->completed++;
			is->bytes += bytes;
			iotest_bytes += bytes;
		}
	}

	if (cmd && !(cmd->flags & DNET_FLAGS_MORE)) {
		iotest_completed++;

		if (iotest_sleep && (iotest_started - iotest_completed < iotest_max_pending/2)) {
			unsigned int b;
			int err;

			err = write(iotest_pipe[1], &b, 4);
			iotest_sleep = 0;
		}
	}

	return 0;
}

static int iotest_lookup_complete(struct dnet_net_state *st, struct dnet_cmd *cmd,
		struct dnet_attr *attr, void *priv)
{
	int err;

	err = dnet_lookup_complete(st, cmd, attr, priv);
	if (cmd && !cmd->status && !err && cmd->size) {
		printf("%s: lookup completed: err: %d.\n", dnet_dump_id(cmd->id), err);
		iotest_lookup_found++;
	}

	iotest_lookup_pending--;

	return 0;
}

static void iotest_wait(void)
{
	if (iotest_started - iotest_completed > iotest_max_pending) {
		unsigned int b;
		int err;
		struct pollfd pfd;

		pfd.fd = iotest_pipe[0];
		pfd.events = POLLIN;
		pfd.revents = 0;

		iotest_sleep = 1;
		err = poll(&pfd, 1, 1000);

		if (err > 0 && (pfd.revents & POLLIN))
			while (read(iotest_pipe[0], &b, 4) > 0);
	}
}

static int iotest_write(struct dnet_node *n, void *data, size_t size, unsigned long long max,
		char *obj)
{
	struct dnet_io_control ctl;
	unsigned int *ptr = data;
	int first, last, err, trans_num;
	unsigned int len = obj ? strlen(obj) : 0;

	memset(&ctl, 0, sizeof(struct dnet_io_control));

	ctl.aflags = 0;
	ctl.complete = iotest_complete;

	ctl.io.offset = 0;
	ctl.io.size = size;
	if (!obj)
		ctl.io.flags = DNET_IO_FLAGS_NO_HISTORY_UPDATE;
	ctl.cmd = DNET_CMD_WRITE;
	ctl.cflags = DNET_FLAGS_NEED_ACK;

	ctl.data = data;
	ctl.fd = -1;

	first = 0;
	last = size / sizeof(int) - 1;

	while (max) {
		if (size > max)
			size = max;

		//ptr[first] = ptr[last] = rand();
		ptr[first] = ptr[last] = iotest_started;

		ctl.data = data;
		ctl.priv = (void *)(unsigned long)size;

		err = dnet_write_object(n, &ctl, obj, len, NULL, !!obj, &trans_num);
		if (err < 0)
			return err;

		iotest_started += trans_num;

		if (iotest_lookup_found < iotest_lookup_num &&
				iotest_lookup_pending < iotest_lookup_num) {
			err = dnet_lookup_object(n, ctl.io.id, 0, iotest_lookup_complete, NULL);
			if (err)
				fprintf(stderr, "Failed to lookup a node for %s object.\n",
						dnet_dump_id(ctl.io.id));
			iotest_lookup_pending++;
		}

		iotest_wait();

		max -= size;
		ctl.io.offset += size;
	}

	return 0;
}

static int iotest_read(struct dnet_node *n,void *data, size_t size, unsigned long long max,
		char *obj)
{
	struct dnet_io_control ctl;
	int err, fd;
	struct dnet_io_attr *ios;
	char hfile[size + sizeof(DNET_HISTORY_SUFFIX) + 1];
	struct stat st;
	size_t  num;

	memset(&ctl, 0, sizeof(struct dnet_io_control));

	err = dnet_read_file(n, obj, NULL, 0, 0, 1);
	if (err)
		return err;

	snprintf(hfile, sizeof(hfile), "%s%s", obj, DNET_HISTORY_SUFFIX);

	fd = open(hfile, O_RDONLY);
	if (fd < 0) {
		err = -errno;
		fprintf(stderr, "Failed to open history file '%s': %s.\n", hfile, strerror(errno));
		goto err_out_exit;
	}

	err = fstat(fd, &st);
	if (err) {
		err = -errno;
		fprintf(stderr, "Failed to stat history file '%s': %s.\n", hfile, strerror(errno));
		goto err_out_close;
	}

	ios = mmap(NULL, st.st_size, PROT_READ, MAP_SHARED, fd, 0);
	if (ios == MAP_FAILED) {
		err = -errno;
		fprintf(stderr, "Failed to map history file '%s': %s.\n", hfile, strerror(errno));
		goto err_out_close;
	}

	ctl.aflags = 0;
	ctl.complete = iotest_complete;

	ctl.cmd = DNET_CMD_READ;
	ctl.cflags = DNET_FLAGS_NEED_ACK;

	ctl.data = data;
	ctl.fd = -1;

	num = st.st_size / sizeof(struct dnet_io_attr) - 1;

	while (max) {
		ctl.io = ios[(int)((double)(rand()) * num / (double) RAND_MAX)];

		dnet_convert_io_attr(&ctl.io);

		if (iotest_lookup_num) {
			err = dnet_lookup_object(n, ctl.io.id, 0, iotest_lookup_complete, NULL);
			if (err)
				fprintf(stderr, "Failed to lookup a node for %s object.\n",
						dnet_dump_id(ctl.io.id));
		}

		memcpy(ctl.addr, ctl.io.id, DNET_ID_SIZE);
		ctl.io.flags = 0;

		if (size > max)
			size = max;

		if (ctl.io.size > size)
			ctl.io.size = size;

		ctl.priv = (void *)(unsigned long)ctl.io.size;

		err = dnet_read_object(n, &ctl);
		if (err)
			return err;

		iotest_wait();

		max -= size;
	}

	munmap(ios, st.st_size);
	close(fd);

	return 0;

err_out_close:
	close(fd);
err_out_exit:
	return err;
}

static void *iotest_perf(void *log_private)
{
	long double speed;
	struct timeval t, p;
	long usec;
	unsigned long long chunks_per_second, prev_completed, prev_bytes;
	struct iotest_state *st;
	char msg[512];

	gettimeofday(&p, NULL);
	prev_completed = 0;
	prev_bytes = 0;

	while (1) {
		sleep(1);

		st = iotest_root.next;

		while (st) {
			gettimeofday(&t, NULL);

			usec = t.tv_usec - p.tv_usec;
			usec += 1000000 * (t.tv_sec - p.tv_sec);

			if (usec == 0)
				usec = 1;
			speed = (double)(st->bytes - prev_bytes) / (double)usec * 1000000 / (1024 * 1024);
			chunks_per_second = (long double)(st->completed - prev_completed) / (long double)usec * 1000000;

			snprintf(msg, sizeof(msg), "%s:%s: bytes: %10llu | %8.3Lf MB/s, "
					"chunks: %8llu | %7llu per sec, errors: %llu, err: %d, addr: %s.\n",
					st->cfg.addr, st->cfg.port,
					st->bytes, speed, st->completed, chunks_per_second, st->errors,
					st->error, dnet_server_convert_dnet_addr(&st->addr));
			dnet_common_log(log_private, DNET_LOG_NOTICE, msg);

			p = t;
			prev_completed = st->completed;
			prev_bytes = st->bytes;
			st = st->next;
		}
	}

	return NULL;
}

static void dnet_usage(char *p)
{
	fprintf(stderr, "Usage: %s\n"
			" -a addr:port:family  - creates a node with given network address\n"
			" -r addr:port:family  - adds a route to the given node\n"
			" -i object            - object name used to be transformed into ID\n"
			" -R                   - read data from the network storage\n"
			" -T hash              - OpenSSL hash to use as a transformation function\n"
			" -l log               - log file. Default: stdout\n"
			" -w timeout           - wait timeout in seconds used to wait for content sync\n"
			" -m mask              - log events mask\n"
			" -s size              - chunk size\n"
			" -S size              - amount of bytes transferred in the test\n"
			" -t seconds           - speed check interval\n"
			" -I id                - node ID\n"
			" -n num               - number of the server lookup requests sent during the test\n"
			" -N num               - number of IO threads\n"
			, p);
}

int main(int argc, char *argv[])
{
	int trans_max = 5, trans_num = 0;
	int ch, err, i, write = 1;
	struct dnet_node *n = NULL;
	struct dnet_config cfg;
	struct iotest_state *st, *prev;
	struct dnet_crypto_engine *e, *trans[trans_max];
	char *logfile = NULL, *obj = NULL;
	FILE *log = NULL;
	size_t size = 1024*1024;
	unsigned long long max = 100ULL * 1024 * 1024 * 1024;
	void *data;
	int seconds = 1;
	pthread_t tid;

	memset(&cfg, 0, sizeof(struct dnet_config));

	cfg.sock_type = SOCK_STREAM;
	cfg.proto = IPPROTO_TCP;
	cfg.wait_timeout = 60*60;
	cfg.log_mask = DNET_LOG_ERROR | DNET_LOG_INFO;
	cfg.io_thread_num = 2;
	cfg.max_pending = 256;

	while ((ch = getopt(argc, argv, "N:n:I:t:S:s:m:i:a:r:RT:l:w:h")) != -1) {
		switch (ch) {
			case 'N':
				cfg.io_thread_num = atoi(optarg);
				break;
			case 'n':
				iotest_lookup_num = atoi(optarg);
				break;
			case 'I':
				err = dnet_parse_numeric_id(optarg, cfg.id);
				if (err)
					return err;
				break;
			case 't':
				seconds = atoi(optarg);
				break;
			case 'S':
				max = strtoull(optarg, NULL, 0);
				break;
			case 's':
				size = strtoul(optarg, NULL, 0);
				break;
			case 'm':
				cfg.log_mask = strtoul(optarg, NULL, 0);
				break;
			case 'w':
				cfg.wait_timeout = atoi(optarg);
				break;
			case 'l':
				logfile = optarg;
				break;
			case 'i':
				obj = optarg;
				break;
			case 'a':
				err = dnet_parse_addr(optarg, &cfg);
				if (err)
					return err;
				break;
			case 'r':
				st = malloc(sizeof(struct iotest_state));
				if (!st)
					return -ENOMEM;
				memset(st, 0, sizeof(struct iotest_state));

				memcpy(&st->cfg, &cfg, sizeof(struct dnet_config));
				err = dnet_parse_addr(optarg, &st->cfg);
				if (err)
					return err;

				st->next = iotest_root.next;
				iotest_root.next = st;
				break;
			case 'R':
				write = 0;
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

	if (!iotest_root.next) {
		fprintf(stderr, "No remote nodes to connect. Exiting.\n");
		return -1;
	}

	if (!obj && !write) {
		fprintf(stderr, "No object name to use as ID.\n");
		return -1;
	}

	data = malloc(size);
	if (!data) {
		fprintf(stderr, "Failed to allocate %zu bytes for the data chunk.\n", size);
		return -1;
	}
	memset(data, 0xcc, size);

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
	prev = &iotest_root;
	st = prev->next;
	while (st) {
		struct iotest_state *iter, *next = st->next, *pr;
		err = dnet_add_state(n, &st->cfg);
		if (err)
			return err;

		pr = &iotest_root;
		iter = pr->next;
		while (iter != st) {
			err = dnet_id_cmp(iter->cfg.id, st->cfg.id);

			if (err < 0) {
				prev->next = st->next;
				pr->next = st;
				st->next = iter;
				break;
			}

			pr = iter;
			iter = iter->next;
		}


		prev = st;
		st = next;
	}

	st = iotest_root.next;
	while (st) {
		printf("%s:%s  %s\n", st->cfg.addr, st->cfg.port, dnet_dump_id(st->cfg.id));
		st = st->next;
	}

	err = pipe(iotest_pipe);
	if (err) {
		err = -errno;
		fprintf(stderr, "Failed to create a control pipe: %d.\n", err);
		return err;
	}

	fcntl(iotest_pipe[0], F_SETFL, O_NONBLOCK);
	fcntl(iotest_pipe[1], F_SETFL, O_NONBLOCK);

	err = pthread_create(&tid, NULL, iotest_perf, cfg.log_private);
	if (err) {
		fprintf(stderr, "Failed to spawn performance checking thread, err: %d.\n", err);
		return err;
	}

	srand(time(NULL));

	if (write)
		err = iotest_write(n, data, size, max, obj);
	else
		err = iotest_read(n, data, size, max, obj);

	printf("%s: size: %zu, max: %llu, obj: '%s', err: %d.\n", (write)?"Write":"Read", size, max, obj, err);

	if (err)
		return err;

	while (iotest_bytes < max)
		sleep(1);

	return 0;
}
