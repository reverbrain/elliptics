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

#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/types.h>

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

#include "common.h"

#ifndef __unused
#define __unused	__attribute__ ((unused))
#endif

static struct dnet_log check_logger;

static void check_usage(char *p)
{
	fprintf(stderr, "Usage: %s\n"
			" -r addr:port:family  - adds remote node\n"
			" -l log               - log file. Default: disabled\n"
			" -w timeout           - wait timeout in seconds used to wait for content sync.\n"
			" -m mask              - log events mask\n"
			" -M                   - do not check copies in other groups, run only merge check\n"
			" -F                   - check not only history logs, but also try to read data object when checking number of copies\n"
			" -R                   - delete objects marked as REMOVED\n"
			" -D                   - dry run - do not perform any action, just update counters\n"
			" -t timestamp         - only check those objects, which were previously checked BEFORE this time\n"
			"                          format: year-month-day hours:minutes:seconds like \"2011-01-13 23:15:00\"\n"
			" -n num               - number of checking threads to start by the server\n"
			" -f file              - file with list of objects to check\n"
			" -h                   - this help\n"
	       , p);
}

static int dnet_check_fill(struct dnet_node *n, struct dnet_check_request *r, char *data, int num)
{
	int i;
	char *cur;
	struct dnet_id id;
	struct dnet_id *rid = (struct dnet_id *)(r + 1);
	char tmp_str[DNET_ID_SIZE*2+1];

	for (i=0; i<num; ++i) {
		cur = strchr(data, '\n');

		if (!cur || !*cur)
			break;

		dnet_transform(n, data, cur - data, &id);

		rid[i] = id;
		dnet_convert_id(&rid[i]);

		dnet_log_raw(n, DNET_LOG_NOTICE, "check: %s\n", dnet_dump_id_len_raw(id.id, DNET_ID_SIZE, tmp_str));

		data = cur + 1;
	}

	return 0;
}

static struct dnet_check_request *dnet_check_gen_request(struct dnet_node *n, struct dnet_check_request *base, char *file)
{
	struct dnet_check_request *r;
	char *data, *cur;
	int fd, err, num = 0;
	struct stat st;

	fd = open(file, O_RDONLY);
	if (fd < 0) {
		err = -errno;
		dnet_log_raw(n, DNET_LOG_ERROR, "check: failed to open check file '%s': %s [%d]\n",
				file, strerror(errno), errno);
		goto err_out_exit;
	}

	err = fstat(fd, &st);
	if (err < 0) {
		err = -errno;
		dnet_log_raw(n, DNET_LOG_ERROR, "check: failed to stat check file '%s': %s [%d]\n",
				file, strerror(errno), errno);
		goto err_out_close;
	}

	data = mmap(NULL, st.st_size, PROT_READ, MAP_SHARED, fd, 0);
	if (data == MAP_FAILED) {
		err = -errno;
		dnet_log_raw(n, DNET_LOG_ERROR, "check: failed to map check file '%s': %s [%d]\n",
				file, strerror(errno), errno);
		goto err_out_close;
	}

	cur = data;
	while (cur && *cur) {
		cur = strchr(cur, '\n');
		if (!cur)
			break;

		num++;
		cur++;
	}

	if (!num) {
		dnet_log_raw(n, DNET_LOG_NOTICE, "check: check file '%s' is empty: %s [%d]\n",
				file, strerror(errno), errno);
	}

	r = malloc(sizeof(*r) + num * sizeof(struct dnet_id));
	if (!r) {
		err = -ENOMEM;
		goto err_out_unmap;
	}

	memcpy(r, base, sizeof(*r));
	r->obj_num = num;

	err = dnet_check_fill(n, r, data, num);
	if (err)
		goto err_out_free;

	munmap(data, st.st_size);
	close(fd);

	return r;

err_out_free:
	free(r);
err_out_unmap:
	munmap(data, st.st_size);
err_out_close:
	close(fd);
err_out_exit:
	return NULL;
}

int main(int argc, char *argv[])
{
	int ch, err, have_remote = 0;
	struct dnet_node *n = NULL;
	struct dnet_config cfg, rem;
	char *logfile = "/dev/stderr";
	FILE *log = NULL;
	struct dnet_check_request r, *req;
	struct tm tm;
	char *file = NULL;

	memset(&cfg, 0, sizeof(struct dnet_config));

	cfg.sock_type = SOCK_STREAM;
	cfg.proto = IPPROTO_TCP;
	cfg.wait_timeout = 60*60;
	check_logger.log_mask = DNET_LOG_ERROR | DNET_LOG_INFO;
	cfg.check_timeout = 60;

	memcpy(&rem, &cfg, sizeof(struct dnet_config));
	memset(&tm, 0, sizeof(tm));

	memset(&r, 0, sizeof(r));

	while ((ch = getopt(argc, argv, "DN:f:n:t:FMRm:w:l:r:h")) != -1) {
		switch (ch) {
			case 'N':
				cfg.ns = optarg;
				cfg.nsize = strlen(optarg);
				break;
			case 'f':
				file = optarg;
				break;
			case 'n':
				r.thread_num = atoi(optarg);
				break;
			case 't':
				if (!strptime(optarg, "%F %T", &tm)) {
					fprintf(stderr, "Invalid timestamp string\n");
					check_usage(argv[0]);
					return -EINVAL;
				}
				r.timestamp = mktime(&tm);
				break;
			case 'D':
				r.flags |= DNET_CHECK_DRY_RUN;
				break;
			case 'M':
				r.flags |= DNET_CHECK_MERGE;
				break;
			case 'F':
				r.flags |= DNET_CHECK_FULL;
				break;
			case 'R':
				r.flags |= DNET_CHECK_DELETE;
				break;
			case 'm':
				check_logger.log_mask = strtoul(optarg, NULL, 0);
				break;
			case 'w':
				cfg.check_timeout = cfg.wait_timeout = atoi(optarg);
				break;
			case 'l':
				logfile = optarg;
				break;
			case 'r':
				err = dnet_parse_addr(optarg, &rem);
				if (err)
					return err;
				have_remote = 1;
				break;
			case 'h':
			default:
				check_usage(argv[0]);
				return -1;
		}
	}

	if ((r.flags & DNET_CHECK_DELETE) && (r.flags & (DNET_CHECK_MERGE|DNET_CHECK_FULL))) {
		fprintf(stderr, "You can't specify -R and -M or -F at the same time!\n");
		return -1;
	}

	if (!have_remote) {
		fprintf(stderr, "No remote node specified to route requests.\n");
		return -ENOENT;
	}

	log = fopen(logfile, "a");
	if (!log) {
		err = -errno;
		fprintf(stderr, "Failed to open log file %s: %s.\n", logfile, strerror(errno));
		return err;
	}

	check_logger.log_private = log;
	check_logger.log = dnet_common_log;
	cfg.log = &check_logger;

	n = dnet_node_create(&cfg);
	if (!n)
		return -1;

	rem.join = DNET_NO_ROUTE_LIST;
	err = dnet_add_state(n, &rem);
	if (err)
		return err;

	req = &r;
	if (file) {
		req = dnet_check_gen_request(n, &r, file);
		if (!req)
			return -EINVAL;
	}

	return dnet_request_check(n, req);
}
