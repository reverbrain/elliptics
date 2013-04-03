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

#define _XOPEN_SOURCE 600

#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/types.h>

#include <ctype.h>
#include <fcntl.h>
#include <errno.h>
#include <limits.h>
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
static char *default_log = "/dev/stderr";

static void check_usage(char *p)
{
	fprintf(stderr, "Usage: %s\n"
			" -r addr:port:family  - adds remote node\n"
			" -l log               - log file. Default: disabled\n"
			" -d                   - work as daemon\n"
			" -w timeout           - wait timeout in seconds used to wait for content sync.\n"
			" -m level             - log events level\n"
			" -M                   - do not check copies in other groups, run only merge check\n"
			" -R                   - only delete objects marked as REMOVED\n"
			" -D                   - dry run - do not perform any action, just update counters\n"
			" -t timestamp         - only check those objects, which were previously checked BEFORE this time\n"
			"                          format: year-month-day hours:minutes:seconds like \"2011-01-13 23:15:00\"\n"
			" -u timestamp         - only check those objects, which were created after this time, format as above\n"
			" -U timestamp         - only check those objects, which were created before this time, format as above\n"
			" -g group:group...    - override groups with replicas\n"
			" -n num               - number of checking threads to start by the server\n"
			" -f file              - file with list of objects to check\n"
			" -b num               - start checking for data in blob number <num>\n"
			" -B num               - number of blobs to check objects in\n"
			" -h                   - this help\n"
	       , p);
}

static int dnet_check_fill(struct dnet_session *s, struct dnet_check_request *r, char *data, int num)
{
	struct dnet_node *n = dnet_session_get_node(s);
	int i;
	char *cur;
	struct dnet_id id;
	struct dnet_id *rid = (struct dnet_id *)(r + 1);
	char tmp_str[DNET_ID_SIZE*2+1];

	for (i=0; i<num; ++i) {
		cur = strchr(data, '\n');

		if (!cur || !*cur)
			break;

		dnet_transform(s, data, cur - data, &id);

		rid[i] = id;
		dnet_convert_id(&rid[i]);

		dnet_log_raw(n, DNET_LOG_NOTICE, "check: %s\n", dnet_dump_id_len_raw(id.id, DNET_ID_SIZE, tmp_str));

		data = cur + 1;
	}

	return 0;
}

static struct dnet_check_request *dnet_check_gen_request(struct dnet_session *s, struct dnet_check_request *base, char *file)
{
	struct dnet_node *n = dnet_session_get_node(s);
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

	err = dnet_check_fill(s, r, data, num);
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
	int ch, err;
	struct dnet_node *n = NULL;
	struct dnet_config cfg;
	char *remote_addr = NULL;
	int remote_port = -1;
	int remote_family = -1;
	char *logfile = default_log;
	int daemonize = 0;
	FILE *log = NULL;
	struct dnet_check_request r, *req, *req2;
	struct tm tm;
	char *file = NULL;
	int group_num = 0, *groups;
	char *ns = NULL;
	int nsize = 0;
	struct dnet_session *s;

	memset(&cfg, 0, sizeof(struct dnet_config));

	cfg.wait_timeout = INT_MAX;
	check_logger.log_level = DNET_LOG_INFO;
	cfg.check_timeout = 60;

	memset(&tm, 0, sizeof(tm));

	memset(&r, 0, sizeof(r));

	r.thread_num = 1;

	while ((ch = getopt(argc, argv, "b:B:DN:f:n:t:u:U:MRm:w:l:dr:g:h")) != -1) {
		switch (ch) {
			case 'b':
				r.blob_start = atoi(optarg);
				break;
			case 'B':
				r.blob_num = atoi(optarg);
				break;
			case 'N':
				ns = optarg;
				nsize = strlen(optarg);
				break;
			case 'f':
				file = optarg;
				break;
			case 'n':
				r.thread_num = atoi(optarg);
				if (r.thread_num > 1)
					fprintf(stderr, "You are going to run your recovery process with %d threads, "
							"this can heavily screw up your system performance.\n", r.thread_num);
				break;
			case 't':
				if (!strptime(optarg, "%F %T", &tm)) {
					fprintf(stderr, "Invalid timestamp string in -t\n");
					check_usage(argv[0]);
					return -EINVAL;
				}
				r.timestamp = mktime(&tm);
				break;
			case 'u':
				if (!strptime(optarg, "%F %T", &tm)) {
					fprintf(stderr, "Invalid timestamp string in -u\n");
					check_usage(argv[0]);
					return -EINVAL;
				}
				r.updatestamp_start = mktime(&tm);
				break;
			case 'U':
				if (!strptime(optarg, "%F %T", &tm)) {
					fprintf(stderr, "Invalid timestamp string in -U\n");
					check_usage(argv[0]);
					return -EINVAL;
				}
				r.updatestamp_stop = mktime(&tm);
				break;
			case 'D':
				r.flags |= DNET_CHECK_DRY_RUN;
				break;
			case 'M':
				r.flags |= DNET_CHECK_MERGE;
				break;
//			case 'F':
//				r.flags |= DNET_CHECK_FULL;
//				break;
			case 'R':
				r.flags |= DNET_CHECK_DELETE;
				break;
			case 'm':
				check_logger.log_level = strtoul(optarg, NULL, 0);
				break;
			case 'w':
				cfg.check_timeout = cfg.wait_timeout = atoi(optarg);
				break;
			case 'l':
				logfile = optarg;
				break;
			case 'd':
				daemonize = 1;
				break;
			case 'r':
				err = dnet_parse_addr(optarg, &remote_port, &remote_family);
				if (err)
					return err;
				remote_addr = optarg;
				break;
			case 'g':
				group_num = dnet_parse_groups(optarg, &groups);
				if (group_num <= 0)
					return -1;
				break;
			case 'h':
			default:
				check_usage(argv[0]);
				return -1;
		}
	}

	if (!remote_addr) {
		fprintf(stderr, "No remote node specified to route requests.\n");
		return -ENOENT;
	}

	log = fopen(logfile, "a");
	if (!log) {
		err = -errno;
		fprintf(stderr, "Failed to open log file %s: %s.\n", logfile, strerror(errno));
		return err;
	}

	if (daemonize) {
		if (logfile == default_log) {
			fprintf(stderr, "You should specify log file for daemon mode\n");
		} else {
			dnet_background();
		}
	}

	check_logger.log_private = log;
	check_logger.log = dnet_common_log;
	cfg.log = &check_logger;

	n = dnet_node_create(&cfg);
	if (!n)
		return -1;

	err = dnet_add_state(n, remote_addr, remote_port, remote_family, DNET_CFG_NO_ROUTE_LIST);
	if (err)
		return err;

	s = dnet_session_create(n);
	if (!s)
		return -ENOMEM;

	err = dnet_session_set_ns(s, ns, nsize);
	if (err)
		return err;

	req = &r;
	if (file) {
		req = dnet_check_gen_request(s, &r, file);
		if (!req)
			return -EINVAL;
	}

	if (group_num > 0) {
		req2 = malloc(sizeof(struct dnet_check_request) + req->obj_num * sizeof(struct dnet_id) + group_num * sizeof(int));
		if (!req2)
			return -ENOMEM;

		memcpy(req2, req, sizeof(struct dnet_check_request) + req->obj_num * sizeof(struct dnet_id));
		memcpy((char *)req2 + sizeof(struct dnet_check_request) + req->obj_num * sizeof(struct dnet_id), groups,
				group_num * sizeof(int));
		req2->group_num = group_num;

		req = req2;
	}

	return dnet_request_check(s, req);
}
