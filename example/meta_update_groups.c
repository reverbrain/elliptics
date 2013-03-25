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
			"  -G group:group...      - groups to upload matadata to\n"
			"  -w timeout             - wait timeout in seconds\n"
			"  -r addr:port:family    - connect to this remote node\n"
			"  -m level               - log level\n"
			"  -l log                 - log file\n"
			, p);
	exit(-1);
}

int main(int argc, char *argv[])
{
	int ch, err;
	char *logfile = "/dev/stderr";
	char *name = NULL;
	FILE *log;
	int *groups, group_num = 0;
	int *newgroups, newgroup_num = 0;
	unsigned char trans_id[DNET_ID_SIZE], *id = NULL;
	struct dnet_config cfg;
	char *remote_addr = NULL;
	int remote_port, remote_family;
	struct dnet_node *n;
	struct dnet_session *s;
	struct dnet_id raw;
	struct dnet_meta_container mc;
	struct dnet_metadata_control mctl;
	struct dnet_meta *m;
	char *ns = NULL;
	int nsize = 0;

	memset(&cfg, 0, sizeof(cfg));

	cfg.wait_timeout = 10;
	meta_logger.log_level = DNET_LOG_INFO;

	while ((ch = getopt(argc, argv, "N:g:G:w:I:n:r:m:l:h")) != -1) {
		switch (ch) {
			case 'N':
				ns = optarg;
				nsize = strlen(optarg);
				break;
			case 'r':
				err = dnet_parse_addr(optarg, &remote_port, &remote_family);
				if (err)
					return err;
				remote_addr = optarg;
				break;
			case 'w':
				cfg.wait_timeout = atoi(optarg);
				break;
			case 'l':
				logfile = optarg;
				break;
			case 'm':
				meta_logger.log_level = strtoul(optarg, NULL, 0);
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
			case 'G':
				newgroup_num = dnet_parse_groups(optarg, &newgroups);
				if (newgroup_num <= 0)
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

	if (id && group_num <= 0) {
		fprintf(stderr, "You must specify groups\n");
		meta_usage(argv[0]);
	}

	if (newgroup_num <= 0) {
		fprintf(stderr, "You must specify new groups\n");
		meta_usage(argv[0]);
	}

	log = fopen(logfile, "a");
	if (!log) {
		err = -errno;
		fprintf(stderr, "Failed to open log file %s: %s.\n", logfile, strerror(errno));
		goto err_out_exit;
	}

	meta_logger.log_private = log;
	meta_logger.log = dnet_common_log;
	cfg.log = &meta_logger;

	n = dnet_node_create(&cfg);
	if (!n)
		goto err_out_exit;

	s = dnet_session_create(n);
	if (!s)
		goto err_out_destroy_node;

	err = dnet_session_set_ns(s, ns, nsize);
	if (err)
		goto err_out_destroy;

	err = dnet_add_state(n, remote_addr, remote_port, remote_family, 0);
	if (err)
		goto err_out_free_ns;

	dnet_session_set_groups(s, groups, group_num);

	/* Read meta */
	memset(&raw, 0, sizeof(struct dnet_id));
	if (!name) {
		dnet_setup_id(&raw, groups[0], id);
		err = dnet_read_meta(s, &mc, NULL, 0, &raw);
	} else {
		err = dnet_transform(s, name, strlen(name), &raw);
		if (err) {
			fprintf(stderr, "dnet_transform failed, err=%d\n", err);
			goto err_out_free_ns;
		}
		err = dnet_read_meta(s, &mc, name, strlen(name), NULL);
	}

	if (err < 0) {
		fprintf(stderr, "Error during reading meta: %d\n", err);
		goto err_out_free_ns;
	}

	/* Prepare control structure for dnet_create_write_metadata */
	memset(&mctl, 0, sizeof(mctl));
	if (!name) {
		m = dnet_meta_search_cust(&mc, DNET_META_PARENT_OBJECT);
		dnet_convert_meta(m);
		mctl.obj = (char *)m->data;
		mctl.len = m->size;
		fprintf(stderr, "File name from meta: %.*s\n", mctl.len, mctl.obj);
	} else {
		mctl.obj = name;
		mctl.len = strlen(name);
	}

	mctl.groups = newgroups;
	mctl.group_num = newgroup_num;
	dnet_setup_id(&mctl.id, newgroups[0], (unsigned char *)&raw.id);

	/* Write new meta */
	dnet_session_set_groups(s, newgroups, newgroup_num);
	err = dnet_create_write_metadata(s, &mctl);
	if (err < 0) {
		fprintf(stderr, "Meta update failed, err=%d\n", err);
	} else {
		fprintf(stderr, "Meta was successfully updated in %d groups\n", err);
	}
	

err_out_free_ns:
	free(ns);
err_out_destroy:
	dnet_session_destroy(s);
err_out_destroy_node:
	dnet_node_destroy(n);
err_out_exit:
	return err;
}
