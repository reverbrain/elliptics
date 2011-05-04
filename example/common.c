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
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#include <netinet/in.h>

#include <elliptics/packet.h>
#include <elliptics/interface.h>

#include "common.h"

#define DNET_CONF_COMMENT	'#'
#define DNET_CONF_DELIM		'='
#define DNET_CONF_ADDR_DELIM	':'
#define DNET_CONF_TIME_DELIM	'.'

int dnet_parse_addr(char *addr, struct dnet_config *cfg)
{
	char *fam, *port;

	fam = strrchr(addr, DNET_CONF_ADDR_DELIM);
	if (!fam)
		goto err_out_print_wrong_param;
	*fam++ = 0;
	if (!fam)
		goto err_out_print_wrong_param;

	cfg->family = atoi(fam);

	port = strrchr(addr, DNET_CONF_ADDR_DELIM);
	if (!port)
		goto err_out_print_wrong_param;
	*port++ = 0;
	if (!port)
		goto err_out_print_wrong_param;

	memset(cfg->addr, 0, sizeof(cfg->addr));
	memset(cfg->port, 0, sizeof(cfg->port));

	snprintf(cfg->addr, sizeof(cfg->addr), "%s", addr);
	snprintf(cfg->port, sizeof(cfg->port), "%s", port);

	return 0;

err_out_print_wrong_param:
	fprintf(stderr, "Wrong address parameter '%s', should be 'addr%cport%cfamily'.\n",
				addr, DNET_CONF_ADDR_DELIM, DNET_CONF_ADDR_DELIM);
	return -EINVAL;
}

int dnet_parse_groups(char *value, int **groupsp)
{
	int len = strlen(value), i, num = 0, start = 0, pos = 0;
	char *ptr = value;
	int *groups;

	if (sscanf(value, "auto%d", &num) == 1) {
		*groupsp = NULL;
		return num;
	}

	for (i=0; i<len; ++i) {
		if (value[i] == DNET_CONF_ADDR_DELIM)
			start = 0;
		else if (!start) {
			start = 1;
			num++;
		}
	}

	if (!num) {
		fprintf(stderr, "no groups found\n");
		return -ENOENT;
	}

	groups = malloc(sizeof(int) * num);
	if (!groups)
		return -ENOMEM;

	memset(groups, 0, num * sizeof(int));

	start = 0;
	for (i=0; i<len; ++i) {
		if (value[i] == DNET_CONF_ADDR_DELIM) {
			value[i] = '\0';
			if (start) {
				groups[pos] = atoi(ptr);
				pos++;
				start = 0;
			}
		} else if (!start) {
			ptr = &value[i];
			start = 1;
		}
	}

	if (start) {
		groups[pos] = atoi(ptr);
		pos++;
	}

	*groupsp = groups;
	return pos;
}

int dnet_parse_numeric_id(char *value, unsigned char *id)
{
	unsigned char ch[5];
	unsigned int i, len = strlen(value);

	memset(id, 0, DNET_ID_SIZE);

	if (len/2 > DNET_ID_SIZE)
		len = DNET_ID_SIZE * 2;

	ch[0] = '0';
	ch[1] = 'x';
	ch[4] = '\0';
	for (i=0; i<len / 2; i++) {
		ch[2] = value[2*i + 0];
		ch[3] = value[2*i + 1];

		id[i] = (unsigned char)strtol((const char *)ch, NULL, 16);
	}

	if (len & 1) {
		ch[2] = value[2*i + 0];
		ch[3] = '0';

		id[i] = (unsigned char)strtol((const char *)ch, NULL, 16);
	}

	return 0;
}

void dnet_common_log(void *priv, uint32_t mask, const char *msg)
{
	char str[64];
	struct tm tm;
	struct timeval tv;
	FILE *stream = priv;

	if (!stream)
		stream = stdout;

	gettimeofday(&tv, NULL);
	localtime_r((time_t *)&tv.tv_sec, &tm);
	strftime(str, sizeof(str), "%F %R:%S", &tm);

	fprintf(stream, "%s.%06lu %ld/%4d %1x: %s", str, tv.tv_usec, dnet_get_id(), getpid(), mask, msg);
	fflush(stream);
}

void dnet_syslog(void *priv __attribute__ ((unused)), uint32_t mask, const char *msg)
{
	int prio = LOG_DEBUG;
	char str[64];
	struct tm tm;
	struct timeval tv;

	if (mask & DNET_LOG_ERROR)
		prio = LOG_ERR;
	if (mask & DNET_LOG_INFO)
		prio = LOG_INFO;

	gettimeofday(&tv, NULL);
	localtime_r((time_t *)&tv.tv_sec, &tm);
	strftime(str, sizeof(str), "%F %R:%S", &tm);

	syslog(prio, "%s.%06lu %ld/%4d %1x: %s", str, tv.tv_usec, dnet_get_id(), getpid(), mask, msg);
}

static void dnet_common_convert_adata(void *adata, struct dnet_io_attr *ioattr)
{
	/*
	 * This is a bit ugly block, since we break common code to update inner data...
	 * But parentally it lived in the place where this was appropriate, and even now
	 * it is used the way this processing is needed.
	 */

	if (adata) {
		struct dnet_attr *a = adata;

		if (a->cmd == DNET_CMD_WRITE) {
			struct dnet_io_attr *io = (struct dnet_io_attr *)(a + 1);

			memcpy(io->parent, ioattr->parent, DNET_ID_SIZE);
			memcpy(io->id, ioattr->id, DNET_ID_SIZE);

			dnet_convert_io_attr(io);
		}
	}
}

static int dnet_common_send_upload_transactions(struct dnet_node *n, struct dnet_io_control *ctl,
		void *adata, uint32_t asize)
{
	int err = 0;

	dnet_common_convert_adata(adata, &ctl->io);

	err = dnet_trans_create_send_all(n, ctl);
	if (err <= 0)
		goto err_out_exit;

err_out_exit:
	return err;
}

int dnet_common_write_object(struct dnet_node *n, struct dnet_id *id,
		void *adata, uint32_t asize, int history_only,
		void *data, uint64_t size, struct timespec *ts,
		int (* complete)(struct dnet_net_state *, struct dnet_cmd *, struct dnet_attr *, void *), void *priv,
		uint32_t ioflags)
{
	struct dnet_io_control ctl;

	memset(&ctl, 0, sizeof(struct dnet_io_control));

	ctl.data = data;
	ctl.fd = -1;

	ctl.complete = complete;
	ctl.priv = priv;

	if (!history_only) {
		ctl.adata = adata;
		ctl.asize = asize;
	}

	ctl.cflags = DNET_FLAGS_NEED_ACK;
	ctl.cmd = DNET_CMD_WRITE;
	ctl.aflags = 0;

	/*
	 * We want to store transaction logs to get modification time.
	 */
	ctl.io.flags = ioflags;
	ctl.io.size = size;
	ctl.io.offset = 0;

	if (ts)
		ctl.ts = *ts;

	memcpy(&ctl.id, id, sizeof(struct dnet_id));
	memcpy(ctl.io.id, ctl.id.id, DNET_ID_SIZE);

	memcpy(ctl.io.parent, ctl.io.id, DNET_ID_SIZE);

	return dnet_common_send_upload_transactions(n, &ctl, adata, asize);
}

int dnet_common_add_remote_addr(struct dnet_node *n, struct dnet_config *main_cfg, char *orig_addr)
{
	char *a;
	char *addr, *p;
	int added = 0, err;
	struct dnet_config cfg;

	if (!orig_addr)
		return 0;

	a = strdup(orig_addr);
	if (!a) {
		err = -ENOMEM;
		goto err_out_exit;
	}

	addr = a;

	while (addr) {
		p = strchr(addr, ' ');
		if (p)
			*p++ = '\0';

		memcpy(&cfg, main_cfg, sizeof(struct dnet_config));

		err = dnet_parse_addr(addr, &cfg);
		if (err) {
			dnet_log_raw(n, DNET_LOG_ERROR, "Failed to parse addr '%s': %d.\n", addr, err);
			goto next;
		}

		err = dnet_add_state(n, &cfg);
		if (err)
			goto next;

		added++;

		if (!p)
			break;

next:
		addr = p;

		while (addr && *addr && isspace(*addr))
			addr++;
	}

	free(a);

	if (!added) {
		err = 0;
		dnet_log_raw(n, DNET_LOG_ERROR, "No remote addresses added. Continue to work though.\n");
		goto err_out_exit;
	}

	return 0;

err_out_exit:
	return err;
}

int dnet_common_prepend_data(struct timespec *ts, uint64_t size, void *buf, int *bufsize)
{
	void *orig = buf;
	struct dnet_common_embed *e = buf;
	uint64_t *edata = (uint64_t *)e->data;

	if (*bufsize < (int)(sizeof(struct dnet_common_embed) + sizeof(uint64_t)) * 2)
		return -ENOBUFS;

	e->size = sizeof(uint64_t) * 2;
	e->type = DNET_FCGI_EMBED_TIMESTAMP;
	e->flags = 0;
	dnet_common_convert_embedded(e);

	edata[0] = dnet_bswap64(ts->tv_sec);
	edata[1] = dnet_bswap64(ts->tv_nsec);

	buf += sizeof(struct dnet_common_embed) + sizeof(uint64_t) * 2;

	e = buf;
	e->size = size;
	e->type = DNET_FCGI_EMBED_DATA;
	e->flags = 0;
	dnet_common_convert_embedded(e);

	buf += sizeof(struct dnet_common_embed);

	*bufsize = buf - orig;
	return 0;
}

#define dnet_map_log(n, mask, fmt, a...) do { if ((n)) dnet_log_raw((n), mask, fmt, ##a); else fprintf(stderr, fmt, ##a); } while (0)

int dnet_map_history(struct dnet_node *n, char *file, struct dnet_history_map *map)
{
	int err;
	struct stat st;

	map->fd = open(file, O_RDWR);
	if (map->fd < 0) {
		err = -errno;
		dnet_map_log(n, DNET_LOG_ERROR, "Failed to open history file '%s': %s [%d].\n",
				file, strerror(errno), errno);
		goto err_out_exit;
	}

	err = fstat(map->fd, &st);
	if (err) {
		err = -errno;
		dnet_map_log(n, DNET_LOG_ERROR, "Failed to stat history file '%s': %s [%d].\n",
				file, strerror(errno), errno);
		goto err_out_close;
	}

	if (st.st_size % (int)sizeof(struct dnet_history_entry)) {
		dnet_map_log(n, DNET_LOG_ERROR, "Corrupted history file '%s', "
				"its size %llu must be multiple of %zu.\n",
				file, (unsigned long long)st.st_size,
				sizeof(struct dnet_history_entry));
		err = -EINVAL;
		goto err_out_close;
	}
	map->size = st.st_size;

	map->ent = mmap(NULL, map->size, PROT_READ | PROT_WRITE, MAP_SHARED, map->fd, 0);
	if (map->ent == MAP_FAILED) {
		err = -errno;
		dnet_map_log(n, DNET_LOG_ERROR, "Failed to mmap history file '%s': %s [%d].\n",
				file, strerror(errno), errno);
		goto err_out_close;
	}

	map->num = map->size / sizeof(struct dnet_history_entry);

	dnet_map_log(n, DNET_LOG_NOTICE, "Mapped %ld entries in '%s'.\n", map->num, file);

	return 0;

err_out_close:
	close(map->fd);
err_out_exit:
	return err;
}

void dnet_unmap_history(struct dnet_node *n, struct dnet_history_map *map)
{
	munmap(map->ent, map->size);
	close(map->fd);
}

