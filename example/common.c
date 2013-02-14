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
#define DNET_CONF_TIME_DELIM	'.'

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

void dnet_common_log(void *priv, int level, const char *msg)
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

	fprintf(stream, "%s.%06lu %ld/%4d %1d: %s", str, tv.tv_usec, dnet_get_id(), getpid(), level, msg);
	fflush(stream);
}

void dnet_syslog(void *priv __attribute__ ((unused)), int level, const char *msg)
{
	int prio = LOG_DEBUG;
	char str[64];
	struct tm tm;
	struct timeval tv;

	if (level == DNET_LOG_ERROR)
		prio = LOG_ERR;
	if (level == DNET_LOG_INFO)
		prio = LOG_INFO;

	gettimeofday(&tv, NULL);
	localtime_r((time_t *)&tv.tv_sec, &tm);
	strftime(str, sizeof(str), "%F %R:%S", &tm);

	syslog(prio, "%s.%06lu %ld/%4d %1x: %s", str, tv.tv_usec, dnet_get_id(), getpid(), level, msg);
}

int dnet_common_add_remote_addr(struct dnet_node *n, struct dnet_config *main_cfg, char *orig_addr)
{
	char *a;
	char *addr, *p;
	int added = 0, err;
	char auto_str[] = "autodiscovery:";
	int auto_len = strlen(auto_str);
	int remote_port, remote_family;

	if (!orig_addr)
		return 0;

	a = strdup(orig_addr);
	if (!a) {
		err = -ENOMEM;
		goto err_out_exit;
	}

	addr = a;

	while (addr) {
		int autodescovery = 0;

		p = strchr(addr, ' ');
		if (p)
			*p++ = '\0';

		if (!strncmp(addr, auto_str, auto_len)) {
			addr[auto_len - 1] = '\0';
			addr += auto_len;
			autodescovery = 1;
		}

		err = dnet_parse_addr(addr, &remote_port, &remote_family);
		if (err) {
			dnet_log_raw(n, DNET_LOG_ERROR, "Failed to parse addr '%s': %d.\n", addr, err);
			goto next;
		}

		if (autodescovery) {
			err = dnet_discovery_add(n, addr, remote_port, remote_family);
			if (err)
				goto next;
		} else {
			err = dnet_add_state(n, addr, remote_port, remote_family, 0);
			if (err)
				goto next;
		}

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

#define dnet_map_log(n, level, fmt, a...) do { if ((n)) dnet_log_raw((n), level, fmt, ##a); else fprintf(stderr, fmt, ##a); } while (0)

int dnet_map_history(struct dnet_node *n, char *file, struct dnet_history_map *map)
{
	int err;
	struct stat st;

	map->fd = open(file, O_RDWR | O_CLOEXEC);
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

void dnet_unmap_history(struct dnet_node *n __attribute((unused)), struct dnet_history_map *map)
{
	munmap(map->ent, map->size);
	close(map->fd);
}

struct dnet_meta * dnet_meta_search_cust(struct dnet_meta_container *mc, uint32_t type)
{
	void *data = mc->data;
	uint32_t size = mc->size;
	struct dnet_meta m, *found = NULL;

	while (size) {
		if (size < sizeof(struct dnet_meta)) {
			fprintf(stderr, "Metadata size %u is too small, min %zu, searching for 0x%x.\n",
					size, sizeof(struct dnet_meta), type);
			break;
		}

		m = *(struct dnet_meta *)data;
		dnet_convert_meta(&m);

		if (m.size + sizeof(struct dnet_meta) > size) {
			fprintf(stderr, "Metadata entry broken: entry size %u, type: 0x%x, struct size: %zu, "
					"total size left: %u, searching for 0x%x.\n",
					m.size, m.type, sizeof(struct dnet_meta), size, type);
			break;
		}

		if (m.type == type) {
			found = data;
			break;
		}

		data += m.size + sizeof(struct dnet_meta);
		size -= m.size + sizeof(struct dnet_meta);
	}

	return found;
}

int dnet_background(void)
{
	pid_t pid;
	int fd;

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

	close(0);
	close(1);
	close(2);

	fd = open("/dev/null", O_RDWR);
	if (fd < 0) {
		fd = -errno;
		fprintf(stderr, "Can not open /dev/null: %d\n", fd);
		exit(fd);
	}

	dup2(fd, 0);
	dup2(fd, 1);
	dup2(fd, 2);

	return 0;
}

