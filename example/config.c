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
#include <malloc.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#include "elliptics/packet.h"
#include "elliptics/interface.h"

#include "common.h"
#include "backends.h"

#ifdef HAVE_SMACK_SUPPORT
int dnet_smack_backend_init(void);
void dnet_smack_backend_exit(void);
#endif

#ifndef __unused
#define __unused	__attribute__ ((unused))
#endif

/*
 * Config parser is single-threaded.
 * No locks and simultaneous access from different threads.
 */

#define DNET_CONF_COMMENT	'#'
#define DNET_CONF_DELIMITER	'='

static char *dnet_skip_line(char *line)
{
	int len = strlen(line), i;

	for (i=0; i<len; ++i) {
		if (line[i] == DNET_CONF_COMMENT)
			return NULL;
		if (isspace(line[i]))
			continue;

		return &line[i];
	}

	return NULL;
}

static struct dnet_log dnet_backend_logger;
char *dnet_logger_value;

static struct dnet_config dnet_cfg_state;
static char *dnet_cfg_remotes;
static int dnet_daemon_mode;

static int dnet_simple_set(struct dnet_config_backend *b __unused, char *key, char *str)
{
	unsigned long value = strtoul(str, NULL, 0);

	if (!strcmp(key, "log_level"))
		dnet_backend_logger.log_level = value;
	else if (!strcmp(key, "wait_timeout"))
		dnet_cfg_state.wait_timeout = value;
	else if (!strcmp(key, "check_timeout"))
		dnet_cfg_state.check_timeout = value;
	else if (!strcmp(key, "stall_count"))
		dnet_cfg_state.stall_count = value;
	else if (!strcmp(key, "join"))
		dnet_cfg_state.flags |= value ? DNET_CFG_JOIN_NETWORK : 0;
	else if (!strcmp(key, "flags"))
		dnet_cfg_state.flags |= (value & ~DNET_CFG_JOIN_NETWORK);
	else if (!strcmp(key, "daemon"))
		dnet_daemon_mode = value;
	else if (!strcmp(key, "io_thread_num"))
		dnet_cfg_state.io_thread_num = value;
	else if (!strcmp(key, "nonblocking_io_thread_num"))
		dnet_cfg_state.nonblocking_io_thread_num = value;
	else if (!strcmp(key, "net_thread_num"))
		dnet_cfg_state.net_thread_num = value;
	else if (!strcmp(key, "bg_ionice_class"))
		dnet_cfg_state.bg_ionice_class = value;
	else if (!strcmp(key, "bg_ionice_prio"))
		dnet_cfg_state.bg_ionice_prio = value;
	else if (!strcmp(key, "removal_delay"))
		dnet_cfg_state.removal_delay = value;
	else if (!strcmp(key, "server_net_prio"))
		dnet_cfg_state.server_prio = value;
	else if (!strcmp(key, "client_net_prio"))
		dnet_cfg_state.client_prio = value;
	else if (!strcmp(key, "oplock_num"))
		dnet_cfg_state.oplock_num = value;
	else
		return -1;

	return 0;
}

static int dnet_set_group(struct dnet_config_backend *b __unused, char *key __unused, char *value)
{
	dnet_cfg_state.group_id = strtoul(value, NULL, 0);
	return 0;
}

static int dnet_set_addr(struct dnet_config_backend *b __unused, char *key __unused, char *value)
{
	return dnet_parse_addr(value, &dnet_cfg_state);
}

static int dnet_set_remote_addrs(struct dnet_config_backend *b __unused, char *key __unused, char *value)
{
	dnet_cfg_remotes = strdup(value);
	if (!dnet_cfg_remotes)
		return -ENOMEM;

	return 0;
}

static int dnet_set_srw(struct dnet_config_backend *b __unused, char *key, char *value)
{
	char **ptr = NULL;

	if (!strcmp(key, "srw_config"))
		ptr = &dnet_cfg_state.srw.config;

	if (ptr) {
		free(*ptr);
		*ptr = strdup(value);
		if (!*ptr)
			return -ENOMEM;
	}

	return 0;
}

static int dnet_set_malloc_options(struct dnet_config_backend *b __unused, char *key __unused, char *value)
{
	int err, thr = atoi(value);

	err = mallopt(M_MMAP_THRESHOLD, thr);
	if (err < 0) {
		dnet_backend_log(DNET_LOG_ERROR, "Failed to set mmap threshold to %d: %s\n", thr, strerror(errno));
		return err;
	}

	dnet_backend_log(DNET_LOG_INFO, "Set mmap threshold to %d.\n", thr);
	return 0;
}

static int dnet_set_auth_cookie(struct dnet_config_backend *b __unused, char *key __unused, char *value)
{
	snprintf(dnet_cfg_state.cookie, DNET_AUTH_COOKIE_SIZE, "%s", value);
	return 0;
}

static int dnet_set_backend(struct dnet_config_backend *b, char *key __unused, char *value);
	
int dnet_set_log(struct dnet_config_backend *b __unused, char *key __unused, char *value)
{
	char *tmp;

	tmp = strdup(value);
	if (!tmp)
		return -ENOMEM;

	if (dnet_logger_value)
		free(dnet_logger_value);

	dnet_logger_value = tmp;

	if (!strcmp(dnet_logger_value, "syslog")) {
		openlog("elliptics", 0, LOG_USER);

		dnet_backend_logger.log_private = NULL;
		dnet_backend_logger.log = dnet_syslog;
	} else {
		FILE *log, *old = dnet_backend_logger.log_private;
		int err;

		log = fopen(dnet_logger_value, "a");
		if (!log) {
			err = -errno;
			fprintf(stderr, "cnf: failed to open log file '%s': %s\n", dnet_logger_value, strerror(errno));
			return err;
		}

		dnet_backend_logger.log_private = log;
		dnet_backend_logger.log = dnet_common_log;

		dnet_common_log(log, 0xff, "Reopened log file\n");

		if (old) {
			dnet_common_log(old, 0xff, "Reopened log file\n");
			fclose(old);
		}
	}

	dnet_cfg_state.log = &dnet_backend_logger;
	return 0;
}

static int dnet_set_history_env(struct dnet_config_backend *b __unused, char *key __unused, char *value)
{
	snprintf(dnet_cfg_state.history_env, sizeof(dnet_cfg_state.history_env), "%s", value);
	return 0;
}

static int dnet_set_cache_size(struct dnet_config_backend *b __unused, char *key __unused, char *value)
{
	dnet_cfg_state.cache_size = strtoull(value, NULL, 0);
	return 0;
}

static struct dnet_config_entry dnet_cfg_entries[] = {
	{"mallopt_mmap_threshold", dnet_set_malloc_options},
	{"log_level", dnet_simple_set},
	{"wait_timeout", dnet_simple_set},
	{"check_timeout", dnet_simple_set},
	{"stall_count", dnet_simple_set},
	{"group", dnet_set_group},
	{"addr", dnet_set_addr},
	{"remote", dnet_set_remote_addrs},
	{"join", dnet_simple_set},
	{"flags", dnet_simple_set},
	{"backend", dnet_set_backend},
	{"daemon", dnet_simple_set},
	{"log", dnet_set_log},
	{"history", dnet_set_history_env},
	{"io_thread_num", dnet_simple_set},
	{"nonblocking_io_thread_num", dnet_simple_set},
	{"net_thread_num", dnet_simple_set},
	{"bg_ionice_class", dnet_simple_set},
	{"bg_ionice_prio", dnet_simple_set},
	{"removal_delay", dnet_simple_set},
	{"auth_cookie", dnet_set_auth_cookie},
	{"server_net_prio", dnet_simple_set},
	{"client_net_prio", dnet_simple_set},
	{"oplock_num", dnet_simple_set},
	{"srw_config", dnet_set_srw},
	{"cache_size", dnet_set_cache_size},
};

static struct dnet_config_entry *dnet_cur_cfg_entries = dnet_cfg_entries;
static int dnet_cur_cfg_size = ARRAY_SIZE(dnet_cfg_entries);

static struct dnet_config_backend *dnet_cfg_backend, *dnet_cfg_current_backend;
static int dnet_cfg_backend_num;

static int dnet_set_backend(struct dnet_config_backend *current_backend __unused, char *key __unused, char *value)
{
	struct dnet_config_backend *b;
	int i;

	for (i=0; i<dnet_cfg_backend_num; ++i) {
		b = &dnet_cfg_backend[i];

		if (!strcmp(value, b->name)) {
			if (b->size) {
				b->data = malloc(b->size);
				if (!b->data)
					return -ENOMEM;
				memset(b->data, 0, b->size);
			}

			b->log = dnet_cfg_state.log;

			dnet_cur_cfg_entries = b->ent;
			dnet_cur_cfg_size = b->num;
			dnet_cfg_current_backend = b;

			return 0;
		}
	}

	return -ENOENT;
}

int dnet_backend_register(struct dnet_config_backend *b)
{
	dnet_cfg_backend = realloc(dnet_cfg_backend, (dnet_cfg_backend_num + 1) * sizeof(struct dnet_config_backend));
	if (!dnet_cfg_backend)
		return -ENOMEM;

	memcpy(&dnet_cfg_backend[dnet_cfg_backend_num], b, sizeof(struct dnet_config_backend));
	dnet_cfg_backend_num++;

	return 0;
}

struct dnet_node *dnet_parse_config(char *file, int mon)
{
	FILE *f;
	int buf_size = 1024 * 1024;
	char *buf, *ptr, *value, *key;
	int err, i, len;
	int line_num = 0;
	struct dnet_node *n;

	sigset_t sig;
	sigfillset(&sig);
	pthread_sigmask(SIG_BLOCK, &sig, NULL);
	sigprocmask(SIG_BLOCK, &sig, NULL);

	f = fopen(file, "r");
	if (!f) {
		err = -errno;
		fprintf(stderr, "cnf: failed to open config file '%s': %s.\n", file, strerror(errno));
		goto err_out_exit;
	}

	buf = malloc(buf_size);
	if (!buf) {
		err = -ENOMEM;
		goto err_out_close;
	}

	dnet_backend_logger.log_level = DNET_LOG_ERROR;
	dnet_backend_logger.log = dnet_common_log;
	dnet_cfg_state.log = &dnet_backend_logger;

	err = dnet_file_backend_init();
	if (err)
		goto err_out_free_buf;
 
	err = dnet_eblob_backend_init();
	if (err)
		goto err_out_file_exit;

#ifdef HAVE_SMACK_SUPPORT
	err = dnet_smack_backend_init();
	if (err)
		goto err_out_eblob_exit;
#endif
	while (1) {
		ptr = fgets(buf, buf_size, f);
		if (!ptr) {
			if (feof(f))
				break;

			err = -errno;
			dnet_backend_log(DNET_LOG_ERROR, "cnf: failed to read config file '%s': %s.\n", file, strerror(errno));
			goto err_out_free;
		}

		line_num++;

		ptr = dnet_skip_line(ptr);
		if (!ptr)
			continue;

		len = strlen(ptr);

		if (len > 1) {
			if (ptr[len - 1] == '\r' || ptr[len - 1] == '\n') {
				ptr[len - 1] = '\0';
				len--;
			}
		}

		if (len > 2) {
			if (ptr[len - 2] == '\r' || ptr[len - 2] == '\n') {
				ptr[len - 2] = '\0';
				len--;
			}
		}

		key = value = NULL;
		err = 0;
		for (i=0; i<len; ++i) {
			if (isspace(ptr[i])) {
				if (key)
					ptr[i] = '\0';
				continue;
			}

			if (!key) {
				key = ptr + i;
				continue;
			}

			if (!value) {
				if (ptr[i] == DNET_CONF_DELIMITER) {
					value = ptr;
					ptr[i] = '\0';
					continue;
				}
				
				if (ptr[i] ==  DNET_CONF_COMMENT) {
					key = value = NULL;
					break;
				}

				continue;
			} else {
				value = ptr + i;
				break;
			}

			key = value = NULL;
			err = -EINVAL;
			fprintf(stderr, "cnf: error in line %d: %s.\n", line_num, ptr);
			goto err_out_free;
		}

		if (err)
			goto err_out_free;
		if (!key || !value)
			continue;

		for (i=0; i<dnet_cur_cfg_size; ++i) {
			if (!strcmp(key, dnet_cur_cfg_entries[i].key)) {
				err = dnet_cur_cfg_entries[i].callback(dnet_cfg_current_backend, key, value);
				dnet_backend_log(DNET_LOG_INFO, "backend: %s, key: %s, value: %s, err: %d\n",
						(dnet_cfg_current_backend) ? dnet_cfg_current_backend->name : "root level",
						ptr, value, err);
				if (err)
					goto err_out_free;

				break;
			}
		}
	}

	if (!dnet_cfg_current_backend) {
		err = -EINVAL;
		goto err_out_free;
	}

	if (dnet_daemon_mode && !mon)
		dnet_background();

	err = dnet_cfg_current_backend->init(dnet_cfg_current_backend, &dnet_cfg_state);
	if (err)
		goto err_out_free;

	fclose(f);
	f = NULL;

	n = dnet_server_node_create(&dnet_cfg_state);
	if (!n) {
		/* backend cleanup is already called */
		goto err_out_free;
	}

	err = dnet_common_add_remote_addr(n, &dnet_cfg_state, dnet_cfg_remotes);
	if (err)
		goto err_out_node_destroy;

	return n;

err_out_node_destroy:
	dnet_server_node_destroy(n);
err_out_free:
	free(dnet_cfg_remotes);

#ifdef HAVE_SMACK_SUPPORT
	dnet_smack_backend_exit();
err_out_eblob_exit:
#endif
	dnet_eblob_backend_exit();
err_out_file_exit:
	dnet_file_backend_exit();
err_out_free_buf:
	free(buf);
err_out_close:
	if (f)
		fclose(f);
err_out_exit:
	return NULL;
}

int dnet_backend_check_log_level(int level)
{
	struct dnet_log *l = dnet_cfg_state.log;

	return (l->log && (l->log_level >= level));
}

void dnet_backend_log_raw(int level, const char *format, ...)
{
	va_list args;
	char buf[1024];
	struct dnet_log *l = dnet_cfg_state.log;
	int buflen = sizeof(buf);

	if (!dnet_backend_check_log_level(level))
		return;

	va_start(args, format);
	vsnprintf(buf, buflen, format, args);
	buf[buflen-1] = '\0';
	l->log(l->log_private, level, buf);
	va_end(args);
}
