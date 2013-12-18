/*
 * Copyright 2008+ Evgeniy Polyakov <zbr@ioremap.net>
 *
 * This file is part of Elliptics.
 *
 * Elliptics is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Elliptics is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public License
 * along with Elliptics.  If not, see <http://www.gnu.org/licenses/>.
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
#include "elliptics/backends.h"

#include "../library/elliptics.h"

#include "common.h"

#ifndef __unused
#define __unused	__attribute__ ((unused))
#endif

/*
 * Config parser is single-threaded.
 * No locks and simultaneous access from different threads.
 */

#define DNET_CONF_COMMENT	'#'
#define DNET_CONF_DELIMITER	'='

extern __thread uint32_t trace_id;

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

static struct dnet_config_data *dnet_cur_cfg_data;

static int dnet_simple_set(struct dnet_config_backend *b __unused, char *key, char *str)
{
	unsigned long value = strtoul(str, NULL, 0);

	if (!strcmp(key, "log_level"))
		dnet_cur_cfg_data->backend_logger.log_level = value;
	else if (!strcmp(key, "wait_timeout"))
		dnet_cur_cfg_data->cfg_state.wait_timeout = value;
	else if (!strcmp(key, "check_timeout"))
		dnet_cur_cfg_data->cfg_state.check_timeout = value;
	else if (!strcmp(key, "cache_sync_timeout"))
		dnet_cur_cfg_data->cfg_state.cache_sync_timeout = value;
	else if (!strcmp(key, "stall_count"))
		dnet_cur_cfg_data->cfg_state.stall_count = value;
	else if (!strcmp(key, "join"))
		dnet_cur_cfg_data->cfg_state.flags |= value ? DNET_CFG_JOIN_NETWORK : 0;
	else if (!strcmp(key, "flags"))
		dnet_cur_cfg_data->cfg_state.flags |= (value & ~DNET_CFG_JOIN_NETWORK);
	else if (!strcmp(key, "daemon"))
		dnet_cur_cfg_data->daemon_mode = value;
	else if (!strcmp(key, "io_thread_num"))
		dnet_cur_cfg_data->cfg_state.io_thread_num = value;
	else if (!strcmp(key, "nonblocking_io_thread_num"))
		dnet_cur_cfg_data->cfg_state.nonblocking_io_thread_num = value;
	else if (!strcmp(key, "net_thread_num"))
		dnet_cur_cfg_data->cfg_state.net_thread_num = value;
	else if (!strcmp(key, "bg_ionice_class"))
		dnet_cur_cfg_data->cfg_state.bg_ionice_class = value;
	else if (!strcmp(key, "bg_ionice_prio"))
		dnet_cur_cfg_data->cfg_state.bg_ionice_prio = value;
	else if (!strcmp(key, "removal_delay"))
		dnet_cur_cfg_data->cfg_state.removal_delay = value;
	else if (!strcmp(key, "server_net_prio"))
		dnet_cur_cfg_data->cfg_state.server_prio = value;
	else if (!strcmp(key, "client_net_prio"))
		dnet_cur_cfg_data->cfg_state.client_prio = value;
	else if (!strcmp(key, "indexes_shard_count"))
		dnet_cur_cfg_data->cfg_state.indexes_shard_count = value;
	else if (!strcmp(key, "monitor_port"))
		dnet_cur_cfg_data->cfg_state.monitor_port = value;
	else
		return -1;

	return 0;
}

static int dnet_set_group(struct dnet_config_backend *b __unused, char *key __unused, char *value)
{
	dnet_cur_cfg_data->cfg_state.group_id = strtoul(value, NULL, 0);
	return 0;
}

struct dnet_addr_wrap {
	struct dnet_addr	addr;
	int			addr_group;
};

static int dnet_addr_wrap_compare(const void *a1, const void *a2)
{
	const struct dnet_addr_wrap *w1 = a1;
	const struct dnet_addr_wrap *w2 = a2;

	return w1->addr_group - w2->addr_group;
}

static int dnet_set_addr(struct dnet_config_backend *b __unused, char *key __unused, char *value)
{
	struct dnet_addr_wrap *wrap = NULL;
	int wrap_num = 0;
	struct dnet_addr addr;
	int err = -EINVAL, i;

	while (value) {
		char *ptr, *addr_group_ptr, *delim_ptr;
		int addr_group = -1;

		while (value && *value) {
			if (isalnum(*value))
				break;

			value++;
		}

		if (!value || !*value)
			break;

		ptr = strchr(value, ' ');
		if (ptr)
			*ptr++ = '\0';

		delim_ptr = strrchr(value, DNET_CONF_ADDR_DELIM);
		if (!delim_ptr)
			break;

		addr_group_ptr = strrchr(value, '-');
		if (addr_group_ptr && addr_group_ptr > delim_ptr) {
			*addr_group_ptr++ = '\0';

			addr_group = atoi(addr_group_ptr);
		}

		err = dnet_parse_addr(value, &dnet_cur_cfg_data->cfg_state.port, &dnet_cur_cfg_data->cfg_state.family);
		if (!err) {
			addr.addr_len = sizeof(addr.addr);
			addr.family = dnet_cur_cfg_data->cfg_state.family;
			err = dnet_fill_addr(&addr, value, dnet_cur_cfg_data->cfg_state.port, SOCK_STREAM, IPPROTO_TCP);
			if (err) {
				dnet_backend_log(DNET_LOG_ERROR, "backend: %s: could not parse addr: %s [%d]\n", value, strerror(-err), err);
			} else {
				dnet_backend_log(DNET_LOG_INFO, "backend: parsed addr: %s, addr-group: %d\n",
						dnet_server_convert_dnet_addr(&addr), addr_group);

				wrap = realloc(wrap, (wrap_num + 1) * sizeof(struct dnet_addr_wrap));
				if (!wrap) {
					err = -ENOMEM;
					goto err_out_exit;
				}

				wrap[wrap_num].addr = addr;
				wrap[wrap_num].addr_group = addr_group;
				wrap_num++;
			}

			if (addr_group == -1)
				break;
		}

		value = ptr;
	}

	if (wrap_num) {
		qsort(wrap, wrap_num, sizeof(struct dnet_addr_wrap), dnet_addr_wrap_compare);

		dnet_cur_cfg_data->cfg_addrs = malloc(sizeof(struct dnet_addr) * wrap_num);
		if (!dnet_cur_cfg_data->cfg_addrs) {
			err = -ENOMEM;
			goto err_out_free;
		}

		for (i = 0; i < wrap_num; ++i)
			dnet_cur_cfg_data->cfg_addrs[i] = wrap[i].addr;
		dnet_cur_cfg_data->cfg_addr_num = wrap_num;

		err = 0;
	}

err_out_free:
	free(wrap);
err_out_exit:
	return err;
}

static int dnet_set_remote_addrs(struct dnet_config_backend *b __unused, char *key __unused, char *value)
{
	dnet_cur_cfg_data->cfg_remotes = strdup(value);
	if (!dnet_cur_cfg_data->cfg_remotes)
		return -ENOMEM;

	return 0;
}

static int dnet_set_srw(struct dnet_config_backend *b __unused, char *key, char *value)
{
	char **ptr = NULL;

	if (!strcmp(key, "srw_config"))
		ptr = &dnet_cur_cfg_data->cfg_state.srw.config;

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
	snprintf(dnet_cur_cfg_data->cfg_state.cookie, DNET_AUTH_COOKIE_SIZE, "%s", value);
	return 0;
}

static int dnet_set_backend(struct dnet_config_backend *b, char *key __unused, char *value);

static int dnet_node_set_log_impl(struct dnet_config_data *data, char *value)
{
	char *tmp;

	tmp = strdup(value);
	if (!tmp)
		return -ENOMEM;

	if (data->logger_value)
		free(data->logger_value);

	data->logger_value = tmp;

	if (!strcmp(data->logger_value, "syslog")) {
		openlog("elliptics", 0, LOG_USER);

		data->backend_logger.log_private = NULL;
		data->backend_logger.log = dnet_syslog;
	} else {
		FILE *log, *old = data->backend_logger.log_private;
		int err;

		log = fopen(data->logger_value, "a");
		if (!log) {
			err = -errno;
			fprintf(stderr, "cnf: failed to open log file '%s': %s\n", data->logger_value, strerror(errno));
			return err;
		}

		data->backend_logger.log_private = log;
		data->backend_logger.log = dnet_common_log;

		dnet_common_log(log, -1, "Reopened log file\n");

		if (old) {
			dnet_common_log(old, -1, "Reopened log file\n");
			fclose(old);
		}
	}

	data->cfg_state.log = &data->backend_logger;
	return 0;
}

int dnet_node_reset_log(struct dnet_node *n)
{
	return dnet_node_set_log_impl(n->config_data, n->config_data->logger_value);
}

static int dnet_set_log(struct dnet_config_backend *b __unused, char *key __unused, char *value)
{
	return dnet_node_set_log_impl(dnet_cur_cfg_data, value);
}

static int dnet_set_history_env(struct dnet_config_backend *b __unused, char *key __unused, char *value)
{
	snprintf(dnet_cur_cfg_data->cfg_state.history_env, sizeof(dnet_cur_cfg_data->cfg_state.history_env), "%s", value);
	return 0;
}

static int dnet_set_cache_size(struct dnet_config_backend *b __unused, char *key __unused, char *value)
{
	dnet_cur_cfg_data->cfg_state.cache_size = strtoull(value, NULL, 0);
	return 0;
}

static int dnet_set_caches_number(struct dnet_config_backend *b __unused, char *key __unused, char *value)
{
	dnet_cur_cfg_data->cfg_state.caches_number = strtoull(value, NULL, 0);
	return 0;
}

static int dnet_set_cache_pages_proportions(struct dnet_config_backend *b __unused, char *key __unused, char *value)
{
	unsigned int cache_pages_number = 0;
	unsigned int *proportions = NULL;

	char *current = value;

	while (*current != '\0') {
		while (*current != '\0' && !isdigit(*current)) {
			++current;
		}
		if (*current == '\0') {
			break;
		}

		unsigned int proportion = 0;
		while (*current != '\0' && isdigit(*current)) {
			proportion = proportion * 10 + (*current - '0');
			++current;
		}

		++cache_pages_number;
		proportions = (unsigned int *) realloc(proportions, cache_pages_number * sizeof(unsigned int));
		proportions[cache_pages_number - 1] = proportion;
	}

	if (!cache_pages_number) {
		return -EINVAL;
	}

	dnet_cur_cfg_data->cfg_state.cache_pages_number = cache_pages_number;

	if (dnet_cur_cfg_data->cfg_state.cache_pages_proportions) {
		free(dnet_cur_cfg_data->cfg_state.cache_pages_proportions);
	}
	dnet_cur_cfg_data->cfg_state.cache_pages_proportions = proportions;
	return 0;
}

static struct dnet_config_entry dnet_cfg_entries[] = {
	{"mallopt_mmap_threshold", dnet_set_malloc_options},
	{"log_level", dnet_simple_set},
	{"wait_timeout", dnet_simple_set},
	{"check_timeout", dnet_simple_set},
	{"cache_sync_timeout", dnet_simple_set},
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
	{"srw_config", dnet_set_srw},
	{"cache_size", dnet_set_cache_size},
	{"caches_number", dnet_set_caches_number},
	{"cache_pages_proportions", dnet_set_cache_pages_proportions},
	{"indexes_shard_count", dnet_simple_set},
	{"monitor_port", dnet_simple_set},
};

static int dnet_set_backend(struct dnet_config_backend *current_backend __unused, char *key __unused, char *value)
{
	struct dnet_config_backend *b;
	int i;

	for (i=0; i<dnet_cur_cfg_data->cfg_backend_num; ++i) {
		b = &dnet_cur_cfg_data->cfg_backend[i];

		if (!strcmp(value, b->name)) {
			if (b->size) {
				b->data = malloc(b->size);
				if (!b->data)
					return -ENOMEM;
				memset(b->data, 0, b->size);
			}

			b->log = dnet_cur_cfg_data->cfg_state.log;

			dnet_cur_cfg_data->cfg_entries = b->ent;
			dnet_cur_cfg_data->cfg_size = b->num;
			dnet_cur_cfg_data->cfg_current_backend = b;

			return 0;
		}
	}

	return -ENOENT;
}

int dnet_backend_register(struct dnet_config_backend *b)
{
	dnet_cur_cfg_data->cfg_backend = realloc(dnet_cur_cfg_data->cfg_backend, (dnet_cur_cfg_data->cfg_backend_num + 1) * sizeof(struct dnet_config_backend));
	if (!dnet_cur_cfg_data->cfg_backend)
		return -ENOMEM;

	memcpy(&dnet_cur_cfg_data->cfg_backend[dnet_cur_cfg_data->cfg_backend_num], b, sizeof(struct dnet_config_backend));
	dnet_cur_cfg_data->cfg_backend_num++;

	return 0;
}

struct dnet_node *dnet_parse_config(const char *file, int mon)
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

	dnet_cur_cfg_data = malloc(sizeof(struct dnet_config_data));
	if (!dnet_cur_cfg_data) {
		err = -ENOMEM;
		goto err_out_exit;
	}

	memset(dnet_cur_cfg_data, 0, sizeof(struct dnet_config_data));
	dnet_cur_cfg_data->cfg_entries = dnet_cfg_entries;
	dnet_cur_cfg_data->cfg_size = ARRAY_SIZE(dnet_cfg_entries);

	f = fopen(file, "r");
	if (!f) {
		err = -errno;
		fprintf(stderr, "cnf: failed to open config file '%s': %s.\n", file, strerror(errno));
		goto err_out_free_data;
	}

	buf = malloc(buf_size);
	if (!buf) {
		err = -ENOMEM;
		goto err_out_close;
	}

	dnet_cur_cfg_data->backend_logger.log_level = DNET_LOG_DEBUG;
	dnet_cur_cfg_data->backend_logger.log = dnet_common_log;
	dnet_cur_cfg_data->cfg_state.log = &dnet_cur_cfg_data->backend_logger;
	dnet_cur_cfg_data->cfg_state.caches_number = DNET_DEFAULT_CACHES_NUMBER;
	dnet_cur_cfg_data->cfg_state.cache_pages_number = DNET_DEFAULT_CACHE_PAGES_NUMBER;
	dnet_cur_cfg_data->cfg_state.cache_pages_proportions = (unsigned int*) calloc(DNET_DEFAULT_CACHE_PAGES_NUMBER, sizeof(unsigned int));

	if (!dnet_cur_cfg_data->cfg_state.cache_pages_proportions) {
		err = -ENOMEM;
		goto err_out_free_buf;
	}

	for (i = 0; i < DNET_DEFAULT_CACHE_PAGES_NUMBER; ++i) {
		dnet_cur_cfg_data->cfg_state.cache_pages_proportions[i] = 1;
	}

	err = dnet_file_backend_init();
	if (err)
		goto err_out_free_proportions;

#ifdef HAVE_MODULE_BACKEND_SUPPORT
	err = dnet_module_backend_init();
#endif
	if (err)
		goto err_out_file_exit;

	err = dnet_eblob_backend_init();
	if (err)
		goto err_out_module_exit;

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

		for (i=0; i<dnet_cur_cfg_data->cfg_size; ++i) {
			if (!strcmp(key, dnet_cur_cfg_data->cfg_entries[i].key)) {
				err = dnet_cur_cfg_data->cfg_entries[i].callback(dnet_cur_cfg_data->cfg_current_backend, key, value);
				dnet_backend_log(DNET_LOG_INFO, "backend: %s, key: %s, value: %s, err: %d\n",
						(dnet_cur_cfg_data->cfg_current_backend) ? dnet_cur_cfg_data->cfg_current_backend->name : "root level",
						ptr, value, err);
				if (err)
					goto err_out_free;

				break;
			}
		}
	}

	if (!dnet_cur_cfg_data->cfg_current_backend) {
		err = -EINVAL;
		goto err_out_free;
	}

	if (dnet_cur_cfg_data->daemon_mode && !mon)
		dnet_background();

	err = dnet_cur_cfg_data->cfg_current_backend->init(dnet_cur_cfg_data->cfg_current_backend, &dnet_cur_cfg_data->cfg_state);
	if (err)
		goto err_out_free;

	fclose(f);
	f = NULL;

	if (!dnet_cur_cfg_data->cfg_addr_num) {
		dnet_backend_log(DNET_LOG_ERROR, "No local address specified, exiting.\n");
		goto err_out_free;
	}

	n = dnet_server_node_create(dnet_cur_cfg_data, &dnet_cur_cfg_data->cfg_state, dnet_cur_cfg_data->cfg_addrs, dnet_cur_cfg_data->cfg_addr_num);
	if (!n) {
		/* backend cleanup is already called */
		goto err_out_free;
	}

	err = dnet_common_add_remote_addr(n, dnet_cur_cfg_data->cfg_remotes);
	if (err)
		goto err_out_node_destroy;

	free(buf);

	return n;

err_out_node_destroy:
	// dnet_cur_cfg_data will be destroyed by dnet_server_node_destroy
	dnet_cur_cfg_data = NULL;
	dnet_server_node_destroy(n);
err_out_free:
	if (dnet_cur_cfg_data)
		free(dnet_cur_cfg_data->cfg_remotes);

//err_out_eblob_exit:
	dnet_eblob_backend_exit();
err_out_module_exit:
#ifdef HAVE_MODULE_BACKEND_SUPPORT
	dnet_module_backend_exit();
#endif
err_out_file_exit:
	dnet_file_backend_exit();
err_out_free_proportions:
	if (dnet_cur_cfg_data)
		free(dnet_cur_cfg_data->cfg_state.cache_pages_proportions);
err_out_free_buf:
	free(buf);
err_out_close:
	if (f)
		fclose(f);
err_out_free_data:
	free(dnet_cur_cfg_data);
err_out_exit:
	dnet_cur_cfg_data = NULL;
	return NULL;
}

int dnet_backend_check_log_level(int level)
{
	struct dnet_log *l = dnet_cur_cfg_data->cfg_state.log;

	return (l->log && ((l->log_level >= level) || (trace_id & DNET_TRACE_BIT)));
}

void dnet_backend_log_raw(int level, const char *format, ...)
{
	va_list args;
	char buf[1024];
	struct dnet_log *l = dnet_cur_cfg_data->cfg_state.log;
	int buflen = sizeof(buf);

	if (!dnet_backend_check_log_level(level))
		return;

	va_start(args, format);
	vsnprintf(buf, buflen, format, args);
	buf[buflen-1] = '\0';
	l->log(l->log_private, level, buf);
	va_end(args);
}
