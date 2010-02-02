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
#include <sys/mman.h>
#include <sys/wait.h>

#include <errno.h>
#include <ctype.h>
#include <dirent.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "dnet/packet.h"
#include "dnet/interface.h"

#include "common.h"
#include "hash.h"

#define DNET_CHECK_TOKEN_STRING			" 	"
#define DNET_CHECK_NEWLINE_TOKEN_STRING		"\r\n"
#define DNET_CHECK_INNER_TOKEN_STRING		","

static char dnet_check_tmp_dir[128] = "/tmp";

struct dnet_check_worker
{
	struct dnet_node			*n;

	int					id;
	pthread_t				tid;

	int					wait_num;
	int					object_present, object_missing;

	pthread_cond_t				wait_cond;
	pthread_mutex_t				wait_lock;
};

struct dnet_check_request
{
	unsigned char			id[DNET_ID_SIZE];
	unsigned char 			addr[DNET_ID_SIZE];
	unsigned int			type;
	unsigned int			present;

	struct dnet_check_worker	*w;
};

#define DNET_CHECK_EXT_INIT	"dnet_check_ext_init"
#define DNET_CHECK_EXT_EXIT	"dnet_check_ext_exit"
#define DNET_CHECK_EXT_MERGE	"dnet_check_ext_merge"

static void *(* dnet_check_ext_init)(char *data);
static void (* dnet_check_ext_exit)(void *priv);
static int (* dnet_check_ext_merge)(void *priv, char *path, int start, int end,
		struct dnet_check_request *req, int num, int update_existing);
static void *dnet_check_ext_private;
static void *dnet_check_ext_library;

static FILE *dnet_check_file;
static pthread_mutex_t dnet_check_file_lock = PTHREAD_MUTEX_INITIALIZER;

#if 0
#define dnet_check_wait(worker,condition)					\
({										\
	pthread_mutex_lock(&(worker)->wait_lock);				\
	while (!(condition)) 							\
		pthread_cond_wait(&(worker)->wait_cond, &(worker->wait_lock));	\
	pthread_mutex_unlock(&(worker)->wait_lock);				\
})

static void dnet_check_wakeup(struct dnet_check_worker *w, int present)
{
	pthread_mutex_lock(&w->wait_lock);
	if (present)
		w->object_present++;
	else
		w->object_missing++;
	pthread_cond_broadcast(&w->wait_cond);
	pthread_mutex_unlock(&w->wait_lock);
}
#endif

static int dnet_check_log_init(struct dnet_node *n, struct dnet_config *cfg, char *log)
{
	int err;
	FILE *old = cfg->log_private;

	if (log) {
		cfg->log_private = fopen(log, "a");
		if (!cfg->log_private) {
			err = -errno;
			fprintf(stderr, "Failed to open log file %s: %s.\n", log, strerror(errno));
			return err;
		}
	}

	if (n)
		dnet_log_init(n, cfg->log_private, cfg->log_mask, dnet_common_log);

	if (log && old)
		fclose(old);

	return 0;
}

static int dnet_check_add_hash(struct dnet_node *n, char *hash)
{
	struct dnet_crypto_engine *e;
	int err = -ENOMEM;

	e = malloc(sizeof(struct dnet_crypto_engine));
	if (!e)
		goto err_out_exit;
	memset(e, 0, sizeof(struct dnet_crypto_engine));

	err = dnet_crypto_engine_init(e, hash);
	if (err) {
		dnet_log_raw(n, DNET_LOG_ERROR, "Failed to initialize crypto engine '%s': %d.\n",
				hash, err);
		goto err_out_free;
	}

	err = dnet_add_transform(n, e, e->name, e->init, e->update, e->final, e->cleanup);
	if (err) {
		dnet_log_raw(n, DNET_LOG_ERROR, "Failed to add transformation engine '%s': %d.\n",
				hash, err);
		goto err_out_exit;
	}

	return 0;

err_out_free:
	free(e);
err_out_exit:
	return err;
}

static int dnet_check_process_hash_string(struct dnet_node *n, char *hash)
{
	char local_hash[128];
	char *token, *saveptr;
	int err, added = 0;

	snprintf(local_hash, sizeof(local_hash), "%s", hash);

	hash = local_hash;

	while (1) {
		token = strtok_r(hash, DNET_CHECK_INNER_TOKEN_STRING, &saveptr);
		if (!token)
			break;

		err = dnet_check_add_hash(n, token);
		if (err)
			return err;

		hash = NULL;
		added++;
	}

	return added;
}

static int dnet_update_copies(struct dnet_check_worker *worker,	char *obj,
		int start, int end, struct dnet_check_request *requests, int num,
		int update_existing)
{
	struct dnet_node *n = worker->n;
	struct dnet_check_request *existing = NULL, *req;
	char file[128];
	int i, err, to_upload = 0, error = 0;

	for (i=0; i<num; ++i) {
		req = &requests[i];

		if (!req->present)
			to_upload++;
		else
			existing = req;
	}

	if (!existing && !update_existing) {
		dnet_log_raw(n, DNET_LOG_ERROR, "'%s': there are no object copies in the storage.\n", obj);
		err = -ENOENT;
		goto err_out_exit;
	}

	if (!to_upload && !update_existing) {
		dnet_log_raw(n, DNET_LOG_INFO, "'%s': all %d copies are in the storage.\n", obj, num);
		err = 0;
		goto err_out_exit;
	}

	if (update_existing) {
		snprintf(file, sizeof(file), "%s", obj);
	} else {
		snprintf(file, sizeof(file), "%s/%s", dnet_check_tmp_dir,
				dnet_dump_id_len(existing->id, DNET_ID_SIZE));

		err = dnet_read_file(n, file, existing->id, 0, 0, 0);
		if (err) {
			dnet_log_raw(n, DNET_LOG_ERROR, "'%s': failed to download a copy: %d.\n", obj, err);
			goto err_out_exit;
		}
	}

	if (dnet_check_ext_merge) {
		error = dnet_check_ext_merge(dnet_check_ext_private, file, start, end,
				requests, num, update_existing);
	} else {
		for (i=0; i<num; ++i) {
			req = &requests[i];

			if (req->present && !update_existing)
				continue;

			err = dnet_write_file(n, file, req->id, 0, 0, existing->type);
			if (err) {
				dnet_log_raw(n, DNET_LOG_ERROR, "'%s': failed to upload a '%s' copy: %d.\n",
						obj, dnet_dump_id_len(req->id, DNET_ID_SIZE), err);
				error = err;
				continue;
			}
		}
	}

	if (!update_existing)
		unlink(file);

	return error;

err_out_exit:
	return err;
}

static int dnet_check_number_of_copies(struct dnet_check_worker *w, char *obj, int start, int end,
		int hash_num, unsigned int type, int update_existing)
{
	struct dnet_node *n = w->n;
	int pos = 0;
	int err, i;
	struct dnet_check_request *requests, *req;
	char file[128];

	req = requests = malloc(hash_num * sizeof(struct dnet_check_request));
	if (!requests)
		return -ENOMEM;
	memset(requests, 0, hash_num * sizeof(struct dnet_check_request));

	while (1) {
		unsigned int rsize = DNET_ID_SIZE;

		req = &requests[pos];
		req->w = w;
		req->type = type;

		err = dnet_transform(n, &obj[start], end - start, req->id, req->addr, &rsize, &pos);
		if (err) {
			if (err > 0)
				break;
			continue;
		}

		snprintf(file, sizeof(file), "%s/%s",
				dnet_check_tmp_dir, dnet_dump_id_len(req->id, DNET_ID_SIZE));
		err = dnet_read_file(n, file, req->id, 0, 1, 1);
		if (err < 0) {
			dnet_log_raw(n, DNET_LOG_ERROR, "%s: failed to read history file: %d.\n",
					dnet_dump_id(req->id), err);
			continue;
		}

		req->present = 1;
	}

	for (i=0; i<hash_num; ++i) {
		req = &requests[i];
		dnet_log_raw(n, DNET_LOG_INFO, "obj: '%s' %d/%d, id: %s: type: %d, "
				"history present: %d, update existing: %d.\n",
				obj, start, end, dnet_dump_id_len(req->id, DNET_ID_SIZE),
				req->type, req->present, update_existing);
	}

	err = dnet_update_copies(w, obj, start, end, requests, hash_num, update_existing);
	
	for (i=0; i<hash_num; ++i) {
		req = &requests[i];

		snprintf(file, sizeof(file), "%s/%s.history",
				dnet_check_tmp_dir, dnet_dump_id_len(req->id, DNET_ID_SIZE));
		unlink(file);
	}

	free(requests);
	return err;
}

static int dnet_check_split_range(char *str, int **ptrs, int num)
{
	char *token, *saveptr, *tmp;
	char *buf = strdup(str);
	int i;

	if (!buf)
		return -ENOMEM;

	tmp = buf;
	for (i=0; i<num; ++i) {
		token = strtok_r(tmp, DNET_CHECK_INNER_TOKEN_STRING, &saveptr);
		if (!token)
			break;

		*ptrs[i] = (int)strtol(token, NULL, 0);
		tmp = NULL;
	}

	if (i != num) {
		for (; i<num; ++i)
			*ptrs[i] = 0;
		return -EINVAL;
	}

	free(buf);

	return 0;
}

static void *dnet_check_process(void *data)
{
	struct dnet_check_worker *w = data;
	char buf[4096], *tmp, *saveptr, *token, *hash, *obj;
	char current_hash[128];
	int size = sizeof(buf);
	int err, type, hash_num = 0, obj_len;
	int start, end, update_existing;
	int *ptrs[] = {&start, &end, &update_existing};

	while (1) {
		pthread_mutex_lock(&dnet_check_file_lock);
		tmp = fgets(buf, size, dnet_check_file);
		pthread_mutex_unlock(&dnet_check_file_lock);
		if (!tmp)
			break;

		token = strtok_r(tmp, DNET_CHECK_TOKEN_STRING, &saveptr);
		if (!token)
			continue;
		type = strtoul(token, NULL, 0);

		tmp = NULL;
		token = strtok_r(tmp, DNET_CHECK_TOKEN_STRING, &saveptr);
		if (!token)
			continue;
		err = dnet_check_split_range(token, ptrs, ARRAY_SIZE(ptrs));
		if (err)
			continue;

		tmp = NULL;
		token = strtok_r(tmp, DNET_CHECK_TOKEN_STRING, &saveptr);
		if (!token)
			continue;
		hash = token;

		tmp = NULL;
		token = strtok_r(tmp, DNET_CHECK_TOKEN_STRING, &saveptr);
		if (!token)
			continue;
		obj = token;

		/*
		 * Cut off remaining newlines
		 */
		saveptr = NULL;
		token = strtok_r(token, DNET_CHECK_NEWLINE_TOKEN_STRING, &saveptr);

		if (strcmp(current_hash, hash)) {
			dnet_cleanup_transform(w->n);

			err = dnet_check_process_hash_string(w->n, hash);
			if (err < 0) {
				current_hash[0] = '\0';
				err = 0;
			} else
				snprintf(current_hash, sizeof(current_hash), "%s", hash);

			hash_num = err;
		}

		obj_len = strlen(obj);

		if (!end)
			end = obj_len;

		if (end - start > obj_len) {
			dnet_log_raw(w->n, DNET_LOG_ERROR, "obj: '%s', obj_len: %d, start: %d, end: %d: "
					"requested start/end pair is outside of the object.\n",
					obj, obj_len, start, end);
			continue;
		}

		err = dnet_check_number_of_copies(w, obj, start, end, hash_num, type, update_existing);
	}

	return NULL;
}

static int dnet_check_setup_ext(char *library, char *library_data)
{
	void *lib, *tmp;
	int err = -EINVAL, i;
	struct tmp_check {
		char *symbol;
		void *ptr;
	} checks[] = {
		{DNET_CHECK_EXT_INIT, &dnet_check_ext_init},
		{DNET_CHECK_EXT_EXIT, &dnet_check_ext_exit},
		{DNET_CHECK_EXT_MERGE, &dnet_check_ext_merge},
	};

	lib = dlopen(library, RTLD_NOW);
	if (!lib) {
		fprintf(stderr, "Failed to dlopen external library '%s': %s.\n",
				library, dlerror());
		goto err_out_exit;
	}

	for (i=0; i<(signed)ARRAY_SIZE(checks); ++i) {
		tmp = dlsym(lib, checks[i].symbol);
		if (!tmp) {
			fprintf(stderr, "Failed to get '%s' symbol from '%s'.\n",
					checks[i].symbol, library);
			goto err_out_close;
		}

		memcpy(checks[i].ptr, tmp, sizeof(void *));
	}

	tmp = dnet_check_ext_init(library_data);
	if (!tmp) {
		fprintf(stderr, "Failed to initialize external library '%s' using '%s'.\n",
				library, library_data);
		goto err_out_close;
	}

	dnet_check_ext_private = tmp;
	dnet_check_ext_library = lib;

	return 0;

err_out_close:
	dlclose(lib);
err_out_exit:
	return err;
}

static void dnet_check_log_help(char *p)
{
	fprintf(stderr, "Usage: %s <options>\n"
			"  -n num                  - number of worker threads.\n"
			"  -m num                  - log mask.\n"
			"  -l log                  - output log file.\n"
			"  -f file                 - input file with log information about objects to be checked.\n"
			"  -r addr:port:family     - remote node to connect to.\n"
			"  -t dir                  - directory to store temporal object.\n"
			"  -e library              - external library which should export merge callbacks.\n"
			"  -E string               - some obscure string used by external library's intialization code.\n"
			"  -h                      - this help.\n", p);
}

int main(int argc, char *argv[])
{
	int ch, err = 0, i, j, worker_num = 1;
	struct dnet_check_worker *w, *workers;
	struct dnet_config cfg, *remotes = NULL;
	char *file = NULL, *log = "/dev/stderr";
	char *library = NULL, *library_data = NULL;
	char log_file[256];
	char local_addr[] = "0.0.0.0:0:2";
	int added_remotes = 0;

	memset(&cfg, 0, sizeof(struct dnet_config));

	cfg.sock_type = SOCK_STREAM;
	cfg.proto = IPPROTO_TCP;
	cfg.wait_timeout = 60;
	cfg.log_mask = DNET_LOG_ERROR;
	cfg.log = dnet_common_log;
	cfg.io_thread_num = 2;
	cfg.max_pending = 256;

	while ((ch = getopt(argc, argv, "e:E:t:n:m:l:f:r:h")) != -1) {
		switch (ch) {
			case 'e':
				library = optarg;
				break;
			case 'E':
				library_data = optarg;
				break;
			case 't':
				snprintf(dnet_check_tmp_dir, sizeof(dnet_check_tmp_dir), "%s", optarg);
				break;
			case 'n':
				worker_num = atoi(optarg);
				break;
			case 'm':
				cfg.log_mask = strtol(optarg, NULL, 0);
				break;
			case 'l':
				log = optarg;
				break;
			case 'f':
				file = optarg;
				break;
			case 'r':
				err = dnet_parse_addr(optarg, &cfg);
				if (err)
					break;
				added_remotes++;
				remotes = realloc(remotes, added_remotes * sizeof(struct dnet_config));
				if (!remotes)
					return -ENOMEM;
				memcpy(&remotes[added_remotes - 1], &cfg, sizeof(struct dnet_config));

				break;
			case 'h':
			default:
				dnet_check_log_help(argv[0]);
				return -1;
		}
	}

	dnet_parse_addr(local_addr, &cfg);

	if (!added_remotes) {
		err = -EINVAL;
		fprintf(stderr, "No remote nodes added, exiting.\n");
		goto out_exit;
	}

	if (!file) {
		err = -EINVAL;
		fprintf(stderr, "No input file, exiting.\n");
		goto out_exit;
	}

	dnet_check_file = fopen(file, "r");
	if (!dnet_check_file) {
		err = -errno;
		fprintf(stderr, "Failed to open file '%s': %s.\n", file, strerror(errno));
		goto out_exit;
	}

	if (library) {
		err = dnet_check_setup_ext(library, library_data);
		if (err)
			goto out_close_check_file;
	}

	workers = malloc(sizeof(struct dnet_check_worker) * worker_num);
	if (!workers) {
		err = -ENOMEM;
		goto out_ext_cleanup;
	}
	memset(workers, 0, sizeof(struct dnet_check_worker) * worker_num);

	for (i=0; i<worker_num; ++i) {
		int added = 0;

		w = &workers[i];

		w->id = i;

		pthread_cond_init(&w->wait_cond, NULL);
		pthread_mutex_init(&w->wait_lock, NULL);

		snprintf(log_file, sizeof(log_file), "%s.%d", log, w->id);
		cfg.log_private = NULL;
		dnet_check_log_init(NULL, &cfg, log_file);

		w->n = dnet_node_create(&cfg);
		if (!w->n) {
			err = -ENOMEM;
			goto out_join;
		}

		added = 0;
		for (j=0; j<added_remotes; ++j) {
			err = dnet_add_state(w->n, &remotes[j]);
			if (!err)
				added++;
		}

		if (!added) {
			dnet_log_raw(w->n, DNET_LOG_ERROR, "No remote nodes added, exiting.\n");
			err = -ENOENT;
			goto out_join;
		}

		err = pthread_create(&w->tid, NULL, dnet_check_process, w);
		if (err) {
			err = -err;
			dnet_log_raw(w->n, DNET_LOG_ERROR, "Failed to start new processing thread: %d.\n", err);
			goto out_join;
		}
	}

out_join:
	for (i=0; i<worker_num; ++i) {
		w = &workers[i];

		if (w->tid)
			pthread_join(w->tid, NULL);

		if (w->n)
			dnet_node_destroy(w->n);
	}
	free(workers);
	if (cfg.log_private)
		fclose(cfg.log_private);

out_ext_cleanup:
	if (dnet_check_ext_library) {
		dnet_check_ext_exit(dnet_check_ext_private);
		dlclose(dnet_check_ext_library);
	}
out_close_check_file:
	fclose(dnet_check_file);
out_exit:
	free(remotes);
	return err;
}
