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

#include "../common.h"
#include "../hash.h"

#include "common.h"

#define DNET_CHECK_EXT_INIT	"dnet_check_ext_init"
#define DNET_CHECK_EXT_EXIT	"dnet_check_ext_exit"
#define DNET_CHECK_EXT_MERGE	"dnet_check_ext_merge"

void *(* dnet_check_ext_init)(char *data);
void (* dnet_check_ext_exit)(void *priv);
int (* dnet_check_ext_merge)(void *priv, char *path, int start, int end,
		struct dnet_check_request *req, int num, int update_existing);
void *dnet_check_ext_private;
void *dnet_check_ext_library;

#define dnet_check_wait(worker,condition)					\
({										\
	pthread_mutex_lock(&(worker)->wait_lock);				\
	while (!(condition)) 							\
		pthread_cond_wait(&(worker)->wait_cond, &(worker->wait_lock));	\
	pthread_mutex_unlock(&(worker)->wait_lock);				\
})

#define dnet_check_wakeup(worker, doit)						\
({										\
 	int ______ret;								\
	pthread_mutex_lock(&(worker)->wait_lock);				\
 	______ret = (doit);							\
	pthread_cond_broadcast(&(worker)->wait_cond);					\
	pthread_mutex_unlock(&(worker)->wait_lock);				\
 	______ret;								\
})

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

int dnet_check_add_hash(struct dnet_node *n, char *hash)
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

int dnet_check_del_hash(struct dnet_node *n, char *hash)
{
	return dnet_remove_transform(n, hash, 1);
}

struct dnet_check_completion
{
	struct dnet_check_worker			*worker;
	uint64_t					write_offset;
};

static int dnet_check_trans_write(struct dnet_check_completion *complete, struct dnet_cmd *cmd, struct dnet_io_attr *io, void *data)
{
	struct dnet_check_worker *worker = complete->worker;
	struct dnet_node *n = worker->n;
	char file[256];
	char eid[2*DNET_ID_SIZE+1];
	int fd;
	ssize_t err;

	snprintf(file, sizeof(file), "%s/%s", dnet_check_tmp_dir, dnet_dump_id_len_raw(cmd->id, DNET_ID_SIZE, eid));
	fd = open(file, O_RDWR | O_TRUNC | O_CREAT, 0644);
	if (fd < 0) {
		err = -errno;
		dnet_log_raw(n, DNET_LOG_ERROR, "Failed to open transaction file '%s': %s.\n", file, strerror(errno));
		goto err_out_exit;
	}

	err = pwrite(fd, data, io->size, io->offset);
	if (err < 0) {
		err = -errno;
		dnet_log_raw(n, DNET_LOG_ERROR, "Failed to write transaction into file '%s': %s.\n", file, strerror(errno));
		goto err_out_close;
	}

	err = 0;
	dnet_log_raw(n, DNET_LOG_INFO, "%s: successfully written transaction into '%s', offset: %llu, size: %llu.\n",
			eid, file, (unsigned long long)io->offset, (unsigned long long)io->size);

err_out_close:
	close(fd);
err_out_exit:
	return err;
}

static int dnet_check_read_complete(struct dnet_net_state *state,
		struct dnet_cmd *cmd, struct dnet_attr *attr, void *priv)
{
	struct dnet_check_completion *complete = priv;
	struct dnet_check_worker *worker = complete->worker;
	struct dnet_node *n = worker->n;
	struct dnet_io_attr *io;
	void *data;
	int err = 0;

	if (!state || !cmd) {
		err = -EINVAL;
		goto out_wakeup;
	}

	err = cmd->status;
	dnet_log_raw(n, DNET_LOG_INFO, "%s: status: %d, last: %d.\n",
			dnet_dump_id(cmd->id), cmd->status, !(cmd->flags & DNET_FLAGS_MORE));

	if (err)
		goto out_exit;

	if (!(cmd->flags & DNET_FLAGS_MORE))
		goto out_wakeup;

	if (cmd->size <= sizeof(struct dnet_attr) + sizeof(struct dnet_io_attr)) {
		dnet_log_raw(n, DNET_LOG_ERROR, "%s: read completion error: wrong size: cmd_size: %llu, must be more than %zu.\n",
				dnet_dump_id(cmd->id), (unsigned long long)cmd->size,
				sizeof(struct dnet_attr) + sizeof(struct dnet_io_attr));
		err = -EINVAL;
		goto out_exit;
	}

	if (!attr) {
		dnet_log_raw(n, DNET_LOG_ERROR, "%s: no attributes but command size is not null.\n", dnet_dump_id(cmd->id));
		err = -EINVAL;
		goto out_exit;
	}

	io = (struct dnet_io_attr *)(attr + 1);
	data = io + 1;

	dnet_convert_attr(attr);
	dnet_convert_io_attr(io);

	dnet_log_raw(n, DNET_LOG_NOTICE, "%s: io: write_offset: %llu, offset: %llu, size: %llu.\n",
			dnet_dump_id(cmd->id), (unsigned long long)complete->write_offset,
			(unsigned long long)io->offset, (unsigned long long)io->size);

	return dnet_check_trans_write(complete, cmd, io, data);

out_wakeup:
	dnet_check_wakeup(worker, worker->wait_num++);
	free(complete);
out_exit:
	return err;
}

int dnet_check_read_transactions(struct dnet_check_worker *worker, struct dnet_check_request *req)
{
	struct dnet_node *n = worker->n;
	char file[256];
	int err;
	long i;
	struct dnet_history_map map;
	struct dnet_history_entry *e;
	struct dnet_io_control ctl;
	char eid[DNET_ID_SIZE*2 + 1];
	struct dnet_check_completion *c;

	dnet_dump_id_len_raw(req->id, DNET_ID_SIZE, eid);
	snprintf(file, sizeof(file), "%s/%s%s", dnet_check_tmp_dir, eid, DNET_HISTORY_SUFFIX);

	err = dnet_map_history(n, file, &map);
	if (err)
		goto err_out_exit;

	worker->wait_num = 0;

	for (i=0; i<map.num; ++i) {
		e = &map.ent[i];

		dnet_convert_history_entry(e);

		c = malloc(sizeof(struct dnet_check_completion));
		if (!c) {
			err = -ENOMEM;
			i--;
			goto err_out_wait;
		}

		c->write_offset = e->offset;
		c->worker = worker;

		memset(&ctl, 0, sizeof(struct dnet_io_control));

		ctl.fd = -1;
		ctl.complete = dnet_check_read_complete;
		ctl.priv = c;
		ctl.cmd = DNET_CMD_READ;
		ctl.cflags = DNET_FLAGS_NEED_ACK;

		ctl.io.flags = 0;
		ctl.io.offset = 0;
		ctl.io.size = 0;

		memcpy(ctl.io.origin, e->id, DNET_ID_SIZE);
		memcpy(ctl.io.id, e->id, DNET_ID_SIZE);
		memcpy(ctl.addr, e->id, DNET_ID_SIZE);

		dnet_log_raw(n, DNET_LOG_INFO, "%s: transaction: %s: offset: %8llu, size: %8llu.\n",
				eid, dnet_dump_id_len(e->id, DNET_ID_SIZE),
				(unsigned long long)e->offset, (unsigned long long)e->size);

		err = dnet_read_object(n, &ctl);
		if (err)
			goto err_out_wait;
	}

	dnet_check_wait(worker, worker->wait_num == map.num);

	dnet_unmap_history(n, &map);
	return 0;

err_out_wait:
	dnet_check_wait(worker, worker->wait_num == i);
err_out_exit:
	return err;
}

int dnet_check_cleanup_transactions(struct dnet_check_worker *w, struct dnet_check_request *existing)
{
	struct dnet_node *n = w->n;
	char file[256];
	int err;
	struct dnet_history_entry *e;
	struct dnet_history_map map;
	struct dnet_io_attr io;
	long i;
	char eid[DNET_ID_SIZE*2 + 1];

	snprintf(file, sizeof(file), "%s/%s%s", dnet_check_tmp_dir,
		dnet_dump_id_len_raw(existing->id, DNET_ID_SIZE, eid), DNET_HISTORY_SUFFIX);

	err = dnet_map_history(n, file, &map);
	if (err)
		goto err_out_exit;

	for (i=0; i<map.num; ++i) {
		io.size = 0;
		io.offset = 0;
		io.flags = 0;

		e = &map.ent[i];

		snprintf(file, sizeof(file), "%s/%s", dnet_check_tmp_dir,
			dnet_dump_id_len_raw(e->id, DNET_ID_SIZE, eid));

		unlink(file);
	}

	snprintf(file, sizeof(file), "%s/%s%s", dnet_check_tmp_dir,
		dnet_dump_id_len_raw(existing->id, DNET_ID_SIZE, eid), DNET_HISTORY_SUFFIX);
	unlink(file);

err_out_exit:
	return err;
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

int dnet_check_start(int argc, char *argv[], void *(* process)(void *data))
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

		err = pthread_create(&w->tid, NULL, process, w);
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

