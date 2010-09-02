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

#include "elliptics/packet.h"
#include "elliptics/interface.h"

#include "../common.h"
#include "../hash.h"

#include "common.h"

#define DNET_CHECK_EXT_INIT	"dnet_check_ext_init"
#define DNET_CHECK_EXT_EXIT	"dnet_check_ext_exit"
#define DNET_CHECK_EXT_MERGE	"dnet_check_ext_merge"

void *(* dnet_check_ext_init)(char *data);
void (* dnet_check_ext_exit)(void *priv);
int (* dnet_check_ext_merge)(void *priv, char *direct_path, char *storage_path, unsigned char *id);
void *dnet_check_ext_private;
void *dnet_check_ext_library;

char dnet_check_tmp_dir[128] = "/tmp";
FILE *dnet_check_file, *dnet_check_output;
pthread_mutex_t dnet_check_file_lock = PTHREAD_MUTEX_INITIALIZER;

int dnet_check_upload_existing;

static void dnet_check_log(void *priv, uint32_t mask, const char *msg)
{
	char str[64];
	struct tm tm;
	struct timeval tv;
	struct dnet_check_worker *w = priv;
	FILE *stream = w->stream;

	gettimeofday(&tv, NULL);
	localtime_r((time_t *)&tv.tv_sec, &tm);
	strftime(str, sizeof(str), "%F %R:%S", &tm);

	fprintf(stream, "%s.%06lu %d %1x: %s", str, tv.tv_usec, w->id, mask, msg);
	fflush(stream);
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

	err = dnet_add_transform(n, e, e->name, e->transform, e->cleanup);
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
		goto out_check;

	if (attr && attr->size) {
		if (cmd->size <= sizeof(struct dnet_attr) + sizeof(struct dnet_io_attr)) {
			dnet_log_raw(n, DNET_LOG_ERROR, "%s: read completion error: wrong size: cmd_size: %llu, must be more than %zu.\n",
					dnet_dump_id(cmd->id), (unsigned long long)cmd->size,
					sizeof(struct dnet_attr) + sizeof(struct dnet_io_attr));
			err = -EINVAL;
			goto out_check;
		}

		if (!attr) {
			dnet_log_raw(n, DNET_LOG_ERROR, "%s: no attributes but command size is not null.\n", dnet_dump_id(cmd->id));
			err = -EINVAL;
			goto out_check;
		}

		io = (struct dnet_io_attr *)(attr + 1);
		data = io + 1;

		dnet_convert_attr(attr);
		dnet_convert_io_attr(io);

		dnet_log_raw(n, DNET_LOG_NOTICE, "%s: io: write_offset: %llu, offset: %llu, size: %llu.\n",
				dnet_dump_id(cmd->id), (unsigned long long)complete->write_offset,
				(unsigned long long)io->offset, (unsigned long long)io->size);

		err = dnet_check_trans_write(complete, cmd, io, data);
	}

out_check:
	if (!(cmd->flags & DNET_FLAGS_MORE))
		goto out_wakeup;

	return err;

out_wakeup:
	dnet_check_wakeup(worker, { do { worker->wait_error = err; worker->wait_num++; } while (0); 0;} );
	free(complete);
	return err;
}

int dnet_check_read_single(struct dnet_check_worker *worker, unsigned char *id, uint64_t offset, int direct)
{
	struct dnet_io_control ctl;
	struct dnet_node *n = worker->n;
	struct dnet_check_completion *c;

	c = malloc(sizeof(struct dnet_check_completion));
	if (!c)
		return -ENOMEM;

	c->write_offset = offset;
	c->worker = worker;

	memset(&ctl, 0, sizeof(struct dnet_io_control));

	ctl.fd = -1;
	ctl.complete = dnet_check_read_complete;
	ctl.priv = c;
	ctl.cmd = DNET_CMD_READ;
	ctl.cflags = DNET_FLAGS_NEED_ACK;
	if (direct)
		ctl.cflags |= DNET_FLAGS_DIRECT;

	ctl.io.flags = 0;
	ctl.io.offset = 0;
	ctl.io.size = 0;

	memcpy(ctl.io.origin, id, DNET_ID_SIZE);
	memcpy(ctl.io.id, id, DNET_ID_SIZE);
	memcpy(ctl.addr, id, DNET_ID_SIZE);

	return dnet_read_object(n, &ctl);
}

int dnet_check_read_transactions(struct dnet_check_worker *worker, struct dnet_check_request *req)
{
	struct dnet_node *n = worker->n;
	char file[256];
	int err;
	long i;
	struct dnet_history_map map;
	struct dnet_history_entry *e;
	char eid[DNET_ID_SIZE*2 + 1];

	dnet_dump_id_len_raw(req->id, DNET_ID_SIZE, eid);
	snprintf(file, sizeof(file), "%s/%s%s", dnet_check_tmp_dir, eid, DNET_HISTORY_SUFFIX);

	err = dnet_map_history(n, file, &map);
	if (err)
		goto err_out_exit;

	worker->wait_num = 0;

	for (i=0; i<map.num; ++i) {
		e = &map.ent[i];

		dnet_convert_history_entry(e);

		err = dnet_check_read_single(worker, e->id, e->offset, 0);
		if (err)
			goto err_out_wait;

		dnet_log_raw(n, DNET_LOG_INFO, "%s: transaction: %s: offset: %8llu, size: %8llu.\n",
				eid, dnet_dump_id_len(e->id, DNET_ID_SIZE),
				(unsigned long long)e->offset, (unsigned long long)e->size);
	}

	dnet_check_wait(worker, worker->wait_num == map.num);

	dnet_unmap_history(n, &map);
	return 0;

err_out_wait:
	dnet_check_wait(worker, worker->wait_num == i);
	dnet_unmap_history(n, &map);
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

	dnet_unmap_history(n, &map);

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

struct dnet_id_request_completion
{
	int				fd;
	unsigned char			id[DNET_ID_SIZE];
	struct dnet_check_worker	*worker;
};

static int dnet_check_write_ids(struct dnet_id_request_completion *complete, struct dnet_id *id, uint64_t size)
{
	struct dnet_check_worker *worker = complete->worker;
	struct dnet_node *n = worker->n;
	long i, num = size / sizeof(struct dnet_id);
	int err;

	if (!size)
		return 0;

	for (i=0; i<num; ++i) {
		dnet_convert_id(&id[i]);
		dnet_log_raw(n, DNET_LOG_INFO, "%s: %x\n", dnet_dump_id_len(id[i].id, DNET_ID_SIZE), id[i].flags);
	}

	err = write(complete->fd, id, size);
	if (err < 0) {
		err = -errno;
		dnet_log_raw(n, DNET_LOG_ERROR, "%s: failed to write IDs: %s.\n", dnet_dump_id(complete->id), strerror(errno));
		return err;
	}

	return 0;
}

static int dnet_check_id_complete(struct dnet_net_state *state,
		struct dnet_cmd *cmd, struct dnet_attr *attr, void *priv)
{
	struct dnet_id_request_completion *complete = priv;
	struct dnet_check_worker *worker = complete->worker;
	struct dnet_node *n = worker->n;
	struct dnet_id *ids;
	int err = 0, last = 0;

	if (!state || !cmd) {
		err = -EINVAL;
		goto out_wakeup;
	}

	err = cmd->status;
	last = !(cmd->flags & DNET_FLAGS_MORE);
	dnet_log_raw(n, DNET_LOG_INFO, "%s: id completion status: %d, last: %d.\n",
			dnet_dump_id(cmd->id), err, last);

	if (err)
		goto out_exit;

	if (attr && attr->size) {
		if (cmd->size <= sizeof(struct dnet_attr)) {
			dnet_log_raw(n, DNET_LOG_ERROR, "%s: ID completion error: wrong size: cmd_size: %llu, must be more than %zu.\n",
					dnet_dump_id(cmd->id), (unsigned long long)cmd->size,
					sizeof(struct dnet_attr));
			err = -EINVAL;
			goto out_exit;
		}

		if (!attr) {
			dnet_log_raw(n, DNET_LOG_ERROR, "%s: no attributes but command size is not null.\n", dnet_dump_id(cmd->id));
			err = -EINVAL;
			goto out_exit;
		}

		ids = (struct dnet_id *)(attr + 1);

		dnet_convert_attr(attr);

		err = dnet_check_write_ids(complete, ids, attr->size);
	}

	if (last)
		goto out_wakeup;

	return err;

out_wakeup:
	dnet_check_wakeup(worker, worker->wait_num++);
	close(complete->fd);
	free(complete);
out_exit:
	return err;
}

static int dnet_check_request_ids(struct dnet_check_worker *w, unsigned char *id, char *file, int types)
{
	int err, fd;
	struct dnet_node *n = w->n;
	struct dnet_id_request_completion *c;
	uint32_t flags = DNET_ATTR_ID_OUT;

	if (types)
		flags = DNET_ATTR_ID_FLAGS;

	fd = open(file, O_RDWR | O_TRUNC | O_CREAT | O_APPEND, 0644);
	if (fd < 0) {
		err = -errno;
		dnet_log_raw(n, DNET_LOG_ERROR, "%s: failed to open/create id completion file '%s': %s.\n",
				dnet_dump_id(id), file, strerror(errno));
		goto err_out_exit;
	}

	c = malloc(sizeof(struct dnet_id_request_completion));
	if (!c) {
		err = -ENOMEM;
		goto err_out_close;
	}

	memcpy(c->id, id, DNET_ID_SIZE);
	c->fd = fd;
	c->worker = w;

	w->wait_num = 0;
	err = dnet_request_ids(n, id, flags, dnet_check_id_complete, c);
	if (err) {
		dnet_log_raw(n, DNET_LOG_ERROR, "%s: failed to request IDs from node: %d.\n", dnet_dump_id(id), err);
		goto err_out_exit;
	}

	err = dnet_check_wait(w, w->wait_num != 0);
	if (err) {
		dnet_log_raw(n, DNET_LOG_ERROR, "%s: failed to wait for ID request completion: %d.\n", dnet_dump_id(id), err);
		goto err_out_exit;
	}

	if (w->wait_num < 0) {
		err = w->wait_num;
		dnet_log_raw(n, DNET_LOG_ERROR, "%s: ID request completed with error: %d.\n", dnet_dump_id(id), err);
		goto err_out_exit;
	}

	dnet_check_file = fopen(file, "r");
	if (!dnet_check_file) {
		err = -errno;
		dnet_log_raw(n, DNET_LOG_ERROR, "%s: failed to open ID completion file '%s': %s.\n",
				dnet_dump_id(id), file, strerror(errno));
		goto err_out_exit;
	}

	return 0;

err_out_close:
	close(fd);
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
			"  -F file                 - output file, when used.\n"
			"  -r addr:port:family     - remote node to connect to.\n"
			"  -t dir                  - directory to store temporal object.\n"
			"  -e library              - external library which should export merge callbacks.\n"
			"  -E string               - some obscure string used by external library's intialization code.\n"
			"  -u                      - reupload existing copy into storage.\n"
			"                              Useful when you change log (like added new hash)\n"
			"                              and want this data uploaded to all nodes.\n"
			"  -w seconds              - timeout to wait for transction completion\n"
			"  -h                      - this help.\n", p);
}

int dnet_check_start(int argc, char *argv[], void *(* process)(void *data), int request_ids, int types)
{
	int ch, err = 0, i, j, worker_num = 1, log_mask;
	struct dnet_check_worker *w, *workers;
	struct dnet_config cfg, *remotes = NULL;
	char *file = NULL, *log = "/dev/stderr", *output_file = NULL;
	char *library = NULL, *library_data = NULL;
	char local_addr[] = "0.0.0.0:0:2";
	int added_remotes = 0;

	memset(&cfg, 0, sizeof(struct dnet_config));

	log_mask = DNET_LOG_ERROR;

	cfg.sock_type = SOCK_STREAM;
	cfg.proto = IPPROTO_TCP;
	cfg.wait_timeout = 60*60*10;
	cfg.resend_timeout.tv_sec = 60*60*10;
	cfg.resend_count = 0;
	cfg.io_thread_num = 2;
	cfg.max_pending = 256;

	while ((ch = getopt(argc, argv, "w:ue:E:t:n:m:l:f:F:r:h")) != -1) {
		switch (ch) {
			case 'w':
				cfg.wait_timeout = cfg.resend_timeout.tv_sec = strtoul(optarg, NULL, 0);
				break;
			case 'u':
				dnet_check_upload_existing = 1;
				break;
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
				log_mask = strtol(optarg, NULL, 0);
				break;
			case 'l':
				log = optarg;
				break;
			case 'F':
				output_file = optarg;
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

	if (!request_ids) {
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
	}

	if (output_file) {
		dnet_check_output = fopen(output_file, "a+");
		if (!dnet_check_output) {
			err = -errno;
			fprintf(stderr, "Failed to open output file '%s': %s.\n", output_file, strerror(errno));
			goto out_close_check_file;
		}
	}

	if (library) {
		err = dnet_check_setup_ext(library, library_data);
		if (err)
			goto out_close_output_file;
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

		w->stream = fopen(log, "a");
		if (!w->stream) {
			err = -errno;
			fprintf(stderr, "Failed to open log file %s: %s.\n", log, strerror(errno));
			goto out_join;
		}
		w->log.log_mask = log_mask;
		w->log.log_private = w;
		w->log.log = dnet_check_log;

		cfg.log = &w->log;

		w->n = dnet_node_create(&cfg);
		if (!w->n) {
			err = -ENOMEM;
			goto out_join;
		}

		added = 0;
		for (j=0; j<added_remotes; ++j) {
			if (request_ids)
				remotes[i].join = DNET_NO_ROUTE_LIST;

			err = dnet_add_state(w->n, &remotes[j]);
			if (!err)
				added++;

			if (request_ids && added)
				break;
		}

		if (!added) {
			dnet_log_raw(w->n, DNET_LOG_ERROR, "No remote nodes added, exiting.\n");
			err = -ENOENT;
			goto out_join;
		}

		if (i == 0 && request_ids) {
			err = dnet_check_request_ids(w, remotes[0].id, file, types);
			if (err) {
				dnet_log_raw(w->n, DNET_LOG_ERROR, "Failed to request ID range from node %s: %d.\n",
						dnet_dump_id_len(remotes[0].id, DNET_ID_SIZE), err);
				goto out_join;
			}
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

		if (w->stream)
			fclose(w->stream);
	}
	free(workers);

out_ext_cleanup:
	if (dnet_check_ext_library) {
		dnet_check_ext_exit(dnet_check_ext_private);
		dlclose(dnet_check_ext_library);
	}
out_close_output_file:
	if (output_file)
		fclose(dnet_check_output);
out_close_check_file:
	if (dnet_check_file)
		fclose(dnet_check_file);
out_exit:
	free(remotes);
	return err;
}

