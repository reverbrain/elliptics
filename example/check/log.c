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

#include "../common.h"
#include "../hash.h"

#include "common.h"

#define DNET_CHECK_TOKEN_STRING			" 	"
#define DNET_CHECK_NEWLINE_TOKEN_STRING		"\r\n"
#define DNET_CHECK_INNER_TOKEN_STRING		","

static int dnet_check_log_num;

static int dnet_check_process_hash_string(struct dnet_check_worker *w, char *hash, int add)
{
	struct dnet_node *n = w->n;
	char local_hash[128];
	char *token, *saveptr;
	int err, added = 0, pos = 0;

	snprintf(local_hash, sizeof(local_hash), "%s", hash);

	hash = local_hash;

	while (1) {
		token = strtok_r(hash, DNET_CHECK_INNER_TOKEN_STRING, &saveptr);
		if (!token)
			break;

		if (add) {
			err = dnet_check_add_hash(n, token);
			if (err)
				return err;
		} else {
			err = dnet_check_del_hash(n, token);
		}

		pos += snprintf(w->hashes + pos, sizeof(w->hashes) - pos, "%s,", token);

		hash = NULL;
		added++;
	}

	if (added) {
		pos--;
		w->hashes[pos] = '\0';
	}

	return added;
}

static int dnet_check_upload_complete(struct dnet_net_state *state,
		struct dnet_cmd *cmd, struct dnet_attr *attr __unused, void *priv)
{
	struct dnet_check_worker *worker = priv;
	struct dnet_node *n = worker->n;
	int err = 0, last = 0;

	if (!state || !cmd) {
		err = -EINVAL;
		goto out_wakeup;
	}

	err = cmd->status;
	last = !(cmd->flags & DNET_FLAGS_MORE);
	dnet_log_raw(n, DNET_LOG_INFO, "%s: check upload completion status: %d, last: %d.\n",
			dnet_dump_id(cmd->id), err, last);

	if (last)
		goto out_wakeup;

	return err;

out_wakeup:
	dnet_check_wakeup(worker, worker->wait_num++);
	return err;
}

static int dnet_check_process_request(struct dnet_check_worker *w,
		char *obj, int len, struct dnet_check_request *existing)
{
	struct dnet_node *n = w->n;
	char file[256];
	int err, version, fd, trans_num;
	struct stat st;
	struct dnet_history_entry *e;
	struct dnet_history_map map;
	struct dnet_io_attr io;
	uint64_t size;
	void *data;
	long i;
	char eid[DNET_ID_SIZE*2 + 1];
	struct timespec ts;

	snprintf(file, sizeof(file), "%s/%s%s", dnet_check_tmp_dir,
		dnet_dump_id_len_raw(existing->id, DNET_ID_SIZE, eid), DNET_HISTORY_SUFFIX);

	err = dnet_map_history(n, file, &map);
	if (err)
		goto err_out_exit;

	for (i=0; i<map.num; ++i) {
		e = &map.ent[i];

		dnet_convert_history_entry(e);

		io.size = 0;
		io.offset = 0;
		io.flags = e->flags;

		ts.tv_sec = e->tsec;
		ts.tv_nsec = e->tnsec;

		snprintf(file, sizeof(file), "%s/%s", dnet_check_tmp_dir,
			dnet_dump_id_len_raw(e->id, DNET_ID_SIZE, eid));

		version = -1;
		if (e->flags & DNET_IO_FLAGS_ID_VERSION)
			version = dnet_common_get_version(e->id);

		fd = open(file, O_RDONLY);
		if (fd < 0) {
			err = -errno;
			dnet_log_raw(n, DNET_LOG_ERROR, "%s: failed to open data file '%s': %d.\n",
					dnet_dump_id(e->id), file, err);
			goto out_break;
		}
		err = fstat(fd, &st);
		if (err) {
			err = -errno;
			dnet_log_raw(n, DNET_LOG_ERROR, "%s: failed to stat data file '%s': %d.\n",
					dnet_dump_id(e->id), file, err);
			goto out_close;
		}
		size = st.st_size;

		data = mmap(NULL, size, PROT_READ, MAP_SHARED, fd, 0);
		if (data == MAP_FAILED) {
			err = -errno;
			dnet_log_raw(n, DNET_LOG_ERROR, "%s: failed to map data file '%s': %d.\n",
					dnet_dump_id(e->id), file, err);
			goto out_close;
		}

		trans_num = 0;
		w->wait_num = 0;
		err = dnet_common_write_object_meta(n, obj, len, w->hashes, strlen(w->hashes), (version != -1),
				data, size, version, &ts, dnet_check_upload_complete, w, 0);

		if (err > 0)
			trans_num = err;

		err = dnet_check_wait(w, w->wait_num == trans_num);
		if (err) {
			dnet_log_raw(n, DNET_LOG_ERROR, "%s: failed to wait for common write completion: %d.\n", dnet_dump_id(e->id), err);
			goto out_unmap;
		}

		if (w->wait_num < 0) {
			err = w->wait_num;
			dnet_log_raw(n, DNET_LOG_ERROR, "%s: common write completed with error: %d.\n", dnet_dump_id(e->id), err);
			goto out_unmap;
		}

out_unmap:
		munmap(data, size);
out_close:
		close(fd);
out_break:
		dnet_log_raw(n, DNET_LOG_NOTICE, "%s: request uploading: %s, "
				"offset: %llu, size: %llu, ioflags: %x, version: %d, err: %d.\n",
				eid, dnet_dump_id(e->id),
				(unsigned long long)e->offset, (unsigned long long)e->size,
				e->flags, version, err);
		if (err)
			break;
	}

	dnet_unmap_history(n, &map);
	return 0;

err_out_exit:
	return err;
}

static int dnet_update_copies(struct dnet_check_worker *worker,	char *obj, int len,
		struct dnet_check_request *requests, int num)
{
	struct dnet_node *n = worker->n;
	struct dnet_check_request *existing = NULL, *req;
	char file[128];
	int i, err = 0, to_upload = 0;
	char eid[2*DNET_ID_SIZE+1];

	for (i=0; i<num; ++i) {
		req = &requests[i];

		if (!req->present)
			to_upload++;
		else
			existing = req;
	}

	if (!existing) {
		dnet_log_raw(n, DNET_LOG_ERROR, "'%s': there are no object copies in the storage.\n", obj);
		err = -ENOENT;
		goto out_exit;
	}

	if (!to_upload) {
		dnet_log_raw(n, DNET_LOG_INFO, "'%s': all %d copies are in the storage.\n", obj, num);
		err = 0;
		goto out_exit;
	}

	snprintf(file, sizeof(file), "%s/%s", dnet_check_tmp_dir,
			dnet_dump_id_len_raw(existing->id, DNET_ID_SIZE, eid));

	err = dnet_read_file(n, file, file, strlen(file), existing->id, 0, ~0ULL, 1);
	if (err) {
		dnet_log_raw(n, DNET_LOG_ERROR, "'%s': failed to download a copy: %d.\n", obj, err);
		goto out_exit;
	}

	err = dnet_check_read_transactions(worker, existing);
	if (err) {
		dnet_log_raw(n, DNET_LOG_ERROR, "'%s': failed to download transactions from existing copy: %d.\n", obj, err);
		goto out_unlink;
	}

	err = dnet_check_process_request(worker, obj, len, existing);
	if (err) {
		dnet_log_raw(n, DNET_LOG_ERROR, "'%s': failed to upload a '%s' request list: %d.\n",
				obj, dnet_dump_id_len(req->id, DNET_ID_SIZE), err);
		goto out_unlink;
	}

out_unlink:
	if (existing)
		dnet_check_cleanup_transactions(worker, existing);

	unlink(file);
	snprintf(file, sizeof(file), "%s/%s%s", dnet_check_tmp_dir,
			dnet_dump_id_len_raw(existing->id, DNET_ID_SIZE, eid),
			DNET_HISTORY_SUFFIX);
	unlink(file);
out_exit:
	return err;
}

static int dnet_check_number_of_copies(struct dnet_check_worker *w, char *obj, int len, int hash_num)
{
	struct dnet_node *n = w->n;
	int pos = 0;
	int err, i;
	struct dnet_check_request *requests, *req;
	char file[256];
	char eid[2*DNET_ID_SIZE+1];

	req = requests = malloc(hash_num * sizeof(struct dnet_check_request));
	if (!requests)
		return -ENOMEM;
	memset(requests, 0, hash_num * sizeof(struct dnet_check_request));

	for (i=0; i<hash_num; ++i) {
		unsigned int rsize = DNET_ID_SIZE;

		req = &requests[pos];
		req->w = w;
		req->pos = pos;

		err = dnet_transform(n, obj, len, req->id, &rsize, &pos);
		if (err) {
			if (err > 0)
				break;
			continue;
		}
		memcpy(req->addr, req->id, DNET_ID_SIZE);

		snprintf(file, sizeof(file), "%s/%s",
				dnet_check_tmp_dir, dnet_dump_id_len_raw(req->id, DNET_ID_SIZE, eid));
		err = dnet_read_file(n, file, file, strlen(file), req->id, 0, 1, 1);
		if (err < 0) {
			dnet_log_raw(n, DNET_LOG_ERROR, "%s: failed to read history file: %d.\n",
					dnet_dump_id(req->id), err);
			continue;
		}

		req->present = 1;
	}

	/*
	 * Must remove existing transformations in reverse order, since otherwise position
	 * will not correspond to the initial transformation number.
	 */
	for (i=hash_num-1; i>=0; --i) {
		req = &requests[i];

		/* XXX we can upload data transactions back to existing nodes if disable this block 
		 * It is useful when we change some data locally, for example metadata (number of copies)
		 */

		if (!dnet_check_upload_existing && req->present) {
			err = dnet_remove_transform_pos(n, req->pos, 1);
			if (err) {
				dnet_log_raw(n, DNET_LOG_ERROR, "%s: failed to remove transformation at position %d: %d.\n",
						dnet_dump_id(req->id), req->pos, err);
			}
		}

		dnet_log_raw(n, DNET_LOG_INFO, "obj: '%s', id: %s: history present: %d, uploading existing: %d.\n",
				obj, dnet_dump_id_len_raw(req->id, DNET_ID_SIZE, eid),
				req->present, dnet_check_upload_existing);
	}

	err = dnet_update_copies(w, obj, len, requests, hash_num);
	
	for (i=0; i<hash_num; ++i) {
		req = &requests[i];

		snprintf(file, sizeof(file), "%s/%s.history",
				dnet_check_tmp_dir, dnet_dump_id_len_raw(req->id, DNET_ID_SIZE, eid));
		unlink(file);
	}

	free(requests);
	return err;
}

static void *dnet_check_process(void *data)
{
	struct dnet_check_worker *w = data;
	char buf[4096], *tmp, *saveptr, *token, *hash, *obj;
	int size = sizeof(buf);
	int err, hash_num = 0;

	while (1) {
		pthread_mutex_lock(&dnet_check_file_lock);
		tmp = fgets(buf, size, dnet_check_file);
		if (tmp)
			dnet_check_log_num++;

		pthread_mutex_unlock(&dnet_check_file_lock);
		if (!tmp) {
			dnet_log_raw(w->n, DNET_LOG_INFO, "Check file is empty, exiting.\n");
			break;
		}

		obj = hash = NULL;
		err = -EINVAL;

		token = strtok_r(tmp, DNET_CHECK_TOKEN_STRING, &saveptr);
		if (!token)
			goto out_continue;
		hash = token;

		tmp = NULL;
		token = strtok_r(tmp, DNET_CHECK_TOKEN_STRING, &saveptr);
		if (!token)
			goto out_continue;
		obj = token;

		/*
		 * Cut off remaining newlines
		 */
		saveptr = NULL;
		token = strtok_r(token, DNET_CHECK_NEWLINE_TOKEN_STRING, &saveptr);

		dnet_cleanup_transform(w->n);

		err = dnet_check_process_hash_string(w, hash, 1);
		if (err < 0)
			goto out_continue;

		hash_num = err;

		err = dnet_check_number_of_copies(w, obj, strlen(obj), hash_num);
		
		dnet_check_process_hash_string(w, hash, 0);

out_continue:
		dnet_log_raw(w->n, DNET_LOG_INFO, "%d/%d: processed obj: %s, hash: %s, err: %d\n",
				dnet_check_log_num, dnet_check_id_num,
				obj, hash, err);
	}

	return NULL;
}

int main(int argc, char *argv[])
{
	return dnet_check_start(argc, argv, dnet_check_process, 0, 0);
}
