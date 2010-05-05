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

static int dnet_check_process_hash_string(struct dnet_node *n, char *hash, int add)
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

		if (add) {
			err = dnet_check_add_hash(n, token);
			if (err)
				return err;
		} else {
			err = dnet_check_del_hash(n, token);
		}

		hash = NULL;
		added++;
	}

	return added;
}

static int dnet_upload_local_file(struct dnet_check_worker *w, struct dnet_check_request *req, char *file)
{
	return dnet_write_file(w->n, file, file, strlen(file), req->id, 0, 0, req->type);
}

static int dnet_check_process_request(struct dnet_check_worker *w,
		struct dnet_check_request *req, struct dnet_check_request *existing)
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

		dnet_convert_history_entry(e);

		snprintf(file, sizeof(file), "%s/%s", dnet_check_tmp_dir,
			dnet_dump_id_len_raw(e->id, DNET_ID_SIZE, eid));

		err = dnet_write_file_local_offset(n, file, file, strlen(file), req->id, 0, e->offset, e->size, req->type, 0);

		dnet_log_raw(n, DNET_LOG_NOTICE, "%s: request uploading hist: %s, "
				"offset: %llu, size: %llu, err: %d.\n",
				eid, dnet_dump_id(req->id),
				(unsigned long long)e->offset, (unsigned long long)e->size, err);
	}

	dnet_unmap_history(n, &map);
	return 0;

err_out_exit:
	return err;
}

static int dnet_update_copies(struct dnet_check_worker *worker,	char *obj,
		struct dnet_check_request *requests, int num, int update_existing)
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

	if (!existing && !update_existing) {
		dnet_log_raw(n, DNET_LOG_ERROR, "'%s': there are no object copies in the storage.\n", obj);
		err = -ENOENT;
		goto out_exit;
	}

	if (!to_upload && !update_existing) {
		dnet_log_raw(n, DNET_LOG_INFO, "'%s': all %d copies are in the storage.\n", obj, num);
		err = 0;
		goto out_exit;
	}

	if (update_existing) {
		snprintf(file, sizeof(file), "%s", obj);
	} else {
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
	}

	for (i=0; i<num; ++i) {
		req = &requests[i];

		err = 0;
		if (update_existing) {
			err = dnet_upload_local_file(worker, req, file);
		} else if (!req->present) {
			err = dnet_check_process_request(worker, req, existing);
		}

		if (err) {
			dnet_log_raw(n, DNET_LOG_ERROR, "'%s': failed to upload a '%s' request list: %d.\n",
					obj, dnet_dump_id_len(req->id, DNET_ID_SIZE), err);
			continue;
		}
	}

out_unlink:
	if (existing)
		dnet_check_cleanup_transactions(worker, existing);

	if (!update_existing) {
		unlink(file);
		snprintf(file, sizeof(file), "%s/%s%s", dnet_check_tmp_dir,
				dnet_dump_id_len_raw(existing->id, DNET_ID_SIZE, eid),
				DNET_HISTORY_SUFFIX);
		unlink(file);
	}

out_exit:
	return err;
}

static int dnet_check_number_of_copies(struct dnet_check_worker *w, char *obj, int start, int end,
		int hash_num, unsigned int type, int update_existing)
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

	while (1) {
		unsigned int rsize = DNET_ID_SIZE;

		req = &requests[pos];
		req->w = w;
		req->type = type;
		req->pos = pos;

		err = dnet_transform(n, &obj[start], end - start, req->id, req->addr, &rsize, &pos);
		if (err) {
			if (err > 0)
				break;
			continue;
		}

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

		if (req->present) {
			err = dnet_remove_transform_pos(n, req->pos, 1);
			if (err) {
				dnet_log_raw(n, DNET_LOG_ERROR, "%s: failed to remove transformation at position %d: %d.\n",
						dnet_dump_id(req->id), req->pos, err);
			}
		}

		dnet_log_raw(n, DNET_LOG_INFO, "obj: '%s' %d/%d, id: %s: type: %d, "
				"history present: %d, update existing: %d.\n",
				obj, start, end, dnet_dump_id_len_raw(req->id, DNET_ID_SIZE, eid),
				req->type, req->present, update_existing);
	}

	err = dnet_update_copies(w, obj, requests, hash_num, update_existing);
	
	for (i=0; i<hash_num; ++i) {
		req = &requests[i];

		snprintf(file, sizeof(file), "%s/%s.history",
				dnet_check_tmp_dir, dnet_dump_id_len_raw(req->id, DNET_ID_SIZE, eid));
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

		dnet_cleanup_transform(w->n);

		err = dnet_check_process_hash_string(w->n, hash, 1);
		if (err < 0)
			continue;

		hash_num = err;

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
		
		dnet_check_process_hash_string(w->n, hash, 0);
	}

	return NULL;
}

int main(int argc, char *argv[])
{
	return dnet_check_start(argc, argv, dnet_check_process, 0);
}
