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

#include "common.h"

#include "../common.h"
#include "../hash.h"

#ifndef __unused
#define __unused	__attribute__ ((unused))
#endif

static void dnet_merge_unlink_local_files(struct dnet_node *n __unused, unsigned char *id)
{
	char file[256];
	char eid[2*DNET_ID_SIZE+1];

	dnet_dump_id_len_raw(id, DNET_ID_SIZE, eid);
	
	snprintf(file, sizeof(file), "%s/%s.direct%s", dnet_check_tmp_dir, eid, DNET_HISTORY_SUFFIX);
	unlink(file);

	snprintf(file, sizeof(file), "%s/%s%s", dnet_check_tmp_dir, eid, DNET_HISTORY_SUFFIX);
	unlink(file);
	
	snprintf(file, sizeof(file), "%s/%s", dnet_check_tmp_dir, eid);
	unlink(file);
}

static int dnet_merge_write_history(struct dnet_node *n, char *file, unsigned char *id)
{
	int err;

	err = dnet_write_file_local_offset(n, file, id, 0, 0, 0, DNET_ATTR_NO_TRANSACTION_SPLIT | DNET_ATTR_DIRECT_TRANSACTION, DNET_IO_FLAGS_HISTORY);
	if (err) {
		dnet_log_raw(n, DNET_LOG_ERROR, "%s: failed to upload transaction history merged: %d.\n",
				dnet_dump_id(id), err);
		goto err_out_exit;
	}

	dnet_log_raw(n, DNET_LOG_INFO, "%s: merged history has been uploaded.\n", dnet_dump_id(id));

err_out_exit:
	return err;
}

static int dnet_merge_direct(struct dnet_check_worker *worker, char *direct, unsigned char *id)
{
	struct dnet_node *n = worker->n;
	char file[256];
	char eid[2*DNET_ID_SIZE+1];
	int err;

	worker->wait_num = 0;
	worker->wait_error = 0;

	err = dnet_check_read_single(worker, id, 0, 1);
	dnet_check_wait(worker, worker->wait_num == 1);

	if (!err && worker->wait_error)
		err = worker->wait_error;

	if (err) {
		if (err != -ENOENT) {
			dnet_log_raw(n, DNET_LOG_ERROR, "%s: failed to read single transaction: %d.\n",
					dnet_dump_id(id), err);
			goto err_out_exit;
		}

		/*
		 * This is a history log for object, which consists of another objects,
		 * not plain transaction, so we just upload history file into the storage.
		 */
	} else {
		snprintf(file, sizeof(file), "%s/%s", dnet_check_tmp_dir, dnet_dump_id_len_raw(id, DNET_ID_SIZE, eid));
		err = dnet_write_file(n, file, id, 0, 0, DNET_ATTR_NO_TRANSACTION_SPLIT | DNET_ATTR_DIRECT_TRANSACTION);
		if (err) {
			dnet_log_raw(n, DNET_LOG_ERROR, "%s: failed to upload transaction to be directly merged: %d.\n",
					dnet_dump_id(id), err);
			goto err_out_exit;
		}
	}
	
	snprintf(file, sizeof(file), "%s%s", direct, DNET_HISTORY_SUFFIX);

	err = dnet_merge_write_history(n, file, id);
	if (err)
		goto err_out_exit;

	err = dnet_remove_object(n, id, id, NULL, NULL, 1);

	//dnet_merge_unlink_local_files(n, id);

err_out_exit:
	return err;
}

static void *dnet_merge_process(void *data)
{
	struct dnet_check_worker *worker = data;
	struct dnet_node *n = worker->n;
	unsigned char id[DNET_ID_SIZE];
	char file[128], direct[128], id_str[2*DNET_ID_SIZE+1];
	int err;

	while (1) {
		pthread_mutex_lock(&dnet_check_file_lock);
		err = fread(id, DNET_ID_SIZE, 1, dnet_check_file);
		pthread_mutex_unlock(&dnet_check_file_lock);

		if (err != 1)
			break;

		dnet_log_raw(n, DNET_LOG_INFO, "merge: %s\n", dnet_dump_id_len_raw(id, DNET_ID_SIZE, id_str));

		snprintf(direct, sizeof(direct), "%s/%s.direct", dnet_check_tmp_dir, id_str);

		err = dnet_read_file_direct(n, direct, id, 0, 0, 1);
		if (err) {
			dnet_log_raw(n, DNET_LOG_ERROR, "%s: failed to download object to be merged from direct node: %d.\n", dnet_dump_id(id), err);
			goto out_continue;
		}

		snprintf(file, sizeof(file), "%s/%s", dnet_check_tmp_dir, id_str);

		err = dnet_read_file(n, file, id, 0, 0, 1);
		if (err) {
			if (err != -ENOENT) {
				dnet_log_raw(n, DNET_LOG_ERROR, "%s: failed to download object to be merged from storage: %d.\n", dnet_dump_id(id), err);
				goto out_continue;
			}

			dnet_log_raw(n, DNET_LOG_INFO, "%s: there is no history in the storage to merge with, "
					"doing direct merge (plain upload).\n", dnet_dump_id(id));
			dnet_merge_direct(worker, direct, id);
		}

out_continue:
		continue;
	}

	return NULL;
}

int main(int argc, char *argv[])
{
	return dnet_check_start(argc, argv, dnet_merge_process, 1);
}
