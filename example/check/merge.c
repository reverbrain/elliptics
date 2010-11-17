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

#ifndef __unused
#define __unused	__attribute__ ((unused))
#endif

static void dnet_merge_unlink_local_files(struct dnet_node *n __unused, struct dnet_id *id)
{
	char file[256];
	char eid[2*DNET_ID_SIZE+1];

	dnet_dump_id_len_raw(id->id, DNET_ID_SIZE, eid);
	
	snprintf(file, sizeof(file), "%s/%s.%d.direct%s", dnet_check_tmp_dir, eid, id->group_id, DNET_HISTORY_SUFFIX);
	unlink(file);

	snprintf(file, sizeof(file), "%s/%s.%d%s", dnet_check_tmp_dir, eid, id->group_id, DNET_HISTORY_SUFFIX);
	unlink(file);
	
	snprintf(file, sizeof(file), "%s/%s.%d", dnet_check_tmp_dir, eid, id->group_id);
	unlink(file);
}

static int dnet_merge_write_history(struct dnet_node *n, char *file, struct dnet_id *id)
{
	int err;

	err = dnet_write_file_local_offset(n, file, file, strlen(file), id, 0, 0, 0,
			DNET_ATTR_DIRECT_TRANSACTION, DNET_IO_FLAGS_HISTORY);
	if (err) {
		dnet_log_raw(n, DNET_LOG_ERROR, "%s: failed to upload transaction history merged: %d.\n",
				dnet_dump_id(id), err);
		goto err_out_exit;
	}

	dnet_log_raw(n, DNET_LOG_INFO, "%s: merged history has been uploaded.\n", dnet_dump_id(id));

err_out_exit:
	return err;
}

static int dnet_merge_write_history_entry(struct dnet_node *n, char *result, int fd, struct dnet_history_entry *ent)
{
	int err;

	err = write(fd, ent, sizeof(struct dnet_history_entry));
	if (err < 0) {
		err = -errno;
		dnet_log_raw(n, DNET_LOG_ERROR, "%s: failed to write merged entry into result file '%s': %s [%d].\n",
				dnet_dump_id_str(ent->id), result, strerror(errno), errno);
	}
	err = 0;

	return err;
}

static int dnet_merge_check_direct_transaction_time(struct dnet_check_worker *worker, struct dnet_history_entry *f)
{
	struct dnet_node *n = worker->n;
	struct dnet_history_map m;
	struct dnet_history_entry e;
	char id_str[2*DNET_ID_SIZE+1];
	struct dnet_id raw;
	char file[256];
	int err;

	dnet_dump_id_len_raw(f->id, DNET_ID_SIZE, id_str);
	dnet_setup_id(&raw, worker->group_id, f->id);

	snprintf(file, sizeof(file), "%s/%s-trans", dnet_check_tmp_dir, id_str);
	err = dnet_read_file_direct(n, file, NULL, 0, &raw, 0, 0, 1);
	if (err)
		goto err_out_exit;

	snprintf(file, sizeof(file), "%s/%s-trans%s", dnet_check_tmp_dir, id_str, DNET_HISTORY_SUFFIX);

	err = dnet_map_history(n, file, &m);
	if (err)
		goto err_out_exit;

	e = m.ent[m.num - 1];
	dnet_convert_history_entry(&e);

	dnet_log_raw(n, DNET_LOG_NOTICE, "%s: direct: %llu.%llu, size: %llu, history transaction: %llu.%llu, size: %llu.\n",
			id_str, (unsigned long long)e.tsec, (unsigned long long)e.tnsec, (unsigned long long)e.size,
			(unsigned long long)f->tsec, (unsigned long long)f->tnsec, (unsigned long long)f->size);

	if (e.tsec < f->tsec)
		goto err_out_unmap;

	if ((e.tsec == f->tsec) && (e.tnsec < f->tnsec))
		goto err_out_unmap;

	dnet_log_raw(n, DNET_LOG_NOTICE, "%s: replacing transction with data read directly.\n", id_str);

	worker->wait_num = 0;
	worker->wait_error = 0;

	err = dnet_check_read_single(worker, &raw, 0, 1);
	dnet_check_wait(worker, worker->wait_num == 1);

	if (!err && worker->wait_error)
		err = worker->wait_error;

	if (err) {
		dnet_log_raw(n, DNET_LOG_INFO, "%s: failed to read direct transction: %d.\n", id_str, err);
		goto err_out_unmap;
	}

	snprintf(file, sizeof(file), "%s/%s.%d", dnet_check_tmp_dir, id_str, raw.group_id);
	err = dnet_write_file_local_offset(n, file, NULL, 0, &raw, 0, 0, 0, DNET_ATTR_DIRECT_TRANSACTION, DNET_IO_FLAGS_NO_HISTORY_UPDATE);

err_out_unmap:
	dnet_unmap_history(n, &m);
err_out_exit:
	snprintf(file, sizeof(file), "%s/%s-trans%s", dnet_check_tmp_dir, id_str, DNET_HISTORY_SUFFIX);
	unlink(file);
	snprintf(file, sizeof(file), "%s/%s-trans", dnet_check_tmp_dir, id_str);
	unlink(file);
	return err;
}

static int dnet_merge_get_latest_transactions(struct dnet_check_worker *worker, char *history)
{
	struct dnet_node *n = worker->n;
	struct dnet_history_map m;
	struct dnet_history_entry *e, *first = NULL;
	long i = 0;
	int err;

	err = dnet_map_history(n, history, &m);
	if (err)
		goto err_out_exit;

	i = m.num - 1;
	first = &m.ent[i];

	do {
		e = &m.ent[i];

		if (!dnet_id_cmp_str(first->id, e->id))
			continue;

		dnet_merge_check_direct_transaction_time(worker, first);

		first = e;
	} while (--i >= 0);

	if (first != e)
		dnet_merge_check_direct_transaction_time(worker, first);

	err = 0;

	dnet_unmap_history(n, &m);

err_out_exit:
	return err;
}

static int dnet_merge_direct(struct dnet_check_worker *worker, char *direct, struct dnet_meta_container *mc)
{
	struct dnet_node *n = worker->n;
	char file[256];
	char eid[2*DNET_ID_SIZE+1];
	int err;

	worker->wait_num = 0;
	worker->wait_error = 0;

	err = dnet_check_read_single(worker, &mc->id, 0, 1);
	dnet_check_wait(worker, worker->wait_num == 1);

	if (!err && worker->wait_error)
		err = worker->wait_error;

	if (err) {
		if (err != -ENOENT) {
			dnet_log_raw(n, DNET_LOG_ERROR, "%s: failed to read single transaction: %d.\n",
					dnet_dump_id(&mc->id), err);
			goto err_out_exit;
		}

		/*
		 * This is a history log for object, which consists of another objects,
		 * not plain transaction, so we just upload history file into the storage.
		 */
	} else {
		snprintf(file, sizeof(file), "%s/%s.%d", dnet_check_tmp_dir, dnet_dump_id_len_raw(mc->id.id, DNET_ID_SIZE, eid), mc->id.group_id);
		err = dnet_write_file_local_offset(n, file, file, strlen(file), &mc->id, 0, 0, 0, DNET_ATTR_DIRECT_TRANSACTION, DNET_IO_FLAGS_NO_HISTORY_UPDATE);
		if (err) {
			dnet_log_raw(n, DNET_LOG_ERROR, "%s: failed to upload transaction to be directly merged: %d.\n",
					dnet_dump_id(&mc->id), err);
			if (err == -ENOENT)
				dnet_remove_object_now(n, &mc->id, 1);
			goto err_out_exit;
		}

		err = dnet_write_metadata(n, mc, 1);
	}

	err = dnet_merge_write_history(n, direct, &mc->id);
	if (err)
		goto err_out_exit;

err_out_exit:
	return err;
}

static int dnet_merge_common(struct dnet_check_worker *worker, char *direct, char *file, struct dnet_meta_container *mc)
{
	struct dnet_node *n = worker->n;
	struct dnet_history_entry ent1, ent2;
	struct dnet_history_map m1, m2;
	char id_str[DNET_ID_SIZE*2+1];
	char result[256];
	long i, j, added = 0;
	int err, fd, removed = 0;

	err = dnet_map_history(n, direct, &m1);
	if (err) {
		/*
		 * If we can not map directly downloaded history entry likely object is also broken.
		 * So delete it.
		 */
		dnet_remove_object_now(n, &mc->id, 1);
		goto err_out_exit;
	}

	err = dnet_map_history(n, file, &m2);
	if (err) {
		err = dnet_merge_direct(worker, direct, mc);
		goto err_out_unmap1;
	}

	snprintf(result, sizeof(result), "%s-%s", file, dnet_dump_id_len_raw(mc->id.id, DNET_ID_SIZE, id_str));

	fd = open(result, O_RDWR | O_CREAT | O_TRUNC | O_APPEND, 0644);
	if (fd < 0) {
		err = -errno;
		dnet_log_raw(n, DNET_LOG_ERROR, "%s: failed to create result file '%s': %s [%d].\n",
				dnet_dump_id(&mc->id), result, strerror(errno), errno);
		goto err_out_unmap2;
	}

	for (i=0, j=0; i<m1.num || j<m2.num; ++i) {
		if (i < m1.num) {
			ent1 = m1.ent[i];

			dnet_convert_history_entry(&ent1);
			dnet_log_raw(n, DNET_LOG_NOTICE, "%s: 1 ts: %llu.%llu\n", dnet_dump_id_str(ent1.id),
					(unsigned long long)ent1.tsec, (unsigned long long)ent1.tnsec);
		}

		for (; j<m2.num; ++j) {
			ent2 = m2.ent[j];

			dnet_convert_history_entry(&ent2);
			dnet_log_raw(n, DNET_LOG_NOTICE, "%s: 2 ts: %llu.%llu\n", dnet_dump_id_str(ent2.id),
					(unsigned long long)ent2.tsec, (unsigned long long)ent2.tnsec);

			if (i < m1.num) {
				if (ent1.tsec < ent2.tsec)
					break;
				if ((ent1.tsec == ent2.tsec) && (ent1.tnsec < ent2.tnsec))
					break;
				if ((ent1.tnsec == ent2.tnsec) && !dnet_id_cmp_str(ent1.id, ent2.id)) {
					j++;
					break;
				}
			}

			err = dnet_merge_write_history_entry(n, result, fd, &m2.ent[j]);
			if (err)
				goto err_out_close;
			added++;
			removed = !!(ent2.flags & DNET_IO_FLAGS_REMOVED);
		}

		if (i < m1.num) {
			err = dnet_merge_write_history_entry(n, result, fd, &m1.ent[i]);
			if (err)
				goto err_out_close;
			added++;
			removed = !!(ent1.flags & DNET_IO_FLAGS_REMOVED);
		}
	}

	fsync(fd);

	err = dnet_merge_write_history(n, result, &mc->id);
	if (err)
		goto err_out_close;

	dnet_log_raw(n, DNET_LOG_INFO, "%s: merged %ld.%ld -> %ld entries, removed: %d.\n",
			dnet_dump_id(&mc->id), m1.num, m2.num, added, removed);

	if (removed)
		dnet_remove_object_now(n, &mc->id, 0);
	else
		err = dnet_merge_get_latest_transactions(worker, result);

err_out_close:
	unlink(result);
	close(fd);
err_out_unmap2:
	dnet_unmap_history(n, &m2);
err_out_unmap1:
	dnet_unmap_history(n, &m1);
err_out_exit:
	return err;
}

static void *dnet_merge_process(void *data)
{
	struct dnet_check_worker *worker = data;
	struct dnet_node *n = worker->n;
	char file[256], direct[256], id_str[2*DNET_ID_SIZE+1];
	void *buf, *ptr;
	struct dnet_meta_container *mc;
	int err, start, num, i, size = 1024 * 1024 * 10;

	buf = malloc(size);
	if (!buf) {
		err = -ENOMEM;
		goto err_out_exit;
	}

	while (1) {
		err = dnet_check_read_block(n, buf, size, &num, &start);
		if (err)
			break;

		ptr = buf;
		for (i=0; i<num; ++i) {
			mc = ptr;
			ptr += sizeof(struct dnet_meta_container);

			dnet_log_raw(n, DNET_LOG_INFO, "%d/%d: started merge: %s\n",
					start + i, dnet_check_id_num,
					dnet_dump_id_len_raw(mc->id.id, DNET_ID_SIZE, id_str));

			snprintf(direct, sizeof(direct), "%s/%s.%d.direct", dnet_check_tmp_dir, id_str, mc->id.group_id);

			err = dnet_read_file_direct(n, direct, direct, strlen(direct), &mc->id, 0, 0, 1);
			if (err) {
				dnet_log_raw(n, DNET_LOG_ERROR, "%s: failed to download object to be merged from direct node: %d.\n", dnet_dump_id(&mc->id), err);
				goto out_continue;
			}
			snprintf(file, sizeof(file), "%s.%d%s", direct, mc->id.group_id, DNET_HISTORY_SUFFIX);
			snprintf(direct, sizeof(direct), "%s", file);

			snprintf(file, sizeof(file), "%s/%s.%d", dnet_check_tmp_dir, id_str, mc->id.group_id);

			err = dnet_read_file(n, file, file, strlen(file), &mc->id, 0, 0, 1);
			if (err) {
				if (err != -ENOENT) {
					dnet_log_raw(n, DNET_LOG_ERROR, "%s: failed to download object to be merged from storage: %d.\n", dnet_dump_id(&mc->id), err);
					goto out_continue;
				}

				dnet_log_raw(n, DNET_LOG_INFO, "%s: there is no history in the storage to merge with, "
						"doing direct merge (plain upload).\n", dnet_dump_id(&mc->id));
				err = dnet_merge_direct(worker, direct, mc);
			} else {
				snprintf(file, sizeof(file), "%s/%s%s", dnet_check_tmp_dir, id_str, DNET_HISTORY_SUFFIX);
				if (dnet_check_ext_merge) {
					err = dnet_check_ext_merge(dnet_check_ext_private, direct, file, &mc->id);
				} else {
					err = dnet_merge_common(worker, direct, file, mc);
				}
			}

			dnet_merge_unlink_local_files(n, &mc->id);

			if (err)
				goto out_continue;

			dnet_remove_object_now(n, &mc->id, 1);
out_continue:
			dnet_log_raw(n, DNET_LOG_INFO, "%d/%d: processed: %s, err: %d\n",
					start + i, dnet_check_id_num, id_str, err);

			ptr += mc->size;
			continue;
		}
	}

	free(buf);
err_out_exit:
	return NULL;
}

int main(int argc, char *argv[])
{
	return dnet_check_start(argc, argv, dnet_merge_process, 1);
}
