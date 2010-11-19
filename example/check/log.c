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

#include "common.h"

static int dnet_check_process_request(struct dnet_check_worker *w,
		struct dnet_meta_container *mc,
		int *groups, int group_num, unsigned int existing_group)
{
	struct dnet_node *n = w->n;
	char file[256];
	int err, version, i, j;
	struct dnet_history_entry *e;
	struct dnet_history_map map;
	struct dnet_id raw;
	char eid[DNET_ID_SIZE*2 + 1];
	struct timespec ts;

	dnet_log_raw(n, DNET_LOG_NOTICE, "%s: starting to multiplicate data transactions.\n", dnet_dump_id(&mc->id));

	snprintf(file, sizeof(file), "%s/%s.%d%s", dnet_check_tmp_dir,
		dnet_dump_id_len_raw(mc->id.id, DNET_ID_SIZE, eid),
		existing_group, DNET_HISTORY_SUFFIX);

	err = dnet_map_history(n, file, &map);
	if (err)
		goto err_out_exit;

	for (i=0; i<map.num; ++i) {
		e = &map.ent[i];

		dnet_convert_history_entry(e);

		ts.tv_sec = e->tsec;
		ts.tv_nsec = e->tnsec;

		snprintf(file, sizeof(file), "%s/%s.%d", dnet_check_tmp_dir,
			dnet_dump_id_len_raw(e->id, DNET_ID_SIZE, eid),
			existing_group);

		dnet_setup_id(&raw, 0, e->id);

		version = -1;
		if (e->flags & DNET_IO_FLAGS_ID_VERSION)
			version = dnet_common_get_version(e->id);

		for (j=0; j<group_num; ++j) {
			raw.group_id = groups[j];

			if (!dnet_check_upload_existing && (existing_group == raw.group_id))
				continue;

			err = dnet_write_file_local_offset(n, file, NULL, 0, &raw, 0, 0, 0,
					(version == -1) ? DNET_ATTR_DIRECT_TRANSACTION : 0, 0);
			dnet_log_raw(n, DNET_LOG_DSA, "%s: uploaded data copy, tranasctions: %d\n", dnet_dump_id(&raw), err);
			if (!err) {
				mc->id.group_id = raw.group_id;
				err = dnet_write_metadata(n, mc, 1);
			}
		}

		dnet_log_raw(n, DNET_LOG_DSA, "%s: request uploaded: %s, "
				"offset: %llu, size: %llu, ioflags: %x, version: %d, err: %d.\n",
				eid, dnet_dump_id_str(e->id),
				(unsigned long long)e->offset, (unsigned long long)e->size,
				e->flags, version, err);
		if (err < 0)
			break;
	}

	dnet_unmap_history(n, &map);
	return 0;

err_out_exit:
	return err;
}

static int dnet_update_copies(struct dnet_check_worker *worker,
		struct dnet_meta_container *mc,
		int *groups, int group_num, unsigned int existing_group)
{
	struct dnet_node *n = worker->n;
	char file[256];
	int err;
	char eid[2*DNET_ID_SIZE+1];
	struct dnet_id raw;

	dnet_setup_id(&raw, existing_group, mc->id.id);

	snprintf(file, sizeof(file), "%s/%s.%d", dnet_check_tmp_dir,
			dnet_dump_id_len_raw(mc->id.id, DNET_ID_SIZE, eid),
			existing_group);

	dnet_log_raw(n, DNET_LOG_NOTICE, "%s: downloading history of existing copy.\n", dnet_dump_id(&raw));

	err = dnet_read_file(n, file, file, strlen(file), &raw, 0, ~0ULL, 1);
	if (err) {
		dnet_log_raw(n, DNET_LOG_ERROR, "%s: failed to download a copy: %d.\n", dnet_dump_id(&raw), err);
		goto out_exit;
	}

	err = dnet_check_read_transactions(worker, &raw);
	if (err) {
		dnet_log_raw(n, DNET_LOG_ERROR, "%s: failed to download transactions from existing copy: %d.\n", dnet_dump_id(&raw), err);
		goto out_unlink;
	}

	err = dnet_check_process_request(worker, mc, groups, group_num, existing_group);
	if (err) {
		dnet_log_raw(n, DNET_LOG_ERROR, "%s: failed to upload requests: %d.\n", dnet_dump_id(&raw), err);
		goto out_unlink;
	}

out_unlink:
	dnet_check_cleanup_transactions(worker, &raw);
	unlink(file);
out_exit:
	return err;
}

static int dnet_check_number_of_copies(struct dnet_check_worker *w, struct dnet_meta_container *mc, int *groups, int group_num)
{
	struct dnet_node *n = w->n;
	struct dnet_id raw;
	int err, i;
	char file[256];
	char eid[2*DNET_ID_SIZE+1];
	int *empty, pos = 0, found = -1;

	empty = malloc(sizeof(int) * group_num);
	if (!empty)
		return -ENOMEM;

	for (i=0; i<group_num; ++i) {
		dnet_setup_id(&raw, groups[i], mc->id.id);

		snprintf(file, sizeof(file), "%s/%s.%d", dnet_check_tmp_dir,
			dnet_dump_id_len_raw(raw.id, DNET_ID_SIZE, eid), raw.group_id);

		dnet_log_raw(n, DNET_LOG_NOTICE, "Checking whether object is present in the storage: %s\n", dnet_dump_id(&raw));

		err = dnet_read_file(n, file, file, strlen(file), &raw, 0, 1, 0);
		if (err < 0) {
			dnet_log_raw(n, DNET_LOG_ERROR, "%s: object is NOT present in the storage: %d.\n",
					dnet_dump_id(&raw), err);

			/*
			 * Kill history and metadata if we failed to read data.
			 * If we will not remove history, fsck will append recovered history to
			 * old one increasing its size more and more.
			 */
			dnet_remove_object_now(n, &raw, 0);
			empty[pos++] = raw.group_id;
			continue;
		}

		found = raw.group_id;
		dnet_log_raw(n, DNET_LOG_NOTICE, "%s: object is present in the storage.\n", dnet_dump_id(&raw));
	}

	if (found == -1) {
		dnet_log_raw(n, DNET_LOG_ERROR, "%s: there are no object copies in the storage.\n", dnet_dump_id(&mc->id));
		err = -ENOENT;
		goto err_out_free;
	}

	if (pos == group_num) {
		dnet_log_raw(n, DNET_LOG_INFO, "%s: all %d copies are in the storage.\n", dnet_dump_id(&mc->id), group_num);
		err = 0;
		goto err_out_free;
	}

	err = dnet_update_copies(w, mc, empty, pos, found);
	
	for (i=0; i<group_num; ++i) {
		snprintf(file, sizeof(file), "%s/%s.%d%s",
				dnet_check_tmp_dir, dnet_dump_id_len_raw(mc->id.id, DNET_ID_SIZE, eid),
				groups[i], DNET_HISTORY_SUFFIX);
		unlink(file);
	}

err_out_free:
	free(empty);
	return err;
}

static int dnet_dump_meta_container(struct dnet_node *n, struct dnet_meta_container *mc)
{
	int fd, err;
	char file[256];
	char id_str[DNET_ID_SIZE*2+1];

	snprintf(file, sizeof(file), "%s/%s.meta", dnet_check_tmp_dir, dnet_dump_id_len_raw(mc->id.id, DNET_ID_SIZE, id_str));

	fd = open(file, O_RDWR | O_TRUNC | O_CREAT, 0644);
	if (fd < 0) {
		err = -errno;
		dnet_log_raw(n, DNET_LOG_ERROR, "Failed to open meta container file '%s': %s\n",
				file, strerror(errno));
		goto err_out_exit;
	}

	err = write(fd, mc->data, mc->size);
	if (err != (int)mc->size) {
		err = -errno;
		dnet_log_raw(n, DNET_LOG_ERROR, "Failed to write meta container into '%s': %s\n",
				file, strerror(errno));
		goto err_out_close;
	}
	err = 0;

err_out_close:
	close(fd);
err_out_exit:
	return err;
}

static int dnet_check_log_meta(struct dnet_node *n, struct dnet_meta_container *mc)
{
	struct dnet_meta *m;
	char obj[256];
	int err;

	m = dnet_meta_search(n, mc->data, mc->size, DNET_META_PARENT_OBJECT);
	if (!m) {
		dnet_log_raw(n, DNET_LOG_ERROR, "%s: failed to find parent object metadata.\n", dnet_dump_id(&mc->id));
		err = -ENOENT;
		goto err_out_exit;
	}

	snprintf(obj, sizeof(obj) < m->size ? sizeof(obj) : m->size, "%s", (char *)m->data);

	dnet_log_raw(n, DNET_LOG_INFO, "obj: '%s', id: %s\n", obj, dnet_dump_id_len(&mc->id, DNET_ID_SIZE));

	return 0;

err_out_exit:
	dnet_dump_meta_container(n, mc);
	return err;
}

int dnet_check_find_groups(struct dnet_node *n, struct dnet_meta_container *mc, int **groupsp)
{
	int err, i, num;
	struct dnet_meta *m;
	int *groups;

	m = dnet_meta_search(n, mc->data, mc->size, DNET_META_GROUPS);
	if (!m) {
		dnet_log_raw(n, DNET_LOG_ERROR, "%s: failed to find groups metadata.\n", dnet_dump_id(&mc->id));
		err = -ENOENT;
		goto err_out_exit;
	}

	groups = malloc(m->size);
	if (!groups) {
		err = -ENOMEM;
		goto err_out_exit;
	}
	memcpy(groups, m->data, m->size);

	num = m->size / sizeof(int32_t);

	for (i=0; i<num; ++i) {
		dnet_log_raw(n, DNET_LOG_DSA, "%s: group: %d\n", dnet_dump_id(&mc->id), groups[i]);
	}

	*groupsp = groups;

	return num;

err_out_exit:
	dnet_dump_meta_container(n, mc);
	return err;
}

static void *dnet_check_process(void *data)
{
	struct dnet_check_worker *w = data;
	struct dnet_node *n = w->n;
	void *ptr, *buf;
	int size = 1024*1024*10;
	int err, start, i, num;
	struct dnet_meta_container *mc;
	char id_str[DNET_ID_SIZE*2 + 1];
	int *groups, group_num;

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

			dnet_log_raw(n, DNET_LOG_INFO, "%d/%d: started log: %s\n",
					start + i, dnet_check_id_num,
					dnet_dump_id_len_raw(mc->id.id, DNET_ID_SIZE, id_str));

			dnet_check_log_meta(n, mc);

			err = dnet_check_find_groups(n, mc, &groups);
			if (err > 0) {
				group_num = err;
				err = dnet_check_number_of_copies(w, mc, groups, group_num);
			}
			
			dnet_log_raw(n, DNET_LOG_INFO, "%d/%d: processed log: %s, err: %d\n",
					start + i, dnet_check_id_num, id_str, err);

			ptr += mc->size;
			free(groups);
		}
	}

	free(buf);
err_out_exit:
	return NULL;
}

int main(int argc, char *argv[])
{
	return dnet_check_start(argc, argv, dnet_check_process, 0);
}
