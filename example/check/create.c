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

static void *dnet_clog_process(void *thread_data)
{
	struct dnet_check_worker *worker = thread_data;
	struct dnet_node *n = worker->n;
	char file[256], id_str[DNET_ID_SIZE*2 + 1];
	struct stat st;
	struct dnet_id id;
	void *data;
	struct dnet_meta *tmp;
	int err, fd;
	char *parent, *transform;

	while (1) {
		pthread_mutex_lock(&dnet_check_file_lock);
		err = fread(&id, sizeof(struct dnet_id), 1, dnet_check_file);
		pthread_mutex_unlock(&dnet_check_file_lock);

		if (err != 1)
			break;

		dnet_log_raw(n, DNET_LOG_INFO, "clog: %s, flags: %x\n", dnet_dump_id_len_raw(id.id, DNET_ID_SIZE, id_str), id.flags);

		if (!(id.flags & DNET_IO_FLAGS_PARENT))
			continue;

		snprintf(file, sizeof(file), "/tmp/clog-%s", id_str);

		err = dnet_meta_read_object_id(n, id.id, file);
		if (err) {
			dnet_log_raw(n, DNET_LOG_ERROR, "%s: failed to download meta object: %d.\n", dnet_dump_id(id.id), err);
			goto out_continue;
		}

		fd = open(file, O_RDONLY);
		if (fd < 0) {
			err = -errno;
			dnet_log_raw(n, DNET_LOG_ERROR, "%s: failed to read meta object '%s': %d.\n", dnet_dump_id(id.id), file, err);
			goto out_unlink;
		}

		err = fstat(fd, &st);
		if (err) {
			err = -errno;
			dnet_log_raw(n, DNET_LOG_ERROR, "%s: failed to stat meta object '%s': %d.\n", dnet_dump_id(id.id), file, err);
			goto out_close;
		}

		data = mmap(NULL, st.st_size, PROT_READ, MAP_SHARED, fd, 0);
		if (data == MAP_FAILED) {
			err = -errno;
			dnet_log_raw(n, DNET_LOG_ERROR, "%s: failed to map meta object '%s': %d.\n", dnet_dump_id(id.id), file, err);
			goto out_close;
		}

		tmp = dnet_meta_search(n, data, st.st_size, DNET_META_PARENT_OBJECT);
		if (!tmp) {
			err = -ENOENT;
			dnet_log_raw(n, DNET_LOG_ERROR, "%s: failed to find parent metadata in object '%s'.\n", dnet_dump_id(id.id), file);
			goto out_unmap;
		}

		parent = (char *)tmp->data;

		tmp = dnet_meta_search(n, data, st.st_size, DNET_META_TRANSFORM);
		if (!tmp) {
			err = -ENOENT;
			dnet_log_raw(n, DNET_LOG_ERROR, "%s: failed to find transform metadata in object '%s'.\n", dnet_dump_id(id.id), file);
			goto out_unmap;
		}

		transform = (char *)tmp->data;

		if (dnet_check_output) {
			pthread_mutex_lock(&dnet_check_file_lock);
			fprintf(dnet_check_output, "%s %s\n", transform, parent);
			dnet_check_id_num++;
			pthread_mutex_unlock(&dnet_check_file_lock);
		}

		dnet_log_raw(n, DNET_LOG_INFO, "%s: parent: '%s', hashes: '%s'.\n", id_str, parent, transform);

out_unmap:
		munmap(data, st.st_size);
out_close:
		close(fd);
out_unlink:
		unlink(file);
out_continue:
		continue;
	}

	return NULL;
}

int main(int argc, char *argv[])
{
	return dnet_check_start(argc, argv, dnet_clog_process, 1, 1);
}
