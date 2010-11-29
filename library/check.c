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
#include <sys/mman.h>

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "elliptics.h"
#include "elliptics/interface.h"

static char dnet_check_tmp_dir[] = "/dev/shm";

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

static int dnet_check_find_groups(struct dnet_node *n, struct dnet_meta_container *mc, int **groupsp)
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

static int dnet_check_number_of_copies(struct dnet_node *n, struct dnet_meta_container *mc, int *groups, int group_num)
{
	struct dnet_id raw;
	int group_id = n->st->idc->group->group_id;
	struct dnet_net_state *st;
	void *data;
	char file[256];
	char eid[2*DNET_ID_SIZE+1];
	int err, i;

	for (i=0; i<group_num; ++i) {
		if (groups[i] == group_id)
			continue;

		dnet_setup_id(&raw, groups[i], mc->id.id);

		snprintf(file, sizeof(file), "%s/%s.%d", dnet_check_tmp_dir,
			dnet_dump_id_len_raw(raw.id, DNET_ID_SIZE, eid), raw.group_id);

		/*
		 * Reading history object, if it does not exist - upload current data.
		 */
		err = dnet_read_file(n, file, NULL, 0, &raw, 0, 0, 1);
		if (err < 0) {
			dnet_log_raw(n, DNET_LOG_ERROR, "%s: object is NOT present in the storage: %d.\n",
					dnet_dump_id(&raw), err);

			if (err != -ENOENT) {
				/*
				 * Kill history and metadata if we failed to read data.
				 * If we will not remove history, fsck will append recovered history to
				 * old one increasing its size more and more.
				 */
				dnet_remove_object_now(n, &raw, 0);
			}

			st = dnet_state_get_first(n, &raw);
			if (!st)
				continue;

			err = -ENOENT;
			if (st != n->st)
				err = n->send(st, n->command_private, &raw);
			dnet_state_put(st);

			if (err)
				continue;

			mc->id.group_id = raw.group_id;
			err = dnet_write_metadata(n, mc, 1);
			if (err <= 0)
				continue;

			err = dnet_db_read_raw(n, 0, mc->id.id, &data);
			if (err <= 0)
				continue;

			err = dnet_write_data_wait(n, NULL, 0, &raw, data, -1, 0, 0, err, NULL,
				DNET_ATTR_DIRECT_TRANSACTION, DNET_IO_FLAGS_HISTORY);
		}
	}

	return 0;
}

static int dnet_check_copies(struct dnet_node *n, struct dnet_meta_container *mc)
{
	int err;
	int *groups;

	err = dnet_check_find_groups(n, mc, &groups);
	if (err > 0) {
		err = dnet_check_number_of_copies(n, mc, groups, err);
	}

	return err;
}

static int dnet_check_merge(struct dnet_node *n __unused, struct dnet_meta_container *mc __unused)
{
	return -1;
}

int dnet_check(struct dnet_node *n, const char *file, unsigned long long size)
{
	int fd, err = 0, check_copies;
	struct dnet_meta_container *mc;
	void *data, *orig_data;
	unsigned long long orig_size = size;

	fd = open(file, O_RDWR);
	if (fd < 0) {
		err = -errno;
		dnet_log_err(n, "failed to open check file '%s'", file);
		goto err_out_exit;
	}

	orig_data = data = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (data == MAP_FAILED) {
		err = -errno;
		dnet_log_err(n, "failed to map check file '%s'", file);
		goto err_out_close;
	}

	while (!n->need_exit && size > 0) {
		mc = data;
		check_copies = mc->id.group_id;

		if (check_copies) {
			err = dnet_check_copies(n, mc);
		} else {
			err = dnet_check_merge(n, mc);
		}

		data += sizeof(struct dnet_meta_container) + mc->size;
		size -= sizeof(struct dnet_meta_container) + mc->size;
	}

	munmap(orig_data, orig_size);
err_out_close:
	close(fd);
err_out_exit:
	return err;
}

static int dnet_check_complete(struct dnet_net_state *state, struct dnet_cmd *cmd,
	struct dnet_attr *attr, void *priv)
{
	struct dnet_wait *w = priv;
	int err = -EINVAL;

	if (!state || !cmd || !attr) {
		dnet_wakeup(w, w->cond++);
		dnet_wait_put(w);
		return 0;
	}

	if (!(cmd->flags & DNET_FLAGS_MORE)) {
		dnet_wakeup(w, w->cond++);
		dnet_wait_put(w);
	}

	return err;
}

int dnet_request_check(struct dnet_node *n)
{
	struct dnet_wait *w;
	struct dnet_net_state *st;
	struct dnet_group *g;
	int err, num = 0;

	w = dnet_wait_alloc(0);
	if (!w) {
		err = -ENOMEM;
		goto err_out_exit;
	}

	pthread_rwlock_rdlock(&n->state_lock);
	list_for_each_entry(g, &n->group_list, group_entry) {
		list_for_each_entry(st, &g->state_list, state_entry) {
			struct dnet_id raw;

			if (st == n->st)
				continue;

			dnet_wait_get(w);

			dnet_setup_id(&raw, st->idc->group->group_id, st->idc->ids[0].raw.id);
			dnet_request_cmd_single(n, st, &raw, DNET_CMD_LIST, dnet_check_complete, w);
			num++;
		}
	}
	pthread_rwlock_unlock(&n->state_lock);

	err = dnet_wait_event(w, w->cond == num, &n->wait_ts);
	if (err)
		goto err_out_put;

	dnet_wait_put(w);

	return num;

err_out_put:
	dnet_wait_put(w);
err_out_exit:
	return err;
}
