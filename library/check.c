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

	m = dnet_meta_search(n, mc, DNET_META_GROUPS);
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

static void dnet_merge_unlink_local_files(struct dnet_node *n __unused, struct dnet_id *id)
{
	char file[256];
	char eid[2*DNET_ID_SIZE+1];

	dnet_dump_id_len_raw(id->id, DNET_ID_SIZE, eid);
	
	snprintf(file, sizeof(file), "%s/%s.%d%s", dnet_check_tmp_dir, eid, id->group_id, DNET_HISTORY_SUFFIX);
	unlink(file);
	
	snprintf(file, sizeof(file), "%s/%s.%d", dnet_check_tmp_dir, eid, id->group_id);
	unlink(file);
}

int dnet_cmd_bulk_check(struct dnet_net_state *orig, struct dnet_cmd *cmd, struct dnet_attr *attr, void *data)
{
	struct dnet_attr ca;
	struct dnet_bulk_id *ids = (struct dnet_bulk_id *)data;
	void *meta;
	//struct dnet_history_entry *hist;
	//struct dnet_history_entry e;
	int i;
	int err = 0;
	int num;

	ca.cmd = DNET_CMD_LIST;
	ca.size = 0;
	ca.flags = 0;

	if (!(attr->size % sizeof(struct dnet_bulk_id))) {
		num = attr->size / sizeof(struct dnet_bulk_id);

		dnet_log(orig->n, DNET_LOG_DSA, "BULK: received %d entries\n", num);

		for (i = 0; i < num; ++i) {
			dnet_log(orig->n, DNET_LOG_DSA, "BULK: processing ID %s\n", dnet_dump_id_str(ids[i].id));
			meta = NULL;
			err = dnet_db_read_raw(orig->n, ids[i].id, (void **)&meta);
			if (meta) {
				/*dnet_convert_history_entry(hist);
				memcpy(&e, &ids[i].last_history, sizeof(struct dnet_history_entry));
				dnet_convert_history_entry(&e);
				if ((hist->tsec < e.tsec) || ((hist->tsec == e.tsec) && (hist->tnsec < e.tnsec))) {
					/* Local file is older than remote *
					err = 0;
				}*/
				kcfree(meta);
			}
			if (err > 0) {
				dnet_log(orig->n, DNET_LOG_DSA, "BULK: file exists in history DB, removing it from output\n");
				memmove(&ids[i], &ids[i+1], (num-i-1) * sizeof(struct dnet_bulk_id));
				--i;
				--num;
			}
		}
	} else {
		dnet_log(orig->n, DNET_LOG_ERROR, "BULK: received corrupted data, size = %llu, sizeof(dnet_bulk_id) = %d\n", attr->size, sizeof(struct dnet_bulk_id));
		err = -1;
		goto err_out_exit;
	}

	return dnet_send_reply(orig, cmd, &ca, data, sizeof(struct dnet_bulk_id) * num, 0);

err_out_exit:
	return err;
}

static int dnet_bulk_check_complete(struct dnet_net_state *state, struct dnet_cmd *cmd,
	struct dnet_attr *attr, void *priv)
{
	struct dnet_wait *w = priv;
	struct dnet_id id;
	void *data;
	int err = -EINVAL;

	if (is_trans_destroyed(state, cmd, attr)) {
		dnet_wakeup(w, w->cond++);
		dnet_wait_put(w);
		return 0;
	}

	if (!attr)
		return cmd->status;

	if (!(attr->size % sizeof(struct dnet_bulk_id))) {
		struct dnet_bulk_id *ids = (struct dnet_bulk_id *)(attr + 1);
		int num = attr->size / sizeof(struct dnet_bulk_id);
		int i;

		dnet_log(state->n, DNET_LOG_DSA, "BULK: received %d entries\n", num);

		for (i = 0; i < num; ++i) {
			dnet_log(state->n, DNET_LOG_DSA, "BULK: sending ID %s\n", dnet_dump_id_str(ids[i].id));
			err = -ENOENT;

			dnet_setup_id(&id, state->idc->group->group_id, ids[i].id);
			err = state->n->send(state, state->n->command_private, &id);

			if (err)
				goto err_out_continue;

			err = dnet_db_read_raw(state->n, ids[i].id, &data);
			if (err <= 0) {
				if (err == 0)
					err = -ENOENT;
				goto err_out_continue;
			}

			dnet_update_check_metadata_raw(state->n, data, err);
			err = dnet_write_data_wait(state->n, NULL, 0, &id, data, -1, 0, 0, err, NULL,
				DNET_ATTR_DIRECT_TRANSACTION, DNET_IO_FLAGS_META | DNET_IO_FLAGS_NO_HISTORY_UPDATE);

			kcfree(data);
			if (err < 0)
				goto err_out_continue;

			/*err = dnet_db_read_raw(state->n, ids[i].id, &data);
			if (err <= 0) {
				if (err == 0)
					err = -ENOENT;
				goto err_out_continue;
			}

			err = dnet_write_data_wait(state->n, NULL, 0, &id, data, -1, 0, 0, err, NULL,
				DNET_ATTR_DIRECT_TRANSACTION, DNET_IO_FLAGS_HISTORY | DNET_IO_FLAGS_NO_HISTORY_UPDATE);

			kcfree(data);*/
			if (err > 0)
				err = 0;
err_out_continue:
			if (err < 0) {
				dnet_log(state->n, DNET_LOG_ERROR, "Failed to send ID %s to %s, err=%d\n", dnet_dump_id_str(ids[i].id),
						dnet_state_dump_addr(state), err);
			}
			dnet_counter_inc(state->n, DNET_CNTR_NODE_CHECK_COPY, err);
		}
	} else {
		dnet_log(state->n, DNET_LOG_ERROR, "BULK: received corrupted data, size = %llu, sizeof(dnet_bulk_id) = %d\n", attr->size, sizeof(struct dnet_bulk_id));
	}

	w->status = cmd->status;
	return err;
}

int dnet_request_bulk_check(struct dnet_node *n, struct dnet_bulk_state *state)
{
	struct dnet_trans_control ctl;
	struct dnet_net_state *st;
	struct dnet_wait *w;
	int err;

	w = dnet_wait_alloc(0);
	if (!w) {
		err = -ENOMEM;
		goto err_out_exit;
	}

	memset(&ctl, 0, sizeof(struct dnet_trans_control));

	ctl.cmd = DNET_CMD_LIST;
	ctl.complete = dnet_bulk_check_complete;
	ctl.priv = w;
	ctl.cflags = DNET_FLAGS_NEED_ACK;
	ctl.aflags = DNET_ATTR_BULK_CHECK;

	ctl.data = state->ids;
	ctl.size = sizeof(struct dnet_bulk_id) * state->num;

	st = dnet_state_search_by_addr(n, &state->addr);
	if (!st) {
		err = -ENOENT;
		goto err_out_put;
	}
	dnet_setup_id(&ctl.id, st->idc->group->group_id, st->idc->ids[0].raw.id);
	dnet_log(n, DNET_LOG_DSA, "BULK: sending %u bytes of data to %s (%s)\n", ctl.size, dnet_dump_id(&ctl.id), dnet_server_convert_dnet_addr(&state->addr));
	err = dnet_trans_alloc_send_state(st, &ctl);
	dnet_state_put(st);

	err = dnet_wait_event(w, w->cond != 0, &n->wait_ts);
	if (err)
		goto err_out_put;

	if (w->status) {
		err = w->status;
		goto err_out_put;
	}

	dnet_wait_put(w);
	return 0;

err_out_put:
	dnet_wait_put(w);

err_out_exit:
	dnet_log(n, DNET_LOG_ERROR, "Bulk check exited with status %d\n", err);
	return err;
}

static int dnet_bulk_add_id(struct dnet_node *n, struct dnet_bulk_array *bulk_array, struct dnet_id *id)
{
	int err = 0;
	struct dnet_bulk_state tmp;
	struct dnet_bulk_state *state = NULL;
	struct dnet_net_state *st = dnet_state_get_first(n, id);
	struct dnet_bulk_id *bulk_id;
	//struct dnet_history_entry *hist;
	int size, num;

	dnet_log(n, DNET_LOG_DSA, "BULK: adding ID %s to array\n", dnet_dump_id(id));
	if (!st)
		return -1;

	memcpy(&tmp.addr, &st->addr, sizeof(struct dnet_addr));
	dnet_state_put(st);
	state = bsearch(&tmp, bulk_array->states, bulk_array->num, sizeof(struct dnet_bulk_state), dnet_compare_bulk_state);
	if (!state)
		return -1;

	dnet_log(n, DNET_LOG_DSA, "BULK: addr = %s state->num = %d\n", dnet_server_convert_dnet_addr(&state->addr), state->num);
	pthread_mutex_lock(&state->state_lock);
	if (state->num >= DNET_BULK_IDS_SIZE || state->num < 0)
		goto err_out_unlock;

	/*size = dnet_db_read_raw(n, 0, id->id, (void **)&hist);
	if (size <= 0) {
		dnet_log(n, DNET_LOG_ERROR, "%s: error while retreiving history, err=%d\n", dnet_dump_id(id), err);
		goto err_out_unlock;
	}

	dnet_log(n, DNET_LOG_DSA, "BULK: history retrieved for ID %s\n", dnet_dump_id(id));
	if (size % sizeof(struct dnet_history_entry)) {
		dnet_log(n, DNET_LOG_ERROR, "%s: corrupted history for id %s\n", dnet_dump_id(id), dnet_dump_id_len(id, DNET_ID_SIZE));
		goto err_out_kcfree;
	}

	num = size / sizeof(struct dnet_history_entry);*/
	bulk_id = &state->ids[state->num];
	memset(bulk_id, 0, sizeof(struct dnet_bulk_id));
	//memcpy(&bulk_id->last_history, &hist[num-1], sizeof(struct dnet_history_entry));
	//dnet_convert_history_entry(&bulk_id->last_history);
	memcpy(&bulk_id->id, &id->id, DNET_ID_SIZE);
	state->num++;

	//kcfree(hist);

	dnet_log(n, DNET_LOG_DSA, "BULK: addr = %s state->num = %d\n", dnet_server_convert_dnet_addr(&state->addr), state->num);
	if (state->num == DNET_BULK_IDS_SIZE) {
		err = dnet_request_bulk_check(n, state);
		state->num = 0;
		if (err)
			goto err_out_unlock;
	}

	pthread_mutex_unlock(&state->state_lock);

	return 0;

err_out_kcfree:
	//kcfree(hist);
err_out_unlock:
	pthread_mutex_unlock(&state->state_lock);
	return -2;
}

static int dnet_check_number_of_copies(struct dnet_node *n, struct dnet_meta_container *mc, int *groups, int group_num, struct dnet_bulk_array *bulk_array, int check_copies)
{
	struct dnet_id raw;
	int group_id = mc->id.group_id;
	struct dnet_net_state *st;
	void *data;
	char file[256];
	char eid[2*DNET_ID_SIZE+1];
	int err, i, error = 0;

	for (i=0; i<group_num; ++i) {
		if (groups[i] == group_id)
			continue;

		dnet_setup_id(&raw, groups[i], mc->id.id);

		err = dnet_bulk_add_id(n, bulk_array, &raw);
		if (err)
			dnet_log(n, DNET_LOG_ERROR, "BULK: after adding ID %s err = %d\n", dnet_dump_id(&raw), err);

#if 0
		snprintf(file, sizeof(file), "%s/%s.%d", dnet_check_tmp_dir,
			dnet_dump_id_len_raw(raw.id, DNET_ID_SIZE, eid), raw.group_id);

		err = 0;
		if (check_copies == DNET_CHECK_COPIES_HISTORY) {
			/*
			 * Reading history object, if it does not exist - upload current data.
			 */
			err = dnet_read_file(n, file, NULL, 0, &raw, 0, 0, 1);
		} else if (check_copies == DNET_CHECK_COPIES_FULL) {
			/*
			 * Reading first byte of data object, if it does not exist - upload current data.
			 */
			err = dnet_read_file(n, file, NULL, 0, &raw, 0, 1, 0);
		}

		if (!err)
			goto err_out_continue;

		dnet_log_raw(n, DNET_LOG_ERROR, "%s: object is NOT present in the storage: %d.\n",
				dnet_dump_id(&raw), err);
#if 0
		/*
		 * -7 - no record Kyoto Cabinet error
		 */
		if ((err != -ENOENT) && (err != -ECONNRESET) && (err != -ETIMEDOUT) && (err != -7)) {
			/*
			 * Kill history and metadata if we failed to read data.
			 * If we will not remove history, fsck will append recovered history to
			 * old one increasing its size more and more.
			 */
			dnet_remove_object_now(n, &raw, 0);
		}
#endif
		err = -ENOENT;
		st = dnet_state_get_first(n, &raw);
		if (!st)
			goto err_out_continue;

		err = n->send(st, n->command_private, &raw);
		dnet_state_put(st);

		if (err)
			goto err_out_continue;

		mc->id.group_id = raw.group_id;
		err = dnet_write_metadata(n, mc, 1);
		if (err <= 0) {
			if (err == 0)
				err = -ENOENT;
			goto err_out_continue;
		}

		err = dnet_db_read_raw(n, 0, mc->id.id, &data);
		if (err <= 0) {
			if (err == 0)
				err = -ENOENT;
			goto err_out_continue;
		}

		err = dnet_write_data_wait(n, NULL, 0, &raw, data, -1, 0, 0, err, NULL,
			DNET_ATTR_DIRECT_TRANSACTION, DNET_IO_FLAGS_HISTORY | DNET_IO_FLAGS_NO_HISTORY_UPDATE);

		kcfree(data);
err_out_continue:
#endif
		if (!err)
			error = 0;
		else if (!error)
			error = err;

		//dnet_merge_unlink_local_files(n, &raw);
	}

	return error;
}

static int dnet_merge_remove_local(struct dnet_node *n, struct dnet_id *id, int full_process)
{
	char buf[sizeof(struct dnet_cmd) + sizeof(struct dnet_attr)];
	struct dnet_cmd *cmd;
	struct dnet_attr *attr;
	struct dnet_net_state *base;
	int err = -ENOENT;

	memset(buf, 0, sizeof(buf));

	cmd = (struct dnet_cmd *)buf;
	attr = (struct dnet_attr *)(cmd + 1);

	memcpy(&cmd->id, id, sizeof(struct dnet_id));
	cmd->size = sizeof(struct dnet_attr);

	attr->cmd = DNET_CMD_DEL;
	if (!full_process)
		attr->flags = DNET_ATTR_DELETE_HISTORY | DNET_ATTR_DIRECT_TRANSACTION;

	dnet_convert_attr(attr);

	base = dnet_node_state(n);
	if (base) {
		err = dnet_process_cmd_raw(base, cmd, attr);
		dnet_state_put(base);
	}

	return err;
}

static int dnet_check_copies(struct dnet_node *n, struct dnet_meta_container *mc, struct dnet_bulk_array *bulk_array, int check_copies)
{
	int err;
	int *groups = NULL;

	err = dnet_check_find_groups(n, mc, &groups);
	if (err <= 0)
		return -ENOENT;

	err = dnet_check_number_of_copies(n, mc, groups, err, bulk_array, check_copies);
	free(groups);

	return err;
}

static int dnet_merge_direct(struct dnet_node *n, struct dnet_meta_container *mc)
{
	struct dnet_net_state *base;
	void *local_history;
	int err, size;

	base = dnet_node_state(n);
	if (!base) {
		err = -ENOENT;
		goto err_out_exit;
	}

	err = n->send(base, n->command_private, &mc->id);
	if (err < 0)
		goto err_out_remove;

	size = dnet_db_read_raw(n, mc->id.id, &local_history);
	if (size <= 0) {
		err = -EINVAL;
		if (size == 0 || size == -7)
			err = -ENOENT;
		goto err_out_remove;
	}

	err = dnet_write_data_wait(n, NULL, 0, &mc->id, local_history, -1, 0, 0, size, NULL,
			DNET_ATTR_DIRECT_TRANSACTION, DNET_IO_FLAGS_HISTORY | DNET_IO_FLAGS_NO_HISTORY_UPDATE);
	kcfree(local_history);
	if (err <= 0)
		goto err_out_exit;

	err = dnet_write_metadata(n, mc, 1);
	if (err <= 0)
		goto err_out_exit;

	err = 0;

err_out_remove:
	if (err == -ENOENT)
		dnet_merge_remove_local(n, &mc->id, 0);
	dnet_state_put(base);
err_out_exit:
	return err;
}

/*
static int dnet_merge_write_history_entry(struct dnet_node *n, char *result, int fd, struct dnet_history_entry *ent)
{
	int err;

	err = write(fd, ent, sizeof(struct dnet_history_entry));
	if (err < 0) {
		err = -errno;
		dnet_log_err(n, "%s: failed to write merged entry into result file '%s'",
				dnet_dump_id_str(ent->id), result);
		return err;
	}

	return 0;
}

static int dnet_merge_upload_latest(struct dnet_node *n, struct dnet_meta_container *mc,
		struct dnet_history_map *local, struct dnet_history_map *remote)
{
	struct dnet_history_entry *elocal = &local->ent[local->num - 1];
	struct dnet_history_entry *eremote = &remote->ent[remote->num - 1];
	struct timespec ltime = {.tv_sec = elocal->tsec, .tv_nsec = elocal->tnsec};
	struct timespec rtime = {.tv_sec = eremote->tsec, .tv_nsec = eremote->tnsec};
	struct dnet_net_state *base;
	int err = 0;

	if (!dnet_time_after(&ltime, &rtime))
		goto err_out_exit;

	base = dnet_node_state(n);
	if (!base) {
		err = -ENOENT;
		goto err_out_exit;
	}

	err = n->send(base, n->command_private, &mc->id);
	if (err)
		goto err_out_put;

	err = dnet_write_metadata(n, mc, 1);
	if (err <= 0)
		goto err_out_put;

err_out_put:
	dnet_state_put(base);
err_out_exit:
	return err;
}

int dnet_merge_history(struct dnet_node *n, struct dnet_history_map *map1, struct dnet_history_map *map2, struct dnet_history_map **res)
{
	struct dnet_history_entry ent1, ent2;
	uint32_t flags1, flags2;
	long i, j, removed = 1;
	size_t result_size;
	struct dnet_history_map *result = NULL;

	result_size = map1->size + map2->size;
	*res = NULL;

	result = (struct dnet_history_map *)malloc(sizeof(struct dnet_history_map));
	if (!result)
		return -1;

	result->ent = NULL;
	if (result_size <= 0)
		goto err_out_free;

	*res = result;

	result->ent = (struct dnet_history_entry *)malloc(result_size);
	if (!result->ent)
		goto err_out_free;

	memset(result->ent, 0, result_size);
	result->num = 0;
	result->fd = -1;

	for (i=0, j=0; i<map1->num || j<map2->num; ++i) {
		if (i < map1->num) {
			ent1 = map1->ent[i];

			dnet_convert_history_entry(&ent1);
			dnet_log(n, DNET_LOG_DSA, "%s: 1 ts: %llu.%llu\n", dnet_dump_id_str(ent1.id),
					(unsigned long long)ent1.tsec, (unsigned long long)ent1.tnsec);
		}

		for (; j<map2->num; ++j) {
			ent2 = map2->ent[j];

			dnet_convert_history_entry(&ent2);
			dnet_log_raw(n, DNET_LOG_DSA, "%s: 2 ts: %llu.%llu\n", dnet_dump_id_str(ent2.id),
					(unsigned long long)ent2.tsec, (unsigned long long)ent2.tnsec);

			if (i < map1->num) {
				if (ent1.tsec < ent2.tsec)
					break;
				if ((ent1.tsec == ent2.tsec) && (ent1.tnsec < ent2.tnsec))
					break;
				if ((ent1.tnsec == ent2.tnsec) && !dnet_id_cmp_str(ent1.id, ent2.id)) {
					j++;
					break;
				}
			}

			memcpy(&result->ent[result->num], &map2->ent[j], sizeof(struct dnet_history_entry));
			result->num++;
		}

		if (i < map1->num) {
			memcpy(&result->ent[result->num], &map1->ent[i], sizeof(struct dnet_history_entry));
			result->num++;
		}
	}

	dnet_log(n, DNET_LOG_DSA, "result->num=%ld\n", result->num);
	/* Collapse records with flag REMOVED *
	for (i = result->num-1; i > 0; --i) {
		flags1 = dnet_bswap32(result->ent[i].flags);
		if (!(flags1 & DNET_IO_FLAGS_REMOVED))
			removed = 0;

		for (j = i-1; j >= 0 && (flags1 & DNET_IO_FLAGS_REMOVED); --j) {
			dnet_log(n, DNET_LOG_DSA, "i=%ld, j=%ld\n", i, j);
			flags2 = dnet_bswap32(result->ent[j].flags);
			if (!memcmp(result->ent[i].id, result->ent[j].id, DNET_ID_SIZE)
				&& result->ent[i].size == result->ent[i].size
				&& result->ent[i].offset == result->ent[i].offset
				&& (flags1 & ~DNET_IO_FLAGS_REMOVED) == (flags2 & ~DNET_IO_FLAGS_REMOVED)) {
				dnet_log(n, DNET_LOG_DSA, "Removing entry, i=%ld, result->num=%ld\n", i, result->num);
				memmove(&result->ent[j], &result->ent[j+1], (result->num - j - 1) * sizeof(struct dnet_history_entry));
				--i;
				result->num--;
				dnet_log(n, DNET_LOG_DSA, "After remove, i=%ld, result->num=%ld\n", i, result->num);
			}
		}
	}

	result->size = result->num * sizeof(struct dnet_history_entry);

	result->ent = realloc(result->ent, result->size);

	return removed;

err_out_free:
	free(result);
	*res = NULL;
	return -1;
} 
*
static int dnet_merge_common(struct dnet_node *n, char *remote_history, struct dnet_meta_container *mc)
{
	struct dnet_history_entry ent1, ent2;
	struct dnet_history_map remote, local;
	char id_str[DNET_ID_SIZE*2+1];
	char result[256];
	long i, j, added = 0;
	int err, fd, removed = 0;
	void *local_history;

	err = dnet_db_read_raw(n, 0, mc->id.id, &local_history);
	if (err <= 0) {
		/*
		 * If we can not map directly downloaded history entry likely object is also broken.
		 * We return 0 here so that dnet_check() subsequently remove local metadata.
		 *
		err = 0;
		goto err_out_exit;
	}

	local.num = err / sizeof(struct dnet_history_entry);
	local.size = err;
	local.ent = local_history;

	err = dnet_map_history(n, remote_history, &remote);
	if (err) {
		err = dnet_merge_direct(n, mc);
		goto err_out_free;
	}

	snprintf(result, sizeof(result), "%s/%s.result",
			dnet_check_tmp_dir,
			dnet_dump_id_len_raw(mc->id.id, DNET_ID_SIZE, id_str));

	fd = open(result, O_RDWR | O_CREAT | O_TRUNC | O_APPEND, 0644);
	if (fd < 0) {
		err = -errno;
		dnet_log_err(n, "%s: failed to create result file '%s'",
				dnet_dump_id(&mc->id), result);
		goto err_out_unmap;
	}

	for (i=0, j=0; i<remote.num || j<local.num; ++i) {
		if (i < remote.num) {
			ent1 = remote.ent[i];

			dnet_convert_history_entry(&ent1);
			dnet_log(n, DNET_LOG_DSA, "%s: 1 ts: %llu.%llu\n", dnet_dump_id_str(ent1.id),
					(unsigned long long)ent1.tsec, (unsigned long long)ent1.tnsec);
		}

		for (; j<local.num; ++j) {
			ent2 = local.ent[j];

			dnet_convert_history_entry(&ent2);
			dnet_log_raw(n, DNET_LOG_DSA, "%s: 2 ts: %llu.%llu\n", dnet_dump_id_str(ent2.id),
					(unsigned long long)ent2.tsec, (unsigned long long)ent2.tnsec);

			if (i < remote.num) {
				if (ent1.tsec < ent2.tsec)
					break;
				if ((ent1.tsec == ent2.tsec) && (ent1.tnsec < ent2.tnsec))
					break;
				if ((ent1.tnsec == ent2.tnsec) && !dnet_id_cmp_str(ent1.id, ent2.id)) {
					j++;
					break;
				}
			}

			err = dnet_merge_write_history_entry(n, result, fd, &local.ent[j]);
			if (err)
				goto err_out_close;
			added++;
			removed = !!(ent2.flags & DNET_IO_FLAGS_REMOVED);
		}

		if (i < remote.num) {
			err = dnet_merge_write_history_entry(n, result, fd, &remote.ent[i]);
			if (err)
				goto err_out_close;
			added++;
			removed = !!(ent1.flags & DNET_IO_FLAGS_REMOVED);
		}
	}

	fsync(fd);

	err = dnet_write_file_local_offset(n, result, NULL, 0, &mc->id, 0, 0, 0,
			DNET_ATTR_DIRECT_TRANSACTION, DNET_IO_FLAGS_HISTORY | DNET_IO_FLAGS_NO_HISTORY_UPDATE);
	if (err) {
		dnet_log_raw(n, DNET_LOG_ERROR, "%s: failed to upload merged transaction history: %d.\n",
				dnet_dump_id(&mc->id), err);
		goto err_out_close;
	}

	dnet_log_raw(n, DNET_LOG_INFO, "%s: merged local: %ld, remote: %ld -> %ld entries, removed: %d.\n",
			dnet_dump_id(&mc->id), local.num, remote.num, added, removed);

	if (removed) {
		dnet_remove_object_now(n, &mc->id, 0);
	} else {
		err = dnet_merge_upload_latest(n, mc, &local, &remote);
	}

err_out_close:
	unlink(result);
	close(fd);
err_out_unmap:
	dnet_unmap_history(n, &remote);
err_out_free:
	kcfree(local_history);
err_out_exit:
	return err;
}

static int dnet_check_merge(struct dnet_node *n, struct dnet_meta_container *mc)
{
	int err;
	char file[256], id_str[2*DNET_ID_SIZE+1];

	snprintf(file, sizeof(file), "%s/%s.%d",
			dnet_check_tmp_dir,
			dnet_dump_id_len_raw(mc->id.id, DNET_ID_SIZE, id_str),
			mc->id.group_id);

	err = dnet_read_file(n, file, NULL, 0, &mc->id, 0, 0, 1);
	if (err) {
		if ((err != -ENOENT) && (err != -7)) { /* Kyoto Cabinet 'no record' error *
			dnet_log_raw(n, DNET_LOG_ERROR, "%s: failed to download object to be merged from storage: %d.\n", dnet_dump_id(&mc->id), err);
			goto err_out_exit;
		}

		dnet_log_raw(n, DNET_LOG_INFO, "%s: there is no history in the storage to merge with, "
				"doing direct merge (plain upload).\n", dnet_dump_id(&mc->id));
		err = dnet_merge_direct(n, mc);
	} else {
		snprintf(file, sizeof(file), "%s/%s.%d%s",
				dnet_check_tmp_dir,
				id_str,
				mc->id.group_id,
				DNET_HISTORY_SUFFIX);

		err = dnet_merge_common(n, file, mc);
	}

	dnet_merge_unlink_local_files(n, &mc->id);

	if (err)
		goto err_out_exit;

err_out_exit:
	return err;
}
*/
int dnet_check(struct dnet_node *n, struct dnet_meta_container *mc, struct dnet_bulk_array *bulk_array, int check_copies)
{
	int err = 0;
	void *data;

	err = dnet_db_read_raw(n, mc->id.id, &data);
	if (err <= 0) {
		dnet_log(n, DNET_LOG_ERROR, "%s: meta is present, but there is no history, removing object.\n",
				dnet_dump_id(&mc->id));
		dnet_merge_remove_local(n, &mc->id, 0);
		return err;
	}
	kcfree(data);

	if (!check_copies) {
		//err = dnet_check_merge(n, mc);
		//if (!err)
		//	dnet_merge_remove_local(n, &mc->id, 1);
	} else {
		err = dnet_check_copies(n, mc, bulk_array, check_copies);
	}

	return err;
}

/*int dnet_check_delete_data(struct dnet_node *n, struct dnet_id *id, struct dnet_history_map *map, struct dnet_meta_container *mc)
{
	int err = 0, i, group_num;
	int *groups = NULL;
	struct dnet_id raw;
	int group_id = mc->id.group_id;
	char file[256];
	char eid[2*DNET_ID_SIZE+1];
	struct dnet_history_map remote_map, *result_map;

	err = dnet_check_find_groups(n, mc, &groups);
	dnet_log(n, DNET_LOG_DSA, "%s: %d groups found\n", dnet_dump_id(id), err);
	if (err <= 0)
		return -ENOENT;

	group_num = err;

	for (i=0; i<group_num; ++i) {
		dnet_log(n, DNET_LOG_DSA, "%s: processing group %d [%d] \n", dnet_dump_id(id), groups[i], i);
		if (groups[i] == group_id)
			continue;

		dnet_setup_id(&raw, groups[i], mc->id.id);

		snprintf(file, sizeof(file), "%s/%s.%d", dnet_check_tmp_dir,
			dnet_dump_id_len_raw(raw.id, DNET_ID_SIZE, eid), raw.group_id);

		err = 0;

		err = dnet_read_file(n, file, NULL, 0, &raw, 0, 0, 1);
		dnet_log(n, DNET_LOG_DSA, "%s: reading file history, err=%d \n", dnet_dump_id(id), err);
		if (err)
			goto err_out_continue;

		snprintf(file, sizeof(file), "%s/%s.%d%s", dnet_check_tmp_dir,
			dnet_dump_id_len_raw(raw.id, DNET_ID_SIZE, eid), raw.group_id, DNET_HISTORY_SUFFIX);

		err = dnet_map_history(n, file, &remote_map);
		dnet_log(n, DNET_LOG_DSA, "%s: mapping history, err=%d \n", dnet_dump_id(id), err);
		if (err)
			goto err_out_continue;

		err = dnet_merge_history(n, map, &remote_map, &result_map);
		if (err < 0)
			goto err_out_unmap;

		if (dnet_check_object_removed(result_map)) {
			err = 1;
		}
		free(result_map);

		if (!err && !dnet_check_object_removed(&remote_map)) {
			err = dnet_remove_object(n, NULL, &raw, NULL, NULL, 0);
		}

		dnet_log(n, DNET_LOG_DSA, "%s: is file removed? err=%d \n", dnet_dump_id(id), err);
err_out_unmap:
		dnet_unmap_history(n, &remote_map);

err_out_continue:
		dnet_merge_unlink_local_files(n, &raw);
		if (err)
			break;
	}

	dnet_log(n, DNET_LOG_DSA, "%s: after loop err=%d \n", dnet_dump_id(id), err);
	if (err)
		goto err_out_exit;

	for (i=0; i<group_num; ++i) {
		dnet_log(n, DNET_LOG_DSA, "%s: processing group %d [%d]\n", dnet_dump_id(id), groups[i], i);
		if (groups[i] == group_id)
			continue;

		dnet_setup_id(&raw, groups[i], mc->id.id);
		err = dnet_remove_object_now(n, &raw, 0);
		dnet_log(n, DNET_LOG_DSA, "%s: removing file on remote node, err=%d \n", dnet_dump_id(id), err);
		if (err)
			goto err_out_exit;
	}

	err = dnet_merge_remove_local(n, id, 0);
	dnet_log(n, DNET_LOG_DSA, "%s: removing file on local node, err=%d \n", dnet_dump_id(id), err);

err_out_exit:
	free(groups);
	return err;
}

int dnet_check_delete(struct dnet_node *n, struct dnet_id *id, struct dnet_history_map *map)
{
	int err = 0;
	struct dnet_meta_container *mc;
	void *data;
	size_t size;

	err = dnet_db_read_raw(n, 1, id->id, &data);
	if (err <= 0) {
		dnet_log(n, DNET_LOG_ERROR, "%s: meta is not present, removing file hash.\n",
				dnet_dump_id(id));
		err = dnet_merge_remove_local(n, id, 0);
		return err;
	}

	size = err;
	mc = (struct dnet_meta_container *)malloc(size + sizeof(struct dnet_meta_container));
	memcpy(&mc->data, data, size);
	memcpy(&mc->id, id, sizeof(struct dnet_id));
	mc->size = size;

	err = dnet_check_delete_data(n, id, map, mc);

	free(mc);
	kcfree(data);

	return err;
}*/

static int dnet_check_complete(struct dnet_net_state *state, struct dnet_cmd *cmd,
	struct dnet_attr *attr, void *priv)
{
	struct dnet_wait *w = priv;
	int err = -EINVAL;

	if (is_trans_destroyed(state, cmd, attr)) {
		dnet_wakeup(w, w->cond++);
		dnet_wait_put(w);
		return 0;
	}

	if (!attr)
		return cmd->status;

	if (attr->size == sizeof(struct dnet_check_reply)) {
		struct dnet_check_reply *r = (struct dnet_check_reply *)(attr + 1);

		dnet_convert_check_reply(r);

		dnet_log(state->n, DNET_LOG_INFO, "check: total: %d, completed: %d, errors: %d\n",
				r->total, r->completed, r->errors);
	}

	w->status = cmd->status;
	return err;
}

static int dnet_send_check_request(struct dnet_net_state *st, struct dnet_id *id,
		struct dnet_wait *w, struct dnet_check_request *r)
{
	struct dnet_trans_control ctl;
	char ctl_time[64];
	struct tm tm;

	memset(&ctl, 0, sizeof(struct dnet_trans_control));

	memcpy(&ctl.id, id, sizeof(struct dnet_id));
	ctl.cmd = DNET_CMD_LIST;
	ctl.complete = dnet_check_complete;
	ctl.priv = w;
	ctl.cflags = DNET_FLAGS_NEED_ACK;
	ctl.aflags = 0;

	if (r->timestamp) {
		localtime_r((time_t *)&r->timestamp, &tm);
		strftime(ctl_time, sizeof(ctl_time), "%F %R:%S %Z", &tm);
	} else {
		snprintf(ctl_time, sizeof(ctl_time), "all records");
	}

	dnet_log(st->n, DNET_LOG_INFO, "%s: check request: objects: %llu, threads: %llu, timestamp: %s, merge: %d\n",
			dnet_state_dump_addr(st), (unsigned long long)r->obj_num, (unsigned long long)r->thread_num,
			ctl_time, !!(r->flags & DNET_CHECK_MERGE));

	dnet_convert_check_request(r);

	ctl.data = r;
	ctl.size = sizeof(*r);

	return dnet_trans_alloc_send_state(st, &ctl);
}

int dnet_request_check(struct dnet_node *n, struct dnet_check_request *r)
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

	pthread_mutex_lock(&n->state_lock);
	list_for_each_entry(g, &n->group_list, group_entry) {
		list_for_each_entry(st, &g->state_list, state_entry) {
			struct dnet_id raw;

			if (st == n->st)
				continue;

			dnet_wait_get(w);

			dnet_setup_id(&raw, st->idc->group->group_id, st->idc->ids[0].raw.id);
			dnet_send_check_request(st, &raw, w, r);
			num++;
		}
	}
	pthread_mutex_unlock(&n->state_lock);

	err = dnet_wait_event(w, w->cond == num, &n->wait_ts);
	if (err)
		goto err_out_put;

	if (w->status) {
		err = w->status;
		goto err_out_put;
	}

	dnet_wait_put(w);

	return num;

err_out_put:
	dnet_wait_put(w);
err_out_exit:
	dnet_log(n, DNET_LOG_ERROR, "Check exited with status %d\n", err);
	return err;
}
