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
		attr->flags = DNET_ATTR_DELETE_HISTORY;

	dnet_convert_attr(attr);

	base = dnet_node_state(n);
	if (base) {
		err = dnet_process_cmd_raw(base, cmd, attr);
		dnet_state_put(base);
	}

	return err;
}

int dnet_cmd_bulk_check(struct dnet_net_state *orig, struct dnet_cmd *cmd, struct dnet_attr *attr, void *data)
{
	struct dnet_attr ca;
	struct dnet_bulk_id *ids = (struct dnet_bulk_id *)data;
	struct dnet_meta_container mc;
	struct dnet_meta_update mu;
	struct dnet_id raw;
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
			mc.data = NULL;
			err = dnet_db_read_raw(orig->n, ids[i].id, (void **)&mc.data);
			if (mc.data) {
				mc.size = err;
				dnet_log(orig->n, DNET_LOG_DSA, "BULK: %d bytes of metadata found, searching for META_UPDATE group_id=%d\n",
						mc.size, orig->n->st->idc->group->group_id);
				if (dnet_get_meta_update(orig->n, &mc, orig->n->st->idc->group->group_id, &mu))
				{
					dnet_convert_meta_update(&ids[i].last_update);
					dnet_log(orig->n, DNET_LOG_DSA, "BULK: mu.tsec=%lu, mu.tnsec=%lu, mu.flags=%02lx\n",
							(unsigned long)mu.tsec, (unsigned long)mu.tnsec, (unsigned long)mu.flags);
					dnet_log(orig->n, DNET_LOG_DSA, "BULK: last_update.tsec=%lu, last_update.tnsec=%lu, last_update.flags=%02lx\n",
							(unsigned long)ids[i].last_update.tsec, (unsigned long)ids[i].last_update.tnsec, (unsigned long)ids[i].last_update.flags);

					if ((mu.flags & DNET_IO_FLAGS_REMOVED) || (mu.tsec < ids[i].last_update.tsec) || 
							((mu.tnsec < ids[i].last_update.tnsec) && (mu.tsec == ids[i].last_update.tsec))) {
						err = 0;
					} else {
						dnet_setup_id(&raw, orig->n->id.group_id, ids[i].id);
						err = dnet_stat_local(orig, &raw);
						if (err) {
							//File was not found in the storage
							mu.tsec = 1;
							mu.flags = 0;
						} else {
							err = dnet_db_check_update(orig->n, &mc);
							if (err) {
								dnet_log(orig->n, DNET_LOG_ERROR, "%s: couldn't update meta CHECK_STATUS\n", dnet_dump_id_str(ids[i].id));
							}
						}
					}

					memcpy(&ids[i].last_update, &mu, sizeof(struct dnet_meta_update));
					dnet_convert_meta_update(&ids[i].last_update);
				}
				kcfree(mc.data);
			} else {
				dnet_convert_meta_update(&ids[i].last_update);
				ids[i].last_update.tsec = 1;
				ids[i].last_update.flags = 0;
				dnet_convert_meta_update(&ids[i].last_update);
			}
/*			if (err > 0) {
				dnet_log(orig->n, DNET_LOG_DSA, "BULK: file exists in meta DB, it is synchronized, removing it from output\n");
				memmove(&ids[i], &ids[i+1], (num-i-1) * sizeof(struct dnet_bulk_id));
				--i;
				--num;
			}*/
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
	struct dnet_meta_container mc;
	struct dnet_meta_update *mu;
	struct dnet_meta *mg;
	int *groups, group_num;
	int my_gropu;
	int err = -EINVAL, error = 0;

	if (is_trans_destroyed(state, cmd, attr)) {
		dnet_wakeup(w, w->cond++);
		dnet_wait_put(w);
		return 0;
	}

	if (!attr)
		return cmd->status;

	my_group = state->n->st->idc->group->group_id;

	if (!(attr->size % sizeof(struct dnet_bulk_id))) {
		struct dnet_bulk_id *ids = (struct dnet_bulk_id *)(attr + 1);
		int num = attr->size / sizeof(struct dnet_bulk_id);
		int i, j;
		int lastest_group = -1;
		struct dnet_meta_update lastest_mu, my_mu, tmp_mu, *tmp_mup;
		int removed_in_all = 1;

		dnet_log(state->n, DNET_LOG_DSA, "BULK: received %d entries\n", num);

		for (i = 0; i < num; ++i) {
			dnet_log(state->n, DNET_LOG_DSA, "BULK: checking ID %s\n", dnet_dump_id_str(ids[i].id));
			err = -ENOENT;
			error = 0;

			dnet_setup_id(&mc.id, my_group, ids[i].id);

			err = dnet_db_read_raw(state->n, ids[i].id, (void **)&mc.data);
			if (err <= 0) {
				if (err == 0)
					err = -ENOENT;
				goto err_out_continue;
			}
			mc.size = err;

			/* Set current group meta_update as lastest_mu */
			if (!dnet_get_meta_update(state->n, &mc, my_group, &my_mu)) {
				dnet_log(state->n, DNET_LOG_ERROR, "%s: BULK: meta_update structure doesn't exist for group %d\n",
						dnet_dump_id_str(ids[i].id), my_group);
				err = -ENOENT;
				goto err_out_kcfree;
			}
			dnet_convert_meta_update(&my_mu);
			memcpy(&lastest_mu, &my_mu, sizeof(struct dnet_meta_update));
			lastest_group = my_group;

			/* Update meta_update for received group */
			mu = dnet_get_meta_update(state->n, &mc, state->idc->group->group_id, NULL);
			if (!mu) {
				dnet_log(state->n, DNET_LOG_ERROR, "%s: BULK: meta_update structure doesn't exist for group %d\n",
						dnet_dump_id_str(ids[i].id), state->idc->group->group_id);
				err = -ENOENT;
				goto err_out_kcfree;
			}
			dnet_convert_meta_update(mu);
			mu->tsec = ids[i].last_update.tsec;
			mu->tnsec = ids[i].last_update.tnsec;
			mu->flags = ids[i].last_update.flags;
			dnet_convert_meta_update(mu);

			err = dnet_db_write_trans(state->n, &mc.id, mc.data, mc.size, 0);

			/* Get group list */
			mg = dnet_meta_search(state->n, &mc, DNET_META_GROUPS);
			if (!mg) {
				dnet_log(state->n, DNET_LOG_ERROR, "%s: BULK: DNET_META_GROUPS structure doesn't exist\n", dnet_dump_id_str(ids[i].id));
				err = -ENOENT;
				goto err_out_kcfree;
			}
			dnet_convert_meta(mg);
			if (mg->size % sizeof(int)) {
				dnet_log(state->n, DNET_LOG_ERROR, "%s: BULK: DNET_META_GROUPS structure is corrupted\n", dnet_dump_id_str(ids[i].id));
				err = -1;
				goto err_out_kcfree;
			}
			group_num = mg->size / sizeof(int);
			groups = (int *)mg->data;
			dnet_convert_meta(mg);

			/* Iterate through groups to find the lastest */
			for (j = 0; j < group_num; ++j) {
				if (groups[j] == my_group)
					continue;

				if (!dnet_get_meta_update(state->n, &mc, groups[j], &tmp_mu)) {
					dnet_log(state->n, DNET_LOG_ERROR, "%s: BULK: meta_update structure doesn't exist for group %d\n",
							dnet_dump_id_str(ids[i].id), groups[j]);
					err = -ENOENT;
					goto err_out_kcfree;
				}
				if (tmp_mu.flags == ~0U)
					break;

				if (!(tmp_mu.flags & DNET_IO_FLAGS_REMOVED))
					removed_in_all = 0;

				if ((tmp_mu.tsec > lastest_mu.tsec) || ((tmp_mu.tsec == lastest_mu.tsec) && (tmp_mu.tnsec > lastest_mu.tnsec))) {
					memcpy(&lastest_mu, &tmp_mu, sizeof(struct dnet_meta_update));
					lastest_group = groups[j];
				}
			}

			/* XXX
			 *
			 * tmp_mu can be uninitialized here, should it be latest_mu instead?
			 */
			if (tmp_mu.flags == ~0U) {
				err = 0;
				goto err_out_kcfree;
			}

			/* TODO: receive newer files from remote groups
			 *
			 * Yep, we should read it locally and send it to other groups too
			 */
			if ((lastest_group != my_group) && !(lastest_mu.flags & DNET_IO_FLAGS_REMOVED)) {
				dnet_log(state->n, DNET_LOG_DSA, "%s: File on remote group %d is newer, skipping this file\n",
						dnet_dump_id_str(ids[i].id), lastest_group);
				err = 0;
				goto err_out_kcfree;
			}

			for (j = 0; j < group_num; ++j) {
				err = 0;
				if (groups[j] == my_group)
					continue;

				tmp_mup = dnet_get_meta_update(state->n, &mc, groups[j], &tmp_mu);
				if (!tmp_mup) {
					dnet_log(state->n, DNET_LOG_ERROR, "%s: BULK: meta_update structure doesn't exist for group %d\n",
							dnet_dump_id_str(ids[i].id), groups[j]);
					err = -ENOENT;
					goto err_out_kcfree;
				}

				dnet_setup_id(&id, groups[j], ids[i].id);

				if (lastest_mu.flags & DNET_IO_FLAGS_REMOVED) {
					if (removed_in_all) {
						dnet_log(state->n, DNET_LOG_DSA, "BULK: dnet_remove_object_now %s in group %d, err=%d\n", dnet_dump_id(&id), my_group, err);
						err = dnet_remove_object_now(state->n, &id, 0);
					} else {
						if (!(tmp_mu.flags & DNET_IO_FLAGS_REMOVED)) {
							err = dnet_remove_object(state->n, NULL, &id, NULL, NULL, 0);
							dnet_log(state->n, DNET_LOG_DSA, "BULK: dnet_remove_object %s in group %d err=%d\n", dnet_dump_id(&id), my_group, err);
						}
					}
					if (err < 0)
						goto err_out_cont2;
				} else {
					if ((tmp_mu.tsec < lastest_mu.tsec) || ((tmp_mu.tsec == lastest_mu.tsec) && ((tmp_mu.tnsec < lastest_mu.tnsec)))) {
						err = state->n->send(state, state->n->command_private, &id);

						if (err)
							goto err_out_cont2;

						memcpy(tmp_mup, &lastest_mu, sizeof(struct dnet_meta_update));
						tmp_mup->group_id = tmp_mu.group_id;
						dnet_convert_meta_update(tmp_mup);

						err = dnet_write_data_wait(state->n, NULL, 0, &id, mc.data, -1, 0, 0, mc.size, NULL,
							0, DNET_IO_FLAGS_META | DNET_IO_FLAGS_NO_HISTORY_UPDATE);
						dnet_log(state->n, DNET_LOG_DSA, "BULK: dnet_write_data_wait %s in group %d, err=%d\n", dnet_dump_id(&id), my_group, err);

						if (err < 0)
							goto err_out_cont2;
					}
				}
err_out_cont2:
				if (err < 0)
					dnet_log(state->n, DNET_LOG_ERROR, "%s: BULK: Error during sending transaction to group %d, err=%d\n",
							dnet_dump_id_str(ids[i].id), groups[j], err);
				if (!error && err < 0)
					error = err;
			}

			if (lastest_mu.flags & DNET_IO_FLAGS_REMOVED) {
				if (removed_in_all) {
					err = dnet_merge_remove_local(state->n, &mc.id, 0);
				} else if (my_mu.flags & DNET_IO_FLAGS_REMOVED) {
					err = dnet_merge_remove_local(state->n, &mc.id, 1);
				}
			}

			if (!(lastest_mu.flags & DNET_IO_FLAGS_REMOVED) && !error)
				dnet_db_check_update(state->n, &mc);

			if (error > 0)
				error = 0;
err_out_kcfree:
			kcfree(mc.data);
err_out_continue:
			if (error < 0) {
				dnet_log(state->n, DNET_LOG_ERROR, "Failed to check ID %s to %s, err=%d\n", dnet_dump_id_str(ids[i].id),
						dnet_state_dump_addr(state), error);
			}
			dnet_counter_inc(state->n, DNET_CNTR_NODE_CHECK_COPY, error);
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
	dnet_wait_get(w);

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

static int dnet_bulk_add_id(struct dnet_node *n, struct dnet_bulk_array *bulk_array, struct dnet_id *id, struct dnet_meta_container *mc)
{
	int err = 0;
	struct dnet_bulk_state tmp;
	struct dnet_bulk_state *state = NULL;
	struct dnet_net_state *st = dnet_state_get_first(n, id);
	struct dnet_bulk_id *bulk_id;
	struct dnet_meta_update mu;

	dnet_log(n, DNET_LOG_DSA, "BULK: adding ID %s to array\n", dnet_dump_id(id));
	if (!st)
		return -1;

	memcpy(&tmp.addr, &st->addr, sizeof(struct dnet_addr));
	dnet_state_put(st);

	state = bsearch(&tmp, bulk_array->states, bulk_array->num, sizeof(struct dnet_bulk_state), dnet_compare_bulk_state);
	if (!state)
		return -1;

	if (!dnet_get_meta_update(n, mc, n->st->idc->group->group_id, &mu))
		return -ENOENT;

	dnet_log(n, DNET_LOG_DSA, "BULK: addr = %s state->num = %d\n", dnet_server_convert_dnet_addr(&state->addr), state->num);
	//pthread_mutex_lock(&state->state_lock);
	if (state->num >= DNET_BULK_IDS_SIZE || state->num < 0)
		goto err_out_unlock;

	bulk_id = &state->ids[state->num];
	memset(bulk_id, 0, sizeof(struct dnet_bulk_id));

	memcpy(&bulk_id->id, &id->id, DNET_ID_SIZE);

	dnet_log(n, DNET_LOG_DSA, "BULK: ID: %s, last_update->tsec=%llu, last_update->tnsec=%llu, flags=%02llx\n", 
			dnet_dump_id_str(bulk_id->id), (unsigned long long)mu.tsec, (unsigned long long)mu.tnsec,
			(unsigned long long)mu.flags);

	dnet_convert_meta_update(&mu);

	memcpy(&bulk_id->last_update, &mu, sizeof(struct dnet_meta_update));

	state->num++;

	dnet_log(n, DNET_LOG_DSA, "BULK: addr = %s state->num = %d\n", dnet_server_convert_dnet_addr(&state->addr), state->num);
	if (state->num == DNET_BULK_IDS_SIZE) {
		err = dnet_request_bulk_check(n, state);
		state->num = 0;
		if (err)
			goto err_out_unlock;
	}

	//pthread_mutex_unlock(&state->state_lock);

	return 0;

err_out_unlock:
	//pthread_mutex_unlock(&state->state_lock);
	return -2;
}

static int dnet_check_number_of_copies(struct dnet_node *n, struct dnet_meta_container *mc, int *groups, int group_num, struct dnet_bulk_array *bulk_array, int check_copies)
{
	struct dnet_id raw;
	int group_id = mc->id.group_id;
	struct dnet_meta_update *mu;
	int err, i, error = 0;

	for (i=0; i<group_num; ++i) {
		if (groups[i] == group_id)
			continue;

		dnet_log(n, DNET_LOG_NOTICE, "Cleaning META_UPDATE for group %d\n", groups[i]);
		mu = dnet_get_meta_update(n, mc, groups[i], NULL);
		if (!mu) {
			dnet_log(n, DNET_LOG_ERROR, "%s: BULK: meta_update structure doesn't exist for group %d\n", dnet_dump_id(&mc->id), groups[i]);
			return -ENOENT;
		}
		mu->tsec = 0;
		mu->tnsec = 0;
		mu->flags = ~0;
	}
	err = dnet_db_write_trans(n, &mc->id, mc->data, mc->size, 0);
	if (err)
		return err;

	for (i=0; i<group_num; ++i) {
		if (groups[i] == group_id)
			continue;

		dnet_setup_id(&raw, groups[i], mc->id.id);

		err = dnet_bulk_add_id(n, bulk_array, &raw, mc);
		if (err)
			dnet_log(n, DNET_LOG_ERROR, "BULK: after adding ID %s err = %d\n", dnet_dump_id(&raw), err);

		if (!err)
			error = 0;
		else if (!error)
			error = err;
	}

	return error;
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
	int err;

	base = dnet_node_state(n);
	if (!base) {
		err = -ENOENT;
		goto err_out_exit;
	}

	err = n->send(base, n->command_private, &mc->id);
	if (err < 0)
		goto err_out_put;

	err = dnet_write_metadata(n, mc, 0);
	if (err <= 0)
		goto err_out_put;

	err = 0;

	//dnet_merge_remove_local(n, &mc->id, 0);

err_out_put:
	dnet_state_put(base);
err_out_exit:
	return err;
}

static int dnet_merge_upload(struct dnet_node *n, struct dnet_meta_container *mc)
{
	struct dnet_net_state *base;
	int err = 0;

	base = dnet_node_state(n);
	if (!base) {
		err = -ENOENT;
		goto err_out_exit;
	}

	err = n->send(base, n->command_private, &mc->id);
	if (err)
		goto err_out_put;

	err = dnet_write_metadata(n, mc, 0);
	if (err <= 0)
		goto err_out_put;

err_out_put:
	dnet_state_put(base);
err_out_exit:
	return err;
}

static int dnet_merge_common(struct dnet_node *n, struct dnet_meta_container *remote_meta, struct dnet_meta_container *mc)
{
	int err = 0;
	struct dnet_meta_update local, remote;

	if (!dnet_get_meta_update(n, mc, mc->id.group_id, &local)) {
		err = -ENOENT;
		dnet_log(n, DNET_LOG_ERROR, "%s: META_UPDATE not found in local meta\n", dnet_dump_id(&mc->id));
		goto err_out_exit;
	}

	if (!dnet_get_meta_update(n, remote_meta, mc->id.group_id, &remote)) {
		err = -ENOENT;
		dnet_log(n, DNET_LOG_ERROR, "%s: META_UPDATE not found in remote meta, perform direct merge\n", dnet_dump_id(&mc->id));
		err = dnet_merge_direct(n, mc);
		goto err_out_exit;
	}

	if ((local.tsec > remote.tsec) || (local.tsec == remote.tsec && local.tnsec > remote.tnsec)) {
		if (local.flags & DNET_IO_FLAGS_REMOVED) {
			err = dnet_remove_object_now(n, &mc->id, 0);
		} else {
			err = dnet_merge_upload(n, mc);
		}
	}

err_out_exit:
	return err;

}

static int dnet_check_merge(struct dnet_node *n, struct dnet_meta_container *mc)
{
	int err;
	struct dnet_meta_container remote_mc;

	memset(&remote_mc, 0, sizeof(struct dnet_meta_container));

	err = dnet_read_meta(n, &remote_mc, NULL, 0, &mc->id);
	if (err) {
		if ((err != -ENOENT) && (err != -7)) { /* Kyoto Cabinet 'no record' error */
			dnet_log_raw(n, DNET_LOG_ERROR, "%s: failed to download object to be merged from storage: %d.\n", dnet_dump_id(&mc->id), err);
			goto err_out_exit;
		}

		dnet_log_raw(n, DNET_LOG_INFO, "%s: there is no meta in the storage to merge with, "
				"doing direct merge (plain upload).\n", dnet_dump_id(&mc->id));
		err = dnet_merge_direct(n, mc);
	} else {

		err = dnet_merge_common(n, &remote_mc, mc);
	}

	//dnet_merge_unlink_local_files(n, &mc->id);

	if (err)
		goto err_out_exit;

err_out_exit:
	if (remote_mc.data)
		free(remote_mc.data);
	return err;
}

int dnet_check(struct dnet_node *n, struct dnet_meta_container *mc, struct dnet_bulk_array *bulk_array, int check_type)
{
	int err = 0;

	dnet_log(n, DNET_LOG_DSA, "check_type = %d\n", check_type);
	switch (check_type) {
		case DNET_CHECK_TYPE_COPIES_HISTORY:
		case DNET_CHECK_TYPE_COPIES_FULL:
		case DNET_CHECK_TYPE_DELETE:
			err = dnet_check_copies(n, mc, bulk_array, check_type);
			break;
		case DNET_CHECK_TYPE_MERGE:
			err = dnet_check_merge(n, mc);
			if (!err)
				dnet_merge_remove_local(n, &mc->id, 0);
			break;
		default:
			dnet_log(n, DNET_LOG_ERROR, "%s: Incorrect check type %d.\n",
				dnet_dump_id(&mc->id), check_type);
	}

	return err;
}

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
	ctl.size = sizeof(*r) + r->obj_num * sizeof(struct dnet_id);

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
