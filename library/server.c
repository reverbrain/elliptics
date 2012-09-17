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

#include <sys/stat.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>

#include "elliptics.h"
#include "elliptics/interface.h"

static int dnet_ids_generate(struct dnet_node *n, const char *file, unsigned long long storage_free)
{
	int fd, err, size = 1024, i, num;
	struct dnet_id id;
	struct dnet_raw_id raw;
	unsigned long long q = 100 * 1024 * 1024 * 1024ULL;
	char *buf;

	srand(time(NULL) + (unsigned long)n + (unsigned long)file + (unsigned long)&buf);

	fd = open(file, O_RDWR | O_CREAT | O_TRUNC | O_APPEND | O_CLOEXEC, 0644);
	if (fd < 0) {
		err = -errno;
		dnet_log_err(n, "failed to open/create ids file '%s'", file);
		goto err_out_exit;
	}

	buf = malloc(size);
	if (!buf) {
		err = -ENOMEM;
		goto err_out_close;
	}

	num = storage_free / q + 1;
	for (i=0; i<num; ++i) {
		int r = rand();
		memcpy(buf, &n->addr, sizeof(struct dnet_addr));
		memcpy(buf + sizeof(struct dnet_addr), &r, sizeof(r));

		dnet_transform(n, buf, size, &id);
		memcpy(&raw, id.id, sizeof(struct dnet_raw_id));

		err = write(fd, &raw, sizeof(struct dnet_raw_id));
		if (err != sizeof(struct dnet_raw_id)) {
			dnet_log_err(n, "failed to write id into ids file '%s'", file);
			goto err_out_unlink;
		}
	}

	close(fd);
	return 0;

err_out_unlink:
	unlink(file);
err_out_close:
	close(fd);
err_out_exit:
	return err;
}

static struct dnet_raw_id *dnet_ids_init(struct dnet_node *n, const char *hdir, int *id_num, unsigned long long storage_free)
{
	int fd, err, num;
	const char *file = "ids";
	char path[strlen(hdir) + 1 + strlen(file) + 1]; /* / + null-byte */
	struct stat st;
	struct dnet_raw_id *ids;

	snprintf(path, sizeof(path), "%s/%s", hdir, file);

again:
	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		err = -errno;
		if (err == -ENOENT) {
			err = dnet_ids_generate(n, path, storage_free);
			if (err)
				goto err_out_exit;

			goto again;
		}

		dnet_log_err(n, "failed to open ids file '%s'", path);
		goto err_out_exit;
	}

	err = fstat(fd, &st);
	if (err)
		goto err_out_close;

	if (st.st_size % sizeof(struct dnet_raw_id)) {
		dnet_log(n, DNET_LOG_ERROR, "Ids file size (%lu) is wrong, must be modulo of raw ID size (%zu).\n",
				(unsigned long)st.st_size, sizeof(struct dnet_raw_id));
		goto err_out_close;
	}

	num = st.st_size / sizeof(struct dnet_raw_id);
	if (!num) {
		dnet_log(n, DNET_LOG_ERROR, "No ids read, exiting.\n");
		err = -EINVAL;
		goto err_out_close;
	}

	ids = malloc(st.st_size);
	if (!ids) {
		err = -ENOMEM;
		goto err_out_close;
	}

	err = read(fd, ids, st.st_size);
	if (err != st.st_size) {
		err = -errno;
		dnet_log_err(n, "Failed to read ids file '%s'", path);
		goto err_out_free;
	}

	close(fd);

	*id_num = num;
	return ids;

err_out_free:
	free(ids);
err_out_close:
	close(fd);
err_out_exit:
	return NULL;
}

static int dnet_node_check_stack(struct dnet_node *n)
{
	size_t stack_size;
	int err;

	err = pthread_attr_getstacksize(&n->attr, &stack_size);
	if (err) {
		err = -err;
		dnet_log_err(n, "Failed to get stack size: %d", err);
		goto err_out_exit;
	}

	if (stack_size <= 1024 * 1024) {
		dnet_log(n, DNET_LOG_ERROR, "Stack size (%zd bytes) is too small, exiting\n", stack_size);
		err = -ENOMEM;
		goto err_out_exit;
	}

	dnet_log(n, DNET_LOG_NOTICE, "Stack size: %zd bytes\n", stack_size);

err_out_exit:
	return err;
}

struct dnet_node *dnet_server_node_create(struct dnet_config *cfg)
{
	struct dnet_node *n;
	struct dnet_raw_id *ids = NULL;
	int id_num = 0;
	int err = -ENOMEM;

	n = dnet_node_create(cfg);
	if (!n)
		goto err_out_exit;

	err = dnet_node_check_stack(n);
	if (err)
		goto err_out_node_destroy;

	if (!n->notify_hash_size) {
		n->notify_hash_size = DNET_DEFAULT_NOTIFY_HASH_SIZE;

		err = dnet_notify_init(n);
		if (err)
			goto err_out_node_destroy;

		dnet_log(n, DNET_LOG_NOTICE, "No notify hash size provided, using default %d.\n",
				n->notify_hash_size);
	}

	err = dnet_cache_init(n);
	if (err)
		goto err_out_notify_exit;

	if (cfg->flags & DNET_CFG_JOIN_NETWORK) {
		int s;

		err = dnet_locks_init(n, cfg->oplock_num);
		if (err)
			goto err_out_cache_cleanup;

		ids = dnet_ids_init(n, cfg->history_env, &id_num, cfg->storage_free);
		if (!ids)
			goto err_out_locks_destroy;

		n->addr.addr_len = sizeof(n->addr.addr);
		err = dnet_socket_create(n, cfg, &n->addr, 1);
		if (err < 0)
			goto err_out_ids_cleanup;

		s = err;
		dnet_setup_id(&n->id, cfg->group_id, ids[0].id);

		n->st = dnet_state_create(n, cfg->group_id, ids, id_num, &n->addr, s, &err, DNET_JOIN, dnet_state_accept_process);
		if (!n->st) {
			close(s);
			goto err_out_state_destroy;
		}

		free(ids);
		ids = NULL;

		err = dnet_srw_init(n, cfg);
		if (err) {
			dnet_log(n, DNET_LOG_ERROR, "srw: initialization failure: %s %d\n", strerror(-err), err);
		}
	}

	dnet_log(n, DNET_LOG_DEBUG, "New server node has been created at %s, ids: %d.\n",
			dnet_dump_node(n), id_num);

	return n;

err_out_state_destroy:
	dnet_srw_cleanup(n);
	dnet_state_put(n->st);
err_out_ids_cleanup:
	free(ids);
err_out_locks_destroy:
	dnet_locks_destroy(n);
err_out_cache_cleanup:
	dnet_cache_cleanup(n);
err_out_notify_exit:
	dnet_notify_exit(n);
err_out_node_destroy:
	dnet_node_destroy(n);
err_out_exit:
	return NULL;
}

void dnet_server_node_destroy(struct dnet_node *n)
{
	dnet_log(n, DNET_LOG_DEBUG, "Destroying server node at %s, st: %p.\n",
			dnet_dump_node(n), n->st);


	dnet_node_cleanup_common_resources(n);

	if (n->cb && n->cb->backend_cleanup)
		n->cb->backend_cleanup(n->cb->command_private);

	dnet_srw_cleanup(n);
	dnet_locks_destroy(n);
	dnet_notify_exit(n);

	free(n);
}

