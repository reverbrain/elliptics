/*
 * Copyright 2008+ Evgeniy Polyakov <zbr@ioremap.net>
 *
 * This file is part of Elliptics.
 *
 * Elliptics is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Elliptics is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with Elliptics.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <sys/stat.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>

#include "elliptics.h"
#include "../monitor/monitor.h"

#include "elliptics/interface.h"

static int dnet_ids_generate(struct dnet_node *n, const char *file, unsigned long long storage_free)
{
	int fd, err, size = 1024, i, num;
	struct dnet_raw_id id;
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
		memcpy(buf, &r, sizeof(r));

		dnet_transform_node(n, buf, size, id.id, sizeof(id.id));
		memcpy(&raw, id.id, sizeof(struct dnet_raw_id));

		err = write(fd, &raw, sizeof(struct dnet_raw_id));
		if (err != sizeof(struct dnet_raw_id)) {
			dnet_log_err(n, "failed to write id into ids file '%s'", file);
			goto err_out_unlink;
		}
	}

	free(buf);
	close(fd);
	return 0;

err_out_unlink:
	unlink(file);
	free(buf);
err_out_close:
	close(fd);
err_out_exit:
	return err;
}

static struct dnet_raw_id *dnet_ids_init(struct dnet_node *n, const char *hdir, int *id_num, unsigned long long storage_free, struct dnet_addr *cfg_addrs, char* remotes)
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
			if (n->flags & DNET_CFG_KEEPS_IDS_IN_CLUSTER)
				err = dnet_ids_update(1, path, cfg_addrs, remotes);
			if (err)
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

	if (n->flags & DNET_CFG_KEEPS_IDS_IN_CLUSTER)
		dnet_ids_update(0, path, cfg_addrs, remotes);

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

static void dnet_local_addr_cleanup(struct dnet_node *n)
{
	free(n->addrs);
	n->addrs = NULL;
	n->addr_num = 0;
}

static int dnet_local_addr_add(struct dnet_node *n, struct dnet_addr *addrs, int addr_num)
{
	int err = 0;

	n->addrs = malloc(sizeof(struct dnet_addr) * addr_num);
	if (!n->addrs) {
		err = -ENOMEM;
		goto err_out_exit;
	}

	memcpy(n->addrs, addrs, addr_num * sizeof(struct dnet_addr));
	n->addr_num = addr_num;

err_out_exit:
	return err;
}

struct dnet_node *dnet_server_node_create(struct dnet_config_data *cfg_data, struct dnet_config *cfg, struct dnet_addr *addrs, int addr_num)
{
	struct dnet_node *n;
	struct dnet_raw_id *ids = NULL;
	int id_num = 0;
	int err = -ENOMEM;

	sigset_t previous_sigset;
	sigset_t sigset;
	sigemptyset(&sigset);
	sigaddset(&sigset, SIGINT);
	sigaddset(&sigset, SIGTERM);
	sigaddset(&sigset, SIGALRM);
	sigaddset(&sigset, SIGQUIT);
	pthread_sigmask(SIG_BLOCK, &sigset, &previous_sigset);

	n = dnet_node_create(cfg);
	if (!n)
		goto err_out_exit;

	n->config_data = cfg_data;

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

	err  = dnet_monitor_init(n, cfg);
	if (err)
		goto err_out_notify_exit;

	err = dnet_cache_init(n);
	if (err)
		goto err_out_monitor_exit;

	err = dnet_local_addr_add(n, addrs, addr_num);
	if (err)
		goto err_out_cache_cleanup;

	if (cfg->flags & DNET_CFG_JOIN_NETWORK) {
		struct dnet_addr la;
		int s;

		err = dnet_locks_init(n, 1024);
		if (err)
			goto err_out_addr_cleanup;

		ids = dnet_ids_init(n, cfg->history_env, &id_num, cfg->storage_free, cfg_data->cfg_addrs, cfg_data->cfg_remotes);
		if (!ids)
			goto err_out_locks_destroy;

		memset(&la, 0, sizeof(struct dnet_addr));
		la.addr_len = sizeof(la.addr);
		la.family = cfg->family;

		err = dnet_socket_create(n, NULL, cfg->port, &la, 1);
		if (err < 0)
			goto err_out_ids_cleanup;

		s = err;
		dnet_setup_id(&n->id, cfg->group_id, ids[0].id);

		n->st = dnet_state_create(n, cfg->group_id, ids, id_num, &la, s, &err, DNET_JOIN, -1, dnet_state_accept_process);
		if (!n->st) {
			close(s);
			goto err_out_state_destroy;
		}

		free(ids);
		ids = NULL;

		if (!cfg->srw.config) {
			dnet_log(n, DNET_LOG_INFO, "srw: no config\n");
			n->srw = NULL;
		} else {
			err = dnet_srw_init(n, cfg);
			if (err) {
				dnet_log(n, DNET_LOG_ERROR, "srw: initialization failure: %s %d\n", strerror(-err), err);
				goto err_out_state_destroy;
			}
		}
	}

	dnet_log(n, DNET_LOG_DEBUG, "New server node has been created at port %d, ids: %d.\n", cfg->port, id_num);

	pthread_sigmask(SIG_SETMASK, &previous_sigset, NULL);
	return n;

	dnet_srw_cleanup(n);
err_out_state_destroy:
	dnet_state_put(n->st);
err_out_ids_cleanup:
	free(ids);
err_out_locks_destroy:
	dnet_locks_destroy(n);
err_out_addr_cleanup:
	dnet_local_addr_cleanup(n);
err_out_cache_cleanup:
	dnet_cache_cleanup(n);
err_out_monitor_exit:
	dnet_monitor_exit(n);
err_out_notify_exit:
	dnet_notify_exit(n);
err_out_node_destroy:
	dnet_node_destroy(n);
err_out_exit:
	pthread_sigmask(SIG_SETMASK, &previous_sigset, NULL);
	return NULL;
}

void dnet_server_node_destroy(struct dnet_node *n)
{
	dnet_log(n, DNET_LOG_DEBUG, "Destroying server node.\n");

	/*
	 * Cache can be accessed from the io threads, so firstly stop them.
	 * Cache uses backend to dump all ansynced data to the disk, so
	 * backend must be destroyed the last.
	 *
	 * After all of them finish destroying the node, all it's counters and so on.
	 */
	dnet_monitor_exit(n);
	dnet_node_cleanup_common_resources(n);

	dnet_srw_cleanup(n);
	dnet_cache_cleanup(n);

	if (n->cache_pages_proportions)
		free(n->cache_pages_proportions);

	if (n->cb && n->cb->backend_cleanup)
		n->cb->backend_cleanup(n->cb->command_private);

	dnet_counter_destroy(n);
	dnet_locks_destroy(n);
	dnet_local_addr_cleanup(n);
	dnet_notify_exit(n);

	if (n->config_data) {
		free(n->config_data->logger_value);
		free(n->config_data->cfg_addrs);
		free(n->config_data->cfg_remotes);
		free(n->config_data->cfg_backend);
		free(n->config_data);
	}

	free(n);
}

