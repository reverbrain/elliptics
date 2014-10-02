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
#include "elliptics/interface.h"
#include "monitor/monitor.h"

static int dnet_node_check_stack(struct dnet_node *n)
{
	size_t stack_size;
	size_t min_stack_size = 1024 * 1024;
	int err;

	err = pthread_attr_getstacksize(&n->attr, &stack_size);
	if (err) {
		err = -err;
		dnet_log_err(n, "Failed to get stack size: %d", err);
		goto err_out_exit;
	}

	if (stack_size < min_stack_size) {
		dnet_log(n, DNET_LOG_ERROR, "Stack size (%zd bytes) is too small, should be at least %zd, exiting",
				stack_size, min_stack_size);
		err = -ENOMEM;
		goto err_out_exit;
	}

	dnet_log(n, DNET_LOG_NOTICE, "Stack size: %zd bytes", stack_size);

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

struct dnet_node *dnet_server_node_create(struct dnet_config_data *cfg_data)
{
	struct dnet_node *n;
	struct dnet_config *cfg = &cfg_data->cfg_state;
	struct dnet_addr *addrs = cfg_data->cfg_addrs;
	int addr_num = cfg_data->cfg_addr_num;
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

	err = dnet_server_io_init(n);
	if (err)
		goto err_out_node_destroy;

	err = dnet_monitor_init(n, cfg);
	if (err)
		goto err_out_node_destroy;

	err = dnet_node_check_stack(n);
	if (err)
		goto err_out_monitor_destroy;

	if (!n->notify_hash_size) {
		n->notify_hash_size = DNET_DEFAULT_NOTIFY_HASH_SIZE;

		err = dnet_notify_init(n);
		if (err)
			goto err_out_monitor_destroy;

		dnet_log(n, DNET_LOG_NOTICE, "No notify hash size provided, using default %d.",
				n->notify_hash_size);
	}

	err = dnet_local_addr_add(n, addrs, addr_num);
	if (err)
		goto err_out_notify_exit;

	if (cfg->flags & DNET_CFG_JOIN_NETWORK) {
		int s;
		struct dnet_addr la;

		err = dnet_locks_init(n, 1024);
		if (err) {
			dnet_log(n, DNET_LOG_ERROR, "failed to init locks: %s %d", strerror(-err), err);
			goto err_out_addr_cleanup;
		}

		n->route = dnet_route_list_create(n);
		if (!n->route) {
			dnet_log(n, DNET_LOG_ERROR, "failed to create route list: %s %d", strerror(-err), err);
			goto err_out_locks_destroy;
		}

		err = dnet_create_addr(&la, NULL, cfg->port, cfg->family);
		if (err < 0) {
			dnet_log(n, DNET_LOG_ERROR, "Failed to get address info for 0.0.0.0:%d, family: %d, err: %d: %s.",
				cfg->port, cfg->family, err, strerror(-err));
			goto err_out_route_list_destroy;
		}

		err = dnet_socket_create_listening(n, &la);
		if (err < 0)
			goto err_out_route_list_destroy;

		s = err;

		if (s < 0) {
			err = s;
			dnet_log(n, DNET_LOG_ERROR, "failed to create socket: %s %d", strerror(-err), err);
			goto err_out_route_list_destroy;
		}

		n->st = dnet_state_create(n, NULL, 0, n->addrs, s, &err, DNET_JOIN, 1, 0, 1, n->addrs, n->addr_num);

		if (!n->st) {
			dnet_log(n, DNET_LOG_ERROR, "failed to create state: %s %d", strerror(-err), err);
			goto err_out_state_destroy;
		}

		// @dnet_state_create() returns state pointer which holds 2 references - one for originally created state
		// and another for caller in case he wants to do something with the state. The first reference is owned
		// by network thread given state was attached to, and it can already release it.
		dnet_state_put(n->st);

		err = dnet_backend_init_all(n);
		if (err) {
			dnet_log(n, DNET_LOG_ERROR, "failed to init backends: %s %d", strerror(-err), err);
			goto err_out_state_destroy;
		}

		if (!cfg->srw.config) {
			dnet_log(n, DNET_LOG_INFO, "srw: no config");
			n->srw = NULL;
		} else {
			err = dnet_srw_init(n, cfg);
			if (err) {
				dnet_log(n, DNET_LOG_ERROR, "srw: initialization failure: %s %d", strerror(-err), err);
				goto err_out_backends_cleanup;
			}
		}
	}

	dnet_log(n, DNET_LOG_DEBUG, "New server node has been created at port %d.", cfg->port);

	pthread_sigmask(SIG_SETMASK, &previous_sigset, NULL);
	return n;

	dnet_srw_cleanup(n);
err_out_backends_cleanup:
	dnet_set_need_exit(n);
	dnet_backend_cleanup_all(n);
err_out_state_destroy:
	dnet_state_put(n->st);
err_out_route_list_destroy:
	dnet_route_list_destroy(n->route);
err_out_locks_destroy:
	dnet_locks_destroy(n);
err_out_addr_cleanup:
	dnet_local_addr_cleanup(n);
err_out_notify_exit:
	n->need_exit = err;
	dnet_notify_exit(n);
err_out_monitor_destroy:
	dnet_monitor_exit(n);
err_out_node_destroy:
	dnet_node_destroy(n);
err_out_exit:
	pthread_sigmask(SIG_SETMASK, &previous_sigset, NULL);
	return NULL;
}

void dnet_server_node_destroy(struct dnet_node *n)
{
	dnet_log(n, DNET_LOG_DEBUG, "Destroying server node.");

	/*
	 * Monitor uses all others, so it should be stopped at first.
	 */
	dnet_monitor_exit(n);

	/*
	 * Cache can be accessed from the io threads, so firstly stop them.
	 * Cache uses backend to dump all ansynced data to the disk, so
	 * backend must be destroyed the last.
	 *
	 * After all of them finish destroying the node, all it's counters and so on.
	 */
	dnet_node_cleanup_common_resources(n);

	dnet_route_list_destroy(n->route);
	n->route = NULL;

	dnet_backend_cleanup_all(n);

	dnet_srw_cleanup(n);

	dnet_counter_destroy(n);
	dnet_locks_destroy(n);
	dnet_local_addr_cleanup(n);
	dnet_notify_exit(n);

	if (n->config_data)
		n->config_data->destroy_config_data(n->config_data);

	free(n);
}

