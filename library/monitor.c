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

#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "elliptics.h"
#include "elliptics/packet.h"
#include "elliptics/interface.h"

static void *dnet_monitor_process(void *__n)
{
	struct dnet_node *n = __n;
	struct pollfd pfd;
	int err = 0;
	char buf[512];

	pfd.events = POLLIN;
	pfd.fd = n->monitor_fd;
	pfd.revents = 0;

	while (!n->need_exit) {
		err = poll(&pfd, 1, 1000);
		if (err < 0) {
			if (errno == EAGAIN || errno == EINTR)
				continue;

			err = -errno;
			dnet_log_err(n, "failed to wait for data in monitor pipe");
			goto err_out_exit;
		}

		if (err == 0)
			continue;

		if (pfd.revents & (POLLRDHUP | POLLERR | POLLHUP | POLLNVAL)) {
			dnet_log(n, DNET_LOG_ERROR, "Monitor pipe returned error revents: %x.\n",
				pfd.revents);
			err = -ECONNRESET;
			goto err_out_exit;
		}

		err = read(n->monitor_fd, buf, sizeof(buf) - 1);
		if (err <= 0) {
			err = -errno;
			dnet_log_err(n, "Failed to read data from monitor pipe");
			goto err_out_exit;
		}

		dnet_log(n, DNET_LOG_INFO, "monitor: %s\n", buf);
		err = snprintf(buf, sizeof(buf), "I'm %d\n", getpid());

		err = write(n->monitor_fd, buf, err + 1);
	}

err_out_exit:
	if (err)
		n->need_exit = err;
	return NULL;
}

void dnet_monitor_exit(struct dnet_node *n)
{
	if (!n->monitor_tid)
		return;
	pthread_join(n->monitor_tid, NULL);
	close(n->monitor_fd);
}

int dnet_monitor_init(struct dnet_node *n, struct dnet_config *cfg)
{
	int err, fd;

	return 0;

	err = mkfifo(cfg->monitor_path, 0644);
	if (err < 0) {
		err = -errno;
		if (err != -EEXIST) {
			dnet_log_err(n, "failed to create monitor pipe '%s'", cfg->monitor_path);
			goto err_out_exit;
		}
	}

	fd = open(cfg->monitor_path, O_RDWR);
	if (fd < 0) {
		err = -errno;
		dnet_log_err(n, "failed to open monitor pipe '%s'", cfg->monitor_path);
		goto err_out_exit;
	}
	fcntl(fd, F_SETFL, O_NONBLOCK);

	n->monitor_fd = fd;

	err = pthread_create(&n->monitor_tid, NULL, dnet_monitor_process, n);
	if (err) {
		dnet_log(n, DNET_LOG_ERROR, "Failed to start monitor thread: %s [%d]\n",
				strerror(err), err);
		goto err_out_close;
	}

	return 0;

err_out_close:
	close(fd);
	n->monitor_fd = -1;
err_out_exit:
	return err;
}
