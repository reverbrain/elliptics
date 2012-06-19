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

#define _XOPEN_SOURCE 600

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <sys/wait.h>

#include <sstream>
#include <stdexcept>

#include "elliptics/cppdef.h"

using namespace ioremap::elliptics;

callback::callback() : complete(0)
{
	pthread_cond_init(&wait_cond, NULL);
	pthread_mutex_init(&lock, NULL);
}

callback::~callback()
{
}

int callback::handle(struct dnet_net_state *state, struct dnet_cmd *cmd)
{
	pthread_mutex_lock(&lock);
	if (is_trans_destroyed(state, cmd)) {
		complete++;
		pthread_cond_broadcast(&wait_cond);
	} else if (cmd && state) {
		data.append((const char *)dnet_state_addr(state), sizeof(struct dnet_addr));
		data.append((const char *)cmd, sizeof(struct dnet_cmd) + cmd->size);
	}
	pthread_mutex_unlock(&lock);

	return 0;
}

std::string callback::wait(int completed)
{
	pthread_mutex_lock(&lock);
	while (complete != completed)
		pthread_cond_wait(&wait_cond, &lock);
	pthread_mutex_unlock(&lock);

	return data;
}
