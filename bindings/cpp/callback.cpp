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

class ioremap::elliptics::callback_data
{
	public:
		std::string		data;
		pthread_cond_t		wait_cond;
		pthread_mutex_t		lock;
		int			complete;
};

callback::callback() : m_data(new callback_data)
{
	m_data->complete = 0;
	pthread_cond_init(&m_data->wait_cond, NULL);
	pthread_mutex_init(&m_data->lock, NULL);
}

callback::~callback()
{
	pthread_cond_destroy(&m_data->wait_cond);
	pthread_mutex_init(&m_data->lock, NULL);
	delete m_data;
}

int callback::handle(struct dnet_net_state *state, struct dnet_cmd *cmd)
{
	pthread_mutex_lock(&m_data->lock);
	if (is_trans_destroyed(state, cmd)) {
		m_data->complete++;
		pthread_cond_broadcast(&m_data->wait_cond);
	} else if (cmd && state) {
		m_data->data.append((const char *)dnet_state_addr(state), sizeof(struct dnet_addr));
		m_data->data.append((const char *)cmd, sizeof(struct dnet_cmd) + cmd->size);
	}
	pthread_mutex_unlock(&m_data->lock);

	return 0;
}

int callback::complete_callback(struct dnet_net_state *st, struct dnet_cmd *cmd, void *priv) {
	callback *c = reinterpret_cast<callback *>(priv);

	return c->handle(st, cmd);
}

std::string callback::wait(int completed)
{
	pthread_mutex_lock(&m_data->lock);
	while (m_data->complete != completed)
		pthread_cond_wait(&m_data->wait_cond, &m_data->lock);
	pthread_mutex_unlock(&m_data->lock);

	return m_data->data;
}
