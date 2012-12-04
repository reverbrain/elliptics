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

#include "elliptics/cppdef.h"

#include <sstream>
#include <stdexcept>

#include <boost/thread.hpp>

namespace ioremap { namespace elliptics {

class callback_data
{
	public:
		std::string		data;
		boost::mutex lock;
		boost::condition_variable wait_cond;
		int			complete;
};

callback::callback() : m_data(new callback_data)
{
	m_data->complete = 0;
}

callback::~callback()
{
	delete m_data;
}

int callback::handle(struct dnet_net_state *state, struct dnet_cmd *cmd)
{
	bool notify = false;
	{
		boost::mutex::scoped_lock locker(m_data->lock);

		if (is_trans_destroyed(state, cmd)) {
			m_data->complete++;
			notify = true;
		} else if (cmd && state) {
			m_data->data.append((const char *)dnet_state_addr(state), sizeof(struct dnet_addr));
			m_data->data.append((const char *)cmd, sizeof(struct dnet_cmd) + cmd->size);
		}
	}
	if (notify)
		m_data->wait_cond.notify_all();

	return 0;
}

int callback::complete_callback(struct dnet_net_state *st, struct dnet_cmd *cmd, void *priv)
{
	callback *c = reinterpret_cast<callback *>(priv);

	return c->handle(st, cmd);
}

std::string callback::wait(int completed)
{
	boost::mutex::scoped_lock locker(m_data->lock);

	while (m_data->complete != completed)
		m_data->wait_cond.wait(locker);

	return m_data->data;
}

} } // namespace ioremap::elliptics
