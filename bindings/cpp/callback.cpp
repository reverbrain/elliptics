/*
 * 2008+ Copyright (c) Evgeniy Polyakov <zbr@ioremap.net>
 * 2012+ Copyright (c) Ruslan Nigmatullin <euroelessar@yandex.ru>
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
		boost::mutex		lock;
		boost::condition_variable wait_cond;
		int			complete;
		std::vector<int>	statuses;
};

callback::callback() : m_data(new callback_data)
{
	m_data->complete = 0;
}

callback::~callback()
{
	delete m_data;
}

void callback::handle(struct dnet_net_state *state, struct dnet_cmd *cmd)
{
	m_data->data.append((const char *)dnet_state_addr(state), sizeof(struct dnet_addr));
	m_data->data.append((const char *)cmd, sizeof(struct dnet_cmd) + cmd->size);
}

int callback::handler(struct dnet_net_state *state, struct dnet_cmd *cmd, void *priv)
{
	callback *that = reinterpret_cast<callback *>(priv);

	bool notify = false;
	{
		boost::mutex::scoped_lock locker(that->m_data->lock);

		if (cmd)
			that->m_data->statuses.push_back(cmd->status);

		if (is_trans_destroyed(state, cmd)) {
			that->m_data->complete++;
			notify = true;
		} else if (cmd && state) {
			that->handle(state, cmd);
		}
	}
	if (notify)
		that->m_data->wait_cond.notify_all();

	return 0;
}

std::string callback::wait(int completed)
{
	boost::mutex::scoped_lock locker(m_data->lock);

	while (m_data->complete != completed)
		m_data->wait_cond.wait(locker);

	if (!check_states(m_data->statuses))
		throw_error(-EIO, "failed to request");

	return m_data->data;
}

void *callback::data() const
{
	return const_cast<callback *>(this);
}

callback_any::callback_any()
{
}

callback_any::~callback_any()
{
}

bool callback_any::check_states(const std::vector<int> &statuses)
{
	bool ok = false;
	for (size_t i = 0; i < statuses.size(); ++i)
		ok |= (statuses[i] != 0);
	return ok;
}

callback_all::callback_all()
{
}

callback_all::~callback_all()
{
}

bool callback_all::check_states(const std::vector<int> &statuses)
{
	bool ok = !statuses.empty();
	for (size_t i = 0; i < statuses.size(); ++i)
		ok &= (statuses[i] != 0);
	return ok;
}

} } // namespace ioremap::elliptics
