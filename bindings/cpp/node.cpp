/*
 * 2008+ Copyright (c) Evgeniy Polyakov <zbr@ioremap.net>
 * 2012+ Copyright (c) Ruslan Nigmatullin <euroelessar@yandex.ru>
 * All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 */

#include <algorithm>
#include <iostream>
#include <stdexcept>
#include <string>
#include <sstream>
#include <vector>

#include "node_p.hpp"

namespace ioremap { namespace elliptics {

node::node()
{
}

node::node(const std::shared_ptr<node_data> &data) : m_data(data)
{
}

node::node(const logger &l) : m_data(new node_data)
{
	m_data->log = l;

	struct dnet_config cfg;

	memset(&cfg, 0, sizeof(cfg));

	cfg.wait_timeout = 5;
	cfg.check_timeout = 20;
	cfg.log = m_data->log.get_native();

	m_data->node_ptr = dnet_node_create(&cfg);
	if (!m_data->node_ptr) {
		throw std::bad_alloc();
	}
}

node::node(const logger &l, struct dnet_config &cfg) : m_data(new node_data)
{
	m_data->log = l;

	cfg.log = m_data->log.get_native();

	m_data->node_ptr = dnet_node_create(&cfg);
	if (!m_data->node_ptr) {
		throw std::bad_alloc();
	}
}

node::node(const node &other) : m_data(other.m_data)
{}

node::~node()
{}

node &node::operator =(const node &other)
{
	m_data = other.m_data;
	return *this;
}

void node::add_remote(const std::string &addr, const int port, const int family)
{
	add_remote(addr.c_str(), port, family);
}

void node::add_remote(const char *addr, const int port, const int family)
{
	if (!m_data)
		throw_error(-EINVAL, "Failed to add remote addr to null node");

	int err;

	err = dnet_add_state(m_data->node_ptr, addr, port, family, 0);
	if (err) {
		throw_error(err, "Failed to add remote addr %s:%d", addr, port);
	}
}

void node::add_remote(const char *addr)
{
	add_remote(std::string(addr));
}

void node::add_remote(const std::string &addr)
{
	if (!m_data)
		throw_error(-EINVAL, "Failed to add remote addr to null node");

	int port, family;

	/*
	 * addr will be modified, so use this ugly hack
	 */
	std::vector<char> addr_tmp;
	addr_tmp.reserve(addr.size() + 1);
	addr_tmp.assign(addr.begin(), addr.end());
	addr_tmp.push_back('\0');

	int err = dnet_parse_addr(addr_tmp.data(), &port, &family);
	if (err)
		throw_error(err, "Failed to parse remote addr %s", addr.c_str());

	err = dnet_add_state(m_data->node_ptr, addr_tmp.data(), port, family, 0);
	if (err)
		throw_error(err, "Failed to add remote addr %s", addr.c_str());
}

void node::set_timeouts(const int wait_timeout, const int check_timeout)
{
	if (m_data)
		dnet_set_timeouts(m_data->node_ptr, wait_timeout, check_timeout);
}

void node::set_keepalive(int idle, int cnt, int interval)
{
	if (m_data)
		dnet_set_keepalive(m_data->node_ptr, idle, cnt, interval);
}

logger node::get_log() const
{
	return m_data ? m_data->log : logger();
}

dnet_node *node::get_native() const
{
	return m_data ? m_data->node_ptr : NULL;
}

} } // namespace ioremap::elliptics
