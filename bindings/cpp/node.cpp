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

void node::add_remote(const char *addr, const int port, const int family)
{
	if (!m_data)
		throw_error(-EINVAL, "Failed to add remote addr to null node");

	int err;

	err = dnet_add_state(m_data->node_ptr, (char *)addr, port, family, 0);
	if (err) {
		throw_error(err, "Failed to add remote addr %s:%d", addr, port);
	}
}

void node::add_remote(const char *orig_addr)
{
	if (!m_data)
		throw_error(-EINVAL, "Failed to add remote addr to null node");

	int port, family;

	/*
	 * addr will be modified, so use this ugly hack
	 */
	std::string addr(orig_addr);

	int err = dnet_parse_addr(const_cast<char *>(addr.c_str()), &port, &family);
	if (err)
		throw_error(err, "Failed to parse remote addr %s", orig_addr);

	err = dnet_add_state(m_data->node_ptr, const_cast<char *>(addr.c_str()), port, family, 0);
	if (err)
		throw_error(err, "Failed to add remote addr %s", orig_addr);
}

void node::set_timeouts(const int wait_timeout, const int check_timeout)
{
	if (m_data)
		dnet_set_timeouts(m_data->node_ptr, wait_timeout, check_timeout);
}

bool node::is_valid() const
{
	return !!m_data;
}

logger node::get_log() const
{
	return m_data ? m_data->log : logger();
}

dnet_node *node::get_native()
{
	return m_data ? m_data->node_ptr : NULL;
}

dnet_node *node::get_native() const
{
	return m_data ? m_data->node_ptr : NULL;
}

} } // namespace ioremap::elliptics
