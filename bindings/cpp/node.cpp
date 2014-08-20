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

node::node(logger &&l) : m_data(new node_data(std::move(l)))
{
	struct dnet_config cfg;

	memset(&cfg, 0, sizeof(cfg));

	cfg.wait_timeout = 5;
	cfg.check_timeout = 20;
	cfg.log = &m_data->log;

	m_data->node_ptr = dnet_node_create(&cfg);
	if (!m_data->node_ptr) {
		throw std::bad_alloc();
	}
}

node::node(logger &&l, dnet_config &cfg) : m_data(new node_data(std::move(l)))
{
	cfg.log = &m_data->log;

	m_data->node_ptr = dnet_node_create(&cfg);
	if (!m_data->node_ptr) {
		throw std::bad_alloc();
	}
}

node::node(const node &other) : m_data(other.m_data)
{}

node::~node()
{}

node node::from_raw(dnet_node *n)
{
	return node::from_raw(n, blackhole::log::attributes_t());
}

node node::from_raw(dnet_node *n, blackhole::log::attributes_t attributes)
{
	node result;
	logger log(*dnet_node_get_logger(n), std::move(attributes));

	result.m_data = std::make_shared<node_data>(std::move(log));
	result.m_data->destroy_node = false;
	result.m_data->node_ptr = n;

	return result;
}

node &node::operator =(const node &other)
{
	m_data = other.m_data;
	return *this;
}

bool node::is_valid() const
{
	return !!m_data;
}

void node::add_remote(const address &addr)
{
	if (!m_data)
		throw_error(-EINVAL, "Failed to add remote addr to null node");

	int err = dnet_add_state(m_data->node_ptr, &addr.to_raw(), 1, 0);
	if (err < 0) {
		throw_error(err, "Failed to add remote addr %s", addr.to_string().c_str());
	}
}

void node::add_remote(const std::vector<address> &addrs)
{
	if (!m_data)
		throw_error(-EINVAL, "Failed to add remote addr to null node");

	static_assert(sizeof(address) == sizeof(dnet_addr), "size of address is not equal to size of dnet_addr");

	// It's safe to cast address to dnet_addr as their size are equal
	int err = dnet_add_state(m_data->node_ptr, reinterpret_cast<const dnet_addr *>(addrs.data()), addrs.size(), 0);
	if (err < 0) {
		throw_error(err, "Failed to add remote %zd addrs", addrs.size());
	}
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

logger &node::get_log() const
{
	return m_data->log;
}

dnet_node *node::get_native() const
{
	return m_data ? m_data->node_ptr : NULL;
}

} } // namespace ioremap::elliptics
