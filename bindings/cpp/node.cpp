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

#include <boost/algorithm/string.hpp>
#include <elliptics/cppdef.h>
#include <fstream>

namespace ioremap { namespace elliptics {

class node_data {
	public:
		node_data() : node_ptr(NULL) {}
		~node_data() {
			dnet_node_destroy(node_ptr);
		}

		struct dnet_node	*node_ptr;
		logger				log;
};

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
	int err;

	err = dnet_add_state(m_data->node_ptr, (char *)addr, port, family, 0);
	if (err) {
		throw_error(err, "Failed to add remote addr %s:%d", addr, port);
	}
}

void node::add_remote(const char *orig_addr)
{
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
	dnet_set_timeouts(m_data->node_ptr, wait_timeout, check_timeout);
}

logger node::get_log() const
{
	return m_data->log;
}

dnet_node *node::get_native()
{
	return m_data->node_ptr;
}

} } // namespace ioremap::elliptics
