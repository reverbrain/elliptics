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

#include <algorithm>
#include <iostream>
#include <stdexcept>
#include <string>
#include <sstream>
#include <vector>

#include <boost/algorithm/string.hpp>
#include <elliptics/cppdef.h>

namespace ioremap { namespace elliptics {

class node_data {
	public:
		node_data() : node_ptr(NULL) {}
		~node_data() {
			dnet_node_destroy(node_ptr);
		}

		struct dnet_node	*node_ptr;
		logger              log;
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

node::node(const logger &l, const std::string &config_path) : m_data(new node_data)
{
	m_data->log = l;

	struct dnet_config cfg;
	memset(&cfg, 0, sizeof(struct dnet_config));

	cfg.log = m_data->log.get_native();

	std::list<address> remotes;
	std::vector<int> groups;

	parse_config(config_path, cfg, remotes, groups, cfg.log->log_level);

	m_data->node_ptr = dnet_node_create(&cfg);
	if (!m_data->node_ptr) {
		throw std::bad_alloc();
	}

	for (std::list<address>::iterator it = remotes.begin(); it != remotes.end(); ++it) {
		try {
			add_remote(it->host.c_str(), it->port, it->family);
		} catch (...) {
			continue;
		}
	}
}

node::node(const node &other) : m_data(other.m_data)
{
}

node::~node()
{
}

node &node::operator =(const node &other)
{
	m_data = other.m_data;
	return *this;
}

void node::parse_config(const std::string &path, struct dnet_config &cfg,
			std::list<address> &remotes,
			std::vector<int> &groups,
			int &log_level)
{
	std::ifstream in(path.c_str());
	std::string line;
	int line_num = 0;

	while (std::getline(in, line)) {
		boost::trim(line);
		line_num++;

		if (line.size() < 3 || line.data()[0] == '#')
			continue;

		std::vector<std::string> strs;
		boost::split(strs, line, boost::is_any_of("="));

		std::string key = strs[0];
		boost::trim(key);

		if (strs.size() != 2) {
			throw_error(-EIO, "%s: invalid elliptics config: line: %d,"
				" key: '%s': string is broken: size: %zu",
				path.c_str(), line_num, key.c_str(), strs.size());
		}
		std::string value = strs[1];
		boost::trim(value);

		if (key == "remote") {
			std::vector<std::string> rem;
			boost::split(rem, value, boost::is_any_of(" "));

			for (std::vector<std::string>::iterator it = rem.begin(); it != rem.end(); ++it) {
				int remote_port, remote_family;

				std::string addr_str = *it;

				/* XXX: modifies addr_str's content in place */
				if (dnet_parse_addr((char *)addr_str.c_str(), &remote_port, &remote_family)) {
					throw_error(-EIO, "%s: invalid elliptics config: '%s' "
						"%s: invalid elliptics config: line: %d, "
						"key: '%s': remote addr is invalid",
						path.c_str(), key.c_str(), path.c_str(),
						line_num, key.c_str());
				}

				address addr((char *)addr_str.c_str(), remote_port, remote_family);
				remotes.push_back(addr);
			}
		}

		if (key == "groups") {
			std::vector<std::string> gr;
			boost::split(gr, value, boost::is_any_of(":"));

			for (std::vector<std::string>::iterator it = gr.begin(); it != gr.end(); ++it) {
				int group = atoi(it->c_str());

				if (group != 0)
					groups.push_back(group);
			}
		}

		if (key == "check_timeout")
			cfg.check_timeout = strtoul(value.c_str(), NULL, 0);
		if (key == "wait_timeout")
			cfg.wait_timeout = strtoul(value.c_str(), NULL, 0);
		if (key == "log_level")
			log_level = strtoul(value.c_str(), NULL, 0);
	}
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
		throw_error(err, "Failed to parse remote addr %s", addr.c_str());

	err = dnet_add_state(m_data->node_ptr, const_cast<char *>(addr.c_str()), port, family, 0);
	if (err)
		throw_error(err, "Failed to add remote addr %s", addr.c_str());
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
