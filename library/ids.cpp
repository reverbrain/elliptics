/*
 * 2013+ Copyright (c) Kirill Smorodinnikov <shaitkir@gmail.com>
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

#include <fcntl.h>

#include <vector>
#include <set>
#include <sstream>

#include "elliptics.h"
#include "elliptics/interface.h"

#include "../include/elliptics/session.hpp"

int dnet_ids_update(struct dnet_node *n, int update_local, const char *file, struct dnet_addr *cfg_addrs, size_t backend_id)
{
	char remote_id[1024];
	sprintf(remote_id, "elliptics_node_ids_%s_%zu", dnet_server_convert_dnet_addr(cfg_addrs), backend_id);

	blackhole::log::attributes_t attributes;
//	attributes.insert(std::make_)

	ioremap::elliptics::node node = ioremap::elliptics::node::from_raw(n, std::move(attributes));
//	blackhole::log::attributes_t {
//		{ "remote_id", remote_id },
//		{ "backend_id", backend_id },
//		{ "file", file },
//		{ "source", "ids_update" }
//	};
	ioremap::elliptics::session session(node);

	session.set_exceptions_policy(ioremap::elliptics::session::no_exceptions);

	auto routes = session.get_routes();
	std::set<int> groups_set;

	for(auto it = routes.begin(), end = routes.end(); it != end; ++it) {
		groups_set.insert(it->group_id);
	}

	session.set_groups(std::vector<int>(groups_set.begin(), groups_set.end()));

	try {
		if (update_local)
			session.read_file(std::string(remote_id), file, 0, 0);
		else
			session.write_file(std::string(remote_id), file, 0, 0, 0);
	} catch(...) {
		return -1;
	}

	return 0;
}
