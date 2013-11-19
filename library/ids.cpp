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

int dnet_ids_update(int update_local, const char *file, struct dnet_addr *cfg_addrs, char *remotes)
{
	char remote_id[1024];
	sprintf(remote_id, "elliptics_node_ids_%s", dnet_server_convert_dnet_addr(cfg_addrs));

	ioremap::elliptics::file_logger log("/dev/null", 0);
	ioremap::elliptics::node node(log);
	ioremap::elliptics::session session(node);

	session.set_exceptions_policy(ioremap::elliptics::session::no_exceptions);

	std::stringstream remotes_stream;
	remotes_stream << remotes;
	std::string addr;
	while (std::getline(remotes_stream, addr, ' ')) {
		try {
			node.add_remote(addr.c_str());
		} catch(...) {}
	}

	auto routes = session.get_routes();
	std::set<int> groups_set;

	for(auto it = routes.begin(), end = routes.end(); it != end; ++it) {
		groups_set.insert(it->first.group_id);
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
