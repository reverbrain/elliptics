/*
	Example code for showing how to iterate specified nodes or all nodes in specified groups
*/

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

#include <vector>
#include <string>
#include <set>
#include <iostream>

#include <boost/program_options.hpp>

#include <elliptics/cppdef.h>

struct Ctx {
	Ctx()
	: iflags(0)
	{}

	std::vector<int> groups;
	uint64_t iflags;
	dnet_iterator_range key_range;
	dnet_time time_begin, time_end;
	std::unique_ptr<ioremap::elliptics::session> session;
	std::vector<std::pair<struct dnet_id, struct dnet_addr>> routes;
};

void iterate_node(Ctx &ctx, const dnet_addr &node) {
	std::cout << "Iterating node: " << dnet_server_convert_dnet_addr(const_cast<dnet_addr*>(&node)) << ":" << node.family << std::endl;
	std::vector<dnet_iterator_range> ranges;
	if (ctx.iflags & DNET_IFLAGS_KEY_RANGE)
		ranges.push_back(ctx.key_range);

	dnet_id id;
	bool found = false;
	for (auto it = ctx.routes.begin(), end = ctx.routes.end(); it != end; ++it) {
		if (dnet_addr_equal(&it->second, const_cast<dnet_addr*>(&node))) {
			id = it->first;
			found = true;
			break;
		}
	}

	if (!found) {
		std::cerr << "Node was not found in the route list" << std::endl;
		return;
	}

	ctx.session->set_groups(std::vector<int>(1, id.group_id));

	auto res = ctx.session->start_iterator(ioremap::elliptics::key(id),
	                                       ranges, DNET_ITYPE_NETWORK,
	                                       ctx.iflags, ctx.time_begin, ctx.time_end);

	char buffer[2*DNET_ID_SIZE + 1] = {0};
	for (auto it = res.begin(), end = res.end(); it != end; ++it) {
		std::cout << "node: "    << dnet_server_convert_dnet_addr(const_cast<dnet_addr*>(&node)) << node.family
		          << ", key: "   << dnet_dump_id_len_raw(it->reply()->key.id, DNET_ID_SIZE, buffer)
		          << ", flags: " << it->reply()->user_flags
		          << ", ts: "    << it->reply()->timestamp.tsec << "/" << it->reply()->timestamp.tnsec
		          << " size: "   << it->reply_data().size()
		          << " data: "   << it->reply_data().to_string()
		          << std::endl;
	}
}

struct less {
	bool operator() (const dnet_addr &lhs, const dnet_addr &rhs) {
		if (lhs.family < rhs.family)
			return true;
		else if (lhs.family > rhs.family)
			return false;
		else if (lhs.addr_len < rhs.addr_len)
			return true;
		else if (lhs.addr_len > rhs.addr_len)
			return false;
		else
			return memcmp(&lhs.addr, &rhs.addr, lhs.addr_len) < 0;
	}
};

void iterate_groups(Ctx &ctx) {
	std::cout << "Iterating groups:" << std::endl;
	std::set<int> groups_set(ctx.groups.begin(), ctx.groups.end());
	std::set<dnet_addr, less> addr_set;

	for (auto it = ctx.routes.begin(), end = ctx.routes.end(); it != end; ++it) {
		if (groups_set.find(it->first.group_id) != groups_set.end()) {
			addr_set.insert(it->second);
		}
	}

	for (auto it = addr_set.begin(), end = addr_set.end(); it != end; ++it) {
		iterate_node(ctx, *it);
	}
}

dnet_raw_id parse_hex_id(const std::string &hex_id) {
	dnet_raw_id id;
	memset(&id, 0, sizeof(id));

	if (strcmp(hex_id.c_str(), "-1") == 0) {
		memset(&id.id, -1, sizeof(id.id));
	} else {
		int i = 0;
		for (auto it = hex_id.rbegin(), end = hex_id.rend(); it != end; ++it, ++i) {
			const char c = *it;
			const uint8_t v = (uint8_t)(strtoul(&c, NULL, 16));
			id.id[DNET_ID_SIZE - 1 - (i / 2)] |= v << (4 * (i % 2));
		}
	}

	return id;
}

dnet_time parse_time(const std::string &str_time) {
	dnet_time time;
	time.tnsec = 0;
	time.tsec = strtoul(str_time.c_str(), NULL, 10);
	return time;
}


dnet_addr parse_addr(const std::string& addr) {
	dnet_addr ret;
	int port, family;
	memset(&ret, 0, sizeof(ret));
	ret.addr_len = sizeof(ret.addr);
	std::string str_addr(addr);
	int err = dnet_parse_addr(const_cast<char *>(str_addr.c_str()), &port, &family);
	if (err) {
		std::cerr << "Wrong remote addr: " << addr << "\n" << std::endl;
		exit(1);
	}
	ret.family = family;
	dnet_fill_addr(&ret, const_cast<char *>(str_addr.c_str()), port, SOCK_STREAM, IPPROTO_TCP);
	return ret;
}

int main(int argc, char *argv[]) {
	Ctx ctx;
	std::string log_file;
	int log_level;
	std::vector<std::string> remotes;
	boost::program_options::options_description desc("Usage");
	bool iter_groups = false;
	bool iter_node = false;

	desc.add_options()
	("group,g", boost::program_options::value<std::vector<int>>()->multitoken(), "group IDs to connect")
	("log-file,l", boost::program_options::value<std::string>()->default_value("/dev/stderr"), "log file")
	("log-level,L", boost::program_options::value<int>()->default_value(1), "log level")
	("remote,r", boost::program_options::value<std::vector<std::string>>()->multitoken(), "adds a route to the given node")
	("data,d", "requests object's data with other info")
	("key-begin,k", boost::program_options::value<std::string>(), "Begin key of range for iterating")
	("key-end,K", boost::program_options::value<std::string>(), "End key of range for iterating")
	("time-begin,t", boost::program_options::value<std::string>(), "Begin timestamp of time range for iterating")
	("time-end,T", boost::program_options::value<std::string>(), "End timestamp of time range for iterating")
	("nodes,n", "Iterate nodes")
	("groups,G", "Iterate nodes in groups")
	("help,h", "this help");

	boost::program_options::variables_map vm;

	try {
		boost::program_options::store(boost::program_options::parse_command_line(argc, argv, desc), vm);
		if (vm.count("help"))
		{
			std::cout << desc << std::endl;
			return 0;
		}
		if (vm.count("group"))
			ctx.groups = vm["group"].as<std::vector<int>>();
		log_file = vm["log-file"].as<std::string>();
		log_level = vm["log-level"].as<int>();
		if (vm.count("remote"))
			remotes = vm["remote"].as<std::vector<std::string>>();
		if (vm.count("data"))
			ctx.iflags |= DNET_IFLAGS_DATA;
		if (vm.count("key-begin")) {
			ctx.key_range.key_begin = parse_hex_id(vm["key-begin"].as<std::string>());
			ctx.iflags |= DNET_IFLAGS_KEY_RANGE;
		}
		if (vm.count("key-end")) {
			ctx.key_range.key_end = parse_hex_id(vm["key-end"].as<std::string>());
			ctx.iflags |= DNET_IFLAGS_KEY_RANGE;
		}
		if (vm.count("time-begin")) {
			ctx.time_begin = parse_time(vm["time-begin"].as<std::string>());
			ctx.iflags |= DNET_IFLAGS_TS_RANGE;
		}
		if (vm.count("time-end")) {
			ctx.time_end = parse_time(vm["time-end"].as<std::string>());
			ctx.iflags |= DNET_IFLAGS_TS_RANGE;
		}
		if (vm.count("groups"))
			iter_groups = true;
		if (vm.count("nodes"))
			iter_node = true;

		boost::program_options::notify(vm);
	} catch(boost::program_options::error& e) {
		std::cerr << "ERROR: " << e.what() << "\n" << desc << std::endl;
		exit(1);
	}

	ioremap::elliptics::file_logger logger(log_file.c_str(), log_level);
	ioremap::elliptics::node node(logger);
	for (auto it = remotes.begin(), end = remotes.end(); it != end; ++it) {
		try {
			node.add_remote(it->c_str());
		} catch(...) {}
	}
	ctx.session.reset(new ioremap::elliptics::session(node));

	ctx.routes = ctx.session->get_routes();

	if (iter_groups)
		iterate_groups(ctx);
	else if (iter_node) {
		for (auto it = remotes.begin(), end = remotes.end(); it != end; ++it) {
			iterate_node(ctx, parse_addr(*it));
		}
	} else {
		std::cerr << "You should specify one of iteration mode: --nodes or --groups\n" << desc << std::endl;
		exit(1);
	}

	return 0;
}
