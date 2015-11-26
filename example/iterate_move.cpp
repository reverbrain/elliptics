/*
 * 2015+ Copyright (c) Evgeniy Polyakov <zbr@ioremap.net>
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
 *
 * This application runs over all backends in given group (or just single specified backend)
 * and copies/moves data to specified remote groups.
 */

#include "common.h"

#include <vector>
#include <string>
#include <set>
#include <iostream>

#include <boost/program_options.hpp>

#include <elliptics/cppdef.h>
#include <elliptics/timer.hpp>

using namespace ioremap;
namespace bpo = boost::program_options;

static dnet_raw_id parse_hex_id(const std::string &hex_id) {
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

static std::vector<int> parse_groups(const std::string &gstr)
{
	std::string str = gstr;
	int *groups_tmp;
	int group_num = dnet_parse_groups((char *)str.c_str(), &groups_tmp);
	if (group_num <= 0)
		throw std::runtime_error("could not parse groups: " + gstr);

	std::vector<int> dst;
	dst.assign(groups_tmp, groups_tmp + group_num);

	free(groups_tmp);

	return dst;
}

static void run_on_single_backend(const bpo::variables_map &vm,
		elliptics::session &s, const dnet_id &id)
{
	// checking iterator flags
	uint64_t iflags = DNET_IFLAGS_NO_META;

	if (vm.count("overwrite")) {
		iflags |= DNET_IFLAGS_OVERWRITE;
	}

	// copy or move data to remote nodes?
	std::vector<int> dst_groups;
	if (vm.count("copy-to")) {
		dst_groups = parse_groups(vm["copy-to"].as<std::string>());
	}
	if (vm.count("move-to")) {
		dst_groups = parse_groups(vm["move-to"].as<std::string>());
		iflags |= DNET_IFLAGS_MOVE;
	}


	// checking key ranges
	std::vector<dnet_iterator_range> ranges;
	dnet_iterator_range r;

	memset(r.key_begin.id, 0, sizeof(dnet_raw_id));
	memset(r.key_end.id, 0xff, sizeof(dnet_raw_id));

	if (vm.count("key-begin")) {
		r.key_begin = parse_hex_id(vm["key-begin"].as<std::string>());
		iflags |= DNET_IFLAGS_KEY_RANGE;
	}
	if (vm.count("key-end")) {
		r.key_end = parse_hex_id(vm["key-begin"].as<std::string>());
		iflags |= DNET_IFLAGS_KEY_RANGE;
	}
	ranges.push_back(r);


	// checking key timestamps
	dnet_time time_begin, time_end;
	dnet_empty_time(&time_begin);
	dnet_current_time(&time_end);

	if (vm.count("time-begin")) {
		time_begin.tsec = vm["time-begin"].as<long>();
		iflags &= ~DNET_IFLAGS_NO_META;
	}
	if (vm.count("time-end")) {
		time_end.tsec = vm["time-end"].as<long>();
		iflags &= ~DNET_IFLAGS_NO_META;
	}

	//elliptics::logger &log = s.get_logger();

	long long copied = 0;
	long long copied_size = 0;

	elliptics::timer tm;
	long prev = tm.elapsed();
	long prev_size = 0;

	auto iter = s.start_copy_iterator(id, ranges, iflags, time_begin, time_end, dst_groups);
	for (auto it = iter.begin(), end = iter.end(); it != end; ++it) {
#if 0
		// we have to explicitly convert all members from dnet_iterator_response
		// since it is packed and there will be alignment issues and
		// following error:
		// error: cannot bind packed field ... to int&
		BH_LOG(log, DNET_LOG_DEBUG,
				"key: %s, backend: %d, user_flags: %llx, ts: %lld.%09lld, status: %d, size: %lld, "
				"iterated_keys: %lld/%lld",
			dnet_dump_id_len_raw(it->reply()->key.id, DNET_ID_SIZE, buffer),
			(int)it->command()->backend_id,
			(unsigned long long)it->reply()->user_flags,
			(unsigned long long)it->reply()->timestamp.tsec, (unsigned long long)it->reply()->timestamp.tnsec,
			(int)it->reply()->status, (unsigned long long)it->reply()->size,
			(unsigned long long)it->reply()->iterated_keys, (unsigned long long)it->reply()->total_keys);
#endif

		copied_size += it->reply()->size;
		copied++;

		if (tm.elapsed() > prev + 1000) {
			float diff = tm.elapsed() - prev;
			float diff_size = copied_size - prev_size;
			float momentum_speed = diff_size / diff;
			float long_speed = (float)copied_size / (float)tm.elapsed();

			prev += diff;
			prev_size = copied_size;

			printf("\r copied: %lld/%lld, speed: %.1f MB/s, momentum speed: %.1f MB/s",
				(unsigned long long)it->reply()->iterated_keys,
				(unsigned long long)it->reply()->total_keys,
				long_speed * 1000.0 / (1024.0 * 1024.0),
				momentum_speed * 1000.0 / (1024.0 * 1024.0));
			fflush(stdout);
		}
	}
}

int main(int argc, char *argv[])
{
	bpo::options_description generic("Generic options");
	generic.add_options()
		("help", "this help message")
		;

	std::vector<std::string> remotes;
	std::string log_file, log_level;
	int igroup;
	std::vector<uint32_t> backends;
	long wait_timeout;
	bpo::options_description ell("Elliptics options");
	ell.add_options()
		("remote,r", bpo::value<std::vector<std::string>>(&remotes)->required()->composing(),
		 	"remote nodes to connect, can be specified multiple times, format: addr:port:family")
		("group,g", bpo::value<int>(&igroup)->required(), "single remote group to iterate over")
		("log-file", bpo::value<std::string>(&log_file)->default_value("/dev/stdout"), "log file")
		("log-level", bpo::value<std::string>(&log_level)->default_value("error"), "log level: error, info, notice, debug")
		("wait-timeout,w", bpo::value<long>(&wait_timeout)->default_value(120), "wait timeout in seconds")
		("backend,b", bpo::value<std::vector<uint32_t>>(&backends)->composing(),
		 	"remote backends in specified group, if not specified, iteration will run over all backends, "
			"can be specified multiple times")
		;

	bpo::options_description iterops("Remote copy/move data iterator options");
	iterops.add_options()
		("copy-to", bpo::value<std::string>(), "remote groups to copy data to, format: 4:5:6")
		("move-to", bpo::value<std::string>(), "remote groups to move data to "
		 	"(will be preferred over 'copy-to'), format: 4:5:6")
		("overwrite", "when set, copy process will overwrite remote data, "
			"even if it differs. If not set, compare-and-swap write will be used, i.e. iterator will "
			"only write data if it doesn't exist or its the same")
		("key-begin", bpo::value<std::string>(), "start of the key range to copy")
		("key-end", bpo::value<std::string>(), "end of the key range to copy")
		("time-begin", bpo::value<long>(), "minimum timestamp of the record to copy")
		("time-end", bpo::value<long>(), "maximum timestamp of the record to copy")
		("help,h", "this help")
		;

	bpo::options_description cmdline_options;
	cmdline_options.add(generic).add(ell).add(iterops);

	bpo::variables_map vm;

	try {
		bpo::store(bpo::command_line_parser(argc, argv).options(cmdline_options).run(), vm);

		if (vm.count("help")) {
			std::cout << cmdline_options << std::endl;
			return 0;
		}

		bpo::notify(vm);
	} catch (const std::exception &e) {
		std::cerr << "Invalid options: " << e.what() << "\n" << cmdline_options << std::endl;
		return -1;
	}

	if (!vm.count("copy-to") && !vm.count("move-to")) {
		std::cerr << "You have to specify groups to copy or move data to\n" << cmdline_options << std::endl;
		return -1;
	}

	try {
		elliptics::file_logger logger(log_file.c_str(), elliptics::file_logger::parse_level(log_level));
		elliptics::node node(ioremap::elliptics::logger(logger, blackhole::log::attributes_t()));
		for (auto r = remotes.begin(), rend = remotes.end(); r != rend; ++r) {
			try {
				node.add_remote(*r);
			} catch (const std::exception &e) {
				std::cerr << "Could not connect to " << *r << ": " << e.what() << std::endl;
			}
		}


		elliptics::session s(node);
		s.set_timeout(wait_timeout);
		s.set_groups({igroup});
		std::vector<dnet_route_entry> routes = s.get_routes();
		if (routes.empty()) {
			std::cerr << "Is not connected to any remote node, exiting" << std::endl;
			return -1;
		}

		std::vector<dnet_id> ids;

		std::set<uint32_t> bs; // set of backends we've already checked in our group

		// iterate over all backends in specified group
		for (auto it = routes.begin(); it != routes.end(); ++it) {
			const dnet_route_entry &entry = *it;

			// only check routes which correspond to our required group to iterate over
			if (entry.group_id == igroup) {
				auto back = bs.find(entry.backend_id);
				if (back == bs.end()) {
					bs.insert(entry.backend_id);

					if (!backends.empty()) {
						auto f = std::find(backends.begin(), backends.end(), entry.backend_id);

						// this backend isn't present in the list of backends
						// we are allowed to iterate over
						if (f == backends.end())
							continue;
					}

					struct dnet_id id;
					dnet_setup_id(&id, igroup, entry.id.id);
					ids.push_back(id);
				}
			}
		}

		for (const auto &id : ids) {
			run_on_single_backend(vm, s, id);
		}
	} catch (const std::exception &e) {
		std::cerr << "Caught exception: " << e.what() << std::endl;
		return -1;
	}
}
