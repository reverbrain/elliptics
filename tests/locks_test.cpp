/*
 * 2015+ Copyright (c) Andrey Budnik <budnik27@gmail.com>
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

#include "test_base.hpp"
#include "../library/elliptics.h"
#include <algorithm>

#define BOOST_TEST_NO_MAIN
#include <boost/test/included/unit_test.hpp>

#include <boost/program_options.hpp>

using namespace ioremap::elliptics;
using namespace boost::unit_test;

namespace tests {

static std::shared_ptr<nodes_data> global_data;

static size_t groups_count = 1;
static size_t nodes_count = 1;
static size_t backends_count = 1;

static server_config default_value(int group)
{
	// Minimize number of threads
	server_config server = server_config::default_value();
	server.options
		("io_thread_num", 8)
		("nonblocking_io_thread_num", 1)
		("net_thread_num", 1)
		("caches_number", 1)
	;

	server.backends[0]("enable", true)("group", group);

	server.backends.resize(backends_count, server.backends.front());

	return server;
}

static void configure_nodes(const std::string &path)
{
	std::vector<server_config> servers;
	for (size_t i = 0; i < groups_count; ++i) {
		for (size_t j = 0; j < nodes_count; ++j) {
			const int group = i + 1;
			server_config server = default_value(group);
			servers.push_back(server);
		}
	}

	start_nodes_config start_config(results_reporter::get_stream(), std::move(servers), path);
	start_config.fork = true;

	global_data = start_nodes(start_config);
}

static void test_writes_consecution(session &sess)
{
	const int num_writes_of_particular_key = 5;
	const int num_keys = 10;
	std::vector<std::pair<key, int>> keys;
	for (int i = 0; i < num_keys; ++i) {
		key id(std::to_string(static_cast<unsigned long long>(i)));
		for (int j = 0; j < num_writes_of_particular_key; ++j) {
			keys.push_back(std::make_pair(id, i));
		}
	}

	std::vector<async_write_result> results(keys.size());
	dnet_id id;

	const int num_iterations = 30;
	for (int i = 0; i < num_iterations; ++i) {
		std::vector<int> write_counter(num_keys, 0);
		std::random_shuffle(keys.begin(), keys.end());

		for (size_t j = 0; j < keys.size(); ++j) {
			const int key_id = keys[j].second;
			const int cnt = write_counter[key_id]++;
			if (cnt > 0) {
				memset(&id, 0, sizeof(id));
				sess.transform(std::to_string(static_cast<unsigned long long>(cnt - 1)), id);
				results[j] = sess.write_cas(keys[j].first, std::to_string(static_cast<unsigned long long>(cnt)), id, 0);
			} else {
				results[j] = sess.write_data(keys[j].first, std::to_string(static_cast<unsigned long long>(cnt)), 0);
			}
		}

		for (size_t j = 0; j < keys.size(); ++j) {
			results[j].wait();
			const int err = results[j].error().code();
		        BOOST_REQUIRE_MESSAGE(err == 0,
					      "write_cas() failed (err=" + std::to_string(static_cast<unsigned long long>(err)) + "): "
					      "multiple consecutive writes are executed out-of-order"
					      " or overlapped. Oplock mechanism of backend's request queue is broken.");
		}
	}
}


bool register_tests(test_suite *suite, node n)
{
	ELLIPTICS_TEST_CASE(test_writes_consecution, create_session(n, { 1 }, 0, 0));

	return true;
}

static void destroy_global_data()
{
	global_data.reset();
}

boost::unit_test::test_suite *register_tests(int argc, char *argv[])
{
	namespace bpo = boost::program_options;

	bpo::variables_map vm;
	bpo::options_description generic("Test options");

	std::string path;

	generic.add_options()
			("help", "This help message")
			("path", bpo::value(&path), "Path where to store everything")
			;

	bpo::store(bpo::parse_command_line(argc, argv, generic), vm);
	bpo::notify(vm);

	if (vm.count("help")) {
		std::cerr << generic;
		return NULL;
	}

	test_suite *suite = new test_suite("Local Test Suite");

	configure_nodes(path);

	register_tests(suite, *global_data->node);

	return suite;
}

}

int main(int argc, char *argv[])
{
	atexit(tests::destroy_global_data);

	srand(time(0));
	return unit_test_main(tests::register_tests, argc, argv);
}
