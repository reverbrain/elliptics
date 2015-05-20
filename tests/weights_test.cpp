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

static size_t groups_count = 3;
static size_t nodes_count = 2;
static size_t backends_count = 1;
static size_t backend_delay = 500; // 0.5 sec
static int slow_group_id = 2;

static server_config default_value(int group)
{
	// Minimize number of threads
	server_config server = server_config::default_value();
	server.options
		("io_thread_num", 1)
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
	start_config.client_node_flags = DNET_CFG_MIX_STATES;

	global_data = start_nodes(start_config);
}

static void set_backends_delay_for_group(session &sess, int group, int delay)
{
	for (size_t i = 0; i < nodes_count; ++i) {
		for (size_t j = 0; j < backends_count; ++j) {
			const size_t node_id = (group - 1) * nodes_count + i;
			const server_node &node = global_data->nodes[node_id];
			sess.set_delay(node.remote(), j, delay);
		}
	}
}

// Writing of keys to all groups updates backend weights for every backend they
// were written. Writes to slow backend leads to significant reduction of this
// backend weigth comparing to faster ones.
// read_data() uses backend weights to choose fastest group via dnet_mix_states().
//
// Following test checks this mechanics by reading of previously written keys and
// checking read distribution among backends. Slow backend simulated by setting artificial delay.
// Expected outcome should be that reads would be rarely sent to that slow backend.
//
// We define "rarely" as no more than 1% of total reads. This value was empirically found.
static void test_backend_weights(session &sess)
{
	// set backends delay to simulate slow backends i/o behaviour for particular group
	set_backends_delay_for_group(sess, slow_group_id, backend_delay);

	const int num_keys = 10;
	for (int i = 0; i < num_keys; ++i) {
		const key id = std::string("key_") + std::to_string(static_cast<long long>(i));
		const std::string data = "some_data";
		ELLIPTICS_REQUIRE(async_write, sess.write_data(id, data, 0));
	}

	const int num_reads = 1000;
	int num_slow_group_reads = 0;
	for (int i = 0; i < num_reads; ++i) {
		const key id = std::string("key_") + std::to_string(static_cast<long long>(i % num_keys));
		auto async_result = sess.read_data(id, 0, 0);
		async_result.wait();

		read_result_entry read_result;
		async_result.get(read_result);

		const dnet_cmd *cmd = read_result.command();
		const int group_id = cmd->id.group_id;
		if ( group_id == slow_group_id )
			++num_slow_group_reads;
	}

	const int max_reads_from_slow_group = 10;
	BOOST_REQUIRE_MESSAGE(num_slow_group_reads < max_reads_from_slow_group,
			      "Too much reads from slow group (it means that backend weights are not working or backend hardware is extremely slow): "
			      "num_slow_group_reads: " + std::to_string(static_cast<long long>(num_slow_group_reads)) +
			      ", max_reads_from_slow_group: " + std::to_string(static_cast<long long>(max_reads_from_slow_group)));

	set_backends_delay_for_group(sess, slow_group_id, 0);
}


bool register_tests(test_suite *suite, node n)
{
	ELLIPTICS_TEST_CASE(test_backend_weights, create_session(n, { 1, 2, 3 }, 0, 0));

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
