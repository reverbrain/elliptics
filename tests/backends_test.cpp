/*
 * 2014+ Copyright (c) Ruslan Nigmatullin <euroelessar@yandex.ru>
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

static size_t groups_count = 2;
static size_t nodes_count = 2;
static size_t backends_count = 8;

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

	server.backends[0]("enable", false)("group", group);

	server.backends.resize(backends_count, server.backends.front());

	return server;
}

static void configure_nodes(const std::string &path)
{
	std::vector<server_config> servers;
	for (size_t i = 0; i < groups_count; ++i) {
		for (size_t j = 0; j < nodes_count; ++j) {
			server_config server = default_value(i);
			server.backends[0]("enable", true);
			server.backends[3]("enable", true);
			servers.push_back(server);
		}
	}

	servers.push_back(default_value(groups_count));

	global_data = start_nodes(results_reporter::get_stream(), servers, path);
}

static std::set<std::tuple<std::string, int, int>> get_unique_hosts(session &sess)
{
	std::vector<dnet_route_entry> routes = sess.get_routes();

	std::set<std::tuple<std::string, int, int>> unique_hosts;

	for (auto it = routes.begin(); it != routes.end(); ++it) {
		dnet_route_entry &entry = *it;
		std::string addr = dnet_server_convert_dnet_addr(&entry.addr);

		unique_hosts.insert(std::make_tuple(addr, entry.group_id, entry.backend_id));
	}

	return unique_hosts;
}

static void test_enable_at_start(session &sess)
{
	auto unique_hosts = get_unique_hosts(sess);
	std::vector<uint32_t> backends = {
		0, 3
	};

//	for (auto it = unique_hosts.begin(); it != unique_hosts.end(); ++it) {
//		std::cout << std::get<0>(*it) << " " << std::get<1>(*it) << " " << std::get<2>(*it) << std::endl;
//	}

	BOOST_REQUIRE_EQUAL(unique_hosts.size(), groups_count * nodes_count * backends.size());

	for (size_t group_id = 0; group_id < groups_count; ++group_id) {
		for (size_t i = 0; i < nodes_count; ++i) {
			for (size_t j = 0; j < backends.size(); ++j) {
				size_t node_id = group_id * nodes_count + i;
				server_node &node = global_data->nodes[node_id];
				std::string host = node.remote().to_string();

				auto tuple = std::make_tuple(host, group_id, backends[j]);

				BOOST_REQUIRE_MESSAGE(unique_hosts.find(tuple) != unique_hosts.end(),
					"Host must exist: " + host + ", group: " + std::to_string(group_id) + ", backend: " + std::to_string(backends[j]));
			}
		}
	}
}

static void test_enable_backend(session &sess)
{
	server_node &node = global_data->nodes[0];

	std::string host = node.remote().to_string();
	auto tuple = std::make_tuple(host, 0, 1);

	auto unique_hosts = get_unique_hosts(sess);

	BOOST_REQUIRE_MESSAGE(unique_hosts.find(tuple) == unique_hosts.end(),
		"Host must not exist: " + host + ", group: 0, backend: 1");

	ELLIPTICS_REQUIRE(enable_result, sess.enable_backend(node.get_native()->addrs[0], 1));

	// Wait 0.5 secs to ensure that route list was changed
	usleep(500 * 1000);

	unique_hosts = get_unique_hosts(sess);

	BOOST_REQUIRE_MESSAGE(unique_hosts.find(tuple) != unique_hosts.end(),
		"Host must exist: " + host + ", group: 0, backend: 1");
}

static void test_backend_status(session &sess)
{
	server_node &node = global_data->nodes[0];

	ELLIPTICS_REQUIRE(async_status_result, sess.request_backends_status(node.get_native()->addrs[0]));
	sync_backend_status_result result = async_status_result;

	BOOST_REQUIRE_EQUAL(result.size(), 1);

	backend_status_result_entry entry = result.front();

	BOOST_REQUIRE_EQUAL(entry.count(), backends_count);

	for (size_t i = 0; i < backends_count; ++i) {
		dnet_backend_status *status = entry.backend(i);
		BOOST_REQUIRE_EQUAL(status->backend_id, i);
		if (i < 2 || i == 3) {
			BOOST_REQUIRE_EQUAL(status->state, DNET_BACKEND_ENABLED);
		} else {
			BOOST_REQUIRE_EQUAL(status->state, DNET_BACKEND_DISABLED);
		}
	}
}

static void test_enable_backend_again(session &sess)
{
	server_node &node = global_data->nodes[0];

	ELLIPTICS_REQUIRE_ERROR(enable_result, sess.enable_backend(node.get_native()->addrs[0], 1), -EALREADY);
}

static void test_disable_backend(session &sess)
{
	server_node &node = global_data->nodes[0];

	std::string host = node.remote().to_string();
	auto tuple = std::make_tuple(host, 0, 1);

	auto unique_hosts = get_unique_hosts(sess);

	BOOST_REQUIRE_MESSAGE(unique_hosts.find(tuple) != unique_hosts.end(),
		"Host must exist: " + host + ", group: 0, backend: 1");

	ELLIPTICS_REQUIRE(enable_result, sess.disable_backend(node.get_native()->addrs[0], 1));

	// Wait 0.5 secs to ensure that route list was changed
	usleep(500 * 1000);

	unique_hosts = get_unique_hosts(sess);

	BOOST_REQUIRE_MESSAGE(unique_hosts.find(tuple) == unique_hosts.end(),
		"Host must not exist: " + host + ", group: 0, backend: 1");
}

static void test_disable_backend_again(session &sess)
{
	server_node &node = global_data->nodes[0];

	ELLIPTICS_REQUIRE_ERROR(enable_result, sess.disable_backend(node.get_native()->addrs[0], 1), -EALREADY);
}

static void test_enable_backend_at_empty_node(session &sess)
{
	server_node &node = global_data->nodes.back();

	std::string host = node.remote().to_string();
	auto tuple = std::make_tuple(host, groups_count, 1);

	auto unique_hosts = get_unique_hosts(sess);

	BOOST_REQUIRE_MESSAGE(unique_hosts.find(tuple) == unique_hosts.end(),
		"Host must not exist: " + host + ", group: 2, backend: 1");

	ELLIPTICS_REQUIRE(enable_result, sess.enable_backend(node.remote(), 1));

	// Wait 0.5 secs to ensure that route list was changed
	usleep(500 * 1000);

	unique_hosts = get_unique_hosts(sess);

	BOOST_REQUIRE_MESSAGE(unique_hosts.find(tuple) != unique_hosts.end(),
		"Host must exist: " + host + ", group: 2, backend: 1");
}

bool register_tests(test_suite *suite, node n)
{
	ELLIPTICS_TEST_CASE(test_enable_at_start, create_session(n, { 1, 2, 3 }, 0, 0));
	ELLIPTICS_TEST_CASE(test_enable_backend, create_session(n, { 1, 2, 3 }, 0, 0));
	ELLIPTICS_TEST_CASE(test_backend_status, create_session(n, { 1, 2, 3 }, 0, 0));
	ELLIPTICS_TEST_CASE(test_enable_backend_again, create_session(n, { 1, 2, 3 }, 0, 0));
	ELLIPTICS_TEST_CASE(test_disable_backend, create_session(n, { 1, 2, 3 }, 0, 0));
	ELLIPTICS_TEST_CASE(test_disable_backend_again, create_session(n, { 1, 2, 3 }, 0, 0));
	ELLIPTICS_TEST_CASE(test_enable_backend_at_empty_node, create_session(n, { 1, 2, 3 }, 0, 0));

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

