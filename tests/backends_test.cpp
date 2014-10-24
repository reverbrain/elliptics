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

	start_nodes_config start_config(results_reporter::get_stream(), std::move(servers), path);
	start_config.fork = true;

	global_data = start_nodes(start_config);
}

static std::set<std::tuple<std::string, int, uint32_t>> get_unique_hosts(session &sess)
{
	std::vector<dnet_route_entry> routes = sess.get_routes();

	std::set<std::tuple<std::string, int, uint32_t>> unique_hosts;

	for (auto it = routes.begin(); it != routes.end(); ++it) {
		dnet_route_entry &entry = *it;
		std::string addr = dnet_addr_string(&entry.addr);

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
					"Host must exist: " + host + ", group: " + std::to_string(static_cast<long long>(group_id)) + ", backend: " + std::to_string(static_cast<long long>(backends[j])));
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

	ELLIPTICS_REQUIRE(enable_result, sess.enable_backend(node.remote(), 1));
	BOOST_REQUIRE_EQUAL(enable_result.get().size(), 1);

	// Wait 0.1 secs to ensure that route list was changed
	usleep(100 * 1000);

	unique_hosts = get_unique_hosts(sess);

	BOOST_REQUIRE_MESSAGE(unique_hosts.find(tuple) != unique_hosts.end(),
		"Host must exist: " + host + ", group: 0, backend: 1");
}

static void test_backend_status(session &sess)
{
	server_node &node = global_data->nodes[0];

	ELLIPTICS_REQUIRE(async_status_result, sess.request_backends_status(node.remote()));
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

	ELLIPTICS_REQUIRE_ERROR(enable_result, sess.enable_backend(node.remote(), 1), -EALREADY);
}

static void test_disable_backend(session &sess)
{
	server_node &node = global_data->nodes[0];

	std::string host = node.remote().to_string();
	auto tuple = std::make_tuple(host, 0, 1);

	auto unique_hosts = get_unique_hosts(sess);

	BOOST_REQUIRE_MESSAGE(unique_hosts.find(tuple) != unique_hosts.end(),
		"Host must exist: " + host + ", group: 0, backend: 1");

	ELLIPTICS_REQUIRE(enable_result, sess.disable_backend(node.remote(), 1));

	// Wait 0.1 secs to ensure that route list was changed
	usleep(100 * 1000);

	unique_hosts = get_unique_hosts(sess);

	BOOST_REQUIRE_MESSAGE(unique_hosts.find(tuple) == unique_hosts.end(),
		"Host must not exist: " + host + ", group: 0, backend: 1");
}

static void test_disable_backend_again(session &sess)
{
	server_node &node = global_data->nodes[0];

	ELLIPTICS_REQUIRE_ERROR(enable_result, sess.disable_backend(node.remote(), 1), -EALREADY);
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

	// Wait 0.1 secs to ensure that route list was changed
	usleep(100 * 1000);

	unique_hosts = get_unique_hosts(sess);

	BOOST_REQUIRE_MESSAGE(unique_hosts.find(tuple) != unique_hosts.end(),
		"Host must exist: " + host + ", group: 2, backend: 1");
}

static void test_direct_backend(session &sess)
{
	const key id = std::string("direct-backend-test");
	sess.set_groups({ 0 });
	const std::string first_str = "first-data";
	const std::string second_str = "second-data";

	server_node &node = global_data->nodes.front();

	session first = sess.clone();
	first.set_direct_id(node.remote(), 0);

	session second = sess.clone();
	second.set_direct_id(node.remote(), 3);

	ELLIPTICS_REQUIRE(async_first_write, first.write_data(id, first_str, 0));
	ELLIPTICS_REQUIRE(async_second_write, second.write_data(id, second_str, 0));

	ELLIPTICS_REQUIRE(async_first_read, first.read_data(id, 0, 0));
	read_result_entry first_read = async_first_read.get_one();
	BOOST_REQUIRE_EQUAL(first_read.file().to_string(), first_str);
	BOOST_REQUIRE_EQUAL(first_read.command()->backend_id, 0);

	ELLIPTICS_REQUIRE(async_second_read, second.read_data(id, 0, 0));
	read_result_entry second_read = async_second_read.get_one();
	BOOST_REQUIRE_EQUAL(second_read.file().to_string(), second_str);
	BOOST_REQUIRE_EQUAL(second_read.command()->backend_id, 3);
}

static std::vector<dnet_raw_id> backend_ids(session &sess, const address &addr, uint32_t backend_id)
{
	std::vector<dnet_route_entry> routes = sess.get_routes();
	std::vector<dnet_raw_id> result;

	for (auto it = routes.begin(); it != routes.end(); ++it) {
		if (it->addr == addr && it->backend_id == backend_id)
			result.push_back(it->id);
	}

	return result;
}

static std::vector<dnet_raw_id> generate_ids(size_t count)
{
	std::vector<dnet_raw_id> result;
	result.reserve(count);

	for (size_t i = 0; i < count; ++i) {
		dnet_raw_id id;
		int seed = rand();
		dnet_digest_transform_raw(&seed, sizeof(seed), id.id, sizeof(id.id));
		result.push_back(id);
	}

	return result;
}

static bool dnet_raw_id_less_than(const dnet_raw_id &first, const dnet_raw_id &second)
{
	return memcmp(first.id, second.id, DNET_ID_SIZE) < 0;
}

static bool dnet_raw_id_equal(const dnet_raw_id &first, const dnet_raw_id &second)
{
	return memcmp(first.id, second.id, DNET_ID_SIZE) == 0;
}

static bool compare_ids(std::vector<dnet_raw_id> first, std::vector<dnet_raw_id> second)
{
	if (first.size() != second.size())
		return false;

	std::sort(first.begin(), first.end(), dnet_raw_id_less_than);
	std::sort(second.begin(), second.end(), dnet_raw_id_less_than);

	return std::equal(first.begin(), first.end(), second.begin(), dnet_raw_id_equal);
}

static void test_set_backend_ids_for_disabled(session &sess)
{
	server_node &node = global_data->nodes.back();

	auto ids = generate_ids(16);

	ELLIPTICS_REQUIRE(async_set_result, sess.set_backend_ids(node.remote(), 4, ids));

	backend_status_result_entry result = async_set_result.get_one();
	BOOST_REQUIRE(result.is_valid());
	BOOST_REQUIRE_EQUAL(result.count(), 1);

	dnet_backend_status *status = result.backend(0);
	BOOST_REQUIRE_EQUAL(status->backend_id, 4);
	BOOST_REQUIRE_EQUAL(status->state, DNET_BACKEND_DISABLED);

	ELLIPTICS_REQUIRE(async_enable_result, sess.enable_backend(node.remote(), 4));

	// Wait 0.1 secs to ensure that route list was changed
	usleep(100 * 1000);

	auto route_ids = backend_ids(sess, node.remote(), 4);
	BOOST_REQUIRE_EQUAL(ids.size(), route_ids.size());
	BOOST_REQUIRE(compare_ids(ids, route_ids));
}

static void test_set_backend_ids_for_enabled(session &sess)
{
	server_node &node = global_data->nodes.back();

	auto ids = generate_ids(16);

	ELLIPTICS_REQUIRE(async_set_result, sess.set_backend_ids(node.remote(), 4, ids));

	backend_status_result_entry result = async_set_result.get_one();
	BOOST_REQUIRE(result.is_valid());
	BOOST_REQUIRE_EQUAL(result.count(), 1);

	dnet_backend_status *status = result.backend(0);
	BOOST_REQUIRE_EQUAL(status->backend_id, 4);
	BOOST_REQUIRE_EQUAL(status->state, DNET_BACKEND_ENABLED);

	// Wait 0.1 secs to ensure that route list was changed
	usleep(100 * 1000);

	auto route_ids = backend_ids(sess, node.remote(), 4);
	BOOST_REQUIRE_EQUAL(ids.size(), route_ids.size());
	BOOST_REQUIRE(compare_ids(ids, route_ids));
}

static void test_make_backend_readonly(session &sess)
{
	server_node &node = global_data->nodes.back();
	const key id = std::string("read_only_key");
	const std::string data = "read_only_data";

	ELLIPTICS_REQUIRE(async_readonly_result, sess.make_readonly(node.remote(), 4));

	backend_status_result_entry result = async_readonly_result.get_one();
	BOOST_REQUIRE(result.is_valid());
	BOOST_REQUIRE_EQUAL(result.count(), 1);

	dnet_backend_status *status = result.backend(0);
	BOOST_REQUIRE_EQUAL(status->backend_id, 4);
	BOOST_REQUIRE_EQUAL(status->read_only, true);

	session new_sess = sess.clone();
	new_sess.set_direct_id(node.remote(), 4);

	ELLIPTICS_REQUIRE_ERROR(write_result, new_sess.write_data(id, data, 0), -EROFS);

	ELLIPTICS_REQUIRE_ERROR(second_async_readonly_result, sess.make_readonly(node.remote(), 4), -EALREADY);
}

static void test_make_backend_writeable(session &sess)
{
	server_node &node = global_data->nodes.back();
	const key id = std::string("read_only_key");
	const std::string data = "read_only_data";

	ELLIPTICS_REQUIRE(async_readonly_result, sess.make_writable(node.remote(), 4));

	backend_status_result_entry result = async_readonly_result.get_one();
	BOOST_REQUIRE(result.is_valid());
	BOOST_REQUIRE_EQUAL(result.count(), 1);

	dnet_backend_status *status = result.backend(0);
	BOOST_REQUIRE_EQUAL(status->backend_id, 4);
	BOOST_REQUIRE_EQUAL(status->read_only, false);

	session new_sess = sess.clone();
	new_sess.set_direct_id(node.remote(), 4);

	ELLIPTICS_REQUIRE(write_result, new_sess.write_data(id, data, 0));
	ELLIPTICS_REQUIRE(read_result, new_sess.read_data(id, 0, 0));

	ELLIPTICS_REQUIRE_ERROR(second_async_readonly_result, sess.make_writable(node.remote(), 4), -EALREADY);
}

static void test_change_group(session &sess)
{
	server_node &node = global_data->nodes.back();
	const uint32_t backend_id = 4;
	const int old_group_id = 2;
	const int new_group_id = 10;

	std::string host = node.remote().to_string();
	auto old_tuple = std::make_tuple(host, old_group_id, backend_id);
	auto new_tuple = std::make_tuple(host, new_group_id, backend_id);

	auto unique_hosts = get_unique_hosts(sess);

	BOOST_REQUIRE_MESSAGE(unique_hosts.find(old_tuple) != unique_hosts.end(),
		"Host must not exist: " + host + ", group: 2, backend: 1");

	BOOST_REQUIRE_MESSAGE(unique_hosts.find(new_tuple) == unique_hosts.end(),
		"Host must not exist: " + host + ", group: 10, backend: 1");

	server_config server = node.config();
	config_data &backend = server.backends[backend_id];
	backend("group", new_group_id);

	server.write(node.config_path());

	ELLIPTICS_REQUIRE(stop_result, sess.disable_backend(node.remote(), backend_id));
	ELLIPTICS_REQUIRE(start_result, sess.enable_backend(node.remote(), backend_id));

	// Wait 0.1 secs to ensure that route list was changed
	usleep(100 * 1000);

	unique_hosts = get_unique_hosts(sess);

	BOOST_REQUIRE_MESSAGE(unique_hosts.find(old_tuple) == unique_hosts.end(),
		"Host must not exist: " + host + ", group: 2, backend: 1");

	BOOST_REQUIRE_MESSAGE(unique_hosts.find(new_tuple) != unique_hosts.end(),
		"Host must not exist: " + host + ", group: 10, backend: 1");
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
	ELLIPTICS_TEST_CASE(test_direct_backend, create_session(n, { 0 }, 0, 0));
	ELLIPTICS_TEST_CASE(test_set_backend_ids_for_disabled, create_session(n, { 0 }, 0, 0));
	ELLIPTICS_TEST_CASE(test_set_backend_ids_for_enabled, create_session(n, { 0 }, 0, 0));
	ELLIPTICS_TEST_CASE(test_make_backend_readonly, create_session(n, { 0 }, 0, 0));
	ELLIPTICS_TEST_CASE(test_make_backend_writeable, create_session(n, { 0 }, 0, 0));
	ELLIPTICS_TEST_CASE(test_change_group, create_session(n, { 0 }, 0, 0));

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

