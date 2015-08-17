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
static int cache_sync_timeout = 1;

static server_config default_value(int group)
{
	server_config server = server_config::default_value();
	server.options
		("io_thread_num", 8)
		("nonblocking_io_thread_num", 1)
		("net_thread_num", 1)
		("caches_number", 1)
		("cache_size", 100000)
		("cache_shards", 1)
		("cache_sync_timeout", cache_sync_timeout)
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

/*
 * Multiple writes with same key must be processed in the same order as
 * they were initiated by client.
 *
 * Following test checks this mechanics by calling write_cas() with data containing
 * counter that is incremented after every write_cas() and checking that previosly stored
 * counter is one unit less than current counter. Also this test writes multiple different
 * keys (with repetitions) in different order, thereby modelling real workload case.
 */
static void test_write_order_execution(session &sess)
{
	const int num_write_repetitions = 5;
	const int num_different_keys = 10;
	std::vector<std::pair<key, int>> keys;
	for (int i = 0; i < num_different_keys; ++i) {
		key id(std::to_string(static_cast<unsigned long long>(i)));
		for (int j = 0; j < num_write_repetitions; ++j) {
			keys.push_back(std::make_pair(id, i));
		}
	}

	std::unique_ptr<async_write_result[]> results(new async_write_result[keys.size()]);
	dnet_id old_csum;

	const int num_iterations = 30;
	for (int i = 0; i < num_iterations; ++i) {
		// every key is associated with counter, which is initialized by zero
		std::vector<int> write_counter(num_different_keys, 0);

		std::random_shuffle(keys.begin(), keys.end());

		for (size_t j = 0; j < keys.size(); ++j) {
			// increment counter associated with key identified by key_id
			const int key_id = keys[j].second;
			const int new_value = write_counter[key_id]++;
			if (new_value > 0) {
				const int prev_value = new_value - 1;
				memset(&old_csum, 0, sizeof(old_csum));
				sess.transform(std::to_string(static_cast<unsigned long long>(prev_value)), old_csum);
				results[j] = std::move(sess.write_cas(keys[j].first, std::to_string(static_cast<unsigned long long>(new_value)), old_csum, 0));
			} else {
				// first write
				results[j] = std::move(sess.write_data(keys[j].first, std::to_string(static_cast<unsigned long long>(new_value)), 0));
			}
		}

		for (size_t j = 0; j < keys.size(); ++j) {
			results[j].wait();
			const int err = results[j].error().code();
			BOOST_REQUIRE_MESSAGE(err == 0,
					      "write_cas() failed (err=" + std::to_string(static_cast<unsigned long long>(err)) + "): "
					      "multiple consecutive writes are executed out-of-order "
					      "or overlapped. Oplock mechanism of backend's request queue is broken.");
		}
	}
}

/*
 * After writing of a key to cache, keys data will be synced to disk cache_sync_timeout seconds later.
 * Before syncing a key, dnet_oplock() taken for this key. After syncing a key, key's oplock released.
 *
 * Following test checks this mechanics by calling write_data(key, data) multiple times with the same data,
 * then writing to cache by calling write_cache(key, cache_data) cache data, waiting cache_sync_timeout seconds
 * until cache is synced back to disk (backend), thereby taking oplock. Then called write_data(key, result_data).
 * If last write_data() operation timeouted, then dnet_opunlock() (after cache sync) is not properly realeased key's oplock.
 */
static void test_oplock(session &sess)
{
	const key id(std::string("oplock_key"));
	const std::string data = "some_data";
	const std::string cache_data = "cache_data";
	const std::string result_data = "result_data";

	const size_t num_writes = 10;
	std::unique_ptr<async_write_result[]> results(new async_write_result[num_writes]);

	for (size_t i = 0; i < num_writes; ++i) {
		results[i] = std::move(sess.write_data(id, data, 0));
	}
	for (size_t i = 0; i < num_writes; ++i) {
		results[i].wait();
	}
	ELLIPTICS_COMPARE_REQUIRE(read_data_result, sess.read_data(id, 0, 0), data);

	ELLIPTICS_REQUIRE(async_cache_write, sess.write_cache(id, cache_data, 0));
	sleep(cache_sync_timeout + 1);
	ELLIPTICS_COMPARE_REQUIRE(read_cache_result, sess.read_data(id, 0, 0), cache_data);
	ELLIPTICS_REQUIRE(async_write, sess.write_data(id, result_data, 0));
	ELLIPTICS_COMPARE_REQUIRE(read_result, sess.read_data(id, 0, 0), result_data);
}


bool register_tests(test_suite *suite, node n)
{
	ELLIPTICS_TEST_CASE(test_write_order_execution, create_session(n, { 1 }, 0, 0));
	ELLIPTICS_TEST_CASE(test_oplock, create_session(n, { 1 }, 0, 0));

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
