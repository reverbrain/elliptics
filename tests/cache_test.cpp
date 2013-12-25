/*
 * 2013+ Copyright (c) Ruslan Nigmatullin <euroelessar@yandex.ru>
 * 2013+ Copyright (c) Andrey Kashin <kashin.andrej@gmail.com>
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
#include "../cache/cache.hpp"

#define BOOST_TEST_NO_MAIN
#include <boost/test/included/unit_test.hpp>

#include <boost/program_options.hpp>

using namespace ioremap::elliptics;
using namespace boost::unit_test;

namespace tests {

static std::shared_ptr<nodes_data> global_data;

static void destroy_global_data()
{
	global_data.reset();
}

static void configure_nodes(const std::string &path)
{
	global_data = start_nodes(results_reporter::get_stream(), std::vector<config_data>({
		config_data::default_value()
			("group", 5)
			("cache_size", 100000)
			("caches_number", 1)
	}), path);
}

static void test_cache_records_sizes(session &sess)
{
	ioremap::cache::cache_manager *cache = (ioremap::cache::cache_manager*) global_data->nodes[0].get_native()->cache;
	const size_t cache_size = cache->cache_size();
	const size_t cache_pages_number = cache->cache_pages_number();
	data_pointer data("0");

	cache->clear();
	size_t record_size = 0;
	{
		ELLIPTICS_REQUIRE(write_result, sess.write_cache(key(boost::lexical_cast<std::string>(0)), data, 3000));
		const auto& stats = cache->get_total_cache_stats();
		record_size = stats.size_of_objects;
		BOOST_REQUIRE_EQUAL(stats.number_of_objects, 1);
	}

	size_t records_number = cache_size / cache_pages_number / record_size - 5;
	for (size_t id = 1; id < records_number; ++id) {
		ELLIPTICS_REQUIRE(write_result, sess.write_cache(key(boost::lexical_cast<std::string>(id)), data, 3000));
		const auto& stats = cache->get_total_cache_stats();

		size_t total_pages_sizes = 0;
		for (size_t i = 0; i < stats.pages_sizes.size(); ++i) {
			total_pages_sizes += stats.pages_sizes[i];
		}

		BOOST_REQUIRE_EQUAL(stats.number_of_objects * record_size, stats.size_of_objects);
		BOOST_REQUIRE_EQUAL(stats.number_of_objects, id + 1);
		BOOST_REQUIRE_EQUAL(stats.size_of_objects, total_pages_sizes);
	}
}

static void test_cache_overflow(session &sess)
{
	ioremap::cache::cache_manager *cache = (ioremap::cache::cache_manager*) global_data->nodes[0].get_native()->cache;
	const size_t cache_size = cache->cache_size();
	const size_t cache_pages_number = cache->cache_pages_number();
	data_pointer data("0");

	cache->clear();
	size_t record_size = 0;
	{
		ELLIPTICS_REQUIRE(write_result, sess.write_cache(key(std::string("0")), data, 3000));
		const auto& stats = cache->get_total_cache_stats();
		record_size = stats.size_of_objects;
	}

	size_t records_number = (cache_size / cache_pages_number / record_size) * 10;
	for (size_t id = 1; id < records_number; ++id) {
		ELLIPTICS_REQUIRE(write_result, sess.write_cache(key(boost::lexical_cast<std::string>(id)), data, 3000));
		const auto& stats = cache->get_total_cache_stats();

		size_t total_pages_sizes = 0;
		for (size_t i = 0; i < stats.pages_sizes.size(); ++i) {
			total_pages_sizes += stats.pages_sizes[i];

//			BOOST_REQUIRE_LE(stats.pages_sizes[i], stats.pages_max_sizes[i]);
		}

//		BOOST_REQUIRE_LE(stats.size_of_objects, cache_size);
//		BOOST_REQUIRE_EQUAL(stats.size_of_objects, total_pages_sizes);
	}
}

std::string generate_data(size_t length)
{
	std::string data;
	for (size_t i = 0; i < length; ++i)
	{
		data += (char) (rand() & (1<<8));
	}
	return data;
}

bool register_tests(test_suite *suite, node n)
{
	ELLIPTICS_TEST_CASE(test_cache_records_sizes, create_session(n, { 5 }, 0, DNET_IO_FLAGS_CACHE | DNET_IO_FLAGS_CACHE_ONLY));
	ELLIPTICS_TEST_CASE(test_cache_overflow, create_session(n, { 5 }, 0, DNET_IO_FLAGS_CACHE | DNET_IO_FLAGS_CACHE_ONLY));
	ELLIPTICS_TEST_CASE(test_cache_overflow, create_session(n, { 5 }, 0, DNET_IO_FLAGS_CACHE));

	return true;
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
