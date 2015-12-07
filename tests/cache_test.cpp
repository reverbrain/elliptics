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

#include <list>
#include <stdexcept>

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
	start_nodes_config start_config(results_reporter::get_stream(), std::vector<server_config>({
		server_config::default_value().apply_options(config_data()
			("group", 5)
			("cache_size", 100000)
			("cache_shards", 1)
		)
	}), path);

	global_data = start_nodes(start_config);
}

static void test_cache_timestamp(session &sess)
{
	argument_data data("this is a timestamp test");

	key k("this is a timestamp test key");
	sess.transform(k);

	dnet_io_control ctl;
	memset(&ctl, 0, sizeof(ctl));

	ctl.data = data.data();

	dnet_current_time(&ctl.io.timestamp);
	ctl.io.flags = DNET_IO_FLAGS_CACHE;
	ctl.io.start = 5;
	ctl.io.size = data.size();

	memcpy(&ctl.id, &k.id(), sizeof(dnet_id));
	ctl.fd = -1;

	ELLIPTICS_REQUIRE(write_result, sess.write_data(ctl));

	sleep(ctl.io.start + 2);

	ELLIPTICS_REQUIRE(read_result, sess.read_data(k, 0, 0));
	auto io = read_result.get_one().io_attribute();

	BOOST_REQUIRE_EQUAL(io->timestamp.tsec, ctl.io.timestamp.tsec);
	BOOST_REQUIRE_EQUAL(io->timestamp.tnsec, ctl.io.timestamp.tnsec);
}

static void test_cache_records_sizes(session &sess)
{
	dnet_node *node = global_data->nodes[0].get_native();
	ioremap::cache::cache_manager *cache = (ioremap::cache::cache_manager*) node->io->backends[0].cache;
	const size_t cache_size = cache->cache_size();
	const size_t cache_pages_number = cache->cache_pages_number();
	argument_data data("0");

	cache->clear();
	size_t record_size = 0;
	{
		ELLIPTICS_REQUIRE(write_result, sess.write_cache(key(boost::lexical_cast<std::string>(0)), data, 3000));
		auto stats = cache->get_total_cache_stats();
		record_size = stats.size_of_objects;
		BOOST_REQUIRE_EQUAL(stats.number_of_objects, 1);
	}

	size_t records_number = cache_size / cache_pages_number / record_size - 5;
	for (size_t id = 1; id < records_number; ++id) {
		ELLIPTICS_REQUIRE(write_result, sess.write_cache(key(boost::lexical_cast<std::string>(id)), data, 3000));
		auto stats = cache->get_total_cache_stats();

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
	dnet_node *node = global_data->nodes[0].get_native();
	ioremap::cache::cache_manager *cache = (ioremap::cache::cache_manager*) node->io->backends[0].cache;
	const size_t cache_size = cache->cache_size();
	const size_t cache_pages_number = cache->cache_pages_number();
	argument_data data("0");

	cache->clear();
	size_t record_size = 0;
	{
		ELLIPTICS_REQUIRE(write_result, sess.write_cache(key(std::string("0")), data, 3000));
		auto stats = cache->get_total_cache_stats();
		record_size = stats.size_of_objects;
	}

	size_t records_number = (cache_size / cache_pages_number / record_size) * 10;
	for (size_t id = 1; id < records_number; ++id) {
		ELLIPTICS_REQUIRE(write_result, sess.write_cache(key(boost::lexical_cast<std::string>(id)), data, 3000));
		auto stats = cache->get_total_cache_stats();

		size_t total_pages_sizes = 0;
		for (size_t i = 0; i < stats.pages_sizes.size(); ++i) {
			total_pages_sizes += stats.pages_sizes[i];
		}
	}
}

/*!
 * \defgroup test_cache_lru_eviction Test cache lru eviction
 * This test assures that cache uses lru eviction scheme.
 * It means that the last accessed element should be removed first on eviction.
 * For this test we define auxiliary class \a lru_list_emulator_t that emulates work of simple lru list.
 * Then we perform operations in parallel on real cache and lru_list_emulator and check that cache evict correct elements.
 * We cannot guarantee that cache will erase some element at some moment, because erases can be deferred.
 * That's why we check the fact that cache doesn't erase element that shouldn't be erased.
 *
 * Test has three stages:
 *  - Write data to cache's full capacity.
 *  - Add one more element and check that all elements, except for the first added to cache are still in list.
 *  - Repeat stage two.
 * \{
 */

class lru_list_emulator_t {
public:
	void add(int value) {
		lru_list.push_back(value);
	}

	void remove(int value) {
		std::list<int>::iterator it = std::find(lru_list.begin(), lru_list.end(), value);
		if (it == lru_list.end()) {
			throw std::logic_error("remove: No such element in list");
		}
		lru_list.erase(it);
	}

	void remove_last() {
		if (lru_list.empty()) {
			throw std::logic_error("remove_last: Can't remove from empty list");
		}
		lru_list.pop_front();
	}

	void update(int value) {
		std::list<int>::iterator it = std::find(lru_list.begin(), lru_list.end(), value);
		if (it == lru_list.end()) {
			throw std::logic_error("update: No such element in list");
		}

		lru_list.erase(it);
		lru_list.push_back(value);
	}

	bool contains(int value) const {
		return std::find(lru_list.begin(), lru_list.end(), value) != lru_list.end();
	}

private:
	std::list<int> lru_list;
};

void cache_write_check_lru(session &sess, int id, const argument_data& data, long timeout,
							   lru_list_emulator_t& lru_list_emulator, ioremap::cache::cache_manager *cache) {

	key idKey = key(boost::lexical_cast<std::string>(id));

	int objects_number_before = cache->get_total_cache_stats().number_of_objects;
	ELLIPTICS_REQUIRE(write_result, sess.write_cache(idKey, data, timeout));
	lru_list_emulator.add(id);
	int objects_number_after = cache->get_total_cache_stats().number_of_objects;

	int objects_removed = objects_number_before - objects_number_after + 1;
	for (int i = 0; i < objects_removed; ++i) {
		lru_list_emulator.remove_last();
	}
}

void cache_read_check_lru(session &sess, int id, lru_list_emulator_t& lru_list_emulator, ioremap::cache::cache_manager *cache) {

	key idKey = key(boost::lexical_cast<std::string>(id));
	std::unique_ptr<async_read_result> read_result;

	int objects_number_before = cache->get_total_cache_stats().number_of_objects;
	if (!lru_list_emulator.contains(id)) {
		ELLIPTICS_WARN_ERROR(read_result, sess.read_data(idKey, 0, 0), -ENOENT);
	} else {
		ELLIPTICS_REQUIRE(read_result, sess.read_data(idKey, 0, 0));
		lru_list_emulator.update(id);
	}
	int objects_number_after = cache->get_total_cache_stats().number_of_objects;

	int objects_removed = objects_number_before - objects_number_after;
	for (int i = 0; i < objects_removed; ++i) {
		lru_list_emulator.remove_last();
	}
}

static void test_cache_lru_eviction(session &sess)
{
	dnet_node *node = global_data->nodes[0].get_native();
	ioremap::cache::cache_manager *cache = (ioremap::cache::cache_manager*) node->io->backends[0].cache;
	const size_t cache_size = cache->cache_size();
	const size_t cache_pages_number = cache->cache_pages_number();

	BOOST_REQUIRE_MESSAGE(cache_pages_number == 1, "Can't run cache_lru_eviction test with more then one cache page");

	lru_list_emulator_t lru_list_emulator;
	argument_data data("0");

	size_t current_objects_number = 0;

	cache->clear();
	size_t record_size = 0;
	{
		cache_write_check_lru(sess, current_objects_number++, data, 3000, lru_list_emulator, cache);
		auto stats = cache->get_total_cache_stats();
		record_size = stats.size_of_objects;
	}

	// Fill cache to full capacity with keys
	size_t max_records_number = (cache_size / cache_pages_number / record_size) - 1;
	for (size_t recordNumber = 1; recordNumber < max_records_number; ++recordNumber) {
		cache_write_check_lru(sess, current_objects_number++, data, 3000, lru_list_emulator, cache);
	}
	auto stats = cache->get_total_cache_stats();
	BOOST_REQUIRE_EQUAL(stats.number_of_objects, current_objects_number);

	int removed_key = current_objects_number;
	cache_write_check_lru(sess, current_objects_number++, data, 3000, lru_list_emulator, cache);

	// Check that 0 record is evicted
	cache_read_check_lru(sess, 0, lru_list_emulator, cache);

	// Check that all keys are in list
	for (size_t recordNumber = 1; recordNumber < max_records_number; ++recordNumber) {
		cache_read_check_lru(sess, recordNumber, lru_list_emulator, cache);
		cache_write_check_lru(sess, recordNumber, data, 3000, lru_list_emulator, cache);
	}

	// Add one more new key, check that removed_key, which was not updated is removed
	cache_write_check_lru(sess, current_objects_number++, data, 3000, lru_list_emulator, cache);
	cache_read_check_lru(sess, removed_key, lru_list_emulator, cache);
}

/*! \} */ //test_cache_lru_eviction group

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
	ELLIPTICS_TEST_CASE(test_cache_timestamp, create_session(n, { 5 }, 0, DNET_IO_FLAGS_CACHE));
	ELLIPTICS_TEST_CASE(test_cache_records_sizes, create_session(n, { 5 }, 0, DNET_IO_FLAGS_CACHE | DNET_IO_FLAGS_CACHE_ONLY));
	ELLIPTICS_TEST_CASE(test_cache_overflow, create_session(n, { 5 }, 0, DNET_IO_FLAGS_CACHE | DNET_IO_FLAGS_CACHE_ONLY));
	ELLIPTICS_TEST_CASE(test_cache_overflow, create_session(n, { 5 }, 0, DNET_IO_FLAGS_CACHE));
	ELLIPTICS_TEST_CASE(test_cache_lru_eviction, create_session(n, { 5 }, 0, DNET_IO_FLAGS_CACHE | DNET_IO_FLAGS_CACHE_ONLY));

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
