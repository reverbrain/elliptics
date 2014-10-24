/*
 * 2008+ Copyright (c) Evgeniy Polyakov <zbr@ioremap.net>
 * 2013+ Copyright (c) Ruslan Nigmatullin <euroelessar@yandex.ru>
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

#include <algorithm>
#include <deque>

#define BOOST_TEST_NO_MAIN
#include <boost/test/included/unit_test.hpp>

#include <boost/program_options.hpp>

using namespace ioremap::elliptics;
using namespace boost::unit_test;

namespace tests {

static std::shared_ptr<nodes_data> global_data;

static void configure_nodes(const std::vector<std::string> &remotes, const std::string &path)
{
#ifndef NO_SERVER
	if (remotes.empty()) {
		start_nodes_config start_config(results_reporter::get_stream(), std::vector<server_config>({
			server_config::default_value().apply_options(config_data()
				("indexes_shard_count", 1)
				("group", 5)
			)
		}), path);

		global_data = start_nodes(start_config);
	} else
#endif // NO_SERVER
		global_data = start_nodes(results_reporter::get_stream(), remotes, path);
}

static void test_capped_collection(session &sess, const std::string &collection_name)
{
	key collection = collection_name;
	sess.transform(collection);

	index_entry index(collection.raw_id(), data_pointer());

	std::deque<key> existing_objects;

	for (int i = 0; i < 10; ++i) {
		std::string object = "capped_obj_" + boost::lexical_cast<std::string>(i);
		std::string object_data = "capped_obj_data_" + boost::lexical_cast<std::string>(i);

		ELLIPTICS_REQUIRE(add_result, sess.add_to_capped_collection(object, index, 5, true));
		ELLIPTICS_REQUIRE(write_result, sess.write_data(object, object_data, 0));
		ELLIPTICS_REQUIRE(find_result, sess.find_any_indexes(std::vector<std::string>(1, collection_name)));
		ELLIPTICS_REQUIRE(test_read_result, sess.read_data(object, 0, 0));

		key id = object;
		sess.transform(id);
		existing_objects.push_back(id.id());

		sync_read_result test_read_result_sync = test_read_result;

		BOOST_REQUIRE_EQUAL(test_read_result_sync.size(), 1);
		BOOST_REQUIRE_EQUAL(object_data, test_read_result_sync[0].file().to_string());

		if (existing_objects.size() > 5) {
			ELLIPTICS_REQUIRE_ERROR(read_result, sess.read_data(existing_objects.front(), 0, 0), -ENOENT);

			existing_objects.pop_front();
		}

		sync_find_indexes_result results = find_result;
		BOOST_REQUIRE_EQUAL(existing_objects.size(), results.size());

		std::set<key> objects(existing_objects.begin(), existing_objects.end());

		for (size_t i = 0; i < results.size(); ++i) {
			const find_indexes_result_entry &entry = results[i];
			key id = entry.id;
			BOOST_REQUIRE(objects.find(id) != objects.end());
			objects.erase(id);
		}
	}
}

bool register_tests(test_suite *suite, node n)
{
	ELLIPTICS_TEST_CASE(test_capped_collection, create_session(n, {5}, 0, 0), "capped-collection");

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

	std::vector<std::string> remotes;
	std::string path;

	generic.add_options()
		("help", "This help message")
		("remote", bpo::value(&remotes), "Remote elliptics server address")
		("path", bpo::value(&path), "Path where to store everything")
		 ;

	bpo::store(bpo::parse_command_line(argc, argv, generic), vm);
	bpo::notify(vm);

#ifndef NO_SERVER
	if (vm.count("help")) {
#else
	if (vm.count("help") || remotes.empty()) {
#endif
		std::cerr << generic;
		return NULL;
	}

	test_suite *suite = new test_suite("Local Test Suite");

	configure_nodes(remotes, path);

	register_tests(suite, *global_data->node);

	return suite;
}

}

int main(int argc, char *argv[])
{
	srand(time(0));
	atexit(tests::destroy_global_data);
	return unit_test_main(tests::register_tests, argc, argv);
}

