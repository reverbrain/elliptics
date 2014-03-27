/*
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

#include "srw_test.hpp"
#include "test_base.hpp"
#include <algorithm>

#define BOOST_TEST_NO_MAIN
#include <boost/test/included/unit_test.hpp>

#include <boost/program_options.hpp>

using namespace ioremap::elliptics;
using namespace boost::unit_test;

namespace tests {

static std::shared_ptr<nodes_data> global_data;

static void configure_nodes(const std::vector<std::string> &remotes, const std::string &path)
{
	if (remotes.empty()) {
		global_data = start_nodes(results_reporter::get_stream(), std::vector<server_config>({
			server_config::default_srw_value().apply_options(config_data()
				("group", 1)
			)
		}), path);
	} else {
		global_data = start_nodes(results_reporter::get_stream(), remotes, path);
	}
}

static void init_application(session &sess, const std::string &app_name)
{
	init_application_impl(sess, app_name, *global_data);
}

static void send_echo(session &sess, const std::string &app_name, const std::string &data)
{
	key key_id = app_name;
	key_id.transform(sess);
	dnet_id id = key_id.id();

	ELLIPTICS_REQUIRE(exec_result, sess.exec(&id, app_name + "@echo", data));

	sync_exec_result result = exec_result;
	BOOST_REQUIRE_EQUAL(result.size(), 1);
	BOOST_REQUIRE_EQUAL(result[0].context().data().to_string(), data);
}

bool register_tests(test_suite *suite, node n)
{
	ELLIPTICS_TEST_CASE(upload_application, global_data->locator_port, global_data->directory.path());
	ELLIPTICS_TEST_CASE(start_application, create_session(n, { 1 }, 0, 0), application_name());
	ELLIPTICS_TEST_CASE(init_application, create_session(n, { 1 }, 0, 0), application_name());
	ELLIPTICS_TEST_CASE(send_echo, create_session(n, { 1 }, 0, 0), application_name(), "some-data");
	ELLIPTICS_TEST_CASE(send_echo, create_session(n, { 1 }, 0, 0), application_name(), "some-data and long-data.. like this");

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

	if (vm.count("help")) {
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
	atexit(tests::destroy_global_data);

	srand(time(0));
	return unit_test_main(tests::register_tests, argc, argv);
}
