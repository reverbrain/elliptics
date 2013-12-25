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

#include "test_base.hpp"
#include <algorithm>
#include <cocaine/framework/services/storage.hpp>

#define BOOST_TEST_NO_MAIN
#include <boost/test/included/unit_test.hpp>

#include <boost/program_options.hpp>

#include "srw_test.hpp"

using namespace ioremap::elliptics;
using namespace boost::unit_test;

namespace tests {

static std::shared_ptr<nodes_data> global_data;

static void configure_nodes(const std::vector<std::string> &remotes, const std::string &path)
{
	if (remotes.empty()) {
		global_data = start_nodes(results_reporter::get_stream(), std::vector<config_data>({
			config_data::default_srw_value()
				("group", 1)
				("srw_config", "some_path")
		}), path);
	} else {
		global_data = start_nodes(results_reporter::get_stream(), remotes, path);
	}
}

static void upload_application(const std::string &app_name)
{
	using namespace cocaine::framework;

	service_manager_t::endpoint_t endpoint("127.0.0.1", global_data->locator_port);
	auto manager = service_manager_t::create(endpoint);

	auto storage = manager->get_service<storage_service_t>("storage");

	const std::vector<std::string> app_tags = {
		"apps"
	};
	const std::vector<std::string> profile_tags = {
		"profiles"
	};

	msgpack::sbuffer buffer;
	{
		msgpack::packer<msgpack::sbuffer> packer(buffer);
		packer.pack_map(1);
		packer << std::string("isolate");
		packer.pack_map(2);
		packer << std::string("type");
		packer << std::string("process");
		packer << std::string("args");
		packer.pack_map(1);
		packer << std::string("spool");
		packer << global_data->directory.path();
	}
	std::string profile(buffer.data(), buffer.size());
	{
		buffer.clear();
		msgpack::packer<msgpack::sbuffer> packer(buffer);
		packer.pack_map(2);
		packer << std::string("type");
		packer << std::string("binary");
		packer << std::string("slave");
		packer << app_name;
	}
	std::string manifest(buffer.data(), buffer.size());
	{
		buffer.clear();
		msgpack::packer<msgpack::sbuffer> packer(buffer);
		packer << read_file(COCAINE_TEST_APP);
	}
	std::string app(buffer.data(), buffer.size());

	storage->write("manifests", app_name, manifest, app_tags).next();
	storage->write("profiles", app_name, profile, profile_tags).next();
	storage->write("apps", app_name, app, profile_tags).next();
}

static void start_application(session &sess, const std::string &app_name)
{
	key key_id = app_name;
	key_id.transform(sess);
	dnet_id id = key_id.id();

	ELLIPTICS_REQUIRE(result, sess.exec(&id, app_name + "@start-task", data_pointer()));
}

static void init_application(session &sess, const std::string &app_name)
{
	key key_id = app_name;
	key_id.transform(sess);
	dnet_id id = key_id.id();

	node_info info;
	info.groups = { 1 };
	info.path = global_data->directory.path();

	for (auto it = global_data->nodes.begin(); it != global_data->nodes.end(); ++it)
		info.remotes.push_back(it->remote());

	ELLIPTICS_REQUIRE(exec_result, sess.exec(&id, app_name + "@init", info.pack()));

	sync_exec_result result = exec_result;
	BOOST_REQUIRE_EQUAL(result.size(), 1);
	BOOST_REQUIRE_EQUAL(result[0].context().data().to_string(), "inited");
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
	ELLIPTICS_TEST_CASE(upload_application, "dnet_cpp_srw_test_app");
	ELLIPTICS_TEST_CASE(start_application, create_session(n, { 1 }, 0, 0), "dnet_cpp_srw_test_app");
	ELLIPTICS_TEST_CASE(init_application, create_session(n, { 1 }, 0, 0), "dnet_cpp_srw_test_app");
	ELLIPTICS_TEST_CASE(send_echo, create_session(n, { 1 }, 0, 0), "dnet_cpp_srw_test_app", "some-data");
	ELLIPTICS_TEST_CASE(send_echo, create_session(n, { 1 }, 0, 0), "dnet_cpp_srw_test_app", "some-data and long-data.. like this");

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
