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

using namespace ioremap::elliptics;
using namespace boost::unit_test;

namespace tests {

static std::shared_ptr<nodes_data> global_data;

static void configure_server_nodes()
{
	global_data = start_nodes(results_reporter::get_stream(), std::vector<config_data>({
		config_data::default_srw_value()
			("group", 1)
			("srw_config", "some_path")
	}));
}

static void upload_application(const std::string &app_name)
{
	using namespace cocaine::framework;

	service_manager_t::endpoint_t endpoint("127.0.0.1", 10053);
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
		packer.pack(std::string("isolate"));
		packer.pack_map(2);
		packer.pack(std::string("type"));
		packer.pack(std::string("process"));
		packer.pack(std::string("args"));
		packer.pack_map(1);
		packer.pack(std::string("spool"));
		packer.pack(std::string("/tmp"));
	}
	std::string profile(buffer.data(), buffer.size());
	{
		msgpack::packer<msgpack::sbuffer> packer(buffer);
		packer.pack_map(2);
		packer.pack(std::string("type"));
		packer.pack(std::string("binary"));
		packer.pack(std::string("slave"));
		packer.pack(app_name);
	}
	std::string manifest(buffer.data(), buffer.size());

	std::string app;

	storage->write("manifests", app_name, manifest, app_tags).next();
	storage->write("profiles", app_name, profile, profile_tags).next();
	storage->write("apps", app_name, app, profile_tags).next();
}

bool register_tests(test_suite *suite, node n)
{
	ELLIPTICS_TEST_CASE(upload_application, "dnet_cpp_srw_test_app");

	return true;
}

boost::unit_test::test_suite *register_tests(int argc, char *argv[])
{
	namespace bpo = boost::program_options;

	bpo::variables_map vm;
	bpo::options_description generic("Test options");

	std::vector<std::string> remote;

	generic.add_options()
			("help", "This help message")
			("remote", bpo::value<std::vector<std::string>>(&remote), "Remote elliptics server address")
			;

	bpo::store(bpo::parse_command_line(argc, argv, generic), vm);
	bpo::notify(vm);

	if (vm.count("help")) {
		std::cerr << generic;
		return NULL;
	}

	test_suite *suite = new test_suite("Local Test Suite");

	if (remote.empty()) {
		configure_server_nodes();
		register_tests(suite, global_data->create_client());
	} else {
		dnet_config config;
		memset(&config, 0, sizeof(config));

		logger log(NULL);

		node n(log, config);
		for (auto it = remote.begin(); it != remote.end(); ++it)
			n.add_remote(it->c_str());

		register_tests(suite, n);
	}

	return suite;
}

}

int main(int argc, char *argv[])
{
	srand(time(0));
	int result = unit_test_main(tests::register_tests, argc, argv);
	tests::global_data.reset();
	return result;
}
