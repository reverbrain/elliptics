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

#ifdef HAVE_COCAINE
# include "srw_test.hpp"
#endif
#include "test_base.hpp"

#include <signal.h>

#include <algorithm>
#include <cstdio>
#include <iostream>

#include <boost/program_options.hpp>
#include <boost/asio.hpp>

#include "rapidjson/document.h"
#include "rapidjson/filestream.h"
#include "rapidjson/writer.h"
#include "rapidjson/stringbuffer.h"

using namespace ioremap::elliptics;

/*
 * 1. Remotes list as json to stdout
 * 2. Ability to write logs to stderr
 * 3. Stop on SIGTERM/SIGINT
 */

static std::shared_ptr<tests::nodes_data> global_data;

static void stop_servers(int, siginfo_t *, void *)
{
	global_data.reset();
}

static void setup_signals()
{
	struct sigaction sa;

	memset(&sa, 0, sizeof(sa));
	sa.sa_flags = SA_SIGINFO;
	sa.sa_sigaction = stop_servers;
	sigemptyset(&sa.sa_mask);
	sigaction(SIGTERM, &sa, NULL);
	sigaction(SIGINT, &sa, NULL);

	signal(SIGTSTP, SIG_DFL);
	signal(SIGQUIT, SIG_DFL);

	sigemptyset(&sa.sa_mask);
	sigaddset(&sa.sa_mask, SIGTERM);
	sigaddset(&sa.sa_mask, SIGINT);
	sigaddset(&sa.sa_mask, SIGTSTP);
	sigaddset(&sa.sa_mask, SIGQUIT);
	pthread_sigmask(SIG_UNBLOCK, &sa.sa_mask, NULL);
	sigprocmask(SIG_UNBLOCK, &sa.sa_mask, NULL);
}

/*!
 * \brief Run servers by json configuration
 *
 * Example:
 * \code{.json}
 * {
 * 	"srw": true,
 * 	"path": "/tmp/elliptics-test",
 * 	"servers": [
 * 		{
 * 			"group": 1,
 * 			"srw_config": "/tmp/srw.conf"
 * 		}
 * 	]
 * }
 * \endcode
 *
 * Possible options are:
 * \li If \c srw is set to true elliptics will be started with Cocaine runtime.
 * \li All logs and blobs' data is written to \c path.
 * \li \c server is a list of key-value maps of servers configurations. Each entry \
 *	 contains options which must overwrite default values in configuration file.
 */
static int run_servers(const rapidjson::Value &doc)
{
	bool srw = false;

#ifdef HAVE_COCAINE
	if (doc.HasMember("srw")) {
		if (!doc["srw"].IsBool()) {
			std::cout << "Field \"srw\" must be boolean" << std::endl;
			return 1;
		}
		srw = doc["srw"].GetBool();
	}
#else
	if (doc.HasMember("srw")) {
		std::cerr << "There is no srw support" << std::endl;
		return 1;
	}
#endif

	if (!doc.HasMember("servers")) {
		std::cerr << "Field \"servers\" is missed" << std::endl;
		return 1;
	}

	if (!doc.HasMember("path")) {
		std::cerr << "Field \"path\" is missed" << std::endl;
		return 1;
	}

	const rapidjson::Value &path = doc["path"];

	if (!path.IsString()) {
		std::cout << "Field \"path\" must be string" << std::endl;
		return 1;
	}

	const rapidjson::Value &servers = doc["servers"];
	if (!servers.IsArray()) {
		std::cerr << "Field \"servers\" must be an array" << std::endl;
		return 1;
	}

	std::vector<tests::server_config> configs;
	configs.resize(servers.Size(), srw ? tests::server_config::default_srw_value() : tests::server_config::default_value());

	std::set<int> unique_groups;

	for (rapidjson::SizeType i = 0; i < servers.Size(); ++i) {
		const rapidjson::Value &server = servers[i];

		tests::config_data config;

		if (server.HasMember("group")) {
			const auto &group = server["group"];
			if (group.IsInt())
				unique_groups.insert(group.GetInt());
		}

		for (auto it = server.MemberBegin(); it != server.MemberEnd(); ++it) {
			const std::string name(it->name.GetString(), it->name.GetStringLength());
			const rapidjson::Value &value = it->value;

			if (value.IsUint64()) {
				config(name, value.GetUint64());
			} else if (value.IsString()) {
				config(name, std::string(value.GetString(), value.GetStringLength()));
			} else {
				std::cerr << "Field \"servers[" << i << "]." << name << "\" has unknown type" << std::endl;
				return 1;
			}
		}

		configs[i].apply_options(config);
		configs[i].log_path = "/dev/stderr";
	}

	try {
		global_data = tests::start_nodes(std::cerr, configs, std::string(path.GetString(), path.GetStringLength()));
	} catch (std::exception &err) {
		std::cerr << "Error during startup: " << err.what() << std::endl;
		return 1;
	}

#ifdef HAVE_COCAINE
	if (srw) {
		const std::vector<int> groups(unique_groups.begin(), unique_groups.end());

		try {
			tests::upload_application(global_data->locator_port, global_data->directory.path());
		} catch (std::exception &exc) {
			std::cerr << "Can not upload application: " << exc.what() << std::endl;
			global_data.reset();
			return 1;
		}
		try {
			session sess(*global_data->node);
			sess.set_groups(groups);
			tests::start_application(sess, tests::application_name());
		} catch (std::exception &exc) {
			std::cerr << "Can not start application: " << exc.what() << std::endl;
			global_data.reset();
			return 1;
		}
		try {
			session sess(*global_data->node);
			sess.set_groups(groups);
			tests::init_application_impl(sess, tests::application_name(), *global_data);
		} catch (std::exception &exc) {
			std::cerr << "Can not init application: " << exc.what() << std::endl;
			global_data.reset();
			return 1;
		}
	}
#endif

	{
		rapidjson::Document info;
		info.SetObject();

		rapidjson::Value servers;
		servers.SetArray();
		for (auto it = global_data->nodes.begin(); it != global_data->nodes.end(); ++it) {
			const tests::server_node &node = *it;

			rapidjson::Value server;
			server.SetObject();

			server.AddMember("remote", node.remote().c_str(), info.GetAllocator());
			server.AddMember("monitor", node.monitor_port(), info.GetAllocator());

			rapidjson::Value remote(node.remote().c_str(), node.remote().size(), info.GetAllocator());
			servers.PushBack(remote, info.GetAllocator());
		}

		info.AddMember("servers", servers, info.GetAllocator());

		rapidjson::StringBuffer buffer;
		rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
		info.Accept(writer);

		std::cout << buffer.GetString() << std::endl;
	}

	setup_signals();

	while (global_data)
		sleep(1);

	return 0;
}

int main(int, char *[])
{
	rapidjson::FileStream stream(stdin);
	rapidjson::Document doc;
	doc.ParseStream<0>(stream);

	if (doc.HasParseError()) {
		std::cerr << "Parse error: " << doc.GetParseError() << std::endl;
		return 1;
	}

	if (!doc.IsObject()) {
		std::cerr << "Root must be an object" << std::endl;
		return 1;
	}

	return run_servers(doc);
}

