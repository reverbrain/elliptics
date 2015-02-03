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
#include <fstream>

#include <boost/program_options.hpp>
#include <boost/asio.hpp>

#include "rapidjson/document.h"
#include "rapidjson/filestream.h"
#include "rapidjson/writer.h"
#include "rapidjson/stringbuffer.h"

#include <sys/wait.h>
#include <sys/types.h>

using namespace ioremap::elliptics;

/*
 * 1. Remotes list as json to stdout
 * 2. Ability to write logs to stderr
 * 3. Stop on SIGTERM/SIGINT
 */

static std::shared_ptr<tests::nodes_data> global_data;
static int result_status = 0;
static std::ofstream logs_out;

struct special_log_struct_next
{
};

struct special_log_struct
{
};

namespace test {
static const special_log_struct log = {};

struct special_endl
{
} static endl;
}

special_log_struct_next &operator <<(special_log_struct_next &out, test::special_endl &)
{
	std::cerr << std::endl;
	logs_out << std::endl;
	return out;
}

template <typename T>
special_log_struct_next &operator <<(special_log_struct_next &out, const T &value)
{
	std::cerr << value;
	logs_out << value;

	return out;
}

template <typename T>
special_log_struct_next &operator <<(const special_log_struct &, const T &value)
{
	char str[64];
	char time_str[64];
	struct tm tm;
	struct timeval tv;

	static special_log_struct_next out;

	gettimeofday(&tv, NULL);
	localtime_r((time_t *)&tv.tv_sec, &tm);
	strftime(str, sizeof(str), "%F %R:%S", &tm);

	snprintf(time_str, sizeof(time_str), "%s.%06lu ", str, tv.tv_usec);

	out << time_str << value;
	return out;
}

static void stop_servers(int sig, siginfo_t *info, void *)
{
	if (sig == SIGCHLD) {
		auto &out = (test::log << "Caught signal: " << sig << ", pid: " << info->si_pid
			<< ", status: " << info->si_status << ", code: " << info->si_code << ", description: \"");
		switch (info->si_code) {
			case CLD_EXITED:
				out << "Child has exited";
				break;
			case CLD_KILLED:
				out << "Child has terminated abnormally and did not create a core file";
				break;
			case CLD_DUMPED:
				out << "Child has terminated abnormally and created a core file";
				break;
			case CLD_TRAPPED:
				out << "Traced child has trapped";
				break;
			case CLD_STOPPED:
				out << "Child has stopped";
				break;
			case CLD_CONTINUED:
				out << "Stopped child has continued";
				break;
			default:
				out << "Unknown happened";
				break;
		}
		out << "\"" << test::endl;
	} else {
		test::log << "Caught signal: " << sig << ", err: " << info->si_errno << ", pid: " << info->si_pid << ", status: " << info->si_status << test::endl;
	}

	std::shared_ptr<tests::nodes_data> data;
	std::swap(global_data, data);

	if (data && sig == SIGCHLD)
		result_status = 1;
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
	sigaction(SIGCHLD, &sa, NULL);

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

template<typename T>
void read_option(const rapidjson::Value &doc, const std::string &value, T default_value, T& result);

template<>
void read_option(const rapidjson::Value &doc, const std::string &value, bool default_value, bool& result)
{
	if (doc.HasMember(value.c_str())) {
		if (!doc[value.c_str()].IsBool()) {
			throw std::runtime_error("Field \"" + value + "\" must be boolean");
		}
		result = doc[value.c_str()].GetBool();
		return;
	}
	result = default_value;
}

template<>
void read_option(const rapidjson::Value &doc, const std::string &value, int64_t default_value, int64_t& result)
{
	if (doc.HasMember(value.c_str())) {
		if (!doc[value.c_str()].IsInt64()) {
			throw std::runtime_error("Field \"" + value + "\" must be int64_t");
		}
		result = doc[value.c_str()].GetInt64();
		return;
	}
	result = default_value;
}

static int fill_config(tests::config_data &config, std::vector<tests::config_data> &backends, std::string &prefix, const rapidjson::Value &options, bool is_server)
{
	for (auto it = options.MemberBegin(); it != options.MemberEnd(); ++it) {
		const std::string name(it->name.GetString(), it->name.GetStringLength());
		const rapidjson::Value &value = it->value;

		if (is_server && name == "backends") {
			backends.resize(value.Size(), backends.front());

			for (size_t i = 0; i < value.Size(); ++i) {
				size_t prefix_size = prefix.size();
				prefix += ".backends[" + boost::lexical_cast<std::string>(i) + "]";
				int err = fill_config(backends[i], backends, prefix, value[i], false);
				prefix.resize(prefix_size);
				if (err)
					return err;
			}
		} else if (value.IsInt64()) {
			config(name, value.GetInt64());
		} else if (value.IsString()) {
			config(name, std::string(value.GetString(), value.GetStringLength()));
		} else {
			test::log << "Field \"" << prefix << "." << name << "\" has unknown type" << test::endl;
			return 1;
		}
	}

	return 0;
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
	bool srw, fork, monitor, isolated;
	read_option(doc, "srw", false, srw);
	read_option(doc, "fork", false, fork);
	read_option(doc, "monitor", true, monitor);
	read_option(doc, "isolated", false, isolated);

	int64_t top_k, top_events_limit, top_period;
	read_option<int64_t>(doc, "top_k", 50, top_k);
	read_option<int64_t>(doc, "top_events_limit", 1000, top_events_limit);
	read_option<int64_t>(doc, "top_period", 300, top_period);

	if (!doc.HasMember("path")) {
		std::cerr << "Field \"path\" is missed" << std::endl;
		return 1;
	}

	const rapidjson::Value &path = doc["path"];

	if (!path.IsString()) {
		std::cerr << "Field \"path\" must be string" << std::endl;
		return 1;
	}

	const std::string logs_out_path = std::string(path.GetString()) + "/run_servers.log";
	logs_out.open(logs_out_path.c_str());
	if (!logs_out) {
		std::cerr << "Failed to open \"" << logs_out_path << "\" for writing" << std::endl;
		return 1;
	}

#ifndef HAVE_COCAINE
	if (srw) {
		test::log << "There is no srw support" << test::endl;
		return 1;
	}
#endif

	if (!doc.HasMember("servers")) {
		test::log << "Field \"servers\" is missed" << test::endl;
		return 1;
	}

	const rapidjson::Value &servers = doc["servers"];
	if (!servers.IsArray()) {
		test::log << "Field \"servers\" must be an array" << test::endl;
		return 1;
	}

	std::vector<tests::server_config> configs;
	configs.resize(servers.Size(), srw ? tests::server_config::default_srw_value() : tests::server_config::default_value());

	std::set<int> unique_groups;

	for (rapidjson::SizeType i = 0; i < servers.Size(); ++i) {
		const rapidjson::Value &server = servers[i];

		tests::config_data config;

		std::string prefix = "servers[" + boost::lexical_cast<std::string>(i) + "]";
		int err = fill_config(config, configs[i].backends, prefix, server, true);
		if (err)
			return err;

		configs[i].apply_options(config);

		for (size_t j = 0; j < configs[i].backends.size(); ++j) {
			tests::config_data &backend = configs[i].backends[j];

			if (backend.has_value("group"))
				unique_groups.insert(atoi(backend.string_value("group").c_str()));
		}
	}

	try {
		tests::start_nodes_config start_config(std::cerr, std::move(configs), std::string(path.GetString(), path.GetStringLength()));
		start_config.fork = fork;
		start_config.monitor = monitor;
		start_config.isolated = isolated;
		start_config.top_k = top_k;
		start_config.top_events_limit = top_events_limit;
		start_config.top_period = top_period;

		global_data = tests::start_nodes(start_config);
	} catch (std::exception &err) {
		test::log << "Error during startup: " << err.what() << test::endl;
		return 1;
	}

	sleep(2);
#ifdef HAVE_COCAINE
	if (srw) {
		const std::vector<int> groups(unique_groups.begin(), unique_groups.end());

		try {
			tests::upload_application(global_data->locator_port, global_data->directory.path());
		} catch (std::exception &exc) {
			test::log << "Can not upload application: " << exc.what() << test::endl;
			global_data.reset();
			return 1;
		}
		try {
			session sess(*global_data->node);
			sess.set_groups(groups);
			tests::start_application(sess, tests::application_name());
		} catch (std::exception &exc) {
			test::log << "Can not start application: " << exc.what() << test::endl;
			global_data.reset();
			return 1;
		}
		sleep(2);
		try {
			session sess(*global_data->node);
			sess.set_groups(groups);
			tests::init_application_impl(sess, tests::application_name(), *global_data);
		} catch (std::exception &exc) {
			test::log << "Can not init application: " << exc.what() << test::endl;
			global_data.reset();
			return 1;
		}
	}
#endif

	for (size_t i = 0; i < global_data->nodes.size(); ++i) {
		tests::server_node &node = global_data->nodes.at(i);
		test::log << "Started node #" << i << ", addr: " << node.remote().to_string() << ", pid: " << node.pid() << test::endl;
	}

	{
		rapidjson::Document info;
		info.SetObject();

		rapidjson::Value servers;
		servers.SetArray();
		for (auto it = global_data->nodes.begin(); it != global_data->nodes.end(); ++it) {
			const tests::server_node &node = *it;

			rapidjson::Value server;
			server.SetObject();

			rapidjson::Value remote;
			remote.SetString(node.remote().to_string_with_family().c_str(), info.GetAllocator());
			server.AddMember("remote", remote, info.GetAllocator());

			rapidjson::Value monitor_port;
			monitor_port.SetInt(node.monitor_port());
			server.AddMember("monitor", monitor_port, info.GetAllocator());

			servers.PushBack(server, info.GetAllocator());
		}

		info.AddMember("servers", servers, info.GetAllocator());

		rapidjson::StringBuffer buffer;
		rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
		info.Accept(writer);

		std::cout << buffer.GetString() << std::endl;
	}

	setup_signals();

	test::log << "Succesffully started all servers" << test::endl;

	while (global_data)
		sleep(1);

	return result_status;
}

int main(int, char *[])
{
	srand(time(NULL));

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

	try {
		return run_servers(doc);
	} catch (std::exception &exc) {
		test::log << "Failed to start servers: " << exc.what() << test::endl;
		return 1;
	}

	test::log << "Exit with status: " << result_status << test::endl;

	return result_status;
}

