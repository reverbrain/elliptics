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
		start_nodes_config start_config(results_reporter::get_stream(), std::vector<server_config>({
			server_config::default_srw_value().apply_options(config_data()
				("group", 1)
			)
		}), path);

		global_data = start_nodes(start_config);
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

/*
 * This funky thread is needed to periodically 'ping' network connection to given node,
 * since otherwise 3 timed out transaction in a row will force elliptics client to kill
 * this connection and all subsequent transactions will be timed out prematurely.
 *
 * State is only marked as 'stall' (and eventually will be killed) when it faces timeout transactions.
 * Read transactions will be quickly completed (even with ENOENT error), which resets stall
 * counter of the selected network connection.
 */
class thread_watchdog {
	public:
		session sess;

		thread_watchdog(const session &sess) : sess(sess), need_exit(false) {
			tid = std::thread(std::bind(&thread_watchdog::ping, this));
		}

		~thread_watchdog() {
			need_exit = true;
			tid.join();
		}

	private:
		std::thread tid;
		bool need_exit;

		void ping() {
			while (!need_exit) {
				sess.read_data(std::string("test-key"), 0, 0).wait();
				sleep(1);
			}
		}
};

/**
 * timeout test runs @num exec transactions with random timeouts.
 * Timeouts must be set to less than 30 seconds, since 30 seconds is a magic number:
 * first, because that's the number of seconds cocaine application sleeps in 'noreply' event,
 * second, because cocaine sends heartbeats every 30 seconds (or at least complains that it didn't
 * receive heartbeat after 30 seconds) and kills application.
 *
 * Trying to set 'heartbeat-timeout' in profile to 60 seconds didn't help.
 * See tests/srw_test.hpp file where we actually set 3 different timeouts to 60 seconds,
 * but yet application is killed in 30 seconds.
 *
 * Basic idea behind this test is following: we run multiple exec transactions with random timeouts,
 * and all transactions must be timed out at most in 2 seconds after timeout expired. These 2 seconds
 * happen because of checker thread which checks timer tree every second and check time (in seconds)
 * must be greater than so called 'death' time.
 *
 * For more details see dnet_trans_iterate_move_transaction() function
 */
static void timeout_test(session &sess, const std::string &app_name)
{
	key key_id = app_name;
	key_id.transform(sess);
	dnet_id id = key_id.id();

	// just a number of test transactions
	int num = 50;

	std::vector<std::pair<int, async_exec_result>> results;
	results.reserve(num);

	sess.set_exceptions_policy(session::no_exceptions);

	thread_watchdog ping(sess);

	for (int i = 0; i < num; ++i) {
		int timeout = rand() % 20 + 1;
		sess.set_timeout(timeout);

		results.emplace_back(std::make_pair(timeout, sess.exec(&id, app_name + "@noreply", "some data")));
	}


	for (auto it = results.begin(); it != results.end(); ++it) {
		auto & res = it->second;

		res.wait();

		auto elapsed = res.elapsed_time();
		auto diff = elapsed.tsec - it->first;

		// 2 is a magic number of seconds, I tried to highlight it in the test description
		unsigned long max_diff = 2;

		if (diff >= max_diff) {
			printf("elapsed: %lld.%lld, timeout: %d, diff: %ld, must be less than %ld, error: %s [%d]\n", 
					(unsigned long long)elapsed.tsec, (unsigned long long)elapsed.tnsec, it->first,
					diff, max_diff,
					res.error().message().c_str(), res.error().code());

			BOOST_REQUIRE_LE(elapsed.tsec - it->first, max_diff);
		}
	}
}

bool register_tests(test_suite *suite, node n)
{
	ELLIPTICS_TEST_CASE(upload_application, global_data->locator_port, global_data->directory.path());
	ELLIPTICS_TEST_CASE(start_application, create_session(n, { 1 }, 0, 0), application_name());
	ELLIPTICS_TEST_CASE(init_application, create_session(n, { 1 }, 0, 0), application_name());
	ELLIPTICS_TEST_CASE(send_echo, create_session(n, { 1 }, 0, 0), application_name(), "some-data");
	ELLIPTICS_TEST_CASE(send_echo, create_session(n, { 1 }, 0, 0), application_name(), "some-data and long-data.. like this");
	ELLIPTICS_TEST_CASE(timeout_test, create_session(n, { 1 }, 0, 0), application_name());

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
