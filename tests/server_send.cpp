/*
 * 2015+ Copyright (c) Evgeniy Polyakov <zbr@ioremap.net>
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

static std::shared_ptr<tests::nodes_data> ssend_servers;

static std::vector<int> ssend_src_groups = {1};
static std::vector<int> ssend_dst_groups = {2, 3};
static size_t ssend_backends = 8;

static std::string print_groups(const std::vector<int> &groups) {
	std::ostringstream ss;
	for (size_t pos = 0; pos < groups.size(); ++pos) {
		ss << groups[pos];
		if (pos != groups.size() - 1)
			ss << ":";
	}

	return ss.str();
}

static tests::server_config ssend_server_config(int group)
{
	// Minimize number of threads
	tests::server_config server = tests::server_config::default_value();
	server.options
		("io_thread_num", 4)
		("nonblocking_io_thread_num", 4)
		("net_thread_num", 1)
		("caches_number", 1)
	;

	server.backends[0]("enable", true)("group", group);
	server.backends.resize(ssend_backends, server.backends.front());

	return server;
}

static void ssend_configure(const std::string &path)
{
	std::vector<tests::server_config> servers;
	for (const auto &g : ssend_src_groups) {
		tests::server_config server = ssend_server_config(g);
		servers.push_back(server);
	}
	for (const auto &g : ssend_dst_groups) {
		tests::server_config server = ssend_server_config(g);
		servers.push_back(server);
	}

	tests::start_nodes_config cfg(results_reporter::get_stream(), std::move(servers), path);
	cfg.fork = true;

	ssend_servers = tests::start_nodes(cfg);
}

static void ssend_test_insert_many_keys_old_ts(session &s, int num, const std::string &id_prefix, const std::string &data_prefix)
{
	s.set_trace_id(rand());
	for (int i = 0; i < num; ++i) {
		std::string id = id_prefix + lexical_cast(i);
		std::string data = data_prefix + lexical_cast(i);

		key k(id);
		s.transform(k);

		dnet_io_attr io;
		memset(&io, 0, sizeof(dnet_io_attr));

		memcpy(io.id, k.raw_id().id, DNET_ID_SIZE);

		dnet_current_time(&io.timestamp);
		io.timestamp.tsec -= 1000;

		ELLIPTICS_REQUIRE(res, s.write_data(io, data));
	}
}

static void ssend_test_insert_many_keys(session &s, int num, const std::string &id_prefix, const std::string &data_prefix)
{
	s.set_trace_id(rand());
	for (int i = 0; i < num; ++i) {
		std::string id = id_prefix + lexical_cast(i);
		std::string data = data_prefix + lexical_cast(i);

		ELLIPTICS_REQUIRE(res, s.write_data(id, data, 0));
	}
}

static void ssend_test_read_many_keys(session &s, int num, const std::string &id_prefix, const std::string &data_prefix)
{
	s.set_trace_id(rand());
	for (int i = 0; i < num; ++i) {
		std::string id = id_prefix + lexical_cast(i);
		std::string data = data_prefix + lexical_cast(i);

		ELLIPTICS_COMPARE_REQUIRE(res, s.read_data(id, 0, 0), data);
	}
}

static void ssend_test_read_many_keys_error(session &s, int num, const std::string &id_prefix, int error)
{
	s.set_trace_id(rand());
	for (int i = 0; i < num; ++i) {
		std::string id = id_prefix + lexical_cast(i);

		ELLIPTICS_REQUIRE_ERROR(res, s.read_data(id, 0, 0), error);
	}
}

static std::vector<dnet_raw_id> ssend_ids(session &s)
{
	std::vector<dnet_raw_id> ret;
	std::set<uint32_t> backends;

	std::vector<int> groups = s.get_groups();
	std::vector<dnet_route_entry> routes = s.get_routes();

	for (auto it = routes.begin(); it != routes.end(); ++it) {
		const dnet_route_entry &entry = *it;
		if (std::find(groups.begin(), groups.end(), entry.group_id) != groups.end()) {
			auto back = backends.find(entry.backend_id);
			if (back == backends.end()) {
				backends.insert(entry.backend_id);
				ret.push_back(entry.id);
			}
		}
	}

	return ret;
}

static void ssend_test_copy(session &s, const std::vector<int> &dst_groups, int num, uint64_t iflags, int status)
{
	auto run_over_single_backend = [] (session &s, const key &id, const std::vector<int> &dst_groups, uint64_t iflags, int status) {
		std::vector<dnet_iterator_range> ranges;
		dnet_iterator_range whole;
		memset(whole.key_begin.id, 0, sizeof(dnet_raw_id));
		memset(whole.key_end.id, 0xff, sizeof(dnet_raw_id));
		ranges.push_back(whole);

		dnet_time time_begin, time_end;
		dnet_empty_time(&time_begin);
		dnet_current_time(&time_end);

		uint64_t ifl = DNET_IFLAGS_KEY_RANGE | DNET_IFLAGS_NO_META | iflags;

		s.set_trace_id(rand());
		auto iter = s.start_copy_iterator(id, ranges, ifl, time_begin, time_end, dst_groups);

		int copied = 0;

		char buffer[2*DNET_ID_SIZE + 1] = {0};

		logger &log = s.get_logger();

		for (auto it = iter.begin(), end = iter.end(); it != end; ++it) {
#if 1
			// we have to explicitly convert all members from dnet_iterator_response
			// since it is packed and there will be alignment issues and
			// following error:
			// error: cannot bind packed field ... to int&
			BH_LOG(log, DNET_LOG_DEBUG,
					"ssend_test: "
					"key: %s, backend: %d, user_flags: %llx, ts: %s (%lld.%09lld), "
					"status: %d (should be: %d), size: %lld, "
					"iterated_keys: %lld/%lld",
				dnet_dump_id_len_raw(it->reply()->key.id, DNET_ID_SIZE, buffer),
				(int)it->command()->backend_id,
				(unsigned long long)it->reply()->user_flags,
				dnet_print_time(&it->reply()->timestamp),
				(unsigned long long)it->reply()->timestamp.tsec, (unsigned long long)it->reply()->timestamp.tnsec,
				(int)it->reply()->status, status, (unsigned long long)it->reply()->size,
				(unsigned long long)it->reply()->iterated_keys, (unsigned long long)it->reply()->total_keys);
#endif

			BOOST_REQUIRE_EQUAL(it->command()->status, 0);
			BOOST_REQUIRE_EQUAL(it->reply()->status, status);

			if (iflags & DNET_IFLAGS_DATA) {
				BOOST_REQUIRE_EQUAL(it->command()->size, sizeof(struct dnet_iterator_response) + it->reply()->size);
			} else {
				BOOST_REQUIRE_EQUAL(it->command()->size, sizeof(struct dnet_iterator_response));
			}

			copied++;
		}

		BH_LOG(log, DNET_LOG_NOTICE, "ssend_test: %s: dst_groups: %s, copied: %d",
				id.to_string(),
				print_groups(dst_groups), copied);

		return copied;
	};

	int copied = 0;
	std::vector<dnet_raw_id> ids = ssend_ids(s);
	for (const auto &id: ids) {
		copied += run_over_single_backend(s, id, dst_groups, iflags, status);
	}

	BOOST_REQUIRE_EQUAL(copied, num);
}

static void ssend_test_server_send(session &s, int num, const std::string &id_prefix, const std::string &data_prefix,
		const std::vector<int> &dst_groups, uint64_t iflags, int status)
{
	logger &log = s.get_logger();

	s.set_trace_id(rand());
	std::vector<std::string> keys;
	for (int i = 0; i < num; ++i) {
		std::string id = id_prefix + lexical_cast(i);
		std::string data = data_prefix + lexical_cast(i);

		ELLIPTICS_REQUIRE(res, s.write_data(id, data, 0));

		keys.push_back(id);
	}

	BH_LOG(log, DNET_LOG_NOTICE, "%s: keys: %d, dst_groups: %s, starting copy",
			__func__, num, print_groups(dst_groups));

	//char buffer[2*DNET_ID_SIZE + 1] = {0};

	int copied = 0;
	auto iter = s.server_send(keys, iflags, dst_groups);
	for (auto it = iter.begin(), iter_end = iter.end(); it != iter_end; ++it) {
		BOOST_REQUIRE_EQUAL(it->command()->status, 0);
		BOOST_REQUIRE_EQUAL(it->reply()->status, status);
#if 0
		// we have to explicitly convert all members from dnet_iterator_response
		// since it is packed and there will be alignment issues and
		// following error:
		// error: cannot bind packed field ... to int&
		BH_LOG(log, DNET_LOG_DEBUG,
				"ssend_test: "
				"key: %s, backend: %d, user_flags: %llx, ts: %lld.%09lld, status: %d, size: %lld, "
				"iterated_keys: %lld/%lld",
			dnet_dump_id_len_raw(it->reply()->key.id, DNET_ID_SIZE, buffer),
			(int)it->command()->backend_id,
			(unsigned long long)it->reply()->user_flags,
			(unsigned long long)it->reply()->timestamp.tsec, (unsigned long long)it->reply()->timestamp.tnsec,
			(int)it->reply()->status, (unsigned long long)it->reply()->size,
			(unsigned long long)it->reply()->iterated_keys, (unsigned long long)it->reply()->total_keys);
#endif

		copied++;
	}

	BH_LOG(log, DNET_LOG_NOTICE, "%s: keys: %d, dst_groups: %s, copied total: %d",
			__func__, num, print_groups(dst_groups), copied);

	BOOST_REQUIRE_EQUAL(copied, num);
}

#if (!DISABLE_LONG_TEST)
static void ssend_test_set_delay(session &s, const std::vector<int> &groups, uint64_t delay) {
	struct backend {
		dnet_addr addr;
		int backend_id;

		bool operator<(const backend &other) const {
			if (auto cmp = dnet_addr_cmp(&addr, &other.addr))
				return cmp < 0;
			return backend_id < other.backend_id;
		}
	};

	std::set<backend> backends;

	for (const auto &route: s.get_routes()) {
		if (std::find(groups.begin(), groups.end(), route.group_id) != groups.end()) {
			backends.insert(backend{route.addr, route.backend_id});
		}
	}

	std::vector<async_backend_control_result> results;
	results.reserve(backends.size());

	for (const auto &backend: backends) {
		results.emplace_back(
			s.set_delay(address(backend.addr), backend.backend_id, delay)
		);
	}

	for (auto &result: results) {
		result.wait();
	}
}
#endif

static bool ssend_register_tests(test_suite *suite, node &n)
{
	std::string id_prefix = "server send id";
	std::string data_prefix = "this is a test data";
	int num = 3000;

	session src(n);
	src.set_groups(ssend_src_groups);
	src.set_timeout(120);

	session src_noexception(n);
	src_noexception.set_groups(ssend_src_groups);
	src_noexception.set_exceptions_policy(session::no_exceptions);
	src_noexception.set_timeout(120);

	uint64_t iflags = DNET_IFLAGS_MOVE | DNET_IFLAGS_DATA;

	// the first stage - write many keys, move them, check that there are no keys
	// in the source groups and that every destination group contains all keys written
	//
	// also test it with DATA flag - client should get not only iterator response
	// per key, but also its data
	ELLIPTICS_TEST_CASE(ssend_test_insert_many_keys, src, num, id_prefix, data_prefix);

	ELLIPTICS_TEST_CASE(ssend_test_copy, src, ssend_dst_groups, num, iflags, 0);
	// use no-exception session, since every read must return error here,
	// with default session this ends up with exception at get/wait/result access time
	ELLIPTICS_TEST_CASE(ssend_test_read_many_keys_error, src_noexception, num, id_prefix, -ENOENT);

	// check every dst group, it must contain all keys originally written into src groups
	for (auto g = ssend_dst_groups.begin(), gend = ssend_dst_groups.end(); g != gend; ++g) {
		ELLIPTICS_TEST_CASE(ssend_test_read_many_keys,
				tests::create_session(n, {*g}, 0, 0), num, id_prefix, data_prefix);
	}

	// the second stage - play with OVERWRITE bit
	//
	//
	// there are no keys in @ssend_src_groups at this point
	// write new data with the same keys as we have moved,
	// but with older timestamp than that already written,
	// so that move with timestamp cas would fail
	data_prefix = "new data prefix";
	ELLIPTICS_TEST_CASE(ssend_test_insert_many_keys_old_ts, src, num, id_prefix, data_prefix);

	// it should actually fail to move any key, since data is different and we
	// do not set OVERWRITE bit, thus reading from source groups should succeed
	// -EBADFD should be returned for cas/timestamp-cas errors
	ELLIPTICS_TEST_CASE(ssend_test_copy, src, ssend_dst_groups, num, iflags, -EBADFD);
	ELLIPTICS_TEST_CASE(ssend_test_read_many_keys, src, num, id_prefix, data_prefix);

	// with OVERWRITE bit move should succeed - there should be no keys in @ssend_src_groups
	// and all keys in @ssend_dst_groups should have been updated
	iflags = DNET_IFLAGS_OVERWRITE | DNET_IFLAGS_MOVE;
	ELLIPTICS_TEST_CASE(ssend_test_copy, src, ssend_dst_groups, num, iflags, 0);
	ELLIPTICS_TEST_CASE(ssend_test_read_many_keys_error, src_noexception, num, id_prefix, -ENOENT);

	for (auto g = ssend_dst_groups.begin(), gend = ssend_dst_groups.end(); g != gend; ++g) {
		ELLIPTICS_TEST_CASE(ssend_test_read_many_keys,
				tests::create_session(n, {*g}, 0, 0), num, id_prefix, data_prefix);
	}


	// the third stage - write many keys, move them using @server_send() method, not iterator,
	// check that there are no keys in the source groups and that every destination group contains all keys written
	id_prefix = "server_send method test";
	data_prefix = "server_send method test data";
	iflags = DNET_IFLAGS_MOVE;
	ELLIPTICS_TEST_CASE(ssend_test_server_send, src, num, id_prefix, data_prefix, ssend_dst_groups, iflags, 0);
	ELLIPTICS_TEST_CASE(ssend_test_read_many_keys_error, src_noexception, num, id_prefix, -ENOENT);
	for (auto g = ssend_dst_groups.begin(), gend = ssend_dst_groups.end(); g != gend; ++g) {
		ELLIPTICS_TEST_CASE(ssend_test_read_many_keys,
				tests::create_session(n, {*g}, 0, 0), num, id_prefix, data_prefix);
	}

	// the fourth stage - check that plain copy iterator doesn't remove data
	iflags = 0;
	id_prefix = "plain iterator test";
	data_prefix = "plain iterator data";
	ELLIPTICS_TEST_CASE(ssend_test_insert_many_keys, src, num, id_prefix, data_prefix);

	ELLIPTICS_TEST_CASE(ssend_test_copy, src, ssend_dst_groups, num, iflags, 0);
	ELLIPTICS_TEST_CASE(ssend_test_read_many_keys, src, num, id_prefix, data_prefix);
	for (auto g = ssend_dst_groups.begin(), gend = ssend_dst_groups.end(); g != gend; ++g) {
		ELLIPTICS_TEST_CASE(ssend_test_read_many_keys,
				tests::create_session(n, {*g}, 0, 0), num, id_prefix, data_prefix);
	}


	/* Check that server_send returns error (-ENXIO) occurred while writing a record.
	 */

	id_prefix = "-ENXIO handling test";
	data_prefix = "-ENXIO handling data";
	iflags = 0;
	ELLIPTICS_TEST_CASE(ssend_test_server_send, src_noexception, 1, id_prefix, data_prefix,
	                    std::vector<int>{1000}, iflags, -ENXIO);

#if (!DISABLE_LONG_TEST)
	/* Check that server_send returns error (-ETIMEDOUT) occurred during writing a record.
	 * This test is disabled because it takes too much time.
	 * TODO: Expedite the completion of the test by setting smaller timeout which require
	 *     the ability to set timeout to write commands which will be sent by dnet_ioserv
	 *     while executing server-send.
	 */
	id_prefix = "-ETIMEDOUT handling test";
	data_prefix = "-ETIMEDOUT handling data";
	iflags = 0;

	std::vector<int> delayed_groups{ssend_dst_groups[0]};
	ELLIPTICS_TEST_CASE(ssend_test_set_delay, src, delayed_groups, 61000);

	ELLIPTICS_TEST_CASE(ssend_test_server_send, src_noexception, 1, id_prefix, data_prefix,
	                    delayed_groups, iflags, -ETIMEDOUT);
#endif

	return true;
}

static void ssend_free_servers()
{
	ssend_servers.reset();
}

static boost::unit_test::test_suite *ssend_setup_tests(int argc, char *argv[])
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

	ssend_configure(path);
	ssend_register_tests(suite, *ssend_servers->node);

	return suite;
}

int main(int argc, char *argv[])
{
	atexit(ssend_free_servers);

	srand(time(0));
	return unit_test_main(ssend_setup_tests, argc, argv);
}
