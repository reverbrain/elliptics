/*
 * 2008+ Copyright (c) Evgeniy Polyakov <zbr@ioremap.net>
 * All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include <sys/time.h>
#include <sys/resource.h>

#include <cerrno>
#include <cstdarg>
#include <cstring>
#include <cassert>

#include <sstream>
#include <fstream>
#include <set>
#include <iostream>

#include <boost/filesystem.hpp>

#define BOOST_TEST_DYN_LINK
#include <boost/test/included/unit_test.hpp>

#include "../../include/elliptics/cppdef.h"
#include "../../example/common.h"

#include <algorithm>

using namespace ioremap::elliptics;
using namespace boost::unit_test;

namespace tests {

#define ELLIPTICS_CHECK_IMPL(R, C, CMD) auto R = (C); \
	R.wait(); \
	{ \
		auto base_message = BOOST_TEST_STRINGIZE(C); \
		std::string message(base_message.begin(), base_message.end()); \
		message += ", err: \""; \
		message += R.error().message(); \
		message += "\""; \
		CMD(!R.error(), message); \
	}

#define ELLIPTICS_CHECK_ERROR_IMPL(R, C, E, CMD) auto R = (C); \
	R.wait(); \
	if (R.error().code() != (E)) { \
		auto base_message = BOOST_TEST_STRINGIZE(C); \
		std::stringstream out; \
		out << std::string(base_message.begin(), base_message.end()) \
			<< ", expected error: " << (E) << ", received: \"" << R.error().message() << "\""; \
		CMD(false, out.str()); \
	}

#define ELLIPTICS_WARN(R, C) ELLIPTICS_CHECK_IMPL(R, (C), BOOST_WARN_MESSAGE)
#define ELLIPTICS_CHECK(R, C) ELLIPTICS_CHECK_IMPL(R, (C), BOOST_CHECK_MESSAGE)
#define ELLIPTICS_REQUIRE(R, C) ELLIPTICS_CHECK_IMPL(R, (C), BOOST_REQUIRE_MESSAGE)

#define ELLIPTICS_WARN_ERROR(R, C, E) ELLIPTICS_CHECK_ERROR_IMPL(R, (C), (E), BOOST_WARN_MESSAGE)
#define ELLIPTICS_CHECK_ERROR(R, C, E) ELLIPTICS_CHECK_ERROR_IMPL(R, (C), (E), BOOST_CHECK_MESSAGE)
#define ELLIPTICS_REQUIRE_ERROR(R, C, E) ELLIPTICS_CHECK_ERROR_IMPL(R, (C), (E), BOOST_REQUIRE_MESSAGE)

#define ELLIPTICS_TEST_CASE(M, C...) do { framework::master_test_suite().add(BOOST_TEST_CASE(std::bind( M, ##C ))); } while (false)

session create_session(node n, std::initializer_list<int> groups, uint64_t cflags, uint32_t ioflags)
{
	session sess(n);

	sess.set_groups(std::vector<int>(groups));
	sess.set_cflags(cflags);
	sess.set_ioflags(ioflags);

	sess.set_exceptions_policy(session::no_exceptions);

	return sess;
}

class directory_handler
{
public:
	directory_handler()
	{
	}

	directory_handler(const std::string &path) : m_path(path)
	{
	}

	directory_handler(directory_handler &&other) : m_path(other.m_path)
	{
		other.m_path.clear();
	}

	directory_handler &operator= (directory_handler &&other)
	{
		std::swap(m_path, other.m_path);

		return *this;
	}

	~directory_handler()
	{
		if (!m_path.empty())
			boost::filesystem::remove_all(m_path);
	}

	directory_handler(const directory_handler &) = delete;
	directory_handler &operator =(const directory_handler &) = delete;

private:
	std::string m_path;
};

void create_directory(const std::string &path)
{
	// Boost throws exception on fail
	boost::filesystem::create_directory(path);
}

enum dummy_value_type { DUMMY_VALUE };

class config_data
{
public:
	config_data()
	{
	}

	config_data &operator() (const std::string &name, const std::string &value)
	{
		for (auto it = m_data.begin(); it != m_data.end(); ++it) {
			if (it->first == name) {
				it->second = value;
				return *this;
			}
		}

		m_data.emplace_back(name, value);

		return *this;
	}

	config_data &operator() (const std::string &name, int value)
	{
		return (*this)(name, boost::lexical_cast<std::string>(value));
	}

	config_data &operator() (const std::string &name, dummy_value_type)
	{
		return (*this)(name, "dummy-value");
	}

protected:
	std::vector<std::pair<std::string, std::string> >  m_data;
};

class config_data_writer : public config_data
{
public:
	config_data_writer() = delete;
	config_data_writer &operator =(const config_data_writer &other) = delete;

	config_data_writer(const config_data_writer &other)
		: config_data(other), m_path(other.m_path)
	{
	}
	config_data_writer(const config_data &other, const std::string &path)
		: config_data(other), m_path(path)
	{
	}

	~config_data_writer()
	{
		write();
	}

	template <typename T>
	config_data_writer &operator() (const std::string &name, const T &value)
	{
		config_data::operator ()(name, value);

		return *this;
	}

	dnet_node *run()
	{
		dnet_node *node = dnet_parse_config(m_path.c_str(), 0);
		if (!node)
			throw std::runtime_error("Can not start server with config file: \"" + m_path + "\"");

		return node;
	}

	void write()
	{
		std::ofstream out;
		out.open(m_path.c_str());

		if (!out) {
			throw std::runtime_error("Can not open file \"" + m_path + "\" for writing");
		}

		for (auto it = m_data.begin(); it != m_data.end(); ++it) {
			if (it->second == "dummy-value")
				throw std::runtime_error("Unset value for key \"" + it->first + "\", file: \"" + m_path + "\"");

			out << it->first << " = " << it->second << std::endl;
		}

		out.flush();
		out.close();
	}
private:

	std::string m_path;
};

class server_node
{
public:
	server_node() : m_node(NULL)
	{
	}

	server_node(const std::string &path) : m_node(NULL), m_path(path)
	{
	}

	server_node(server_node &&other) : m_node(other.m_node), m_path(other.m_path)
	{
		other.m_node = NULL;
		other.m_path.clear();
	}

	server_node &operator =(server_node &&other)
	{
		std::swap(m_node, other.m_node);
		std::swap(m_path, other.m_path);

		return *this;
	}

	server_node(const server_node &other) = delete;
	server_node &operator =(const server_node &other) = delete;

	~server_node()
	{
		if (m_node)
			stop();
	}

	void start()
	{
		if (m_node)
			throw std::runtime_error("Server node \"" + m_path + "\" is already started");

		m_node = dnet_parse_config(m_path.c_str(), 0);
		if (!m_node)
			throw std::runtime_error("Can not start server with config file: \"" + m_path + "\"");
	}

	void stop()
	{
		if (!m_node)
			throw std::runtime_error("Server node \"" + m_path + "\" is already stoped");

		dnet_set_need_exit(m_node);
		while (!dnet_need_exit(m_node))
			sleep(1);

		dnet_server_node_destroy(m_node);
		m_node = NULL;
	}

private:
	dnet_node *m_node;
	std::string m_path;
};

struct tests_data
{
	~tests_data()
	{
		nodes.clear();
	}

	std::vector<server_node> nodes;
	directory_handler directory;
};

static std::shared_ptr<tests_data> global_data;

static config_data_writer create_config(config_data base_config, const std::string &path)
{
	return config_data_writer(base_config, path);
}

static void configure_server_nodes()
{
	std::string base_path;
	std::string auth_cookie;

	{
		char buffer[1024];

		snprintf(buffer, sizeof(buffer), "/tmp/elliptics-test-%04x/", rand());
		buffer[sizeof(buffer) - 1] = 0;
		base_path = buffer;

		snprintf(buffer, sizeof(buffer), "%04x%04x", rand(), rand());
		buffer[sizeof(buffer) - 1] = 0;
		auth_cookie = buffer;
	}

	create_directory(base_path);

	directory_handler guard(base_path);

	results_reporter::get_stream() << "Set base directory: \"" << base_path << "\"" << std::endl;
	results_reporter::get_stream() << "Starting up servers" << std::endl;

	const std::string first_server_path = base_path + "/server-1";
	const std::string second_server_path = base_path + "/server-2";

	create_directory(first_server_path);
	create_directory(first_server_path + "/blob");
	create_directory(first_server_path + "/history");
	create_directory(second_server_path);
	create_directory(second_server_path + "/blob");
	create_directory(second_server_path + "/history");

	config_data ioserv_config;

	ioserv_config("log", "/dev/stderr")
			("log_level", DNET_LOG_DEBUG)
			("join", 1)
			("flags", 4)
			("group", DUMMY_VALUE)
			("addr", DUMMY_VALUE)
			("remote", DUMMY_VALUE)
			("wait_timeout", 60)
			("check_timeout", 60)
			("io_thread_num", 50)
			("nonblocking_io_thread_num", 16)
			("net_thread_num", 16)
			("history", DUMMY_VALUE)
			("daemon", 0)
			("auth_cookie", auth_cookie)
			("bg_ionice_class", 3)
			("bg_ionice_prio", 0)
			("server_net_prio", 1)
			("client_net_prio", 6)
			("cache_size", 1024 * 1024 * 256)
			("backend", "blob")
			("sync", 5)
			("data", DUMMY_VALUE)
			("data_block_size", 1024)
			("blob_flags", 6)
			("iterate_thread_num", 1)
			("blob_size", "10M")
			("records_in_blob", 10000000)
			("defrag_timeout", 3600)
			("defrag_percentage", 25)
			;

	create_config(ioserv_config, first_server_path + "/ioserv.conf")
			("log", first_server_path + "/log.log")
			("group", 1)
			("addr", "localhost:1025:2")
			("remote", "localhost:1026:2")
			("history", first_server_path + "/history")
			("data", first_server_path + "/blob/data")
			;

	server_node first_server(first_server_path + "/ioserv.conf");

	first_server.start();
	results_reporter::get_stream() << "First server started" << std::endl;

	create_config(ioserv_config, second_server_path + "/ioserv.conf")
			("log", second_server_path + "/log.log")
			("group", 2)
			("addr", "localhost:1026:2")
			("remote", "localhost:1025:2")
			("history", second_server_path + "/history")
			("data", second_server_path + "/blob/data")
			;

	server_node second_server(second_server_path + "/ioserv.conf");

	second_server.start();
	results_reporter::get_stream() << "Second server started" << std::endl;

	global_data = std::make_shared<tests_data>();

	global_data->directory = std::move(guard);
	global_data->nodes.emplace_back(std::move(first_server));
	global_data->nodes.emplace_back(std::move(second_server));
}

static void test_write(session &sess, const std::string &id, const std::string &data)
{
	ELLIPTICS_REQUIRE(write_result, sess.write_data(id, data, 0));
	ELLIPTICS_REQUIRE(read_result, sess.read_data(id, 0, 0));
	read_result_entry result = read_result.get_one();

	BOOST_REQUIRE_EQUAL(result.file().to_string(), data);
}

static void test_recovery(session &sess, const std::string &id, const std::string &data)
{
	std::vector<int> groups = sess.get_groups();
	std::vector<int> valid_groups(1, groups.back());

	sess.set_groups(valid_groups);

	ELLIPTICS_REQUIRE(write_result, sess.write_data(id, data, 0));
	ELLIPTICS_REQUIRE(recovery_read_result, sess.read_data(id, groups, 0, 0));

	for (size_t i = 0; i < groups.size(); ++i) {
		std::vector<int> current_groups(1, groups[i]);
		ELLIPTICS_CHECK(read_result, sess.read_data(id, current_groups, 0, 0));
		read_result_entry result = read_result.get_one();
		if (result.is_valid()) {
			BOOST_CHECK_EQUAL(result.file().to_string(), data);
			BOOST_CHECK_EQUAL(result.command()->id.group_id, groups[i]);
		}
	}
}

static void test_indexes(session &sess)
{
	std::vector<std::string> indexes = {
		"fast",
		"elliptics",
		"distributive",
		"reliable",
		"falt-tolerante"
	};

	std::vector<data_pointer> data(indexes.size());

	std::string key = "elliptics";

	ELLIPTICS_REQUIRE(clear_indexes_result, sess.set_indexes(key, std::vector<std::string>(), std::vector<data_pointer>()));
	ELLIPTICS_REQUIRE(set_indexes_result, sess.set_indexes(key, indexes, data));

	ELLIPTICS_REQUIRE(all_indexes_result, sess.find_all_indexes(indexes));
	sync_find_indexes_result all_result = all_indexes_result.get();

	ELLIPTICS_REQUIRE(any_indexes_result, sess.find_any_indexes(indexes));
	sync_find_indexes_result any_result = any_indexes_result.get();

	BOOST_CHECK_EQUAL(all_result.size(), any_result.size());
	BOOST_CHECK_EQUAL(all_result.size(), 1);
	BOOST_CHECK_EQUAL(all_result[0].indexes.size(), any_result[0].indexes.size());
	BOOST_CHECK_EQUAL(all_result[0].indexes.size(), indexes.size());
}

static void test_more_indexes(session &sess)
{
	std::vector<std::string> indexes;
	for (size_t i = 0; i < 16; ++i) {
		indexes.push_back("index-" + boost::lexical_cast<std::string>(i));
	}

	std::vector<data_pointer> data(indexes.size());

	std::vector<std::string> keys;
	for (size_t i = 0; i < 256; ++i) {
		keys.push_back("key-" + boost::lexical_cast<std::string>(i));
	}

	for (auto it = keys.begin(); it != keys.end(); ++it) {
		std::string key = *it;
		ELLIPTICS_REQUIRE(clear_indexes_result, sess.set_indexes(key, std::vector<std::string>(), std::vector<data_pointer>()));
		ELLIPTICS_REQUIRE(set_indexes_result, sess.set_indexes(key, indexes, data));
	}

	ELLIPTICS_REQUIRE(all_indexes_result, sess.find_all_indexes(indexes));
	sync_find_indexes_result all_result = all_indexes_result.get();

	ELLIPTICS_REQUIRE(any_indexes_result, sess.find_any_indexes(indexes));
	sync_find_indexes_result any_result = any_indexes_result.get();

	BOOST_CHECK_EQUAL(all_result.size(), any_result.size());
	BOOST_CHECK_EQUAL(all_result.size(), 256);
	BOOST_CHECK_EQUAL(all_result[0].indexes.size(), any_result[0].indexes.size());
	BOOST_CHECK_EQUAL(all_result[0].indexes.size(), indexes.size());
}

static void test_error(session &s, const std::string &id, int err)
{
	ELLIPTICS_REQUIRE_ERROR(read_result, s.read_data(id, 0, 0), err);
}

static void test_remove(session &s, const std::string &id)
{
	ELLIPTICS_REQUIRE(remove_result, s.remove(id));
	ELLIPTICS_REQUIRE_ERROR(read_result, s.read_data(id, 0, 0), -ENOENT);
}

static void test_cache_write(session &sess, int num)
{
	std::vector<struct dnet_io_attr> ios;
	std::vector<std::string> data;

	for (int i = 0; i < num; ++i) {
		std::ostringstream os;
		struct dnet_io_attr io;
		struct dnet_id id;

		os << "test_cache" << i;

		memset(&io, 0, sizeof(io));
		memset(&id, 0, sizeof(id));

		sess.transform(os.str(), id);
		memcpy(io.id, id.id, DNET_ID_SIZE);
		io.size = os.str().size();
		io.timestamp.tsec = -1;
		io.timestamp.tnsec = -1;

		ios.push_back(io);
		data.push_back(os.str());
	}

	ELLIPTICS_REQUIRE(write_result, sess.bulk_write(ios, data));

	sync_write_result result = write_result.get();

	int count = 0;

	for (auto it = result.begin(); it != result.end(); ++it) {
		count += (it->status() == 0) && (!it->is_ack());
	}

	BOOST_REQUIRE_EQUAL(count, num * 2);
}

static void test_cache_read(session &sess, int num, int percentage)
{
	/* Read random percentage % of records written by test_cache_write() */
	for (int i = 0; i < num; ++i) {
		if ((rand() % 100) > percentage)
			continue;

		std::ostringstream os;
		os << "test_cache" << i;

		key id(os.str());
		id.transform(sess);

		ELLIPTICS_REQUIRE(read_result, sess.read_data(os.str(), 0, 0));
	}
}

static void test_cache_delete(session &sess, int num, int percentage)
{
	/* Remove random percentage % of records written by test_cache_write() */
	for (int i = 0; i < num; ++i) {
		if ((rand() % 100) > percentage)
			continue;

		std::ostringstream os;

		os << "test_cache" << i;

		std::string id(os.str());

		ELLIPTICS_REQUIRE(remove_result, sess.remove(id));
		ELLIPTICS_REQUIRE_ERROR(read_result, sess.read_data(id, 0, 0), -ENOENT);
	}
}

static void test_cas(session &sess)
{
	const std::string key = "cas-test";
	const std::string data1 = "cas data first";
	const std::string data2 = "cas data second";

	ELLIPTICS_REQUIRE(write_result, sess.write_data(key, data1, 0));

	ELLIPTICS_REQUIRE(read_result, sess.read_data(key, 0, 0));

	read_result_entry read_entry = read_result.get_one();

	BOOST_REQUIRE_EQUAL(read_entry.file().to_string(), data1);

	dnet_id csum;
	memset(&csum, 0, sizeof(csum));

	sess.transform(data1, csum);

	BOOST_REQUIRE(memcmp(csum.id, read_entry.io_attribute()->parent, DNET_ID_SIZE) == 0);

	ELLIPTICS_REQUIRE(write_cas_result, sess.write_cas(key, data2, csum, 0));

	ELLIPTICS_REQUIRE(second_read_result, sess.read_data(key, 0, 0));

	read_result_entry second_read_entry = second_read_result.get_one();

	BOOST_REQUIRE_EQUAL(second_read_entry.file().to_string(), data2);
}

static void test_append(session &sess)
{
	const std::string data = "first part of the message";
	const std::string data_append = " | second part of the message";
	const std::string data_append_more = " | third part of the message";
	read_result_entry read_entry;

	// Append
	const std::string key_a = "append-test";
	ELLIPTICS_REQUIRE(write_result1, sess.write_data(key_a, data, 0));

	session sa = sess.clone();
	sa.set_ioflags(sa.get_ioflags() | DNET_IO_FLAGS_APPEND);
	ELLIPTICS_REQUIRE(append_result1, sa.write_data(key_a, data_append, 0));

	ELLIPTICS_REQUIRE(read_result1, sa.read_data(key_a, 0, 0));
	read_entry = read_result1.get_one();
	BOOST_REQUIRE_EQUAL(read_entry.file().to_string(), data + data_append);

	// Append only
	const std::string key_ao = "append-only-test";
	ELLIPTICS_REQUIRE(write_result_ao1, sa.write_data(key_ao, data, 0));
	ELLIPTICS_REQUIRE(write_result_ao2, sa.write_data(key_ao, data_append, 0));
	ELLIPTICS_REQUIRE(write_result_ao3, sa.write_data(key_ao, data_append_more, 0));
	ELLIPTICS_REQUIRE(read_result_ao, sa.read_data(key_ao, 0, 0));
	read_entry = read_result_ao.get_one();
	BOOST_REQUIRE_EQUAL(read_entry.file().to_string(),
			data + data_append + data_append_more);

	// Apend + Prepare
	const std::string key_ap = "append-prepare-test";
	ELLIPTICS_REQUIRE(write_result2, sess.write_data(key_ap, data, 0));

	session sap = sess.clone();
	sap.set_ioflags(sap.get_ioflags() | DNET_IO_FLAGS_APPEND | DNET_IO_FLAGS_PREPARE);
	ELLIPTICS_REQUIRE(append_result2, sap.write_data(key_ap, data_append, 0));

	ELLIPTICS_REQUIRE(read_result2, sap.read_data(key_ap, 0, 0));
	read_entry = read_result2.get_one();
	BOOST_REQUIRE_EQUAL(read_entry.file().to_string(), data + data_append);

	// Multi-Append
	const std::string key_ma = "multi-append-test";
	std::string full;
	for (int i = 0; i < 1000; ++i) {
		std::ostringstream str;
		str << "test_" << i << ", ";
		ELLIPTICS_REQUIRE(append_result_ma, sa.write_data(key_ma, str.str(), 0));

		ELLIPTICS_REQUIRE(read_result_ma, sa.read_data(key_ma, 0, 0));
		full.append(str.str());
		read_entry = read_result_ma.get_one();
		BOOST_REQUIRE_EQUAL(read_entry.file().to_string(), full);
	}
}

static void test_read_write_offsets(session &sess)
{
	const std::string key = "read-write-test";
	const std::string data = "55555";
	const std::string test1 = "43210", cmp1 = "543210", cmp2 = "210", cmp3 = "3";

	// Write data
	ELLIPTICS_REQUIRE(write_result, sess.write_data(key, data, 0));

	// Overwrite partially
	ELLIPTICS_REQUIRE(partial_overwrite_result, sess.write_data(key, test1, 1));

	// Read whole & Check
	ELLIPTICS_REQUIRE(read_result, sess.read_data(key, 0, 0));
	read_result_entry read_entry = read_result.get_one();
	BOOST_REQUIRE_EQUAL(read_entry.file().to_string(), cmp1);

	// Read with offset & Check
	ELLIPTICS_REQUIRE(second_read_result, sess.read_data(key, 3, 0));
	read_result_entry second_read_entry = second_read_result.get_one();
	BOOST_REQUIRE_EQUAL(second_read_entry.file().to_string(), cmp2);

	// Read with offset/size & Check
	ELLIPTICS_REQUIRE(third_read_result, sess.read_data(key, 2, 1));
	read_result_entry third_read_entry = third_read_result.get_one();
	BOOST_REQUIRE_EQUAL(third_read_entry.file().to_string(), cmp3);
}

// Test manual write with commit flag
static void test_commit(session &s)
{
	const std::string key = "commit-test";
	const std::string data = "commit-test-data";

	// Manually construct io control
	struct dnet_io_control ctl;
	memset(&ctl, 0, sizeof(ctl));

	dnet_id raw;
	s.transform(key, raw);
	memcpy(&ctl.id, &raw, sizeof(struct dnet_id));

	ctl.cflags = s.get_cflags();
	ctl.data = data_pointer(data).data();
	ctl.io.flags = DNET_IO_FLAGS_COMMIT;
	ctl.io.user_flags = 0;
	ctl.io.offset = 0;
	ctl.io.size = data.size();
	ctl.io.num = data.size();
	ctl.io.timestamp.tsec = -1;
	ctl.io.timestamp.tnsec = -1;
	ctl.fd = -1;

	// Write
	ELLIPTICS_REQUIRE(write_result, s.write_data(ctl));

	// Read
	ELLIPTICS_REQUIRE(read_result, s.read_data(key, 0, 0));
	read_result_entry read_entry = read_result.get_one();
	BOOST_REQUIRE_EQUAL(read_entry.file().to_string(), data);
}

static void test_prepare_commit(session &sess, const std::string &remote, int psize, int csize)
{
	std::string written;

	std::string prepare_data = "prepare data|";
	std::string commit_data = "commit data";
	std::string plain_data[3] = {"plain data0|", "plain data1|", "plain data2|"};

	if (psize)
		prepare_data.clear();
	if (csize)
		commit_data.clear();

	uint64_t offset = 0;
	uint64_t total_size_to_reserve = 1024;

	ELLIPTICS_REQUIRE(prepare_result, sess.write_prepare(remote, prepare_data, offset, total_size_to_reserve));
	offset += prepare_data.size();

	written += prepare_data;

	for (int i = 0; i < 3; ++i) {
		ELLIPTICS_REQUIRE(plain_result, sess.write_plain(remote, plain_data[i], offset));

		offset += plain_data[i].size();
		written += plain_data[i];
	}

	/* append data first so that subsequent written.size() call returned real size of the written data */
	written += commit_data;

	ELLIPTICS_REQUIRE(commit_result, sess.write_commit(remote, commit_data, offset, written.size()));

	ELLIPTICS_REQUIRE(read_result, sess.read_data(remote, 0, 0));
	read_result_entry read_entry = read_result.get_one();
	BOOST_REQUIRE_EQUAL(read_entry.file().to_string(), written);
}

static void test_bulk_write(session &sess, size_t test_count)
{
	std::vector<struct dnet_io_attr> ios;
	std::vector<std::string> data;

	for (size_t i = 0; i < test_count; ++i) {
		struct dnet_io_attr io;
		struct dnet_id id;

		std::ostringstream os;
		os << "bulk_write" << i;

		memset(&io, 0, sizeof(io));
		memset(&id, 0, sizeof(id));

		sess.transform(os.str(), id);
		memcpy(io.id, id.id, DNET_ID_SIZE);
		io.size = os.str().size();
		io.timestamp.tsec = -1;
		io.timestamp.tnsec = -1;

		ios.push_back(io);
		data.push_back(os.str());
	}

	ELLIPTICS_REQUIRE(write_result, sess.bulk_write(ios, data));

	sync_write_result result = write_result.get();

	int count = 0;

	for (auto it = result.begin(); it != result.end(); ++it) {
		count += (it->status() == 0) && (!it->is_ack());
	}

	BOOST_REQUIRE_EQUAL(count, test_count * 2);

	for (size_t i = 0; i < test_count; ++i) {
		std::ostringstream os;
		os << "bulk_write" << i;

		ELLIPTICS_REQUIRE(read_result, sess.read_data(os.str(), 0, 0));
		read_result_entry read_entry = read_result.get_one();
		BOOST_REQUIRE_EQUAL(read_entry.file().to_string(), data[i]);
	}
}

static void test_bulk_read(session &sess, size_t test_count)
{
	std::vector<std::string> keys;
	std::map<dnet_raw_id, std::string, dnet_raw_id_less_than<>> all_data;

	for (size_t i = 0; i < test_count; ++i) {
		std::ostringstream os;
		os << "bulk_write" << i;
		keys.push_back(os.str());

		key id(os.str());
		id.transform(sess);

		all_data[id.raw_id()] = os.str();
	}

	ELLIPTICS_REQUIRE(read_result, sess.bulk_read(keys));

	sync_read_result result = read_result.get();

	BOOST_REQUIRE_EQUAL(result.size(), keys.size());

	for (auto it = result.begin(); it != result.end(); ++it) {
		key id(it->command()->id);
		std::string data = all_data[id.raw_id()];
		BOOST_REQUIRE_EQUAL(it->file().to_string(), data);
	}
}

static void test_range_request_prepare(session &sess, size_t item_count)
{
	const size_t number_index = 5; // DNET_ID_SIZE - 1

	struct dnet_id begin;
	memset(&begin, 0x13, sizeof(begin));
	begin.group_id = 0;
	begin.id[number_index] = 0;

	for (size_t i = 0; i < item_count; ++i) {
		std::stringstream out;
		out << "range_test_data_" << i;

		dnet_id id = begin;
		id.id[number_index] = i;
		ELLIPTICS_REQUIRE(write_result, sess.write_data(id, out.str(), 0));

		ELLIPTICS_REQUIRE(read_result, sess.read_data(id, 0, 0));
		read_result_entry read_entry = read_result.get_one();
		BOOST_REQUIRE_EQUAL(read_entry.file().to_string(), out.str());
	}
}

static void test_range_request(session &sess, int limit_start, int limit_num, int group_id)
{
	const size_t item_count = 16;
	const size_t number_index = 5; // DNET_ID_SIZE - 1

	// Prepare storage for test
	test_range_request_prepare(sess, item_count);

	struct dnet_id begin;
	memset(&begin, 0x13, sizeof(begin));
	begin.group_id = group_id;
	begin.id[number_index] = 0;

	struct dnet_id end = begin;
	end.id[number_index] = item_count;

	std::vector<std::string> data(item_count);

	for (size_t i = 0; i < data.size(); ++i) {
		std::stringstream out;
		out << "range_test_data_" << i;

		data[i] = out.str();
	}

	struct dnet_io_attr io;
	memset(&io, 0, sizeof(io));
	memcpy(io.id, begin.id, sizeof(io.id));
	memcpy(io.parent, end.id, sizeof(io.id));
	io.start = limit_start;
	io.num = limit_num;

	ELLIPTICS_REQUIRE(read_result_async, sess.read_data_range(io, group_id));
	sync_read_result read_result = read_result_async.get();
	BOOST_REQUIRE_EQUAL(read_result.size(), std::min(limit_num, int(item_count) - limit_start));

	std::vector<std::string> read_result_vector;

	for (size_t i = 0; i < read_result.size(); ++i) {
		read_result_vector.push_back(read_result[i].file().to_string());
	}

	BOOST_REQUIRE_EQUAL_COLLECTIONS(data.begin() + limit_start,
					data.begin() + limit_start + read_result.size(),
					read_result_vector.begin(),
					read_result_vector.end());

	ELLIPTICS_REQUIRE(remote_result_async, sess.remove_data_range(io, group_id));

	sync_read_result remove_result = remote_result_async.get();
	int removed = 0;
	for (size_t i = 0; i < remove_result.size(); ++i)
		removed += remove_result[i].io_attribute()->num;

	BOOST_REQUIRE_EQUAL(removed, int(item_count));

	ELLIPTICS_REQUIRE(remote_result_fail_async, sess.remove_data_range(io, group_id));

	sync_read_result remove_result_fail = remote_result_fail_async.get();
	int removed_fail = 0;
	for (size_t i = 0; i < remove_result_fail.size(); ++i)
		removed_fail += remove_result_fail[i].io_attribute()->num;

	BOOST_REQUIRE_EQUAL(removed_fail, 0);
}

#define ELLIPTICS_COMPARE_REQUIRE(R, C, D) ELLIPTICS_REQUIRE(R, C); \
	do { \
		auto R ## _result = (R).get_one(); \
		BOOST_REQUIRE_EQUAL((R ## _result).file().to_string(), (D)); \
	} while (0)

static void test_cache_and_no(session &sess, const std::string &id)
{
	const std::string first_part = "first part";
	const std::string second_part = " | second part";
	const std::string third_path = " | third part";

	session cache_sess = sess.clone();
	cache_sess.set_ioflags(sess.get_ioflags() | DNET_IO_FLAGS_CACHE | DNET_IO_FLAGS_APPEND);

	ELLIPTICS_REQUIRE(first_write_result, sess.write_data(id, first_part, 0));
	ELLIPTICS_COMPARE_REQUIRE(first_read_result, sess.read_data(id, 0, 0), first_part);

	ELLIPTICS_REQUIRE(second_write_result, cache_sess.write_data(id, second_part, 0));
	ELLIPTICS_COMPARE_REQUIRE(second_read_result, cache_sess.read_data(id, 0, 0), first_part + second_part);

	sess.set_ioflags(sess.get_ioflags() | DNET_IO_FLAGS_APPEND);

	ELLIPTICS_REQUIRE(third_write_result, sess.write_data(id, third_path, 0));
	ELLIPTICS_COMPARE_REQUIRE(third_read_result, sess.read_data(id, 0, 0), first_part + second_part + third_path);
	ELLIPTICS_COMPARE_REQUIRE(third_cache_read_result, cache_sess.read_data(id, 0, 0), first_part + second_part + third_path);
}

static void test_cache_populating(session &sess, const std::string &id, const std::string &data)
{
	session cache_sess = sess.clone();
	cache_sess.set_ioflags(sess.get_ioflags() | DNET_IO_FLAGS_CACHE);

	session cache_only_sess = sess.clone();
	cache_only_sess.set_ioflags(sess.get_ioflags() | DNET_IO_FLAGS_CACHE | DNET_IO_FLAGS_CACHE_ONLY);

	ELLIPTICS_REQUIRE(write_result, sess.write_data(id, data, 0));
	ELLIPTICS_COMPARE_REQUIRE(read_result, sess.read_data(id, 0, 0), data);

	ELLIPTICS_REQUIRE_ERROR(read_cache_only_result, cache_only_sess.read_data(id, 0, 0), -ENOENT);
	ELLIPTICS_COMPARE_REQUIRE(read_cache_result, cache_sess.read_data(id, 0, 0), data);
	ELLIPTICS_COMPARE_REQUIRE(read_cache_only_populated_result, cache_only_sess.read_data(id, 0, 0), data);
}

static void test_metadata(session &sess, const std::string &id, const std::string &data)
{
	const uint64_t unique_flags = rand();

	session cache_sess = sess.clone();
	cache_sess.set_ioflags(sess.get_ioflags() | DNET_IO_FLAGS_CACHE);

	session cache_only_sess = sess.clone();
	cache_only_sess.set_ioflags(sess.get_ioflags() | DNET_IO_FLAGS_CACHE | DNET_IO_FLAGS_CACHE_ONLY);

	sess.set_user_flags(unique_flags);

	ELLIPTICS_REQUIRE(write_result, sess.write_data(id, data, 0));

	ELLIPTICS_COMPARE_REQUIRE(read_result, sess.read_data(id, 0, 0), data);
	read_result_entry read_entry = read_result.get_one();
	BOOST_REQUIRE_EQUAL(read_entry.io_attribute()->user_flags, unique_flags);

	ELLIPTICS_COMPARE_REQUIRE(read_cache_result, cache_sess.read_data(id, 0, 0), data);
	read_entry = read_cache_result.get_one();
	BOOST_REQUIRE_EQUAL(read_entry.io_attribute()->user_flags, unique_flags);

	ELLIPTICS_COMPARE_REQUIRE(read_cache_only_result, cache_only_sess.read_data(id, 0, 0), data);
	read_entry = read_cache_only_result.get_one();
	BOOST_REQUIRE_EQUAL(read_entry.io_attribute()->user_flags, unique_flags);
}

static void test_partial_bulk_read(session &sess)
{
	const std::string first_key = "first-bulk-partial-key";
	const std::string second_key = "second-bulk-partial-key";
	const std::string first_data = "first-data";

	ELLIPTICS_REQUIRE(write_result, sess.write_data(first_key, first_data, 0));
	ELLIPTICS_COMPARE_REQUIRE(read_firt_result, sess.read_data(first_key, 0, 0), first_data);
	ELLIPTICS_REQUIRE_ERROR(read_second_result, sess.read_data(second_key, 0, 0), -ENOENT);

	ELLIPTICS_CHECK(bulk_result, sess.bulk_read(std::vector<std::string>({ first_key, second_key })));
	auto bulk_entries = bulk_result.get();
	BOOST_REQUIRE_EQUAL(bulk_entries.size(), 1);
	BOOST_REQUIRE_EQUAL(bulk_entries[0].file().to_string(), first_data);
}

static void test_indexes_update(session &sess)
{
	data_pointer first_data = data_pointer::copy("1", 1);
	data_pointer second_data = data_pointer::copy("22", 2);
//	data_pointer third_data = data_pointer::copy("333", 3);

	std::map<key, std::string> mapper;

	std::vector<std::string> first_indexes = {
		"index_1",
		"index_2",
		"index_3"
	};

	std::vector<std::string> second_indexes = {
		"index_3",
		"index_4",
		"index_5"
	};

	std::vector<std::string> all_indexes = {
		"index_1",
		"index_2",
		"index_3",
		"index_4",
		"index_5"
	};

	std::vector<std::string> third_indexes = {
		"index_4",
		"index_5"
	};

	std::vector<std::string> fourth_indexes = {
		"index_4"
	};

	std::vector<std::string> anti_fourth_indexes = {
		"index_1",
		"index_2",
		"index_3",
		"index_5"
	};

	std::string fifth_index = "index_5";

	for (auto it = all_indexes.begin(); it != all_indexes.end(); ++it) {
		key tmp_key(*it);
		tmp_key.transform(sess);
		mapper[tmp_key.id()] = *it;
	}

	std::vector<data_pointer> data(first_indexes.size(), first_data);

	std::string first_key = "indexes_update";

	ELLIPTICS_REQUIRE(set_indexes_result, sess.set_indexes(first_key, first_indexes, data));
	ELLIPTICS_REQUIRE(first_find_result, sess.find_any_indexes(all_indexes));

	sync_find_indexes_result first_sync_find_result = first_find_result.get();

	BOOST_REQUIRE_EQUAL(first_sync_find_result.size(), 1);
	BOOST_REQUIRE_EQUAL(first_sync_find_result[0].indexes.size(), 3);

	data.assign(second_indexes.size(), second_data);

	ELLIPTICS_REQUIRE(update_indexes_result, sess.update_indexes(first_key, second_indexes, data));
	ELLIPTICS_REQUIRE(second_find_result, sess.find_any_indexes(all_indexes));

	sync_find_indexes_result second_sync_find_result = second_find_result.get();

	BOOST_REQUIRE_EQUAL(second_sync_find_result.size(), 1);
	BOOST_REQUIRE_EQUAL(second_sync_find_result[0].indexes.size(), 5);

	for (auto it = second_sync_find_result[0].indexes.begin();
		it != second_sync_find_result[0].indexes.end();
		++it) {
		const index_entry &entry = *it;

		std::string id = mapper[entry.index];
		auto first_it = std::find(first_indexes.begin(), first_indexes.end(), id);
		auto second_it = std::find(second_indexes.begin(), second_indexes.end(), id);

		BOOST_REQUIRE((first_it != first_indexes.end()) || (second_it != second_indexes.end()));

		if (second_it != second_indexes.end())
			BOOST_REQUIRE_EQUAL(entry.data.to_string(), second_data.to_string());
		else
			BOOST_REQUIRE_EQUAL(entry.data.to_string(), first_data.to_string());
	}

	ELLIPTICS_REQUIRE(remove_indexes_result, sess.remove_indexes(first_key, first_indexes));
	ELLIPTICS_REQUIRE(third_find_result, sess.find_any_indexes(all_indexes));

	sync_find_indexes_result third_sync_find_result = third_find_result.get();

	BOOST_REQUIRE_EQUAL(third_sync_find_result.size(), 1);
	BOOST_REQUIRE_EQUAL(third_sync_find_result[0].indexes.size(), 2);

	for (auto it = third_sync_find_result[0].indexes.begin();
		it != third_sync_find_result[0].indexes.end();
		++it) {
		const index_entry &entry = *it;

		std::string id = mapper[entry.index];
		auto first_it = std::find(first_indexes.begin(), first_indexes.end(), id);
		auto third_it = std::find(third_indexes.begin(), third_indexes.end(), id);

		BOOST_REQUIRE((first_it == first_indexes.end()) || (third_it != third_indexes.end()));
		BOOST_REQUIRE_EQUAL(entry.data.to_string(), second_data.to_string());
	}

	ELLIPTICS_REQUIRE(remove_index_result, sess.remove_index_internal(fifth_index));
	ELLIPTICS_REQUIRE(fourth_find_result, sess.find_any_indexes(all_indexes));

	sync_find_indexes_result fourth_sync_find_result = fourth_find_result.get();

	BOOST_REQUIRE_EQUAL(fourth_sync_find_result.size(), 1);
	BOOST_REQUIRE_EQUAL(fourth_sync_find_result[0].indexes.size(), 1);

	for (auto it = fourth_sync_find_result[0].indexes.begin();
		it != fourth_sync_find_result[0].indexes.end();
		++it) {
		const index_entry &entry = *it;

		std::string id = mapper[entry.index];
		auto fourth_it = std::find(fourth_indexes.begin(), fourth_indexes.end(), id);
		auto anti_fourth_it = std::find(anti_fourth_indexes.begin(), anti_fourth_indexes.end(), id);

		BOOST_REQUIRE((fourth_it != first_indexes.end()) || (anti_fourth_it != anti_fourth_indexes.end()));
		BOOST_REQUIRE_EQUAL(entry.data.to_string(), second_data.to_string());
	}
}

static void test_lookup(session &sess, const std::string &id, const std::string &data)
{
	dnet_io_attr io;
	memset(&io, 0, sizeof(io));
	dnet_current_time(&io.timestamp);

	key kid(id);
	kid.transform(sess);
	memcpy(io.id, kid.raw_id().id, DNET_ID_SIZE);

	ELLIPTICS_REQUIRE(write_result, sess.write_data(io, data));
	ELLIPTICS_REQUIRE(read_result, sess.read_data(kid, 0, 0));
	ELLIPTICS_REQUIRE(lookup_result, sess.lookup(kid));
	dnet_time new_time = lookup_result.get_one().file_info()->mtime;
	BOOST_REQUIRE_EQUAL(new_time.tsec, io.timestamp.tsec);
	BOOST_REQUIRE_EQUAL(new_time.tnsec, io.timestamp.tnsec);
}

static void test_prepare_latest(session &sess, const std::string &id)
{
	const std::string first_data = "first-data";
	const std::string second_data = "second-data";

	dnet_raw_id raw_id;
	sess.transform(id, raw_id);

	session first_sess = sess.clone();
	first_sess.set_groups(std::vector<int>(1, 1));
	session second_sess = sess.clone();
	second_sess.set_groups(std::vector<int>(1, 2));

	dnet_io_attr io;
	memset(&io, 0, sizeof(io));
	dnet_current_time(&io.timestamp);
	memcpy(io.id, raw_id.id, DNET_ID_SIZE);

	ELLIPTICS_REQUIRE(first_write_result, first_sess.write_data(io, first_data));

	io.timestamp.tsec += 5;

	ELLIPTICS_REQUIRE(second_write_result, second_sess.write_data(io, second_data));

	ELLIPTICS_REQUIRE(prepare_result, sess.prepare_latest(id, std::vector<int>({ 1, 2 })));

	auto lookup_result = prepare_result.get();

	BOOST_REQUIRE_EQUAL(lookup_result.size(), 2);
}

bool register_tests()
{
	srand(time(0));
	configure_server_nodes();

	dnet_config config;
	memset(&config, 0, sizeof(config));

	logger log(NULL);
//	file_logger log("/dev/stderr", 4);
	node n(log);
	n.add_remote("localhost", 1025);

	ELLIPTICS_TEST_CASE(test_write, create_session(n, {1, 2}, 0, DNET_IO_FLAGS_CACHE), "new-id", "new-data");
	ELLIPTICS_TEST_CASE(test_write, create_session(n, {1, 2}, 0, DNET_IO_FLAGS_CACHE), "new-id", "new-data-long");
	ELLIPTICS_TEST_CASE(test_write, create_session(n, {1, 2}, 0, DNET_IO_FLAGS_CACHE), "new-id", "short");
	ELLIPTICS_TEST_CASE(test_remove, create_session(n, {1, 2}, 0, DNET_IO_FLAGS_CACHE), "new-id");
	ELLIPTICS_TEST_CASE(test_write, create_session(n, {1, 2}, 0, 0), "new-id-real", "new-data");
	ELLIPTICS_TEST_CASE(test_write, create_session(n, {1, 2}, 0, 0), "new-id-real", "new-data-long");
	ELLIPTICS_TEST_CASE(test_write, create_session(n, {1, 2}, 0, 0), "new-id-real", "short");
	ELLIPTICS_TEST_CASE(test_remove, create_session(n, {1, 2}, 0, 0), "new-id-real");
	ELLIPTICS_TEST_CASE(test_recovery, create_session(n, {1, 2}, 0, 0), "recovery-id", "recovered-data");
	ELLIPTICS_TEST_CASE(test_indexes, create_session(n, {1, 2}, 0, 0));
	ELLIPTICS_TEST_CASE(test_more_indexes, create_session(n, {1, 2}, 0, 0));
	ELLIPTICS_TEST_CASE(test_error, create_session(n, {99}, 0, 0), "non-existen-key", -ENXIO);
	ELLIPTICS_TEST_CASE(test_cache_write, create_session(n, { 1, 2 }, 0, DNET_IO_FLAGS_CACHE | DNET_IO_FLAGS_CACHE_ONLY), 1000);
	ELLIPTICS_TEST_CASE(test_cache_read, create_session(n, { 1, 2 }, 0, DNET_IO_FLAGS_CACHE | DNET_IO_FLAGS_CACHE_ONLY | DNET_IO_FLAGS_NOCSUM), 1000, 20);
	ELLIPTICS_TEST_CASE(test_cache_delete, create_session(n, { 1, 2 }, 0, DNET_IO_FLAGS_CACHE | DNET_IO_FLAGS_CACHE_ONLY), 1000, 20);
	ELLIPTICS_TEST_CASE(test_lookup, create_session(n, {1, 2}, 0, 0), "2.xml", "lookup data");
	ELLIPTICS_TEST_CASE(test_lookup, create_session(n, {1, 2}, 0, DNET_IO_FLAGS_CACHE), "cache-2.xml", "lookup data");
	ELLIPTICS_TEST_CASE(test_cas, create_session(n, {1, 2}, 0, DNET_IO_FLAGS_CHECKSUM));
	ELLIPTICS_TEST_CASE(test_append, create_session(n, {1, 2}, 0, DNET_IO_FLAGS_CACHE));
	ELLIPTICS_TEST_CASE(test_read_write_offsets, create_session(n, {1, 2}, 0, DNET_IO_FLAGS_CACHE));
	ELLIPTICS_TEST_CASE(test_commit, create_session(n, {1, 2}, 0, 0));
	ELLIPTICS_TEST_CASE(test_prepare_commit, create_session(n, {1, 2}, 0, 0), "prepare-commit-test-1", 0, 0);
	ELLIPTICS_TEST_CASE(test_prepare_commit, create_session(n, {1, 2}, 0, 0), "prepare-commit-test-2", 0, 1);
	ELLIPTICS_TEST_CASE(test_prepare_commit, create_session(n, {1, 2}, 0, 0), "prepare-commit-test-3", 1, 0);
	ELLIPTICS_TEST_CASE(test_prepare_commit, create_session(n, {1, 2}, 0, 0), "prepare-commit-test-4", 1, 1);
	ELLIPTICS_TEST_CASE(test_bulk_write, create_session(n, {1, 2}, 0, 0), 1000);
	ELLIPTICS_TEST_CASE(test_bulk_read, create_session(n, {1, 2}, 0, 0), 1000);
	ELLIPTICS_TEST_CASE(test_range_request, create_session(n, {2}, 0, 0), 0, 255, 2);
	ELLIPTICS_TEST_CASE(test_range_request, create_session(n, {2}, 0, 0), 3, 14, 2);
	ELLIPTICS_TEST_CASE(test_range_request, create_session(n, {2}, 0, 0), 7, 3, 2);
	ELLIPTICS_TEST_CASE(test_cache_and_no, create_session(n, {1, 2}, 0, 0), "cache-and-no-key");
	ELLIPTICS_TEST_CASE(test_cache_populating, create_session(n, {1, 2}, 0, 0), "cache-populated-key", "cache-data");
	ELLIPTICS_TEST_CASE(test_metadata, create_session(n, {1, 2}, 0, 0), "metadata-key", "meta-data");
	ELLIPTICS_TEST_CASE(test_partial_bulk_read, create_session(n, {1, 2, 3}, 0, 0));
	ELLIPTICS_TEST_CASE(test_indexes_update, create_session(n, {2}, 0, 0));
	ELLIPTICS_TEST_CASE(test_prepare_latest, create_session(n, {1, 2}, 0, 0), "prepare-latest-key");

	return true;
}

}

int main(int argc, char *argv[])
{
	int result = unit_test_main(tests::register_tests, argc, argv);
	tests::global_data.reset();
	return result;
}
