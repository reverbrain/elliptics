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
				("group", 1)
			),

			server_config::default_value().apply_options(config_data()
				("group", 2)
			),

			server_config::default_value().apply_options(config_data()
				("group", 3)
			)
		}), path);

		global_data = start_nodes(start_config);
	} else
#endif // NO_SERVER
		global_data = start_nodes(results_reporter::get_stream(), remotes, path);
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

	// We need to sleep 100 ms as recovery process is run asynchronously in background
	// so we need to give the server a bit more time to process this write command
	usleep(100 * 1000);

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

/*!
 * \defgroup test_indexes Test indexes
 * This tests check operations with indexes
 * \{
 */

static void test_indexes(session &sess)
{
	const std::vector<std::string> indexes = {
		"fast",
		"elliptics",
		"distributive",
		"reliable",
		"falt-tolerante"
	};

	const std::vector<data_pointer> data(indexes.size());

	const std::string key = "elliptics";

	ELLIPTICS_REQUIRE(clear_indexes_result, sess.set_indexes(key, std::vector<std::string>(), std::vector<data_pointer>()));
	ELLIPTICS_REQUIRE(set_indexes_result, sess.set_indexes(key, indexes, data));

	ELLIPTICS_REQUIRE(list_indexes_result, sess.list_indexes(key));
	sync_list_indexes_result list_result = list_indexes_result;

	BOOST_REQUIRE_EQUAL(list_result.size(), indexes.size());

	ELLIPTICS_REQUIRE(all_indexes_result, sess.find_all_indexes(indexes));
	sync_find_indexes_result all_result = all_indexes_result.get();

	ELLIPTICS_REQUIRE(any_indexes_result, sess.find_any_indexes(indexes));
	sync_find_indexes_result any_result = any_indexes_result.get();

	BOOST_REQUIRE_EQUAL(all_result.size(), 1);
	BOOST_REQUIRE_EQUAL(any_result.size(), 1);
	BOOST_CHECK_EQUAL(all_result[0].indexes.size(), indexes.size());
	BOOST_CHECK_EQUAL(any_result[0].indexes.size(), indexes.size());
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

	BOOST_REQUIRE_EQUAL(all_result.size(), any_result.size());
	BOOST_REQUIRE_EQUAL(all_result.size(), 256);
	BOOST_CHECK_EQUAL(all_result[0].indexes.size(), any_result[0].indexes.size());
	BOOST_CHECK_EQUAL(all_result[0].indexes.size(), indexes.size());
}

/*!
 * \brief Tests correctness of get_index_metadata function
 * Test workflow:
 * - Write 256 keys to index "index"
 * - Request "index" metadata, which will consist of metadatas for each shard
 * - Sum up sizes of shards indexes and check if it equals to 256
 * - Check if all metainformations from shards were valid
 */
static void test_indexes_metadata(session &sess)
{
	std::string index = "index";
	std::vector<std::string> indexes;
	indexes.push_back(index);

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

	ELLIPTICS_REQUIRE(get_index_metadata_result, sess.get_index_metadata(index));
	sync_get_index_metadata_result metadata = get_index_metadata_result.get();

	get_index_metadata_result_entry aggregated_metadata;
	get_index_metadata_result.get(aggregated_metadata);

	size_t total_index_size = 0;
	int invalid_results_number = 0;
	for (size_t i = 0; i < metadata.size(); ++i) {
		if (metadata[i].is_valid) {
			total_index_size += metadata[i].index_size;
			BOOST_REQUIRE_GE(metadata[i].index_size, 0);
		} else {
			++invalid_results_number;
		}
	}
	if (invalid_results_number == 0) {
		BOOST_REQUIRE_EQUAL(total_index_size, keys.size());
		BOOST_REQUIRE_EQUAL(total_index_size, aggregated_metadata.index_size);
	} else {
		BOOST_REQUIRE_LE(total_index_size, keys.size());
	}
	BOOST_REQUIRE_EQUAL(invalid_results_number, 0);
}

/*! \} */ //test_indexes group

static void test_error(session &s, const std::string &id, int err)
{
	ELLIPTICS_REQUIRE_ERROR(read_result, s.read_data(id, 0, 0), err);
}

static void test_remove(session &s, const std::string &id)
{
	ELLIPTICS_REQUIRE(remove_result, s.remove(id));
	ELLIPTICS_REQUIRE_ERROR(read_result, s.read_data(id, 0, 0), -ENOENT);
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

/*
 * Simultaneously set PREPARE/PLAIN_WRITE/COMMIT flags.
 * Data read must be equal to what was written.
 *
 * Depending on backend, reserved space may be higher.
 * This test was added to fix eblob write (see commit 57deaf6c77d1fcfc06f22b004fa4e1f895438789),
 * where it committed exactly the size specified in io.num, i.e. prepare size.
 * If it was higher than io.size (data size), then bunch of zeroes were added to the data.
 */
static void test_prepare_commit_simultaneously(session &sess)
{
	const std::string data = "prepare + commit data";
	size_t prepare_size = 1024*1024;
	std::string k = "prepare-commit-key." + lexical_cast(rand());

	data_pointer dp = data_pointer::from_raw((char *)data.c_str(), data.size());

	session s = sess.clone();

	key id(k);
	s.transform(id);

	dnet_io_control ctl;

	memset(&ctl, 0, sizeof(ctl));
	dnet_current_time(&ctl.io.timestamp);

	ctl.cflags = s.get_cflags();
	ctl.data = dp.data();

	ctl.io.flags = s.get_ioflags() | DNET_IO_FLAGS_PREPARE | DNET_IO_FLAGS_PLAIN_WRITE | DNET_IO_FLAGS_COMMIT;
	ctl.io.user_flags = s.get_user_flags();
	ctl.io.offset = 0;
	ctl.io.size = dp.size();
	ctl.io.num = prepare_size;

	memcpy(&ctl.id, &id.id(), sizeof(ctl.id));

	ctl.fd = -1;

	ELLIPTICS_REQUIRE(write_result, s.write_data(ctl));
	ELLIPTICS_REQUIRE(read_result, s.read_data(k, 0, 0));

	read_result_entry read_entry = read_result.get_one();
	BOOST_REQUIRE_EQUAL(read_entry.file().to_string(), data);
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
	ctl.data = data.c_str();
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
		BOOST_WARN_EQUAL(it->status(), 0);
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

static void test_bulk_remove(session &sess, size_t test_count)
{
	std::vector<key> keys;

	for (size_t i = 0; i < test_count; ++i) {
		std::ostringstream os;
		os << "bulk_write" << i;

		key id(os.str());

		keys.push_back(id);
	}

	sess.set_checker(checkers::no_check);
	sess.set_filter(filters::all_with_ack);

	ELLIPTICS_REQUIRE(remove_result, sess.bulk_remove(keys));

	sync_remove_result result = remove_result.get();

	size_t count = 0;
	for (auto it = result.begin(); it != result.end(); ++it) {
		// count only acks since they are the only packets returned by remove()
		count += (it->status() == 0) && (it->is_ack());
		BOOST_WARN_EQUAL(it->status(), 0);
	}
	BOOST_REQUIRE_EQUAL(count, test_count * 2);

	sess.set_checker(checkers::at_least_one);
	sess.set_filter(filters::positive);
	for (size_t i = 0; i < test_count; ++i) {
		std::ostringstream os;
		os << "bulk_write" << i;

		ELLIPTICS_REQUIRE_ERROR(read_result, sess.read_data(os.str(), 0, 0), -ENOENT);
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

static void test_partial_lookup(session &sess, const std::string &id)
{
	const std::string data = "some-data";

	session second_sess = sess.clone();
	second_sess.set_groups(std::vector<int>(1, 2));

	sess.set_filter(filters::all);

	dnet_raw_id raw_id;
	sess.transform(id, raw_id);

	dnet_io_attr io;
	memset(&io, 0, sizeof(io));
	dnet_current_time(&io.timestamp);
	memcpy(io.id, raw_id.id, DNET_ID_SIZE);

	ELLIPTICS_REQUIRE(second_write_result, second_sess.write_data(io, data));
	ELLIPTICS_REQUIRE(lookup_result, sess.lookup(id));

	auto sync_lookup_result = lookup_result.get();

	BOOST_REQUIRE_EQUAL(sync_lookup_result.size(), 2);

	BOOST_REQUIRE_EQUAL(sync_lookup_result[0].command()->id.group_id, 1);
	BOOST_REQUIRE_EQUAL(sync_lookup_result[0].command()->status, -ENOENT);

	BOOST_REQUIRE_EQUAL(sync_lookup_result[1].command()->id.group_id, 2);
	BOOST_REQUIRE_EQUAL(sync_lookup_result[1].command()->status, 0);
	BOOST_REQUIRE_EQUAL(sync_lookup_result[1].file_info()->size, data.size());
}

// The test checks basic case of using the perallel_lookup
// If a key presents in every group, number of result_entries will equal to number of groups
static void test_parallel_lookup(session &sess, const std::string &id)
{
	std::string data = "data";

	dnet_io_attr io;
	memset(&io, 0, sizeof(io));
	dnet_current_time(&io.timestamp);

	key kid(id);
	kid.transform(sess);
	memcpy(io.id, kid.raw_id().id, DNET_ID_SIZE);

	sess.set_filter(filters::positive);

	ELLIPTICS_REQUIRE(write_result, sess.write_data(io, data));
	ELLIPTICS_REQUIRE(read_result, sess.read_data(kid, 0, 0));
	ELLIPTICS_REQUIRE(lookup_result, sess.parallel_lookup(kid));

	auto results = lookup_result.get();
	BOOST_REQUIRE_EQUAL(sess.get_groups().size(), results.size());

	for (auto it = results.begin(), end = results.end(); it != end; ++it) {
		dnet_time new_time = it->file_info()->mtime;
		BOOST_REQUIRE_EQUAL(new_time.tsec, io.timestamp.tsec);
		BOOST_REQUIRE_EQUAL(new_time.tnsec, io.timestamp.tnsec);
	}
}

// The test checks basic case of using the quorum_lookup
// If a key present as follows:
//  - two groups have the key with the same timestamp
//  - one group has the key with some other timestamp
// then only result_entries for the key with the same timestamp will be received
static void test_quorum_lookup(session &sess, const std::string &id)
{
	const std::string first_data = "first-data";
	const std::string second_data = "second-data";

	dnet_raw_id raw_id;
	sess.transform(id, raw_id);

	session first_sess = sess.clone();
	first_sess.set_groups({1, 2});

	session second_sess = sess.clone();
	second_sess.set_groups({3});

	dnet_io_attr io;
	memset(&io, 0, sizeof(io));
	dnet_current_time(&io.timestamp);
	memcpy(io.id, raw_id.id, DNET_ID_SIZE);

	ELLIPTICS_REQUIRE(first_write_result, first_sess.write_data(io, first_data));

	io.timestamp.tsec += 5;

	ELLIPTICS_REQUIRE(second_write_result, second_sess.write_data(io, second_data));

	ELLIPTICS_REQUIRE(prepare_result, sess.quorum_lookup(id));

	auto lookup_result = prepare_result.get();

	BOOST_REQUIRE_EQUAL(lookup_result.size(), 2);

	io.timestamp.tsec -= 5;

	for (size_t i = 0; i != 2; ++i) {
		BOOST_REQUIRE_EQUAL(lookup_result[i].file_info()->mtime.tsec, io.timestamp.tsec);
		BOOST_REQUIRE_EQUAL(lookup_result[i].file_info()->mtime.tnsec, io.timestamp.tnsec);
	}
}

// Test checks the work of quorum_lookup in case of there are two different keys in two groups
// and no key in third one.
static void test_partial_quorum_lookup(session &sess, const std::string &id)
{
	const std::string first_data = "first-data";
	const std::string second_data = "second-data";

	dnet_raw_id raw_id;
	sess.transform(id, raw_id);

	session first_sess = sess.clone();
	first_sess.set_groups({1});

	session second_sess = sess.clone();
	second_sess.set_groups({2});

	dnet_io_attr io;
	memset(&io, 0, sizeof(io));
	dnet_current_time(&io.timestamp);
	memcpy(io.id, raw_id.id, DNET_ID_SIZE);

	ELLIPTICS_REQUIRE(first_write_result, first_sess.write_data(io, first_data));

	io.timestamp.tsec += 5;

	ELLIPTICS_REQUIRE(second_write_result, second_sess.write_data(io, second_data));

	ELLIPTICS_REQUIRE(prepare_result, sess.quorum_lookup(id));

	auto lookup_result = prepare_result.get();

	BOOST_REQUIRE_EQUAL(lookup_result.size(), 1);

	BOOST_REQUIRE_EQUAL(lookup_result[0].file_info()->mtime.tsec, io.timestamp.tsec);
	BOOST_REQUIRE_EQUAL(lookup_result[0].file_info()->mtime.tnsec, io.timestamp.tnsec);
}

// The test checks quorum_lookup returns an error in case of there are two different keys
// in two groups and no key in third one and checker::quorum is set
static void test_fail_partial_quorum_lookup(session &sess, const std::string &id)
{
	const std::string first_data = "first-data";
	const std::string second_data = "second-data";

	dnet_raw_id raw_id;
	sess.transform(id, raw_id);

	session first_sess = sess.clone();
	first_sess.set_groups({1});

	session second_sess = sess.clone();
	second_sess.set_groups({2});

	dnet_io_attr io;
	memset(&io, 0, sizeof(io));
	dnet_current_time(&io.timestamp);
	memcpy(io.id, raw_id.id, DNET_ID_SIZE);

	ELLIPTICS_REQUIRE(first_write_result, first_sess.write_data(io, first_data));

	io.timestamp.tsec += 5;

	ELLIPTICS_REQUIRE(second_write_result, second_sess.write_data(io, second_data));

	sess.set_checker(checkers::quorum);
	ELLIPTICS_REQUIRE_ERROR(prepare_result, sess.quorum_lookup(id), -ENXIO);
}

// The test checks parallel_lookup returns an error in case of
// there were not result_entries without errors
static void test_fail_parallel_lookup(session &sess, int error)
{
	ELLIPTICS_REQUIRE_ERROR(result,
			sess.parallel_lookup(std::string("test_fail_parallel_lookup_key")), error);
}

// The test checks quorum_lookup returns an error in case of
// there were not result_entries without errors
static void test_fail_quorum_lookup(session &sess, int error)
{
	ELLIPTICS_REQUIRE_ERROR(result,
			sess.quorum_lookup(std::string("test_fail_quorum_lookup_key")), error);
}

static void test_read_latest_non_existing(session &sess, const std::string &id)
{
	ELLIPTICS_REQUIRE_ERROR(read_data, sess.read_latest(id, 0, 0), -ENOENT);
}

// This test checks that read with DNET_IO_FLAGS_MIX_STATES succeeds and doesn't lock up.
static void test_read_mix_states_ioflags(session &sess, const std::string &id)
{
	std::string data = "mix states test data";

	sess.set_ioflags(sess.get_ioflags() | DNET_IO_FLAGS_MIX_STATES);

	ELLIPTICS_REQUIRE(write_result, sess.write_data(id, data, 0));
	ELLIPTICS_REQUIRE(read_result, sess.read_data(id, 0, 0));
	read_result_entry result = read_result.get_one();

	BOOST_REQUIRE_EQUAL(result.file().to_string(), data);
}

/*!
 * \brief test_merge_indexes
 *
 * Test the correctness of session::merge_indexes method.
 *
 * Algorithm is the following:
 * \li Add 'merge-key' to indexes 'merge-1' and 'merge-2' at group 1 with data 'data-1'
 * \li Add 'merge-key' to indexes 'merge-2' and 'merge-3' at group 2 with data 'data-22'
 * \li Merge indexes for 'merge-key' at groups 1, 2
 * \li Check if indexes were merged successfully
 */
static void test_merge_indexes(session &sess, std::string suffix, result_checker checker)
{
	sess.set_namespace("merge-indexes-" + suffix);
	sess.set_checker(checker);

	key object_id = std::string("merge-key");
	sess.transform(object_id);

	std::vector<std::string> tags_1 = {
		"merge-1",
		"merge-2"
	};
	std::vector<data_pointer> data_1 = {
		data_pointer::copy("data-1"),
		data_pointer::copy("data-1")
	};

	std::vector<std::string> tags_2 = {
		"merge-2",
		"merge-3"
	};
	std::vector<data_pointer> data_2 = {
		data_pointer::copy("data-22"),
		data_pointer::copy("data-22")
	};

	std::vector<std::string> result_tags = {
		"merge-1",
		"merge-2",
		"merge-3"
	};
	std::vector<data_pointer> result_data = {
		data_pointer::copy("data-1"),
		data_pointer::copy("data-22"),
		data_pointer::copy("data-22")
	};

	std::map<key, data_pointer> result;

	for (size_t i = 0; i < result_tags.size(); ++i) {
		key tag = result_tags[i];
		tag.transform(sess);
		result[tag.id()] = result_data[i];
	}

	session sess_1 = sess.clone();
	sess_1.set_groups(std::vector<int>(1, 1));
	ELLIPTICS_REQUIRE(set_indexes_1, sess_1.set_indexes(object_id, tags_1, data_1));

	session sess_2 = sess.clone();
	sess_2.set_groups(std::vector<int>(1, 2));
	ELLIPTICS_REQUIRE(set_indexes_2, sess_2.set_indexes(object_id, tags_2, data_2));

	dnet_id index_id;
	memset(&index_id, 0, sizeof(index_id));

	dnet_indexes_transform_object_id(sess.get_native_node(), &object_id.id(), &index_id);
	ELLIPTICS_REQUIRE(merge_result, sess.merge_indexes(index_id, sess.get_groups(), sess.get_groups()));

	ELLIPTICS_REQUIRE(list_indexes_1, sess_1.list_indexes(object_id));
	ELLIPTICS_REQUIRE(list_indexes_2, sess_2.list_indexes(object_id));

	{
		sync_list_indexes_result list_indexes = list_indexes_1;

		BOOST_REQUIRE_EQUAL(list_indexes.size(), result.size());

		for (auto it = list_indexes.begin(); it != list_indexes.end(); ++it) {
			auto jt = result.find(it->index);
			BOOST_REQUIRE(jt != result.end());
			BOOST_REQUIRE_EQUAL(jt->second.to_string(), it->data.to_string());
		}
	}

	{
		sync_list_indexes_result list_indexes = list_indexes_2;

		BOOST_REQUIRE_EQUAL(list_indexes.size(), result.size());

		for (auto it = list_indexes.begin(); it != list_indexes.end(); ++it) {
			auto jt = result.find(it->index);
			BOOST_REQUIRE(jt != result.end());
			BOOST_REQUIRE_EQUAL(jt->second.to_string(), it->data.to_string());
		}
	}
}

/*!
 * Test index recovery correctnes.
 *
 * Add several object to single index differently at different groups.
 * Then run session::recovery_index and check if every-thing is ok.
 */
void test_index_recovery(session &sess)
{
	sess.set_namespace("index-recovery");

	key index = std::string("index");
	sess.transform(index);

	std::vector<std::string> objects_1 = {
		"doc-1",
		"doc-2",
		"doc-3"
	};

	std::vector<data_pointer> data_1 = {
		data_pointer::copy("data-1")
	};

	std::vector<std::string> objects_2 = {
		"doc-2",
		"doc-3",
		"doc-4"
	};

	std::vector<data_pointer> data_2 = {
		data_pointer::copy("data-22")
	};

	std::vector<std::string> result_objects = {
		"doc-1",
		"doc-2",
		"doc-3",
		"doc-4",
		"doc-5"
	};

	std::vector<data_pointer> result_data = {
		data_pointer::copy("data-1"),
		data_pointer::copy("data-22"),
		data_pointer::copy("data-22"),
		data_pointer::copy("data-22"),
		data_pointer::copy("data-3")
	};

	std::map<key, data_pointer> result;

	for (size_t i = 0; i < result_objects.size(); ++i) {
		key object = result_objects[i];
		object.transform(sess);
		result[object.id()] = result_data[i];
	}

	session sess_1 = sess.clone();
	sess_1.set_groups(std::vector<int>(1, 1));

	session sess_2 = sess.clone();
	sess_2.set_groups(std::vector<int>(1, 2));

	for (auto it = objects_1.begin(); it != objects_1.end(); ++it) {
		ELLIPTICS_REQUIRE(set_indexes_1, sess_1.set_indexes(*it, std::vector<std::string>(1, index.remote()), data_1));
	}

	for (auto it = objects_2.begin(); it != objects_2.end(); ++it) {
		ELLIPTICS_REQUIRE(set_indexes_2, sess_2.set_indexes(*it, std::vector<std::string>(1, index.remote()), data_2));
	}

	ELLIPTICS_REQUIRE(update_index_internal, sess_1.update_indexes_internal(std::string("doc-5"),
		std::vector<std::string>(1, index.remote()),
		std::vector<data_pointer>(1, data_pointer::copy("data-3"))));

	ELLIPTICS_REQUIRE(recover_index_result, sess.recover_index(index));

	for (int group = 1; group <= 2; ++group) {
		session group_sess = sess.clone();
		group_sess.set_groups(std::vector<int>(1, group));

		for (size_t i = 0; i < result_objects.size(); ++i) {
			ELLIPTICS_REQUIRE(async_list_indexes, group_sess.list_indexes(result_objects[i]));
			sync_list_indexes_result list_indexes = async_list_indexes;

			BOOST_REQUIRE_EQUAL(list_indexes.size(), 1);
			index_entry entry = list_indexes.front();

			BOOST_REQUIRE_EQUAL(memcmp(entry.index.id, index.raw_id().id, DNET_ID_SIZE), 0);
			BOOST_REQUIRE_EQUAL(entry.data.to_string(), result_data[i].to_string());
		}

		ELLIPTICS_REQUIRE(async_find_result, group_sess.find_any_indexes(std::vector<dnet_raw_id>(1, index.raw_id())));
		sync_find_indexes_result find_result = async_find_result;

		BOOST_REQUIRE_EQUAL(find_result.size(), result.size());

		for (size_t i = 0; i < find_result.size(); ++i) {
			find_indexes_result_entry result_entry = find_result[i];
			BOOST_REQUIRE_EQUAL(result_entry.indexes.size(), 1);

			index_entry entry = result_entry.indexes.front();

			BOOST_REQUIRE_EQUAL(memcmp(entry.index.id, index.raw_id().id, DNET_ID_SIZE), 0);

			auto it = result.find(result_entry.id);
			BOOST_REQUIRE(it != result.end());
			BOOST_REQUIRE_EQUAL(entry.data.to_string(), it->second.to_string());
		}
	}
}

static void test_lookup_non_existing(session &sess, int error)
{
	ELLIPTICS_REQUIRE_ERROR(lookup, sess.lookup(std::string("lookup_non_existing")), error);
}

#ifndef NO_SERVER
static void test_requests_to_own_server(session &sess)
{
	key id = std::string("own-requests-id");
	sess.set_filter(filters::positive);

	ELLIPTICS_REQUIRE(async_write, sess.write_data(id, "some-file", 0));

	sync_write_result result = async_write;

	BOOST_REQUIRE_EQUAL(result.size(), 3);
}
#endif

/* Check that lookup doesn't validate records if checksum isn't requested and does if not:
 * * write and corrupt one record
 * * make lookup without requesting checksum and check that it is succeeded
 * * make lookup with requesting checksum and check that it is failed with -EILSEQ (corruption detected)
 */
static void test_lookup_corrupted(session &sess, const std::string &id, const std::string &data)
{
	{
		ELLIPTICS_REQUIRE(write_result, sess.write_data(id, data, 0));

		/* Corrupt written record */
		const int fd = open(write_result.get_one().file_path(), O_RDWR, 0644);
		BOOST_REQUIRE_GT(fd, 0);
		const std::string corruption = "vkn3i49hfbvs";
		const off_t offset = write_result.get_one().file_info()->offset + 5;
		BOOST_REQUIRE_EQUAL(pwrite(fd, corruption.c_str(), corruption.size(), offset),
		                    corruption.size());
		close(fd);
	}
	{
		/* Lookup without requesting checksum */
		ELLIPTICS_REQUIRE(lookup_result, sess.lookup(id));
	}
	{
		/* Lookup with requesting checksum */
		sess.set_cflags(DNET_FLAGS_CHECKSUM);
		ELLIPTICS_REQUIRE_ERROR(lookup_result, sess.lookup(id), -EILSEQ);
	}
}

bool register_tests(test_suite *suite, node n)
{
	ELLIPTICS_TEST_CASE(test_cache_write, create_session(n, { 1, 2 }, 0, DNET_IO_FLAGS_CACHE | DNET_IO_FLAGS_CACHE_ONLY), 1000);
	ELLIPTICS_TEST_CASE(test_cache_read, create_session(n, { 1, 2 }, 0, DNET_IO_FLAGS_CACHE | DNET_IO_FLAGS_CACHE_ONLY | DNET_IO_FLAGS_NOCSUM), 1000, 20);
	ELLIPTICS_TEST_CASE(test_cache_delete, create_session(n, { 1, 2 }, 0, DNET_IO_FLAGS_CACHE | DNET_IO_FLAGS_CACHE_ONLY), 1000, 20);
	ELLIPTICS_TEST_CASE(test_cache_and_no, create_session(n, {1, 2}, 0, 0), "cache-and-no-key");
	ELLIPTICS_TEST_CASE(test_cache_populating, create_session(n, {1, 2}, 0, 0), "cache-populated-key", "cache-data");
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
	ELLIPTICS_TEST_CASE(test_indexes_metadata, create_session(n, {1, 2}, 0, 0));
	ELLIPTICS_TEST_CASE(test_error, create_session(n, {99}, 0, 0), "non-existen-key", -ENXIO);
	ELLIPTICS_TEST_CASE(test_error, create_session(n, {1, 2}, 0, 0), "non-existen-key", -ENOENT);
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
	ELLIPTICS_TEST_CASE(test_prepare_commit_simultaneously, create_session(n, {1, 2}, 0, 0));
	ELLIPTICS_TEST_CASE(test_bulk_write, create_session(n, {1, 2}, 0, 0), 1000);
	ELLIPTICS_TEST_CASE(test_bulk_read, create_session(n, {1, 2}, 0, 0), 1000);
	ELLIPTICS_TEST_CASE(test_bulk_remove, create_session(n, {1, 2}, 0, 0), 1000);
	ELLIPTICS_TEST_CASE(test_range_request, create_session(n, {2}, 0, 0), 0, 255, 2);
	ELLIPTICS_TEST_CASE(test_range_request, create_session(n, {2}, 0, 0), 3, 14, 2);
	ELLIPTICS_TEST_CASE(test_range_request, create_session(n, {2}, 0, 0), 7, 3, 2);
	ELLIPTICS_TEST_CASE(test_metadata, create_session(n, {1, 2}, 0, 0), "metadata-key", "meta-data");
	ELLIPTICS_TEST_CASE(test_partial_bulk_read, create_session(n, {1, 2, 3}, 0, 0));
	ELLIPTICS_TEST_CASE(test_indexes_update, create_session(n, {2}, 0, 0));
	ELLIPTICS_TEST_CASE(test_prepare_latest, create_session(n, {1, 2}, 0, 0), "prepare-latest-key");
	ELLIPTICS_TEST_CASE(test_partial_lookup, create_session(n, {1, 2}, 0, 0), "partial-lookup-key");
	ELLIPTICS_TEST_CASE(test_parallel_lookup, create_session(n, {1, 2, 3}, 0, 0), "parallel-lookup-key");
	ELLIPTICS_TEST_CASE(test_quorum_lookup, create_session(n, {1, 2, 3}, 0, 0), "quorum-lookup-key");
	ELLIPTICS_TEST_CASE(test_partial_quorum_lookup, create_session(n, {1, 2, 3}, 0, 0), "partial-quorum-lookup-key");
	ELLIPTICS_TEST_CASE(test_fail_partial_quorum_lookup, create_session(n, {1, 2, 3}, 0, 0), "fail-partial-quorum-lookup-key");
	ELLIPTICS_TEST_CASE(test_fail_parallel_lookup, create_session(n, {1, 2, 3}, 0, 0), -ENOENT);
	ELLIPTICS_TEST_CASE(test_fail_parallel_lookup, create_session(n, {91, 92, 93}, 0, 0), -ENXIO);
	ELLIPTICS_TEST_CASE(test_fail_quorum_lookup, create_session(n, {1, 2, 3}, 0, 0), -ENOENT);
	ELLIPTICS_TEST_CASE(test_fail_quorum_lookup, create_session(n, {91, 92, 93}, 0, 0), -ENXIO);
	ELLIPTICS_TEST_CASE(test_read_latest_non_existing, create_session(n, {1, 2}, 0, 0), "read-latest-non-existing");
	ELLIPTICS_TEST_CASE(test_merge_indexes, create_session(n, { 1, 2 }, 0, 0), "one", checkers::at_least_one);
	ELLIPTICS_TEST_CASE(test_merge_indexes, create_session(n, { 1, 2 }, 0, 0), "quorum", checkers::quorum);
	ELLIPTICS_TEST_CASE(test_merge_indexes, create_session(n, { 1, 2 }, 0, 0), "all", checkers::all);
	ELLIPTICS_TEST_CASE(test_index_recovery, create_session(n, { 1, 2 }, 0, 0));
	ELLIPTICS_TEST_CASE(test_lookup_non_existing, create_session(n, { 1, 2 }, 0, 0), -ENOENT);
	ELLIPTICS_TEST_CASE(test_lookup_non_existing, create_session(n, { 1 }, 0, 0), -ENOENT);
	ELLIPTICS_TEST_CASE(test_lookup_non_existing, create_session(n, { 99 }, 0, 0), -ENXIO);
	ELLIPTICS_TEST_CASE(test_read_mix_states_ioflags, create_session(n, {1, 2}, 0, 0), "read-mix-states-ioflags");
#ifndef NO_SERVER
	ELLIPTICS_TEST_CASE(test_requests_to_own_server, create_session(node::from_raw(global_data->nodes.front().get_native()), { 1, 2, 3 }, 0, 0));
#endif
	ELLIPTICS_TEST_CASE(test_lookup_corrupted, create_session(n, {1}, 0, 0), "lookup corrupted test key", "lookup corrupted test data");

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
