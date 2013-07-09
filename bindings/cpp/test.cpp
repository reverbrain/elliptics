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

#include "../../include/elliptics/cppdef.h"

#include <algorithm>

using namespace ioremap::elliptics;

static void test_prepare_commit(session &s, int psize, int csize)
{
	std::string written, ret;
//	try {
		std::string remote = "prepare-commit-test";

		std::string prepare_data = "prepare data|";
		std::string commit_data = "commit data";
		std::string plain_data[3] = {"plain data0|", "plain data1|", "plain data2|"};

		if (psize)
			prepare_data.clear();
		if (csize)
			commit_data.clear();

		uint64_t offset = 0;
		uint64_t total_size_to_reserve = 1024;

		s.write_prepare(key(remote), prepare_data, offset, total_size_to_reserve).wait();
		offset += prepare_data.size();

		written += prepare_data;

		for (int i = 0; i < 3; ++i) {
			s.write_plain(key(remote), plain_data[i], offset).wait();
			offset += plain_data[i].size();

			written += plain_data[i];
		}

		/* append data first so that subsequent written.size() call returned real size of the written data */
		written += commit_data;

		s.write_commit(key(remote), commit_data, offset, written.size()).wait();

		ret = s.read_data(key(remote), 0, 0).get()[0].file().to_string();
		std::cerr << "prepare/commit write: '" << written << "', read: '" << ret << "'" << std::endl;
//	} catch (const std::exception &e) {
//		std::cerr << "PREPARE/COMMIT test failed: " << e.what() << std::endl;
//		throw;
//	}

	if (ret != written) {
		std::cerr << "PREPARE/COMMIT test failed: read mismatch" << std::endl;
		throw std::runtime_error("PREPARE/COMMIT test failed: read mismatch");
	}
}

static void test_range_request(session &s, int limit_start, int limit_num, uint64_t cflags, int group_id)
{
	s.set_cflags(cflags);

	struct dnet_io_attr io;

	memset(&io, 0, sizeof(io));

#if 0
	dnet_parse_numeric_id("76a046fcd25ebeaaa65a0fa692faf8b8701695c6ba67008b5922ae9f134fc1da7ffffed191edf767000000000000000000000000000000000000000000000000", &io.id);
	dnet_parse_numeric_id("76a046fcd25ebeaaa65a0fa692faf8b8701695c6ba67008b5922ae9f134fc1da7ffffed22220037fffffffffffffffffffffffffffffffffffffffffffffffff", &io.parent);
#else
	memset(io.id, 0x00, sizeof(io.id));
	memset(io.parent, 0xff, sizeof(io.id));
#endif
	io.start = limit_start;
	io.num = limit_num;

	std::vector<std::string> ret;
	ret = s.read_data_range_raw(io, group_id);

	std::cerr << "range [LIMIT(" << limit_start << ", " << limit_num << "): " << ret.size() << " elements" << std::endl;
#if 0
	for (size_t i = 0; i < ret.size(); ++i) {
		char id_str[DNET_ID_SIZE * 2 + 1];
		const char *data = ret[i].data();
		const unsigned char *id = (const unsigned char *)data;
		uint64_t size = dnet_bswap64(*(uint64_t *)(data + DNET_ID_SIZE));
		char *str = (char *)(data + DNET_ID_SIZE + 8);

		std::cerr << "range [LIMIT(" << limit_start << ", " << limit_num << "): " <<
			dnet_dump_id_len_raw(id, DNET_ID_SIZE, id_str) << ": size: " << size << ": " << str << std::endl;
	}
#endif
}

static void test_range_request_2(session &s, int limit_start, int limit_num, int group_id)
{
	const size_t item_count = 16;
	const size_t number_index = 5; // DNET_ID_SIZE - 1

	dnet_id begin;
	memset(&begin, 0x13, sizeof(begin));
	begin.group_id = group_id;
	begin.id[number_index] = 0;

	dnet_id end = begin;
	end.id[number_index] = item_count;

	dnet_id id = begin;

	std::vector<std::string> data(item_count);

	// Write data
	for (size_t i = 0; i < data.size(); ++i) {
		std::string &str = data[i];
		str.resize(5 + (rand() % 95));
		std::generate(str.begin(), str.end(), std::rand);

		id.id[number_index] = i;
		s.write_data(id, data[i], 0).wait();
		sync_read_result entry = s.read_data(id, std::vector<int>(1, group_id), 0, 0);
		if (entry[0].file().to_string() != str)
			throw_error(-EIO, id, "read_data_range_2: Write failed");
	}

	dnet_io_attr io;
	memset(&io, 0, sizeof(io));
	memcpy(io.id, begin.id, sizeof(io.id));
	memcpy(io.parent, end.id, sizeof(io.id));
	io.start = limit_start;
	io.num = limit_num;

	// Test read range
	sync_read_result result = s.read_data_range(io, group_id);
	if (int(result.size()) != std::min(limit_num, int(item_count) - limit_start))
		throw_error(-ENOENT, begin, "read_data_range_2: Received size: %d, expected: %d",
			int(result.size()), std::min(limit_num, int(item_count) - limit_start));

	for (int i = 0; i < std::min(int(item_count) - limit_start, limit_num); ++i) {
		int index = i + limit_start;
		if (data[index] != result[i].file().to_string()) {
			throw_error(-ENOENT, begin, "read_data_range_2: Invalid data at %d of %d",
				i, limit_num);
		}
	}
	int removed = 0;

	// Test range remove
	sync_read_result remove_result = s.remove_data_range(io, group_id);
	for (size_t i = 0; i < remove_result.size(); ++i)
		removed += remove_result[i].io_attribute()->num;
	if (removed != int(item_count))
		throw_error(-EIO, begin, "read_data_range_2: Failed to remove data"
				", expected items: %d, found: %d", int(result.size()), removed);
	removed = 0;

	// Test remove range again
	try {
		remove_result = s.remove_data_range(io, group_id);
		for (size_t i = 0; i < remove_result.size(); ++i)
			removed += remove_result[i].io_attribute()->num;
	} catch (...) {}
	if (removed != 0)
		throw_error(-EIO, begin,
				"read_data_range_2: Failed to remove no data, expected items: 0"
				", found: %d", removed);
	removed = 0;

	// Test remove range again
	for (int i = 0; i < std::min(int(item_count) - limit_start, limit_num); ++i) {
		id.id[number_index] = i + limit_start;
		try {
			sync_read_result entry = s.read_data(id, std::vector<int>(1, group_id), 0, 0);
		} catch (not_found_error) { removed++; }
	}
	if (removed != std::min(int(item_count) - limit_start, limit_num))
		throw_error(-EEXIST, begin, "read_data_range_2: removed data is read back: "
				"%d vs %d", removed, std::min(limit_num, int(item_count) - limit_start));
}

static void test_lookup_parse(const std::string &key,
	struct dnet_cmd *cmd, struct dnet_addr *addr, const char *path)
{
	std::cerr << key << ": lives on addr: " << dnet_server_convert_dnet_addr(addr);

	if (cmd->size > sizeof(struct dnet_addr)) {
		struct dnet_file_info *info = (struct dnet_file_info *)(addr + 1);

		dnet_convert_file_info(info);
		std::cerr << ", offset: " << (unsigned long long)info->offset;
		std::cerr << ", size: " << (unsigned long long)info->size;
		std::cerr << ", file: " << path;
	}
	std::cerr << std::endl;
}

static void test_lookup_parse(const std::string &key, const sync_lookup_result &results)
{
	for (auto it = results.begin(); it != results.end(); ++it) {
		test_lookup_parse(key, it->command(), it->address(), it->file_path());
	}
}

static void test_lookup(session &s, std::vector<int> &groups)
{
	(void) groups;
	try {
		std::string key = "2.xml";
		std::string data = "lookup data";

		sync_write_result lret = s.write_data(key, data, 0);
		test_lookup_parse(key, lret);

		struct dnet_id id;
		memset(&id, 0, sizeof(struct dnet_id));

		s.transform(key, id);

		sync_lookup_result lret2 = s.lookup(key);
		test_lookup_parse(key, lret2);
	} catch (const std::exception &e) {
		std::cerr << "LOOKUP test failed: " << e.what() << std::endl;
		throw;
	}
}

static void test_append(session &s)
{
	try {
		std::string key = "append-test";
		std::string data1 = "first part of the message";
		std::string data2 = " | second part of the message";

		// Cleanup previous test reincarnation
		try {
			s.remove(key).wait();
		} catch (const std::exception &e) {}

		// Write data
		s.write_data(key, data1, 0).wait();

		// Append
		s.set_ioflags(DNET_IO_FLAGS_APPEND);
		s.write_data(key, data2, 0).wait();
		s.set_ioflags(0);

		// Read
		std::string result;
		result = s.read_data(key, 0, 0).get()[0].file().to_string();
		std::cerr << key << ": " << result << std::endl;

		// Check
		if (result != (data1 + data2))
			throw std::runtime_error(data1 + data2 + " != " + result);
	} catch (const std::exception &e) {
		std::cerr << "APPEND test failed: " << e.what() << std::endl;
		throw std::runtime_error("APPEND test failed");
	}
}

static void test_read_write_offsets(session &s)
{
	try {
		std::string key = "read-write-test";
		std::string data = "55555", result;
		std::string test1 = "43210", cmp1 = "543210", cmp2 = "210", cmp3 = "3";

		// Cleanup previous test reincarnation
		try {
			s.remove(key).wait();
		} catch (const std::exception &e) {}

		// Write data
		s.write_data(key, data, 0).wait();

		// Overwrite partially
		s.write_data(key, test1, 1).wait();

		// Read whole & Check
		result = s.read_data(key, 0, 0).get()[0].file().to_string();
		std::cerr << key << ": " << result << std::endl;
		if (result != cmp1)
			throw std::runtime_error(result + " != " + cmp1);

		// Read with offset & Check
		result = s.read_data(key, 3, 0).get()[0].file().to_string();
		std::cerr << key << ": " << result << std::endl;
		if (result != cmp2)
			throw std::runtime_error(result + " != " + cmp2);

		// Read with offset/size & Check
		result = s.read_data(key, 2, 1).get()[0].file().to_string();
		std::cerr << key << ": " << result << std::endl;
		if (result != cmp3)
			throw std::runtime_error(result + " != " + cmp3);
	} catch (const std::exception &e) {
		std::cerr << "READ/WRITE test failed: " << e.what() << std::endl;
		throw std::runtime_error("READ/WRITE test failed");
	}
}

// Test manual write with commit flag
static void test_commit(session &s)
{
	try {
		std::string key = "commit-test";
		std::string data = "commit-test-data";

		// Cleanup previous test reincarnation
		try {
			s.remove(key).wait();
		} catch (const std::exception &e) {}

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
		ctl.fd = -1;

		// Write
		s.write_data(ctl).wait();

		// Read
		std::string result;
		result = s.read_data(key, 0, 0).get()[0].file().to_string();
		std::cerr << key << ": " << result << std::endl;

		// Check
		if (result != data)
			throw std::runtime_error(result + " != " + data);
	} catch (const std::exception &e) {
		std::cerr << "COMMIT test failed: " << e.what() << std::endl;
		throw std::runtime_error("COMMIT test failed");
	}
}

static void test_cas(session &s)
{
	try {
		std::string key = "cas-test";
		std::string data1 = "cas data first";
		std::string data2 = "cas data second";

		// Cleanup previous test reincarnation
		try {
			s.remove(key).wait();
		} catch (const std::exception &e) {}

		// Write data
		s.write_data(key, data1, 0).wait();

		// Read csum
		std::string result = s.read_data(key, 0, 0).get()[0].file().to_string();
		struct dnet_id csum1 = {{}, 0, 0}, csum2 = {{}, 0, 0};
		s.transform(data1, csum1);
		s.transform(result, csum2);

		if (memcmp(&csum1, &csum2, sizeof(struct dnet_id)))
			throw std::runtime_error("CAS: csum does not match");

		// CAS
		s.write_cas(key, data2, csum1, 0).wait();

		// Read
		result = s.read_data(key, 0, 0).get()[0].file().to_string();
		std::cerr << key << ": " << result << std::endl;

		// Check
		if (result != data2)
			throw std::runtime_error(data2 + " != " + result);
	} catch (const std::exception &e) {
		std::cerr << "CAS test failed: " << e.what() << std::endl;
		throw std::runtime_error("CAS test failed");
	}
}

enum { BulkTestCount = 10 };

static void test_bulk_write(session &s)
{
	try {
		std::vector<struct dnet_io_attr> ios;
		std::vector<std::string> data;

		int i;

		for (i = 0; i < BulkTestCount; ++i) {
			std::ostringstream os;
			struct dnet_io_attr io;
			struct dnet_id id;

			os << "bulk_write" << i;

			memset(&io, 0, sizeof(io));
			memset(&id, 0, sizeof(id));

			s.transform(os.str(), id);
			memcpy(io.id, id.id, DNET_ID_SIZE);
			io.size = os.str().size();

			ios.push_back(io);
			data.push_back(os.str());
		}

		sync_write_result ret = s.bulk_write(ios, data);

		std::cerr << "BULK WRITE:" << std::endl;
		std::cerr << "ret size = " << ret.size() << std::endl;

		s.set_ioflags(DNET_IO_FLAGS_NOCSUM);

		uint64_t offset = 0;
		uint64_t size = 0;

		/* read without checksums since we did not write metadata */
		for (i = 0; i < BulkTestCount; ++i) {
			std::ostringstream os;

			os << "bulk_write" << i;
			std::cerr << os.str() << ": " << s.read_data(key(os.str()), offset, size).get()[0].file().to_string() << std::endl;
		}
	} catch (const std::exception &e) {
		std::cerr << "BULK WRITE test failed: " << e.what() << std::endl;
		throw;
	}
	s.set_ioflags(0);
}

static void test_bulk_read(session &s)
{
	try {
		std::vector<std::string> keys;

		for (size_t i = 0; i < BulkTestCount; ++i) {
			std::ostringstream os;
			os << "bulk_write" << i;
			keys.push_back(os.str());
		}

		sync_read_result ret = s.bulk_read(keys);

		std::cerr << "BULK READ:" << std::endl;
		std::cerr << "ret size = " << ret.size() << std::endl;

		if (ret.size() != BulkTestCount) {
			throw_error(-ENOENT, "BULK READ test failed, expected count: %d, received: %d",
				int(BulkTestCount), int(ret.size()));
		}

		/* read without checksums since we did not write metadata */
		for (size_t i = 0; i < ret.size(); ++i) {
			std::ostringstream os;

			os << "bulk_read" << i;
			std::cerr << os.str() << ": " << ret[i].file().to_string() << std::endl;
		}
	} catch (const std::exception &e) {
		std::cerr << "BULK READ test failed: " << e.what() << std::endl;
		throw;
	}

}

static void memory_test_io(session &s, int num)
{
	int ids[16];

	for (int i = 0; i < num; ++i) {
		std::string data;

		data.resize(rand() % 102400 + 100);

		for (int j = 0; j < (int)ARRAY_SIZE(ids); ++j)
			ids[j] = rand();

		std::string id((char *)ids, sizeof(ids));
		sync_write_result written;

		try {
			written = s.write_data(id, data, 0);
			std::string res = s.read_data(id, 0, 0).get()[0].file().to_string();
		} catch (const std::exception &e) {
			std::cerr << "could not perform read/write: " << e.what() << std::endl;
			if (!written.empty()) {
				std::cerr << "but written successfully\n";
				test_lookup_parse(id, written);
			}
			throw;
		}
	}

}

static void test_cache_write(session &s, int num)
{
	try {
		std::vector<struct dnet_io_attr> ios;
		std::vector<std::string> data;

		int i;

		for (i = 0; i < num; ++i) {
			std::ostringstream os;
			struct dnet_io_attr io;
			struct dnet_id id;

			os << "test_cache" << i;

			memset(&io, 0, sizeof(io));
			memset(&id, 0, sizeof(id));

			s.transform(os.str(), id);
			memcpy(io.id, id.id, DNET_ID_SIZE);
			io.size = os.str().size();

			ios.push_back(io);
			data.push_back(os.str());
		}

		s.bulk_write(ios, data);
	} catch (const std::exception &e) {
		std::cerr << "cache write test failed: " << e.what() << std::endl;
		throw;
	}
	std::cerr << "Cache entries writted: " << num << std::endl;
}

static void test_cache_read(session &s, int num)
{
	int count = 0;

	/* Read random 20% of records written by test_cache_write() */
	for (int i = 0; i < num; ++i) {
		if ((rand() % 100) > 20)
			continue;

		std::ostringstream os;

		os << "test_cache" << i;

		const std::string id(os.str());

		uint64_t offset = 0;
		uint64_t size = 0;

		s.set_ioflags(DNET_IO_FLAGS_NOCSUM);
		try {
			s.read_data(key(id), offset, size).get()[0].file().to_string();
		} catch (const std::exception &e) {
			std::cerr << "could not perform read : " << id << ": " << e.what() << std::endl;
			throw;
		}
		s.set_ioflags(0);
		count++;
	}
	std::cerr << "Cache entries read: " << count << std::endl;
}

static void test_cache_delete(session &s, int num)
{
	int count = 0;

	/* Read random 20% of records written by test_cache_write() */
	for (int i = 0; i < num; ++i) {
		if ((rand() % 100) > 20)
			continue;

		std::ostringstream os;

		os << "test_cache" << i;

		std::string id(os.str());

		try {
			s.remove(id).wait();
		} catch (const std::exception &e) {
			std::cerr << "could not perform remove: " << e.what() << std::endl;
			throw;
		}
		count++;
	}
	std::cerr << "Cache entries deleted: " << count << std::endl;
}

void check_read_recovery_availability(std::stringstream &log, session &s, const std::string &key, int group)
{
	auto sess = s.clone();
	sess.set_groups({ group });
	sess.set_exceptions_policy(session::no_exceptions);

	auto result = sess.read_data(key, 0, 0);
	result.wait();

	log << group << ": " << result.error().code() << ", ";
}

void print_read_recovery_availability(session &s, const std::string &key)
{
	std::stringstream log;
	log << "Data availability: ";

	check_read_recovery_availability(log, s, key, 1);
	check_read_recovery_availability(log, s, key, 2);

	std::cerr << log.str() << std::endl;
}

void test_read_recovery(session &s)
{
	std::string id = "test-id";
	std::string data = "test-data";

	auto sess = s.clone();

	sess.set_groups({ 1, 2 });

	sess.write_data(id, data, 0).wait();

	print_read_recovery_availability(s, id);

	s.remove(id).wait();

	print_read_recovery_availability(s, id);

	sess.read_data(id, 0, 0).wait();

	print_read_recovery_availability(s, id);
}

void test_indexes(session &s)
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

	s.set_indexes(key, std::vector<std::string>(), std::vector<data_pointer>()).wait();
	s.set_indexes(key, indexes, data).wait();

	sleep(1);

	sync_find_indexes_result all_result = s.find_all_indexes(indexes);

	sleep(1);

	sync_find_indexes_result any_result = s.find_any_indexes(indexes);

	assert(all_result.size() == any_result.size());
	assert(all_result.size() == 1);
	assert(all_result[0].indexes.size() == any_result[0].indexes.size());
	assert(all_result[0].indexes.size() == indexes.size());
}

static void memory_test(session &s)
{
	struct rusage start, end;

	getrusage(RUSAGE_SELF, &start);
	memory_test_io(s, 1000);
	getrusage(RUSAGE_SELF, &end);
	std::cerr << "IO leaked: " << end.ru_maxrss - start.ru_maxrss << " Kb\n";
}

void usage(char *p)
{
	fprintf(stderr, "Usage: %s <options>\n"
			"  -r host              - remote host name\n"
			"  -p port              - remote port\n"
			"  -g group_id          - group_id for range request and bulk write\n"
			"  -w                   - write cache before read\n"
			"  -m                   - start client's memory leak test (rather long - several minutes, and space consuming)\n"
			, p);
	exit(-1);
}

int main(int argc, char *argv[])
{
	int g[] = { 2 };
	std::vector<int> groups(g, g+ARRAY_SIZE(g));
	const char *host = "localhost";
	int port = 1025;
	int ch, write_cache = 0;
	int mem_check = 0;
	int group_id = 2;

	while ((ch = getopt(argc, argv, "mr:p:g:wh")) != -1) {
		switch (ch) {
			case 'r':
				host = optarg;
				break;
			case 'p':
				port = atoi(optarg);
				break;
			case 'g':
				group_id = atoi(optarg);
				break;
			case 'w':
				write_cache = 1;
				break;
			case 'm':
				mem_check = 1;
				break;
			case 'h':
			default:
				usage(argv[0]);
		}
	}


	try {
		file_logger log("/dev/stderr", DNET_LOG_DEBUG);

		node n(log);
		session s(n);
		s.set_groups(groups);


//		s.set_filter(all());
//		s.set_policy(session::at_least(5));

////		s.write_data(id, data, 0).connect(handler);
//		for (auto entry : s.write_data(id, data, 0)) {
//			...
//		}

		try {
			n.add_remote(host, port, AF_INET);
		} catch (...) {
			throw std::runtime_error("Could not add remote nodes, exiting");
		}

		test_indexes(s);

//		test_read_recovery(s);

		std::string str;
		str.assign(300, 'c');
		s.write_data(key("123"), str, 0).wait();

//		{
//			s.set_cflags(DNET_FLAGS_NOLOCK);
//			auto result = s.exec(NULL, "queue@test", data_pointer());
//			for (auto it = result.begin(); it != result.end(); ++it) {
//				auto result = *it;
//				if (result.error()) {
//					error_info error = result.error();
//					std::cout << dnet_server_convert_dnet_addr(result.address())
//						<< ": failed to process: \"" << error.message() << "\": " << error.code() << std::endl;
//				} else {
//					exec_context context = result.context();
//					if (context.is_null()) {
//						std::cout << dnet_server_convert_dnet_addr(result.address())
//							<< ": acknowledge" << std::endl;
//					} else {
//						std::cout << dnet_server_convert_dnet_addr(context.address())
//							<< ": " << context.event()
//							<< " \"" << context.data().to_string() << "\"" << std::endl;
//					}
//				}
//			}
//		}
//		return 0;

		test_range_request_2(s, 0, 255, group_id);
		test_range_request_2(s, 3, 14, group_id);
		test_range_request_2(s, 7, 3, group_id);

		test_lookup(s, groups);

		s.stat_log();

		s.set_ioflags(0);

		test_commit(s);

		test_prepare_commit(s, 0, 0);
		test_prepare_commit(s, 1, 0);
		test_prepare_commit(s, 0, 1);
		test_prepare_commit(s, 1, 1);

		const uint64_t cflags = s.get_cflags();
		test_range_request(s, 0, 0, 0, group_id);
		test_range_request(s, 0, 0, DNET_ATTR_SORT, group_id);
		test_range_request(s, 1, 0, 0, group_id);
		test_range_request(s, 0, 1, 0, group_id);
		s.set_cflags(cflags);

		test_append(s);
		test_read_write_offsets(s);
		test_cas(s);

		test_bulk_write(s);
		test_bulk_read(s);

		if (mem_check)
			memory_test(s);

		if (write_cache)
			test_cache_write(s, 1000);

		test_cache_write(s, 1000);
		test_cache_read(s, 1000);
		test_cache_delete(s, 1000);

		test_indexes(s);

//	} catch (const std::exception &e) {
//		std::cerr << "Error occurred : " << e.what() << std::endl;
//		return 1;
	} catch (int err) {
		std::cerr << "Error : " << err << std::endl;
		return 1;
	}
	return 0;
}
