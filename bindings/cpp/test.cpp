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

#include <elliptics/cppdef.h>

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

		int column = 0;

		s.write_prepare(key(remote, column), prepare_data, offset, total_size_to_reserve);
		offset += prepare_data.size();

		written += prepare_data;

		for (int i = 0; i < 3; ++i) {
			s.write_plain(key(remote, column), plain_data[i], offset);
			offset += plain_data[i].size();

			written += plain_data[i];
		}

		/* append data first so that subsequent written.size() call returned real size of the written data */
		written += commit_data;

		s.write_commit(key(remote, column), commit_data, offset, written.size());

		ret = s.read_data(key(remote, column), 0, 0)->file().to_string();
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

	struct dnet_id begin;
	memset(&begin, 0x13, sizeof(begin));
	begin.group_id = group_id;
	begin.type = 0;
	begin.id[number_index] = 0;

	struct dnet_id end = begin;
	end.id[number_index] = item_count;

	struct dnet_id id = begin;

	std::vector<std::string> data(item_count);

	for (size_t i = 0; i < data.size(); ++i) {
		std::string &str = data[i];
		str.resize(5 + (rand() % 95));
		std::generate(str.begin(), str.end(), std::rand);

		id.id[number_index] = i;
		s.write_data(id, data[i], 0);
		read_result entry = s.read_data(id, group_id, 0, 0);
		if (entry->file().to_string() != str)
			throw_error(-EIO, id, "read_data_range_2: Write failed");
	}

	struct dnet_io_attr io;
	memset(&io, 0, sizeof(io));
	memcpy(io.id, begin.id, sizeof(io.id));
	memcpy(io.parent, end.id, sizeof(io.id));
	io.start = limit_start;
	io.num = limit_num;

	read_range_result result = s.read_data_range(io, group_id);

	if (int(result.size()) != std::min(limit_num, int(item_count) - limit_start)) {
		throw_error(-ENOENT, begin, "read_data_range_2: Received size: %d, expected: %d",
			int(result.size()), std::min(limit_num, int(item_count) - limit_start));
	}

	for (int i = 0; i < std::min(int(item_count) - limit_start, limit_num); ++i) {
		int index = i + limit_start;
		if (data[index] != result[i].file().to_string()) {
			throw_error(-ENOENT, begin, "read_data_range_2: Invalid data at %d of %d",
				i, limit_num);
		}
	}

	remove_range_result remove_result = s.remove_data_range(io, group_id);
	int removed = 0;
	for (size_t i = 0; i < remove_result.size(); ++i)
		removed += remove_result[i].io_attribute()->num;

	if (removed != int(item_count)) {
		throw_error(-EIO, begin, "read_data_range_2: Failed to remove data, expected items: %d, found: %d",
			int(result.size()), removed);
	}
	removed = 0;
	try {
		remove_result = s.remove_data_range(io, group_id);
		for (size_t i = 0; i < remove_result.size(); ++i)
			removed += remove_result[i].io_attribute()->num;
	} catch (...) {
	}
	if (removed != 0) {
		throw_error(-EIO, begin, "read_data_range_2: Failed to remove no data, expected items: 0, found: %d",
			 removed);
	}
}

static void test_lookup_parse(const std::string &key,
	struct dnet_cmd *cmd, struct dnet_addr_attr *a, const char *path)
{
	std::cerr << key << ": lives on addr: " << dnet_server_convert_dnet_addr(&a->addr);

	if (cmd->size > sizeof(struct dnet_addr_attr)) {
		struct dnet_file_info *info = (struct dnet_file_info *)(a + 1);

		dnet_convert_file_info(info);
		std::cerr << ": mode: " << std::oct << info->mode << std::dec;
		std::cerr << ", offset: " << (unsigned long long)info->offset;
		std::cerr << ", size: " << (unsigned long long)info->size;
		std::cerr << ", file: " << path;
	}
	std::cerr << std::endl;
}

static void test_lookup_parse(const std::string &key, const lookup_result &lret)
{
	test_lookup_parse(key, lret->command(), lret->address_attribute(), lret->file_path());
}

static void test_lookup(session &s, std::vector<int> &groups)
{
	try {
		std::string key = "2.xml";
		std::string data = "lookup data";

		write_result lret = s.write_data(key, data, 0);
		test_lookup_parse(key, lret[0]);

		struct dnet_id id;
		s.transform(key, id);
		id.group_id = 0;
		id.type = 0;

		struct timespec ts = {0, 0};
		s.write_metadata(id, key, groups, ts);

		lookup_result lret2 = s.lookup(key);
		test_lookup_parse(key, lret2);
	} catch (const std::exception &e) {
		std::cerr << "LOOKUP test failed: " << e.what() << std::endl;
		throw;
	}
}

static void test_append(session &s)
{
	try {
		std::string remote = "append-test";
		std::string data = "first part of the message";

		s.write_data(remote, data, 0);

		data = "| second part of the message";
		s.set_ioflags(DNET_IO_FLAGS_APPEND);
		s.write_data(remote, data, 0);
		s.set_ioflags(0);

		std::cerr << remote << ": " << s.read_data(remote, 0, 0)->file().to_string() << std::endl;
	} catch (const std::exception &e) {
		std::cerr << "APPEND test failed: " << e.what() << std::endl;
		throw std::runtime_error("APPEND test failed");
	}
}

static void read_column_raw(session &s, const std::string &remote, const std::string &data, int column)
{
	read_result ret;
	try {
		ret = s.read_data(key(remote, column), 0, 0);
	} catch (const std::exception &e) {
		std::cerr << "COLUMN-" << column << " read test failed: " << e.what() << std::endl;
		throw;
	}
	std::string ret_str = ret->file().to_string();

	std::cerr << "read-column-" << column << ": " << remote << " : " << ret_str << std::endl;
	if (ret_str != data) {
		throw std::runtime_error("column test failed");
	}
}

static void column_test(session &s)
{
	std::string remote = "some-key-1";

	std::string data0 = "some-compressed-data-in-column-0";
	std::string data1 = "some-data-in-column-2";
	std::string data2 = "some-data-in-column-3";

	s.set_ioflags(DNET_IO_FLAGS_COMPRESS);
	s.write_data(key(remote, 0), data0, 0);
	s.set_ioflags(0);

	s.write_data(key(remote, 2), data1, 0);
	s.write_data(key(remote, 3), data2, 0);

	read_column_raw(s, remote, data0, 0);
	read_column_raw(s, remote, data1, 2);
	read_column_raw(s, remote, data2, 3);
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
			io.type = id.type;
			io.size = os.str().size();

			ios.push_back(io);
			data.push_back(os.str());
		}

		write_result ret = s.bulk_write(ios, data);

		std::cerr << "BULK WRITE:" << std::endl;
		std::cerr << "ret size = " << ret.size() << std::endl;

		s.set_ioflags(DNET_IO_FLAGS_NOCSUM);
		int type = 0;

		uint64_t offset = 0;
		uint64_t size = 0;

		/* read without checksums since we did not write metadata */
		for (i = 0; i < BulkTestCount; ++i) {
			std::ostringstream os;

			os << "bulk_write" << i;
			std::cerr << os.str() << ": " << s.read_data(key(os.str(), type), offset, size)->file().to_string() << std::endl;
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

		bulk_read_result ret = s.bulk_read(keys);

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
		write_result written;

		try {
			written = s.write_data(id, data, 0);
			std::string res = s.read_data(id, 0, 0)->file().to_string();
		} catch (const std::exception &e) {
			std::cerr << "could not perform read/write: " << e.what() << std::endl;
			if (!written.exception()) {
				std::cerr << "but written successfully\n";
				test_lookup_parse(id, written[0]);
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
			io.type = id.type;
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

		int type = 0;

		uint64_t offset = 0;
		uint64_t size = 0;

		s.set_ioflags(DNET_IO_FLAGS_NOCSUM);
		try {
			s.read_data(key(id, type), offset, size)->file().to_string();
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
			s.remove(id);
		} catch (const std::exception &e) {
			std::cerr << "could not perform remove: " << e.what() << std::endl;
			throw;
		}
		count++;
	}
	std::cerr << "Cache entries deleted: " << count << std::endl;
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
	int g[] = {1, 2, 3};
	std::vector<int> groups(g, g+ARRAY_SIZE(g));
	char *host = (char *)"localhost";
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

		try {
			n.add_remote(host, port, AF_INET);
		} catch (...) {
			throw std::runtime_error("Could not add remote nodes, exiting");
		}

		test_range_request_2(s, 0, 255, group_id);
		test_range_request_2(s, 3, 14, group_id);
		test_range_request_2(s, 7, 3, group_id);

		test_lookup(s, groups);

		s.stat_log();

		column_test(s);
		s.set_ioflags(0);

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

		test_bulk_write(s);
		test_bulk_read(s);

		if (mem_check)
			memory_test(s);

		if (write_cache)
			test_cache_write(s, 1000);

		test_cache_write(s, 1000);
		test_cache_read(s, 1000);
		test_cache_delete(s, 1000);

	} catch (const std::exception &e) {
		std::cerr << "Error occured : " << e.what() << std::endl;
		return 1;
	} catch (int err) {
		std::cerr << "Error : " << err << std::endl;
		return 1;
	}
	return 0;
}
