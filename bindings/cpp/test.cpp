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

#include <errno.h>
#include <stdarg.h>
#include <string.h>

#include <sstream>
#include <fstream>

#include <elliptics/cppdef.h>

using namespace ioremap::elliptics;

static void test_log_raw(logger *l, int level, const char *format, ...)
{
	va_list args;
	char buf[1024];
	int buflen = sizeof(buf);

	if (l->get_log_level() < level)
		return;

	va_start(args, format);
	vsnprintf(buf, buflen, format, args);
	buf[buflen-1] = '\0';
	l->log(level, buf);
	va_end(args);
}

class callback_io : public callback {
	public:
		callback_io(logger *l) { log = l; }
		virtual ~callback_io() {}

		virtual void		handle(struct dnet_net_state *state, struct dnet_cmd *cmd);

	private:
		logger			*log;
};

void callback_io::handle(struct dnet_net_state *state, struct dnet_cmd *cmd)
{
	int err;
	struct dnet_io_attr *io;

	if (is_trans_destroyed(state, cmd)) {
		err = -EINVAL;
		goto err_out_exit;
	}

	if (cmd->status || !cmd->size) {
		err = cmd->status;
		goto err_out_exit;
	}

	if (cmd->size <= sizeof(struct dnet_io_attr)) {
		test_log_raw(log, DNET_LOG_ERROR, "%s: read completion error: wrong size: "
				"cmd_size: %llu, must be more than %zu.\n",
				dnet_dump_id(&cmd->id), (unsigned long long)cmd->size,
				sizeof(struct dnet_io_attr));
		err = -EINVAL;
		goto err_out_exit;
	}

	if (!cmd->size) {
		test_log_raw(log, DNET_LOG_ERROR, "%s: no attributes but command size is not null.\n",
				dnet_dump_id(&cmd->id));
		err = -EINVAL;
		goto err_out_exit;
	}

	io = (struct dnet_io_attr *)(cmd + 1);

	dnet_convert_io_attr(io);
	err = 0;

	test_log_raw(log, DNET_LOG_INFO, "%s: io completion: offset: %llu, size: %llu.\n",
			dnet_dump_id(&cmd->id), (unsigned long long)io->offset, (unsigned long long)io->size);

err_out_exit:
	if (!cmd || !(cmd->flags & DNET_FLAGS_MORE))
		test_log_raw(log, DNET_LOG_INFO, "%s: io completed: %d.\n", cmd ? dnet_dump_id(&cmd->id) : "nil", err);
//	return err;
}

static void test_prepare_commit(session &s, int psize, int csize)
{
	std::string written, ret;
	try {
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

		ret = s.read_data_wait(key(remote, column), 0, 0);
		std::cout << "prepare/commit write: '" << written << "', read: '" << ret << "'" << std::endl;
	} catch (const std::exception &e) {
		std::cerr << "PREPARE/COMMIT test failed: " << e.what() << std::endl;
		throw;
	}

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
	ret = s.read_data_range(io, group_id);

	std::cout << "range [LIMIT(" << limit_start << ", " << limit_num << "): " << ret.size() << " elements" << std::endl;
#if 0
	for (size_t i = 0; i < ret.size(); ++i) {
		char id_str[DNET_ID_SIZE * 2 + 1];
		const char *data = ret[i].data();
		const unsigned char *id = (const unsigned char *)data;
		uint64_t size = dnet_bswap64(*(uint64_t *)(data + DNET_ID_SIZE));
		char *str = (char *)(data + DNET_ID_SIZE + 8);

		std::cout << "range [LIMIT(" << limit_start << ", " << limit_num << "): " <<
			dnet_dump_id_len_raw(id, DNET_ID_SIZE, id_str) << ": size: " << size << ": " << str << std::endl;
	}
#endif
}

static void test_lookup_parse(const std::string &key, const std::string &lret)
{
	struct dnet_addr *addr = (struct dnet_addr *)lret.data();
	struct dnet_cmd *cmd = (struct dnet_cmd *)(addr + 1);
	struct dnet_addr_attr *a = (struct dnet_addr_attr *)(cmd + 1);

	dnet_convert_addr_attr(a);
	std::cout << key << ": lives on addr: " << dnet_server_convert_dnet_addr(&a->addr);

	if (cmd->size > sizeof(struct dnet_addr_attr)) {
		struct dnet_file_info *info = (struct dnet_file_info *)(a + 1);

		dnet_convert_file_info(info);
		std::cout << ": mode: " << std::oct << info->mode << std::dec;
		std::cout << ", offset: " << (unsigned long long)info->offset;
		std::cout << ", size: " << (unsigned long long)info->size;
		std::cout << ", file: " << (char *)(info + 1);
	}
	std::cout << std::endl;
}

static void test_lookup(session &s, std::vector<int> &groups)
{
	try {
		std::string key = "2.xml";
		std::string data = "lookup data";

		std::string lret = s.write_data_wait(key, data, 0);
		test_lookup_parse(key, lret);

		struct dnet_id id;
		s.transform(key, id);
		id.group_id = 0;
		id.type = 0;

		struct timespec ts = {0, 0};
		s.write_metadata(id, key, groups, ts);

		lret = s.lookup(key);
		test_lookup_parse(key, lret);
	} catch (const std::exception &e) {
		std::cerr << "LOOKUP test failed: " << e.what() << std::endl;
	}
}

static void test_append(session &s)
{
	try {
		std::string remote = "append-test";
		std::string data = "first part of the message";

		s.write_data_wait(remote, data, 0);

		data = "| second part of the message";
		s.set_ioflags(DNET_IO_FLAGS_APPEND);
		s.write_data_wait(remote, data, 0);
		s.set_ioflags(0);

		std::cout << remote << ": " << s.read_data_wait(remote, 0, 0) << std::endl;
	} catch (const std::exception &e) {
		std::cerr << "APPEND test failed: " << e.what() << std::endl;
		throw std::runtime_error("APPEND test failed");
	}
}

static void read_column_raw(session &s, const std::string &remote, const std::string &data, int column)
{
	std::string ret;
	try {
		ret = s.read_data_wait(key(remote, column), 0, 0);
	} catch (const std::exception &e) {
		std::cerr << "COLUMN-" << column << " read test failed: " << e.what() << std::endl;
		throw;
	}

	std::cout << "read-column-" << column << ": " << remote << " : " << ret << std::endl;
	if (ret != data) {
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
	s.write_data_wait(key(remote, 0), data0, 0);
	s.set_ioflags(0);

	s.write_data_wait(key(remote, 2), data1, 0);
	s.write_data_wait(key(remote, 3), data2, 0);

	read_column_raw(s, remote, data0, 0);
	read_column_raw(s, remote, data1, 2);
	read_column_raw(s, remote, data2, 3);
}

static void test_bulk_write(session &s)
{
	try {
		std::vector<struct dnet_io_attr> ios;
		std::vector<std::string> data;

		int i;

		for (i = 0; i < 3; ++i) {
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

		std::string ret = s.bulk_write(ios, data);

		std::cout << "ret size = " << ret.size() << std::endl;

		s.set_ioflags(DNET_IO_FLAGS_NOCSUM);
		int type = 0;

		uint64_t offset = 0;
		uint64_t size = 0;

		/* read without checksums since we did not write metadata */
		for (i = 0; i < 3; ++i) {
			std::ostringstream os;

			os << "bulk_write" << i;
			std::cout << os.str() << ": " << s.read_data_wait(key(os.str(), type), offset, size) << std::endl;
		}
	} catch (const std::exception &e) {
		std::cerr << "BULK WRITE test failed: " << e.what() << std::endl;
	}
	s.set_ioflags(0);
}

static void test_bulk_read(session &s)
{
	try {
		std::vector<std::string> keys;

		int i;

		for (i = 0; i < 3; ++i) {
			std::ostringstream os;
			os << "bulk_write" << i;
			keys.push_back(os.str());
		}

		std::vector<std::string> ret = s.bulk_read(keys);

		std::cout << "ret size = " << ret.size() << std::endl;

		/* read without checksums since we did not write metadata */
		for (i = 0; i < 3; ++i) {
			std::ostringstream os;

			os << "bulk_read" << i;
			std::cout << os.str() << ": " << ret[i].substr(DNET_ID_SIZE + 8) << std::endl;
		}
	} catch (const std::exception &e) {
		std::cerr << "BULK READ test failed: " << e.what() << std::endl;
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
		std::string written;

		try {
			written = s.write_data_wait(id, data, 0);
			std::string res = s.read_data_wait(id, 0, 0);
		} catch (const std::exception &e) {
			std::cerr << "could not perform read/write: " << e.what() << std::endl;
			if (written.size() > 0) {
				std::cerr << "but written successfully\n";
				test_lookup_parse(id, written);
			}
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
	}
	std::cout << "Cache entries writted: " << num << std::endl;
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
			s.read_data_wait(key(id, type), offset, size);
		} catch (const std::exception &e) {
			std::cerr << "could not perform read : " << e.what() << std::endl;
		}
		s.set_ioflags(0);
		count++;
	}
	std::cout << "Cache entries read: " << count << std::endl;
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
		}
		count++;
	}
	std::cout << "Cache entries deleted: " << count << std::endl;
}

static void memory_test(session &s)
{
	struct rusage start, end;

	getrusage(RUSAGE_SELF, &start);
	memory_test_io(s, 1000);
	getrusage(RUSAGE_SELF, &end);
	std::cout << "IO leaked: " << end.ru_maxrss - start.ru_maxrss << " Kb\n";
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

		test_cache_read(s, 1000);
		test_cache_delete(s, 1000);
		test_cache_write(s, 1000);

	} catch (const std::exception &e) {
		std::cerr << "Error occured : " << e.what() << std::endl;
	} catch (int err) {
		std::cerr << "Error : " << err << std::endl;
	}
}
