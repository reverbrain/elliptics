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

#include "config.h"

#include <errno.h>
#include <stdarg.h>
#include <string.h>

#include <fstream>

#include "elliptics/cppdef.h"

using namespace zbr;

static void test_log_raw(elliptics_log *l, uint32_t mask, const char *format, ...)
{
	va_list args;
	char buf[1024];
	int buflen = sizeof(buf);

	if (!(l->get_log_mask() & mask))
		return;

	va_start(args, format);
	vsnprintf(buf, buflen, format, args);
	buf[buflen-1] = '\0';
	l->log(mask, buf);
	va_end(args);
}

class elliptics_callback_io : public elliptics_callback {
	public:
		elliptics_callback_io(elliptics_log *l) { log = l; };
		virtual ~elliptics_callback_io() {};

		virtual int		callback(struct dnet_net_state *state, struct dnet_cmd *cmd, struct dnet_attr *attr);

	private:
		elliptics_log		*log;
};

int elliptics_callback_io::callback(struct dnet_net_state *state, struct dnet_cmd *cmd, struct dnet_attr *attr)
{
	int err;
	struct dnet_io_attr *io;
	void *data;

	if (is_trans_destroyed(state, cmd, attr)) {
		err = -EINVAL;
		goto err_out_exit;
	}

	if (cmd->status || !cmd->size) {
		err = cmd->status;
		goto err_out_exit;
	}

	if (cmd->size <= sizeof(struct dnet_attr) + sizeof(struct dnet_io_attr)) {
		test_log_raw(log, DNET_LOG_ERROR, "%s: read completion error: wrong size: "
				"cmd_size: %llu, must be more than %zu.\n",
				dnet_dump_id(&cmd->id), (unsigned long long)cmd->size,
				sizeof(struct dnet_attr) + sizeof(struct dnet_io_attr));
		err = -EINVAL;
		goto err_out_exit;
	}

	if (!attr) {
		test_log_raw(log, DNET_LOG_ERROR, "%s: no attributes but command size is not null.\n",
				dnet_dump_id(&cmd->id));
		err = -EINVAL;
		goto err_out_exit;
	}

	io = (struct dnet_io_attr *)(attr + 1);
	data = io + 1;

	dnet_convert_io_attr(io);
	err = 0;

	test_log_raw(log, DNET_LOG_INFO, "%s: io completion: offset: %llu, size: %llu.\n",
			dnet_dump_id(&cmd->id), (unsigned long long)io->offset, (unsigned long long)io->size);

err_out_exit:
	if (!cmd || !(cmd->flags & DNET_FLAGS_MORE))
		test_log_raw(log, DNET_LOG_INFO, "%s: io completed: %d.\n", cmd ? dnet_dump_id(&cmd->id) : "nil", err);
	return err;
}

static void test_prepare_commit(elliptics_node &n, int psize, int csize)
{
	std::string key = "prepare-commit-test";

	std::string prepare_data = "prepare data|";
	std::string commit_data = "commit data";
	std::string plain_data[3] = {"plain data0|", "plain data1|", "plain data2|"};

	if (psize)
		prepare_data.clear();
	if (csize)
		commit_data.clear();

	uint64_t offset = 0;
	uint64_t total_size_to_reserve = 1024;

	/* we did not write metadata, so do not try to read checksums */
	unsigned int aflags = DNET_ATTR_NOCSUM;
	unsigned int ioflags = 0;

	int column = 0;

	n.write_prepare(key, prepare_data, offset, total_size_to_reserve, aflags, ioflags, column);
	offset += prepare_data.size();

	for (int i = 0; i < 3; ++i) {
		n.write_plain(key, plain_data[i], offset, aflags, ioflags, column);
		offset += plain_data[i].size();
	}

	n.write_commit(key, commit_data, offset, 0, aflags, ioflags, column);

	std::cout << "prepare/commit read: " << n.read_data_wait(key, 0, 0, aflags, ioflags, column) << std::endl;
}

static void test_range_request(elliptics_node &n, int limit_start, int limit_num, unsigned int aflags)
{
	struct dnet_io_attr io;
	char id_str[DNET_ID_SIZE * 2 + 1];

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

	int group_id = 2;

	std::vector<std::string> ret;
	ret = n.read_data_range(io, group_id, aflags);

	for (size_t i = 0; i < ret.size(); ++i) {
		const char *data = ret[i].data();
		const unsigned char *id = (const unsigned char *)data;
		uint64_t size = dnet_bswap64(*(uint64_t *)(data + DNET_ID_SIZE));
		char *str = (char *)(data + DNET_ID_SIZE + 8);

		std::cout << "range [LIMIT(" << limit_start << ", " << limit_num << "): " <<
			dnet_dump_id_len_raw(id, DNET_ID_SIZE, id_str) << ": size: " << size << ": " << str << std::endl;
	}
}

static void test_lookup_parse(const std::string &key, const std::string &lret)
{
	struct dnet_addr *addr = (struct dnet_addr *)lret.data();
	struct dnet_cmd *cmd = (struct dnet_cmd *)(addr + 1);
	struct dnet_attr *attr = (struct dnet_attr *)(cmd + 1);
	struct dnet_addr_attr *a = (struct dnet_addr_attr *)(attr + 1);

	dnet_convert_addr_attr(a);
	std::cout << key << ": lives on addr: " << dnet_server_convert_dnet_addr(&a->addr);

	if (attr->size > sizeof(struct dnet_addr_attr)) {
		struct dnet_file_info *info = (struct dnet_file_info *)(a + 1);

		dnet_convert_file_info(info);
		std::cout << ": mode: " << std::oct << info->mode << std::dec;
		std::cout << ", offset: " << (unsigned long long)info->offset;
		std::cout << ", size: " << (unsigned long long)info->size;
		std::cout << ", file: " << (char *)(info + 1);
	}
	std::cout << std::endl;
}

static void test_lookup(elliptics_node &n, std::vector<int> &groups)
{
	std::string key = "2.xml";
	std::string data = "lookup data";

	std::string lret = n.write_data_wait(key, data, 0, 0, 0, 0);
	test_lookup_parse(key, lret);

	struct dnet_id id;
	n.transform(key, id);
	id.group_id = 0;
	id.type = 0;

	struct timespec ts = {0, 0};
	n.write_metadata(id, key, groups, ts);

	try {
		lret = n.lookup(key);
		test_lookup_parse(key, lret);
	} catch (const std::exception &e) {
		std::cerr << key << ": LOOKUP failed" << std::endl;
	}
}

static void test_append(elliptics_node &n)
{
	std::string key = "append-test";
	std::string data = "first part of the message";

	n.write_data_wait(key, data, 0, 0, 0, 0);

	data = "| second part of the message";
	n.write_data_wait(key, data, 0, 0, DNET_IO_FLAGS_APPEND, 0);

	std::cout << key << ": " << n.read_data_wait(key, 0, 0, 0, 0, 0) << std::endl;
}

int main()
{
	int g[] = {1, 2, 3};
	std::vector<int> groups(g, g+ARRAY_SIZE(g));

	try {
		elliptics_log_file log("/dev/stderr", DNET_LOG_ERROR | DNET_LOG_DATA);

		elliptics_node n(log);
		n.add_groups(groups);

		int ports[] = {1025, 1026};
		int added = 0;

		for (int i = 0; i < (int)ARRAY_SIZE(ports); ++i) {
			try {
				n.add_remote("localhost", ports[i], AF_INET);
				added++;
			} catch (...) {
			}
		}

		if (!added)
			throw std::runtime_error("Could not add remote nodes, exiting");

		test_lookup(n, groups);

		n.stat_log();

		std::string key = "some-key-1";

		std::string data0 = "some-compressed-data-in-column-0";
		std::string data1 = "some-data-in-column-2";
		std::string data2 = "some-data-in-column-3";

		n.write_data_wait(key, data0, 0, 0, DNET_IO_FLAGS_COMPRESS, 0);
		n.write_data_wait(key, data1, 0, 0, 0, 2);
		n.write_data_wait(key, data2, 0, 0, 0, 3);

		std::cout << "read-column-0: " << key << " : " << n.read_data_wait(key, 0, 0, 0, 0, 0) << std::endl;
		/* columns should be read without checksums, since we do not update metadata for them */
		std::cout << "read-column-2: " << key << " : " << n.read_data_wait(key, 0, 0, DNET_ATTR_NOCSUM, 0, 2) << std::endl;
		std::cout << "read-column-3: " << key << " : " << n.read_data_wait(key, 0, 0, DNET_ATTR_NOCSUM, 0, 3) << std::endl;

		test_prepare_commit(n, 0, 0);
		test_prepare_commit(n, 1, 0);
		test_prepare_commit(n, 0, 1);
		test_prepare_commit(n, 1, 1);

		test_range_request(n, 0, 0, 0);
		test_range_request(n, 0, 0, DNET_ATTR_SORT);
		test_range_request(n, 1, 0, 0);
		test_range_request(n, 0, 1, 0);

		test_append(n);
	} catch (const std::exception &e) {
		std::cerr << "Error occured : " << e.what() << std::endl;
	} catch (int err) {
		std::cerr << "Error : " << err << std::endl;
	}
}
