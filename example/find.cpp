/*
 * 2011+ Copyright (c) Evgeniy Polyakov <zbr@ioremap.net>
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

#define _XOPEN_SOURCE 600

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <sys/wait.h>

#include <errno.h>
#include <ctype.h>
#include <dirent.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sstream>
#include <stdexcept>

#include "elliptics/interface.h"
#include "elliptics/packet.h"
#include "elliptics/cppdef.h"

#include "common.h"

using namespace ioremap::elliptics;

class finder : public node {
	public:
		finder(logger &log) : node(log) {};
		finder(logger &log, struct dnet_config &cfg) : node(log, cfg) {};
		virtual ~finder() {};

		void add_remote(const char *addr);

		void parse_lookup(const std::string &ret);
		void parse_meta(const std::string &ret);
};

void finder::add_remote(const char *addr)
{
	struct dnet_config rem;
	int err;

	memset(&rem, 0, sizeof(rem));

	err = dnet_parse_addr((char *)addr, &rem);
	if (err < 0) {
		std::ostringstream str;
		str << "Failed to parse addr: " << addr;
		throw std::runtime_error(str.str());
	}

	node::add_remote(rem.addr, atoi(rem.port), rem.family);
}

void finder::parse_lookup(const std::string &ret)
{
	long size = ret.size();
	void *data = (void *)ret.data();

	while (size) {
		struct dnet_addr *addr = (struct dnet_addr *)data;
		struct dnet_cmd *cmd = (struct dnet_cmd *)(addr + 1);

		if (cmd->size) {
			struct dnet_file_info *info = NULL;
			char addr_str[128] = "no-address";

			if (cmd->size >= sizeof(struct dnet_addr_attr)) {
				struct dnet_addr_attr *a = (struct dnet_addr_attr *)(cmd + 1);

				if (cmd->size > sizeof(struct dnet_addr_attr) + sizeof(struct dnet_file_info)) {
					info = (struct dnet_file_info *)(a + 1);
					dnet_convert_file_info(info);
				}

				dnet_convert_addr_attr(a);
				dnet_server_convert_dnet_addr_raw(&a->addr, addr_str, sizeof(addr_str));
			}

			std::string route_addr = "failed to get route table";

			try {
				route_addr = lookup_addr(cmd->id);
			} catch (const std::exception &e) {
			}

			if (!info)
				dnet_log_raw(m_node, DNET_LOG_DATA, "%s: FIND object: %s: should live at: %s\n",
					dnet_dump_id(&cmd->id), addr_str, route_addr.c_str());
			else
				dnet_log_raw(m_node, DNET_LOG_DATA, "%s: FIND-OK object: %s: should live at: %s, "
						"offset: %llu, size: %llu, mode: %llo, path: %s\n",
					dnet_dump_id(&cmd->id), addr_str, route_addr.c_str(),
					(unsigned long long)info->offset, (unsigned long long)info->size,
					(unsigned long long)info->mode, (char *)(info + 1));
		} else {
			if (cmd->status != 0)
				dnet_log_raw(m_node, DNET_LOG_DATA, "%s: FIND object: status: %d\n", dnet_dump_id(&cmd->id), cmd->status);
		}

		data = (char *)data + sizeof(struct dnet_addr) + sizeof(struct dnet_cmd) + cmd->size;
		size -= sizeof(struct dnet_addr) + sizeof(struct dnet_cmd) + cmd->size;
	}
}

void finder::parse_meta(const std::string &ret)
{
	long size = ret.size();
	void *data = (void *)ret.data();

	while (size) {
		struct dnet_addr *addr = (struct dnet_addr *)data;
		struct dnet_cmd *cmd = (struct dnet_cmd *)(addr + 1);
		char addr_str[128];

		dnet_server_convert_dnet_addr_raw(addr, addr_str, sizeof(addr_str));

		if (cmd->size > sizeof(struct dnet_io_attr)) {
			struct dnet_io_attr *io = (struct dnet_io_attr *)(cmd + 1);

			dnet_convert_io_attr(io);

			dnet_log_raw(m_node, DNET_LOG_DATA, "%s: FIND-OK meta: %s: cmd: %s, io size: %llu\n",
					dnet_dump_id(&cmd->id), addr_str, dnet_cmd_string(cmd->cmd),
					(unsigned long long)io->size);

			struct dnet_meta_container mc;
			memset(&mc, 0, sizeof(mc));
			mc.data = io + 1;
			mc.size = io->size;

			memcpy(&mc.id, &cmd->id, sizeof(struct dnet_id));
			dnet_meta_print(m_node, &mc);
		} else {
			if (cmd->status != 0)
				dnet_log_raw(m_node, DNET_LOG_DATA, "%s: FIND meta: %s: status: %d\n",
						dnet_dump_id(&cmd->id), addr_str, cmd->status);
		}

		data = (char *)data + sizeof(struct dnet_addr) + sizeof(struct dnet_cmd) + cmd->size;
		size -= sizeof(struct dnet_addr) + sizeof(struct dnet_cmd) + cmd->size;
	}
}

static __attribute__ ((noreturn)) void efinder_usage(const char *p)
{
	fprintf(stderr, "Usage: %s <options>\n"
			"  -r addr:port:family            - remote node to connect\n"
			"  -l log                         - log file\n"
			"  -m mask                        - log mask\n"
			"  -I id                          - object ID\n"
			"  -h                             - this help\n"
			, p);
	exit(-1);
}

int main(int argc, char *argv[])
{
	int ch, err;
	char *logfile = (char *)"/dev/stderr";
	int log_mask = DNET_LOG_ERROR | DNET_LOG_DATA;
	char *remote = NULL;
	struct dnet_id raw;
	struct dnet_trans_control ctl;

	while ((ch = getopt(argc, argv, "r:l:m:I:h")) != -1) {
		switch (ch) {
			case 'r':
				remote = optarg;
				break;
			case 'l':
				logfile = optarg;
				break;
			case 'm':
				log_mask = strtoul(optarg, NULL, 0);
				break;
			case 'I':
				err = dnet_parse_numeric_id(optarg, raw.id);
				if (err < 0)
					return err;
				break;
			case 'h':
			default:
				efinder_usage(argv[0]);

		}
	}

	if (!remote) {
		fprintf(stderr, "You must specify remote addr and object ID\n");
		efinder_usage(argv[0]);
	}

	try {
		log_file log(logfile, log_mask);
		finder find(log);

		find.add_remote(remote);

		{
			callback c;

			memset(&ctl, 0, sizeof(struct dnet_trans_control));

			ctl.priv = (void *)&c;
			ctl.complete = callback::complete_callback;

			dnet_setup_id(&ctl.id, 0, raw.id);
			ctl.cflags = DNET_FLAGS_DIRECT | DNET_FLAGS_NEED_ACK | DNET_ATTR_META_TIMES;
			ctl.cmd = DNET_CMD_LOOKUP;

			int num = find.request_cmd(ctl);
			std::string lookup_ret = c.wait(num);
			find.parse_lookup(lookup_ret);
		}



		{
			callback c;

			memset(&ctl, 0, sizeof(ctl));

			ctl.priv = (void *)&c;
			ctl.complete = callback::complete_callback;

			dnet_setup_id(&ctl.id, 0, raw.id);
			ctl.cmd = DNET_CMD_READ;
			ctl.cflags = DNET_FLAGS_DIRECT | DNET_FLAGS_NEED_ACK;

			struct dnet_io_attr io;
			memset(&io, 0, sizeof(io));
			io.flags = DNET_IO_FLAGS_META;
			memcpy(io.id, ctl.id.id, DNET_ID_SIZE);
			memcpy(io.parent, ctl.id.id, DNET_ID_SIZE);
			ctl.data = &io;
			ctl.size = sizeof(io);

			int num = find.request_cmd(ctl);
			std::string meta_ret = c.wait(num);
			find.parse_meta(meta_ret);
		}
	} catch (const std::exception &e) {
		std::cerr << e.what() << std::endl;
	}

	return 0;
}

