/*
 * 2011+ Copyright (c) Evgeniy Polyakov <zbr@ioremap.net>
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
#include <iostream>

#include "elliptics/interface.h"
#include "elliptics/packet.h"
#include "elliptics/cppdef.h"

#include "common.h"

using namespace ioremap::elliptics;

class finder : public session {
	public:
		finder(node &n) : session(n) {}
		virtual ~finder() {}

		void parse_lookup(const sync_generic_result &ret);
};

void finder::parse_lookup(const sync_generic_result &ret)
{
	for (size_t i = 0; i < ret.size(); ++i) {
		const callback_result_entry &data = ret[i];
		struct dnet_cmd *cmd = data.command();

		if (data.size()) {
			struct dnet_file_info *info = NULL;
			char addr_str[128] = "no-address";
			int backend_id = cmd->backend_id;

			if (data.size() >= sizeof(struct dnet_addr)) {
				struct dnet_addr *addr = data.data<struct dnet_addr>();

				if (cmd->size >= sizeof(struct dnet_addr) + sizeof(struct dnet_file_info)) {
					info = (struct dnet_file_info *)(addr + 1);
					dnet_convert_file_info(info);
				}

				dnet_convert_addr(addr);
				dnet_addr_string_raw(addr, addr_str, sizeof(addr_str));
			}

			std::string route_addr = "failed to get route table";

			try {
				int tmp_backend_id = 0;
				dnet_net_state *st = dnet_state_get_first_with_backend(get_native_node(), &cmd->id, &tmp_backend_id);

				if (st) {
					dnet_addr addr = *dnet_state_addr(st);
					dnet_state_put(st);

					std::string tmp = dnet_addr_string(&addr);
					tmp += ", backend: ";
					tmp += std::to_string(static_cast<long long int>(tmp_backend_id));
					std::swap(route_addr, tmp);
				}
			} catch (const std::exception &) {
			}

			if (!info) {
				printf("%s: FIND object: %s, backend: %d: should live at: %s\n",
					dnet_dump_id(&cmd->id), addr_str, backend_id, route_addr.c_str());
			} else {
				char tstr[64];
				struct tm tm;

				localtime_r((time_t *)&info->mtime.tsec, &tm);
				strftime(tstr, sizeof(tstr), "%F %R:%S %Z", &tm);

				printf("%s: FIND-OK object: %s, backend: %d, should live at: %s, "
						"offset: %llu, size: %llu, mtime: %s, path: %s\n",
					dnet_dump_id(&cmd->id), addr_str, backend_id, route_addr.c_str(),
					(unsigned long long)info->offset, (unsigned long long)info->size,
					tstr, (char *)(info + 1));
			}
		} else {
			if (cmd->status != 0)
				printf("%s: FIND object: status: %d\n",
						dnet_dump_id(&cmd->id), cmd->status);
		}
		fflush(stdout);
	}
}

static __attribute__ ((noreturn)) void efinder_usage(const char *p)
{
	fprintf(stderr, "Usage: %s <options>\n"
			"  -r addr:port:family            - remote node to connect\n"
			"  -l log                         - log file\n"
			"  -m level                       - log level\n"
			"  -I id                          - object ID\n"
			"  -h                             - this help\n"
			, p);
	exit(-1);
}

int main(int argc, char *argv[])
{
	int ch, err;
	const char *logfile = "/dev/stderr";
	dnet_log_level log_level = DNET_LOG_ERROR;
	char *remote = NULL;
	struct dnet_id raw;
	memset(&raw, 0, sizeof(struct dnet_id));

	try {
		while ((ch = getopt(argc, argv, "r:l:m:I:h")) != -1) {
			switch (ch) {
				case 'r':
					remote = optarg;
					break;
				case 'l':
					logfile = optarg;
					break;
				case 'm':
					log_level = file_logger::parse_level(optarg);
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

		file_logger log(logfile, log_level);
		node n(logger(log, blackhole::log::attributes_t()));
		finder find(n);

		n.add_remote(remote);

		{
			transport_control ctl(raw, DNET_CMD_LOOKUP,
				DNET_FLAGS_DIRECT | DNET_FLAGS_DIRECT_BACKEND | DNET_FLAGS_NEED_ACK);

			sync_generic_result results = find.request_cmd(ctl);
			find.parse_lookup(results);
		}
	} catch (const std::exception &e) {
		std::cerr << e.what() << std::endl;
	}

	return 0;
}

