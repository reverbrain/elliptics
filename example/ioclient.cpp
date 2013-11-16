/*
 * 2008+ Copyright (c) Evgeniy Polyakov <zbr@ioremap.net>
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

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/syscall.h>

#include <ctype.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <iostream>

#include <netinet/in.h>

#include "elliptics/cppdef.h"
#include "elliptics/backends.h"

#include "common.h"

using namespace ioremap::elliptics;

#ifndef __unused
#define __unused	__attribute__ ((unused))
#endif

static void dnet_usage(char *p)
{
	fprintf(stderr, "Usage: %s\n"
			" -r addr:port:family  - adds a route to the given node\n"
			" -W file              - write given file to the network storage\n"
			" -s                   - request IO counter stats from node\n"
			" -z                   - request VFS IO stats from node\n"
			" -a                   - request stats from all connected nodes\n"
			" -U status            - update server status: 1 - elliptics exits, 2 - goes RO\n"
			" -R file              - read given file from the network into the local storage\n"
			" -I id                - transaction id (used to read data)\n"
			" -g groups            - group IDs to connect\n"
			" -c cmd-event         - execute event on a remote node\n"
			" -k src-key           - use this src_key with exec\n"
			" -L file              - lookup a storage which hosts given file\n"
			" -l log               - log file. Default: disabled\n"
			" -w timeout           - wait timeout in seconds used to wait for content sync.\n"
			" -m level             - log level\n"
			" -M level             - set new log level\n"
			" -F flags             - change node flags (see @cfg->flags comments in include/elliptics/interface.h)\n"
			" -O offset            - read/write offset in the file\n"
			" -S size              - read/write transaction size\n"
			" -u file              - unlink file\n"
			" -N namespace         - use this namespace for operations\n"
			" -D object            - read latest data for given object, if -I id is specified, this field is unused\n"
			" -C flags             - command flags\n"
			" -d request_string    - defragmentation request: 'start' - start defragmentation, 'status' - request current status\n"
			" -i flags             - IO flags (see DNET_IO_FLAGS_* in include/elliptics/packet.h\n"
			" -H                   - do not hash id, use it as is\n"
			" -h                   - this help\n"
			" ...                  - every parameter can be repeated multiple times, in this case the last one will be used\n"
			, p);
}

static key create_id(unsigned char *id, const char *file_name)
{
	if (id) {
		struct dnet_id raw;

		dnet_setup_id(&raw, 0, id);

		return raw;
	} else {
		return key(file_name);
	}
}

int main(int argc, char *argv[])
{
	int ch, err;
	int io_counter_stat = 0, vfs_stat = 0, single_node_stat = 1;
	struct dnet_node_status node_status;
	int update_status = 0;
	struct dnet_config cfg;
	char *remote_addr = NULL;
	int port = -1;
	int family = -1;
	int remote_flags = 0;
	const char *logfile = "/dev/stderr", *readf = NULL, *writef = NULL, *cmd = NULL, *lookup = NULL;
	const char *read_data = NULL;
	char *removef = NULL;
	unsigned char trans_id[DNET_ID_SIZE], *id = NULL;
	uint64_t offset, size;
	std::vector<int> groups;
	uint64_t cflags = 0;
	uint64_t ioflags = 0;
	char *defrag = NULL;
	sigset_t mask;
	char *ns = NULL;
	int nsize = 0;
	std::string as_is_key;
	int exec_src_key = -1;

	memset(&node_status, 0, sizeof(struct dnet_node_status));
	memset(&cfg, 0, sizeof(struct dnet_config));

	cfg.indexes_shard_count = 10;

	node_status.nflags = -1;
	node_status.status_flags = -1;
	node_status.log_level = ~0U;

	size = offset = 0;

	cfg.wait_timeout = 60;
	int log_level = DNET_LOG_ERROR;

	while ((ch = getopt(argc, argv, "i:d:C:A:F:M:N:g:u:O:S:m:zsU:aL:w:l:c:k:I:r:W:R:D:hH")) != -1) {
		switch (ch) {
			case 'i':
				ioflags = strtoull(optarg, NULL, 0);
				break;
			case 'd':
				defrag = optarg;
				break;
			case 'C':
				cflags = strtoull(optarg, NULL, 0);
				break;
			case 'F':
				node_status.nflags = strtol(optarg, NULL, 0);
				update_status = 1;
				break;
			case 'M':
				node_status.log_level = atoi(optarg);
				update_status = 1;
				break;
			case 'N':
				ns = optarg;
				nsize = strlen(optarg);
				break;
			case 'u':
				removef = optarg;
				break;
			case 'O':
				offset = strtoull(optarg, NULL, 0);
				break;
			case 'S':
				size = strtoull(optarg, NULL, 0);
				break;
			case 'm':
				log_level = atoi(optarg);
				break;
			case 's':
				io_counter_stat = 1;
				break;
			case 'U':
				node_status.status_flags = strtol(optarg, NULL, 0);
				update_status = 1;
				break;
			case 'z':
				vfs_stat = 1;
				break;
			case 'a':
				single_node_stat = 0;
				break;
			case 'L':
				lookup = optarg;
				break;
			case 'w':
				cfg.check_timeout = cfg.wait_timeout = atoi(optarg);
				break;
			case 'l':
				logfile = optarg;
				break;
			case 'c':
				cmd = optarg;
				break;
			case 'k':
				exec_src_key = atoi(optarg);
				break;
			case 'I':
				err = dnet_parse_numeric_id(optarg, trans_id);
				if (err)
					return err;
				id = trans_id;
				break;
			case 'g': {
				int *groups_tmp = NULL, group_num = 0;
				group_num = dnet_parse_groups(optarg, &groups_tmp);
				if (group_num <= 0)
					return -1;
				groups.assign(groups_tmp, groups_tmp + group_num);
				free(groups_tmp);
				break;
			}
			case 'r':
				err = dnet_parse_addr(optarg, &port, &family);
				if (err)
					return err;
				remote_addr = optarg;
				break;
			case 'W':
				writef = optarg;
				break;
			case 'R':
				readf = optarg;
				break;
			case 'D':
				read_data = optarg;
				break;
			case 'H':
				as_is_key=read_data;
				id=(unsigned char*)(as_is_key.c_str());
				break;
			case 'h':
			default:
				dnet_usage(argv[0]);
				return -1;
		}
	}

	try {
		file_logger log(logfile, log_level);

		node n(log, cfg);
		session s(n);

		s.set_cflags(cflags);
		s.set_ioflags(ioflags);

		sigemptyset(&mask);
		sigaddset(&mask, SIGTERM);
		sigaddset(&mask, SIGINT);
		sigaddset(&mask, SIGHUP);
		sigaddset(&mask, SIGCHLD);
		pthread_sigmask(SIG_UNBLOCK, &mask, NULL);
		sigprocmask(SIG_UNBLOCK, &mask, NULL);

		if (!remote_addr) {
			fprintf(stderr, "You must specify remote address\n");
			return -EINVAL;
		}

		/*
		 * Only request stats or start defrag on the single node
		 */
		if (single_node_stat && (vfs_stat || io_counter_stat || defrag))
			remote_flags = DNET_CFG_NO_ROUTE_LIST;

		err = dnet_add_state(n.get_native(), remote_addr, port, family, remote_flags);
		if (err)
			return err;

		s.set_groups(groups);
		s.set_namespace(ns, nsize);

		if (defrag) {
			struct dnet_defrag_ctl ctl;

			memset(&ctl, 0, sizeof(struct dnet_defrag_ctl));

			if (!strcmp(defrag, "status"))
				ctl.flags = DNET_DEFRAG_FLAGS_STATUS;

			err = dnet_start_defrag(s.get_native(), &ctl);

			std::string str_status("Ok");

			if (err < 0) {
				str_status = strerror(-err);
			} else {
				if (!strcmp(defrag, "status")) {
					if (err > 0)
						str_status = "defragmentation is in progress";
					else
						str_status = "defragmentation is not running";
				} else {
					if (err == 0)
						str_status = "started successfully";
					else if (err > 0)
						str_status = "unknown positive status";
				}
			}

			fprintf(stdout, "DEFRAG: %s: %s [%d]\n", defrag, str_status.c_str(), err);
			return err;
		}

		if (writef)
			s.write_file(create_id(id, writef), writef, offset, offset, size);

		if (readf)
			s.read_file(create_id(id, readf), readf, offset, size);

		if (read_data) {
			sync_read_result result = s.read_latest(create_id(id, read_data), offset, size);

			data_pointer file = result[0].file();

			while (!file.empty()) {
				err = write(1, file.data(), file.size());
				if (err <= 0) {
					err = -errno;
					throw_error(err, "%s: can not write data to stdout", read_data);
					return err;
				}
				file = file.skip(err);
			}
		}

		if (removef)
			s.remove(create_id(id, removef)).wait();

		if (cmd) {
			session exec_session = s.clone();
			exec_session.set_filter(filters::all_with_ack);
			exec_session.set_cflags(cflags | DNET_FLAGS_NOLOCK);

			dnet_id did_tmp, *did = NULL;
			std::string event, data;

			memset(&did_tmp, 0, sizeof(struct dnet_id));

			if (const char *tmp = strchr(cmd, ' ')) {
				event.assign(cmd, tmp);
				data.assign(tmp + 1);
			} else {
				event.assign(cmd);
			}

			if (id || data.size()) {
				did = &did_tmp;

				if (id) {
					dnet_setup_id(did, 0, id);
				} else {
					exec_session.transform(data, did_tmp);
				}
			}

			bool failed = false;
			auto result = exec_session.exec(did, exec_src_key, event, data);
			for (auto it = result.begin(); it != result.end(); ++it) {
				if (it->error()) {
					error_info error = it->error();
					std::cerr << dnet_server_convert_dnet_addr(it->address())
						<< ": failed to process: \"" << error.message() << "\": " << error.code() << std::endl;
					failed = true;
				} else {
					exec_context context = it->context();
					if (log_level > DNET_LOG_DATA) {
						if (context.is_null()) {
							std::cout << dnet_server_convert_dnet_addr(it->address())
								<< ": acknowledge" << std::endl;
						} else {
							std::cout << dnet_server_convert_dnet_addr(context.address())
								<< ": " << context.event()
								<< " \"" << context.data().to_string() << "\"" << std::endl;
						}
					} else {
						if (!context.is_null()) {
							std::cout << context.data().to_string() << std::endl;
						}
					}
				}
			}
			if (failed)
				return -1;
		}

		if (lookup) {
			sync_lookup_result res = s.lookup(std::string(lookup));
			for(auto it = res.begin(), end = res.end(); it != end; ++it) {
				auto info = it->file_info();
				auto storage = it->storage_address();
				std::cout	<< "Storage address: " << (char*)storage->addr << "\n"
							<< "File path: " << it->file_path() << "\n"
							<< " File info: " << "\n"
								<< "\tsize: "	<< info->size << "\n"
								<< "\toffset: " << info->offset << "\n"
								<< "\ttime: " << info->mtime.tsec << "/" << info->mtime.tnsec << std::endl;
			}
		}

		if (vfs_stat) {
			float la[3];
			auto results = s.stat_log();
			for (auto it = results.begin(); it != results.end(); ++it) {
				const stat_result_entry &result = *it;
				dnet_cmd *cmd = result.command();
				dnet_addr *addr = result.address();
				dnet_stat *st = result.statistics();

				la[0] = (float)st->la[0] / 100.0;
				la[1] = (float)st->la[1] / 100.0;
				la[2] = (float)st->la[2] / 100.0;

				dnet_log_raw(n.get_native(), DNET_LOG_DATA, "%s: %s: la: %.2f %.2f %.2f.\n",
						dnet_dump_id(&cmd->id), dnet_state_dump_addr_only(addr),
						la[0], la[1], la[2]);
				dnet_log_raw(n.get_native(), DNET_LOG_DATA, "%s: %s: mem: "
						"total: %llu kB, free: %llu kB, cache: %llu kB.\n",
						dnet_dump_id(&cmd->id), dnet_state_dump_addr_only(addr),
						(unsigned long long)st->vm_total,
						(unsigned long long)st->vm_free,
						(unsigned long long)st->vm_cached);
				dnet_log_raw(n.get_native(), DNET_LOG_DATA, "%s: %s: fs: "
						"total: %llu mB, avail: %llu mB, files: %llu, fsid: 0x%llx.\n",
						dnet_dump_id(&cmd->id), dnet_state_dump_addr_only(addr),
						(unsigned long long)(st->frsize * st->blocks / 1024 / 1024),
						(unsigned long long)(st->bavail * st->bsize / 1024 / 1024),
						(unsigned long long)st->files, (unsigned long long)st->fsid);
			}
		}

		if (io_counter_stat) {
			auto results = s.stat_log_count();
			for (auto it = results.begin(); it != results.end(); ++it) {
				const stat_count_result_entry &result = *it;
				dnet_cmd *cmd = result.command();
				dnet_addr *addr = result.address();
				dnet_addr_stat *as = result.statistics();

				for (int j = 0; j < (int)((cmd->size - sizeof(struct dnet_addr_stat)) / sizeof(struct dnet_stat_count)); ++j) {
					if (j == 0)
						dnet_log_raw(n.get_native(), DNET_LOG_DATA, "%s: %s: storage-to-storage commands\n",
							dnet_dump_id(&cmd->id), dnet_state_dump_addr_only(addr));
					if (j == as->cmd_num)
						dnet_log_raw(n.get_native(), DNET_LOG_DATA, "%s: %s: client-to-storage commands\n",
							dnet_dump_id(&cmd->id), dnet_state_dump_addr_only(addr));
					if (j == as->cmd_num * 2)
						dnet_log_raw(n.get_native(), DNET_LOG_DATA, "%s: %s: Global stat counters\n",
							dnet_dump_id(&cmd->id), dnet_state_dump_addr_only(addr));

					dnet_log_raw(n.get_native(), DNET_LOG_DATA, "%s: %s:    cmd: %s, count: %llu, err: %llu\n",
							dnet_dump_id(&cmd->id), dnet_state_dump_addr_only(addr),
							dnet_counter_string(j, as->cmd_num),
							(unsigned long long)as->count[j].count, (unsigned long long)as->count[j].err);
				}
			}
		}

		if (update_status) {
			s.update_status(remote_addr, port, family, &node_status);
		}

	} catch (const std::exception &e) {
		std::cerr << e.what() << std::endl;
		return -1;
	}

	return 0;
}

