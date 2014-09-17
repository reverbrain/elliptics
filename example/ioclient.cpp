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

static void dnet_usage(char *p)
{
	fprintf(stderr, "Usage: %s\n"
			" -r addr:port:family  - adds a route to the given node\n"
			" -W file              - write given file to the network storage\n"
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
			" -f flags             - node flags (see @cfg->flags comments in include/elliptics/interface.h)\n"
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
			" -b backend_id        - operate with given backend ID, it is needed for defragmentation request or backend status update\n"
			" -B status            - change backend status, possible options are: enable, disable, enable_write, disable_write, status (default)\n"
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
	int single_node_stat = 1;
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
	char *defrag_status_str = NULL;
	sigset_t mask;
	char *ns = NULL;
	int nsize = 0;
	std::string as_is_key;
	int exec_src_key = -1;
	int backend_id = -1;
	char *backend_status_str = NULL;

	memset(&node_status, 0, sizeof(struct dnet_node_status));
	memset(&cfg, 0, sizeof(struct dnet_config));

	cfg.indexes_shard_count = 10;

	node_status.nflags = -1;
	node_status.status_flags = -1;
	node_status.log_level = ~0U;

	size = offset = 0;

	cfg.wait_timeout = 60;
	dnet_log_level log_level = DNET_LOG_ERROR;

	while ((ch = getopt(argc, argv, "i:d:C:A:f:F:M:N:g:u:O:S:m:zsU:aL:w:l:c:k:I:r:W:R:D:hHb:B:")) != -1) {
		switch (ch) {
			case 'i':
				ioflags = strtoull(optarg, NULL, 0);
				break;
			case 'd':
				defrag_status_str = optarg;
				break;
			case 'C':
				cflags = strtoull(optarg, NULL, 0);
				break;
			case 'f':
				cfg.flags = strtol(optarg, NULL, 0);
				break;
			case 'F':
				node_status.nflags = strtol(optarg, NULL, 0);
				update_status = 1;
				break;
			case 'M':
				try {
					node_status.log_level = static_cast<uint32_t>(file_logger::parse_level(optarg));
				} catch (std::exception &exc) {
					std::cerr << "remote log level: " << exc.what() << std::endl;
					return -1;
				}
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
				try {
					log_level = file_logger::parse_level(optarg);
				} catch (std::exception &exc) {
					std::cerr << exc.what() << std::endl;
					return -1;
				}

				break;
			case 'U':
				node_status.status_flags = strtol(optarg, NULL, 0);
				update_status = 1;
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
			case 'b':
				backend_id = atoi(optarg);
				break;
			case 'B':
				backend_status_str = optarg;
				break;
			case 'h':
			default:
				dnet_usage(argv[0]);
				return -1;
		}
	}

	try {
		file_logger log(logfile, log_level);

		/*
		 * Only request stats or start defrag on the single node
		 */
		if (single_node_stat && defrag_status_str) {
			remote_flags = DNET_CFG_NO_ROUTE_LIST;
			cfg.flags |= DNET_CFG_NO_ROUTE_LIST;
		}

		node n(logger(log, blackhole::log::attributes_t()), cfg);
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

		struct dnet_addr ra;

		err = dnet_create_addr(&ra, remote_addr, port, family);
		if (err) {
			BH_LOG(n.get_log(), DNET_LOG_ERROR, "Failed to get address info for %s:%d, family: %d, err: %d: %s.",
					remote_addr, port, family, err, strerror(-err));
			return err;
		}

		err = dnet_add_state(n.get_native(), &ra, 1, remote_flags);
		if (err < 0)
			return err;

		s.set_groups(groups);
		s.set_namespace(ns, nsize);

		if (defrag_status_str || backend_status_str) {
			if (backend_id < 0) {
				fprintf(stderr, "You must specify backend id (-b)\n");
				return -EINVAL;
			}

			std::string defrag_status, backend_status;
			if (defrag_status_str)
				defrag_status.assign(defrag_status_str);
			else
				backend_status.assign(backend_status_str);

			session sess = s.clone();
			sess.set_exceptions_policy(session::no_exceptions);

			async_backend_status_result result;

			if (defrag_status == "start") {
				result = sess.start_defrag(ra, backend_id);
			} else if ((defrag_status == "status") || (backend_status == "status")) {
				result = sess.request_backends_status(ra);
			} else if (backend_status == "enable") {
				result = sess.enable_backend(ra, backend_id);
			} else if (backend_status == "disable") {
				result = sess.disable_backend(ra, backend_id);
			} else if (backend_status == "enable_write") {
				result = sess.make_writable(ra, backend_id);
			} else if (backend_status == "disable_write") {
				result = sess.make_readonly(ra, backend_id);
			} else {
				fprintf(stderr, "Invalid %s status '%s'\n", defrag_status_str ? "defrag" : "backend",
						defrag_status_str ? defrag_status_str : backend_status_str);
				return -EINVAL;
			}

			result.wait();

			if (result.error())
				std::cout << "result: " << result.error().message() << std::endl;

			backend_status_result_entry entry = result.get_one();
			if (entry.is_valid()) {
				for (size_t i = 0; i < entry.count(); ++i) {
					dnet_backend_status *status = entry.backend(i);
					std::cout << "backend: " << status->backend_id << " at " << dnet_server_convert_dnet_addr(entry.address()) << std::endl;
					std::cout << "  backend state: " << dnet_backend_state_string(status->state) << std::endl;
					std::cout << "  defrag  state: " << dnet_backend_defrag_state_string(status->defrag_state) << std::endl;
					if (dnet_time_is_empty(&status->last_start)) {
						std::cout << "  backend has never been started" << std::endl;
					} else {
						std::cout << "  backend last start: " << dnet_print_time(&status->last_start) << ", err: " << status->last_start_err << std::endl;
					}
				}
			} else {
				std::cout << "status results are missed" << std::endl;
			}

			return result.error().code();
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
					if (context.is_null()) {
						std::cout << dnet_server_convert_dnet_addr(it->address())
							<< ": acknowledge" << std::endl;
					} else {
						std::cout << dnet_server_convert_dnet_addr(context.address())
							<< ": " << context.event()
							<< " \"" << context.data().to_string() << "\"" << std::endl;
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

		if (update_status) {
			s.update_status(address(remote_addr, port, family), &node_status);
		}

	} catch (const std::exception &e) {
		std::cerr << e.what() << std::endl;
		return -1;
	}

	return 0;
}

