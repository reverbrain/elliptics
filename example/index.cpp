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
#include <ctime>
#include <iostream>

#include <netinet/in.h>

#include <elliptics/cppdef.h>

using namespace ioremap::elliptics;

#ifndef __unused
#define __unused	__attribute__ ((unused))
#endif

static void dnet_usage(char *p)
{
	fprintf(stderr, "Usage: %s\n"
			" -r addr:port:family  - adds a route to the given node\n"
			" -W file              - write given file to the network storage\n"
			" -I id                - transaction id\n"
			" -g groups            - group IDs to connect\n"
			" -l log               - log file. Default: disabled\n"
			" -w timeout           - wait timeout in seconds used to wait for content sync.\n"
			" ...                  - parameters can be repeated multiple times\n"
			"                        each time they correspond to the last added node\n"
			" -m level             - log level\n"
			" -F flags             - change node flags (see @cfg->flags comments in include/elliptics/interface.h)\n"
			" -N namespace         - use this namespace for operations\n"
			" -C flags             - command flags\n"
			" -i flags             - IO flags (see DNET_IO_FLAGS_* in include/elliptics/packet.h\n"
			, p);
}

static key create_id(unsigned char *id, const char *file_name)
{
	if (id) {
		struct dnet_id raw;
		memset(&raw, 0, sizeof(struct dnet_id));

		dnet_setup_id(&raw, 0, id);

		return raw;
	} else {
		return key(file_name);
	}
}

std::vector<int> parse_groups(char *value)
{
	std::vector<int> result;
	bool finished = false;
	while (!finished && value && *value) {
		char *delimiter = const_cast<char *>(strchrnul(value, DNET_CONF_ADDR_DELIM));
		finished = !*delimiter;
		*delimiter = '\0';
		if (delimiter - value > 0)
			result.push_back(atoi(value));
		value = delimiter + 1;
	}
	return result;
}

class timer
{
	public:
		timer(const char *name) : m_name(name), m_clock(clock())
		{
		}

		~timer()
		{
			std::cerr << m_name << ": "
				<< double(clock() - m_clock)
				<< " ticks"
				<< std::endl;
		}

	private:
		const char *m_name;
		clock_t m_clock;
};

int main(int argc, char *argv[])
{
	int ch, err;
	struct dnet_config cfg;
	const char *logfile = "/dev/stderr";
	unsigned char trans_id[DNET_ID_SIZE], *id = NULL;
	std::vector<int> groups;
	std::vector<const char *> remotes;
	uint64_t cflags = 0;
	uint64_t ioflags = 0;
	sigset_t mask;
	char *update = NULL;
	bool find = false;
	std::vector<std::string> indexes;
	std::vector<data_pointer> datas;
	char *ns = NULL;
	int nsize = 0;

	memset(&cfg, 0, sizeof(struct dnet_config));

	cfg.wait_timeout = 60;
	int log_level = DNET_LOG_ERROR;

	while ((ch = getopt(argc, argv, "-i:C:N:g:m:w:l:I:r:U:Fh")) != -1) {
		switch (ch) {
			case 1:
				indexes.push_back(optarg);
				break;
			case 'i':
				ioflags = strtoull(optarg, NULL, 0);
				break;
			case 'C':
				cflags = strtoull(optarg, NULL, 0);
				break;
			case 'N':
				ns = optarg;
				nsize = strlen(optarg);
				break;
			case 'm':
				log_level = atoi(optarg);
				break;
			case 'w':
				cfg.check_timeout = cfg.wait_timeout = atoi(optarg);
				break;
			case 'l':
				logfile = optarg;
				break;
			case 'I':
				err = dnet_parse_numeric_id(optarg, trans_id);
				if (err)
					return err;
				id = trans_id;
				break;
			case 'g': {
				groups = parse_groups(optarg);
				std::cerr << optarg << " -> {";
				for (auto it = groups.begin(); it != groups.end(); ++it) {
					std::cerr << *it << ", ";
				}
				std::cerr << "}" << std::endl;
				break;
			}
			case 'r':
				remotes.push_back(optarg);
				break;
			case 'U':
				update = optarg;
				break;
			case 'F':
				find = true;
				break;
			case 'h':
				dnet_usage(argv[0]);
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

		for (size_t i = 0; i < remotes.size(); ++i)
			n.add_remote(remotes[i]);

		s.set_groups(groups);
		s.set_namespace(ns, nsize);

		if (update) {
			timer t("update");
			int result = 0;
			try {
				datas.resize(indexes.size());
				s.set_indexes(create_id(id, update), indexes, datas).wait();
			} catch (error &e) {
				result = e.error_code();
			} catch (std::bad_alloc &e) {
				result = -ENOMEM;
			}

			std::cerr << "update: " << result << std::endl;
		}

		if (find) {
			timer t("find");
			std::vector<find_indexes_result_entry> results;
			int result = 0;
			try {
				results = s.find_all_indexes(indexes);
			} catch (error &e) {
				result = e.error_code();
			} catch (std::bad_alloc &e) {
				result = -ENOMEM;
			}

			std::cerr << "find: " << result << std::endl;
			std::cerr << "find: found: " << results.size() << std::endl;
			for (size_t i = 0; i < results.size(); ++i) {
				std::cerr << "find: "
					<< i << " " << dnet_dump_id_str(results[i].id.id)
//					<< " \"" << results[i].data.to_string() << "\""
					<< std::endl;
			}
		}
	} catch (const std::exception &e) {
		std::cerr << e.what() << std::endl;
	}

	return 0;
}

