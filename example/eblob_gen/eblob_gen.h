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

#ifndef __EBLOB_GEN_H
#define __EBLOB_GEN_H

#include "config.h"

#include <time.h>
#include <libtar.h>

#include <fstream>
#include <iostream>
#include <map>
#include <string>
#include <sstream>

#include <boost/shared_ptr.hpp>

#include <eblob/eblob.hpp>
#include <elliptics/cppdef.h>

using namespace zbr;

class eblob_gen {
	public:
		eblob_gen(elliptics_log &l);
		virtual ~eblob_gen();

		void add_remote(const char *addr, const int port, const int family = AF_INET);
		void write(const std::string &name, const std::string &data, const struct timespec &ts);
	private:
		elliptics_node		node;
};

#include <time.h>

class eblob_data_source {
	public:
		eblob_data_source() {};
		virtual ~eblob_data_source() {};

		void prepend_data(std::string &data, const size_t size, struct timespec *ts = NULL);

		virtual bool next(const bool prepend, const struct timespec *ts,
				std::string &name, std::string &data) = 0;
};

#define BOOST_FILESYSTEM_VERSION 2

#include <boost/filesystem/operations.hpp>
namespace fs = boost::filesystem;

class eblob_dir_source : public eblob_data_source {
	public:
		eblob_dir_source(const std::string &path);
		virtual ~eblob_dir_source();

		virtual bool next(const bool prepend, const struct timespec *ts,
				std::string &name, std::string &data);
	private:
		fs::directory_iterator end_itr, itr;
};

class eblob_tar_source : public eblob_data_source {
	public:
		eblob_tar_source(const std::string &path);
		virtual ~eblob_tar_source();

		virtual bool next(const bool prepend, const struct timespec *ts,
				std::string &name, std::string &data);
	private:
		TAR *tar;
};

class eblob_processor {
	public:
		eblob_processor(const std::string &log_file, const bool prepend_data,
				std::vector<int> &groups, const std::string &eblob_base,
				const struct eblob_config &cfg);

		void process(elliptics_node &node, const std::string &path);

	private:
		bool prepend_data_;
		std::vector<int> groups_;
		struct eblob_config eblob_cfg_;
		std::string eblob_base_, log_file_;

		std::map<std::string, boost::shared_ptr<eblob> > blobs;
};

#endif /* __EBLOB_GEN_H */
