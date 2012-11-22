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

#include <elliptics/cppdef.h>

using namespace ioremap::elliptics;

void logger::real_logger(void *priv, const int level, const char *msg)
{
	logger *log = reinterpret_cast<logger *> (priv);

	log->log(level, msg);
}

log_file::log_file(const char *file, const int level) :
	logger(level)
{
	try {
		this->file = new std::string(file);
	} catch (...) {
		throw -ENOMEM;
	}

	try {
		stream = new std::ofstream(file, std::ios_base::app);
	} catch (...) {
		delete this->file;
		throw -errno;
	}
}

unsigned long log_file::clone(void)
{
	return reinterpret_cast<unsigned long>(new log_file (file->c_str(), get_log_level()));
}

log_file::~log_file(void)
{
	delete file;
	delete stream;
}

void log_file::log(int level, const char *msg)
{
	if (level <= ll.log_level) {
		char str[64];
		struct tm tm;
		struct timeval tv;
		char usecs_and_id[64];

		gettimeofday(&tv, NULL);
		localtime_r((time_t *)&tv.tv_sec, &tm);
		strftime(str, sizeof(str), "%F %R:%S", &tm);

		snprintf(usecs_and_id, sizeof(usecs_and_id), ".%06lu %ld/%d : ", tv.tv_usec, dnet_get_id(), getpid());

		(*stream) << str << usecs_and_id << msg;
		stream->flush();
	}
}
