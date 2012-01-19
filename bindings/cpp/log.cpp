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

#include "elliptics/cppdef.h"

using namespace zbr;

void elliptics_log::logger(void *priv, const uint32_t mask, const char *msg)
{
	elliptics_log *log = reinterpret_cast<elliptics_log *> (priv);

	log->log(mask, msg);
}

elliptics_log_file::elliptics_log_file(const char *file, const uint32_t mask) :
	elliptics_log(mask)
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

unsigned long elliptics_log_file::clone(void)
{
	return reinterpret_cast<unsigned long>(new elliptics_log_file (file->c_str(), get_log_mask()));
}

elliptics_log_file::~elliptics_log_file(void)
{
	delete file;
	delete stream;
}

void elliptics_log_file::log(uint32_t mask, const char *msg)
{
	if (mask & ll.log_mask) {
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
