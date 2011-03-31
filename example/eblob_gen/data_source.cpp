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

#include "eblob_gen.h"
#include "common.h"

void eblob_data_source::prepend_data(std::string &data, const size_t size, struct timespec *ts)
{
	struct timespec ts_;

	if (!ts) {
		struct timeval tv;

		gettimeofday(&tv, NULL);
		ts_.tv_sec = tv.tv_sec;
		ts_.tv_nsec = tv.tv_usec * 1000;

		ts = &ts_;
	}

	int err, bufsize;
	char *buf;

	bufsize = 128;
	buf = new char[bufsize];

	try {
		err = dnet_common_prepend_data(ts, size, buf, &bufsize);
		if (err)
			throw std::runtime_error("Not enough buf");
		data.append(buf, bufsize);
	} catch (...) {
		delete [] buf;
		throw;
	}
	delete [] buf;
}
