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

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>


#include <sstream>

#include "eblob_gen.h"

eblob_tar_source::eblob_tar_source(const std::string &path)
{
	int err;

	err = tar_open(&tar, (char *)path.c_str(), NULL, O_RDONLY, 0644, TAR_GNU);
	if (err) {
		err = -errno;
		std::ostringstream str;
		str << "Failed to open tar file " << path << ": " << err;
		throw std::runtime_error(str.str());
	}
}

eblob_tar_source::~eblob_tar_source()
{
	tar_close(tar);
}

bool eblob_tar_source::next(const bool prepend, const struct timespec *ts,
				std::string &name, std::string &data)
{
	int err;
	off_t size, orig_size;

	err = th_read(tar);
	if (err == 1)
		return false;
	if (err < 0) {
		err = -errno;
		std::ostringstream str;
		str << "Failed to read tar header: " << err;
		throw std::runtime_error(str.str());
	}

	name.assign(th_get_pathname(tar));

	orig_size = size = th_get_size(tar);

	data.clear();

	if (prepend)
		prepend_data(data, size, (struct timespec *)ts);

	char *buf = new char[size];

	try {
		void *ptr = buf;

		while (size) {
			err = read(tar_fd(tar), ptr, size);
			if (err <= 0) {
				if (err == 0)
					err = -EIO;
				else
					err = -errno;

				if (err == -EINTR || err == -EAGAIN)
					continue;

				std::ostringstream str;
				str << "Failed to read " << size << " bytes from tar file: " << err;
				throw std::runtime_error(str.str());
			}

			ptr = (void *)((unsigned long)ptr + err);
			size -= err;
		}

		lseek(tar_fd(tar), -orig_size, SEEK_CUR);
		tar_skip_regfile(tar);

		data.append(buf, orig_size);
	} catch (...) {
		delete [] buf;
		throw;
	}
	delete [] buf;

	return true;
}
