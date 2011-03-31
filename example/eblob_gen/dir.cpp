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

eblob_dir_source::eblob_dir_source(const std::string &path) : itr(fs::path(path))
{
}

eblob_dir_source::~eblob_dir_source()
{
}

bool eblob_dir_source::next(const bool prepend, const struct timespec *ts, std::string &name, std::string &data)
{
	if (itr == end_itr)
		return false;

	if (!is_regular_file(*itr)) {
		std::ostringstream str;

		str << "Not regular file " << *itr << std::endl;
		throw std::runtime_error(str.str());
	}

	std::ifstream file(itr->path().string().c_str(), std::ios::binary | std::ios::in);
	std::filebuf *pbuf = file.rdbuf();
	std::stringstream ss;

	if (prepend) {
		size_t size = pbuf->pubseekoff(0, std::ios::end, std::ios::in);
		pbuf->pubseekpos(0, std::ios::in);

		prepend_data(data, size, (struct timespec *)ts);
	}

	ss << pbuf;

	name.assign(itr->path().filename());
	data.append(ss.str());
	++itr;

	return itr != end_itr;
}
