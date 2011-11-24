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

eblob_gen::eblob_gen(elliptics_log &l) : node(l)
{
}

eblob_gen::~eblob_gen()
{
}

void eblob_gen::add_remote(const char *addr, const int port, const int family)
{
	try {
		node.add_remote(addr, port, family);
	} catch (...) {
		std::ostringstream str;

		str << "Failed to connect to " << addr << ":" << port;
		throw std::runtime_error(str.str());
	}
}

void eblob_gen::write(const std::string &name, const std::string &, const struct timespec &ts)
{
	struct dnet_id id;
	int aflags = 0;

	node.transform(name, id);
	node.write_metadata(id, name, node.get_groups(), ts, aflags);
}
