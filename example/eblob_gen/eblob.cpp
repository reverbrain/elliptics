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

#include <sstream>

#include "eblob_gen.h"

eblob::eblob(struct eblob_config &cfg)
{
	blob = eblob_init(&cfg);
	if (!blob)
		throw std::runtime_error("Failed to initialize eblob");
}

eblob::~eblob()
{
	std::cerr << "Destructing eblob\n";
	eblob_cleanup(blob);
}

void eblob::write(const struct dnet_id &id, const std::string &data)
{
	int err;

	err = eblob_write_data(blob, (unsigned char *)id.id, sizeof(id.id), (void *)data.data(), data.size(), 0);
	if (err) {
		std::ostringstream str;
		str << "Failed to write into eblob: key: " << dnet_dump_id_len(&id, DNET_ID_SIZE) << ", data size: " << data.size() << std::endl;
		throw std::runtime_error(str.str());
	}
}

