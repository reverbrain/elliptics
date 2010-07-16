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

void elliptics_log::logger(void *priv, const uint32_t mask, const char *msg)
{
	elliptics_log *log = reinterpret_cast<elliptics_log *> (priv);

	log->log(mask, msg);
}

elliptics_log_file::elliptics_log_file(const char *file, const uint32_t mask) :
	elliptics_log (mask)
{
	stream.open(file);
}

elliptics_log_file::~elliptics_log_file()
{
	stream.close();
}

void elliptics_log_file::log(uint32_t mask, const char *msg)
{
	if (mask & ll.log_mask) {
		stream << msg;
		stream.flush();
	}
}


