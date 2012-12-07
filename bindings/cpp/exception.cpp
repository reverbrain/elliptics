/*
 * 2008+ Copyright (c) Evgeniy Polyakov <zbr@ioremap.net>
 * 2012+ Copyright (c) Ruslan Nigmatullin <euroelessar@yandex.ru>
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

#include <cstdarg>
#include <cstdio>
#include <sstream>

namespace ioremap { namespace elliptics {

error::error(int code, const std::string &message) throw() : m_errno(code), m_message(message)
{
}

int error::error_code() const
{
	return m_errno;
}

const char *error::what() const throw()
{
	return m_message.c_str();
}

not_found_error::not_found_error(const std::string &message) throw()
	: error(ENOENT, message)
{
}

timeout_error::timeout_error(const std::string &message) throw()
	: error(EIO, message)
{
}

static void throw_error_detail(int err, const std::string &message)
{
	switch (err) {
		case ENOENT:
			throw not_found_error(message);
			break;
		case EIO:
			throw timeout_error(message);
			break;
		default:
			throw error(err, message);
			break;
	}
}

static void throw_error_detail(int err, const char *id, const char *format, va_list args)
{
	std::ostringstream message;
	char buffer[1024];
	const size_t buffer_size = sizeof(buffer);
	if (id) {
		message << id << ": ";
	}
	vsnprintf(buffer, buffer_size, format, args);
	buffer[buffer_size - 1] = '\0';
	message << buffer << ": " << strerror(-err) << ": " << err;
	throw_error_detail(err, message.str());
}

void throw_error(int err, const char *format, ...)
{
	va_list args;
	va_start(args, format);
	throw_error_detail(err, 0, format, args);
	va_end(args);
}

void throw_error(int err, const struct dnet_id &id, const char *format, ...)
{
	va_list args;
	va_start(args, format);
	throw_error_detail(err, dnet_dump_id(&id), format, args);
	va_end(args);
}

void throw_error(int err, const uint8_t *id, const char *format, ...)
{
	va_list args;
	va_start(args, format);
	throw_error_detail(err, dnet_dump_id_str(id), format, args);
	va_end(args);
}

} } // namespace ioremap::elliptics
