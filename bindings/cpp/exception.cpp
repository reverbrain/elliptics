/*
 * 2008+ Copyright (c) Evgeniy Polyakov <zbr@ioremap.net>
 * 2012+ Copyright (c) Ruslan Nigmatullin <euroelessar@yandex.ru>
 * All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 */

#include "../../include/elliptics/cppdef.h"

#include <cstdarg>
#include <cstdio>
#include <sstream>

#include <errno.h>

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

std::string error::error_message() const throw()
{
	return m_message;
}

not_found_error::not_found_error(const std::string &message) throw()
	: error(-ENOENT, message)
{
}

timeout_error::timeout_error(const std::string &message) throw()
	: error(-ETIMEDOUT, message)
{
}

no_such_address_error::no_such_address_error(const std::string &message) throw()
	: error(-ENXIO, message)
{
}

void error_info::throw_error() const
{
	switch (m_code) {
		case -ENOENT:
			throw not_found_error(m_message);
			break;
		case -ETIMEDOUT:
			throw timeout_error(m_message);
			break;
		case -ENOMEM:
			throw std::bad_alloc();
			break;
		case -ENXIO:
			throw no_such_address_error(m_message);
			break;
		case 0:
			// Do nothing, it's not an error
			break;
		default:
			throw error(m_code, m_message);
			break;
	}
}

static error_info create_info(int err, const char *id, const char *format, va_list args)
{
	if (err == -ENOMEM)
		return error_info(err, std::string());

	std::ostringstream message;
	char buffer[1024];
	const size_t buffer_size = sizeof(buffer);
	if (id) {
		message << id << ": ";
	}
	vsnprintf(buffer, buffer_size, format, args);
	buffer[buffer_size - 1] = '\0';
	message << buffer << ": " << strerror(-err) << ": " << err;
	return error_info(err, message.str());
}

void throw_error(int err, const char *format, ...)
{
	va_list args;
	va_start(args, format);
	error_info error = create_info(err, 0, format, args);
	va_end(args);
	error.throw_error();
}

void throw_error(int err, const struct dnet_id &id, const char *format, ...)
{
	va_list args;
	va_start(args, format);
	error_info error = create_info(err, dnet_dump_id(&id), format, args);
	va_end(args);
	error.throw_error();
}

void throw_error(int err, const key &id, const char *format, ...)
{
	va_list args;
	va_start(args, format);
	const char *id_str = id.by_id() ? dnet_dump_id(&id.id()) : id.remote().c_str();
	error_info error = create_info(err, id_str, format, args);
	va_end(args);
	error.throw_error();
}

void throw_error(int err, const uint8_t *id, const char *format, ...)
{
	va_list args;
	va_start(args, format);
	error_info error = create_info(err, dnet_dump_id_str(id), format, args);
	va_end(args);
	error.throw_error();
}

error_info create_error(int err, const char *format, ...)
{
	va_list args;
	va_start(args, format);
	error_info error = create_info(err, 0, format, args);
	va_end(args);
	return error;
}

error_info create_error(int err, const struct dnet_id &id, const char *format, ...)
{
	va_list args;
	va_start(args, format);
	error_info error = create_info(err, dnet_dump_id(&id), format, args);
	va_end(args);
	return error;
}

error_info create_error(int err, const key &id, const char *format, ...)
{
	va_list args;
	va_start(args, format);
	const char *id_str = id.by_id() ? dnet_dump_id(&id.id()) : id.remote().c_str();
	error_info error = create_info(err, id_str, format, args);
	va_end(args);
	return error;
}

error_info create_error(int err, const uint8_t *id, const char *format, ...)
{
	va_list args;
	va_start(args, format);
	error_info error = create_info(err, dnet_dump_id_str(id), format, args);
	va_end(args);
	return error;
}

error_info create_error(const dnet_cmd &cmd)
{
	return create_error(cmd.status, cmd.id, "Failed to process %s command", dnet_cmd_string(cmd.cmd));
}

} } // namespace ioremap::elliptics
