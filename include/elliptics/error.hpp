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
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Lesser General Public License for more details.
 */

#ifndef ELLIPTICS_ERROR_HPP
#define ELLIPTICS_ERROR_HPP

#include <stdexcept>
#include <string>
#include "packet.h"

namespace ioremap { namespace elliptics {

#define ELLIPTICS_DISABLE_COPY(CLASS) \
		CLASS(const CLASS &) = delete; \
		CLASS &operator =(const CLASS &) = delete;

class error : public std::exception
{
	public:
		// err must be negative value
		explicit error(int err, const std::string &message) throw();
		~error() throw() {}

		int error_code() const;

		virtual const char *what() const throw();

		std::string error_message() const throw();

	private:
		int m_errno;
		std::string m_message;
};

class not_found_error : public error
{
	public:
		explicit not_found_error(const std::string &message) throw();
};

class timeout_error : public error
{
	public:
		explicit timeout_error(const std::string &message) throw();
};

class no_such_address_error : public error
{
	public:
		explicit no_such_address_error(const std::string &message) throw();
};

class error_info
{
	public:
		inline error_info() : m_code(0) {}
		inline error_info(int code, const std::string &&message)
			: m_code(code), m_message(message) {}
		inline error_info(int code, const std::string &message)
			: m_code(code), m_message(message) {}
		inline ~error_info() {}

		inline int code() const { return m_code; }
		inline const std::string &message() const { return m_message; }
		inline operator bool() const { return m_code != 0; }
		inline bool operator !() const { return !operator bool(); }
		operator int() const = delete; // disable implicit cast to int

		void throw_error() const;
	private:
		int m_code;
		std::string m_message;
};

class key;

// err must be negative value
void throw_error(int err, const char *format, ...)
	__attribute__ ((format (printf, 2, 3)));

// err must be negative value
void throw_error(int err, const struct dnet_id &id, const char *format, ...)
	__attribute__ ((format (printf, 3, 4)));

// err must be negative value
void throw_error(int err, const key &id, const char *format, ...)
	__attribute__ ((format (printf, 3, 4)));

// err must be negative value
void throw_error(int err, const uint8_t *id, const char *format, ...)
	__attribute__ ((format (printf, 3, 4)));

// err must be negative value
error_info create_error(int err, const char *format, ...)
	__attribute__ ((format (printf, 2, 3)));

// err must be negative value
error_info create_error(int err, const struct dnet_id &id, const char *format, ...)
	__attribute__ ((format (printf, 3, 4)));

// err must be negative value
error_info create_error(int err, const key &id, const char *format, ...)
	__attribute__ ((format (printf, 3, 4)));

// err must be negative value
error_info create_error(int err, const uint8_t *id, const char *format, ...)
	__attribute__ ((format (printf, 3, 4)));

error_info create_error(const dnet_cmd &cmd);

}} /* namespace ioremap::elliptics */

#endif // ELLIPTICS_ERROR_HPP
