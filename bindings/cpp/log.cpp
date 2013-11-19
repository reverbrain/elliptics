/*
 * 2008+ Copyright (c) Evgeniy Polyakov <zbr@ioremap.net>
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

#include <elliptics/cppdef.h>
#include <fstream>
#include <iostream>

#include <stdarg.h>

using namespace ioremap::elliptics;

extern __thread uint32_t trace_id;

class ioremap::elliptics::logger_data {
	public:
		logger_data(logger_interface *interface, int level) : impl(interface) {
			log.log_level = level;
			log.log = real_logger;
			log.log_private = interface ? this : NULL;
		}
		~logger_data() {
			delete impl;
		}

		static void real_logger(void *priv, const int level, const char *msg)
		{
			if (logger_data *log = reinterpret_cast<logger_data *>(priv))
				log->push_log(level, msg);
		}

		bool check_level(int level)
		{
			return (level <= log.log_level && impl);
		}

		void push_log(const int level, const char *msg)
		{
			if (check_level(level) || (trace_id & DNET_TRACE_BIT))
				impl->log(level, msg);
		}

		dnet_log log;
		logger_interface *impl;
};

logger::logger(logger_interface *interface, const int level)
	: m_data(new logger_data(interface, level)) {
}

logger::logger() : m_data(new logger_data(NULL, DNET_LOG_INFO)) {
}

logger::logger(const logger &other) : m_data(other.m_data) {
}

logger::~logger() {
}

logger &logger::operator =(const logger &other) {
	m_data = other.m_data;
	return *this;
}

void logger::log(const int level, const char *msg)
{
    m_data->push_log(level, msg);
}

void logger::print(int level, const char *format, ...)
{
	if (!m_data->check_level(level) && !(trace_id & DNET_TRACE_BIT))
		return;

	va_list args;
	char buffer[1024];
	const size_t buffer_size = sizeof(buffer);

	va_start(args, format);

	vsnprintf(buffer, buffer_size, format, args);
	buffer[buffer_size - 1] = '\0';
	m_data->impl->log(level, buffer);

	va_end(args);
}

int logger::get_log_level()
{
	return m_data->log.log_level;
}

dnet_log *logger::get_native()
{
	return &m_data->log;
}

class file_logger_interface : public logger_interface {
	public:
		file_logger_interface(const char *file) {
			m_stream.open(file, std::ios_base::app);
			if (!m_stream) {
				std::string message = "Can not open file: \"";
				message += file;
				message += "\"";
				throw std::ios_base::failure(message);
			}
			m_stream.exceptions(std::ofstream::failbit);
		}
		~file_logger_interface() {
		}

		void log(int level, const char *msg)
		{
			(void) level;
			char str[64];
			struct tm tm;
			struct timeval tv;
			char usecs_and_id[64];

			gettimeofday(&tv, NULL);
			localtime_r((time_t *)&tv.tv_sec, &tm);
			strftime(str, sizeof(str), "%F %R:%S", &tm);

			snprintf(usecs_and_id, sizeof(usecs_and_id), ".%06lu %u/%ld/%d : ", tv.tv_usec, (trace_id & ~DNET_TRACE_BIT), dnet_get_id(), getpid());

			if (m_stream) {
				m_stream << str << usecs_and_id << msg;
				size_t msg_len = strlen(msg);
				if (msg[msg_len - 1] != '\n')
					m_stream << '\n';
				m_stream.flush();
			} else {
				std::cerr << str << usecs_and_id << ": could not write log in elliptics file logger" << std::endl;
			}
		}

	private:
		std::ofstream	m_stream;
};

file_logger::file_logger(const char *file, const int level) :
	logger(new file_logger_interface(file), level)
{
}

file_logger::~file_logger()
{
}
