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

#define _XOPEN_SOURCE 600

#include "elliptics/cppdef.h"

#include "callback_p.h"

#include <sstream>
#include <stdexcept>

#include <boost/thread.hpp>
#include <boost/make_shared.hpp>

namespace ioremap { namespace elliptics {

struct data_skiper
{
	public:
		data_skiper(char *data, size_t size) : m_data(data), m_size(size)
		{
		}

		data_skiper(std::string &data) : m_data(&data[0]), m_size(data.length())
		{
		}

		template <typename T>
		data_skiper &skip()
		{
			if (m_size < sizeof(T)) {
				m_size = 0;
				m_data = NULL;
			} else {
				m_data += sizeof(T);
				m_size -= sizeof(T);
			}
			return *this;
		}

		template <typename T>
		T *data()
		{
			if (m_size == 0)
				throw not_found_error("null pointer exception");
			return reinterpret_cast<T *>(m_size > 0 ? m_data : NULL);
		}

	private:
		char *m_data;
		size_t m_size;
};

callback_result::callback_result() : m_data(boost::make_shared<callback_result_data>())
{
}

callback_result::callback_result(const callback_result &other) : m_data(other.m_data)
{
}

callback_result::callback_result(const boost::shared_ptr<callback_result_data> &data) : m_data(data)
{
}

callback_result::~callback_result()
{
}

callback_result &callback_result::operator =(const callback_result &other)
{
	m_data = other.m_data;
	return *this;
}

bool callback_result::is_valid() const
{
	return !m_data->data.empty();
}

std::string callback_result::raw_data() const
{
	return m_data->data;
}

struct dnet_addr *callback_result::address() const
{
	return data_skiper(m_data->data)
		.data<struct dnet_addr>();
}

struct dnet_cmd *callback_result::command() const
{
	return data_skiper(m_data->data)
		.skip<struct dnet_addr>()
		.data<struct dnet_cmd>();
}

void *callback_result::data() const
{
	return data_skiper(m_data->data)
		.skip<struct dnet_addr>()
		.skip<struct dnet_cmd>()
		.data<void>();
}

uint64_t callback_result::size() const
{
	return (m_data->data.size() <= (sizeof(struct dnet_addr) + sizeof(struct dnet_cmd *)))
		? (0)
	: (m_data->data.size() - (sizeof(struct dnet_addr) + sizeof(struct dnet_cmd *)));
}

boost::exception_ptr callback_result::exception() const
{
	return m_data->exc;
}

void callback_result::set_exception(const boost::exception_ptr &exc)
{
	m_data->exc = exc;
}

lookup_result::lookup_result()
{
}

lookup_result::lookup_result(const lookup_result &other) : callback_result(other)
{
}

lookup_result::~lookup_result()
{
}

lookup_result &lookup_result::operator =(const lookup_result &other)
{
	callback_result::operator =(other);
	return *this;
}

struct dnet_addr_attr *lookup_result::address_attribute() const
{
	return data_skiper(m_data->data)
		.skip<struct dnet_addr>()
		.skip<struct dnet_cmd>()
		.data<struct dnet_addr_attr>();
}

struct dnet_file_info *lookup_result::file_info() const
{
	return data_skiper(m_data->data)
		.skip<struct dnet_addr>()
		.skip<struct dnet_cmd>()
		.skip<struct dnet_addr_attr>()
		.data<struct dnet_file_info>();
}

const char *lookup_result::file_path() const
{
	return data_skiper(m_data->data)
		.skip<struct dnet_addr>()
		.skip<struct dnet_cmd>()
		.skip<struct dnet_addr_attr>()
		.skip<struct dnet_file_info>()
		.data<char>();
}

stat_result::stat_result()
{
}

stat_result::stat_result(const stat_result &other) : callback_result(other)
{
}

stat_result::~stat_result()
{
}

stat_result &stat_result::operator =(const stat_result &other)
{
	callback_result::operator =(other);
	return *this;
}

dnet_stat *stat_result::statistics() const
{
	return data_skiper(m_data->data)
		.skip<struct dnet_addr>()
		.skip<struct dnet_cmd>()
		.data<struct dnet_stat>();
}

stat_count_result::stat_count_result()
{
}

stat_count_result::stat_count_result(const stat_count_result &other) : callback_result(other)
{
}

stat_count_result::~stat_count_result()
{
}

stat_count_result &stat_count_result::operator =(const stat_count_result &other)
{
	callback_result::operator =(other);
	return *this;
}

struct dnet_addr_stat *stat_count_result::statistics() const
{
	return data_skiper(m_data->data)
		.skip<struct dnet_addr>()
		.skip<struct dnet_cmd>()
		.data<struct dnet_addr_stat>();
}

} } // namespace ioremap::elliptics
