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

#include "callback_p.h"

#include <sstream>
#include <stdexcept>

namespace ioremap { namespace elliptics {

callback_result_entry::callback_result_entry() : m_data(std::make_shared<callback_result_data>())
{
}

callback_result_entry::callback_result_entry(const callback_result_entry &other) : m_data(other.m_data)
{
}

callback_result_entry::callback_result_entry(const std::shared_ptr<callback_result_data> &data) : m_data(data)
{
}

callback_result_entry::~callback_result_entry()
{
}

callback_result_entry &callback_result_entry::operator =(const callback_result_entry &other)
{
	m_data = other.m_data;
	return *this;
}

bool callback_result_entry::is_valid() const
{
	return !m_data->data.empty();
}

bool callback_result_entry::is_ack() const
{
	return status() == 0 && data().empty();
}

int callback_result_entry::status() const
{
	return command()->status;
}

error_info callback_result_entry::error() const
{
	return m_data->error;
}

data_pointer callback_result_entry::raw_data() const
{
	return m_data->data;
}

struct dnet_addr *callback_result_entry::address() const
{
	return m_data->data
		.data<struct dnet_addr>();
}

struct dnet_cmd *callback_result_entry::command() const
{
	return m_data->data
		.skip<struct dnet_addr>()
		.data<struct dnet_cmd>();
}

data_pointer callback_result_entry::data() const
{
	return m_data->data
		.skip<struct dnet_addr>()
		.skip<struct dnet_cmd>();
}

uint64_t callback_result_entry::size() const
{
	return (m_data->data.size() <= (sizeof(struct dnet_addr) + sizeof(struct dnet_cmd)))
		? (0)
	: (m_data->data.size() - (sizeof(struct dnet_addr) + sizeof(struct dnet_cmd)));
}

read_result_entry::read_result_entry()
{
}

read_result_entry::read_result_entry(const read_result_entry &other) : callback_result_entry(other)
{
}

read_result_entry::~read_result_entry()
{
}

read_result_entry &read_result_entry::operator =(const read_result_entry &other)
{
	callback_result_entry::operator =(other);
	return *this;
}

struct dnet_io_attr *read_result_entry::io_attribute() const
{
	return data()
		.data<struct dnet_io_attr>();
}

data_pointer read_result_entry::file() const
{
	return data()
		.skip<struct dnet_io_attr>();
}

lookup_result_entry::lookup_result_entry()
{
}

lookup_result_entry::lookup_result_entry(const lookup_result_entry &other) : callback_result_entry(other)
{
}

lookup_result_entry::~lookup_result_entry()
{
}

lookup_result_entry &lookup_result_entry::operator =(const lookup_result_entry &other)
{
	callback_result_entry::operator =(other);
	return *this;
}

struct dnet_addr *lookup_result_entry::storage_address() const
{
	return data()
		.data<struct dnet_addr>();
}

struct dnet_file_info *lookup_result_entry::file_info() const
{
	return data()
		.skip<struct dnet_addr>()
		.data<struct dnet_file_info>();
}

const char *lookup_result_entry::file_path() const
{
	return data()
		.skip<struct dnet_addr>()
		.skip<struct dnet_file_info>()
		.data<char>();
}

stat_result_entry::stat_result_entry()
{
}

stat_result_entry::stat_result_entry(const stat_result_entry &other) : callback_result_entry(other)
{
}

stat_result_entry::~stat_result_entry()
{
}

stat_result_entry &stat_result_entry::operator =(const stat_result_entry &other)
{
	callback_result_entry::operator =(other);
	return *this;
}

dnet_stat *stat_result_entry::statistics() const
{
	return m_data->data
		.skip<struct dnet_addr>()
		.skip<struct dnet_cmd>()
		.data<struct dnet_stat>();
}

stat_count_result_entry::stat_count_result_entry()
{
}

stat_count_result_entry::stat_count_result_entry(const stat_count_result_entry &other) : callback_result_entry(other)
{
}

stat_count_result_entry::~stat_count_result_entry()
{
}

stat_count_result_entry &stat_count_result_entry::operator =(const stat_count_result_entry &other)
{
	callback_result_entry::operator =(other);
	return *this;
}

struct dnet_addr_stat *stat_count_result_entry::statistics() const
{
	return m_data->data
		.skip<struct dnet_addr>()
		.skip<struct dnet_cmd>()
		.data<struct dnet_addr_stat>();
}

exec_result_entry::exec_result_entry()
{
}

exec_result_entry::exec_result_entry(const std::shared_ptr<callback_result_data> &data)
	: callback_result_entry(data)
{
}

exec_result_entry::exec_result_entry(const exec_result_entry &other) : callback_result_entry(other)
{
}

exec_result_entry::~exec_result_entry()
{
}

exec_result_entry &exec_result_entry::operator =(const exec_result_entry &other)
{
	callback_result_entry::operator =(other);
	return *this;
}

exec_context exec_result_entry::context() const
{
	if (m_data->error)
		m_data->error.throw_error();
	return m_data->context;
}

iterator_result_entry::iterator_result_entry()
{
}

iterator_result_entry::iterator_result_entry(const iterator_result_entry &other) : callback_result_entry(other)
{
}

iterator_result_entry::~iterator_result_entry()
{
}

iterator_result_entry &iterator_result_entry::operator =(const iterator_result_entry &other)
{
	callback_result_entry::operator =(other);
	return *this;
}

dnet_iterator_response *iterator_result_entry::reply() const
{
	return data<dnet_iterator_response>();
}

uint64_t iterator_result_entry::user_flags() const
{
	return reply()->user_flags;
}

uint64_t iterator_result_entry::id() const
{
	return reply()->id;
}

data_pointer iterator_result_entry::reply_data() const
{
	return data().skip<dnet_iterator_response>();
}

} } // namespace ioremap::elliptics
