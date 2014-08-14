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

#ifndef CALLBACK_P_H
#define CALLBACK_P_H

#include "elliptics/cppdef.h"

#include <algorithm>
#include <cassert>
#include <condition_variable>
#include <exception>
#include <iostream>
#include <mutex>
#include <set>
#include <sstream>
#include <thread>

#include <blackhole/scoped_attributes.hpp>

#include "elliptics/async_result_cast.hpp"

extern "C" {
#include "foreign/cmp/cmp.h"
}

//#ifdef DEVELOPER_BUILD
//#  define elliptics_assert(expr) assert(expr)
//#else
#  define elliptics_assert(expr)
//#endif

namespace ioremap { namespace elliptics {

class session_scope
{
	public:
		session_scope(session &sess) : m_sess(sess)
		{
			m_filter = m_sess.get_filter();
			m_checker = m_sess.get_checker();
			m_policy = m_sess.get_exceptions_policy();
			m_cflags = m_sess.get_cflags();
			m_ioflags = m_sess.get_ioflags();
		}

		~session_scope()
		{
			m_sess.set_filter(m_filter);
			m_sess.set_checker(m_checker);
			m_sess.set_exceptions_policy(m_policy);
			m_sess.set_cflags(m_cflags);
			m_sess.set_ioflags(m_ioflags);
		}

	private:
		session &m_sess;
		result_filter m_filter;
		result_checker m_checker;
		uint64_t m_cflags;
		uint32_t m_ioflags;
		uint32_t m_policy;
};

class scoped_trace_id
{
public:
	scoped_trace_id(session &sess) :
		m_attributes(sess.get_logger(), create_attributes(sess))
	{
	}

private:
	static blackhole::log::attributes_t create_attributes(session &sess)
	{
		blackhole::log::attributes_t attributes = {
			keyword::request_id() = sess.get_trace_id()
		};
		return std::move(attributes);
	}

	blackhole::scoped_attributes_t m_attributes;
};

typedef int (*complete_func)(struct dnet_net_state *, struct dnet_cmd *, void *);

class callback_result_data
{
	public:
		callback_result_data()
		{
		}

		callback_result_data(dnet_addr *addr, dnet_cmd *cmd)
		{
			const size_t size = sizeof(dnet_addr) + sizeof(dnet_cmd) + cmd->size;
			data = data_pointer::allocate(size);
			if (addr)
				memcpy(data.data(), addr, sizeof(dnet_addr));
			else
				memset(data.data(), 0, sizeof(dnet_addr));
			memcpy(data.data<char>() + sizeof(dnet_addr), cmd, sizeof(dnet_cmd) + cmd->size);
		}

		virtual ~callback_result_data()
		{
		}

		data_pointer data;
		error_info error;
		exec_context context;
};

enum special_count { unlimited };

struct entry_converter
{
	static void convert(exec_result_entry &entry, callback_result_data *data)
	{
		data->context = exec_context::parse(entry.data(), &data->error);
	}

	static void convert(iterator_result_entry &entry, callback_result_data *)
	{
		dnet_convert_iterator_response(entry.reply());
	}

	static void convert(lookup_result_entry &entry, callback_result_data *)
	{
		dnet_convert_addr(entry.storage_address());
		dnet_convert_file_info(entry.file_info());
	}

	static void convert(read_result_entry &entry, callback_result_data *)
	{
		dnet_convert_io_attr(entry.io_attribute());
	}

	static void convert(backend_status_result_entry &, callback_result_data *)
	{
	}

	static void convert(callback_result_entry &, callback_result_data *)
	{
	}
};

struct dnet_net_state_deleter
{
	void operator () (dnet_net_state *state) const
	{
		if (state)
			dnet_state_put(state);
	}
};

typedef std::unique_ptr<dnet_net_state, dnet_net_state_deleter> net_state_ptr;

// Send request to specific state
async_generic_result send_to_single_state(session &sess, const transport_control &control);
async_generic_result send_to_single_state(session &sess, dnet_io_control &control);

// Send request to each backend
async_generic_result send_to_each_backend(session &sess, const transport_control &control);

// Send request to each node
async_generic_result send_to_each_node(session &sess, const transport_control &control);

// Send request to one state at each session's group
async_generic_result send_to_groups(session &sess, const transport_control &control);
async_generic_result send_to_groups(session &sess, dnet_io_control &control);

async_generic_result send_srw_command(session &sess, dnet_id *id, sph *srw_data);

template <typename Handler, typename Entry>
class multigroup_handler : public std::enable_shared_from_this<multigroup_handler<Handler, Entry>>
{
public:
	typedef multigroup_handler<Handler, Entry> parent_type;

	multigroup_handler(const session &sess, const async_result<Entry> &result, std::vector<int> &&groups) :
		m_sess(sess.clean_clone()),
		m_handler(result),
		m_groups(std::move(groups)),
		m_group_index(0)
	{
		m_sess.set_checker(sess.get_checker());
	}

	void start()
	{
		if (m_groups.empty()) {
			m_handler.complete(error_info());
			return;
		}

		next_group();
	}

	void process(const Entry &entry)
	{
		process_entry(entry);

		m_handler.process(entry);
	}

	void complete(const error_info &error)
	{
		group_finished(error);
		++m_group_index;

		if (m_group_index < m_groups.size() && need_next_group(error)) {
			next_group();
		} else {
			m_handler.complete(error_info());
		}
	}

	void set_total(size_t total)
	{
		m_handler.set_total(total);
	}

protected:
	int current_group()
	{
		return m_groups[m_group_index];
	}

	void next_group()
	{
		using std::placeholders::_1;

		async_result_cast<Entry>(m_sess, send_to_next_group()).connect(
			std::bind(&multigroup_handler::process, this->shared_from_this(), _1),
			std::bind(&multigroup_handler::complete, this->shared_from_this(), _1)
		);
	}

	// Override this if you want to do something on each received packet
	virtual void process_entry(const Entry &entry)
	{
		(void) entry;
	}

	// Override this if you want to change the stop condition
	virtual bool need_next_group(const error_info &error)
	{
		return !!error;
	}

	// Override this if you want to do something before going to next group
	virtual void group_finished(const error_info &error)
	{
		(void) error;
	}

	// Override this to implement your send logic
	virtual async_generic_result send_to_next_group() = 0;

	session m_sess;
	async_result_handler<Entry> m_handler;
	const std::vector<int> m_groups;
	size_t m_group_index;
};

class net_state_id
{
public:
	net_state_id() : m_backend(-1)
	{
	}

	net_state_id(net_state_id &&other) : m_state(std::move(other.m_state)), m_backend(other.m_backend)
	{
	}

	net_state_id(dnet_node *node, const dnet_id *id) : m_backend(-1)
	{
		reset(node, id);
	}

	net_state_id &operator =(net_state_id &&other)
	{
		m_state = std::move(other.m_state);
		m_backend = other.m_backend;
		return *this;
	}

	void reset(dnet_node *node, const dnet_id *id)
	{
		m_backend = -1;
		m_state.reset(dnet_state_get_first_with_backend(node, id, &m_backend));
	}

	void reset()
	{
		m_state.reset();
		m_backend = -1;
	}

	dnet_net_state *operator ->() const
	{
		return m_state.get();
	}

	bool operator ==(const net_state_id &other)
	{
		return m_state == other.m_state && m_backend == other.m_backend;
	}

	bool operator !() const
	{
		return !m_state;
	}

	operator bool() const
	{
		return !!m_state;
	}

	dnet_net_state *state() const
	{
		return m_state.get();
	}

	int backend() const
	{
		return m_backend;
	}

private:
	net_state_ptr m_state;
	int m_backend;
};

#define debug(...) BH_LOG(m_logger, DNET_LOG_DEBUG, __VA_ARGS__)
#define notice(...) BH_LOG(m_logger, DNET_LOG_NOTICE, __VA_ARGS__)

} } // namespace ioremap::elliptics

#endif // CALLBACK_P_H
