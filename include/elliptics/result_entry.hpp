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

#ifndef ELLIPTICS_RESULT_ENTRY_HPP
#define ELLIPTICS_RESULT_ENTRY_HPP

#include "elliptics/utils.hpp"
#include "elliptics/async_result.hpp"

#include <map>
#include <vector>

namespace ioremap { namespace elliptics {

class callback_result_data;
struct exec_context_data;

// exec_context is context for execution requests, it stores
// internal identification of the process and environmental
// variables like event name and data
class exec_context
{
	public:
		// type of reply
		enum final_state {
			progressive, // there will be more replies
			final // final reply
		};

		exec_context();
		// construct from data_pointer, may throw exception
		exec_context(const data_pointer &data);
		exec_context(const std::shared_ptr<exec_context_data> &data);
		exec_context(const exec_context &other);
		exec_context &operator =(const exec_context &other);
		~exec_context();

		// construct from raw_data
		static exec_context from_raw(const void *data, size_t size);
		// construct from data_pointer, in case of error \a error is filled
		static exec_context parse(const data_pointer &data, error_info *error);

		// event name
		std::string event() const;
		// event data
		data_pointer data() const;

		// access to address of the machine emitted the reply
		dnet_addr *address() const;

		// access to "return id" by which reply is routed back,
		// allows to augment sph.src with some sub id or change it completely
		//NOTE: dangerous, use with care
		dnet_raw_id *src_id() const;

		// access to "sub id" supplement to src_id
		// also allows to change it on the fly
		//NOTE: dangerous, use with care
		int src_key() const;
		void set_src_key(int src_key) const;

		// get back original data block of the entire request
		data_pointer native_data() const;

		bool is_final() const;
		bool is_null() const;

	private:
		friend class session;
		friend struct exec_context_data;
		std::shared_ptr<exec_context_data> m_data;
};

class callback_result_entry
{
	public:
		callback_result_entry();
		callback_result_entry(const callback_result_entry &other);
		callback_result_entry(const std::shared_ptr<callback_result_data> &data);
		~callback_result_entry();

		callback_result_entry &operator =(const callback_result_entry &other);

		bool is_valid() const;
		bool is_ack() const;
		int status() const;
		error_info error() const;
		data_pointer		raw_data() const;
		struct dnet_addr	*address() const;
		struct dnet_cmd		*command() const;
		data_pointer		data() const;
		uint64_t		size() const;
		template <typename T>
		inline T		*data() const
		{ return data().data<T>(); }

	protected:
		std::shared_ptr<callback_result_data> m_data;
};

class read_result_entry : public callback_result_entry
{
	public:
		read_result_entry();
		read_result_entry(const read_result_entry &other);
		~read_result_entry();

		read_result_entry &operator =(const read_result_entry &other);

		struct dnet_io_attr *io_attribute() const;
		data_pointer file() const;
};

class lookup_result_entry : public callback_result_entry
{
	public:
		lookup_result_entry();
		lookup_result_entry(const lookup_result_entry &other);
		~lookup_result_entry();

		lookup_result_entry &operator =(const lookup_result_entry &other);

		struct dnet_addr *storage_address() const;
		struct dnet_file_info *file_info() const;
		const char *file_path() const;
};

class stat_result_entry : public callback_result_entry
{
	public:
		stat_result_entry();
		stat_result_entry(const stat_result_entry &other);
		~stat_result_entry();

		stat_result_entry &operator =(const stat_result_entry &other);

		struct dnet_stat *statistics() const;
};

class stat_count_result_entry : public callback_result_entry
{
	public:
		stat_count_result_entry();
		stat_count_result_entry(const stat_count_result_entry &other);
		~stat_count_result_entry();

		stat_count_result_entry &operator =(const stat_count_result_entry &other);

		struct dnet_addr_stat *statistics() const;
};

class exec_context;
class exec_callback;

class exec_result_entry : public callback_result_entry
{
	public:
		exec_result_entry();
		exec_result_entry(const std::shared_ptr<callback_result_data> &data);
		exec_result_entry(const exec_result_entry &other);
		~exec_result_entry();

		exec_result_entry &operator =(const exec_result_entry &other);

		exec_context context() const;

	private:
		friend class exec_callback;
};

class iterator_result_entry : public callback_result_entry
{
	public:
		iterator_result_entry();
		iterator_result_entry(const iterator_result_entry &other);
		~iterator_result_entry();

		iterator_result_entry &operator =(const iterator_result_entry &other);

		dnet_iterator_response *reply() const;
		data_pointer reply_data() const;

		uint64_t id() const;
};

// Container for iterator results
class iterator_result_container
{
	public:
		iterator_result_container(int fd, bool sorted = false, uint64_t write_position = 0)
			: m_fd(fd), m_sorted(sorted), m_write_position(write_position) {
				m_count = m_write_position / sizeof(dnet_iterator_response);
			}
		// Appends one result to container
		void append(const iterator_result_entry &result);
		void append(const dnet_iterator_response *response);
		// Sorts container
		void sort();
		//! Puts difference between \a this and \a other into \a diff
		void diff(const iterator_result_container &other,
				iterator_result_container &result) const;
		dnet_iterator_response operator [](size_t n) const;

		int m_fd;
		bool m_sorted;
		uint64_t m_count;
		uint64_t m_write_position;
};

typedef lookup_result_entry write_result_entry;
typedef callback_result_entry remove_result_entry;

struct index_entry
{
	index_entry()
	{}

	index_entry(const dnet_raw_id &index, const data_pointer &data) : index(index), data(data)
	{}

	dnet_raw_id index;
	data_pointer data;
};

struct find_indexes_result_entry
{
	dnet_raw_id id;
	std::vector<index_entry> indexes;
};

typedef async_result<callback_result_entry> async_generic_result;
typedef std::vector<callback_result_entry> sync_generic_result;

typedef async_result<write_result_entry> async_write_result;
typedef std::vector<write_result_entry> sync_write_result;
typedef async_result<lookup_result_entry> async_lookup_result;
typedef std::vector<lookup_result_entry> sync_lookup_result;
typedef async_result<read_result_entry> async_read_result;
typedef std::vector<read_result_entry> sync_read_result;
typedef async_generic_result async_remove_result;
typedef sync_generic_result sync_remove_result;

typedef async_result<stat_result_entry> async_stat_result;
typedef std::vector<stat_result_entry> sync_stat_result;
typedef async_result<stat_count_result_entry> async_stat_count_result;
typedef std::vector<stat_count_result_entry> sync_stat_count_result;

typedef async_result<iterator_result_entry> async_iterator_result;
typedef std::vector<iterator_result_entry> sync_iterator_result;

typedef async_result<exec_result_entry> async_exec_result;
typedef std::vector<exec_result_entry> sync_exec_result;
typedef async_result<exec_result_entry> async_push_result;
typedef std::vector<exec_result_entry> sync_push_result;
typedef async_result<exec_result_entry> async_reply_result;
typedef std::vector<exec_result_entry> sync_reply_result;

typedef async_result<callback_result_entry> async_update_indexes_result;
typedef std::vector<callback_result_entry> sync_update_indexes_result;
typedef async_result<callback_result_entry> async_set_indexes_result;
typedef std::vector<callback_result_entry> sync_set_indexes_result;
typedef async_result<find_indexes_result_entry> async_find_indexes_result;
typedef std::vector<find_indexes_result_entry> sync_find_indexes_result;
typedef async_result<index_entry> async_list_indexes_result;
typedef std::vector<index_entry> sync_list_indexes_result;

static inline bool operator <(const dnet_raw_id &a, const dnet_raw_id &b)
{
	return memcmp(a.id, b.id, sizeof(a.id)) < 0;
}

static inline bool operator ==(const dnet_raw_id &a, const dnet_raw_id &b)
{
	return memcmp(a.id, b.id, sizeof(a.id)) == 0;
}

static inline bool operator ==(const dnet_raw_id &a, const ioremap::elliptics::index_entry &b)
{
	return memcmp(a.id, b.index.id, sizeof(a.id)) == 0;
}

static inline bool operator ==(const ioremap::elliptics::index_entry &a, const dnet_raw_id &b)
{
	return memcmp(b.id, a.index.id, sizeof(b.id)) == 0;
}

static inline bool operator ==(const ioremap::elliptics::data_pointer &a, const ioremap::elliptics::data_pointer &b)
{
	return a.size() == b.size() && memcmp(a.data(), b.data(), a.size()) == 0;
}

static inline bool operator ==(const ioremap::elliptics::index_entry &a, const ioremap::elliptics::index_entry &b)
{
	return a.data.size() == b.data.size()
		&& memcmp(b.index.id, a.index.id, sizeof(b.index.id)) == 0
		&& memcmp(a.data.data(), b.data.data(), a.data.size()) == 0;
}

enum { skip_data = 0, compare_data = 1 };

template <int CompareData = compare_data>
struct dnet_raw_id_less_than
{
	inline bool operator() (const dnet_raw_id &a, const dnet_raw_id &b) const
	{
		return memcmp(a.id, b.id, sizeof(a.id)) < 0;
	}
	inline bool operator() (const index_entry &a, const dnet_raw_id &b) const
	{
		return operator() (a.index, b);
	}
	inline bool operator() (const dnet_raw_id &a, const index_entry &b) const
	{
		return operator() (a, b.index);
	}
	inline bool operator() (const index_entry &a, const index_entry &b) const
	{
		ssize_t cmp = memcmp(a.index.id, b.index.id, sizeof(b.index.id));
		if (CompareData && cmp == 0) {
			cmp = a.data.size() - b.data.size();
			if (cmp == 0) {
				cmp = memcmp(a.data.data(), b.data.data(), a.data.size());
			}
		}
		return cmp < 0;
	}
	inline bool operator() (const index_entry &a, const find_indexes_result_entry &b) const
	{
		return operator() (a.index, b.id);
	}
	inline bool operator() (const find_indexes_result_entry &a, const index_entry &b) const
	{
		return operator() (a.id, b.index);
	}
};

typedef std::map<dnet_raw_id, std::string, dnet_raw_id_less_than<>> id_to_name_map_t;
typedef std::map<std::string, dnet_raw_id> name_to_id_map_t;

}} /* namespace ioremap::elliptics */

#endif // ELLIPTICS_RESULT_ENTRY_HPP
