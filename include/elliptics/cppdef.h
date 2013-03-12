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
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 */

#ifndef __EDEF_H
#define __EDEF_H

#include <errno.h>

#include <elliptics/typedefs.h>
#include <elliptics/packet.h>
#include <elliptics/interface.h>


#include <iostream>
#include <fstream>
#include <exception>
#include <memory>
#include <list>
#include <stdexcept>
#include <string>
#include <vector>
#include <memory>
#include <functional>

#define ELLIPTICS_DISABLE_COPY(CLASS) \
private: \
		CLASS(const CLASS &); \
		CLASS &operator =(const CLASS &);

namespace ioremap { namespace elliptics {

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

		void throw_error() const;
	private:
		int m_code;
		std::string m_message;
};

class key;
class session;

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

class default_callback;
class callback_data;
class callback_result_data;

class data_pointer
{
	public:
		data_pointer() : m_index(0), m_size(0) {}

		data_pointer(void *data, size_t size)
			: m_data(std::make_shared<wrapper>(data)), m_index(0), m_size(size)
		{
		}

		data_pointer(const std::string &str)
			: m_data(std::make_shared<wrapper>(const_cast<char*>(str.c_str()), false)),
			m_index(0), m_size(str.size())
		{
		}

		static data_pointer copy(void *data, size_t size)
		{
			data_pointer that = allocate(size);
			memcpy(that.data(), data, size);
			return that;
		}

		static data_pointer copy(const data_pointer &other)
		{
			return copy(other.data(), other.size());
		}

		static data_pointer allocate(size_t size)
		{
			void *data = malloc(size);
			if (!data)
				throw std::bad_alloc();
			return data_pointer(data, size);
		}

		static data_pointer from_raw(void *data, size_t size)
		{
			data_pointer pointer;
			pointer.m_index = 0;
			pointer.m_size = size;
			pointer.m_data =  std::make_shared<wrapper>(data, false);
			return pointer;
		}

		static data_pointer from_raw(const std::string &str)
		{
			return from_raw(const_cast<char*>(str.c_str()), str.size());
		}

		template <typename T>
		data_pointer skip() const
		{
			data_pointer tmp(*this);
			tmp.m_index += sizeof(T);
			return tmp;
		}

		data_pointer skip(size_t size) const
		{
			data_pointer tmp(*this);
			tmp.m_index += size;
			return tmp;
		}

		void *data() const
		{
			if (m_index > m_size)
				throw not_found_error("null pointer exception");
			else if (m_index == m_size)
				return NULL;
			else
				return reinterpret_cast<char*>(m_data->get()) + m_index;
		}

		template <typename T>
		T *data() const
		{
			if (m_index + sizeof(T) > m_size)
				throw not_found_error("null pointer exception");
			return reinterpret_cast<T *>(data());
		}

		size_t size() const { return m_index >= m_size ? 0 : (m_size - m_index); }
		size_t offset() const { return m_index; }
		bool empty() const { return m_index >= m_size; }
		std::string to_string() const { return std::string(reinterpret_cast<char*>(data()), size()); }

	private:
		class wrapper
		{
			public:
				inline wrapper(void *data, bool owner = true) : data(data), owner(owner) {}
				inline ~wrapper() { if (owner && data) free(data); }

				inline void *get() const { return data; }

			private:
				void *data;
				bool owner;
		};

		std::shared_ptr<wrapper> m_data;
		size_t m_index;
		size_t m_size;
};

class generic_result_holder
{
	protected:
		class generic_data
		{
			public:
				generic_data() {}
				generic_data(const std::exception_ptr &exc) : exception(exc) {}

				virtual ~generic_data() {}

				std::exception_ptr exception;
		};

	public:
		generic_result_holder() {}
		generic_result_holder(generic_data &data) : m_data(&data) {}
		~generic_result_holder() {}

		std::exception_ptr exception() const
		{
			return m_data->exception;
		}

		void check() const
		{
			if (!m_data)
				throw not_found_error("no data received");
			else if (m_data->exception != std::exception_ptr())
				std::rethrow_exception(m_data->exception);
		}

	protected:
		std::shared_ptr<generic_data> m_data;
};

template <typename T>
class result_holder : public generic_result_holder
{
	public:
		result_holder() {}
		result_holder(const T &result) : generic_result_holder(*new data(result)) {}
		result_holder(const std::exception_ptr &exc) : generic_result_holder(*new data(exc)) {}

		T *operator-> () { check(); return &d_func()->result; }
		const T *operator-> () const { check(); return &d_func()->result; }
		T &operator *() { check(); return d_func()->result; }
		const T &operator *() const { check(); return d_func()->result; }

	private:
		class data : public generic_data
		{
			public:
				data(const T &result) : result(result) {}
				data(const std::exception_ptr &exc) : generic_data(exc) {}

				T result;
		};

		data *d_func() { return static_cast<data*>(m_data.get()); }
		const data *d_func() const { return static_cast<data*>(m_data.get()); }
};

template <typename T>
class array_result_holder : public generic_result_holder
{
	public:
		array_result_holder() {}
		array_result_holder(const std::vector<T> &result) : generic_result_holder(*new data(result)) {}
		array_result_holder(const std::exception_ptr &exc) : generic_result_holder(*new data(exc)) {}

		T &operator[] (size_t index) { check(); return d_func()->result[index]; }
		const T &operator[] (size_t index) const { check(); return d_func()->result[index]; }
		size_t size() const { if (!d_func()) return 0; check(); return d_func()->result.size(); }

		operator std::vector<T> &() { check(); return d_func()->result; }
		operator const std::vector<T> &() const { check(); return d_func()->result; }

	private:
		class data : public generic_data
		{
			public:
				data(const std::vector<T> &result) : result(result) {}
				data(const std::exception_ptr &exc) : generic_data(exc) {}

				std::vector<T> result;
		};

		data *d_func() { return static_cast<data*>(m_data.get()); }
		const data *d_func() const { return static_cast<data*>(m_data.get()); }
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

		friend class callback;
		friend class default_callback;
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
class exec_result_data;

class exec_result_entry : public callback_result_entry
{
	public:
		exec_result_entry();
		exec_result_entry(const std::shared_ptr<exec_result_data> &data);
		exec_result_entry(const exec_result_entry &other);
		~exec_result_entry();

		exec_result_entry &operator =(const exec_result_entry &other);

		error_info error() const;

		exec_context context() const;
};

typedef lookup_result_entry write_result_entry;
typedef result_holder<read_result_entry> read_result;
typedef array_result_holder<write_result_entry> write_result;
typedef array_result_holder<read_result_entry> read_results;
typedef array_result_holder<read_result_entry> bulk_read_result;
typedef array_result_holder<read_result_entry> read_range_result;
typedef array_result_holder<read_result_entry> remove_range_result;
typedef array_result_holder<callback_result_entry> command_result;
typedef result_holder<lookup_result_entry> lookup_result;
typedef array_result_holder<stat_result_entry> stat_result;
typedef array_result_holder<stat_count_result_entry> stat_count_result;
typedef array_result_holder<int> prepare_latest_result;

typedef exec_result_entry exec_result;
typedef std::vector<exec_result> exec_results;
typedef exec_result_entry push_result;
typedef exec_result_entry reply_result;

typedef std::exception_ptr update_indexes_result;
typedef array_result_holder<dnet_raw_id> find_indexes_result;
typedef array_result_holder<dnet_raw_id> check_indexes_result;

class exec_context_data;

class exec_context
{
	public:
		enum final_state { progressive, final };

		exec_context();
		exec_context(const data_pointer &data);
		exec_context(const std::shared_ptr<exec_context_data> &data);
		exec_context(const exec_context &other);
		exec_context &operator =(const exec_context &other);
		~exec_context();

		static exec_context from_raw(const void *data, size_t size);

		std::string event() const;
		data_pointer data() const;
		dnet_addr *address() const;
		bool is_final() const;

	private:
		friend class session;
		friend class exec_context_data;
		std::shared_ptr<exec_context_data> m_data;
};

class transport_control
{
	public:
		transport_control();
		transport_control(const struct dnet_id &id, unsigned int cmd, uint64_t cflags = 0);

		void set_key(const struct dnet_id &id);
		void set_command(unsigned int cmd);
		void set_cflags(uint64_t cflags);
		void set_data(void *data, unsigned int size);

		struct dnet_trans_control get_native() const;

	private:
		struct dnet_trans_control m_data;
};

struct address
{
	address(const std::string &l_host, const int l_port, const int l_family = AF_INET)
		: host(l_host), port(l_port), family(l_family) {}

	std::string		host;
	int			port;
	int			family;
};

class logger_interface
{
	public:
		virtual ~logger_interface() {}

		virtual void log(const int level, const char *msg) = 0;
};

class logger_data;

class logger
{
	public:
		explicit logger(logger_interface *interface, const int level = DNET_LOG_INFO);
		logger();
		logger(const logger &other);
		~logger();

		logger &operator =(const logger &other);

		void 		log(const int level, const char *msg);
		int			get_log_level();
		struct dnet_log		*get_native();

	protected:
		std::shared_ptr<logger_data> m_data;
};

class file_logger : public logger
{
	public:
		explicit file_logger(const char *file, const int level = DNET_LOG_INFO);
		~file_logger();
};

class node_data;
class session_data;

class node
{
	public:
		explicit node(const logger &l);
		node(const logger &l, struct dnet_config &cfg);
		node(const logger &l, const std::string &config_path);
		node(const node &other);
		~node();

		node &operator =(const node &other);

		void			parse_config(const std::string &path, struct dnet_config &cfg,
							std::list<address> &remotes,
							std::vector<int> &groups,
							int &log_level);

		void			add_remote(const char *addr, const int port, const int family = AF_INET);
		void			add_remote(const char *addr);

		void			set_timeouts(const int wait_timeout, const int check_timeout);

		logger get_log() const;
		struct dnet_node *	get_native();

	protected:
		std::shared_ptr<node_data> m_data;

		friend class session;
		friend class session_data;
};

class session;

class key
{
	public:
		key();
		key(const std::string &remote, int type = 0);
		key(const struct dnet_id &id);
		key(const key &other);
		key &operator = (const key &other);
		~key();

		bool operator==(const key &other) const;
		bool operator <(const key &other) const;

		bool by_id() const;
		const std::string &remote() const;
		int type() const;
		const struct dnet_id &id() const;
		std::string to_string() const;

		void transform(session &sess);

	private:
		bool m_by_id;
		std::string m_remote;
		int m_type;
		struct dnet_id m_id;
};

class session
{
	public:
		explicit session(const node &n);
		session(const session &other);
		virtual ~session();

		session &operator =(const session &other);

		/*!
		 * Converts string \a data to dnet_id \a id.
		 */
		void			transform(const std::string &data, struct dnet_id &id);
		/*!
		 * \overload transform()
		 */
		void			transform(const data_pointer &data, struct dnet_id &id);
		/*!
		 * Makes dnet_id be accessable by key::id() in the key \a id.
		 */
		void			transform(const key &id);

		/*!
		 * Sets \a groups to the session.
		 */
		void			set_groups(const std::vector<int> &groups);
		/*!
		 * Gets groups of the session.
		 */
		std::vector<int>	get_groups() const;

		/*!
		 * Sets command flags \a cflags to the session.
		 */
		void			set_cflags(uint64_t cflags);
		/*!
		 * Gets command flags of the session.
		 */
		uint64_t		get_cflags() const;

		/*!
		 * Sets i/o flags \a ioflags to the session.
		 */
		void			set_ioflags(uint32_t ioflags);
		/*!
		 * Gets i/o flags of the session.
		 */
		uint32_t		get_ioflags() const;

		void			set_timeout(unsigned int timeout);

		/*!
		 * Read file by key \a id to \a file by \a offset and \a size.
		 */
		void			read_file(const key &id, const std::string &file, uint64_t offset, uint64_t size);
		/*!
		 * Write file from \a file to server by key \a id, \a offset and \a size.
		 */
		void			write_file(const key &id, const std::string &file, uint64_t local_offset,
							uint64_t offset, uint64_t size);

		/*!
		 * Reads data from server by \a key id and dnet_io_attr \io.
		 * Data is requested iteratively to \a groups until the first success
		 * or groups are ended.
		 * Command is sent to server is DNET_CMD_READ.
		 *
		 * Result is returned to \a handler.
		 */
		void			read_data(const std::function<void (const read_results &)> &handler,
						const key &id, const std::vector<int> &groups,
						const struct dnet_io_attr &io);
		/*!
		 * \overload read_data()
		 * Allows to specify the command \a cmd.
		 */
		void			read_data(const std::function<void (const read_results &)> &handler,
						const key &id, const std::vector<int> &groups,
						const struct dnet_io_attr &io, unsigned int cmd);
		/*!
		 * \overload read_data()
		 * Allows to specify the single \a group.
		 */
		void			read_data(const std::function<void (const read_results &)> &handler,
						const key &id, int group_id, const struct dnet_io_attr &io);
		/*!
		 * \overload read_data()
		 * Allows to specify the \a offset and the \a size.
		 */
		void			read_data(const std::function<void (const read_result  &)> &handler,
						const key &id, const std::vector<int> &groups,
						uint64_t offset, uint64_t size);
		/*!
		 * \overload read_data()
		 * Allows to specify the \a offset and the \a size.
		 * Groups are generated automatically by session::mix_states().
		 */
		void			read_data(const std::function<void (const read_result &)> &handler,
						const key &id, uint64_t offset, uint64_t size);
		/*!
		 * \overload read_data()
		 * Synchronous overload.
		 */
		read_result		read_data(const key &id, uint64_t offset, uint64_t size);
		/*!
		 * \overload read_data()
		 * Synchronous overload.
		 */
		read_result		read_data(const key &id, const std::vector<int> &groups,
						uint64_t offset, uint64_t size);
		/*!
		 * \overload read_data()
		 * Synchronous overload.
		 */
		read_result		read_data(const key &id, int group_id, uint64_t offset, uint64_t size);

		/*!
		 * Filters the list \a groups and leaves only ones with the latest
		 * data at key \a id.
		 *
		 * Result is returned to \a handler.
		 */
		void			prepare_latest(const std::function<void (const prepare_latest_result &)> &handler,
						const key &id, const std::vector<int> &groups);
		/*!
		 * \overload prepare_latest()
		 * Synchronous overload.
		 *
		 * Results overrides the \a groups argument.
		 */
		void			prepare_latest(const key &id, std::vector<int> &groups);

		/*!
		 * Reads the latest data from server by the key \a id, \a offset and \a size.
		 *
		 * Result is returned to \a handler.
		 */
		void			read_latest(const std::function<void (const read_result &)> &handler,
						const key &id, uint64_t offset, uint64_t size);
		/*!
		 * \overload read_latest()
		 * Synchronous overload.
		 */
		read_result		read_latest(const key &id, uint64_t offset, uint64_t size);

		/*!
		 * Writes data to server by the dnet_io_control \a ctl.
		 *
		 * Result is returned to \a handler.
		 */
		void			write_data(const std::function<void (const write_result &)> &handler,
						const dnet_io_control &ctl);
		/*!
		 * Writes data \a file by the key \a id and remote offset \a remote_offset.
		 *
		 * Result is returned to \a handler.
		 *
		 * \note Calling this method is equal to consecutive calling
		 * of write_prepare(), write_plain() and write_commit().
		 */
		void			write_data(const std::function<void (const write_result &)> &handler,
						const key &id, const data_pointer &file,
						uint64_t remote_offset);
		/*!
		 * \overload write_data()
		 * Synchronous overload.
		 */
		write_result		write_data(const key &id, const data_pointer &file,
						uint64_t remote_offset);


		void write_cas(const std::function<void (const write_result &)> &handler, const key &id,
			const std::function<data_pointer (const data_pointer &)> &converter, uint64_t remote_offset, int count = 3);
		write_result write_cas(const key &id, const std::function<data_pointer (const data_pointer &)> &converter,
			uint64_t remote_offset, int count = 3);

		/*!
		 * Writes data \a file by the key \a id and remote offset \a remote_offset.
		 *
		 * Writing is refused if check sum of server data is not equal
		 * to \a old_csum. elliptics::error with -EINVAL is thrown at this case.
		 *
		 * Result is returned to \a handler.
		 */
		void			write_cas(const std::function<void (const write_result &)> &handler,
						const key &id, const data_pointer &file,
						const struct dnet_id &old_csum, uint64_t remote_offset);
		/*!
		 * \overload write_cas()
		 * Synchronous overload.
		 */
		write_result		write_cas(const key &id, const data_pointer &file,
						const struct dnet_id &old_csum, uint64_t remote_offset);

		/*!
		 * Prepares place to write data \a file by the key \a id and
		 * remote offset \a remote_offset.
		 *
		 * Result is returned to \a handler.
		 *
		 * \note No data is really written.
		 */
		void			write_prepare(const std::function<void (const write_result &)> &handler,
						const key &id, const data_pointer &file,
						uint64_t remote_offset, uint64_t psize);
		/*!
		 * \overload write_prepare()
		 * Synchronous overload.
		 */
		write_result		write_prepare(const key &id, const data_pointer &file,
						uint64_t remote_offset, uint64_t psize);

		/*!
		 * Writes data \a file by the key \a id and remote offset \a remote_offset.
		 *
		 * Result is returned to \a handler.
		 *
		 * \note Indexes are not updated. Data is not accessable for reading.
		 */
		void			write_plain(const std::function<void (const write_result &)> &handler,
						const key &id, const data_pointer &file,
						uint64_t remote_offset);
		/*!
		 * \overload write_plain()
		 * Synchronous overload.
		 */
		write_result		write_plain(const key &id, const data_pointer &file,
						uint64_t remote_offset);

		/*!
		 * Commites data \a file by the key \a id and remote offset \a remote_offset.
		 *
		 * Result is returned to \a handler.
		 *
		 * \note Indexes are updated. Data becomes accessable for reading.
		 */
		void			write_commit(const std::function<void (const write_result &)> &handler,
						const key &id, const data_pointer &file,
						uint64_t remote_offset, uint64_t csize);
		/*!
		 * \overload write_commit()
		 * Synchronous overload.
		 */
		write_result		write_commit(const key &id, const data_pointer &file,
						uint64_t remote_offset, uint64_t csize);

		/*!
		 * Writes data \a file by the key \a id and remote offset \a remote_offset.
		 * Also writes data to the server cache.
		 *
		 * Result is returned to \a handler.
		 */
		void			write_cache(const std::function<void (const write_result &)> &handler,
						const key &id, const data_pointer &file, long timeout);
		/*!
		 * \overload write_cache()
		 * Synchronous overload.
		 */
		write_result		write_cache(const key &id, const data_pointer &file, long timeout);

		/*!
		 * Returnes address (ip and port pair) of remote node where
		 * data with key \a id may be in group \a group_id.
		 */
		std::string		lookup_address(const key &id, int group_id = 0);

		/*!
		 * Creates meta data \a obj with timestamp \a ts for key \a id at \a groups.
		 *
		 * \note This method is left only for compatibility.
		 */
		std::string		create_metadata(const key &id, const std::string &obj,
							const std::vector<int> &groups,
							const struct timespec &ts);
		/*!
		 * Writes meta data \a obj with timestamp \a ts for key \a id at \a groups.
		 *
		 * \note This method is left only for compatibility.
		 */
		int			write_metadata(const key &id, const std::string &obj,
							const std::vector<int> &groups,
							const struct timespec &ts);

		/*!
		 * Lookups information for key \a id.
		 *
		 * Result is returned to \a handler.
		 */
		void			lookup(const std::function<void (const lookup_result &)> &handler,
						const key &id);
		/*!
		 * \overload lookup()
		 * Synchronous overload.
		 */
		lookup_result		lookup(const key &id);

		void 			remove_raw(const key &id);
		/*!
		 * Removes all the entries of key \a id at server nodes.
		 *
		 * Returnes exception if no entry is removed.
		 * Result is returned to \a handler.
		 */
		void 			remove(const std::function<void (const std::exception_ptr &)> &handler,
						const key &id);
		/*!
		 * \overload remove()
		 * Synchronous overload.
		 */
		void 			remove(const key &id);

		/*!
		 * Queries statistics information from the server nodes.
		 *
		 * Result is returned to \a handler.
		 */
		void			stat_log(const std::function<void (const stat_result &)> &handler);
		/*!
		 * \overload stat_log()
		 * Allows to specify the key \a id.
		 */
		void			stat_log(const std::function<void (const stat_result &)> &handler,
						const key &id);
		/*!
		 * \overload stat_log()
		 * Synchronous overload.
		 */
		stat_result		stat_log();
		/*!
		 * \overload stat_log()
		 * Synchronous overload.
		 */
		stat_result		stat_log(const key &id);

		/*!
		 * Queries statistics information from the server nodes.
		 *
		 * Result is returned to \a handler.
		 */
		void			stat_log_count(const std::function<void (const stat_count_result &)> &handler);
		/*!
		 * \overload stat_log_count()
		 * Synchronous overload.
		 */
		stat_count_result	stat_log_count();

		/*!
		 * Returnes the number of session states.
		 */
		int			state_num();

		/*!
		 * Requests execution of custom command at server.
		 *
		 * Result is returned to \a handler.
		 */
		void			request_cmd(const std::function<void (const command_result &)> &handler,
						const transport_control &ctl);
		/*!
		 * \overload request_cmd()
		 * Synchronous overload.
		 */
		command_result		request_cmd(const transport_control &ctl);

		/*!
		 * Changes node \a status on given \a address, \a port and network \a family.
		 */
		void			update_status(const char *addr, const int port,
						const int family, struct dnet_node_status *status);
		/*!
		 * Changes node \a status on key \a id.
		 */
		void			update_status(const key &id, struct dnet_node_status *status);

		/*!
		 * Reads data in range specified in \a io at group \a group_id.
		 * Exception is thrown if no entry is read.
		 *
		 * Result is returned to \a handler.
		 */
		void			read_data_range(const std::function<void (const read_range_result &)> &handler,
						const struct dnet_io_attr &io, int group_id);
		/*!
		 * \overload read_data_range()
		 * Synchronous overload.
		 */
		read_range_result	read_data_range(struct dnet_io_attr &io, int group_id);
		/*!
		 * \internal
		 * \overload read_data_range()
		 * Synchronous overload.
		 *
		 * \note This method is left only for compatibility.
		 */
		std::vector<std::string>read_data_range_raw(struct dnet_io_attr &io, int group_id);

		/*!
		 * Removes data in range specified in \a io at group \a group_id.
		 *
		 * Result is returned to \a handler.
		 */
		void			remove_data_range(const std::function<void (const remove_range_result &)> &handler,
						struct dnet_io_attr &io, int group_id);
		/*!
		 * \overload remove_data_range()
		 * Synchronous overload.
		 */
		remove_range_result	remove_data_range(struct dnet_io_attr &io, int group_id);

		/*!
		 * Returnes the list of network routes.
		 */
		std::vector<std::pair<struct dnet_id, struct dnet_addr> > get_routes();

		void exec(const std::function<void (const exec_result &)> &handler, const std::function<void ()> &complete_handler,
			dnet_id *id, const std::string &event, const data_pointer &data);
		void exec(const std::function<void (const exec_result &)> &handler, dnet_id *id, const std::string &event, const data_pointer &data);
		exec_results exec(dnet_id *id, const std::string &event, const data_pointer &data);

		void push(const std::function<void (const push_result &)> &handler, dnet_id *id,
				const exec_context &context, const std::string &event, const data_pointer &data);
		void push(dnet_id *id, const exec_context &context, const std::string &event, const data_pointer &data);

		void reply(const std::function<void (const reply_result &)> &handler, const exec_context &context,
				const data_pointer &data, exec_context::final_state state);
		void reply(const exec_context &context, const data_pointer &data, exec_context::final_state state);

		/*!
		 * Starts execution for \a id of the given \a event with \a data and \a binary.
		 */
		std::string		exec_locked(struct dnet_id *id, const std::string &event,
						const std::string &data,
						const std::string &binary);
		std::string		exec_unlocked(struct dnet_id *id, const std::string &event,
						const std::string &data,
						const std::string &binary);

		/*
		 * execution with saving ID of the original (blocked) caller
		 */
		std::string		push_locked(struct dnet_id *id, const struct sph &sph,
						const std::string &event, const std::string &data,
						const std::string &binary);
		std::string		push_unlocked(struct dnet_id *id, const struct sph &sph,
						const std::string &event, const std::string &data,
						const std::string &binary);

		/* send reply back to blocked execution client */
		void			reply(const struct sph &sph, const std::string &event,
						const std::string &data,
						const std::string &binary);

		/*!
		 * Reads all data from server nodes by the list \a ios.
		 * Exception is thrown if no entry is read successfully.
		 *
		 * Result is returned to \a handler.
		 */
		void			bulk_read(const std::function<void (const bulk_read_result &)> &handler,
						const std::vector<struct dnet_io_attr> &ios);
		/*!
		 * \overload bulk_read()
		 * Synchronous overload.
		 */
		bulk_read_result	bulk_read(const std::vector<struct dnet_io_attr> &ios);
		/*!
		 * \overload bulk_read()
		 * Synchronous overload.
		 *
		 * Allows to specify the list of string \a keys.
		 */
		bulk_read_result	bulk_read(const std::vector<std::string> &keys);

		/*!
		 * Writes all data \a data to server nodes by the list \a ios.
		 * Exception is thrown if no entry is written successfully.
		 *
		 * Result is returned to \a handler.
		 */
		void			bulk_write(const std::function<void (const write_result &)> &handler,
						const std::vector<struct dnet_io_attr> &ios,
						const std::vector<data_pointer> &data);
		void			bulk_write(const std::function<void (const write_result &)> &handler,
						const std::vector<struct dnet_io_attr> &ios,
						const std::vector<std::string> &data);
		/*!
		 * \overload bulk_write()
		 * Synchronous overload.
		 */
		write_result		bulk_write(const std::vector<struct dnet_io_attr> &ios,
							const std::vector<std::string> &data);
		/*!
		 * \overload bulk_write()
		 * Synchronous overload.
		 */
		write_result		bulk_write(const std::vector<struct dnet_io_attr> &ios,
							const std::vector<data_pointer> &data);

		void update_indexes(const std::function<void (const update_indexes_result &)> &handler, const key &id, const std::vector<dnet_raw_id> &indexes);
		void update_indexes(const key &id, const std::vector<dnet_raw_id> &indexes);
		void update_indexes(const key &id, const std::vector<std::string> &indexes);

		void find_indexes(const std::function<void (const find_indexes_result &)> &handler, const std::vector<dnet_raw_id> &indexes);
		find_indexes_result find_indexes(const std::vector<dnet_raw_id> &indexes);
		find_indexes_result find_indexes(const std::vector<std::string> &indexes);

		void check_indexes(const std::function<void (const check_indexes_result &)> &handler, const key &id);
		check_indexes_result check_indexes(const key &id);

		/*!
		 * Returnes reference to parent node.
		 */
		node	&get_node();
		/*!
		 * \overload get_node()
		 */
		const node	&get_node() const;
		/*!
		 * Returnes pointer to dnet_session.
		 */
		struct dnet_session *	get_native();

	protected:
		std::shared_ptr<session_data>		m_data;

		void request(const std::function<void (const exec_result &)> &handler,
				const std::function<void ()> &complete_handler,
				dnet_id *id, const exec_context &context);
		void			mix_states(const key &id, std::vector<int> &groups);
		void			mix_states(std::vector<int> &groups);
		std::vector<int>	mix_states(const key &id);
		std::vector<int>	mix_states();
};

}} /* namespace ioremap::elliptics */

#endif /* __EDEF_H */
