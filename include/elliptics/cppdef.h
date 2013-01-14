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

#include <boost/shared_ptr.hpp>
#include <boost/make_shared.hpp>
#include <boost/function.hpp>

#include <iostream>
#include <fstream>
#include <exception>
#include <memory>
#include <list>
#include <stdexcept>
#include <string>
#include <vector>

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

class default_callback;
class callback_data;
class callback_result_data;

class data_pointer
{
	public:
		data_pointer() : m_index(0), m_size(0) {}

		data_pointer(void *data, size_t size)
			: m_data(boost::make_shared<wrapper>(data)), m_index(0), m_size(size)
		{
		}

		data_pointer(const std::string &str)
			: m_data(boost::make_shared<wrapper>(const_cast<char*>(str.c_str()), false)), m_index(0), m_size(str.size())
		{
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
			if (m_index >= m_size)
				throw not_found_error("null pointer exception");
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
		bool empty() const { return m_index >= m_size; }
		std::string to_string() const { return std::string(data<char>(), size()); }

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

		boost::shared_ptr<wrapper> m_data;
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
			else if (m_data->exception)
				std::rethrow_exception(m_data->exception);
		}

	protected:
		boost::shared_ptr<generic_data> m_data;
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

		operator std::vector<int> &() { check(); return d_func()->result; }
		operator const std::vector<int> &() const { check(); return d_func()->result; }

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
		callback_result_entry(const boost::shared_ptr<callback_result_data> &data);
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
		boost::shared_ptr<callback_result_data> m_data;

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

		struct dnet_addr_attr *address_attribute() const;
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
		boost::shared_ptr<logger_data> m_data;
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

		void			set_timeouts(const int wait_timeout, const int check_timeout);

		logger get_log() const;
		struct dnet_node *	get_native();

	protected:
		boost::shared_ptr<node_data> m_data;

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

		void			transform(const std::string &data, struct dnet_id &id);
		void			transform(const key &id);

		void			set_groups(const std::vector<int> &groups);
		const std::vector<int> &get_groups() const;

		void			set_cflags(uint64_t cflags);
		uint64_t		get_cflags() const;

		void			set_ioflags(uint32_t ioflags);
		uint32_t		get_ioflags() const;

		void			read_file(const key &id, const std::string &file, uint64_t offset, uint64_t size);

		void			write_file(const key &id, const std::string &file, uint64_t local_offset,
							uint64_t offset, uint64_t size);

		void			read_data(const boost::function<void (const read_results &)> &handler, const key &id, const std::vector<int> &groups, const struct dnet_io_attr &io);
		void			read_data(const boost::function<void (const read_results &)> &handler, const key &id, const std::vector<int> &groups, const struct dnet_io_attr &io, unsigned int cmd);
		void			read_data(const boost::function<void (const read_results &)> &handler, const key &id, int group_id, const struct dnet_io_attr &io);
		void			read_data(const boost::function<void (const read_result  &)> &handler, const key &id, const std::vector<int> &groups, uint64_t offset, uint64_t size);
		void			read_data(const boost::function<void (const read_result &)> &handler, const key &id, uint64_t offset, uint64_t size);
		read_result		read_data(const key &id, uint64_t offset, uint64_t size);
		read_result		read_data(const key &id, const std::vector<int> &groups, uint64_t offset, uint64_t size);
		read_result		read_data(const key &id, int group_id, uint64_t offset, uint64_t size);

		void			prepare_latest(const boost::function<void (const prepare_latest_result &)> &handler, const key &id, const std::vector<int> &groups);
		void			prepare_latest(const key &id, std::vector<int> &groups);

		void			read_latest(const boost::function<void (const read_result &)> &handler, const key &id, uint64_t offset, uint64_t size);
		read_result		read_latest(const key &id, uint64_t offset, uint64_t size);

		void			write_data(const boost::function<void (const write_result &)> &handler, const dnet_io_control &ctl);
		void			write_data(const boost::function<void (const write_result &)> &handler, const key &id, const data_pointer &file, uint64_t remote_offset);
		write_result		write_data(const key &id, const std::string &str, uint64_t remote_offset);

		void			write_cas(const boost::function<void (const write_result &)> &handler, const key &id, const std::string &str, const struct dnet_id &old_csum, uint64_t remote_offset);
		write_result		write_cas(const key &id, const std::string &str, const struct dnet_id &old_csum, uint64_t remote_offset);

		void			write_prepare(const boost::function<void (const write_result &)> &handler, const key &id, const std::string &str, uint64_t remote_offset, uint64_t psize);
		write_result		write_prepare(const key &id, const std::string &str, uint64_t remote_offset, uint64_t psize);
		void			write_commit(const boost::function<void (const write_result &)> &handler, const key &id, const std::string &str, uint64_t remote_offset, uint64_t csize);
		write_result		write_commit(const key &id, const std::string &str, uint64_t remote_offset, uint64_t csize);
		void			write_plain(const boost::function<void (const write_result &)> &handler, const key &id, const std::string &str, uint64_t remote_offset);
		write_result		write_plain(const key &id, const std::string &str, uint64_t remote_offset);

		void			write_cache(const boost::function<void (const write_result &)> &handler, const key &id, const std::string &str, long timeout);
		write_result		write_cache(const key &id, const std::string &str, long timeout);



		std::string		lookup_address(const key &id, int group_id = 0);

		std::string		create_metadata(const key &id, const std::string &obj,
							const std::vector<int> &groups, const struct timespec &ts);
		int			write_metadata(const key &id, const std::string &obj,
							const std::vector<int> &groups, const struct timespec &ts);

		void			lookup(const boost::function<void (const lookup_result &)> &handler, const key &id);
		lookup_result		lookup(const key &id);

		void 			remove_raw(const key &id);
		void 			remove(const key &id);

		void			stat_log(const boost::function<void (const stat_result &)> &handler);
		stat_result		stat_log();

		void			stat_log_count(const boost::function<void (const stat_count_result &)> &handler);
		stat_count_result	stat_log_count();

		int			state_num();

		command_result		request_cmd(const transport_control &ctl);
		void			request_cmd(const boost::function<void (const command_result &)> &handler, const transport_control &ctl);

		void			update_status(const char *addr, const int port, const int family, struct dnet_node_status *status);
		void			update_status(const key &id, struct dnet_node_status *status);

		void			read_data_range(const boost::function<void (const read_range_result &)> &handler, const struct dnet_io_attr &io, int group_id);
		read_range_result	read_data_range(struct dnet_io_attr &io, int group_id);
		std::vector<std::string>read_data_range_raw(struct dnet_io_attr &io, int group_id);

		void			remove_data_range(const boost::function<void (const remove_range_result &)> &handler, struct dnet_io_attr &io, int group_id);
		remove_range_result	remove_data_range(struct dnet_io_attr &io, int group_id);

		std::vector<std::pair<struct dnet_id, struct dnet_addr> > get_routes();

		/*
		 * start execution of the given event
		 */
		std::string		exec_locked(struct dnet_id *id, const std::string &event, const std::string &data,
							const std::string &binary);
		std::string		exec_unlocked(struct dnet_id *id, const std::string &event, const std::string &data,
							const std::string &binary);

		/*
		 * execution with saving ID of the original (blocked) caller
		 */
		std::string		push_locked(struct dnet_id *id, const struct sph &sph,
							const std::string &event, const std::string &data, const std::string &binary);
		std::string		push_unlocked(struct dnet_id *id, const struct sph &sph,
							const std::string &event, const std::string &data, const std::string &binary);

		/* send reply back to blocked execution client */
		void			reply(const struct sph &sph, const std::string &event, const std::string &data,
						const std::string &binary);

		void			bulk_read(const boost::function<void (const bulk_read_result &)> &handler, const std::vector<struct dnet_io_attr> &ios);
		bulk_read_result	bulk_read(const std::vector<struct dnet_io_attr> &ios);
		bulk_read_result	bulk_read(const std::vector<std::string> &keys);

		std::string		bulk_write(const std::vector<struct dnet_io_attr> &ios,
							const std::vector<std::string> &data);

		node	&get_node();
		const node	&get_node() const;
		struct dnet_session *	get_native();

	protected:
		boost::shared_ptr<session_data>		m_data;

		std::string		raw_exec(struct dnet_id *id,
							const struct sph *sph,
							const std::string &event,
							const std::string &data,
							const std::string &binary,
							bool lock);
		std::string		request(struct dnet_id *id, struct sph *sph, bool lock);
		void			mix_states(const key &id, std::vector<int> &groups);
		void			mix_states(std::vector<int> &groups);
		std::vector<int>	mix_states(const key &id);
		std::vector<int>	mix_states();
};

}} /* namespace ioremap::elliptics */

#endif /* __EDEF_H */
