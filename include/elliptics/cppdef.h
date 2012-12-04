/*
 * 2008+ Copyright (c) Evgeniy Polyakov <zbr@ioremap.net>
 * All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.	See the
 * GNU General Public License for more details.
 */

#ifndef __EDEF_H
#define __EDEF_H

#include <errno.h>

#include <elliptics/typedefs.h>
#include <elliptics/packet.h>
#include <elliptics/interface.h>

#include <boost/shared_ptr.hpp>

#include <iostream>
#include <fstream>
#include <exception>
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

// err must be negative value
void throw_error(int err, const char *format, ...)
	__attribute__ ((format (printf, 2, 3)));

// err must be negative value
void throw_error(int err, const struct dnet_id &id, const char *format, ...)
	__attribute__ ((format (printf, 3, 4)));

// err must be negative value
void throw_error(int err, const uint8_t *id, const char *format, ...)
	__attribute__ ((format (printf, 3, 4)));


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
		struct dnet_log		*get_dnet_log();

	protected:
		boost::shared_ptr<logger_data> m_data;
};

class file_logger : public logger
{
	public:
		explicit file_logger(const char *file, const int level = DNET_LOG_INFO);
		~file_logger();
};

class callback_data;

class callback
{
	ELLIPTICS_DISABLE_COPY(callback)
	public:
		callback();
		virtual ~callback();

		virtual void handle(struct dnet_net_state *state, struct dnet_cmd *cmd);
		virtual bool check_states(const std::vector<int> &statuses) = 0;

		std::string wait(int completed = 1);

		static int complete_callback(struct dnet_net_state *st, struct dnet_cmd *cmd, void *priv);

	private:
		callback_data *m_data;
};

class callback_any : public callback
{
	public:
		callback_any();
		~callback_any();

		virtual bool check_states(const std::vector<int> &statuses);
};

class callback_all : public callback
{
	public:
		callback_all();
		~callback_all();

		virtual bool check_states(const std::vector<int> &statuses);
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

		struct dnet_node *	get_native();

	protected:
		int			write_data_ll(struct dnet_id *id, void *remote, unsigned int remote_len,
							void *data, unsigned int size, callback &c,
							uint64_t cflags, unsigned int ioflags, int type);

		boost::shared_ptr<node_data> m_data;

		friend class session;
		friend class session_data;
};

class session
{
	ELLIPTICS_DISABLE_COPY(session)
	public:
		explicit session(const node &n);
		virtual ~session();

		void			transform(const std::string &data, struct dnet_id &id);

		void			set_groups(const std::vector<int> &groups);
		const std::vector<int> &get_groups() const;

		void			read_file(struct dnet_id &id, const std::string &file, uint64_t offset, uint64_t size);
		void			read_file(const std::string &remote, const std::string &file,
							uint64_t offset, uint64_t size, int type);

		void			write_file(struct dnet_id &id, const std::string &file, uint64_t local_offset,
							uint64_t offset, uint64_t size, uint64_t cflags, unsigned int ioflags);
		void			write_file(const std::string &remote, const std::string &file,
							uint64_t local_offset, uint64_t offset, uint64_t size,
							uint64_t cflags, unsigned int ioflags, int type);

		std::string		read_data_wait(struct dnet_id &id, uint64_t offset, uint64_t size,
							uint64_t cflags, uint32_t ioflags);
		std::string		read_data_wait(const std::string &remote, uint64_t offset, uint64_t size,
							uint64_t cflags, uint32_t ioflags, int type);

		void			prepare_latest(struct dnet_id &id, uint64_t cflags, std::vector<int> &groups);

		std::string		read_latest(struct dnet_id &id, uint64_t offset, uint64_t size,
							uint64_t cflags, uint32_t ioflags);
		std::string		read_latest(const std::string &remote, uint64_t offset, uint64_t size,
							uint64_t cflags, uint32_t ioflags, int type);

		std::string		write_compare_and_swap(const struct dnet_id &id, const std::string &str,
								const struct dnet_id &old_csum, uint64_t remote_offset, uint64_t cflags, unsigned int ioflags);
		std::string		write_compare_and_swap(const std::string &remote, const std::string &str,
								const struct dnet_id &old_csum, uint64_t remote_offset, uint64_t cflags, unsigned int ioflags, int type);

		std::string		write_data_wait(struct dnet_id &id, const std::string &str,
							uint64_t remote_offset, uint64_t cflags, unsigned int ioflags);
		std::string		write_data_wait(const std::string &remote, const std::string &str,
							uint64_t remote_offset, uint64_t cflags, unsigned int ioflags, int type);

		std::string		write_prepare(const std::string &remote, const std::string &str, uint64_t remote_offset,
							uint64_t psize, uint64_t cflags, unsigned int ioflags, int type);
		std::string		write_commit(const std::string &remote, const std::string &str, uint64_t remote_offset,
							uint64_t csize, uint64_t cflags, unsigned int ioflags, int type);
		std::string		write_plain(const std::string &remote, const std::string &str, uint64_t remote_offset,
							uint64_t cflags, unsigned int ioflags, int type);

		std::string		write_prepare(const struct dnet_id &id, const std::string &str, uint64_t remote_offset,
							uint64_t psize, uint64_t cflags, unsigned int ioflags);
		std::string		write_commit(const struct dnet_id &id, const std::string &str, uint64_t remote_offset,
							uint64_t csize, uint64_t cflags, unsigned int ioflags);
		std::string		write_plain(const struct dnet_id &id, const std::string &str, uint64_t remote_offset,
							uint64_t cflags, unsigned int ioflags);

		std::string		write_cache(struct dnet_id &id, const std::string &str,
							uint64_t cflags, unsigned int ioflags, long timeout);
		std::string		write_cache(const std::string &key, const std::string &str,
							uint64_t cflags, unsigned int ioflags, long timeout);



		std::string		lookup_address(const std::string &remote, const int group_id);
		std::string		lookup_address(const struct dnet_id &id);

		std::string		create_metadata(const struct dnet_id &id, const std::string &obj,
							const std::vector<int> &groups, const struct timespec &ts);
		int			write_metadata(const struct dnet_id &id, const std::string &obj,
							const std::vector<int> &groups, const struct timespec &ts, uint64_t cflags);

		void			lookup(const std::string &data, const callback &c);
		void			lookup(const struct dnet_id &id, const callback &c);
		std::string		lookup(const std::string &data);
		std::string		lookup(const struct dnet_id &id);

		void 			remove_raw(struct dnet_id &id, uint64_t cflags, uint64_t ioflags);
		void			remove_raw(const std::string &data, int type, uint64_t cflags, uint64_t ioflags);
		void 			remove(struct dnet_id &id);
		void			remove(const std::string &data, int type = EBLOB_TYPE_DATA);

		std::string		stat_log();

		int			state_num();
		
		int			request_cmd(struct dnet_trans_control &ctl);

		std::string		read_metadata(struct dnet_id &id);

		void			update_status(const char *addr, const int port, const int family, struct dnet_node_status *status);
		void			update_status(struct dnet_id &id, struct dnet_node_status *status);

		std::vector<std::string>	read_data_range(struct dnet_io_attr &io, int group_id, uint64_t cflags = 0);

		std::vector<struct dnet_io_attr> remove_data_range(struct dnet_io_attr &io, int group_id, uint64_t cflags = 0);

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

		std::vector<std::string>	bulk_read(const std::vector<struct dnet_io_attr> &ios, uint64_t cflags = 0);
		std::vector<std::string>	bulk_read(const std::vector<std::string> &keys, uint64_t cflags = 0);

		std::string		bulk_write(const std::vector<struct dnet_io_attr> &ios,
							const std::vector<std::string> &data, uint64_t cflags);

		node	&get_node();
		const node	&get_node() const;
		struct dnet_session *	get_native();

	protected:
		session_data		*m_data;

		std::string		raw_exec(struct dnet_id *id,
							const struct sph *sph,
							const std::string &event,
							const std::string &data,
							const std::string &binary,
							bool lock);
		std::string		request(struct dnet_id *id, struct sph *sph, bool lock);

};

}} /* namespace ioremap::elliptics */

#endif /* __EDEF_H */
