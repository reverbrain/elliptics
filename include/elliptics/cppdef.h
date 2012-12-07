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

		void *data() const;

		static int handler(struct dnet_net_state *st, struct dnet_cmd *cmd, void *priv);

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
	ELLIPTICS_DISABLE_COPY(session)
	public:
		explicit session(const node &n);
		virtual ~session();

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

		std::string		read_data_wait(const key &id, uint64_t offset, uint64_t size);

		void			prepare_latest(const key &id, std::vector<int> &groups);

		std::string		read_latest(const key &id, uint64_t offset, uint64_t size);

		std::string		write_cas(const key &id, const std::string &str,
							const struct dnet_id &old_csum, uint64_t remote_offset);

		std::string		write_data_wait(const key &id, const std::string &str,
							uint64_t remote_offset);

		std::string		write_prepare(const key &id, const std::string &str, uint64_t remote_offset,
							uint64_t psize);
		std::string		write_commit(const key &id, const std::string &str, uint64_t remote_offset,
							uint64_t csize);
		std::string		write_plain(const key &id, const std::string &str, uint64_t remote_offset);

		std::string		write_cache(const key &id, const std::string &str, long timeout);



		std::string		lookup_address(const key &id, int group_id = 0);

		std::string		create_metadata(const key &id, const std::string &obj,
							const std::vector<int> &groups, const struct timespec &ts);
		int			write_metadata(const key &id, const std::string &obj,
							const std::vector<int> &groups, const struct timespec &ts);

		void			lookup(const key &id, const callback &c);
		std::string		lookup(const key &id);

		void 			remove_raw(const key &id);
		void 			remove(const key &id);

		std::string		stat_log();

		int			state_num();
		
		int			request_cmd(struct dnet_trans_control &ctl);

		std::string		read_metadata(const key &id);

		void			update_status(const char *addr, const int port, const int family, struct dnet_node_status *status);
		void			update_status(const key &id, struct dnet_node_status *status);

		std::vector<std::string>	read_data_range(struct dnet_io_attr &io, int group_id);

		std::vector<struct dnet_io_attr> remove_data_range(struct dnet_io_attr &io, int group_id);

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

		std::vector<std::string>	bulk_read(const std::vector<struct dnet_io_attr> &ios);
		std::vector<std::string>	bulk_read(const std::vector<std::string> &keys);

		std::string		bulk_write(const std::vector<struct dnet_io_attr> &ios,
							const std::vector<std::string> &data);

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
