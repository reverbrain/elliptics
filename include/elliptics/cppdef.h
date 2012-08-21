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
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#ifndef __EDEF_H
#define __EDEF_H

#include <errno.h>
#include <stdint.h>

#include <elliptics/packet.h>
#include <elliptics/interface.h>

#include <iostream>
#include <fstream>
#include <exception>
#include <list>
#include <stdexcept>
#include <string>
#include <vector>

namespace ioremap { namespace elliptics {

class elliptics_error : public std::runtime_error {
public:
	explicit elliptics_error(int err);
	int error_code() const;
private:
	static std::string convert(int err);
	int errno_;
};

class not_found_error : public elliptics_error {
public:
	explicit not_found_error();
};

class timeout_error : public elliptics_error {
public:
	explicit timeout_error();
};

void throw_exception(int err);

struct addr_tuple {
	addr_tuple(const std::string &l_host, const int l_port, const int l_family = AF_INET) :
		host(l_host), port(l_port), family(l_family) {}

	std::string		host;
	int			port;
	int			family;
};

class logger {
	public:
		logger(const int level = DNET_LOG_INFO) {
			ll.log_level = level;
			ll.log = logger::real_logger;
			ll.log_private = this;
		};
		virtual ~logger() {};

		virtual void 		log(const int level, const char *msg) = 0;

		/*
		 * Clone is used instead of 'virtual' copy constructor, since we have to
		 * hold a reference to object outside of our scope, namely python created
		 * logger. This is also a reason we return 'unsigned long' instead of
		 * 'logger *' - python does not have pointer.
		 */
		virtual unsigned long	clone(void) = 0;

		static void		real_logger(void *priv, const int level, const char *msg);
		int			get_log_level(void) { return ll.log_level; };
		struct dnet_log		*get_dnet_log(void) { return &ll; };
	protected:
		struct dnet_log		ll;
};

class log_file : public logger {
	public:
		log_file(const char *file, const int level = DNET_LOG_INFO);
		virtual ~log_file();

		virtual unsigned long	clone(void);
		virtual void 		log(const int level, const char *msg);

		std::string		*file;
	private:
		/*
		 * Oh shi, I put pointer here to avoid boost::python compiler issues,
		 * when it tries to copy stream, which is not allowed
		 */
		std::ofstream		*stream;
};

class callback {
	public:
		callback();
		virtual ~callback();

		virtual int handle(struct dnet_net_state *state, struct dnet_cmd *cmd);

		static int complete_callback(struct dnet_net_state *st, struct dnet_cmd *cmd, void *priv) {
			callback *c = reinterpret_cast<callback *>(priv);

			return c->handle(st, cmd);
		};

		std::string wait(int completed = 1);

	protected:
		std::string		data;
		pthread_cond_t		wait_cond;
		pthread_mutex_t		lock;
		int			complete;
};

class node {
	public:
		/* we shold use logger and proper copy constructor here, but not this time */
		node(logger &l);
		node(logger &l, struct dnet_config &cfg);
		node(logger &l, const std::string &config_path);
		virtual ~node();

		void			parse_config(const std::string &path, struct dnet_config &cfg,
						std::list<addr_tuple> &remotes,
						std::vector<int> &groups,
						int &log_level);

		void			transform(const std::string &data, struct dnet_id &id);

		void			add_groups(std::vector<int> &groups);
		std::vector<int>	get_groups() {return groups;};

		void			set_timeouts(const int wait_timeout, const int check_timeout);

		void			add_remote(const char *addr, const int port, const int family = AF_INET);

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

		std::string		lookup_addr(const std::string &remote, const int group_id);
		std::string		lookup_addr(const struct dnet_id &id);

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

		/* locked execution */
		std::string		exec(struct dnet_id *id, const std::string &event, const std::string &data,
						const std::string &binary);

		/* unlocked execution */
		std::string		push(struct dnet_id *id, const std::string &event, const std::string &data,
						const std::string &binary);

		/* send reply back to blocked exec client */
		std::string		request(struct sph *sph, bool lock);
		void			reply(struct sph *sph, const std::string &event, const std::string &data,
						const std::string &binary);

		std::vector<std::string>	bulk_read(const std::vector<struct dnet_io_attr> &ios, uint64_t cflags = 0);
		std::vector<std::string>	bulk_read(const std::vector<std::string> &keys, uint64_t cflags = 0);

		std::string		bulk_write(const std::vector<struct dnet_io_attr> &ios,
						const std::vector<std::string> &data, uint64_t cflags);

	protected:
		int			write_data_ll(struct dnet_id *id, void *remote, unsigned int remote_len,
							void *data, unsigned int size, callback &c,
							uint64_t cflags, unsigned int ioflags, int type);
		struct dnet_node	*m_node;
		logger			*m_log;

		std::vector<int>	groups;


		std::string		raw_exec(struct dnet_id *id,
						const std::string &event,
						const std::string &data,
						const std::string &binary,
						bool lock);
};

}}; /* namespace ioremap::elliptics */

#endif /* __EDEF_H */
