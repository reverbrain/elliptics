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

#include "elliptics/packet.h"
#include "elliptics/interface.h"

#include <iostream>
#include <fstream>
#include <exception>
#include <stdexcept>
#include <string>
#include <vector>

namespace zbr {

class elliptics_log {
	public:
		elliptics_log(const uint32_t mask = DNET_LOG_ERROR | DNET_LOG_INFO) {
			ll.log_mask = mask;
			ll.log = elliptics_log::logger;
			ll.log_private = this;
		};
		virtual ~elliptics_log() {};

		virtual void 		log(const uint32_t mask, const char *msg) = 0;

		/*
		 * Clone is used instead of 'virtual' copy constructor, since we have to
		 * hold a reference to object outside of our scope, namely python created
		 * logger. This is also a reason we return 'unsigned long' instead of
		 * 'elliptics_log *' - python does not have pointer.
		 */
		virtual unsigned long	clone(void) = 0;

		static void		logger(void *priv, const uint32_t mask, const char *msg);
		uint32_t		get_log_mask(void) { return ll.log_mask; };
		struct dnet_log		*get_dnet_log(void) { return &ll; };
	protected:
		struct dnet_log		ll;
};

class elliptics_log_file : public elliptics_log {
	public:
		elliptics_log_file(const char *file, const uint32_t mask = DNET_LOG_ERROR | DNET_LOG_INFO);
		virtual ~elliptics_log_file();

		virtual unsigned long	clone(void);
		virtual void 		log(const uint32_t mask, const char *msg);

		std::string		*file;
	private:
		/*
		 * Oh shi, I put pointer here to avoid boost::python compiler issues,
		 * when it tries to copy stream, which is not allowed
		 */
		std::ofstream		*stream;
};

class elliptics_callback {
	public:
		elliptics_callback();
		virtual ~elliptics_callback();

		virtual int callback(struct dnet_net_state *state, struct dnet_cmd *cmd, struct dnet_attr *attr);

		static int elliptics_complete_callback(struct dnet_net_state *st, struct dnet_cmd *cmd, struct dnet_attr *a, void *priv) {
			elliptics_callback *c = reinterpret_cast<elliptics_callback *>(priv);

			return c->callback(st, cmd, a);
		};

		std::string wait(int completed = 1);

	protected:
		std::string		data;
		pthread_cond_t		wait_cond;
		pthread_mutex_t		lock;
		int			complete;
};

class elliptics_node {
	public:
		/* we shold use elliptics_log and proper copy constructor here, but not this time */
		elliptics_node(elliptics_log &l);
		elliptics_node(elliptics_log &l, struct dnet_config &cfg);
		virtual ~elliptics_node();

		void			transform(const std::string &data, struct dnet_id &id);

		void			add_groups(std::vector<int> &groups);
		std::vector<int>	get_groups() {return groups;};

		void			add_remote(const char *addr, const int port, const int family = AF_INET);

		void			read_file(struct dnet_id &id, const std::string &file, uint64_t offset, uint64_t size);
		void			read_file(const std::string &remote, const std::string &file, uint64_t offset, uint64_t size, int type);

		void			write_file(struct dnet_id &id, const std::string &file, uint64_t local_offset,
						uint64_t offset, uint64_t size, unsigned int aflags, unsigned int ioflags);
		void			write_file(const std::string &remote, const std::string &file,
						uint64_t local_offset, uint64_t offset, uint64_t size,
						unsigned int aflags, unsigned int ioflags, int type);

		std::string		read_data_wait(struct dnet_id &id, uint64_t offset, uint64_t size,
						uint32_t aflags, uint32_t ioflags);
		std::string		read_data_wait(const std::string &remote, uint64_t offset, uint64_t size,
						uint32_t aflags, uint32_t ioflags, int type);

		std::string		read_latest(struct dnet_id &id, uint64_t offset, uint64_t size,
						uint32_t aflags, uint32_t ioflags);
		std::string		read_latest(const std::string &remote, uint64_t offset, uint64_t size,
						uint32_t aflags, uint32_t ioflags, int type);

		std::string		write_data_wait(struct dnet_id &id, const std::string &str,
						uint64_t remote_offset, unsigned int aflags, unsigned int ioflags);
		std::string		write_data_wait(const std::string &remote, const std::string &str,
						uint64_t remote_offset, unsigned int aflags, unsigned int ioflags, int type);

		int			write_prepare(const std::string &remote, const std::string &str, uint64_t remote_offset,
						uint64_t psize, unsigned int aflags, unsigned int ioflags, int type);
		int			write_commit(const std::string &remote, const std::string &str, uint64_t remote_offset,
						uint64_t csize, unsigned int aflags, unsigned int ioflags, int type);
		int			write_plain(const std::string &remote, const std::string &str, uint64_t remote_offset,
						unsigned int aflags, unsigned int ioflags, int type);

		std::string		lookup_addr(const std::string &remote, const int group_id);
		std::string		lookup_addr(const struct dnet_id &id);

		int			write_metadata(const struct dnet_id &id, const std::string &obj,
							const std::vector<int> &groups, const struct timespec &ts);

		void			lookup(const std::string &data, const elliptics_callback &c);
		void			lookup(const struct dnet_id &id, const elliptics_callback &c);
		std::string		lookup(const std::string &data);

		void 			remove(struct dnet_id &id);
		void			remove(const std::string &data, int type = EBLOB_TYPE_DATA);

		std::string		stat_log();

		int			state_num();
		
		int			request_cmd(struct dnet_trans_control &ctl);

		std::string		read_metadata(struct dnet_id &id);

		void			update_status(const char *addr, const int port, const int family,
						struct dnet_node_status *status, int update);
		void			update_status(struct dnet_id &id, struct dnet_node_status *status, int update);

		std::vector<std::string>	read_data_range(struct dnet_io_attr &io, int group_id, uint32_t aflags = 0);

	protected:
		int			write_data_ll(struct dnet_id *id, void *remote, unsigned int remote_len,
							void *data, unsigned int size, elliptics_callback &c,
							unsigned int aflags, unsigned int ioflags, int type);
		struct dnet_node	*node;
		elliptics_log		*log;

		std::vector<int>	groups;
};

}; /* namespace zbr */
#endif /* __EDEF_H */
