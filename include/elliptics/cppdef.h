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
#include <string>

class elliptics_log {
	public:
		elliptics_log(const uint32_t mask = DNET_LOG_ERROR | DNET_LOG_INFO) {
			ll.log_mask = mask;
			ll.log = elliptics_log::logger;
			ll.log_private = this;
		};
		virtual ~elliptics_log() {};

		virtual void 		log(const uint32_t mask, const char *msg) = 0;
		static void		logger(void *priv, const uint32_t mask, const char *msg);
		uint32_t		get_log_mask(void) { return ll.log_mask; };
		struct dnet_log		*get_dnet_log(void) { return &ll; };
	protected:
		struct dnet_log		ll;
};

class elliptics_log_file : public elliptics_log {
	public:
		elliptics_log_file(const char *file, const uint32_t mask = DNET_LOG_ERROR | DNET_LOG_INFO);
		elliptics_log_file(const elliptics_log_file &l);
		virtual ~elliptics_log_file();

		virtual void 		log(const uint32_t mask, const char *msg);

		std::string		*file;
	private:
		/*
		 * Oh shi, I put pointer here to avoid boost::python compiler issues,
		 * when it tries to copy stream, which is not allowed
		 */
		std::ofstream		*stream;
};

/* we should use proper copy constructors here instead of hardcoded openssl usage */
class elliptics_transform {
	public:
		elliptics_transform(const char *n) { snprintf(name, sizeof(name), "%s", n); };
		virtual ~elliptics_transform() {};

		virtual int		transform(void *priv, void *src, uint64_t size,
					                   void *dst, unsigned int *dsize,
							   unsigned int flags) = 0;
		virtual void		cleanup(void *priv) = 0;
		const char		*get_name(void) { return name; };
	private:
		char			name[DNET_MAX_NAME_LEN];
};

#include <openssl/hmac.h>
#include <openssl/evp.h>

class elliptics_transform_openssl : public elliptics_transform {
	public:
		elliptics_transform_openssl(const char *n);
		virtual ~elliptics_transform_openssl();

		virtual int		transform(void *priv, void *src, uint64_t size,
					                   void *dst, unsigned int *dsize,
							   unsigned int flags);
		virtual void		cleanup(void *priv);
	private:
		EVP_MD_CTX 		mdctx;
		const EVP_MD		*evp_md;
};

class elliptics_callback {
	public:
		elliptics_callback() : state(NULL), cmd(NULL), attr(NULL) {};
		virtual ~elliptics_callback() {};

		virtual	int		callback(void) = 0;

		bool last(void) {
			return (!cmd || !(cmd->flags & DNET_FLAGS_MORE));
		};

		int status(void) {
			int err = -EINVAL;

			if (cmd)
				err = cmd->status;

			return err;
		};

		static int elliptics_complete_callback(struct dnet_net_state *st, struct dnet_cmd *cmd, struct dnet_attr *a, void *priv) {
			elliptics_callback *c = reinterpret_cast<elliptics_callback *>(priv);

			c->state = st;
			c->cmd = cmd;
			c->attr = a;

			return c->callback();
		};

	protected:
		struct dnet_net_state	*state;
		struct dnet_cmd		*cmd;
		struct dnet_attr	*attr;
};

class elliptics_node {
	public:
		/* we shold use elliptics_log and proper copy constructor here, but not this time */
		elliptics_node(unsigned char *id, const elliptics_log &l);
		virtual ~elliptics_node();

		void			add_remote(const char *addr, const int port, const int family = AF_INET);
		void			add_transform(elliptics_transform &t);

		void			read_file(unsigned char *id, char *dst_file, uint64_t offset, uint64_t size);
		void			read_file(void *remote, unsigned int remote_size, char *dst_file, uint64_t offset, uint64_t size);

		void			read_data(unsigned char *id, uint64_t offset, uint64_t size, elliptics_callback &c);
		void			read_data(void *remote, unsigned int remote_size, uint64_t offset, uint64_t size, elliptics_callback &c);

		void 			write_file(unsigned char *id, char *src_file, uint64_t local_offset, uint64_t offset, uint64_t size,
							unsigned int aflags = 0, unsigned int ioflags = 0);
		void			write_file(void *remote, unsigned int remote_size, char *src_file, uint64_t local_offset,
							uint64_t offset, uint64_t size,
							unsigned int aflags = 0, unsigned int ioflags = 0);

		int			write_data(unsigned char *id, void *data, unsigned int size, elliptics_callback &c,
							unsigned int aflags = 0, unsigned int ioflags = 0);
		int			write_data(void *remote, unsigned int remote_len, void *data, unsigned int size, elliptics_callback &c,
							unsigned int aflags = 0, unsigned int ioflags = 0);

		void			read_data_wait(unsigned char *id, void *data, uint64_t offset, uint64_t size);
		void			read_data_wait(void *remote, unsigned int remote_size, void *data, uint64_t offset, uint64_t size);

		int			write_data_wait(unsigned char *id, void *data, uint64_t offset, uint64_t size,
							unsigned int aflags = DNET_ATTR_DIRECT_TRANSACTION | DNET_ATTR_NO_TRANSACTION_SPLIT,
							unsigned int ioflags = DNET_IO_FLAGS_NO_HISTORY_UPDATE);
		int			write_data_wait(void *remote, unsigned int remote_len, void *data, uint64_t offset, uint64_t size,
							unsigned int aflags = DNET_ATTR_DIRECT_TRANSACTION | DNET_ATTR_NO_TRANSACTION_SPLIT,
							unsigned int ioflags = DNET_IO_FLAGS_NO_HISTORY_UPDATE);

	private:
		int			write_data_ll(unsigned char *id, void *remote, unsigned int remote_len,
							void *data, unsigned int size, elliptics_callback &c,
							unsigned int aflags, unsigned int ioflags);
		struct dnet_node	*node;
		elliptics_log		&log;
};

#endif /* __EDEF_H */
