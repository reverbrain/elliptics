/*
 * Copyright 2013+ Ruslan Nigmatullin <euroelessar@yandex.ru>
 *
 * This file is part of Elliptics.
 *
 * Elliptics is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Elliptics is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with Elliptics.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef LOCAL_SESSION_H
#define LOCAL_SESSION_H

#include "../library/elliptics.h"
#include "../include/elliptics/session.hpp"

#include <chrono>

class local_session
{
	ELLIPTICS_DISABLE_COPY(local_session)
	public:
		local_session(dnet_backend_io *backend, dnet_node *node);
		~local_session();

		void set_ioflags(uint32_t flags);
		void set_cflags(uint64_t flags);

		int backend_id() const;

		ioremap::elliptics::data_pointer read(const dnet_id &id, int *errp);
		ioremap::elliptics::data_pointer read(const dnet_id &id, uint64_t *user_flags, dnet_time *timestamp, int *errp);
		int write(const dnet_id &id, const ioremap::elliptics::data_pointer &data);
		int write(const dnet_id &id, const char *data, size_t size);
		int write(const dnet_id &id, const char *data, size_t size, uint64_t user_flags, const dnet_time &timestamp);
		ioremap::elliptics::data_pointer lookup(const dnet_cmd &cmd, int *errp);
		int remove(const dnet_id &id);

		int update_index_internal(const dnet_id &id, const dnet_raw_id &index, const ioremap::elliptics::data_pointer &data,
			uint32_t action, uint32_t shard_id, uint32_t shard_count);

	private:
		void clear_queue(int *errp = NULL);

		dnet_backend_io *m_backend;
		dnet_net_state *m_state;
		uint32_t m_ioflags;
		uint64_t m_cflags;
};

#endif // LOCAL_SESSION_H
