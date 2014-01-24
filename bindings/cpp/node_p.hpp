/*
 * 2013+ Copyright (c) Ruslan Nigmatullin <euroelessar@yandex.ru>
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

#ifndef IOREMAP_ELLIPTICS_NODE_P_HPP
#define IOREMAP_ELLIPTICS_NODE_P_HPP

#include <elliptics/cppdef.h>

namespace ioremap { namespace elliptics {

class node_data {
	public:
		node_data() : node_ptr(NULL) {}
		~node_data() {
			dnet_node_destroy(node_ptr);
		}

		struct dnet_node	*node_ptr;
		logger				log;
};

class session_data
{
	public:
		session_data(const node &n);
		session_data(const session_data &other);
		~session_data();

		struct dnet_session	*session_ptr;
		std::weak_ptr<node_data>node_guard;
		elliptics::logger logger;
		result_filter		filter;
		result_checker		checker;
		result_error_handler	error_handler;
		uint32_t		policy;
		uint32_t		trace_id;
};

}} // namespace ioremap::elliptics

#endif // IOREMAP_ELLIPTICS_NODE_P_HPP
