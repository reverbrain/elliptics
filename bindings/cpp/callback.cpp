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
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 */

#include "callback_p.h"
#include "../../library/elliptics.h"

namespace ioremap { namespace elliptics {

namespace detail {

class basic_handler
{
public:
	static int handler(dnet_net_state *state, dnet_cmd *cmd, void *priv)
	{
		basic_handler *that = reinterpret_cast<basic_handler *>(priv);
		if (that->handle(state, cmd)) {
			delete that;
		}

		return 0;
	}

	basic_handler(async_generic_result &result) : m_handler(result), m_completed(0), m_total(0)
	{
	}

	bool handle(dnet_net_state *state, dnet_cmd *cmd)
	{
		if (is_trans_destroyed(state, cmd)) {
			return increment_completed();
		}

		auto data = std::make_shared<callback_result_data>(dnet_state_addr(state), cmd);

		if (cmd->status)
			data->error = create_error(*cmd);

		m_handler.process(callback_result_entry(data));

		return false;
	}

	bool set_total(size_t total)
	{
		m_handler.set_total(total);
		m_total = total + 1;
		return increment_completed();
	}

private:
	bool increment_completed()
	{
		if (++m_completed == m_total) {
			m_handler.complete(error_info());
			return true;
		}

		return false;
	}

	async_result_handler<callback_result_entry> m_handler;
	std::atomic_size_t m_completed;
	std::atomic_size_t m_total;
};

} // namespace detail


// Send request to specificly set state by id
async_generic_result send_to_single_state(session &sess, const transport_control &control)
{
	scoped_trace_id guard(sess);
	async_generic_result result(sess);

	detail::basic_handler *handler = new detail::basic_handler(result);
	dnet_trans_control dnet_control = control.get_native();

	dnet_control.complete = detail::basic_handler::handler;
	dnet_control.priv = handler;

	dnet_trans_alloc_send(sess.get_native(), &dnet_control);

	if (handler->set_total(1))
		delete handler;

	return result;
}

// Send request to each backend
async_generic_result send_to_all_backends(session &sess, const transport_control &control)
{
	scoped_trace_id guard(sess);
	return async_generic_result();
}

// Send request to one state at each session's groups
async_generic_result send_to_groups(session &sess, const transport_control &control)
{
	scoped_trace_id guard(sess);
	return async_generic_result();
}

// Send request to each state in route table
async_generic_result send_to_each_node(session &sess, const transport_control &control)
{
	scoped_trace_id guard(sess);
	return async_generic_result();
}

} } // namespace ioremap::elliptics
