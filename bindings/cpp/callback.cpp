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
	static int handler(dnet_addr *addr, dnet_cmd *cmd, void *priv)
	{
		basic_handler *that = reinterpret_cast<basic_handler *>(priv);
		if (that->handle(addr, cmd)) {
			delete that;
		}

		return 0;
	}

	basic_handler(const elliptics::logger *logger, async_generic_result &result) :
		m_logger(*logger),
		m_handler(result), m_completed(0), m_total(0)
	{
	}

	bool handle(dnet_addr *addr, dnet_cmd *cmd)
	{
		if (is_trans_destroyed(cmd)) {
			return increment_completed();
		}

		BH_LOG(m_logger, cmd->status ? DNET_LOG_ERROR : DNET_LOG_NOTICE,
			"%s: handled reply from: %s, cmd: %s, flags: %s, trans: %lld, status: %d, size: %lld, client: %d, last: %d",
			dnet_dump_id(&cmd->id), addr ? dnet_server_convert_dnet_addr(addr) : "<unknown>", dnet_cmd_string(cmd->cmd),
			dnet_flags_dump_cflags(cmd->flags), uint64_t(cmd->trans), int(cmd->status), uint64_t(cmd->size),
			!(cmd->flags & DNET_FLAGS_REPLY), !(cmd->flags & DNET_FLAGS_MORE));

		auto data = std::make_shared<callback_result_data>(addr, cmd);

		if (cmd->status)
			data->error = create_error(*cmd);

		callback_result_entry entry(data);

		if (cmd->cmd == DNET_CMD_EXEC && cmd->size > 0) {
			data->context = exec_context::parse(entry.data(), &data->error);
		}

		m_handler.process(entry);

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

	const elliptics::logger &m_logger;
	async_result_handler<callback_result_entry> m_handler;
	std::atomic_size_t m_completed;
	std::atomic_size_t m_total;
};

} // namespace detail

template <typename Method, typename T>
async_generic_result send_impl(session &sess, T &control, Method method)
{
	scoped_trace_id guard(sess);
	async_generic_result result(sess);

	detail::basic_handler *handler = new detail::basic_handler(sess.get_native_node()->log, result);

	control.complete = detail::basic_handler::handler;
	control.priv = handler;

	const size_t count = method(sess, control);

	if (handler->set_total(count))
		delete handler;

	return result;
}

static size_t send_to_single_state_impl(session &sess, dnet_trans_control &ctl)
{
	dnet_trans_alloc_send(sess.get_native(), &ctl);
	return 1;
}

// Send request to specificly set state by id
async_generic_result send_to_single_state(session &sess, const transport_control &control)
{
	dnet_trans_control writable_copy = control.get_native();
	return send_impl(sess, writable_copy, send_to_single_state_impl);
}

static size_t send_to_single_state_io_impl(session &sess, dnet_io_control &ctl)
{
	dnet_io_trans_alloc_send(sess.get_native(), &ctl);
	return 1;
}

async_generic_result send_to_single_state(session &sess, dnet_io_control &control)
{
	return send_impl(sess, control, send_to_single_state_io_impl);
}

static size_t send_to_each_backend_impl(session &sess, dnet_trans_control &ctl)
{
	return dnet_request_cmd(sess.get_native(), &ctl);
}

// Send request to each backend
async_generic_result send_to_each_backend(session &sess, const transport_control &control)
{
	dnet_trans_control writable_copy = control.get_native();
	return send_impl(sess, writable_copy, send_to_each_backend_impl);
}

static size_t send_to_each_node_impl(session &sess, dnet_trans_control &ctl)
{
	dnet_node *node = sess.get_native_node();
	dnet_session *native_sess = sess.get_native();
	dnet_net_state *st;

	ctl.cflags |= DNET_FLAGS_DIRECT;
	size_t count = 0;

	pthread_mutex_lock(&node->state_lock);
	list_for_each_entry(st, &node->dht_state_list, node_entry) {
		if (st == node->st)
			continue;

		dnet_trans_alloc_send_state(native_sess, st, &ctl);
		++count;
	}
	pthread_mutex_unlock(&node->state_lock);

	return count;
}

async_generic_result send_to_each_node(session &sess, const transport_control &control)
{
	dnet_trans_control writable_copy = control.get_native();
	return send_impl(sess, writable_copy, send_to_each_node_impl);
}

static size_t send_to_groups_impl(session &sess, dnet_trans_control &ctl)
{
	dnet_session *native = sess.get_native();
	size_t counter = 0;

	for (int i = 0; i < native->group_num; ++i) {
		ctl.id.group_id = native->groups[i];
		dnet_trans_alloc_send(native, &ctl);
		++counter;
	}

	return counter;
}

// Send request to one state at each session's group
async_generic_result send_to_groups(session &sess, const transport_control &control)
{
	dnet_trans_control writable_copy = control.get_native();
	return send_impl(sess, writable_copy, send_to_groups_impl);
}

static size_t send_to_groups_io_impl(session &sess, dnet_io_control &ctl)
{
	return dnet_trans_create_send_all(sess.get_native(), &ctl);
}

async_generic_result send_to_groups(session &sess, dnet_io_control &control)
{
	return send_impl(sess, control, send_to_groups_io_impl);
}

async_generic_result send_srw_command(session &sess, dnet_id *id, sph *srw_data)
{
	scoped_trace_id guard(sess);
	async_generic_result result(sess);

	detail::basic_handler *handler = new detail::basic_handler(sess.get_native_node()->log, result);

	const size_t count = dnet_send_cmd(sess.get_native(), id, detail::basic_handler::handler, handler, srw_data);

	if (handler->set_total(count))
		delete handler;

	return result;
}

} } // namespace ioremap::elliptics
