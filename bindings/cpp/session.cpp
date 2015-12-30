/*
 * 2008+ Copyright (c) Evgeniy Polyakov <zbr@ioremap.net>
 * 2012+ Copyright (c) Ruslan Nigmatullin <euroelessar@yandex.ru>
 * 2013+ Copyright (c) Kirill Smorodinnikov <shaitkir@gmail.com>
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
#include "functional_p.h"

#include <cerrno>
#include <sstream>
#include <functional>

#include "node_p.hpp"

#include "elliptics/async_result_cast.hpp"

namespace ioremap { namespace elliptics {

template <typename T>
class cstyle_scoped_pointer
{
	ELLIPTICS_DISABLE_COPY(cstyle_scoped_pointer)
	public:
		cstyle_scoped_pointer() : m_data(NULL)
		{
		}

		~cstyle_scoped_pointer()
		{
			if (m_data)
				free(m_data);
		}

		T * &data()
		{
			return m_data;
		}

	private:
		T *m_data;
};

transport_control::transport_control()
{
	memset(&m_data, 0, sizeof(m_data));
}

transport_control::transport_control(const dnet_id &id, unsigned int cmd, uint64_t cflags)
{
	memset(&m_data, 0, sizeof(m_data));
	memcpy(&m_data.id, &id, sizeof(id));
	m_data.cmd = cmd;
	m_data.cflags = cflags;
}

transport_control::transport_control(const dnet_trans_control &control) : m_data(control)
{
}

transport_control::~transport_control()
{
}

void transport_control::set_key(const dnet_id &id)
{
	m_data.id = id;
}

void transport_control::set_command(unsigned int cmd)
{
	m_data.cmd = cmd;
}

void transport_control::set_cflags(uint64_t cflags)
{
	m_data.cflags = cflags;
}

void transport_control::set_data(void *data, unsigned int size)
{
	m_data.data = data;
	m_data.size = size;
}

struct dnet_trans_control transport_control::get_native() const
{
	return m_data;
}

address::address()
{
	memset(&m_addr, 0, sizeof(m_addr));
}

address::address(const std::string &host, int port, int family)
{
	int err = dnet_create_addr(&m_addr, host.c_str(), port, family);
	if (err) {
		throw_error(err, "could not create addr: %s:%d:%d: %d", host.c_str(), port, family, err);
	}
}

address::address(const char *host, int port, int family)
{
	int err = dnet_create_addr(&m_addr, host, port, family);
	if (err) {
		throw_error(err, "could not create addr: %s:%d:%d: %d", host, port, family, err);
	}
}

address::address(const std::string &addr)
{
	int err = dnet_create_addr_str(&m_addr, addr.c_str(), addr.size());
	if (err) {
		throw_error(err, "could not create addr: %s: %d", addr.c_str(), err);
	}
}

address::address(const char *addr)
{
	int err = dnet_create_addr_str(&m_addr, addr, strlen(addr));
	if (err) {
		throw_error(err, "could not create addr: %s: %d", addr, err);
	}
}

address::address(const dnet_addr &addr) : m_addr(addr)
{
}

address::~address()
{
}

address::address(const address &other) : m_addr(other.m_addr)
{
}

address &address::operator =(const address &other)
{
	m_addr = other.m_addr;
	return *this;
}

bool address::operator ==(const address &other) const
{
	return dnet_addr_equal(&m_addr, &other.m_addr);
}

bool address::is_valid() const
{
	return m_addr.addr_len > 0;
}

std::string address::host() const
{
	return std::string(dnet_addr_host_string(&m_addr));
}

int address::port() const
{
	return dnet_addr_port(&m_addr);
}

int address::family() const
{
	return m_addr.family;
}

std::string address::to_string() const
{
	return dnet_addr_string(&m_addr);
}

std::string address::to_string_with_family() const
{
	std::string str = to_string();
	if (!str.empty()) {
		str += ':';
		str += std::to_string(static_cast<long long int>(m_addr.family));
	}
	return str;
}

const dnet_addr &address::to_raw() const
{
	return m_addr;
}

struct exec_context_data
{
	data_pointer srw_data;
	std::string event;
	data_pointer data;

	static exec_context create_raw(const exec_context *other, const std::string &event, const argument_data &data)
	{
		std::shared_ptr<exec_context_data> p = std::make_shared<exec_context_data>();

		p->srw_data = data_pointer::allocate(sizeof(sph) + event.size() + data.size());

		sph *raw_sph = p->srw_data.data<sph>();
		if (other) {
			memcpy(p->srw_data.data<sph>(), other->m_data->srw_data.data<sph>(), sizeof(sph));
		} else {
			memset(raw_sph, 0, sizeof(sph));
			raw_sph->src_key = -1;
		}

		char *raw_event = reinterpret_cast<char *>(raw_sph + 1);
		memcpy(raw_event, event.data(), event.size());
		char *raw_data = raw_event + event.size();
		memcpy(raw_data, data.data(), data.size());

		raw_sph->event_size = event.size();
		raw_sph->data_size = data.size();

		p->event = event;
		p->data = data_pointer::from_raw(raw_data, raw_sph->data_size);

		return exec_context(p);
	}

	static exec_context create(const std::string &event, const argument_data &data)
	{
		return create_raw(NULL, event, data);
	}

	static exec_context copy(const exec_context &other, const std::string &event, const argument_data &data)
	{
		return create_raw(&other, event, data);
	}

	static exec_context copy(const sph &other, const std::string &event, const argument_data &data)
	{
		sph tmp = other;
		tmp.event_size = 0;
		tmp.data_size = 0;
		return copy(exec_context::from_raw(&tmp, sizeof(tmp)), event, data);
	}
};

exec_context::exec_context()
{
}

exec_context::exec_context(const data_pointer &data)
{
	error_info error;
	exec_context tmp = parse(data, &error);
	if (error)
		error.throw_error();
	m_data = tmp.m_data;
}

exec_context::exec_context(const std::shared_ptr<exec_context_data> &data) : m_data(data)
{
}

exec_context::exec_context(const exec_context &other) : m_data(other.m_data)
{
}

exec_context &exec_context::operator =(const exec_context &other)
{
	m_data = other.m_data;
	return *this;
}

exec_context::~exec_context()
{
}

exec_context exec_context::from_raw(const void *const_data, size_t size)
{
	data_pointer data = data_pointer::from_raw(const_cast<void*>(const_data), size);
	return exec_context(data);
}

exec_context exec_context::parse(const data_pointer &data, error_info *error)
{
	if (data.size() < sizeof(sph)) {
		*error = create_error(-EINVAL, "Invalid exec_context size: %zu, must be more than sph: %zu",
				data.size(), sizeof(sph));
		return exec_context();
	}

	sph *s = data.data<sph>();
	if (data.size() != sizeof(sph) + s->event_size + s->data_size) {
		*error = create_error(-EINVAL, "Invalid exec_context size: %zu, "
				"must be equal to sph+event_size+data_size: %llu",
				data.size(),
				static_cast<unsigned long long>(sizeof(sph) + s->event_size + s->data_size));
		return exec_context();
	}

	char *event = reinterpret_cast<char *>(s + 1);

	auto priv = std::make_shared<exec_context_data>();
	priv->srw_data = data;
	priv->event.assign(event, event + s->event_size);
	priv->data = data.skip<sph>().skip(s->event_size);
	return exec_context(priv);
}

std::string exec_context::event() const
{
	return m_data ? m_data->event : std::string();
}

data_pointer exec_context::data() const
{
	return m_data ? m_data->data : data_pointer();
}

dnet_addr *exec_context::address() const
{
	return m_data ? &m_data->srw_data.data<sph>()->addr : NULL;
}

dnet_raw_id *exec_context::src_id() const
{
	return m_data ? &m_data->srw_data.data<sph>()->src : NULL;
}

int exec_context::src_key() const
{
	return m_data ? m_data->srw_data.data<sph>()->src_key : 0;
}

void exec_context::set_src_key(int src_key) const
{
	if (m_data) {
		m_data->srw_data.data<sph>()->src_key = src_key;
	}
}

data_pointer exec_context::native_data() const
{
	return m_data ? m_data->srw_data : data_pointer();
}

bool exec_context::is_final() const
{
	return m_data ? (m_data->srw_data.data<sph>()->flags & DNET_SPH_FLAGS_FINISH) : false;
}

bool exec_context::is_null() const
{
	return !m_data;
}

namespace filters {
bool positive(const callback_result_entry &entry)
{
	return entry.status() == 0 && !entry.data().empty();
}

bool positive_with_ack(const callback_result_entry &entry)
{
	return entry.status() == 0;
}

bool negative(const callback_result_entry &entry)
{
	return entry.status() != 0;
}

bool negative_with_ack(const callback_result_entry &entry)
{
	return entry.status() != 0 || entry.data().empty();
}

bool all(const callback_result_entry &entry)
{
	return entry.status() != 0 || !entry.data().empty();
}

bool all_with_ack(const callback_result_entry &entry)
{
	(void) entry;
	return true;
}

bool positive_final(const callback_result_entry &entry)
{
	return entry.is_final() && entry.status() == 0;
}

bool negative_final(const callback_result_entry &entry)
{
	return entry.is_final() && entry.status() != 0;
}

bool all_final(const callback_result_entry &entry)
{
	return entry.is_final();
}

} // namespace filters

namespace checkers
{
bool no_check(const std::vector<dnet_cmd> &statuses, size_t total)
{
	(void) statuses;
	(void) total;
	return true;
}

bool at_least_one(const std::vector<dnet_cmd> &statuses, size_t total)
{
	(void) total;
	for (auto it = statuses.begin(); it != statuses.end(); ++it) {
		if (it->status == 0)
			return true;
	}
	return false;
}

bool all(const std::vector<dnet_cmd> &statuses, size_t total)
{
	size_t success = 0;
	for (auto it = statuses.begin(); it != statuses.end(); ++it) {
		if (it->status == 0)
			++success;
	}

	return success == total;
}

bool quorum(const std::vector<dnet_cmd> &statuses, size_t total)
{
	size_t success = 0;
	for (auto it = statuses.begin(); it != statuses.end(); ++it) {
		if (it->status == 0)
			++success;
	}

	return (success > total / 2);
}
} // namespace checkers

namespace error_handlers
{
void none(const error_info &, const std::vector<dnet_cmd> &)
{
}

void remove_on_fail_impl(session &sess_, const error_info &error, const std::vector<dnet_cmd> &statuses) {
	auto sess = sess_.clone();

	logger &log = sess.get_logger();

	if (statuses.size() == 0) {
		BH_LOG(log, DNET_LOG_ERROR, "Unexpected empty statuses list at remove_on_fail_impl");
		return;
	}

	BH_LOG(log, DNET_LOG_DEBUG, "%s: failed to exec %s: %s, going to remove_data",
		dnet_dump_id(&statuses.front().id),
		dnet_cmd_string(statuses.front().cmd),
		error.message());

	std::vector<int> rm_groups;
	for (auto it = statuses.begin(); it != statuses.end(); ++it) {
		const dnet_cmd &cmd = *it;
		if (cmd.status == 0) {
			rm_groups.push_back(cmd.id.group_id);
		}
	}

	sess.set_groups(rm_groups);
	sess.remove(key(statuses.front().id));
}

result_error_handler remove_on_fail(const session &sess)
{
	return std::bind(remove_on_fail_impl, sess.clone(), std::placeholders::_1, std::placeholders::_2);
}

} // namespace error_handlers

static void create_session_data(session_data &sess, struct dnet_node *node)
{
	sess.session_ptr = dnet_session_create(node);
	if (!sess.session_ptr)
		throw std::bad_alloc();
	sess.filter = filters::positive;
	sess.checker = checkers::at_least_one;
	sess.error_handler = error_handlers::none;
	sess.policy = session::default_exceptions;
}

session_data::session_data(const node &n) : logger(n.get_log(), blackhole::log::attributes_t())
{
	create_session_data(*this, n.get_native());
}

session_data::session_data(dnet_node *node) : logger(*dnet_node_get_logger(node), blackhole::log::attributes_t())
{
	create_session_data(*this, node);
}

session_data::session_data(session_data &other)
	: logger(other.logger, blackhole::log::attributes_t()),
	  filter(other.filter),
	  checker(other.checker),
	  error_handler(other.error_handler),
	  policy(other.policy)
{
	session_ptr = dnet_session_copy(other.session_ptr);
	if (!session_ptr)
		throw std::bad_alloc();
}

session_data::~session_data()
{
	dnet_session_destroy(session_ptr);
}

session::session(const node &n) : m_data(std::make_shared<session_data>(n))
{
}

session::session(dnet_node *node) : m_data(std::make_shared<session_data>(node))
{

}

session::session(const std::shared_ptr<session_data> &d) : m_data(d)
{
}

session::session(const session &other) : m_data(other.m_data)
{
}

session::~session()
{
}

session session::clone() const
{
	return session(std::make_shared<session_data>(*m_data));
}

session session::clean_clone() const
{
	session sess = clone();
	sess.set_filter(filters::all_with_ack);
	sess.set_checker(checkers::no_check);
	sess.set_exceptions_policy(session::no_exceptions);
	return sess;
}

session &session::operator =(const session &other)
{
	m_data = other.m_data;
	return *this;
}

void session::set_groups(const std::vector<int> &groups)
{
	if (dnet_session_set_groups(m_data->session_ptr, groups.data(), groups.size()))
		throw std::bad_alloc();
}

std::vector<int> session::get_groups() const
{
	int count = 0;
	int *groups = dnet_session_get_groups(m_data->session_ptr, &count);
	return std::vector<int>(groups, groups + count);
}

void session::set_filter(const result_filter &filter)
{
	m_data->filter = filter;
}

result_filter session::get_filter() const
{
	return m_data->filter;
}

void session::set_checker(const result_checker &checker)
{
	m_data->checker = checker;
}

result_checker session::get_checker() const
{
	return m_data->checker;
}

void session::set_error_handler(const result_error_handler &error_handler)
{
	m_data->error_handler = error_handler;
}

result_error_handler session::get_error_handler() const
{
	return m_data->error_handler;
}

void session::set_exceptions_policy(uint32_t policy)
{
	m_data->policy = policy;
}

uint32_t session::get_exceptions_policy() const
{
	return m_data->policy;
}

dnet_id session::get_direct_id()
{
	if ((get_cflags() & DNET_FLAGS_DIRECT) == 0)
		throw ioremap::elliptics::error(-EINVAL, "DNET_FLAGS_DIRECT was not set");

	return *dnet_session_get_direct_id(get_native());
}

void session::set_direct_id(const address &remote_addr)
{
	set_cflags((get_cflags() | DNET_FLAGS_DIRECT) & ~DNET_FLAGS_DIRECT_BACKEND);
	dnet_session_set_direct_addr(get_native(), &remote_addr.to_raw());
}

void session::set_direct_id(const address &remote_addr, uint32_t backend_id)
{
	dnet_session_set_direct_addr(get_native(), &remote_addr.to_raw());
	dnet_session_set_direct_backend(get_native(), backend_id);
	set_cflags(get_cflags() | DNET_FLAGS_DIRECT | DNET_FLAGS_DIRECT_BACKEND);
}

void session::set_cflags(uint64_t cflags)
{
	dnet_session_set_cflags(m_data->session_ptr, cflags);
}

uint64_t session::get_cflags() const
{
	return dnet_session_get_cflags(m_data->session_ptr);
}

void session::set_ioflags(uint32_t ioflags)
{
	dnet_session_set_ioflags(m_data->session_ptr, ioflags);
}

void session::set_namespace(const std::string &ns)
{
	set_namespace(ns.c_str(), ns.size());
}

void session::set_namespace(const char *ns, int nsize)
{
	int err = dnet_session_set_ns(m_data->session_ptr, ns, nsize);
	if (err) {
		throw_error(err, "Could not set namespace '%s'", ns);
	}
}

uint32_t session::get_ioflags() const
{
	return dnet_session_get_ioflags(m_data->session_ptr);
}

void session::set_user_flags(uint64_t user_flags)
{
	dnet_session_set_user_flags(m_data->session_ptr, user_flags);
}

uint64_t session::get_user_flags() const
{
	return dnet_session_get_user_flags(m_data->session_ptr);
}

void session::set_timestamp(const dnet_time &ts)
{
	dnet_session_set_timestamp(m_data->session_ptr, &ts);
}

void session::set_timestamp(const dnet_time *ts)
{
	dnet_session_set_timestamp(m_data->session_ptr, ts);
}

void session::get_timestamp(dnet_time *ts)
{
	dnet_session_get_timestamp(m_data->session_ptr, ts);
}

void session::set_timeout(long timeout)
{
	dnet_session_set_timeout(m_data->session_ptr, timeout);
}

long session::get_timeout(void) const
{
	timespec *tm = dnet_session_get_timeout(m_data->session_ptr);
	return tm->tv_sec;
}

void session::set_trace_id(trace_id_t trace_id)
{
	dnet_session_set_trace_id(m_data->session_ptr, trace_id);
	blackhole::log::attributes_t attributes = {
		keyword::request_id() = trace_id
	};
	m_data->logger = logger(m_data->logger, std::move(attributes));
}

trace_id_t session::get_trace_id() const
{
	return dnet_session_get_trace_id(m_data->session_ptr);
}

void session::set_trace_bit(bool trace)
{
	dnet_session_set_trace_bit(m_data->session_ptr, trace);
}

bool session::get_trace_bit() const
{
	return dnet_session_get_trace_bit(m_data->session_ptr);
}

class read_handler : public multigroup_handler<read_handler, read_result_entry>
{
public:
	read_handler(const session &sess, const async_read_result &result,
		std::vector<int> &&groups, const dnet_io_control &control) :
		parent_type(sess, result, std::move(groups)),
		m_control(control)
	{
	}

	async_generic_result send_to_next_group()
	{
		m_control.id.group_id = current_group();

		return send_to_single_state(m_sess, m_control);
	}

	void process_entry(const read_result_entry &entry)
	{
		if (filters::positive(entry)) {
			m_read_result = entry;
		}

		switch (entry.status()) {
		case -ENOENT:
		case -EBADFD:
		case -EILSEQ:
			m_failed_groups.push_back(current_group());
			break;
		default:
			break;
		}
	}

	std::string join_groups(const std::vector<int> &groups)
	{
		std::ostringstream ss;
		for (auto it = groups.begin(); it != groups.end(); ++it) {
			if (it != groups.begin())
				ss << ":";
			ss << *it;
		}
		return ss.str();
	}

	void group_finished(const error_info &error)
	{
		dnet_io_attr *io = (m_read_result.is_valid() ? m_read_result.io_attribute() : NULL);

		if (!error && !m_failed_groups.empty()
				&& io
				&& (io->size == io->total_size)
				&& (io->offset == 0)) {

			BH_LOG(m_sess.get_logger(), DNET_LOG_INFO,
				"read_callback::read-recovery: %s: going to write %llu bytes -> %s groups",
				dnet_dump_id_str(io->id), static_cast<unsigned long long>(io->size),
				join_groups(m_failed_groups));

			std::sort(m_failed_groups.begin(), m_failed_groups.end());
			m_failed_groups.erase(std::unique(m_failed_groups.begin(), m_failed_groups.end()),
					m_failed_groups.end());

			session new_sess = m_sess.clone();
			new_sess.set_groups(m_failed_groups);

			dnet_io_control write_ctl;
			memcpy(&write_ctl, &m_control, sizeof(write_ctl));

			write_ctl.id = m_control.id;
			write_ctl.io = *io;

			write_ctl.data = m_read_result.file().data();
			write_ctl.io.size = m_read_result.file().size();

			write_ctl.fd = -1;
			write_ctl.cmd = DNET_CMD_WRITE;
			write_ctl.cflags = m_control.cflags;

			BH_LOG(m_sess.get_logger(), DNET_LOG_INFO,
				"read_callback::read-recovery: %s: write %llu bytes -> %s groups",
				dnet_dump_id_str(io->id), static_cast<unsigned long long>(io->size),
				join_groups(m_failed_groups));

			new_sess.write_data(write_ctl);
		}
	}

private:
	dnet_io_control m_control;
	read_result_entry m_read_result;
	std::vector<int> m_failed_groups;
};

async_read_result session::read_data(const key &id, const std::vector<int> &groups, const dnet_io_attr &io, unsigned int cmd)
{
	transform(id);

	dnet_io_control control;
	memset(&control, 0, sizeof(control));

	control.fd = -1;
	control.cmd = cmd;
	control.cflags = DNET_FLAGS_NEED_ACK;
	control.id = id.id();

	memcpy(&control.io, &io, sizeof(dnet_io_attr));

	async_read_result result(*this);
	auto handler = std::make_shared<read_handler>(*this, result, std::vector<int>(groups), control);
	handler->set_total(1);
	handler->start();

	return result;
}

async_read_result session::read_data(const key &id, const std::vector<int> &groups, const dnet_io_attr &io)
{
	return read_data(id, groups, io, DNET_CMD_READ);
}

async_read_result session::read_data(const key &id, int group, const dnet_io_attr &io)
{
	const std::vector<int> groups(1, group);
	return read_data(id, groups, io);
}

async_read_result session::read_data(const key &id, const std::vector<int> &groups, uint64_t offset, uint64_t size)
{
	transform(id);

	dnet_io_attr io;
	memset(&io, 0, sizeof(io));

	io.size   = size;
	io.offset = offset;
	io.flags  = get_ioflags();

	memcpy(io.id, id.id().id, DNET_ID_SIZE);
	memcpy(io.parent, id.id().id, DNET_ID_SIZE);

	return read_data(id, groups, io);
}

async_read_result session::read_data(const key &id, uint64_t offset, uint64_t size)
{
	DNET_SESSION_GET_GROUPS(async_read_result);

	return read_data(id, std::move(groups), offset, size);
}

// It could be a lambda functor! :`(
struct read_latest_callback
{
	session sess;
	key id;
	uint64_t offset;
	uint64_t size;
	async_result_handler<read_result_entry> handler;
	std::vector<int> groups;

	void operator() (const std::vector<lookup_result_entry> &result, const error_info &error)
	{
		if (error) {
			handler.complete(error);
			return;
		} else if (result.empty()) {
			handler.complete(create_error(-ENOENT, id, "prepare_latest failed"));
			return;
		}

		groups.clear();
		groups.reserve(result.size());
		for (auto it = result.begin(); it != result.end(); ++it)
			groups.push_back(it->command()->id.group_id);

		sess.set_filter(filters::all_with_ack);
		sess.set_checker(checkers::no_check);
		sess.read_data(id, groups, offset, size).connect(handler);
	}
};

async_read_result session::read_latest(const key &id, uint64_t offset, uint64_t size)
{
	DNET_SESSION_GET_GROUPS(async_read_result);

	session sess = clone();
	sess.set_exceptions_policy(no_exceptions);
	sess.set_filter(filters::positive);
	sess.set_checker(checkers::no_check);

	async_read_result result(*this);
	read_latest_callback callback = { sess, id, offset, size, result, std::move(groups) };
	callback.handler.set_total(1);
	prepare_latest(id, callback.groups).connect(callback);
	return result;
}

async_write_result session::write_data(const dnet_io_control &ctl)
{
	dnet_io_control ctl_copy = ctl;

	ctl_copy.cmd = DNET_CMD_WRITE;
	ctl_copy.cflags |= DNET_FLAGS_NEED_ACK;
	ctl_copy.io.user_flags |= get_user_flags();

	memcpy(ctl_copy.io.id, ctl_copy.id.id, DNET_ID_SIZE);

	if (dnet_time_is_empty(&ctl_copy.io.timestamp)) {
		get_timestamp(&ctl_copy.io.timestamp);

		if (dnet_time_is_empty(&ctl_copy.io.timestamp))
			dnet_current_time(&ctl_copy.io.timestamp);
	}

	session sess = clean_clone();
	return async_result_cast<write_result_entry>(*this, send_to_groups(sess, ctl_copy));
}

async_write_result session::write_data(const dnet_io_attr &io, const argument_data &file)
{
	dnet_io_control ctl;
	memset(&ctl, 0, sizeof(ctl));
	dnet_empty_time(&ctl.io.timestamp);

	ctl.cflags = get_cflags();
	ctl.data = file.data();

	ctl.io = io;

	ctl.io.size = file.size();

	ctl.io.flags |= get_ioflags();

	dnet_setup_id(&ctl.id, 0, (unsigned char *)io.id);

	ctl.fd = -1;

	return write_data(ctl);
}


async_write_result session::write_data(const key &id, const argument_data &file, uint64_t remote_offset)
{
	transform(id);

	dnet_io_control ctl;

	memset(&ctl, 0, sizeof(ctl));
	dnet_empty_time(&ctl.io.timestamp);

	ctl.cflags = get_cflags();
	ctl.data = file.data();

	ctl.io.flags = get_ioflags();
	ctl.io.user_flags = get_user_flags();
	ctl.io.offset = remote_offset;
	ctl.io.size = file.size();

	ctl.id = id.id();

	ctl.fd = -1;

	return write_data(ctl);
}

struct chunk_handler : public std::enable_shared_from_this<chunk_handler> {

	chunk_handler(const async_write_result::handler &handler, const session &sess,
			const key &id, const data_pointer &content,
			const uint64_t &remote_offset, const uint64_t &local_offset,
			const uint64_t &chunk_size)
		: handler(handler)
		, sess(sess.clone())
		, id (id)
		, content(content)
		, remote_offset(remote_offset)
		, local_offset(local_offset)
		, chunk_size(chunk_size)
	{
		//this->sess.set_filter(filters::all_with_ack);
	}

	void write_next(const std::vector<write_result_entry> &entries, const error_info &error) {
		if (error.code() != 0) {
			handler.complete(error);
			return;
		}

		std::vector<int> groups;
		for (auto it = entries.begin(); it != entries.end(); ++it) {
			groups.push_back(it->command()->id.group_id);
		}
		sess.set_groups(groups);

		local_offset += chunk_size;
		if (local_offset + chunk_size >= content.size()) {
			auto write_content = content.slice(local_offset, content.size() - local_offset);
			auto awr = sess.write_commit(id, write_content,
					remote_offset + local_offset,
					remote_offset + content.size());
			awr.connect(std::bind(&chunk_handler::finish, shared_from_this(),
						std::placeholders::_1, std::placeholders::_2));
		} else {
			auto write_content = content.slice(local_offset, chunk_size);
			auto awr = sess.write_plain(id, write_content, remote_offset + local_offset);
			awr.connect(std::bind(&chunk_handler::write_next, shared_from_this(),
						std::placeholders::_1, std::placeholders::_2));
		}
	}

	void finish(const std::vector<write_result_entry> &entries, const error_info &error) {
		for (auto it = entries.begin(); it != entries.end(); ++it)
			handler.process(*it);
		handler.complete(error);
	}

	async_write_result::handler handler;
	session sess;

	key id;
	data_pointer content;
	const uint64_t remote_offset;
	uint64_t local_offset;
	uint64_t chunk_size;

};

async_write_result session::write_data(const key &id, const data_pointer &file, uint64_t remote_offset, uint64_t chunk_size)
{
	if (file.size() <= chunk_size || chunk_size == 0)
		return write_data(id, file, remote_offset);

	data_pointer write_content = file.slice(0, chunk_size);
	auto awr = write_prepare(id, write_content, remote_offset, remote_offset + file.size());

	async_write_result res(*this);
	async_write_result::handler handler(res);

	auto ch = std::make_shared<chunk_handler>(handler, *this, id, file, remote_offset, 0, chunk_size);
	awr.connect(std::bind(&chunk_handler::write_next, ch, std::placeholders::_1, std::placeholders::_2));

	return res;
}

// At every iteration ask items to find the latest one
// Read it, process and write result to all groups
struct cas_functor : std::enable_shared_from_this<cas_functor>
{
	ELLIPTICS_DISABLE_COPY(cas_functor)

	typedef std::shared_ptr<cas_functor> ptr;

	cas_functor(session &sess,
		const async_write_result &result,
		const std::function<data_pointer (const data_pointer &)> &converter,
		const key &id,
		uint64_t remote_offset,
		int count,
		std::vector<int> &&groups)
		: sess(sess),
		handler(result),
		converter(converter),
		id(id),
		remote_offset(remote_offset),
		index(0),
		count(count),
		groups(groups)
	{
		handler.set_total(1);
	}

	session sess;
	async_result_handler<write_result_entry> handler;
	std::function<data_pointer (const data_pointer &)> converter;
	key id;
	uint64_t remote_offset;
	int index;
	int count;

	std::vector<int> groups;
	std::vector<dnet_id> check_sums;

	void next_iteration() {
		session_scope guard(sess);
		sess.set_exceptions_policy(session::no_exceptions);
		sess.set_filter(filters::all);
		sess.set_cflags(sess.get_cflags() | DNET_FLAGS_CHECKSUM);

		sess.prepare_latest(id, groups)
			.connect(bind_method(shared_from_this(), &cas_functor::on_prepare_lastest));
	}

	void on_prepare_lastest(const sync_lookup_result &result, const error_info &err) {
		if (!err && !result.empty()) {
			groups.clear();
			check_sums.clear();
			groups.reserve(result.size());
			check_sums.reserve(result.size());

			dnet_id checksum;

			for (auto it = result.begin(); it != result.end(); ++it) {
				const lookup_result_entry &entry = *it;
				if (entry.is_ack()) {
					continue;
				} if (entry.error()) {
					memset(&checksum, 0, sizeof(checksum));
				} else {
					memcpy(checksum.id, entry.file_info()->checksum, sizeof(checksum.id));
				}
				groups.push_back(entry.command()->id.group_id);
				check_sums.push_back(checksum);
			}
		} else {
			dnet_id checksum;
			memset(&checksum, 0, sizeof(checksum));
			check_sums.assign(groups.size(), checksum);
		}

		session_scope guard(sess);
		sess.set_exceptions_policy(session::no_exceptions);
		sess.set_filter(filters::positive);
		sess.set_ioflags(sess.get_ioflags() | DNET_IO_FLAGS_CHECKSUM);

		sess.read_data(id, remote_offset, 0)
			.connect(bind_method(shared_from_this(), &cas_functor::on_read));
	}

	void on_read(const sync_read_result &result, const error_info &err) {
		if (err && err.code() != -ENOENT) {
			handler.complete(err);
			return;
		}
		data_pointer data;
		uint32_t group_id = 0;
		const read_result_entry *entry = NULL;
		dnet_id csum;
		if (err.code() != -ENOENT) {
			entry = &result[0];
			data = entry->file();
			group_id = entry->command()->id.group_id;
			memcpy(csum.id, entry->io_attribute()->parent, sizeof(csum.id));
			csum.group_id = 0;
		} else {
			memset(&csum, 0, sizeof(csum));
		}

		data_pointer write_data = converter(data);

		if (write_data.size() == data.size()
			&& ((write_data.empty() && data.empty())
				|| write_data.data() == data.data())) {
			// Fake users and the system
			// We gave them a hope that write was successful,
			// but really data were already OK.

			dnet_addr addr;
			memset(&addr, 0, sizeof(addr));
			dnet_cmd cmd;
			memset(&cmd, 0, sizeof(cmd));
			if (entry) {
				cmd.id = entry->command()->id;
			} else if (!result.empty()) {
				cmd.id = result[0].command()->id;
			}
			cmd.cmd = DNET_CMD_WRITE;

			auto data = std::make_shared<callback_result_data>(&addr, &cmd);
			callback_result_entry entry = data;
			handler.process(*static_cast<const write_result_entry *>(&entry));
			handler.complete(error_info());
			return;
		}

		session write_sess = sess.clone();
		write_sess.set_filter(filters::all_with_ack);
		write_sess.set_exceptions_policy(session::no_exceptions);
		write_sess.set_groups(std::vector<int>());

		std::vector<async_write_result> write_results;

		std::vector<int> write_groups;
		std::swap(write_groups, groups);

		dnet_id raw_id = id.id();
		for (size_t i = 0; i < write_groups.size(); ++i) {
			raw_id.group_id = write_groups[i];
			if (raw_id.group_id == group_id)
				check_sums[i] = csum;

			auto result = write_sess.write_cas(raw_id, write_data, check_sums[i], remote_offset);
			write_results.emplace_back(std::move(result));
		}

		aggregated(write_sess, write_results.begin(), write_results.end())
			.connect(bind_method(shared_from_this(), &cas_functor::on_write_entry),
				bind_method(shared_from_this(), &cas_functor::on_write_finished));
	}

	void on_write_entry(const write_result_entry &result) {
		handler.process(result);

		if (result.error().code() == -EBADFD)
			groups.push_back(result.command()->id.group_id);
	}

	void on_write_finished(const error_info &err) {
		if (groups.empty()) {
			handler.complete(err);
			return;
		}

		++index;
		if (index < count) {
			next_iteration();
		} else {
			handler.complete(create_error(-EBADFD, id, "write_cas: too many attemps: %d", count));
		}
	}
}; /* write_entry */

async_write_result session::write_cas(const key &id, const std::function<data_pointer (const data_pointer &)> &converter,
		uint64_t remote_offset, int count)
{
	DNET_SESSION_GET_GROUPS(async_write_result);

	async_write_result result(*this);

	auto functor = std::make_shared<cas_functor>(*this, result, converter, id, remote_offset, count, std::move(groups));
	functor->next_iteration();

	return result;
}

async_write_result session::write_cas(const key &id, const argument_data &file, const dnet_id &old_csum, uint64_t remote_offset)
{
	transform(id);
	dnet_id raw = id.id();

	dnet_io_control ctl;

	memset(&ctl, 0, sizeof(ctl));
	dnet_empty_time(&ctl.io.timestamp);

	ctl.cflags = get_cflags();
	ctl.data = file.data();

	ctl.io.flags = get_ioflags() | DNET_IO_FLAGS_COMPARE_AND_SWAP;
	ctl.io.user_flags = get_user_flags();
	ctl.io.offset = remote_offset;
	ctl.io.size = file.size();
	ctl.io.num = file.size() + remote_offset;

	memcpy(&ctl.id, &raw, sizeof(dnet_id));
	memcpy(&ctl.io.parent, &old_csum.id, DNET_ID_SIZE);

	ctl.fd = -1;

	return write_data(ctl);
}

async_write_result session::write_prepare(const key &id, const argument_data &file, uint64_t remote_offset, uint64_t psize)
{
	transform(id);

	dnet_io_control ctl;

	memset(&ctl, 0, sizeof(ctl));
	dnet_empty_time(&ctl.io.timestamp);

	ctl.cflags = get_cflags();
	ctl.data = file.data();

	ctl.io.flags = get_ioflags() | DNET_IO_FLAGS_PREPARE | DNET_IO_FLAGS_PLAIN_WRITE;
	ctl.io.user_flags = get_user_flags();
	ctl.io.offset = remote_offset;
	ctl.io.size = file.size();
	ctl.io.num = psize;

	memcpy(&ctl.id, &id.id(), sizeof(ctl.id));

	ctl.fd = -1;

	return write_data(ctl);
}

async_write_result session::write_plain(const key &id, const argument_data &file, uint64_t remote_offset)
{
	transform(id);

	dnet_io_control ctl;

	memset(&ctl, 0, sizeof(ctl));
	dnet_empty_time(&ctl.io.timestamp);

	ctl.cflags = get_cflags();
	ctl.data = file.data();

	ctl.io.flags = get_ioflags() | DNET_IO_FLAGS_PLAIN_WRITE;
	ctl.io.user_flags = get_user_flags();
	ctl.io.offset = remote_offset;
	ctl.io.size = file.size();
	ctl.id = id.id();
	ctl.io.num = file.size() + remote_offset;

	memcpy(&ctl.id, &id.id(), sizeof(ctl.id));

	ctl.fd = -1;

	return write_data(ctl);
}

async_write_result session::write_commit(const key &id, const argument_data &file, uint64_t remote_offset, uint64_t csize)
{
	transform(id);

	dnet_io_control ctl;

	memset(&ctl, 0, sizeof(ctl));
	dnet_empty_time(&ctl.io.timestamp);

	ctl.cflags = get_cflags();
	ctl.data = file.data();

	ctl.io.flags = get_ioflags() | DNET_IO_FLAGS_COMMIT | DNET_IO_FLAGS_PLAIN_WRITE;
	ctl.io.user_flags = get_user_flags();
	ctl.io.offset = remote_offset;
	ctl.io.size = file.size();
	ctl.io.num = csize;
	ctl.id = id.id();

	ctl.fd = -1;

	return write_data(ctl);
}

async_write_result session::write_cache(const key &id, const argument_data &file, long timeout)
{
	transform(id);
	dnet_id raw = id.id();

	dnet_io_control ctl;

	memset(&ctl, 0, sizeof(ctl));
	dnet_empty_time(&ctl.io.timestamp);

	ctl.cflags = get_cflags();
	ctl.data = file.data();

	ctl.io.flags = get_ioflags() | DNET_IO_FLAGS_CACHE;
	ctl.io.user_flags = get_user_flags();
	ctl.io.start = timeout;
	ctl.io.size = file.size();

	memcpy(&ctl.id, &raw, sizeof(dnet_id));

	ctl.fd = -1;

	return write_data(ctl);
}

// TODO: Remove this method in elliptics-2.27
std::string session::lookup_address(const key &id, int group_id)
{
	char buf[128];
	struct dnet_addr addr;
	int backend_id = -1;

	memset(&addr, 0, sizeof(struct dnet_addr));

	int err = dnet_lookup_addr(m_data->session_ptr,
		id.by_id() ? NULL : id.remote().c_str(),
		id.by_id() ? 0 : id.remote().size(),
		id.by_id() ? &id.id() : NULL,
		group_id, &addr, &backend_id);

	if (err < 0) {
		if (id.by_id()) {
			throw_error(err, id.id(), "Failed to lookup");
		} else {
			throw_error(err, "Failed to lookup in group %d: key size: %zu",
				group_id, id.remote().size());
		}
	}

	dnet_addr_string_raw(&addr, buf, sizeof(buf));
	return std::string(buf, strlen(buf));
}

void session::transform(const std::string &data, dnet_id &id) const
{
	dnet_transform(m_data->session_ptr, (void *)data.data(), data.size(), &id);
}

void session::transform(const std::string &data, dnet_raw_id &id) const
{
	dnet_transform_raw(m_data->session_ptr, (void *)data.data(), data.size(), (char *)id.id, sizeof(id.id));
}

void session::transform(const data_pointer &data, dnet_id &id) const
{
	dnet_transform(m_data->session_ptr, data.data(), data.size(), &id);
}

void session::transform(const key &id) const
{
	id.transform(*this);
}

class lookup_handler : public multigroup_handler<lookup_handler, lookup_result_entry>
{
public:
	lookup_handler(const session &sess, const async_lookup_result &result,
		std::vector<int> &&groups, const dnet_trans_control control) :
		multigroup_handler<lookup_handler, lookup_result_entry>(sess, result, std::move(groups)),
		m_control(control)
	{
	}

	async_generic_result send_to_next_group()
	{
		m_control.id.group_id = current_group();

		return send_to_single_state(m_sess, m_control);
	}

private:
	dnet_trans_control m_control;
};

async_lookup_result session::lookup(const key &id)
{
	DNET_SESSION_GET_GROUPS(async_lookup_result);

	transport_control control(id.id(), DNET_CMD_LOOKUP, DNET_FLAGS_NEED_ACK);

	async_lookup_result result(*this);
	auto handler = std::make_shared<lookup_handler>(*this, result, std::move(groups), control.get_native());
	handler->set_total(1);
	handler->start();

	return result;
}

async_lookup_result session::parallel_lookup(const key &id)
{
	transform(id);

	transport_control control(id.id(), DNET_CMD_LOOKUP, DNET_FLAGS_NEED_ACK);

	session sess = clean_clone();
	return async_result_cast<lookup_result_entry>(*this, send_to_groups(sess, control));
}

struct prepare_latest_functor
{
	async_result_handler<lookup_result_entry> result;
	uint32_t group_id;

	struct comparator
	{
		bool operator() (dnet_file_info *a, dnet_file_info *b) const
		{
			return (a->mtime.tsec > b->mtime.tsec)
				|| (a->mtime.tsec == b->mtime.tsec
					&& (a->mtime.tnsec > b->mtime.tnsec));
		}

		int type(const lookup_result_entry &entry) const
		{
			const int status = entry.status();
			// valid positive response
			if (status == 0 && entry.data().size() > sizeof(dnet_file_info))
				return 0;
			// ack response
			if (status == 0)
				return 1;
			// negative response
			return 2;
		}

		bool operator() (const lookup_result_entry &a, const lookup_result_entry &b) const
		{
			const int type_a = type(a);
			const int type_b = type(b);

			if (type_a == 0 && type_b == 0) {
				return operator() (a.file_info(), b.file_info());
			}
			return type_a < type_b;
		}
	};

	bool is_equal(dnet_file_info *a, dnet_file_info *b)
	{
		return a->mtime.tsec == b->mtime.tsec
			&& a->mtime.tnsec == b->mtime.tnsec;
	}

	void operator() (std::vector<lookup_result_entry> results, const error_info &error)
	{
		comparator cmp;
		std::stable_sort(results.begin(), results.end(), cmp);
		for (auto it = results.begin(); it != results.end(); ++it)
			result.process(*it);

		// Prefer to use user's group
		for (size_t i = 1; i < results.size(); ++i) {
			// We've found answer with interested group
			if (results[i].command()->id.group_id == group_id) {
				// Check if it has the same priority as first one
				if (!cmp(results[i], results[0]) && !cmp(results[0], results[i]))
					std::swap(results[i], results[0]);
				break;
			}
		}
		result.complete(error);
	}
};

async_lookup_result session::prepare_latest(const key &id, const std::vector<int> &groups)
{
	async_lookup_result result(*this);
	async_result_handler<lookup_result_entry> result_handler(result);
	result_handler.set_total(groups.size());

	// One clones the session in order not to affect the user settings
	auto sess = clean_clone();
	sess.set_groups(groups);

	prepare_latest_functor functor = { result_handler, id.id().group_id };
	sess.parallel_lookup(id).connect(functor);

	return result;
}

struct quorum_lookup_aggregator_handler
{
	// Helper methods for comparison dnet_times
	static bool dnet_time_less_than(const dnet_time &t1, const dnet_time &t2) {
		return std::make_tuple(t1.tsec, t1.tnsec) < std::make_tuple(t2.tsec, t2.tnsec);
	}

	struct dnet_time_less_checker {
		bool operator() (const dnet_time &t1, const dnet_time &t2) {
			return dnet_time_less_than(t1, t2);
		}
	};

	ELLIPTICS_DISABLE_COPY(quorum_lookup_aggregator_handler)

	quorum_lookup_aggregator_handler(const async_result_handler<lookup_result_entry> &result_handler,
		size_t requests_count)
		: handler(result_handler), in_work(requests_count), quorum(requests_count / 2 + 1),
		max_ts{0, 0}, has_finished(false)
	{
		handler.set_total(requests_count);
	}

	void complete(const std::vector<lookup_result_entry> &result, const error_info &reply_error) {
		std::lock_guard<std::mutex> lock(mutex);
		(void) lock;

		// has_finished will be set when necessary lookup_result_entries are passed into async_result
		// to avoid handling the rest of results
		if (has_finished) {
			return;
		}

		in_work -= 1;

		// reply_error means transaction is bad, so result contains entries with error
		// every error is passed into async_result
		if (reply_error) {
			for (auto it = result.begin(), end = result.end(); it != end; ++it) {
				if (filters::negative(*it)) {
					handler.process(*it);
				}
			}

			// This result can be the last; should pass necessary lookup_result_entries into async_result
			complete_if_no_works();
			return;
		}

		const auto &entry = find_positive(result);
		auto ts = entry.file_info()->mtime;

		if (dnet_time_less_than(max_ts, ts)) {
			max_ts = ts;
		}

		// lookup_result_entries with the same timestamp are merged into one vector for convenient usage
		auto &record = entries[ts];
		{
			auto &list = std::get<1>(record);
			list.insert(list.end(), result.begin(), result.end());
		}

		// if there are quorum results with the same timestamp pass them into async_result
		if ((std::get<0>(record) += 1) == quorum) {
			complete_with_ts(ts);
			return;
		}

		// This result can be the last; should pass necessary lookup_result_entries into async_result
		complete_if_no_works();
	}

	const lookup_result_entry &find_positive(const std::vector<lookup_result_entry> &result) {
		for (auto it = result.begin(), end = result.end(); it != end; ++it) {
			if (filters::positive(*it)) {
				return *it;
			}
		}

		assert(false);
		exit(-22);
	}

	void complete_if_no_works() {
		// if the last result is processed and there are no quorum results with the same timestamp
		// than pass entries with maximum timestamp
		if (in_work == 0) {
			complete_with_ts(max_ts);
			return;
		}
	}

	// The method passes lookup_result_entries with timestamp equals to ts into async_result
	void complete_with_ts(const dnet_time &ts) {
		has_finished = true;

		const auto &list = std::get<1>(entries[ts]);
		for (auto it = list.begin(), end = list.end(); it != end; ++it) {
			handler.process(*it);
		}

		// We shouldn't set an error here, the reason is:
		// - it's possible to get good responses from the quorum of groups and errors from the others
		// and it's not an error in general for quorum_lookup
		// - it's possible to get only a good result from a group and errors from others
		// and it's also not an error for quorum_lookup
		// If user want to distinguish these cases, he can set a corresponding checker for session
		handler.complete(error_info());
	}

	std::mutex mutex;
	async_result_handler<lookup_result_entry> handler;
	std::map<dnet_time, std::tuple<size_t, std::vector<lookup_result_entry>>, dnet_time_less_checker> entries;
	size_t in_work;
	size_t quorum;
	dnet_time max_ts;
	bool has_finished;
};

// quorum_lookup aggregates lookup_result_entries by timestamp by using helper class quorum_lookup_aggregator_handler
// Handler will complete if there are quorum (groups_count / 2 + 1) lookup_result_entries with the same timestamp
// These lookup_result_entries are the result
// Otherwise handler will complete when every lookup is finished
// In this case result is lookup_result_entries with the greatest timestamp
// In both cases result also contains lookup_result_entries with error info
async_lookup_result session::quorum_lookup(const key &id)
{
	// The only thing doing here: connecting helper class to async_results
	transform(id);

	async_lookup_result result(*this);
	async_result_handler<lookup_result_entry> result_handler(result);

	const std::vector<int> &groups = get_groups();

	auto handler = std::make_shared<quorum_lookup_aggregator_handler>(result_handler,
			groups.size());
	auto complete = std::bind(&quorum_lookup_aggregator_handler::complete, handler,
			std::placeholders::_1, std::placeholders::_2);

	// Prepare c-style transport control as we need to set valid groups every time
	dnet_trans_control control = transport_control(id.id(), DNET_CMD_LOOKUP, DNET_FLAGS_NEED_ACK).get_native();

	// We need to set at_least_one checker as we need to determine if request failed
	session sess = clean_clone();
	sess.set_checker(checkers::at_least_one);

	// Notify handler about each finished transaction
	for (size_t i = 0; i < groups.size(); ++i) {
		control.id.group_id = groups[i];
		async_result_cast<lookup_result_entry>(sess, send_to_single_state(sess, control)).connect(complete);
	}

	return result;
}

async_remove_result session::remove(const key &id)
{
	transform(id);

	dnet_io_control ctl;
	memset(&ctl, 0, sizeof(struct dnet_io_control));

	memcpy(&ctl.id, &id.id(), sizeof(struct dnet_id));

	memcpy(&ctl.io.id, id.id().id, DNET_ID_SIZE);
	memcpy(&ctl.io.parent, id.id().id, DNET_ID_SIZE);
	ctl.io.flags = dnet_session_get_ioflags(get_native());

	ctl.fd = -1;

	ctl.cmd = DNET_CMD_DEL;
	ctl.cflags = DNET_FLAGS_NEED_ACK;

	return send_to_groups(*this, ctl);
}

async_monitor_stat_result session::monitor_stat(uint64_t categories)
{
	dnet_monitor_stat_request request;
	memset(&request, 0, sizeof(struct dnet_monitor_stat_request));
	request.categories = categories;
	dnet_convert_monitor_stat_request(&request);

	transport_control control;
	control.set_command(DNET_CMD_MONITOR_STAT);
	control.set_cflags(DNET_FLAGS_NEED_ACK | DNET_FLAGS_NOLOCK);
	control.set_data(&request, sizeof(request));

	session sess = clean_clone();
	return async_result_cast<monitor_stat_result_entry>(*this, send_to_each_node(sess, control));
}

async_monitor_stat_result session::monitor_stat(const address &addr, uint64_t categories)
{
	dnet_monitor_stat_request request;
	memset(&request, 0, sizeof(struct dnet_monitor_stat_request));
	request.categories = categories;
	dnet_convert_monitor_stat_request(&request);

	transport_control control;
	control.set_command(DNET_CMD_MONITOR_STAT);
	control.set_cflags(DNET_FLAGS_NEED_ACK | DNET_FLAGS_NOLOCK);
	control.set_data(&request, sizeof(request));

	session sess = clean_clone();
	sess.set_direct_id(addr);
	return async_result_cast<monitor_stat_result_entry>(*this, send_to_single_state(sess, control));
}

int session::state_num(void)
{
	return dnet_state_num(m_data->session_ptr);
}

async_generic_result session::request_cmd(const transport_control &ctl)
{
	return send_to_each_backend(*this, ctl);
}

async_generic_result session::request_single_cmd(const transport_control &ctl)
{
	return send_to_single_state(*this, ctl);
}

async_node_status_result session::update_status(const address &addr, const dnet_node_status &status)
{
	data_pointer data = data_pointer::allocate(sizeof(dnet_node_status));
	dnet_node_status *node_status = data.data<dnet_node_status>();
	*node_status = status;

	transport_control control;
	control.set_command(DNET_CMD_STATUS);
	control.set_cflags(DNET_FLAGS_NEED_ACK);
	control.set_data(data.data(), data.size());

	session sess = clean_clone();
	sess.set_direct_id(addr);
	return async_result_cast<node_status_result_entry>(*this, send_to_single_state(sess, control));
}

async_node_status_result session::request_node_status(const address &addr)
{
	struct dnet_node_status node_status;
	memset(&node_status, 0, sizeof(struct dnet_node_status));
	node_status.nflags = -1;
	node_status.status_flags = -1;
	node_status.log_level = ~0U;

	return update_status(addr, node_status);
}

struct backend_status_params
{
	backend_status_params(session &sess, const address &address, uint32_t id_backend, dnet_backend_command cmd)
	: orig_sess(sess),
	 addr(address),
	 backend_id(id_backend),
	 command(cmd),
	 defrag_level(DNET_BACKEND_DEFRAG_FULL),
	 delay(0)
	{}

	session &orig_sess;
	address addr;
	uint32_t backend_id;
	dnet_backend_command command;
	dnet_backend_defrag_level defrag_level;
	uint32_t delay;
	std::vector<dnet_raw_id> ids;
};

static async_backend_control_result update_backend_status(const backend_status_params &params)
{
	data_pointer data = data_pointer::allocate(sizeof(dnet_backend_control) + params.ids.size() * sizeof(dnet_raw_id));
	dnet_backend_control *backend_control = data.data<dnet_backend_control>();
	memset(backend_control, 0, sizeof(dnet_backend_control));

	backend_control->backend_id = params.backend_id;
	backend_control->command = params.command;
	backend_control->ids_count = params.ids.size();
	backend_control->defrag_level = params.defrag_level;
	backend_control->delay = params.delay;

	if (!params.ids.empty()) {
		data_pointer tmp = data.skip<dnet_backend_control>();
		memcpy(tmp.data(), params.ids.data(), params.ids.size() * sizeof(dnet_raw_id));
	}

	// We want to set random dnet_id to ensure that we won't occupy all IO threads
	// by accident control calls for single backend.
	dnet_id id;
	memset(&id, 0, sizeof(id));
	reinterpret_cast<uint32_t &>(*id.id) = params.backend_id;
	for (size_t i = sizeof(uint32_t); i < sizeof(id.id); ++i) {
		id.id[i] = rand();
	}

	transport_control control;
	control.set_key(id);
	control.set_command(DNET_CMD_BACKEND_CONTROL);
	control.set_cflags(DNET_FLAGS_NEED_ACK | DNET_FLAGS_DIRECT);
	control.set_data(data.data(), data.size());

	session sess = params.orig_sess.clean_clone();
	sess.set_direct_id(params.addr);
	return async_result_cast<backend_status_result_entry>(params.orig_sess, send_to_single_state(sess, control));
}

async_backend_control_result session::enable_backend(const address &addr, uint32_t backend_id)
{
	return update_backend_status(backend_status_params(*this, addr, backend_id, DNET_BACKEND_ENABLE));
}

async_backend_control_result session::disable_backend(const address &addr, uint32_t backend_id)
{
	return update_backend_status(backend_status_params(*this, addr, backend_id, DNET_BACKEND_DISABLE));
}

async_backend_control_result session::start_defrag(const address &addr, uint32_t backend_id)
{
	backend_status_params params(*this, addr, backend_id, DNET_BACKEND_START_DEFRAG);
	params.defrag_level = DNET_BACKEND_DEFRAG_FULL;
	return update_backend_status(params);
}

async_backend_control_result session::start_compact(const address &addr, uint32_t backend_id)
{
	backend_status_params params(*this, addr, backend_id, DNET_BACKEND_START_DEFRAG);
	params.defrag_level = DNET_BACKEND_DEFRAG_COMPACT;
	return update_backend_status(params);
}

async_backend_control_result session::stop_defrag(const address &addr, uint32_t backend_id)
{
	return update_backend_status(backend_status_params(*this, addr, backend_id, DNET_BACKEND_STOP_DEFRAG));
}

async_backend_control_result session::set_backend_ids(const address &addr, uint32_t backend_id,
		const std::vector<dnet_raw_id> &ids)
{
	backend_status_params params(*this, addr, backend_id, DNET_BACKEND_SET_IDS);
	params.ids = ids;
	return update_backend_status(params);
}

async_backend_control_result session::make_readonly(const address &addr, uint32_t backend_id)
{
	return update_backend_status(backend_status_params(*this, addr, backend_id, DNET_BACKEND_READ_ONLY));
}

async_backend_control_result session::make_writable(const address &addr, uint32_t backend_id)
{
	return update_backend_status(backend_status_params(*this, addr, backend_id, DNET_BACKEND_WRITEABLE));
}

async_backend_control_result session::set_delay(const address &addr, uint32_t backend_id, uint32_t delay)
{
	backend_status_params params(*this, addr, backend_id, DNET_BACKEND_CTL);
	params.delay = delay;
	return update_backend_status(params);
}

async_backend_status_result session::request_backends_status(const address &addr)
{
	transport_control control;
	control.set_command(DNET_CMD_BACKEND_STATUS);
	control.set_cflags(DNET_FLAGS_NEED_ACK | DNET_FLAGS_DIRECT);

	session sess = clean_clone();
	sess.set_direct_id(addr);
	return async_result_cast<backend_status_result_entry>(*this, send_to_single_state(sess, control));
}

class read_data_range_callback
{
	public:
		struct scope
		{
			scope(const session &sess, const async_result_handler<read_result_entry> &handler)
				: sess(sess), handler(handler) {}

			session sess;
			dnet_io_attr io;
			dnet_id id;
			int group_id;
			unsigned int cmd;
			bool need_exit;

			bool has_any;
			dnet_io_attr rep;

			async_result_handler<read_result_entry> handler;
			std::function<void (const read_result_entry &)> me_entry;
			std::function<void (const error_info &)> me_final;
			dnet_raw_id start, next;
			dnet_raw_id end;
			uint64_t size;
			std::vector<read_result_entry> result;
			error_info last_exception;
		};

		std::shared_ptr<scope> data;

		read_data_range_callback(const session &sess,
			const dnet_io_attr &io, int group_id,
			const async_result_handler<read_result_entry> &handler)
			: data(std::make_shared<scope>(sess, handler))
		{
			scope *d = data.get();

			d->io = io;
			d->group_id = group_id;
			d->need_exit = false;
			d->has_any = false;
			d->me_entry = *this;
			d->me_final = *this;
			d->cmd = DNET_CMD_READ_RANGE;
			d->size = io.size;

			memcpy(d->end.id, d->io.parent, DNET_ID_SIZE);

			dnet_setup_id(&d->id, d->group_id, d->io.id);
		}

		void do_next(error_info *error)
		{
			scope *d = data.get();
			dnet_node * const node = d->sess.get_native_node();
			d->has_any = false;

			if (d->need_exit) {
				if (d->result.empty())
					d->handler.complete(d->last_exception);
				else
					d->handler.complete(error_info());
				return;
			}
			int err = dnet_search_range(node, &d->id, &d->start, &d->next);
			if (err) {
				*error = create_error(err, d->io.id, "Failed to read range data object: group: %d, size: %llu",
					d->group_id, static_cast<unsigned long long>(d->io.size));
				return;
			}

			if ((dnet_id_cmp_str(d->id.id, d->next.id) > 0) ||
					!memcmp(d->start.id, d->next.id, DNET_ID_SIZE) ||
					(dnet_id_cmp_str(d->next.id, d->end.id) > 0)) {
				memcpy(d->next.id, d->end.id, DNET_ID_SIZE);
				d->need_exit = true;
			}

			{
				logger &log = d->sess.get_logger();
				int len = 6;
				char start_id[2*len + 1];
				char next_id[2*len + 1];
				char end_id[2*len + 1];
				char id_str[2*len + 1];

				BH_LOG(log, DNET_LOG_NOTICE, "id: %s, start: %s: next: %s, end: %s, size: %llu, cmp: %d",
					dnet_dump_id_len_raw(d->id.id, len, id_str),
					dnet_dump_id_len_raw(d->start.id, len, start_id),
					dnet_dump_id_len_raw(d->next.id, len, next_id),
					dnet_dump_id_len_raw(d->end.id, len, end_id),
					d->size,
					dnet_id_cmp_str(d->next.id, d->end.id));
			}

			memcpy(d->io.id, d->id.id, DNET_ID_SIZE);
			memcpy(d->io.parent, d->next.id, DNET_ID_SIZE);

			d->io.size = d->size;

			std::vector<int> groups(1, d->group_id);
			{
				session sess = d->sess.clean_clone();
				sess.read_data(d->id, groups, d->io, d->cmd).connect(d->me_entry, d->me_final);
			}
		}

		void operator() (const read_result_entry &entry)
		{
			scope *d = data.get();

			d->has_any = true;
			if (entry.status() == 0 && entry.data().size() == sizeof(dnet_io_attr))
				d->rep = *entry.io_attribute();
			else
				d->handler.process(entry);
		}

		void operator() (const error_info &error)
		{
			scope *d = data.get();

			if (error) {
				d->last_exception = error;
			} else {
				dnet_io_attr *rep = &d->rep;

				BH_LOG(d->sess.get_logger(),
					DNET_LOG_NOTICE, "%s: rep_num: %llu, io_start: %llu, io_num: %llu, io_size: %llu",
					dnet_dump_id(&d->id), (unsigned long long)rep->num, (unsigned long long)d->io.start,
					(unsigned long long)d->io.num, (unsigned long long)d->io.size);

				if (d->io.start < rep->num) {
					rep->num -= d->io.start;
					d->io.start = 0;
					d->io.num -= rep->num;

					d->last_exception = error_info();

					if (!d->io.num) {
						d->handler.complete(error_info());
						return;
					}
				} else {
					d->io.start -= rep->num;
				}
			}

			memcpy(d->id.id, d->next.id, DNET_ID_SIZE);

			error_info next_error;
			do_next(&next_error);
			if (next_error)
				d->handler.complete(next_error);
		}
};

class remove_data_range_callback : public read_data_range_callback
{
	public:
		remove_data_range_callback(const session &sess,
			const dnet_io_attr &io, int group_id,
			const async_result_handler<read_result_entry> &handler)
		: read_data_range_callback(sess, io, group_id, handler)
		{
			scope *d = data.get();

			d->cmd = DNET_CMD_DEL_RANGE;
			d->me_entry = *this;
			d->me_final = *this;
		}

		void operator() (const read_result_entry &entry)
		{
			scope *d = data.get();

			d->has_any = true;
			if (entry.status() == 0 && entry.data().size() == sizeof(dnet_io_attr))
				d->rep = *entry.io_attribute();
			d->handler.process(entry);
		}

		void operator() (const error_info &error)
		{
			scope *d = data.get();

			if (error) {
				d->last_exception = error;
			} else {
				if (d->has_any) {
					BH_LOG(d->sess.get_logger(), DNET_LOG_NOTICE,
							"%s: rep_num: %llu, io_start: %llu, io_num: %llu, io_size: %llu",
							dnet_dump_id(&d->id),
							(unsigned long long)d->rep.num, (unsigned long long)d->io.start,
							(unsigned long long)d->io.num, (unsigned long long)d->io.size);
				} else {
					d->handler.complete(create_error(-ENOENT, d->io.id,
						"Failed to remove range data object: group: %d, size: %llu",
						d->group_id, static_cast<unsigned long long>(d->io.size)));
				}
			}

			memcpy(d->id.id, d->next.id, DNET_ID_SIZE);

			error_info next_error;
			do_next(&next_error);
			if (next_error)
				d->handler.complete(next_error);
		}
};

async_read_result session::read_data_range(const dnet_io_attr &io, int group_id)
{
	async_read_result result(*this);
	async_result_handler<read_result_entry> handler(result);
	error_info error;
	read_data_range_callback(*this, io, group_id, handler).do_next(&error);
	if (get_exceptions_policy() & throw_at_start)
		error.throw_error();
	return result;
}

async_read_result session::remove_data_range(const dnet_io_attr &io, int group_id)
{
	async_read_result result(*this);
	async_result_handler<read_result_entry> handler(result);
	error_info error;
	remove_data_range_callback(*this, io, group_id, handler).do_next(&error);
	if (get_exceptions_policy() & throw_at_start)
		error.throw_error();
	return result;
}

std::vector<dnet_route_entry> session::get_routes()
{
	scoped_trace_id guard(*this);
	cstyle_scoped_pointer<dnet_route_entry> entries;

	int count = dnet_get_routes(m_data->session_ptr, &entries.data());

	if (count < 0)
		return std::vector<dnet_route_entry>();

	return std::vector<dnet_route_entry>(entries.data(), entries.data() + count);
}

async_exec_result session::request(dnet_id *id, const exec_context &context)
{
	session sess = clean_clone();
	return async_result_cast<exec_result_entry>(*this, send_srw_command(sess, id, context.m_data->srw_data.data<sph>()));
}

async_iterator_result session::iterator(const key &id, const data_pointer& request)
{
	if (get_groups().empty()) {
		async_iterator_result result(*this);
		async_result_handler<iterator_result_entry> handler(result);
		handler.complete(create_error(-ENXIO, "iterator: groups list is empty"));
		return result;
	}

	transform(id);

	dnet_trans_control ctl;
	memset(&ctl, 0, sizeof(ctl));
	memcpy(&ctl.id, &id.id(), sizeof(dnet_id));
	ctl.id.group_id = get_groups().front();
	ctl.cflags = DNET_FLAGS_NEED_ACK | DNET_FLAGS_NOLOCK;
	ctl.cmd = DNET_CMD_ITERATOR;

	dnet_iterator_request *req = request.data<dnet_iterator_request>();
	if (req->range_num)
		req->flags |= DNET_IFLAGS_KEY_RANGE;

	dnet_convert_iterator_request(req);

	ctl.data = request.data();
	ctl.size = request.size();

	session sess = clean_clone();
	return async_result_cast<iterator_result_entry>(*this, send_to_single_state(sess, ctl));
}

error_info session::mix_states(const key &id, std::vector<int> &groups)
{
	transform(id);

	cstyle_scoped_pointer<int> groups_ptr;

	dnet_id raw = id.id();

	int num = dnet_mix_states(m_data->session_ptr, &raw, get_ioflags(), &groups_ptr.data());
	if (num < 0)
		return create_error(num, id, "could not fetch groups, num: %zd, ioflags: %s",
				groups.size(), dnet_flags_dump_ioflags(get_ioflags()));

	groups.assign(groups_ptr.data(), groups_ptr.data() + num);

	return error_info();
}

async_iterator_result session::start_iterator(const key &id, const std::vector<dnet_iterator_range>& ranges,
		uint32_t type, uint64_t flags, const dnet_time& time_begin, const dnet_time& time_end)
{
	if (type == DNET_ITYPE_SERVER_SEND) {
		async_iterator_result result(*this);
		async_result_handler<iterator_result_entry> handler(result);
		handler.complete(create_error(-EINVAL, "iterator: server-send iterator can not be started via this call"));
		return result;
	}

	size_t ranges_size = ranges.size() * sizeof(ranges.front());

	data_pointer data = data_pointer::allocate(sizeof(dnet_iterator_request) + ranges_size);
	memset(data.data(), 0, sizeof(dnet_iterator_request));

	auto req = data.data<dnet_iterator_request>();

	req->action = DNET_ITERATOR_ACTION_START;
	req->itype = type;
	req->flags = flags;
	req->time_begin = time_begin;
	req->time_end = time_end;
	req->range_num = ranges.size();

	if (ranges_size)
		memcpy(data.skip<dnet_iterator_request>().data(), &ranges.front(), ranges_size);

	return iterator(id, data);
}

async_iterator_result session::start_copy_iterator(const key &id,
		const std::vector<dnet_iterator_range>& ranges,
		uint64_t flags,
		const dnet_time& time_begin, const dnet_time& time_end,
		const std::vector<int> &dst_groups)
{
	size_t ranges_size = ranges.size() * sizeof(ranges.front());
	size_t groups_size = dst_groups.size() * sizeof(dst_groups.front());

	if (dst_groups.empty()) {
		async_iterator_result result(*this);
		async_result_handler<iterator_result_entry> handler(result);
		handler.complete(create_error(-ENXIO, "iterator: remote groups list is empty"));
		return result;
	}

	data_pointer data = data_pointer::allocate(sizeof(dnet_iterator_request) + ranges_size + groups_size);
	memset(data.data(), 0, sizeof(dnet_iterator_request));

	auto req = data.data<dnet_iterator_request>();

	req->action = DNET_ITERATOR_ACTION_START;
	req->itype = DNET_ITYPE_SERVER_SEND;
	req->flags = flags;
	req->time_begin = time_begin;
	req->time_end = time_end;
	req->range_num = ranges.size();
	req->group_num = dst_groups.size();

	if (ranges_size)
		memcpy(data.skip<dnet_iterator_request>().data(), &ranges.front(), ranges_size);

	if (groups_size)
		memcpy(data.skip(ranges_size + sizeof(dnet_iterator_request)).data(), &dst_groups.front(), groups_size);

	return iterator(id, data);
}

async_iterator_result session::pause_iterator(const key &id, uint64_t iterator_id)
{
	data_pointer data = data_pointer::allocate(sizeof(dnet_iterator_request));
	auto request = data.data<dnet_iterator_request>();
	memset(request, 0, sizeof(dnet_iterator_request));
	request->action = DNET_ITERATOR_ACTION_PAUSE;
	request->id = iterator_id;

	return iterator(id, data);
}

async_iterator_result session::continue_iterator(const key &id, uint64_t iterator_id)
{
	data_pointer data = data_pointer::allocate(sizeof(dnet_iterator_request));
	auto request = data.data<dnet_iterator_request>();
	memset(request, 0, sizeof(dnet_iterator_request));
	request->action = DNET_ITERATOR_ACTION_CONTINUE;
	request->id = iterator_id;

	return iterator(id, data);
}

async_iterator_result session::cancel_iterator(const key &id, uint64_t iterator_id)
{
	data_pointer data = data_pointer::allocate(sizeof(dnet_iterator_request));
	auto request = data.data<dnet_iterator_request>();
	memset(request, 0, sizeof(dnet_iterator_request));
	request->action = DNET_ITERATOR_ACTION_CANCEL;
	request->id = iterator_id;

	return iterator(id, data);
}

async_iterator_result session::server_send(const std::vector<key> &keys, uint64_t iflags, const std::vector<int> &groups)
{
	if (get_groups().empty()) {
		async_iterator_result result(*this);
		async_result_handler<iterator_result_entry> handler(result);
		handler.complete(create_error(-ENXIO, "server_send: local group list is empty"));
		return result;
	}

	if (groups.empty()) {
		async_iterator_result result(*this);
		async_result_handler<iterator_result_entry> handler(result);
		handler.complete(create_error(-ENXIO, "server_send: remote group list is empty"));
		return result;
	}

	if (keys.empty()) {
		async_iterator_result result(*this);
		async_result_handler<iterator_result_entry> handler(result);
		handler.complete(create_error(-ENXIO, "server_send: keys list is empty"));
		return result;
	}

	int local_group = get_groups().front();
	int err;

	struct la {
		dnet_addr	addr;
		int		backend_id;

		// this ID is used to send set of keys to single remote node (addr+backend),
		// which hosts all of them according to current route table
		dnet_id		id;

		bool operator<(const la &other) const {
			int cmp = dnet_addr_cmp(&addr, &other.addr);
			if (cmp < 0)
				return true;
			if (cmp > 0)
				return false;
			return backend_id < other.backend_id;
		}
	};

	std::map<la, std::vector<dnet_raw_id>> raw_ids;
	for (auto key_it = keys.begin(), id_end = keys.end(); key_it != id_end; ++key_it) {
		la l;

		err = dnet_lookup_addr(get_native(), NULL, 0, &key_it->id(), local_group, &l.addr, &l.backend_id);
		if (err != 0) {
			l.id = key_it->id();
			l.id.group_id = local_group;

			async_iterator_result result(*this);
			async_result_handler<iterator_result_entry> handler(result);
			handler.complete(create_error(-ENXIO,
					"server_send: could not locate backend for requested key %d:%s",
					local_group, dnet_dump_id(&l.id)));
			return result;
		}

		auto it = raw_ids.find(l);
		if (it == raw_ids.end()) {
			// we only have to setup @l.id when it is inserted into id map
			// only address+backend are used for lookup in this map,
			// while @l.id will be used later to specify remote node to send command to
			l.id = key_it->id();
			l.id.group_id = local_group;

			raw_ids[l] = std::vector<dnet_raw_id>({key_it->raw_id()});
		} else {
			it->second.push_back(key_it->raw_id());
		}
	}

	const size_t groups_size = groups.size() * sizeof(groups.front());

	std::list<async_iterator_result> results;

	{
		session_scope scope(*this);

		// Ensure checkers and filters will work only for aggregated request
		set_filter(filters::all_with_ack);
		set_checker(checkers::no_check);
		set_exceptions_policy(no_exceptions);

		session sess = clean_clone();

		for (auto it = raw_ids.begin(), ids_end = raw_ids.end(); it != ids_end; ++it) {
			auto &id = it->first;
			auto &ids = it->second;

			const size_t ids_size = ids.size() * sizeof(dnet_raw_id);

			data_pointer data = data_pointer::allocate(sizeof(dnet_server_send_request) + ids_size + groups_size);
			auto req = data.data<dnet_server_send_request>();
			req->id_num = ids.size();
			req->group_num = groups.size();
			req->iflags = iflags;

			dnet_convert_server_send_request(req);

			memcpy(data.skip<dnet_server_send_request>().data(), ids.data(), ids_size);
			memcpy(data.skip(ids_size + sizeof(dnet_server_send_request)).data(), groups.data(), groups_size);

			dnet_trans_control ctl;
			memset(&ctl, 0, sizeof(dnet_trans_control));
			ctl.id = id.id;
			ctl.cflags = DNET_FLAGS_NEED_ACK | DNET_FLAGS_NOLOCK;
			ctl.cmd = DNET_CMD_SEND;

			ctl.data = data.data();
			ctl.size = data.size();

			async_iterator_result res = async_result_cast<iterator_result_entry>(sess, send_to_single_state(*this, ctl));
			results.emplace_back(std::move(res));
		}
	}

	return aggregated(*this, results.begin(), results.end());
}

async_iterator_result session::server_send(const std::vector<dnet_raw_id> &ids, uint64_t iflags, const std::vector<int> &groups)
{
	std::vector<key> keys;
	for (auto id = ids.begin(), id_end = ids.end(); id != id_end; ++id) {
		keys.emplace_back(*id);
	}

	return server_send(keys, iflags, groups);
}

async_iterator_result session::server_send(const std::vector<std::string> &strs, uint64_t iflags, const std::vector<int> &groups)
{
	std::vector<key> keys;
	for (auto s = strs.begin(), send = strs.end(); s != send; ++s) {
		key k(*s);
		k.transform(*this);

		keys.emplace_back(k);
	}

	return server_send(keys, iflags, groups);
}

async_exec_result session::exec(dnet_id *id, const std::string &event, const argument_data &data)
{
	return exec(id, -1, event, data);
}

async_exec_result session::exec(dnet_id *id, int src_key, const std::string &event, const argument_data &data)
{
	exec_context context = exec_context_data::create(event, data);

	sph *s = context.m_data->srw_data.data<sph>();
	s->flags = DNET_SPH_FLAGS_SRC_BLOCK;
	s->src_key = src_key;

	if (id)
		memcpy(s->src.id, id->id, sizeof(s->src.id));

	return request(id, context);
}

async_exec_result session::exec(const exec_context &tmp_context, const std::string &event, const argument_data &data)
{
	exec_context context = exec_context_data::copy(tmp_context, event, data);

	sph *s = context.m_data->srw_data.data<sph>();
	s->flags = DNET_SPH_FLAGS_SRC_BLOCK;

	dnet_id id;
	dnet_setup_id(&id, 0, s->src.id);

	return request(&id, context);
}

async_push_result session::push(dnet_id *id, const exec_context &tmp_context,
		const std::string &event, const argument_data &data)
{
	exec_context context = exec_context_data::copy(tmp_context, event, data);

	sph *s = context.m_data->srw_data.data<sph>();
	s->flags &= ~DNET_SPH_FLAGS_SRC_BLOCK;
	s->flags &= ~(DNET_SPH_FLAGS_REPLY | DNET_SPH_FLAGS_FINISH);

	return request(id, context);
}

async_reply_result session::reply(const exec_context &tmp_context,
		const argument_data &data, exec_context::final_state state)
{
	exec_context context = exec_context_data::copy(tmp_context, tmp_context.event(), data);

	sph *s = context.m_data->srw_data.data<sph>();

	s->flags |= DNET_SPH_FLAGS_REPLY;
	s->flags &= ~DNET_SPH_FLAGS_SRC_BLOCK;

	if (state == exec_context::final)
		s->flags |= DNET_SPH_FLAGS_FINISH;
	else
		s->flags &= ~DNET_SPH_FLAGS_FINISH;

	dnet_id id;
	dnet_setup_id(&id, 0, s->src.id);

	return request(&id, context);
}

struct io_attr_comparator
{
	bool operator() (const dnet_io_attr &io1, const dnet_io_attr &io2)
	{
		return memcmp(io1.id, io2.id, DNET_ID_SIZE) < 0;
	}
};

typedef std::set<dnet_io_attr, io_attr_comparator> io_attr_set;

class bulk_read_handler : public multigroup_handler<bulk_read_handler, read_result_entry>
{
public:
	bulk_read_handler(const session &sess, const async_read_result &result,
		std::vector<int> &&groups, const dnet_io_control &control, io_attr_set &&ios) :
		parent_type(sess, result, std::move(groups)),
		m_control(control), m_original_id(control.id),
		m_ios_set(std::move(ios)), m_logger(m_sess.get_logger())
	{
		m_sess.set_checker(checkers::no_check);
	}

	async_generic_result send_to_next_group()
	{
		size_t count = 0;

		m_ios_cache.assign(m_ios_set.begin(), m_ios_set.end());
		const size_t io_num = m_ios_cache.size();
		dnet_io_attr *ios = m_ios_cache.data();

		dnet_node *node = m_sess.get_native_node();
		net_state_id cur, next;
		const int group_id = current_group();
		int start = 0;

		std::vector<async_generic_result> results;

		dnet_id next_id;
		memset(&next_id, 0, sizeof(next_id));

		dnet_id id;
		memset(&id, 0, sizeof(id));
		dnet_setup_id(&id, group_id, ios[0].id);

		debug("BULK_READ, callback: %p, group: %d, next", this, group_id);

		cur.reset(node, &id);
		if (!cur) {
			debug("BULK_READ, callback: %p, group: %d, id: %s, state: failed",
				this, group_id, dnet_dump_id(&id));
			return aggregated(m_sess, results.begin(), results.end());
		}
		debug("BULK_READ, callback: %p, id: %s, state: %s, backend: %d",
			this, dnet_dump_id(&id), dnet_state_dump_addr(cur.state()), cur.backend());

		for (size_t i = 0; i < io_num; ++i) {
			if ((i + 1) < io_num) {
				dnet_setup_id(&next_id, group_id, ios[i + 1].id);

				next.reset(node, &next_id);
				if (!next) {
					debug("BULK_READ, callback: %p, group: %d, id: %s, state: failed",
						this, group_id, dnet_dump_id(&next_id));
					return aggregated(m_sess, results.begin(), results.end());
				}
				debug("BULK_READ, callback: %p, id: %s, state: %s, backend: %d",
					this, dnet_dump_id(&next_id), dnet_state_dump_addr(next.state()), next.backend());

				/* Send command only if state changes or it's a last id */
				if (cur == next) {
					next.reset();
					continue;
				}
			}

			m_control.io.size = (i - start + 1) * sizeof(struct dnet_io_attr);
			m_control.data = ios + start;

			memcpy(&m_control.id, &id, sizeof(id));

			notice("BULK_READ, callback: %p, start: %s: end: %s, count: %llu, state: %s, backend: %d",
				this,
				dnet_dump_id(&id),
				dnet_dump_id(&next_id),
				(unsigned long long)m_control.io.size / sizeof(struct dnet_io_attr),
				dnet_state_dump_addr(cur.state()), cur.backend());

			++count;

			results.emplace_back(send_to_single_state(m_sess, m_control));

			debug("BULK_READ, callback: %p, group: %d", this, group_id);

			start = i + 1;
			cur.reset();
			std::swap(cur, next);

			id = next_id;
		}

		debug("BULK_READ, callback: %p, group: %d, count: %d", this, group_id, count);

		return aggregated(m_sess, results.begin(), results.end());
	}

	bool need_next_group(const error_info &error)
	{
		(void) error;

		debug("BULK_READ, callback: %p, ios_set.size: %llu, group_index: %llu, group_count: %llu",
		      this, m_ios_set.size(), m_group_index, m_groups.size());

		// all results are found or all groups are iterated
		return !m_ios_set.empty();
	}

	void process_entry(const read_result_entry &entry)
	{
		if (filters::positive(entry)) {
			m_ios_set.erase(*entry.io_attribute());
		}
	}

private:
	dnet_io_control m_control;
	const dnet_id m_original_id;
	io_attr_set m_ios_set;
	std::vector<dnet_io_attr> m_ios_cache;
	const dnet_logger &m_logger;
};

async_read_result session::bulk_read(const std::vector<dnet_io_attr> &ios_vector)
{
	if (ios_vector.empty()) {
		error_info error = create_error(-EINVAL, "bulk_read failed: ios list is empty");
		if (get_exceptions_policy() & throw_at_start) {
			error.throw_error();
		} else {
			async_read_result result(*this);
			async_result_handler<read_result_entry> handler(result);
			handler.complete(error);
			return result;
		}
	}

	dnet_raw_id id;
	memcpy(id.id, ios_vector[0].id, DNET_ID_SIZE);

	DNET_SESSION_GET_GROUPS(async_read_result);

	io_attr_set ios(ios_vector.begin(), ios_vector.end());

	dnet_io_control control;
	memset(&control, 0, sizeof(control));

	control.fd = -1;

	control.cmd = DNET_CMD_BULK_READ;
	control.cflags = DNET_FLAGS_NEED_ACK;

	memset(&control.io, 0, sizeof(dnet_io_attr));
	control.io.flags = get_ioflags();

	async_read_result result(*this);
	auto handler = std::make_shared<bulk_read_handler>(*this, result, std::move(groups), control, std::move(ios));
	handler->start();

	return result;
}

async_read_result session::bulk_read(const std::vector<std::string> &keys)
{
	std::vector<dnet_io_attr> ios;
	dnet_io_attr io;
	memset(&io, 0, sizeof(io));

	io.flags = get_ioflags();

	ios.reserve(keys.size());

	for (size_t i = 0; i < keys.size(); ++i) {
		dnet_id id;

		transform(keys[i], id);
		memcpy(io.id, id.id, sizeof(io.id));
		ios.push_back(io);
	}

	return bulk_read(ios);
}

async_read_result session::bulk_read(const std::vector<key> &keys)
{
	std::vector<dnet_io_attr> ios;
	dnet_io_attr io;
	memset(&io, 0, sizeof(io));

	io.flags = get_ioflags();

	ios.reserve(keys.size());

	for (size_t i = 0; i < keys.size(); ++i) {
		transform(keys[i]);

		memcpy(io.id, keys[i].id().id, sizeof(io.id));
		ios.push_back(io);
	}

	return bulk_read(ios);
}

async_write_result session::bulk_write(const std::vector<dnet_io_attr> &ios, const std::vector<argument_data> &data)
{
	if (ios.size() != data.size()) {
		error_info error = create_error(-EINVAL, "BULK_WRITE: ios doesn't meet data: io.size: %zd, data.size: %zd",
			ios.size(), data.size());
		if (get_exceptions_policy() & throw_at_start) {
			error.throw_error();
		} else {
			async_write_result result(*this);
			async_result_handler<write_result_entry> handler(result);
			handler.complete(error);
			return result;
		}
	}

	std::vector<async_write_result> results;

	{
		session_scope scope(*this);

		// Ensure checkers and filters will work only for aggregated request
		set_filter(filters::all_with_ack);
		set_checker(checkers::no_check);
		set_exceptions_policy(no_exceptions);

		for(size_t i = 0; i < ios.size(); ++i) {
			results.emplace_back(std::move(write_data(ios[i], data[i])));
		}
	}

	return aggregated(*this, results.begin(), results.end());
}

async_remove_result session::bulk_remove(const std::vector<key> &keys)
{
	std::vector<async_remove_result> results;

	{
		session_scope scope(*this);

		// Ensure checkers and filters will work only for aggregated request
		set_checker(checkers::no_check);
		set_filter(filters::all_with_ack);
		set_exceptions_policy(no_exceptions);

		for(size_t i = 0; i < keys.size(); ++i) {
			results.emplace_back(std::move(remove(keys[i])));
		}
	}

	return aggregated(*this, results.begin(), results.end());
}

async_write_result session::bulk_write(const std::vector<dnet_io_attr> &ios, const std::vector<std::string> &data)
{
	std::vector<argument_data> pointer_data;
	pointer_data.reserve(data.size());
	for (auto it = data.begin(); it != data.end(); ++it)
		pointer_data.push_back(*it);
	return bulk_write(ios, pointer_data);
}

logger &session::get_logger() const
{
	return m_data->logger;
}

dnet_node *session::get_native_node() const
{
	return dnet_session_get_node(m_data->session_ptr);
}

dnet_session *session::get_native()
{
	return m_data->session_ptr;
}

} } // namespace ioremap::elliptics
