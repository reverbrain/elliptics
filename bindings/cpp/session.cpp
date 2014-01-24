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

extern __thread uint32_t trace_id;

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

transport_control::transport_control(const struct dnet_id &id, unsigned int cmd, uint64_t cflags)
{
	memset(&m_data, 0, sizeof(m_data));
	memcpy(&m_data.id, &id, sizeof(id));
	m_data.cmd = cmd;
	m_data.cflags = cflags;
}

void transport_control::set_key(const struct dnet_id &id)
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

struct exec_context_data
{
	data_pointer sph;
	std::string event;
	data_pointer data;

	static exec_context create_raw(const exec_context *other, const std::string &event, const data_pointer &data)
	{
		std::shared_ptr<exec_context_data> p = std::make_shared<exec_context_data>();

		p->sph = data_pointer::allocate(sizeof(struct sph) + event.size() + data.size());

		struct sph *raw_sph = p->sph.data<struct sph>();
		if (other) {
			memcpy(p->sph.data<struct sph>(), other->m_data->sph.data<struct sph>(), sizeof(struct sph));
		} else {
			memset(raw_sph, 0, sizeof(struct sph));
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

	static exec_context create(const std::string &event, const data_pointer &data)
	{
		return create_raw(NULL, event, data);
	}

	static exec_context copy(const exec_context &other, const std::string &event, const data_pointer &data)
	{
		return create_raw(&other, event, data);
	}

	static exec_context copy(const struct sph &other, const std::string &event, const data_pointer &data)
	{
		struct sph tmp = other;
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
		*error = create_error(-EINVAL, "Invalid exec_context size: %zu, must be more than sph: %zu", data.size(), sizeof(sph));
		return exec_context();
	}

	sph *s = data.data<sph>();
	if (data.size() != sizeof(sph) + s->event_size + s->data_size) {
		*error = create_error(-EINVAL, "Invalid exec_context size: %zu, must be equal to sph+event_size+data_size: %llu",
				data.size(), static_cast<unsigned long long>(sizeof(sph) + s->event_size + s->data_size));
		return exec_context();
	}

	char *event = reinterpret_cast<char *>(s + 1);

	auto priv = std::make_shared<exec_context_data>();
	priv->sph = data;
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
	return m_data ? &m_data->sph.data<sph>()->addr : NULL;
}

dnet_raw_id *exec_context::src_id() const
{
	return m_data ? &m_data->sph.data<sph>()->src : NULL;
}

int exec_context::src_key() const
{
	return m_data ? m_data->sph.data<sph>()->src_key : 0;
}

void exec_context::set_src_key(int src_key) const
{
	if (m_data) {
		m_data->sph.data<sph>()->src_key = src_key;
	}
}

data_pointer exec_context::native_data() const
{
	return m_data ? m_data->sph : data_pointer();
}

bool exec_context::is_final() const
{
	return m_data ? (m_data->sph.data<sph>()->flags & DNET_SPH_FLAGS_FINISH) : false;
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

bool negative(const callback_result_entry &entry)
{
	return entry.status() != 0;
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

void remove_on_fail_impl(session &sess, const error_info &error, const std::vector<dnet_cmd> &statuses) {
	logger log = sess.get_logger();

	if (statuses.size() == 0) {
		log.log(DNET_LOG_ERROR, "Unexpected empty statuses list at remove_on_fail_impl");
		return;
	}

	if (log.get_log_level() >= DNET_LOG_DEBUG) {
		// TODO: Add printf-like stile to elliptics::logger interface
		char buffer[1024];
		DNET_DUMP_ID(id, &statuses.front().id);
		snprintf(buffer, sizeof(buffer), "%s: failed to exec %s: %s, going to remove data",
			id, dnet_cmd_string(statuses.front().cmd), error.message().c_str());
		buffer[sizeof(buffer) - 1] = '\0';
		log.log(DNET_LOG_DEBUG, buffer);
	}

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

session_data::session_data(const node &n) : node_guard(n.m_data), logger(n.get_log())
{
	session_ptr = dnet_session_create(n.get_native());
	if (!session_ptr)
		throw std::bad_alloc();
	filter = filters::positive;
	checker = checkers::at_least_one;
	error_handler = error_handlers::none;
	policy = session::default_exceptions;
	trace_id = 0;
	::trace_id = 0;
}

session_data::session_data(const session_data &other)
	: node_guard(other.node_guard),
	  logger(other.logger),
	  filter(other.filter),
	  checker(other.checker),
	  error_handler(other.error_handler),
	  policy(other.policy),
	  trace_id(other.trace_id)
{
	session_ptr = dnet_session_copy(other.session_ptr);
	if (!session_ptr)
		throw std::bad_alloc();
	::trace_id = other.trace_id;
}

session_data::~session_data()
{
	dnet_session_destroy(session_ptr);
}

session::session(const node &n) : m_data(std::make_shared<session_data>(n))
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

void session::set_direct_id(dnet_addr remote_addr)
{
	std::vector<std::pair<struct dnet_id, struct dnet_addr> > routes = get_routes();

	if (routes.empty())
		throw ioremap::elliptics::error(-ENXIO, "Route list is empty");

	for (auto it = routes.begin(); it != routes.end(); ++it) {
		if (dnet_addr_equal(&remote_addr, &it->second)) {
			dnet_session_set_direct_id(get_native(), &it->first);
			set_cflags(get_cflags() | DNET_FLAGS_DIRECT);
			return;
		}
	}

	throw ioremap::elliptics::error(-ESRCH, "Route not found");
}

void session::set_direct_id(const char *saddr, int port, int family)
{
	dnet_addr addr;
	int err;

	memset(&addr, 0, sizeof(addr));
	addr.addr_len = sizeof(addr.addr);
	addr.family = family;

	err = dnet_fill_addr(&addr, saddr, port, SOCK_STREAM, IPPROTO_TCP);
	if (err != 0)
		throw ioremap::elliptics::error(err, "dnet_fill_addr failed");

	set_direct_id(addr);
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

void session::set_namespace(const char *ns, int nsize)
{
	int err;

	err = dnet_session_set_ns(m_data->session_ptr, ns, nsize);
	if (err) {
		std::string tmp(ns, nsize);
		throw ioremap::elliptics::error(err, "Could not set namespace '" + tmp + "'");
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

void session::set_timestamp(struct dnet_time *ts)
{
	dnet_session_set_timestamp(m_data->session_ptr, ts);
}

void session::get_timestamp(struct dnet_time *ts)
{
	dnet_session_get_timestamp(m_data->session_ptr, ts);
}

void session::set_timeout(unsigned int timeout)
{
	dnet_session_set_timeout(m_data->session_ptr, timeout);
}

long session::get_timeout(void) const
{
	struct timespec *tm = dnet_session_get_timeout(m_data->session_ptr);
	return tm->tv_sec;
}

void session::set_trace_id(uint32_t trace_id)
{
	m_data->trace_id = trace_id;
	::trace_id = trace_id;
}

uint32_t session::get_trace_id()
{
	return m_data->trace_id;
}

void session::read_file(const key &id, const std::string &file, uint64_t offset, uint64_t size)
{
	int err;

	if (id.by_id()) {
		dnet_id raw = id.id();
		err = dnet_read_file_id(m_data->session_ptr, file.c_str(), &raw, offset, size);
	} else {
		err = dnet_read_file(m_data->session_ptr, file.c_str(), id.remote().c_str(), id.remote().size(), offset, size);
	}

	if (err) {
		transform(id);
		throw_error(err, id.id(), "READ: %s: offset: %llu, size: %llu",
			file.c_str(), static_cast<unsigned long long>(offset),
			static_cast<unsigned long long>(size));
	}
}

void session::write_file(const key &id, const std::string &file, uint64_t local_offset,
				uint64_t offset, uint64_t size)
{
	int err;

	if (id.by_id()) {
		dnet_id raw = id.id();
		err = dnet_write_file_id(m_data->session_ptr, file.c_str(), &raw, local_offset, offset, size);
	} else {
		err = dnet_write_file(m_data->session_ptr, file.c_str(), id.remote().c_str(), id.remote().size(),
							 local_offset, offset, size);
	}
	if (err) {
		transform(id);
		throw_error(err, id.id(), "WRITE: %s, local_offset: %llu, "
			"offset: %llu, size: %llu",
			file.c_str(), static_cast<unsigned long long>(local_offset),
			static_cast<unsigned long long>(offset),
			static_cast<unsigned long long>(size));
	}
}

async_read_result session::read_data(const key &id, const std::vector<int> &groups, const dnet_io_attr &io)
{
	return read_data(id, groups, io, DNET_CMD_READ);
}

async_read_result session::read_data(const key &id, const std::vector<int> &groups, const dnet_io_attr &io, unsigned int cmd)
{
	transform(id);

	async_read_result result(*this);
	struct dnet_io_control control;
	memset(&control, 0, sizeof(control));

	control.fd = -1;
	control.cmd = cmd;
	control.cflags = DNET_FLAGS_NEED_ACK | get_cflags();

	memcpy(&control.io, &io, sizeof(struct dnet_io_attr));

	auto cb = createCallback<read_callback>(*this, result, control);
	cb->kid = id;
	cb->groups = groups;

	startCallback(cb);
	return result;
}

async_read_result session::read_data(const key &id, int group, const dnet_io_attr &io)
{
	const std::vector<int> groups(1, group);
	return read_data(id, groups, io);
}

async_read_result session::read_data(const key &id, const std::vector<int> &groups, uint64_t offset, uint64_t size)
{
	transform(id);

	struct dnet_io_attr io;
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
	transform(id);

	return read_data(id, mix_states(id), offset, size);
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
		sort(results.begin(), results.end(), cmp);
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

	if (groups.empty()) {
		result_handler.complete(error_info());
		return result;
	}
	transform(id);

	std::list<async_lookup_result> lookup_results;

	{
		session_scope scope(*this);

		// Ensure checkers and policy will work only for aggregated request
		set_filter(filters::all_with_ack);
		set_checker(checkers::no_check);
		set_exceptions_policy(no_exceptions);

		dnet_id raw = id.id();
		for(size_t i = 0; i < groups.size(); ++i) {
			session session_copy = clone();

			session_copy.set_groups(std::vector<int>(1, groups[i]));
			try {
				auto lookup_result = session_copy.lookup(raw);
				lookup_results.emplace_back(std::move(lookup_result));
			} catch (error &e) {
				raw.group_id = groups[i];
				auto logger = get_logger();
				logger.print(DNET_LOG_ERROR, "%s: failed to lookup, err: %s", dnet_dump_id(&raw), e.error_message().c_str());
			}
		}

		if (lookup_results.empty()) {
			result_handler.complete(error_info());
			return result;
		}

		auto tmp_result = aggregated(*this, lookup_results.begin(), lookup_results.end());
		prepare_latest_functor functor = { result_handler, id.id().group_id };
		tmp_result.connect(functor);
	}
	return result;
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
		if (!error && !result.empty()) {
			groups.clear();
			groups.reserve(result.size());
			for (auto it = result.begin(); it != result.end(); ++it)
				groups.push_back(it->command()->id.group_id);
		}

		{
			session_scope scope(sess);
			sess.set_exceptions_policy(session::no_exceptions);
			sess.read_data(id, groups, offset, size).connect(handler);
		}
	}
};

async_read_result session::read_latest(const key &id, uint64_t offset, uint64_t size)
{
	async_read_result result(*this);
	{
		session sess = clone();
		sess.set_filter(filters::positive);
		sess.set_checker(checkers::no_check);

		read_latest_callback callback = { sess, id, offset, size, result, mix_states(id) };
		prepare_latest(id, callback.groups).connect(callback);
	}
	return result;
}

async_write_result session::write_data(const dnet_io_control &ctl)
{
	async_write_result result(*this);
	auto cb = createCallback<write_callback>(*this, result, ctl);

	cb->ctl.cmd = DNET_CMD_WRITE;
	cb->ctl.cflags |= DNET_FLAGS_NEED_ACK;

	memcpy(cb->ctl.io.id, cb->ctl.id.id, DNET_ID_SIZE);

	startCallback(cb);
	return result;
}

async_write_result session::write_data(const dnet_io_attr &io, const data_pointer &file)
{
	struct dnet_io_control ctl;
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


async_write_result session::write_data(const key &id, const data_pointer &file, uint64_t remote_offset)
{
	transform(id);
	dnet_id raw = id.id();

	struct dnet_io_control ctl;

	memset(&ctl, 0, sizeof(ctl));
	dnet_empty_time(&ctl.io.timestamp);

	ctl.cflags = get_cflags();
	ctl.data = file.data();

	ctl.io.flags = get_ioflags();
	ctl.io.user_flags = get_user_flags();
	ctl.io.offset = remote_offset;
	ctl.io.size = file.size();

	memcpy(&ctl.id, &raw, sizeof(struct dnet_id));

	ctl.fd = -1;

	return write_data(ctl);
}

struct chunk_handler : public std::enable_shared_from_this<chunk_handler> {

	chunk_handler(const async_write_result::handler &handler, const session &sess,
				  const key &id, const data_pointer &content, const uint64_t &remote_offset, const uint64_t &local_offset, const uint64_t &chunk_size)
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
			auto awr = sess.write_commit(id, write_content, remote_offset + local_offset, remote_offset + content.size());
			awr.connect(std::bind(&chunk_handler::finish, shared_from_this(), std::placeholders::_1, std::placeholders::_2));
		} else {
			auto write_content = content.slice(local_offset, chunk_size);
			auto awr = sess.write_plain(id, write_content, remote_offset + local_offset);
			awr.connect(std::bind(&chunk_handler::write_next, shared_from_this(), std::placeholders::_1, std::placeholders::_2));
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

		std::list<async_write_result> write_results;

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
}; /* struct write_entry */

async_write_result session::write_cas(const key &id, const std::function<data_pointer (const data_pointer &)> &converter,
		uint64_t remote_offset, int count)
{
	transform(id);

	async_write_result result(*this);

	auto functor = std::make_shared<cas_functor>(*this, result, converter, id, remote_offset, count, mix_states(id));
	functor->next_iteration();

	return result;
}

async_write_result session::write_cas(const key &id, const data_pointer &file, const dnet_id &old_csum, uint64_t remote_offset)
{
	transform(id);
	dnet_id raw = id.id();

	struct dnet_io_control ctl;

	memset(&ctl, 0, sizeof(ctl));
	dnet_empty_time(&ctl.io.timestamp);

	ctl.cflags = get_cflags();
	ctl.data = file.data();

	ctl.io.flags = get_ioflags() | DNET_IO_FLAGS_COMPARE_AND_SWAP;
	ctl.io.user_flags = get_user_flags();
	ctl.io.offset = remote_offset;
	ctl.io.size = file.size();
	ctl.io.num = file.size() + remote_offset;

	memcpy(&ctl.id, &raw, sizeof(struct dnet_id));
	memcpy(&ctl.io.parent, &old_csum.id, DNET_ID_SIZE);

	ctl.fd = -1;

	return write_data(ctl);
}

async_write_result session::write_prepare(const key &id, const data_pointer &file, uint64_t remote_offset, uint64_t psize)
{
	transform(id);

	struct dnet_io_control ctl;

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

async_write_result session::write_plain(const key &id, const data_pointer &file, uint64_t remote_offset)
{
	transform(id);

	struct dnet_io_control ctl;

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

async_write_result session::write_commit(const key &id, const data_pointer &file, uint64_t remote_offset, uint64_t csize)
{
	transform(id);

	struct dnet_io_control ctl;

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

async_write_result session::write_cache(const key &id, const data_pointer &file, long timeout)
{
	transform(id);
	dnet_id raw = id.id();

	struct dnet_io_control ctl;

	memset(&ctl, 0, sizeof(ctl));
	dnet_empty_time(&ctl.io.timestamp);

	ctl.cflags = get_cflags();
	ctl.data = file.data();

	ctl.io.flags = get_ioflags() | DNET_IO_FLAGS_CACHE;
	ctl.io.user_flags = get_user_flags();
	ctl.io.start = timeout;
	ctl.io.size = file.size();

	memcpy(&ctl.id, &raw, sizeof(struct dnet_id));

	ctl.fd = -1;

	return write_data(ctl);
}

std::string session::lookup_address(const key &id, int group_id)
{
	char buf[128];

	int err = dnet_lookup_addr(m_data->session_ptr,
		id.by_id() ? NULL : id.remote().c_str(),
		id.by_id() ? 0 : id.remote().size(),
		id.by_id() ? const_cast<struct dnet_id*>(&id.id()) : NULL,
		group_id, buf, sizeof(buf));
	if (err < 0) {
		if (id.by_id()) {
			throw_error(err, id.id(), "Failed to lookup");
		} else {
			throw_error(err, "Failed to lookup in group %d: key size: %zu",
				group_id, id.remote().size());
		}
	}

	return std::string(buf, strlen(buf));
}

void session::transform(const std::string &data, struct dnet_id &id) const
{
	dnet_transform(m_data->session_ptr, (void *)data.data(), data.size(), &id);
	id.trace_id = m_data->trace_id;
	trace_id = m_data->trace_id;
}

void session::transform(const std::string &data, struct dnet_raw_id &id) const
{
	dnet_transform_raw(m_data->session_ptr, (void *)data.data(), data.size(), (char *)id.id, sizeof(id.id));
}

void session::transform(const data_pointer &data, dnet_id &id) const
{
	dnet_transform(m_data->session_ptr, data.data(), data.size(), &id);
	id.trace_id = m_data->trace_id;
	trace_id = m_data->trace_id;
}

void session::transform(const key &id) const
{
	const_cast<key&>(id).transform(*this);
}

async_lookup_result session::lookup(const key &id)
{
	transform(id);

	async_lookup_result result(*this);
	auto cb = createCallback<lookup_callback>(*this, result);
	cb->kid = id;

	mix_states(id, cb->groups);

	startCallback(cb);
	return result;
}

async_remove_result session::remove(const key &id)
{
	transform(id);

	async_remove_result result(*this);
	auto cb = createCallback<remove_callback>(*this, result, id.id());

	startCallback(cb);
	return result;
}

async_stat_result session::stat_log()
{
	async_stat_result result(*this);
	auto cb = createCallback<stat_callback>(*this, result);

	startCallback(cb);
	return result;
}

async_stat_result session::stat_log(const key &id)
{
	async_stat_result result(*this);
	transform(id);

	auto cb = createCallback<stat_callback>(*this, result);
	cb->id = id.id();
	cb->has_id = true;

	startCallback(cb);
	return result;
}

async_stat_count_result session::stat_log_count()
{
	async_stat_count_result result(*this);
	auto cb = createCallback<stat_count_callback>(*this, result);

	startCallback(cb);
	return result;
}

int session::state_num(void)
{
	return dnet_state_num(m_data->session_ptr);
}

async_generic_result session::request_cmd(const transport_control &ctl)
{
	async_generic_result result(*this);
	auto cb = createCallback<cmd_callback>(*this, result, ctl);

	startCallback(cb);
	return result;
}

void session::update_status(const char *saddr, const int port, const int family, struct dnet_node_status *status)
{
	int err;
	struct dnet_addr addr;

	memset(&addr, 0, sizeof(addr));
	addr.addr_len = sizeof(addr.addr);
	addr.family = family;

	err = dnet_fill_addr(&addr, saddr, port, SOCK_STREAM, IPPROTO_TCP);
	if (!err)
		err = dnet_update_status(m_data->session_ptr, &addr, NULL, status);

	if (err < 0) {
		throw_error(err, "%s:%d: failed to request set status %p", saddr, port, status);
	}
}

void session::update_status(const key &id, struct dnet_node_status *status)
{
	transform(id);
	dnet_id raw = id.id();

	int err;

	err = dnet_update_status(m_data->session_ptr, NULL, &raw, status);
	if (err < 0) {
		throw_error(err, id.id(), "failed to request set status %p", status);
	}
}

class read_data_range_callback
{
	public:
		struct scope
		{
			scope(const session &sess, const async_result_handler<read_result_entry> &handler)
				: sess(sess), handler(handler) {}

			session sess;
			struct dnet_io_attr io;
			struct dnet_id id;
			int group_id;
			unsigned int cmd;
			bool need_exit;

			bool has_any;
			dnet_io_attr rep;

			async_result_handler<read_result_entry> handler;
			std::function<void (const read_result_entry &)> me_entry;
			std::function<void (const error_info &)> me_final;
			struct dnet_raw_id start, next;
			struct dnet_raw_id end;
			uint64_t size;
			std::vector<read_result_entry> result;
			error_info last_exception;
		};

		std::shared_ptr<scope> data;

		read_data_range_callback(const session &sess,
			const struct dnet_io_attr &io, int group_id,
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

			logger log = d->sess.get_logger();

			if (log.get_log_level() > DNET_LOG_NOTICE) {
				int len = 6;
				char start_id[2*len + 1];
				char next_id[2*len + 1];
				char end_id[2*len + 1];
				char id_str[2*len + 1];

				dnet_log_raw(node, DNET_LOG_NOTICE, "id: %s, start: %s: next: %s, end: %s, size: %llu, cmp: %d\n",
						dnet_dump_id_len_raw(d->id.id, len, id_str),
						dnet_dump_id_len_raw(d->start.id, len, start_id),
						dnet_dump_id_len_raw(d->next.id, len, next_id),
						dnet_dump_id_len_raw(d->end.id, len, end_id),
						(unsigned long long)d->size, dnet_id_cmp_str(d->next.id, d->end.id));
			}

			memcpy(d->io.id, d->id.id, DNET_ID_SIZE);
			memcpy(d->io.parent, d->next.id, DNET_ID_SIZE);

			d->io.size = d->size;

			std::vector<int> groups(1, d->group_id);
			{
				session_scope scope(d->sess);
				d->sess.set_checker(checkers::no_check);
				d->sess.set_filter(filters::all_with_ack);
				d->sess.set_exceptions_policy(session::no_exceptions);

				d->sess.read_data(d->id, groups, d->io, d->cmd).connect(d->me_entry, d->me_final);
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
				struct dnet_io_attr *rep = &d->rep;

				dnet_log_raw(d->sess.get_native_node(),
					DNET_LOG_NOTICE, "%s: rep_num: %llu, io_start: %llu, io_num: %llu, io_size: %llu\n",
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
			const struct dnet_io_attr &io, int group_id,
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
					dnet_log_raw(d->sess.get_native_node(), DNET_LOG_NOTICE,
							"%s: rep_num: %llu, io_start: %llu, io_num: %llu, io_size: %llu\n",
							dnet_dump_id(&d->id), (unsigned long long)d->rep.num, (unsigned long long)d->io.start,
							(unsigned long long)d->io.num, (unsigned long long)d->io.size);
				} else {
					d->handler.complete(create_error(-ENOENT, d->io.id, "Failed to remove range data object: group: %d, size: %llu",
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

async_read_result session::read_data_range(const struct dnet_io_attr &io, int group_id)
{
	async_read_result result(*this);
	async_result_handler<read_result_entry> handler(result);
	error_info error;
	read_data_range_callback(*this, io, group_id, handler).do_next(&error);
	if (get_exceptions_policy() & throw_at_start)
		error.throw_error();
	return result;
}


std::vector<std::string> session::read_data_range_raw(dnet_io_attr &io, int group_id)
{
	sync_read_result range_result = read_data_range(io, group_id).get();
	std::vector<std::string> result;

	uint64_t num = 0;

	for (size_t i = 0; i < range_result.size(); ++i) {
		read_result_entry entry = range_result[i];
		if (!(io.flags & DNET_IO_FLAGS_NODATA))
			num += entry.io_attribute()->num;
		else
			result.push_back(entry.data().to_string());
	}

	if (io.flags & DNET_IO_FLAGS_NODATA) {
		std::ostringstream str;
		str << num;
		result.push_back(str.str());
	}

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

std::vector<std::pair<struct dnet_id, struct dnet_addr> > session::get_routes()
{
	std::vector<std::pair<struct dnet_id, struct dnet_addr> > res;
	struct dnet_id *ids = NULL;
	struct dnet_addr *addrs = NULL;

	int count = 0;

	count = dnet_get_routes(m_data->session_ptr, &ids, &addrs);

	if (count > 0) {
		for (int i = 0; i < count; ++i) {
			res.push_back(std::make_pair(ids[i], addrs[i]));
		}
	}

	if (ids)
		free(ids);

	if (addrs)
		free(addrs);

	return res;
}

async_exec_result session::request(dnet_id *id, const exec_context &context)
{
	async_exec_result result(*this);
	auto cb = createCallback<exec_callback>(*this, result);
	cb->id = id;
	cb->sph = context.m_data->sph.data<sph>();

	startCallback(cb);
	return result;
}

async_iterator_result session::iterator(const key &id, const data_pointer& request)
{
	transform(id);
	async_iterator_result result(*this);
	auto cb = createCallback<iterator_callback>(*this, result);
	cb->id = id.id();
	cb->request = request;

	startCallback(cb);
	return result;
}

void session::mix_states(const key &id, std::vector<int> &groups)
{
	transform(id);
	cstyle_scoped_pointer<int> groups_ptr;

	dnet_id raw = id.id();
	int num = dnet_mix_states(m_data->session_ptr, &raw, &groups_ptr.data());
	if (num < 0)
		throw_error(num, id, "could not fetch groups");
	groups.assign(groups_ptr.data(), groups_ptr.data() + num);
}
void session::mix_states(std::vector<int> &groups)
{
	cstyle_scoped_pointer<int> groups_ptr;

	int num = dnet_mix_states(m_data->session_ptr, NULL, &groups_ptr.data());
	if (num < 0)
		throw std::runtime_error("could not fetch groups: " + std::string(strerror(num)));

	groups.assign(groups_ptr.data(), groups_ptr.data() + num);
}

std::vector<int> session::mix_states(const key &id)
{
	std::vector<int> result;
	mix_states(id, result);
	return result;
}

std::vector<int> session::mix_states()
{
	std::vector<int> result;
	mix_states(result);
	return result;
}

async_iterator_result session::start_iterator(const key &id, const std::vector<dnet_iterator_range>& ranges,
								uint32_t type, uint64_t flags,
								const dnet_time& time_begin, const dnet_time& time_end)
{
	auto ranges_size = ranges.size() * sizeof(ranges.front());

	data_pointer data = data_pointer::allocate(sizeof(dnet_iterator_request) + ranges_size);

	auto req = data.data<dnet_iterator_request>();

	req->action = DNET_ITERATOR_ACTION_START;
	req->itype = type;
	req->flags = flags;
	req->time_begin = time_begin;
	req->time_end = time_end;
	req->range_num = ranges.size();

	memcpy(data.skip<dnet_iterator_request>().data(), &ranges.front(), ranges_size);

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

async_exec_result session::exec(dnet_id *id, const std::string &event, const data_pointer &data)
{
	return exec(id, -1, event, data);
}

async_exec_result session::exec(struct dnet_id *id, int src_key, const std::string &event, const data_pointer &data)
{
	exec_context context = exec_context_data::create(event, data);

	sph *s = context.m_data->sph.data<sph>();
	s->flags = DNET_SPH_FLAGS_SRC_BLOCK;
	s->src_key = src_key;

	if (id)
		memcpy(s->src.id, id->id, sizeof(s->src.id));

	return request(id, context);
}

async_exec_result session::exec(const exec_context &tmp_context, const std::string &event, const data_pointer &data)
{
	exec_context context = exec_context_data::copy(tmp_context, event, data);

	sph *s = context.m_data->sph.data<sph>();
	s->flags = DNET_SPH_FLAGS_SRC_BLOCK;

	struct dnet_id id;
	dnet_setup_id(&id, 0, s->src.id);

	return request(&id, context);
}

async_push_result session::push(dnet_id *id, const exec_context &tmp_context, const std::string &event, const data_pointer &data)
{
	exec_context context = exec_context_data::copy(tmp_context, event, data);

	sph *s = context.m_data->sph.data<sph>();
	s->flags &= ~DNET_SPH_FLAGS_SRC_BLOCK;
	s->flags &= ~(DNET_SPH_FLAGS_REPLY | DNET_SPH_FLAGS_FINISH);

	return request(id, context);
}

async_reply_result session::reply(const exec_context &tmp_context, const data_pointer &data, exec_context::final_state state)
{
	exec_context context = exec_context_data::copy(tmp_context, tmp_context.event(), data);

	sph *s = context.m_data->sph.data<sph>();

	s->flags |= DNET_SPH_FLAGS_REPLY;
	s->flags &= ~DNET_SPH_FLAGS_SRC_BLOCK;

	if (state == exec_context::final)
		s->flags |= DNET_SPH_FLAGS_FINISH;
	else
		s->flags &= ~DNET_SPH_FLAGS_FINISH;

	struct dnet_id id;
	dnet_setup_id(&id, 0, s->src.id);

	return request(&id, context);
}

void session::reply(const struct sph &sph, const std::string &event, const std::string &data, const std::string &)
{
	exec_context context = exec_context_data::copy(sph, event, data);
	reply(context, data, (sph.flags & DNET_SPH_FLAGS_FINISH) ? exec_context::final : exec_context::progressive).wait();
}

async_read_result session::bulk_read(const std::vector<struct dnet_io_attr> &ios_vector)
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
	io_attr_set ios(ios_vector.begin(), ios_vector.end());

	struct dnet_io_control control;
	memset(&control, 0, sizeof(control));

	control.fd = -1;

	control.cmd = DNET_CMD_BULK_READ;
	control.cflags = DNET_FLAGS_NEED_ACK | get_cflags();

	memset(&control.io, 0, sizeof(struct dnet_io_attr));
	control.io.flags = get_ioflags();

	dnet_raw_id tmp_id;
	memcpy(tmp_id.id, ios_vector[0].id, DNET_ID_SIZE);

	async_read_result result(*this);
	auto cb = createCallback<read_bulk_callback>(*this, result, ios, control);
	cb->groups = mix_states(key(tmp_id));

	startCallback(cb);
	return result;
}

namespace {
bool dnet_io_attr_compare(const struct dnet_io_attr &io1, const struct dnet_io_attr &io2) {
	int cmp;

	cmp = dnet_id_cmp_str(io1.id, io2.id);
	return cmp < 0;
}
}

async_read_result session::bulk_read(const std::vector<std::string> &keys)
{
	std::vector<struct dnet_io_attr> ios;
	struct dnet_io_attr io;
	memset(&io, 0, sizeof(io));

	io.flags = get_ioflags();

	ios.reserve(keys.size());

	for (size_t i = 0; i < keys.size(); ++i) {
		struct dnet_id id;

		transform(keys[i], id);
		memcpy(io.id, id.id, sizeof(io.id));
		ios.push_back(io);
	}

	return bulk_read(ios);
}

async_read_result session::bulk_read(const std::vector<key> &keys)
{
	std::vector<struct dnet_io_attr> ios;
	struct dnet_io_attr io;
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

async_write_result session::bulk_write(const std::vector<dnet_io_attr> &ios, const std::vector<data_pointer> &data)
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

	std::list<async_write_result> results;

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

async_write_result session::bulk_write(const std::vector<dnet_io_attr> &ios, const std::vector<std::string> &data)
{
	std::vector<data_pointer> pointer_data(data.begin(), data.end());
	return bulk_write(ios, pointer_data);
}

logger session::get_logger() const
{
	return m_data->logger;
}

ioremap::elliptics::node session::get_node() const
{
	if (auto node_guard = m_data->node_guard.lock())
		return node(node_guard);
	return node();
}

dnet_node *ioremap::elliptics::session::get_native_node() const
{
	return dnet_session_get_node(m_data->session_ptr);
}

dnet_session *session::get_native()
{
	return m_data->session_ptr;
}

} } // namespace ioremap::elliptics
