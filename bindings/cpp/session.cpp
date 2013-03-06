/*
 * 2008+ Copyright (c) Evgeniy Polyakov <zbr@ioremap.net>
 * 2012+ Copyright (c) Ruslan Nigmatullin <euroelessar@yandex.ru>
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

#include <elliptics/cppdef.h>
#include "callback_p.h"

#include <sstream>

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
	memcpy(&m_data.id, &id, sizeof(id));
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
		if (other)
			memcpy(p->sph.data<struct sph>(), other->m_data->sph.data<struct sph>(), sizeof(struct sph));
		else
			memset(raw_sph, 0, sizeof(struct sph));
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
	if (data.size() < sizeof(sph))
		throw_error(-EINVAL, "Invalid exec_context size: %zu", data.size());

	sph *s = data.data<sph>();
	if (data.size() != sizeof(sph) + s->event_size + s->data_size)
		throw_error(-EINVAL, "Invalid exec_context size: %zu", data.size());

	char *event = reinterpret_cast<char *>(s + 1);

	m_data = std::make_shared<exec_context_data>();
	m_data->sph = data;
	m_data->event.assign(event, event + s->event_size);
	m_data->data = data_pointer::from_raw(event + s->event_size, s->data_size);
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

std::string exec_context::event() const
{
	return m_data ? m_data->event : std::string();
}

data_pointer exec_context::data() const
{
	return m_data ? m_data->data : data_pointer();
}

class session_data
{
	public:
		session_data(const node &n) : node_guard(n), cflags(0), ioflags(0)
		{
			session_ptr = dnet_session_create(node_guard.get_native());
			if (!session_ptr)
				throw std::bad_alloc();
		}

		~session_data()
		{
			dnet_session_destroy(session_ptr);
		}



		struct dnet_session	*session_ptr;
		node			node_guard;

		std::vector<int>	groups;
		uint64_t		cflags;
		uint32_t		ioflags;
};

session::session(const node &n) : m_data(std::make_shared<session_data>(n))
{
}

session::session(const session &other) : m_data(other.m_data)
{
}

session::~session()
{
}

session &session::operator =(const session &other)
{
	m_data = other.m_data;
	return *this;
}

void session::set_groups(const std::vector<int> &groups)
{
	m_data->groups = groups;
	if (dnet_session_set_groups(m_data->session_ptr, &m_data->groups[0], groups.size()))
		throw std::bad_alloc();
}

const std::vector<int> &session::get_groups() const
{
	return m_data->groups;
}

void session::set_cflags(uint64_t cflags)
{
	m_data->cflags = cflags;
}

uint64_t session::get_cflags() const
{
	return m_data->cflags;
}

void session::set_ioflags(uint32_t ioflags)
{
	m_data->ioflags = ioflags;
}

uint32_t session::get_ioflags() const
{
	return m_data->ioflags;
}

void session::read_file(const key &id, const std::string &file, uint64_t offset, uint64_t size)
{
	int err;

	if (id.by_id()) {
		dnet_id raw = id.id();
		err = dnet_read_file_id(m_data->session_ptr, file.c_str(), &raw, offset, size);
	} else {
		err = dnet_read_file(m_data->session_ptr, file.c_str(), id.remote().c_str(), id.remote().size(), offset, size, id.type());
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
		err = dnet_write_file_id(m_data->session_ptr, file.c_str(), &raw, local_offset, offset, size, m_data->cflags, m_data->cflags);
	} else {
		err = dnet_write_file(m_data->session_ptr, file.c_str(), id.remote().c_str(), id.remote().size(),
							 local_offset, offset, size, m_data->cflags, m_data->cflags, id.type());
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

void session::read_data(const std::function<void (const read_results &)> &handler,
	const key &id, const std::vector<int> &groups, const dnet_io_attr &io)
{
	read_data(handler, id, groups, io, DNET_CMD_READ);
}

void session::read_data(const std::function<void (const read_results &)> &handler,
	const key &id, const std::vector<int> &groups, const dnet_io_attr &io, unsigned int cmd)
{
	transform(id);

	struct dnet_io_control control;
	memset(&control, 0, sizeof(control));

	control.fd = -1;
	control.cmd = cmd;
	control.cflags = DNET_FLAGS_NEED_ACK | m_data->cflags;

	memcpy(&control.io, &io, sizeof(struct dnet_io_attr));

	read_callback::ptr cb = std::make_shared<read_callback>(*this, control);
	cb->handler = handler;
	cb->kid = id;
	cb->groups = groups;

	startCallback(cb);
}

void session::read_data(const std::function<void (const read_results &)> &handler,
	const key &id, int group, const dnet_io_attr &io)
{
	const std::vector<int> groups(1, group);
	read_data(handler, id, groups, io);
}

struct results_to_result_proxy
{
	std::function<void (const read_result &)> handler;

	void operator() (const read_results &results)
	{
		if (results.exception() != std::exception_ptr()) {
			handler(results.exception());
		} else {
			handler(results[0]);
		}
	}
};

void session::read_data(const std::function<void (const read_result &)> &handler,
	const key &id, const std::vector<int> &groups, uint64_t offset, uint64_t size)
{
	transform(id);

	struct dnet_io_attr io;
	memset(&io, 0, sizeof(io));

	io.size   = size;
	io.offset = offset;
	io.flags  = m_data->ioflags;
	io.type   = id.type();

	memcpy(io.id, id.id().id, DNET_ID_SIZE);
	memcpy(io.parent, id.id().id, DNET_ID_SIZE);

	results_to_result_proxy proxy = { handler };

	read_data(proxy, id, groups, io);
}

void session::read_data(const std::function<void (const read_result &)> &handler,
	const key &id, uint64_t offset, uint64_t size)
{
	transform(id);

	read_data(handler, id, mix_states(), offset, size);
}

read_result session::read_data(const key &id, uint64_t offset, uint64_t size)
{
	waiter<read_result> w;
	read_data(w.handler(), id, offset, size);
	return w.result();
}

read_result session::read_data(const key &id, const std::vector<int> &groups, uint64_t offset, uint64_t size)
{
	waiter<read_result> w;
	read_data(w.handler(), id, groups, offset, size);
	return w.result();
}

read_result session::read_data(const key &id, int group_id, uint64_t offset, uint64_t size)
{
	std::vector<int> groups(1, group_id);
	return read_data(id, groups, offset, size);
}

void session::prepare_latest(const std::function<void (const prepare_latest_result &)> &handler,
	const key &id, const std::vector<int> &groups)
{
	if (groups.empty()) {
		handler(groups);
		return;
	}

	transform(id);

	prepare_latest_callback::ptr cb = std::make_shared<prepare_latest_callback>(*this, groups);
	cb->handler = handler;
	cb->id = id;
	cb->group_id = id.id().group_id;

	startCallback(cb);
}

void session::prepare_latest(const key &id, std::vector<int> &groups)
{
	waiter<prepare_latest_result> w;
	prepare_latest(w.handler(), id, groups);
	groups = w.result();
}

// It could be a lambda functor! :`(
struct read_latest_callback
{
	session sess;
	key id;
	uint64_t offset;
	uint64_t size;
	std::function<void (const read_result &)> handler;

	void operator() (const prepare_latest_result &result)
	{
		if (result.exception() != std::exception_ptr()) {
			handler(result.exception());
			return;
		}

		try {
			sess.read_data(handler, id, result, offset, size);
		} catch (...) {
			handler(std::current_exception());
		}
	}
};

void session::read_latest(const std::function<void (const read_result &)> &handler,
	const key &id, uint64_t offset, uint64_t size)
{
	read_latest_callback callback = { *this, id, offset, size, handler };
	prepare_latest(callback, id, mix_states());
}

read_result session::read_latest(const key &id, uint64_t offset, uint64_t size)
{
	waiter<read_result> w;
	read_latest(w.handler(), id, offset, size);
	return w.result();
}

void session::write_data(const std::function<void (const write_result &)> &handler, const dnet_io_control &ctl)
{
	write_callback::ptr cb = std::make_shared<write_callback>(*this, ctl);

	cb->ctl.cmd = DNET_CMD_WRITE;
	cb->ctl.cflags |= DNET_FLAGS_NEED_ACK;

	memcpy(cb->ctl.io.id, cb->ctl.id.id, DNET_ID_SIZE);

	cb->handler = handler;

	startCallback(cb);
}

void session::write_data(const std::function<void (const write_result &)> &handler,
	const key &id, const data_pointer &file, uint64_t remote_offset)
{
	transform(id);
	dnet_id raw = id.id();

	struct dnet_io_control ctl;

	memset(&ctl, 0, sizeof(ctl));

	ctl.cflags = m_data->cflags;
	ctl.data = file.data();

	ctl.io.flags = m_data->ioflags;
	ctl.io.offset = remote_offset;
	ctl.io.size = file.size();
	ctl.io.type = raw.type;
	ctl.io.num = file.size() + remote_offset;

	memcpy(&ctl.id, &raw, sizeof(struct dnet_id));

	ctl.fd = -1;

	write_data(handler, ctl);
}

write_result session::write_data(const key &id, const data_pointer &file, uint64_t remote_offset)
{
	waiter<write_result> w;
	write_data(w.handler(), id, file, remote_offset);
	return w.result();
}

struct cas_data
{
	typedef std::shared_ptr<cas_data> ptr;

	session sess;
	std::function<void (const write_result &)> handler;
	std::function<data_pointer (const data_pointer &)> converter;
	key id;
	uint64_t remote_offset;
	int index;
	int count;

	struct functor
	{
		ptr scope;

		void next_iteration()
		{
			scope->sess.read_latest(*this, scope->id, scope->remote_offset, 0);
		}

		void operator () (const read_result &result)
		{
			data_pointer data;
			try {
				data = result->file();
			} catch (error &e) {
				if (e.error_code() != -ENOENT) {
					scope->handler(std::exception_ptr());
					return;
				}
			} catch (...) {
				scope->handler(std::exception_ptr());
				return;
			}

			try {
				data_pointer write_data = scope->converter(data);

				if (write_data.size() == data.size()
					&& ((write_data.empty() && data.empty())
						|| write_data.data() == data.data())) {
					scope->handler(std::exception_ptr());
					return;
				}

				dnet_id csum;
				memset(&csum, 0, sizeof(csum));
				scope->sess.transform(data, csum);

				scope->sess.write_cas(*this, scope->id, write_data, csum, scope->remote_offset);
			} catch (...) {
				scope->handler(std::current_exception());
			}
		}

		void operator () (const write_result &result)
		{
			try {
				result.check();
				scope->handler(result);
			} catch (error &e) {
				if (e.error_code() == -EINVAL) {
					// mismatched checksum
					++scope->index;
					if (scope->index < scope->count)
						next_iteration();
				}
				scope->handler(std::current_exception());
				return;
			} catch (...) {
				scope->handler(std::current_exception());
				return;
			}
		}
	};
};

void session::write_cas(const std::function<void (const write_result &)> &handler, const key &id,
	const std::function<data_pointer (const data_pointer &)> &converter, uint64_t remote_offset, int count)
{
	cas_data scope = { *this, handler, converter, id, remote_offset, 0, count };
	cas_data::functor cas_handler = { std::make_shared<cas_data>(scope) };
	cas_handler.next_iteration();
}

write_result session::write_cas(const key &id, const std::function<data_pointer (const data_pointer &)> &converter,
	uint64_t remote_offset, int count)
{
	waiter<write_result> w;
	write_cas(w.handler(), id, converter, remote_offset, count);
	return w.result();
}

void session::write_cas(const std::function<void (const write_result &)> &handler,
	const key &id, const data_pointer &file, const dnet_id &old_csum, uint64_t remote_offset)
{
	transform(id);
	dnet_id raw = id.id();
	raw.type = id.type();

	struct dnet_io_control ctl;

	memset(&ctl, 0, sizeof(ctl));

	ctl.cflags = m_data->cflags;
	ctl.data = file.data();

	ctl.io.flags = m_data->ioflags | DNET_IO_FLAGS_COMPARE_AND_SWAP;
	ctl.io.offset = remote_offset;
	ctl.io.size = file.size();
	ctl.io.type = raw.type;
	ctl.io.num = file.size() + remote_offset;

	memcpy(&ctl.id, &raw, sizeof(struct dnet_id));
	memcpy(&ctl.io.parent, &old_csum.id, DNET_ID_SIZE);

	ctl.fd = -1;

	write_data(handler, ctl);
}

write_result session::write_cas(const key &id, const data_pointer &file, const dnet_id &old_csum, uint64_t remote_offset)
{
	waiter<write_result> w;
	write_cas(w.handler(), id, file, old_csum, remote_offset);
	return w.result();
}

void session::write_prepare(const std::function<void (const write_result &)> &handler,
	const key &id, const data_pointer &file, uint64_t remote_offset, uint64_t psize)
{
	transform(id);

	struct dnet_io_control ctl;

	memset(&ctl, 0, sizeof(ctl));

	ctl.cflags = m_data->cflags;
	ctl.data = file.data();

	ctl.io.flags = m_data->ioflags | DNET_IO_FLAGS_PREPARE | DNET_IO_FLAGS_PLAIN_WRITE;
	ctl.io.offset = remote_offset;
	ctl.io.size = file.size();
	ctl.io.type = id.id().type;
	ctl.io.num = psize;

	memcpy(&ctl.id, &id.id(), sizeof(ctl.id));

	ctl.fd = -1;

	write_data(handler, ctl);
}

write_result session::write_prepare(const key &id, const data_pointer &file, uint64_t remote_offset, uint64_t psize)
{
	waiter<write_result> w;
	write_prepare(w.handler(), id, file, remote_offset, psize);
	return w.result();
}

void session::write_plain(const std::function<void (const write_result &)> &handler,
	const key &id, const data_pointer &file, uint64_t remote_offset)
{
	transform(id);
	dnet_id raw = id.id();

	struct dnet_io_control ctl;

	memset(&ctl, 0, sizeof(ctl));

	ctl.cflags = m_data->cflags;
	ctl.data = file.data();

	ctl.io.flags = m_data->ioflags | DNET_IO_FLAGS_PLAIN_WRITE;
	ctl.io.offset = remote_offset;
	ctl.io.size = file.size();
	ctl.io.type = raw.type;

	memcpy(&ctl.id, &raw, sizeof(id));

	ctl.fd = -1;

	write_data(handler, ctl);
}

write_result session::write_plain(const key &id, const data_pointer &file, uint64_t remote_offset)
{
	waiter<write_result> w;
	write_plain(w.handler(), id, file, remote_offset);
	return w.result();
}

void session::write_commit(const std::function<void (const write_result &)> &handler,
	const key &id, const data_pointer &file, uint64_t remote_offset, uint64_t csize)
{
	transform(id);

	struct dnet_io_control ctl;

	memset(&ctl, 0, sizeof(ctl));

	ctl.cflags = m_data->cflags;
	ctl.data = file.data();

	ctl.io.flags = m_data->ioflags | DNET_IO_FLAGS_COMMIT | DNET_IO_FLAGS_PLAIN_WRITE;
	ctl.io.offset = remote_offset;
	ctl.io.size = file.size();
	ctl.io.type = id.id().type;
	ctl.io.num = csize;

	memcpy(&ctl.id, &id.id(), sizeof(ctl.id));

	ctl.fd = -1;

	write_data(handler, ctl);
}

write_result session::write_commit(const key &id, const data_pointer &file, uint64_t remote_offset, uint64_t csize)
{
	waiter<write_result> w;
	write_commit(w.handler(), id, file, remote_offset, csize);
	return w.result();
}

void session::write_cache(const std::function<void (const write_result &)> &handler,
	const key &id, const data_pointer &file, long timeout)
{
	transform(id);
	dnet_id raw = id.id();
	raw.type = id.type();

	struct dnet_io_control ctl;

	memset(&ctl, 0, sizeof(ctl));

	ctl.cflags = m_data->cflags;
	ctl.data = file.data();

	ctl.io.flags = m_data->ioflags | DNET_IO_FLAGS_CACHE;
	ctl.io.start = timeout;
	ctl.io.size = file.size();
	ctl.io.type = raw.type;
	ctl.io.num = file.size();

	memcpy(&ctl.id, &raw, sizeof(struct dnet_id));

	ctl.fd = -1;

	write_data(handler, ctl);
}

write_result session::write_cache(const key &id, const data_pointer &file, long timeout)
{
	waiter<write_result> w;
	write_cache(w.handler(), id, file, timeout);
	return w.result();
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

std::string session::create_metadata(const key &id, const std::string &obj,
					    const std::vector<int> &groups, const struct timespec &ts)
{
	transform(id);

	struct dnet_metadata_control ctl;
	struct dnet_meta_container mc;
	int err;

	memset(&mc, 0, sizeof(struct dnet_meta_container));
	memset(&ctl, 0, sizeof(struct dnet_metadata_control));

	ctl.obj = (char *)obj.data();
	ctl.len = obj.size();

	ctl.groups = (int *)&groups[0];
	ctl.group_num = groups.size();

	ctl.ts = ts;
	ctl.id = id.id();

	err = dnet_create_metadata(m_data->session_ptr, &ctl, &mc);
	if (err) {
		throw_error(err, id.id(), "Failed to create metadata");
	}

	std::string ret;

	try {
		ret.assign((char *)mc.data, mc.size);
	} catch (...) {
		free(mc.data);
		throw;
	}

	free(mc.data);
	return ret;
}

int session::write_metadata(const key &id, const std::string &obj,
				   const std::vector<int> &groups, const struct timespec &ts)
{
	transform(id);

	int err;
	std::string meta;
	struct dnet_meta_container mc;

	if (dnet_flags(m_data->node_guard.get_native()) & DNET_CFG_NO_META)
		return 0;

	meta = create_metadata(id, obj, groups, ts);

	mc.data = (void *)meta.data();
	mc.size = meta.size();

	mc.id = id.id();

	err = dnet_write_metadata(m_data->session_ptr, &mc, 1, m_data->cflags);
	if (err) {
		throw_error(err, id.id(), "Failed to write metadata");
	}

	return 0;
}

void session::transform(const std::string &data, struct dnet_id &id)
{
	dnet_transform(m_data->node_guard.get_native(), (void *)data.data(), data.size(), &id);
}

void session::transform(const data_pointer &data, dnet_id &id)
{
	dnet_transform(m_data->node_guard.get_native(), data.data(), data.size(), &id);
}

void session::transform(const key &id)
{
	const_cast<key&>(id).transform(*this);
}

void session::lookup(const std::function<void (const lookup_result &)> &handler, const key &id)
{
	transform(id);

	lookup_callback::ptr cb = std::make_shared<lookup_callback>(*this);
	cb->handler = handler;
	cb->kid = id;

	mix_states(id, cb->groups);

	startCallback(cb);
}

lookup_result session::lookup(const key &id)
{
	waiter<lookup_result> w;
	lookup(w.handler(), id);
	return w.result();
}

void session::remove_raw(const key &id)
{
	remove(id);
}

void session::remove(const std::function<void (const std::exception_ptr &)> &handler, const key &id)
{
	transform(id);

	remove_callback::ptr cb = std::make_shared<remove_callback>(*this, id.id());
	cb->handler = handler;

	startCallback(cb);
}

void session::remove(const key &id)
{
	waiter<std::exception_ptr> w;
	remove(w.handler(), id);
	w.result();
}

void session::stat_log(const std::function<void (const stat_result &)> &handler)
{
	stat_callback::ptr cb = std::make_shared<stat_callback>(*this);
	cb->handler = handler;

	startCallback(cb);
}

void session::stat_log(const std::function<void (const stat_result &)> &handler, const key &id)
{
	transform(id);

	stat_callback::ptr cb = std::make_shared<stat_callback>(*this);
	cb->handler = handler;
	cb->id = id.id();
	cb->has_id = true;

	startCallback(cb);
}

stat_result session::stat_log()
{
	waiter<stat_result> w;
	stat_log(w.handler());
	return w.result();
}

stat_result session::stat_log(const key &id)
{
	waiter<stat_result> w;
	stat_log(w.handler(), id);
	return w.result();
}

void session::stat_log_count(const std::function<void (const stat_count_result &)> &handler)
{
	stat_count_callback::ptr cb = std::make_shared<stat_count_callback>(*this);
	cb->handler = handler;

	startCallback(cb);
}

stat_count_result session::stat_log_count()
{
	waiter<stat_count_result> w;
	stat_log_count(w.handler());
	return w.result();
}

int session::state_num(void)
{
	return dnet_state_num(m_data->session_ptr);
}

void session::request_cmd(const std::function<void (const command_result &)> &handler, const transport_control &ctl)
{
	cmd_callback::ptr cb = std::make_shared<cmd_callback>(*this, ctl);
	cb->handler = handler;

	startCallback(cb);
}
command_result session::request_cmd(const transport_control &ctl)
{
	waiter<command_result> w;
	request_cmd(w.handler(), ctl);
	return w.result();
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
			scope(const session &sess) : sess(sess) {}

			session sess;
			struct dnet_io_attr io;
			struct dnet_id id;
			int group_id;
			unsigned int cmd;
			bool need_exit;
			std::function<void (const read_range_result &)> handler;
			std::function<void (const read_results &)> me;
			struct dnet_raw_id start, next;
			struct dnet_raw_id end;
			uint64_t size;
			std::vector<read_result_entry> result;
			std::exception_ptr last_exception;
		};

		std::shared_ptr<scope> data;

		read_data_range_callback(const session &sess,
			const struct dnet_io_attr &io, int group_id,
			const std::function<void (const read_range_result &)> &handler)
			: data(std::make_shared<scope>(sess))
		{
			scope *d = data.get();

			d->io = io;
			d->group_id = group_id;
			d->need_exit = false;
			d->handler = handler;
			d->me = *this;
			d->cmd = DNET_CMD_READ_RANGE;
			d->size = io.size;

			memcpy(d->end.id, d->io.parent, DNET_ID_SIZE);

			dnet_setup_id(&d->id, d->group_id, d->io.id);
			d->id.type = d->io.type;
		}


		void do_next()
		{
			scope *d = data.get();
			struct dnet_node * const node = d->sess.get_node().get_native();
			try {
				if (d->need_exit) {
					if (d->result.empty())
						d->handler(d->last_exception);
					else
						d->handler(d->result);
					return;
				}
				int err = dnet_search_range(node, &d->id, &d->start, &d->next);
				if (err) {
					throw_error(err, d->io.id, "Failed to read range data object: group: %d, size: %llu",
						d->group_id, static_cast<unsigned long long>(d->io.size));
				}

				if ((dnet_id_cmp_str(d->id.id, d->next.id) > 0) ||
						!memcmp(d->start.id, d->next.id, DNET_ID_SIZE) ||
						(dnet_id_cmp_str(d->next.id, d->end.id) > 0)) {
					memcpy(d->next.id, d->end.id, DNET_ID_SIZE);
					d->need_exit = true;
				}

				logger log = d->sess.get_node().get_log();

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
				d->sess.read_data(d->me, d->id, groups, d->io, d->cmd);
			} catch (...) {
				std::exception_ptr exc = std::current_exception();
				d->handler(exc);
			}
		}

		void operator () (const read_results &result)
		{
			scope *d = data.get();

			if (result.exception() != std::exception_ptr()) {
				d->last_exception = result.exception();
			} else {
				size_t size = result.size();

				/* If DNET_IO_FLAGS_NODATA is set do not decrement size as 'rep' is the only structure in output */
				if (!(d->io.flags & DNET_IO_FLAGS_NODATA))
					--size;

				read_result_entry last_entry = result[result.size() - 1];
				struct dnet_io_attr *rep = last_entry.io_attribute();

				dnet_log_raw(d->sess.get_node().get_native(),
					DNET_LOG_NOTICE, "%s: rep_num: %llu, io_start: %llu, io_num: %llu, io_size: %llu\n",
					dnet_dump_id(&d->id), (unsigned long long)rep->num, (unsigned long long)d->io.start,
					(unsigned long long)d->io.num, (unsigned long long)d->io.size);

				if (d->io.start < rep->num) {
					rep->num -= d->io.start;
					d->io.start = 0;
					d->io.num -= rep->num;

					for (size_t i = 0; i < size; ++i)
						d->result.push_back(result[i]);

					d->last_exception = std::exception_ptr();

					if (!d->io.num) {
						d->handler(d->result);
						return;
					}
				} else {
					d->io.start -= rep->num;
				}
			}

			memcpy(d->id.id, d->next.id, DNET_ID_SIZE);

			do_next();
		}
};

class remove_data_range_callback : public read_data_range_callback
{
	public:
		remove_data_range_callback(const session &sess,
			const struct dnet_io_attr &io, int group_id,
			const std::function<void (const read_range_result &)> &handler)
		: read_data_range_callback(sess, io, group_id, handler)
		{
			scope *d = data.get();

			d->cmd = DNET_CMD_DEL_RANGE;
			d->me = *this;
		}

		void operator () (const read_results &result)
		{
			scope *d = data.get();

			if (result.exception() != std::exception_ptr()) {
				d->last_exception = result.exception();
			} else if (result.size() > 0){
				struct dnet_io_attr *rep = result[0].io_attribute();

				dnet_log_raw(d->sess.get_node().get_native(), DNET_LOG_NOTICE,
						"%s: rep_num: %llu, io_start: %llu, io_num: %llu, io_size: %llu\n",
						dnet_dump_id(&d->id), (unsigned long long)rep->num, (unsigned long long)d->io.start,
						(unsigned long long)d->io.num, (unsigned long long)d->io.size);

				d->result.push_back(result[0]);
			} else {
				try {
					throw_error(-ENOENT, d->io.id, "Failed to remove range data object: group: %d, size: %llu",
						d->group_id, static_cast<unsigned long long>(d->io.size));
				} catch (...) {
					d->last_exception = std::current_exception();
				}
				d->handler(d->last_exception);
				return;
			}

			memcpy(d->id.id, d->next.id, DNET_ID_SIZE);

			do_next();
		}
};

void session::read_data_range(const std::function<void (const read_range_result &)> &handler,
	const struct dnet_io_attr &io, int group_id)
{
	read_data_range_callback(*this, io, group_id, handler).do_next();
}

read_range_result session::read_data_range(struct dnet_io_attr &io, int group_id)
{
	waiter<read_range_result> w;
	read_data_range(w.handler(), io, group_id);
	return w.result();
}

std::vector<std::string> session::read_data_range_raw(dnet_io_attr &io, int group_id)
{
	read_range_result range_result = read_data_range(io, group_id);
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

void session::remove_data_range(const std::function<void (const remove_range_result &)> &handler, dnet_io_attr &io, int group_id)
{
	remove_data_range_callback(*this, io, group_id, handler).do_next();
}

remove_range_result session::remove_data_range(struct dnet_io_attr &io, int group_id)
{
	waiter<remove_range_result> w;
	remove_data_range(w.handler(), io, group_id);
	return w.result();
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

void session::request(const std::function<void (const exec_result &)> &handler,
		dnet_id *id, const exec_context &context)
{
	exec_callback::ptr cb = std::make_shared<exec_callback>(*this);
	cb->id = id;
	cb->sph = context.m_data->sph.data<sph>();
	cb->handler = handler;

	startCallback(cb);
}

void session::mix_states(const key &id, std::vector<int> &groups)
{
	transform(id);
	cstyle_scoped_pointer<int> groups_ptr;

	if (id.by_id()) {
		groups.push_back(id.id().group_id);
	} else {
		dnet_id raw = id.id();
		int num = dnet_mix_states(m_data->session_ptr, &raw, &groups_ptr.data());
		if (num < 0)
			throw_error(num, "could not fetch groups");
		groups.assign(groups_ptr.data(), groups_ptr.data() + num);
	}
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

void session::exec(const std::function<void (const exec_result &)> &handler, dnet_id *id, const std::string &event, const data_pointer &data)
{
	exec_context context = exec_context_data::create(event, data);

	sph *s = context.m_data->sph.data<sph>();
	s->flags = DNET_SPH_FLAGS_SRC_BLOCK;

	if (id)
		memcpy(s->src.id, id->id, sizeof(s->src.id));

	request(handler, id, context);
}

exec_result session::exec(dnet_id *id, const std::string &event, const data_pointer &data)
{
	waiter<exec_result> w;
	exec(w.handler(), id, event, data);
	return w.result();
}

struct push_converter
{
	std::function<void (const push_result &)> handler;

	void operator() (const exec_result &result) const
	{
		handler(result.exception());
	}
};

void session::push(const std::function<void (const push_result &)> &handler, dnet_id *id, const exec_context &tmp_context, const std::string &event, const data_pointer &data)
{
	exec_context context = exec_context_data::copy(tmp_context, event, data);

	sph *s = context.m_data->sph.data<sph>();
	s->flags &= ~DNET_SPH_FLAGS_SRC_BLOCK;

	push_converter functor = { handler };
	request(functor, id, context);
}

void session::push(dnet_id *id, const exec_context &context, const std::string &event, const data_pointer &data)
{
	waiter<push_result> w;
	push(w.handler(), id, context, event, data);
	w.result();
}

void session::reply(const std::function<void (const reply_result &)> &handler, const exec_context &tmp_context, const data_pointer &data, exec_context::final_state state)
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
	id.type = 0;

	push_converter functor = { handler };
	request(functor, &id, context);
}

void session::reply(const exec_context &context, const data_pointer &data, exec_context::final_state state)
{
	waiter<reply_result> w;
	reply(w.handler(), context, data, state);
	w.result();
}

std::string session::exec_locked(struct dnet_id *id, const std::string &event, const std::string &data, const std::string &)
{
	std::string result;
	std::vector<exec_context> results = exec(id, event, data);
	for (size_t i = 0; i < results.size(); ++i)
		result += results[i].data().to_string();
	return result;
}

std::string session::exec_unlocked(struct dnet_id *id, const std::string &event, const std::string &data, const std::string &binary)
{
	uint64_t cflags = get_cflags();
	set_cflags(cflags | DNET_FLAGS_NOLOCK);
	std::string result = exec_locked(id, event, data, binary);
	set_cflags(cflags);
	return result;
}

std::string session::push_locked(struct dnet_id *id, const struct sph &sph, const std::string &event,
					const std::string &data, const std::string &)
{
	exec_context context = exec_context_data::copy(sph, event, data);
	push(id, context, event, data);
	return std::string();
}

std::string session::push_unlocked(struct dnet_id *id, const struct sph &sph, const std::string &event,
					  const std::string &data, const std::string &binary)
{
	uint64_t cflags = get_cflags();
	set_cflags(cflags | DNET_FLAGS_NOLOCK);
	push_locked(id, sph, event, data, binary);
	set_cflags(cflags);
	return std::string();
}

void session::reply(const struct sph &sph, const std::string &event, const std::string &data, const std::string &)
{
	exec_context context = exec_context_data::copy(sph, event, data);
	reply(context, data, (sph.flags & DNET_SPH_FLAGS_FINISH) ? exec_context::final : exec_context::progressive);
}

void session::bulk_read(const std::function<void (const bulk_read_result &)> &handler, const std::vector<struct dnet_io_attr> &ios_vector)
{
	io_attr_set ios(ios_vector.begin(), ios_vector.end());

	struct dnet_io_control control;
	memset(&control, 0, sizeof(control));

	control.fd = -1;

	control.cmd = DNET_CMD_BULK_READ;
	control.cflags = DNET_FLAGS_NEED_ACK | m_data->cflags;

	memset(&control.io, 0, sizeof(struct dnet_io_attr));

	read_bulk_callback::ptr cb = std::make_shared<read_bulk_callback>(*this, ios, control);
	cb->handler = handler;
	cb->groups = mix_states();

	startCallback(cb);
}

namespace {
bool dnet_io_attr_compare(const struct dnet_io_attr &io1, const struct dnet_io_attr &io2) {
	int cmp;

	cmp = dnet_id_cmp_str(io1.id, io2.id);
	return cmp < 0;
}
}

bulk_read_result session::bulk_read(const std::vector<struct dnet_io_attr> &ios)
{
	waiter<bulk_read_result> w;
	bulk_read(w.handler(), ios);
	return w.result();
}

bulk_read_result session::bulk_read(const std::vector<std::string> &keys)
{
	std::vector<struct dnet_io_attr> ios;
	struct dnet_io_attr io;
	memset(&io, 0, sizeof(io));

	ios.reserve(keys.size());

	for (size_t i = 0; i < keys.size(); ++i) {
		struct dnet_id id;

		transform(keys[i], id);
		memcpy(io.id, id.id, sizeof(io.id));
		ios.push_back(io);
	}

	return bulk_read(ios);
}

class bulk_write_callback
{
	public:
		class scope
		{
			public:
				int condition;
				int count;
				std::mutex mutex;
				std::vector<write_result_entry> entries;
				std::exception_ptr exc;
				std::function<void (const write_result &)> handler;
		};

		std::shared_ptr<scope> d;

		bulk_write_callback(const std::function<void (const write_result &)> &handler, int count)
		{
			d = std::make_shared<scope>();
			d->handler = handler;
			d->condition = count;
			d->count = 0;
		}

		void operator() (const write_result &result)
		{
			std::lock_guard<std::mutex> lock(d->mutex);
			++d->count;

			if (result.exception() != std::exception_ptr()) {
				d->exc = result.exception();
			} else {
				for (size_t i = 0; i < result.size(); ++i)
					d->entries.push_back(result[i]);
			}

			if (d->condition == d->count) {
				if (d->entries.empty())
					d->handler(d->exc);
				else
					d->handler(d->entries);
			}
		}
};

void session::bulk_write(const std::function<void (const write_result &)> &handler,
	const std::vector<struct dnet_io_attr> &ios,
	const std::vector<std::string> &data)
{
	if (ios.size() != data.size()) {
		throw_error(-EIO, "BULK_WRITE: ios doesn't meet data: io.size: %zd, data.size: %zd",
			ios.size(), data.size());
	}

	std::function<void (const write_result &)> callback
		= bulk_write_callback(handler, ios.size());

	for(size_t i = 0; i < ios.size(); ++i) {
		struct dnet_io_control ctl;
		memset(&ctl, 0, sizeof(ctl));

		ctl.cflags = m_data->cflags;
		ctl.data = data[i].data();

		ctl.io = ios[i];

		dnet_setup_id(&ctl.id, 0, (unsigned char *)ios[i].id);
		ctl.id.type = ios[i].type;

		ctl.fd = -1;

		write_data(callback, ctl);
	}
}

write_result session::bulk_write(const std::vector<struct dnet_io_attr> &ios, const std::vector<std::string> &data)
{
	waiter<write_result> w;
	bulk_write(w.handler(), ios, data);
	return w.result();
}

node &session::get_node()
{
	return m_data->node_guard;
}

const node &session::get_node() const
{
	return m_data->node_guard;
}

dnet_session *session::get_native()
{
	return m_data->session_ptr;
}

} } // namespace ioremap::elliptics
