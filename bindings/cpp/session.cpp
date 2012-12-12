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

#include <boost/make_shared.hpp>

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

session::session(const node &n) : m_data(boost::make_shared<session_data>(n))
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

std::string session::read_data_wait(const key &id, uint64_t offset, uint64_t size)
{
	struct dnet_io_attr io;
	int err;

	transform(id);
	dnet_id raw = id.id();
	raw.type = id.type();

	memset(&io, 0, sizeof(io));
	io.size = size;
	io.offset = offset;
	io.flags = m_data->ioflags;
	io.type = raw.type;

	memcpy(io.id, raw.id, DNET_ID_SIZE);
	memcpy(io.parent, raw.id, DNET_ID_SIZE);

	void *data = dnet_read_data_wait(m_data->session_ptr, &raw, &io, m_data->cflags, &err);
	if (!data) {
		throw_error(err, raw, "READ: size: %llu",
			static_cast<unsigned long long>(size));
	}

	std::string ret = std::string((const char *)data + sizeof(struct dnet_io_attr), io.size - sizeof(struct dnet_io_attr));
	free(data);

	return ret;
}

void session::prepare_latest(const key &id, std::vector<int> &groups)
{
	if (groups.empty()) {
		return;
	}

	transform(id);

	struct dnet_read_latest_prepare pr;
	int err;

	memset(&pr, 0, sizeof(struct dnet_read_latest_prepare));

	pr.s = m_data->session_ptr;
	pr.id = id.id();
	pr.cflags = m_data->cflags;
	pr.group = &groups[0];
	pr.group_num = groups.size();

	err = dnet_read_latest_prepare(&pr);
	groups.resize(pr.group_num);

	if (!groups.size())
		err = -ENOENT;

	if (err) {
		transform(id);
		throw_error(err, id.id(), "prepare_latest: groups: %zu", groups.size());
	}
}

std::string session::read_latest(const key &id, uint64_t offset, uint64_t size)
{
	transform(id);
	dnet_id raw = id.id();
	raw.type = id.type();

	struct dnet_io_attr io;
	void *data;
	int err;

	memset(&io, 0, sizeof(io));
	io.size = size;
	io.offset = offset;
	io.flags = m_data->ioflags;
	io.type = raw.type;
	io.num = m_data->groups.size();

	memcpy(io.id, raw.id, DNET_ID_SIZE);
	memcpy(io.parent, raw.id, DNET_ID_SIZE);

	err = dnet_read_latest(m_data->session_ptr, &raw, &io, m_data->cflags, &data);
	if (err < 0) {
		throw_error(err, raw, "READ: size: %llu", static_cast<unsigned long long>(size));
	}

	std::string ret = std::string((const char *)data + sizeof(struct dnet_io_attr),
					io.size - sizeof(struct dnet_io_attr));
	free(data);

	return ret;
}

std::string session::write_cache(const key &id, const std::string &str, long timeout)
{
	transform(id);
	dnet_id raw = id.id();
	raw.type = id.type();

	struct dnet_io_control ctl;

	memset(&ctl, 0, sizeof(ctl));

	ctl.cflags = m_data->cflags;
	ctl.data = str.data();

	ctl.io.flags = m_data->ioflags | DNET_IO_FLAGS_CACHE;
	ctl.io.start = timeout;
	ctl.io.size = str.size();
	ctl.io.type = raw.type;
	ctl.io.num = str.size();

	memcpy(&ctl.id, &raw, sizeof(struct dnet_id));

	ctl.fd = -1;

	char *result = NULL;
	int err = dnet_write_data_wait(m_data->session_ptr, &ctl, reinterpret_cast<void**>(&result));
	if (err < 0) {
		throw_error(err, raw, "WRITE: size: %zu", str.size());
	}

	std::string ret((const char *)result, err);
	free(result);

	return ret;
}

std::string session::write_cas(const key &id, const std::string &str, const dnet_id &old_csum, uint64_t remote_offset)
{
	transform(id);
	dnet_id raw = id.id();
	raw.type = id.type();

	struct dnet_io_control ctl;

	memset(&ctl, 0, sizeof(ctl));

	ctl.cflags = m_data->cflags;
	ctl.data = str.data();

	ctl.io.flags = m_data->ioflags | DNET_IO_FLAGS_COMPARE_AND_SWAP;
	ctl.io.offset = remote_offset;
	ctl.io.size = str.size();
	ctl.io.type = raw.type;
	ctl.io.num = str.size() + remote_offset;

	memcpy(&ctl.id, &raw, sizeof(struct dnet_id));
	memcpy(&ctl.io.parent, &old_csum.id, DNET_ID_SIZE);

	ctl.fd = -1;

	char *result = NULL;
	int err = dnet_write_data_wait(m_data->session_ptr, &ctl, reinterpret_cast<void**>(&result));
	if (err < 0) {
		throw_error(err, raw, "WRITE: size: %zu", str.size());
	}

	std::string ret((const char *)result, err);
	free(result);

	return ret;
}

std::string session::write_data_wait(const key &id, const std::string &str,
					    uint64_t remote_offset)
{
	transform(id);
	dnet_id raw = id.id();

	struct dnet_io_control ctl;

	memset(&ctl, 0, sizeof(ctl));

	ctl.cflags = m_data->cflags;
	ctl.data = str.data();

	ctl.io.flags = m_data->ioflags;
	ctl.io.offset = remote_offset;
	ctl.io.size = str.size();
	ctl.io.type = raw.type;
	ctl.io.num = str.size() + remote_offset;

	memcpy(&ctl.id, &raw, sizeof(struct dnet_id));

	ctl.fd = -1;

	char *result = NULL;
	int err = dnet_write_data_wait(m_data->session_ptr, &ctl, reinterpret_cast<void**>(&result));
	if (err < 0) {
		throw_error(err, raw, "WRITE: size: %zu", str.size());
	}

	std::string ret((const char *)result, err);
	free(result);

	return ret;
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

void session::transform(const key &id)
{
	const_cast<key&>(id).transform(*this);
}

void session::lookup(const key &id, const boost::function<void (const lookup_result &)> &handler)
{
	transform(id);
	cstyle_scoped_pointer<int> groups_ptr;

	lookup_callback::ptr cb = boost::make_shared<lookup_callback>(*this);
	cb->handler = handler;
	cb->kid = id;

	if (id.by_id()) {
		cb->groups.push_back(cb->id.group_id);
	} else {
		int num = dnet_mix_states(m_data->session_ptr, &cb->id, &groups_ptr.data());
		if (num < 0)
			throw std::bad_alloc();
		cb->groups.assign(groups_ptr.data(), groups_ptr.data() + num);
	}

	dnet_style_handler<lookup_callback>::start(cb);
}

lookup_result session::lookup(const key &id)
{
	waiter<lookup_result> w;
	lookup(id, w.handler());
	return w.result();
}

void session::remove_raw(const key &id)
{
	transform(id);
	dnet_id raw = id.id();

	int err = -ENOENT;
	std::vector<int> g = m_data->groups;

	for (int i=0; i<(int)g.size(); ++i) {
		raw.group_id = g[i];

		if (!dnet_remove_object_now(m_data->session_ptr, &raw, m_data->cflags, m_data->ioflags))
			err = 0;
	}

	if (err) {
		throw_error(err, id.id(), "REMOVE");
	}
}

void session::remove(const key &id)
{
	uint32_t ioflags = m_data->ioflags;
	m_data->ioflags = 0;
	remove_raw(id);
	m_data->ioflags = ioflags;
}

void session::stat_log(const boost::function<void (const std::vector<stat_result> &)> &handler)
{
	stat_callback::ptr cb = boost::make_shared<stat_callback>(*this);
	cb->handler = handler;

	dnet_style_handler<stat_callback>::start(cb);

	callback_any c;
	int err = dnet_request_stat(m_data->session_ptr, NULL, DNET_CMD_STAT, 0,
				callback::handler, &c);
	if (err < 0) {
		throw_error(err, "Failed to request statistics");
	}
}

std::string session::stat_log()
{
	callback_any c;
	std::string ret;
	int err;

	err = dnet_request_stat(m_data->session_ptr, NULL, DNET_CMD_STAT, 0,
				callback::handler, &c);
	if (err < 0) {
		throw_error(err, "Failed to request statistics");
	}

	c.wait(err);
	ret = c.any_result().raw_data();

	/* example reply parsing */
#if 0
	float la[3];
	const void *data = ret.data();
	int size = ret.size();
	char id_str[DNET_ID_SIZE*2 + 1];
	char addr_str[128];

	while (size) {
		struct dnet_addr *addr = (struct dnet_addr *)data;
		struct dnet_cmd *cmd = (struct dnet_cmd *)(addr + 1);
		struct dnet_stat *st = (struct dnet_stat *)(cmd + 1);

		dnet_convert_stat(st);

		la[0] = (float)st->la[0] / 100.0;
		la[1] = (float)st->la[1] / 100.0;
		la[2] = (float)st->la[2] / 100.0;

		printf(	"<stat addr=\"%s\" id=\"%s\"><la>%.2f %.2f %.2f</la>"
			"<memtotal>%llu KB</memtotal><memfree>%llu KB</memfree><memcached>%llu KB</memcached>"
			"<storage_size>%llu MB</storage_size><available_size>%llu MB</available_size>"
			"<files>%llu</files><fsid>0x%llx</fsid></stat>",
			dnet_server_convert_dnet_addr_raw(addr, addr_str, sizeof(addr_str)),
			dnet_dump_id_len_raw(cmd->id.id, DNET_ID_SIZE, id_str),
			la[0], la[1], la[2],
			(unsigned long long)st->vm_total,
			(unsigned long long)st->vm_free,
			(unsigned long long)st->vm_cached,
			(unsigned long long)(st->frsize * st->blocks / 1024 / 1024),
			(unsigned long long)(st->bavail * st->bsize / 1024 / 1024),
			(unsigned long long)st->files, (unsigned long long)st->fsid);
		printf("\n");

		int sz = sizeof(*addr) + sizeof(*cmd) + cmd->size;

		size -= sz;
		data += sz;
	}
#endif

	if (ret.size() < sizeof(struct dnet_addr) + sizeof(struct dnet_cmd) + sizeof(struct dnet_stat))
		throw_error(-ENOENT, "Failed to request statistics: not enough data returned");
	return ret;
}

int session::state_num(void)
{
	return dnet_state_num(m_data->session_ptr);
}

int session::request_cmd(struct dnet_trans_control &ctl)
{
	int err;

	err = dnet_request_cmd(m_data->session_ptr, &ctl);
	if (err < 0) {
		throw_error(err, "failed to request cmd: %s", dnet_cmd_string(ctl.cmd));
	}

	return err;
}

void session::update_status(const char *saddr, const int port, const int family, struct dnet_node_status *status)
{
	int err;
	struct dnet_addr addr;
	char sport[16];

	memset(&addr, 0, sizeof(addr));
	addr.addr_len = sizeof(addr.addr);

	snprintf(sport, sizeof(sport), "%d", port);

	err = dnet_fill_addr(&addr, saddr, sport, family, SOCK_STREAM, IPPROTO_TCP);
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

struct range_sort_compare {
		bool operator () (const std::string &s1, const std::string &s2) {
			unsigned char *id1 = (unsigned char *)s1.data();
			unsigned char *id2 = (unsigned char *)s2.data();

			int cmp = dnet_id_cmp_str(id1, id2);

			return cmp < 0;
		}
};

std::vector<std::string> session::read_data_range(struct dnet_io_attr &io, int group_id)
{
	struct dnet_range_data *data;
	uint64_t num = 0;
	uint32_t ioflags = io.flags;
	int err;

	data = dnet_read_range(m_data->session_ptr, &io, group_id, m_data->cflags, &err);
	if (!data && err) {
		throw_error(err, io.id, "Failed to read range data object: group: %d, size: %llu",
			group_id, static_cast<unsigned long long>(io.size));
	}

	std::vector<std::string> ret;

	if (data) {
		try {
			for (int i = 0; i < err; ++i) {
				struct dnet_range_data *d = &data[i];
				char *data = (char *)d->data;

				if (!(ioflags & DNET_IO_FLAGS_NODATA)) {
					while (d->size > sizeof(struct dnet_io_attr)) {
						struct dnet_io_attr *io = (struct dnet_io_attr *)data;

						dnet_convert_io_attr(io);

						std::string str;

						if (sizeof(struct dnet_io_attr) + io->size > d->size) {
							throw_error(-EIO, "read_data_range: incorrect data size: d->size = %llu io->size = %llu",
								static_cast<unsigned long long>(d->size),
								static_cast<unsigned long long>(io->size));
						}

						str.append((char *)io->id, DNET_ID_SIZE);
						str.append((char *)&io->size, sizeof(io->size));
						str.append((const char *)(io + 1), io->size);

						ret.push_back(str);

						data += sizeof(struct dnet_io_attr) + io->size;
						d->size -= sizeof(struct dnet_io_attr) + io->size;
					}
				} else {
					if (d->size != sizeof(struct dnet_io_attr)) {
						throw_error(-EIO, "Incorrect data size: d->size = %llu sizeof = %zu",
							static_cast<unsigned long long>(d->size),
							sizeof(struct dnet_io_attr));
					}
					struct dnet_io_attr *rep = (struct dnet_io_attr *)data;
					num += rep->num;
				}
			}
			for (int i = 0; i < err; ++i) {
				struct dnet_range_data *d = &data[i];
				free(d->data);
			}
			free(data);
		} catch (const std::exception & e) {
			for (int i = 0; i < err; ++i) {
				struct dnet_range_data *d = &data[i];
				free(d->data);
			}
			free(data);
		}

		if (ioflags & DNET_IO_FLAGS_NODATA) {
			std::ostringstream str;
			str << num;
			ret.push_back(str.str());
		}
	}

	return ret;
}

std::vector<struct dnet_io_attr> session::remove_data_range(struct dnet_io_attr &io, int group_id)
{
	struct dnet_io_attr *retp;
	int ret_num;
	int err;

	retp = dnet_remove_range(m_data->session_ptr, &io, group_id, m_data->cflags, &ret_num, &err);

	if (!retp && err) {
		throw_error(err, io.id, "Failed to read range data object: group: %d, size: %llu",
			group_id, static_cast<unsigned long long>(io.size));
	}

	std::vector<struct dnet_io_attr> ret;;

	if (retp) {
		for (int i = 0; i < ret_num; ++i) {
			ret.push_back(retp[i]);
		}

		free(retp);
	}

	return ret;
}

std::string session::write_prepare(const key &id, const std::string &str, uint64_t remote_offset,
					  uint64_t psize)
{
	transform(id);

	struct dnet_io_control ctl;

	memset(&ctl, 0, sizeof(ctl));

	ctl.cflags = m_data->cflags;
	ctl.data = str.data();

	ctl.io.flags = m_data->ioflags | DNET_IO_FLAGS_PREPARE | DNET_IO_FLAGS_PLAIN_WRITE;
	ctl.io.offset = remote_offset;
	ctl.io.size = str.size();
	ctl.io.type = id.id().type;
	ctl.io.num = psize;

	memcpy(&ctl.id, &id.id(), sizeof(ctl.id));

	ctl.fd = -1;

	char *result = NULL;
	int err = dnet_write_data_wait(m_data->session_ptr, &ctl, reinterpret_cast<void**>(&result));
	if (err < 0) {
		throw_error(err, ctl.id, "write_prepare: size: %zd", str.size());
	}

	std::string ret(result, err);
	free(result);

	return ret;
}

std::string session::write_commit(const key &id, const std::string &str, uint64_t remote_offset, uint64_t csize)
{
	transform(id);

	struct dnet_io_control ctl;

	memset(&ctl, 0, sizeof(ctl));

	ctl.cflags = m_data->cflags;
	ctl.data = str.data();

	ctl.io.flags = m_data->ioflags | DNET_IO_FLAGS_COMMIT | DNET_IO_FLAGS_PLAIN_WRITE;
	ctl.io.offset = remote_offset;
	ctl.io.size = str.size();
	ctl.io.type = id.id().type;
	ctl.io.num = csize;

	memcpy(&ctl.id, &id.id(), sizeof(ctl.id));

	ctl.fd = -1;

	char *result = NULL;
	int err = dnet_write_data_wait(m_data->session_ptr, &ctl, reinterpret_cast<void**>(&result));
	if (err < 0) {
		throw_error(err, ctl.id, "write_commit: size: %zd", str.size());
	}

	std::string ret(result, err);
	free(result);

	return ret;
}

std::string session::write_plain(const key &id, const std::string &str, uint64_t remote_offset)
{
	transform(id);
	dnet_id raw = id.id();

	struct dnet_io_control ctl;

	memset(&ctl, 0, sizeof(ctl));

	ctl.cflags = m_data->cflags;
	ctl.data = str.data();

	ctl.io.flags = m_data->ioflags | DNET_IO_FLAGS_PLAIN_WRITE;
	ctl.io.offset = remote_offset;
	ctl.io.size = str.size();
	ctl.io.type = raw.type;

	memcpy(&ctl.id, &raw, sizeof(id));

	ctl.fd = -1;

	char *result = NULL;
	int err = dnet_write_data_wait(m_data->session_ptr, &ctl, reinterpret_cast<void**>(&result));
	if (err < 0) {
		throw_error(err, ctl.id, "write_plain: size: %zd", str.size());
	}

	std::string ret(result, err);
	free(result);

	return ret;
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

std::string session::request(struct dnet_id *id, struct sph *sph, bool lock)
{
	std::string ret_str;

	void *ret = NULL;
	int err;

	if (lock)
		err = dnet_send_cmd(m_data->session_ptr, id, sph, &ret);
	else
		err = dnet_send_cmd_nolock(m_data->session_ptr, id, sph, &ret);

	if (err < 0) {
		throw_error(err, *id, "failed to send request");
	}

	if (ret && err) {
		try {
			ret_str.assign((char *)ret, err);
		} catch (...) {
			free(ret);
			throw;
		}
		free(ret);
	}

	return ret_str;
}

std::string session::raw_exec(struct dnet_id *id, const struct sph *orig_sph,
				     const std::string &event, const std::string &data, const std::string &binary, bool lock)
{
	std::vector<char> vec(event.size() + data.size() + binary.size() + sizeof(struct sph));
	std::string ret_str;

	struct sph *sph = (struct sph *)&vec[0];

	memset(sph, 0, sizeof(struct sph));
	if (orig_sph) {
		*sph = *orig_sph;
		sph->flags &= ~DNET_SPH_FLAGS_SRC_BLOCK;
	} else if (id) {
		sph->flags = DNET_SPH_FLAGS_SRC_BLOCK;
		memcpy(sph->src.id, id->id, sizeof(sph->src.id));
	}

	sph->data_size = data.size();
	sph->binary_size = binary.size();
	sph->event_size = event.size();

	memcpy(sph->data, event.data(), event.size());
	memcpy(sph->data + event.size(), data.data(), data.size());
	memcpy(sph->data + event.size() + data.size(), binary.data(), binary.size());

	return request(id, sph, lock);
}

std::string session::exec_locked(struct dnet_id *id, const std::string &event, const std::string &data, const std::string &binary)
{
	return raw_exec(id, NULL, event, data, binary, true);
}

std::string session::exec_unlocked(struct dnet_id *id, const std::string &event, const std::string &data, const std::string &binary)
{
	return raw_exec(id, NULL, event, data, binary, false);
}

std::string session::push_locked(struct dnet_id *id, const struct sph &sph, const std::string &event,
					const std::string &data, const std::string &binary)
{
	return raw_exec(id, &sph, event, data, binary, true);
}

std::string session::push_unlocked(struct dnet_id *id, const struct sph &sph, const std::string &event,
					  const std::string &data, const std::string &binary)
{
	return raw_exec(id, &sph, event, data, binary, false);
}

void session::reply(const struct sph &orig_sph, const std::string &event, const std::string &data, const std::string &binary)
{
	std::vector<char> vec(event.size() + data.size() + binary.size() + sizeof(struct sph));
	std::string ret_str;

	struct sph *sph = (struct sph *)&vec[0];

	*sph = orig_sph;

	sph->data_size = data.size();
	sph->binary_size = binary.size();
	sph->event_size = event.size();

	memcpy(sph->data, event.data(), event.size());
	memcpy(sph->data + event.size(), data.data(), data.size());
	memcpy(sph->data + event.size() + data.size(), binary.data(), binary.size());

	struct dnet_id id;
	dnet_setup_id(&id, 0, sph->src.id);
	id.type = 0;

	request(&id, sph, false);
}

namespace {
bool dnet_io_attr_compare(const struct dnet_io_attr &io1, const struct dnet_io_attr &io2) {
	int cmp;

	cmp = dnet_id_cmp_str(io1.id, io2.id);
	return cmp < 0;
}
}

std::vector<std::string> session::bulk_read(const std::vector<struct dnet_io_attr> &ios)
{
	struct dnet_range_data *data;
	int num, *g, err;

	num = dnet_mix_states(m_data->session_ptr, NULL, &g);
	if (num < 0)
		throw std::runtime_error("could not fetch groups: " + std::string(strerror(num)));

	std::vector<int> groups;
	try {
		groups.assign(g, g + num);
		free(g);
	} catch (...) {
		free(g);
		throw;
	}

	std::vector<struct dnet_io_attr> tmp_ios = ios;
	std::sort(tmp_ios.begin(), tmp_ios.end(), dnet_io_attr_compare);

	std::vector<std::string> ret;

	for (std::vector<int>::iterator group = groups.begin(); group != groups.end(); ++group) {
		if (!tmp_ios.size())
			break;

		data = dnet_bulk_read(m_data->session_ptr, (struct dnet_io_attr *)(&tmp_ios[0]), tmp_ios.size(), *group, m_data->cflags, &err);
		if (!data && err) {
			throw_error(err, "Failed to read bulk data: group: %d", *group);
		}

		if (data) {
			for (int i = 0; i < err; ++i) {
				struct dnet_range_data *d = &data[i];
				char *data = (char *)d->data;

				while (d->size) {
					struct dnet_io_attr *io = (struct dnet_io_attr *)data;

					for (std::vector<struct dnet_io_attr>::iterator it = tmp_ios.begin(); it != tmp_ios.end(); ++it) {
						int cmp = dnet_id_cmp_str(it->id, io->id);

						if (cmp == 0) {
							tmp_ios.erase(it);
							break;
						}
					}

					dnet_convert_io_attr(io);

					uint64_t size = dnet_bswap64(io->size);

					std::string str;

					str.append((char *)io->id, DNET_ID_SIZE);
					str.append((char *)&size, 8);
					str.append((const char *)(io + 1), io->size);

					ret.push_back(str);

					data += sizeof(struct dnet_io_attr) + io->size;
					d->size -= sizeof(struct dnet_io_attr) + io->size;
				}

				free(d->data);
			}

			free(data);
		}
	}

	return ret;
}

std::vector<std::string> session::bulk_read(const std::vector<std::string> &keys)
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

std::string session::bulk_write(const std::vector<struct dnet_io_attr> &ios, const std::vector<std::string> &data)
{
	std::vector<struct dnet_io_control> ctls;
	unsigned int i;
	int err;

	if (ios.size() != data.size()) {
		throw_error(-EIO, "BULK_WRITE: ios doesn't meet data: io.size: %zd, data.size: %zd",
			ios.size(), data.size());
	}

	ctls.reserve(ios.size());

	for(i = 0; i < ios.size(); ++i) {
		struct dnet_io_control ctl;
		memset(&ctl, 0, sizeof(ctl));

		ctl.cflags = m_data->cflags;
		ctl.data = data[i].data();

		ctl.io = ios[i];

		dnet_setup_id(&ctl.id, 0, (unsigned char *)ios[i].id);
		ctl.id.type = ios[i].type;

		ctl.fd = -1;

		ctls.push_back(ctl);
	}

	struct dnet_range_data ret = dnet_bulk_write(m_data->session_ptr, &ctls[0], ctls.size(), &err);
	if (err < 0) {
		throw_error(-EIO, "BULK_WRITE: size: %lld",
			static_cast<unsigned long long>(ret.size));
	}

	std::string ret_str((const char *)ret.data, ret.size);
	free(ret.data);

	return ret_str;
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
