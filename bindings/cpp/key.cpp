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

#include <elliptics/cppdef.h>

#include <sstream>

#include <boost/make_shared.hpp>

namespace ioremap { namespace elliptics {

enum key_reserved_flags : int {
	KEY_INITED = 0x0001
};

key::key() : m_by_id(false), m_reserved(KEY_INITED)
{
	memset(&m_id, 0, sizeof(m_id));
}

key::key(const std::string &remote) : m_by_id(false), m_remote(remote), m_reserved(0)
{
	memset(&m_id, 0, sizeof(m_id));
}

key::key(const dnet_id &id) : m_by_id(true), m_reserved(KEY_INITED), m_id(id)
{
}

key::key(const dnet_raw_id &id) : m_by_id(true), m_reserved(KEY_INITED)
{
	memset(&m_id, 0, sizeof(m_id));
	memcpy(m_id.id, id.id, sizeof(id.id));
}

key::key(const key &other)
	: m_by_id(other.m_by_id), m_remote(other.m_remote), m_reserved(other.m_reserved), m_id(other.m_id)
{
}

key &key::operator =(const key &other)
{
	m_by_id = other.m_by_id;
	m_remote = other.m_remote;
	m_reserved = other.m_reserved;
	m_id = other.m_id;
	return *this;
}

key::~key()
{
}

bool key::operator ==(const key &other) const
{
	if (m_by_id != other.m_by_id) {
		return false;
	} else if (m_by_id) {
		int cmp = memcmp(&m_id, &other.m_id, DNET_ID_SIZE);
		return cmp == 0;
	} else {
		return m_remote == other.m_remote;
	}
}

bool key::operator <(const key &other) const
{
	if (m_by_id != other.m_by_id) {
		return other.m_by_id;
	} else if (m_by_id) {
		int cmp = memcmp(&m_id, &other.m_id, DNET_ID_SIZE);
		return cmp < 0;
	} else {
		return m_remote < other.m_remote;
	}
}

bool key::by_id() const
{
	return m_by_id;
}

const std::string &key::remote() const
{
	return m_remote;
}

const dnet_id &key::id() const
{
	return m_id;
}

const dnet_raw_id &key::raw_id() const
{
	return *reinterpret_cast<const dnet_raw_id *>(&m_id);
}

std::string key::to_string() const
{
	if (m_by_id) {
		return dnet_dump_id(&m_id);
	} else {
		return m_remote;
	}
}

void key::transform(const session &sess) const
{
	if (m_by_id)
		return;

	if (!inited()) {
		memset(&m_id, 0, sizeof(m_id));
		sess.transform(m_remote, m_id);
		const_cast<key *>(this)->set_inited(true);
	}
}

bool key::inited() const
{
	return (m_reserved & KEY_INITED);
}

void key::set_inited(bool inited)
{
	if (inited) {
		m_reserved |= KEY_INITED;
	} else {
		m_reserved &= ~KEY_INITED;
	}
}

void key::set_id(const dnet_id &id)
{
	m_by_id = true;
	m_id = id;
	set_inited(true);
}

void key::set_id(const dnet_raw_id &id)
{
	m_by_id = true;
	memset(&m_id, 0, sizeof(m_id));
	memcpy(m_id.id, id.id, sizeof(id.id));
	set_inited(true);
}

void key::set_group_id(uint32_t group_id)
{
	m_id.group_id = group_id;
}

} } // namespace ioremap::elliptics
