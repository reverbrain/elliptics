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

#include <sstream>

#include <boost/make_shared.hpp>

namespace ioremap { namespace elliptics {

key::key() : m_by_id(false), m_type(0)
{
	memset(&m_id, 0, sizeof(m_id));
}

key::key(const std::string &remote, int type) : m_by_id(false), m_remote(remote), m_type(type)
{
	memset(&m_id, 0, sizeof(m_id));
}

key::key(const struct dnet_id &id) : m_by_id(true), m_type(0), m_id(id)
{
}

key::key(const key &other)
	: m_by_id(other.m_by_id), m_remote(other.m_remote), m_type(other.m_type), m_id(other.m_id)
{
}

key &key::operator =(const key &other)
{
	m_by_id = other.m_by_id;
	m_remote = other.m_remote;
	m_type = other.m_type;
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
		if (cmp == 0)
			cmp = m_id.type - other.m_id.type;
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
		if (cmp == 0)
			cmp = m_id.type - other.m_id.type;
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

int key::type() const
{
	return m_by_id ? m_id.type : m_type;
}

const struct dnet_id &key::id() const
{
	return m_id;
}

std::string key::to_string() const
{
	if (m_by_id)
		return dnet_dump_id(&m_id);
	else
		return m_remote;
}

void key::transform(session &sess)
{
	if (m_by_id)
		return;

	memset(&m_id, 0, sizeof(m_id));
	sess.transform(m_remote, m_id);
	m_id.type = m_type;
}

} } // namespace ioremap::elliptics
