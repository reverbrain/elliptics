/*
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
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
* GNU Lesser General Public License for more details.
*/

#ifndef ELLIPTICS_PYTHON_ELLIPTICS_ID_HPP
#define ELLIPTICS_PYTHON_ELLIPTICS_ID_HPP

#include <boost/python.hpp>
#include <boost/python/list.hpp>
#include <boost/python/long.hpp>

#include <elliptics/session.hpp>

namespace bp = boost::python;

namespace ioremap { namespace elliptics { namespace python {

class elliptics_id {
public:
	elliptics_id();
	elliptics_id(const dnet_id &id);
	elliptics_id(const dnet_raw_id &id);
	elliptics_id(const dnet_raw_id &id, uint32_t group_id);
	elliptics_id(const uint8_t id[DNET_ID_SIZE]);
	elliptics_id(const elliptics_id &other);
	elliptics_id(const bp::object &id, const uint32_t &group_id);

	const dnet_id &id() const { return m_id; }
	const dnet_raw_id &raw_id() const { return *reinterpret_cast<const dnet_raw_id *>(&m_id); }

	bp::list list_id() const;

	void set_list_id(const bp::object &id);

	uint32_t group_id() const;

	void set_group_id(const uint32_t &group_id);

	int cmp(const elliptics_id &other) const;

	static elliptics_id* from_hex(const std::string &hex);

	// Implements __str__ method.
	// Always returns printable hex representation of all id bytes
	std::string to_str() const;

	// Implements __repr__ method.
	// Returns group, hex id prefix, and original key string
	// (depending on key's previous history, any of those could be zero or empty).
	std::string to_repr() const;

	dnet_id m_id;
};

struct id_pickle : bp::pickle_suite
{
	static bp::tuple getinitargs(const elliptics_id& id);
	static bp::tuple getstate(const elliptics_id& id);
	static void setstate(elliptics_id& id, bp::tuple state);
};

void init_elliptics_id();

} } } // namespace ioremap::elliptics::python

#endif // ELLIPTICS_PYTHON_ELLIPTICS_ID_HPP
