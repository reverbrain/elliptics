/*
* 2013+ Copyright (c) Kirill Smorodinnikov <shaitkir@gmail.com>
* All rights reserved.
*
* This program is free software; you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation; either version 2 of the License, or
* (at your option) any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
* GNU General Public License for more details.
*/

#ifndef ELLIPTICS_PYTHON_ELLIPTICS_DATA_HPP
#define ELLIPTICS_PYTHON_ELLIPTICS_DATA_HPP

#include <elliptics/utils.hpp>
#include <boost/python/object.hpp>

namespace bp = boost::python;

namespace ioremap { namespace elliptics { namespace python {

class data_wrapper {
public:
	data_wrapper(const std::string &data);
	data_wrapper(const data_wrapper &other);
	data_wrapper(const data_pointer &pointer);

	static data_wrapper convert(const bp::api::object &obj);

	data_pointer pointer() const { return m_pointer; }
	std::string to_string() const { return m_pointer.to_string(); }
	bool empty() const { return m_pointer.empty(); }
	size_t size() const { return m_pointer.size(); }

private:
	data_pointer m_pointer;
};

void init_elliptcs_data();

} } } // namespace ioremap::elliptics::python

#endif // ELLIPTICS_PYTHON_ELLIPTICS_DATA_HPP
