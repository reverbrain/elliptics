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
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 */

#include "elliptics_data.h"

#include <boost/python.hpp>

namespace ioremap { namespace elliptics { namespace python {

data_wrapper::data_wrapper(const std::string &data) {
	m_pointer = data_pointer::copy(data);
}

data_wrapper::data_wrapper(const data_wrapper &other) {
	m_pointer = other.m_pointer;
}

data_wrapper::data_wrapper(const data_pointer &pointer) {
	m_pointer = pointer;
}

data_wrapper data_wrapper::convert(const bp::api::object &obj) {
	bp::extract<std::string> get_string(obj);
	bp::extract<data_pointer> get_pointer(obj);
	bp::extract<data_wrapper> get_wrapper(obj);

	if(get_string.check())
		return data_wrapper(get_string());

	if(get_pointer.check())
		return data_wrapper(get_pointer());

	return get_wrapper();
}


void init_elliptics_data() {
	bp::class_<data_wrapper>("Data", bp::init<std::string>())
		.def(bp::init<data_pointer>())
		.def(bp::init<data_wrapper>())
		.def("__str__", &data_wrapper::to_string)
		.def("empty", &data_wrapper::empty)
		.def("size", &data_wrapper::size)
		.def("__len__", &data_wrapper::size)
	;
}

} } } // namespace ioremap::elliptics::python