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

#ifndef ELLIPTICS_PYTHON_PY_CONVERTERS_HPP
#define ELLIPTICS_PYTHON_PY_CONVERTERS_HPP

#include <boost/python/list.hpp>
#include <boost/python/stl_iterator.hpp>
#include <boost/python/iterator.hpp>

#include <vector>

namespace bp = boost::python;

namespace ioremap { namespace elliptics { namespace python {

template <typename T>
static std::vector<T> convert_to_vector(const bp::api::object &list)
{
	bp::stl_input_iterator<T> begin(list), end;
	return std::vector<T>(begin, end);
}

template<>
std::vector<data_pointer> convert_to_vector<data_pointer>(const bp::api::object &list) {
	auto wdatas = convert_to_vector<std::string>(list);
	std::vector<data_pointer> ret;
	for (auto it = wdatas.begin(), end = wdatas.end(); it != end; ++it) {
		ret.push_back(data_pointer::copy(*it));
	}
	return ret;
}

template <typename T>
static bp::list convert_to_list(const std::vector<T> &vect)
{
	bp::list ret;

	for (auto it = vect.cbegin(), end = vect.cend(); it != end; ++it) {
		ret.append(*it);
	}

	return ret;
}

} } } // namespace ioremap::elliptics::python

#endif // ELLIPTICS_PYTHON_PY_CONVERTERS_HPP
